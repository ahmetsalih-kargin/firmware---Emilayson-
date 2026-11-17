"""firmae/image.py: the flow of the old scripts/makeImage.sh in Python
(REFACTORING_PLAN 4.3). No root, no loop device, no mount: the external
commands are replaced by a recorder that imitates their effect on a plain
directory, so the order of the steps, the cleanup on every exit path and the
symlink handling can be checked."""

import contextlib
import os
import signal
import stat
import subprocess
import sys
import tarfile
import textwrap
import time
import types

import pytest

pytestmark = pytest.mark.linux

if sys.platform.startswith("linux"):
    from firmae import image
else:                                   # O_NOFOLLOW & co. do not exist on Windows
    image = None

LOOP = "/dev/loop7"
DEVICE = LOOP + "p1"


# ---------------------------------------------------------------- fake world

class World:
    """Records the commands image.py runs and imitates their effect."""

    def __init__(self, tmp_path, repo_root, etc="true"):
        self.tmp = tmp_path
        self.root = str(repo_root)
        self.scratch = tmp_path / "scratch"
        self.work = self.scratch / "1"
        self.mnt = self.work / "image"
        self.images = tmp_path / "images"
        self.images.mkdir(parents=True)
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.host = tmp_path / "host"
        self.host.mkdir()
        (self.host / "victim").write_bytes(b"host data\n")
        for name in ("busybox", "bash-static", "console", "libnvram.so"):
            p = self.bin / name
            p.write_bytes(b"\x7fELF " + name.encode() + b"\n")
            p.chmod(0o755)
        self.binaries = [("busybox", str(self.bin / "busybox")), ("console", str(self.bin / "console")),
                         ("libnvram.so", str(self.bin / "libnvram.so"))]
        self.cfg = types.SimpleNamespace(SCRATCH_DIR=str(self.scratch), TARBALL_DIR=str(self.images) + "/",
                                         SCRIPT_DIR=str(repo_root / "scripts") + "/",
                                         FIRMAE_BOOT="true", FIRMAE_ETC=etc)
        self.calls = []
        self.timeouts = []            # (call name, timeout, grace)
        self.mounted = False
        self.loops = set()
        self.rc = {}                  # call name -> exit code
        self.hooks = {}               # call name -> callable (raise / side effect)
        self.infer = lambda mnt: None  # extra things inferFile.sh "creates"
        self.service = b"/usr/sbin/httpd"
        self.make_tarball({"etc/rcS": b"#!/bin/sh\n", "bin/sh": b"sh\n", "sbin/init": b"init\n"})

    def make_tarball(self, files, links=()):
        src = self.tmp / "rootfs"
        for rel, data in files.items():
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        for rel, target in links:
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, str(p))
        with tarfile.open(str(self.images / "1.tar.gz"), "w:gz") as t:
            for entry in sorted(os.listdir(str(src))):
                t.add(str(src / entry), arcname=entry)

    # -- the replacement of image.run
    def run(self, argv, timeout, stdin=None, env=None, cwd=None, capture=False, grace=None):
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv), argv
        self.timeouts.append((self._name(argv), timeout, grace))
        assert timeout and timeout > 0
        name, out = self._name(argv), b""
        self.calls.append(name)
        if name in self.hooks:
            self.hooks[name](argv)
        rc = self.rc.get(name, 0)
        if rc:
            return rc, out
        if name == "binaries":
            assert cwd == self.root and argv[-1] == "mipsel"
            out = b"".join(b"%s\0%s\0" % (n.encode(), p.encode()) for n, p in self.binaries)
        elif name == "qemu-img":
            assert argv == ["qemu-img", "create", "-f", "raw", str(self.work / "image.raw"), "1G"]
            (self.work / "image.raw").write_bytes(b"")
        elif name == "fdisk":
            assert argv == [image.FDISK, str(self.work / "image.raw")]
            assert stdin.read() == b"o\nn\np\n1\n\n\nw\n"
        elif name == "add_partition":
            assert argv[5:] == [str(self.work / "image.raw")] and cwd == self.root
            self.loops.add(LOOP)
            out = (DEVICE + "\n").encode()
        elif name == "mount_partition":
            assert argv[5:] == [DEVICE, str(self.mnt) + "/"]
            assert self.mnt.is_dir()
            self.mounted = True
        elif name == "tar":
            assert argv == ["tar", "-xf", str(self.work / "1.tar.gz"), "-C", str(self.mnt) + "/"]
            assert self.mounted
            with tarfile.open(argv[2]) as t:
                t.extractall(argv[4], **({"filter": "fully_trusted"} if hasattr(tarfile, "data_filter") else {}))
        elif name == "chroot inferFile.sh":
            assert argv == ["chroot", str(self.mnt) + "/", "/bash-static", "/inferFile.sh"]
            assert env["FIRMAE_BOOT"] == "true" and env["FIRMAE_ETC"] == self.cfg.FIRMAE_ETC
            for f in ("busybox", "bash-static", "inferFile.sh"):
                assert (self.mnt / f).is_file() and not (self.mnt / f).is_symlink()
            (self.mnt / "firmadyne/init").write_bytes(b"/sbin/init\n/firmadyne/preInit.sh\n")
            if self.service is not None:
                (self.mnt / "firmadyne/service").write_bytes(self.service)
            self.infer(self.mnt)
        elif name == "chroot fixImage.sh":
            assert argv == ["chroot", str(self.mnt) + "/", "/busybox", "ash", "/fixImage.sh"]
            assert not (self.mnt / "bash-static").exists() and not (self.mnt / "inferFile.sh").exists()
            assert (self.mnt / "fixImage.sh").is_file()
            os.symlink("/firmadyne/busybox", str(self.mnt / "firmadyne/sh"))
        elif name in ("umount", "umount -l"):
            assert argv[-1] == str(self.mnt) + "/"
            self.mounted = False
        elif name.startswith("del_partition"):
            self.loops.discard(argv[5])
        return 0, (out if capture else None)

    @staticmethod
    def _name(argv):
        if argv[0] == "bash":
            if "get_binary" in argv[2]:
                return "binaries"
            return argv[4] if argv[4] != "del_partition" else "del_partition " + argv[5]
        if argv[0] == "chroot":
            return "chroot " + argv[-1].lstrip("/")
        if argv[0] == "umount" and argv[1] == "-l":
            return "umount -l"
        return os.path.basename(argv[0])

    def build(self):
        return image.build(self.cfg, "1", "mipsel", self.root)


@pytest.fixture
def world(tmp_path, repo_root, monkeypatch):
    w = World(tmp_path, repo_root)
    monkeypatch.setattr(image, "run", w.run)
    monkeypatch.setattr(image, "is_mounted", lambda p: w.mounted)
    monkeypatch.setattr(image.time, "sleep", lambda s: None)
    real_which = image.shutil.which
    monkeypatch.setattr(image.shutil, "which",
                        lambda n: str(w.bin / n) if n in ("busybox", "bash-static") else real_which(n))
    devices = []

    def char_device(dir_fd, name, mode, major, minor):    # mknod needs root
        image.remove_entry(dir_fd, name, name)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        os.close(fd)
        devices.append((name, mode, major, minor))
    monkeypatch.setattr(image, "make_char_device", char_device)
    w.devices = devices
    monkeypatch.setenv("USER", "root")
    return w


# what the old makeImage.sh ran, in order (`sync` included; secure_workdir and
# chown are firmae.config / coreutils calls it made as well)
OLD_SEQUENCE = [
    "secure_workdir", "qemu-img", "fdisk", "add_partition", "sync", "mkfs.ext2", "chown",
    "sync", "mount_partition", "tar", "chroot inferFile.sh", "chroot fixImage.sh",
    "sync", "umount", "del_partition " + LOOP, "add_partition", "e2fsck", "sync",
    "del_partition " + LOOP,
]

OLD_HEADINGS = [
    "----Running----", "----Copying Filesystem Tarball----", "----Creating QEMU Image----",
    "----Creating Partition Table----", "----Mounting QEMU Image----", "----Creating Filesystem----",
    "----Making QEMU Image Mountpoint----", "----Mounting QEMU Image Partition----",
    "----Extracting Filesystem Tarball----", "----Creating FIRMADYNE Directories----",
    "----Finding Init (chroot)----", "----Patching Filesystem (chroot)----",
    "----Setting up FIRMADYNE----", "----Unmounting QEMU Image----",
]


def _mode(p):
    return stat.S_IMODE(os.lstat(str(p)).st_mode)


# ---------------------------------------------------------------- the normal flow

def test_steps_run_in_the_order_of_the_old_script(world, capsys):
    world.build()
    # get_binary is asked first now (an invalid architecture fails before anything is built)
    assert world.calls == ["binaries"] + OLD_SEQUENCE
    out = capsys.readouterr().out.splitlines()
    assert [l for l in out if l.startswith("----")] == OLD_HEADINGS
    assert "Image: %s/image.raw" % world.work in out and "Device: %s" % LOOP in out
    assert not world.mounted and not world.loops


def test_result_of_the_normal_flow(world):
    world.work.mkdir(parents=True)
    (world.work / "kernelInit").write_bytes(b"init=/sbin/init\n")
    old_mask = os.umask(0o022)
    try:
        world.build()
    finally:
        os.umask(old_mask)
    mnt, fd = world.mnt, world.mnt / "firmadyne"
    # helper files used by the chroot steps are gone again
    for top in ("busybox", "bash-static", "inferFile.sh", "fixImage.sh", "kernelInit"):
        assert not os.path.lexists(str(mnt / top)), top
    assert (fd / "libnvram").is_dir() and (fd / "libnvram.override").is_dir()
    for name, src in world.binaries:
        assert (fd / name).read_bytes() == open(src, "rb").read()
        assert _mode(fd / name) == 0o755
    for name in image.GUEST_SCRIPTS:
        assert (fd / name).read_bytes() == open(world.cfg.SCRIPT_DIR + name, "rb").read()
        assert _mode(fd / name) == 0o755
    assert (mnt / "bin/a").read_bytes() == open(world.cfg.SCRIPT_DIR + "injectionChecker.sh", "rb").read()
    assert _mode(mnt / "bin/a") == 0o755
    assert (fd / "debug.sh").read_bytes() == b"" and _mode(fd / "debug.sh") == 0o755
    assert world.devices == [("ttyS1", 0o666, 4, 65)]
    assert os.readlink(str(fd / "sh")) == "/firmadyne/busybox"     # fixImage.sh's link is kept
    # init moved out, service copied out
    assert (world.work / "init").read_bytes() == b"/sbin/init\n/firmadyne/preInit.sh\n"
    assert not os.path.lexists(str(fd / "init"))
    assert (world.work / "service").read_bytes() == b"/usr/sbin/httpd"
    assert (fd / "service").exists()
    assert not (world.work / "1.tar.gz").exists()
    assert _mode(world.work / "image.raw") == 0o644


def test_tarball_already_in_the_work_dir_is_used(world):
    world.work.mkdir(parents=True)
    os.rename(str(world.images / "1.tar.gz"), str(world.work / "1.tar.gz"))
    world.build()
    assert (world.mnt / "etc/rcS").exists()


def test_missing_tarball(world):
    os.remove(str(world.images / "1.tar.gz"))
    with pytest.raises(image.ImageError, match="Cannot find tarball of root filesystem for 1!"):
        world.build()
    assert "qemu-img" not in world.calls


def test_existing_mountpoint_is_not_chowned(world):
    world.mnt.mkdir(parents=True)
    world.build()
    assert "chown" not in world.calls


def test_user_must_be_set_when_the_mountpoint_is_created(world, monkeypatch):
    """Kept from the old script (`chown "${USER}"` under set -u)."""
    monkeypatch.delenv("USER")
    with pytest.raises(image.ImageError, match="USER"):
        world.build()
    assert world.calls[-1] == "del_partition " + LOOP


def test_firmae_etc_false_edits_equal_the_old_sed_commands(world, tmp_path):
    world.cfg.FIRMAE_ETC = "false"
    world.build()
    ref = tmp_path / "ref"
    ref.mkdir()
    for n in image.GUEST_SCRIPTS:
        (ref / n).write_bytes(open(world.cfg.SCRIPT_DIR + n, "rb").read())
    old = textwrap.dedent("""\
        set -e
        sed -i 's/sleep 60/sleep 15/g' "${D}/network.sh"
        sed -i 's/sleep 120/sleep 30/g' "${D}/run_service.sh"
        sed -i 's@/firmadyne/sh@/bin/sh@g' ${D}/{preInit.sh,network.sh,run_service.sh}
        sed -i 's@BUSYBOX=/firmadyne/busybox@BUSYBOX=@g' ${D}/{preInit.sh,network.sh,run_service.sh}
        """)
    res = subprocess.run(["bash", "-c", old], env=dict(os.environ, D=str(ref)), capture_output=True, timeout=30)
    assert res.returncode == 0, res.stderr
    changed = 0
    for n in image.GUEST_SCRIPTS:
        new = (world.mnt / "firmadyne" / n).read_bytes()
        assert new == (ref / n).read_bytes(), n
        changed += new != open(world.cfg.SCRIPT_DIR + n, "rb").read()
    assert changed          # the edits did something on the shipped scripts


def test_edits_equal_sed_on_tricky_text(tmp_path):
    text = (b"sleep 600\nsleep 60sleep 60\n/firmadyne/shell /firmadyne/sh\n"
            b"BUSYBOX=/firmadyne/busybox BUSYBOX=/firmadyne/busybox2\nno newline sleep 120")
    d = tmp_path / "d"
    d.mkdir()
    for n in image.GUEST_SCRIPTS:
        (d / n).write_bytes(text)
        (tmp_path / n).write_bytes(text)
    fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for n, edits in image.ETC_OFF_EDITS:
            image.edit_file(fd, n, edits, n)
    finally:
        os.close(fd)
    old = ("sed -i 's/sleep 60/sleep 15/g' network.sh && sed -i 's/sleep 120/sleep 30/g' run_service.sh && "
           "sed -i 's@/firmadyne/sh@/bin/sh@g' preInit.sh network.sh run_service.sh && "
           "sed -i 's@BUSYBOX=/firmadyne/busybox@BUSYBOX=@g' preInit.sh network.sh run_service.sh")
    subprocess.run(["bash", "-c", old], cwd=str(tmp_path), check=True, timeout=30)
    for n in image.GUEST_SCRIPTS:
        assert (d / n).read_bytes() == (tmp_path / n).read_bytes(), n


def test_bad_switch_value_is_refused(world):
    world.cfg.FIRMAE_ETC = "rm -rf /"
    with pytest.raises(image.ImageError, match="FIRMAE_ETC"):
        world.build()
    assert world.calls == []


# ---------------------------------------------------------------- cleanup

def _tail_ok(calls):
    """After a failure while mounted: unmount, then release the loop device."""
    i = calls.index("umount")
    assert calls[i + 1:] == ["del_partition " + LOOP]


@pytest.mark.parametrize("step", ["mkfs.ext2", "mount_partition", "tar", "chroot inferFile.sh",
                                  "chroot fixImage.sh", "umount", "e2fsck"])
def test_failing_step_leaves_nothing_mounted_or_attached(world, step, capsys):
    world.rc[step] = 3 if step != "e2fsck" else 1
    with pytest.raises(image.ImageError) as e:
        world.build()
    assert e.value.code == world.rc[step]
    assert not world.mounted and not world.loops
    assert world.calls[-1] == "del_partition " + LOOP
    if step in ("tar", "chroot inferFile.sh", "chroot fixImage.sh"):
        _tail_ok(world.calls)
    if step == "umount":                     # the normal unmount failed: lazy unmount
        assert world.calls[-2:] == ["umount -l", "del_partition " + LOOP]
    if step == "e2fsck":
        assert "e2fsck -y %s exited with 1" % DEVICE in capsys.readouterr().out


@pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit(143), SystemExit(129), RuntimeError("bug")])
@pytest.mark.parametrize("step", ["tar", "chroot inferFile.sh", "e2fsck"])
def test_exception_in_a_step_still_cleans_up(world, step, exc):
    def boom(argv):
        raise exc
    world.hooks[step] = boom
    with pytest.raises(type(exc) if isinstance(exc, BaseException) else exc):
        world.build()
    assert not world.mounted and not world.loops
    assert world.calls[-1] == "del_partition " + LOOP


def test_failure_in_python_code_between_commands_cleans_up(world):
    """e.g. /firmadyne already in the tarball: the mkdir fails as before."""
    world.make_tarball({"firmadyne/x": b"x"})
    with pytest.raises(image.ImageError, match="File exists"):
        world.build()
    _tail_ok(world.calls)


def test_failure_before_the_loop_device_runs_no_cleanup_command(world):
    world.rc["fdisk"] = 1
    with pytest.raises(image.ImageError):
        world.build()
    assert world.calls[-1] == "fdisk"


def test_add_partition_output_must_be_a_loop_partition(world, monkeypatch):
    def run(argv, timeout, **kw):
        rc, out = world.run(argv, timeout, **kw)
        if world._name(argv) == "add_partition":
            return 0, b"/dev/sda1; rm -rf /\n"
        return rc, out
    monkeypatch.setattr(image, "run", run)
    with pytest.raises(image.ImageError, match="not a loop partition"):
        world.build()
    assert "mkfs.ext2" not in world.calls


def test_release_defers_signals_until_cleanup_is_done(world, monkeypatch):
    """A second Ctrl-C/SIGTERM during the cleanup cannot cut it short."""
    held = image.Held(world.root)
    held.loops = [LOOP]
    held.mountpoint = str(world.mnt) + "/"
    world.mounted = True

    def umount_and_signal(argv):
        os.kill(os.getpid(), signal.SIGTERM)
    world.hooks["umount"] = umount_and_signal
    old = signal.signal(signal.SIGTERM, lambda s, f: (_ for _ in ()).throw(SystemExit(143)))
    try:
        with pytest.raises(SystemExit) as e:
            held.release()
    finally:
        signal.signal(signal.SIGTERM, old)
    assert e.value.code == 143
    assert world.calls == ["umount", "del_partition " + LOOP]     # both ran before the exit


def test_cleanup_fits_in_the_pipeline_grace():
    """pipeline.run_with_timeout SIGKILLs the stage STAGE_GRACE seconds after
    its SIGINT/SIGTERM; by then the interrupted command must be stopped and
    Held.release() done."""
    from firmae import pipeline
    stop_interrupted = 2 * image.STOP_GRACE + image.GUARD_REAP          # _stop + reaping the guard
    assert image.run_overhead(image.STOP_GRACE) == stop_interrupted
    worst = stop_interrupted + image.CLEANUP_BUDGET
    assert worst == 47
    assert worst < pipeline.STAGE_GRACE
    # every cleanup command must fit at least once
    for cap in (image.T_CLEANUP_UMOUNT, image.T_CLEANUP_LAZY):
        assert cap + image.run_overhead(image.CLEANUP_STOP_GRACE) < image.CLEANUP_BUDGET


@pytest.mark.parametrize("hang", [False, True])
def test_release_stays_within_its_budget(world, monkeypatch, hang, capsys):
    """Each cleanup command is charged its full timeout plus the stop overhead
    (the worst case of run()); release() must still end within CLEANUP_BUDGET
    and give every step a positive timeout or skip it."""
    clock = [1000.0]
    monkeypatch.setattr(image, "_clock", lambda: clock[0])

    def run(argv, timeout, grace=None, **kw):
        assert grace == image.CLEANUP_STOP_GRACE
        assert 1 <= timeout
        clock[0] += timeout + image.run_overhead(grace)        # used up completely
        if hang and world._name(argv) == "umount":
            world.calls.append("umount")
            raise image.ImageError("Error: umount timed out after %ds" % timeout)
        return world.run(argv, timeout, grace=grace, **kw)
    monkeypatch.setattr(image, "run", run)
    world.rc["umount"] = 32
    held = image.Held(world.root)
    held.loops = [LOOP]
    held.mountpoint = str(world.mnt) + "/"
    world.mounted = True
    held.release()
    assert clock[0] - 1000.0 <= image.CLEANUP_BUDGET
    assert world.calls == ["umount", "umount -l", "del_partition " + LOOP]
    assert not world.loops and held.loops == [] and held.mountpoint is None
    t = {n: to for n, to, _ in world.timeouts}
    assert t["umount -l"] == image.T_CLEANUP_LAZY
    assert t["del_partition " + LOOP] < image.T_CLEANUP        # cut to what is left


def test_release_skips_what_no_longer_fits(world, monkeypatch, capsys):
    clock = [0.0]
    monkeypatch.setattr(image, "_clock", lambda: clock[0])

    def run(argv, timeout, grace=None, **kw):
        clock[0] += image.CLEANUP_BUDGET          # the first command eats everything
        return world.run(argv, timeout, grace=grace, **kw)
    monkeypatch.setattr(image, "run", run)
    world.rc["umount"] = 32
    held = image.Held(world.root)
    held.loops = [LOOP]
    held.mountpoint = str(world.mnt) + "/"
    world.mounted = True
    held.release()
    assert world.calls == ["umount"]
    assert held.loops == [] and held.mountpoint is None
    out = capsys.readouterr().out
    assert "no time left to unmount" in out and "no time left to release %s" % LOOP in out


# ---------------------------------------------------------------- signals, for real

DRIVER = r'''
import os, sys, time, types
sys.path.insert(0, sys.argv[1])
from firmae import image
log = open(sys.argv[2], "a", buffering=1)
ready = sys.argv[3]
state = {"mounted": False}

def run(argv, timeout, stdin=None, env=None, cwd=None, capture=False, grace=None):
    name = argv[4] if argv[0] == "bash" and "get_binary" not in argv[2] else os.path.basename(argv[0])
    log.write(name + "\n")
    if name == "qemu-img":
        open(argv[4], "w").close()
    if name == "add_partition":
        return 0, b"/dev/loop7p1\n"
    if name == "mount_partition":
        state["mounted"] = True
    if name == "umount":
        state["mounted"] = False
    if name == "bash":
        return 0, b"busybox\0/x\0"
    if name == "tar":
        open(ready, "w").close()
        time.sleep(60)
    return 0, b""

image.run = run
image.is_mounted = lambda p: state["mounted"]
image.os.geteuid = lambda: 0
image.config.load = lambda root: types.SimpleNamespace(
    SCRATCH_DIR=sys.argv[4], TARBALL_DIR=sys.argv[4], SCRIPT_DIR="/nonexistent/",
    FIRMAE_BOOT="true", FIRMAE_ETC="true")
os.environ["USER"] = "root"
sys.exit(image.main(["1", "mipsel"]))
'''


@pytest.mark.parametrize("sig,code", [(signal.SIGINT, 130), (signal.SIGTERM, 143), (signal.SIGHUP, 129)])
def test_signal_during_a_step_unmounts_and_releases(repo_root, tmp_path, sig, code):
    drv, log, ready = tmp_path / "drv.py", tmp_path / "log", tmp_path / "ready"
    drv.write_text(DRIVER)
    scratch = tmp_path / "scratch"
    (scratch / "1").mkdir(parents=True)
    (scratch / "1.tar.gz").write_bytes(b"")
    proc = subprocess.Popen([sys.executable, "-I", str(drv), str(repo_root), str(log), str(ready), str(scratch)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 30
        while not ready.exists():
            assert proc.poll() is None, proc.stdout.read().decode()[-2000:]
            assert time.time() < deadline
            time.sleep(0.05)
        proc.send_signal(sig)
        out, _ = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert proc.returncode == code, out.decode()[-2000:]
    calls = log.read_text().split()
    assert calls[-3:] == ["tar", "umount", "del_partition"], calls


# ---------------------------------------------------------------- run()

def _dead(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    try:
        with open("/proc/%d/stat" % pid) as f:      # a zombie waiting for its reaper is dead too
            return f.read().rsplit(")", 1)[1].split()[0] == "Z"
    except (FileNotFoundError, ProcessLookupError):
        return True


def _wait_dead(pids, seconds, what="process"):
    deadline = time.time() + seconds
    while not all(_dead(p) for p in pids):
        assert time.time() < deadline, "%s survived: %s" % (what, [p for p in pids if not _dead(p)])
        time.sleep(0.05)


def _read_pids(path, count, seconds=20, proc=None):
    deadline = time.time() + seconds
    while True:
        try:
            pids = [int(x) for x in path.read_text().split()]
        except (FileNotFoundError, ValueError):
            pids = []
        if len(pids) >= count:
            return pids
        if proc is not None:
            assert proc.poll() is None, proc.stdout.read().decode()[-2000:]
        assert time.time() < deadline, "no pids in %s" % path
        time.sleep(0.05)


def test_run_timeout_stops_the_whole_process_group(tmp_path, monkeypatch):
    monkeypatch.setattr(image, "STOP_GRACE", 2)
    pidfile = tmp_path / "pid"
    t = time.time()
    with pytest.raises(image.ImageError, match="timed out after 1s"):
        image.run(["sh", "-c", 'sleep 60 & echo $! > "$0"; wait', str(pidfile)], 1)
    assert time.time() - t < 15
    _wait_dead([int(pidfile.read_text())], 10, "grandchild")


def test_run_normal_exit_kills_what_the_command_left_behind(tmp_path):
    """The command exits at once but leaves a background child (as a firmware
    script run by chroot could): run() returns promptly and the child is gone."""
    pidfile = tmp_path / "pid"
    t = time.time()
    rc, out = image.run(["sh", "-c", 'sleep 60 > /dev/null 2>&1 & echo $! > "$0"; exit 0', str(pidfile)], 30)
    assert (rc, out) == (0, None)
    assert time.time() - t < 5
    pid = int(pidfile.read_text())
    _wait_dead([pid], 2, "background child")


def test_run_puts_the_command_in_a_guarded_group_of_our_session():
    """Not in image.py's process group (the pipeline's SIGINT to that group must
    not cut a cleanup umount short), but in the same session, led by the guard."""
    rc, out = image.run(["sh", "-c", 'cat /proc/$$/stat; cat "/proc/$(cut -d" " -f5 /proc/$$/stat)/cmdline"'],
                        10, capture=True)
    assert rc == 0
    stat_line, guard_cmdline = out.split(b"\n", 1)
    fields = stat_line.rsplit(b")", 1)[1].split()
    pgrp, session = int(fields[2]), int(fields[3])
    assert pgrp != os.getpgrp() and session == os.getsid(0)
    assert guard_cmdline.split(b"\0")[:2] == [b"/bin/sh", b"-c"]
    assert b"kill -s KILL 0" in guard_cmdline
    _wait_dead([pgrp], 2, "guard")


def test_run_stdin_defaults_to_dev_null():
    rc, out = image.run(["sh", "-c", "readlink /proc/$$/fd/0"], 10, capture=True)
    assert (rc, out) == (0, b"/dev/null\n")


SIGKILL_DRIVER = r'''
import sys
sys.path.insert(0, sys.argv[1])
from firmae import image
print("pid", flush=True)
image.run(["sh", "-c", 'sleep 300 > /dev/null 2>&1 & echo $! > "$0"; echo $$ >> "$0"; wait', sys.argv[2]], 600)
'''


def test_sigkill_of_image_py_leaves_no_command_behind(repo_root, tmp_path):
    """The pipeline SIGKILLs makeImage.sh (= image.py) when its grace is over;
    the command (and what it started) must not keep running against the
    mounted image. Real processes, no root."""
    drv, pidfile = tmp_path / "drv.py", tmp_path / "pids"
    drv.write_text(SIGKILL_DRIVER)
    proc = subprocess.Popen([sys.executable, "-I", str(drv), str(repo_root), str(pidfile)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    pids = []
    try:
        pids = _read_pids(pidfile, 2, proc=proc)
        with open("/proc/%d/stat" % pids[1]) as f:
            group = int(f.read().rsplit(")", 1)[1].split()[2])        # pgrp of the command
        assert group != os.getpgid(proc.pid)          # not hit by a signal to image.py's group
        assert not any(_dead(p) for p in pids + [group])
        proc.kill()
        proc.wait(timeout=10)
        _wait_dead(sorted(set(pids + [group])), 5, "command of the killed image.py")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        for p in pids:                      # never leave a sleep 300 behind, whatever happened
            with contextlib.suppress(OSError):
                os.kill(p, signal.SIGKILL)


def test_run_exception_while_waiting_stops_the_child(tmp_path, monkeypatch):
    monkeypatch.setattr(image, "STOP_GRACE", 2)
    started = []
    real_popen = subprocess.Popen

    class Popen(real_popen):
        def communicate(self, *a, **k):
            started.append(self.pid)
            raise KeyboardInterrupt
    monkeypatch.setattr(image.subprocess, "Popen", Popen)
    with pytest.raises(KeyboardInterrupt):
        image.run(["sleep", "60"], 30)
    with pytest.raises(ProcessLookupError):
        os.kill(started[0], 0)       # reaped by _stop's wait


def test_run_reports_missing_commands_and_exit_codes():
    with pytest.raises(image.ImageError) as e:
        image.run(["/nonexistent/qemu-img"], 5)
    assert e.value.code == 127
    assert image.run(["sh", "-c", "exit 3"], 5) == (3, None)
    assert image.run(["printf", "x"], 5, capture=True) == (0, b"x")
    with pytest.raises(image.ImageError) as e:
        image.check(["sh", "-c", "exit 4"], 5)
    assert e.value.code == 4
    with pytest.raises(image.ImageError) as e:
        image.check(["sh", "-c", "kill -TERM $$"], 5)
    assert e.value.code == 143


def test_no_shell_is_used(repo_root):
    src = (repo_root / "firmae/image.py").read_text()
    assert "shell=True" not in src and "os.system" not in src and "os.popen" not in src


def test_binaries_come_from_firmae_config(repo_root):
    got = image.binaries(str(repo_root), "mipsel")
    names = [n for n, _ in got]
    assert names == ["busybox", "console", "gdb", "gdbserver", "strace", "libnvram.so", "libnvram_ioctl.so"]
    assert all(p == "%s/binaries//%s.mipsel" % (repo_root, n) for n, p in got)
    with pytest.raises(image.ImageError, match="Invalid architecture"):
        image.binaries(str(repo_root), "x86")


# ---------------------------------------------------------------- symlinks planted in the image

# The "Setting up FIRMADYNE" block of the old scripts/makeImage.sh (commit
# 38d1bb0, lines 120-158), verbatim. mknod is replaced by a function (needs root).
OLD_SETUP_BLOCK = r'''
image_path () {
    python3 "${SCRIPT_DIR}/imagepath.py" "${IMAGE_DIR}" "${@}"
}
echo "----Setting up FIRMADYNE----"
for BINARY_NAME in "${BINARIES[@]}"
do
    BINARY_PATH=`get_binary ${BINARY_NAME} ${ARCH}`
    cp "${BINARY_PATH}" "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
    chmod a+x "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
done
mknod -m 666 "${IMAGE_DIR}/firmadyne/ttyS1" c 4 65

cp "${SCRIPT_DIR}/preInit.sh" "${IMAGE_DIR}/firmadyne/preInit.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/preInit.sh"

cp "${SCRIPT_DIR}/network.sh" "${IMAGE_DIR}/firmadyne/network.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/network.sh"

cp "${SCRIPT_DIR}/run_service.sh" "${IMAGE_DIR}/firmadyne/run_service.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/run_service.sh"

INJECTION_CHECKER=`image_path /bin/a --no-follow-final`
if [ ! -d "${INJECTION_CHECKER%/*}" ] || [ -L "${INJECTION_CHECKER%/*}" ]; then
    echo "Error: /bin of the image is not a directory"
    exit 1
fi
rm -f -- "${INJECTION_CHECKER}"
cp -- "${SCRIPT_DIR}/injectionChecker.sh" "${INJECTION_CHECKER}"
chmod a+x "${INJECTION_CHECKER}"

touch "${IMAGE_DIR}/firmadyne/debug.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/debug.sh"

if (! ${FIRMAE_ETC}); then
  sed -i 's/sleep 60/sleep 15/g' "${IMAGE_DIR}/firmadyne/network.sh"
  sed -i 's/sleep 120/sleep 30/g' "${IMAGE_DIR}/firmadyne/run_service.sh"
  sed -i 's@/firmadyne/sh@/bin/sh@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
  sed -i 's@BUSYBOX=/firmadyne/busybox@BUSYBOX=@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
fi
'''

OLD_PRELUDE = r'''set -e
set -u
BINARIES=( "busybox" "console" "libnvram.so" )
get_binary () { echo "${BIN}/${1}"; }
mknod () { : > "${3}"; }
'''


def _fake_image(tmp_path, name):
    img = tmp_path / name
    (img / "firmadyne").mkdir(parents=True)
    (img / "bin").mkdir()
    return img


def _run_old(world, img, etc="true"):
    script = world.tmp / "old.sh"
    script.write_text(OLD_PRELUDE + OLD_SETUP_BLOCK)
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60,
                          env=dict(os.environ, IMAGE_DIR=str(img), SCRIPT_DIR=world.cfg.SCRIPT_DIR,
                                   BIN=str(world.bin), ARCH="mipsel", FIRMAE_ETC=etc))


def _run_new(world, img, etc=True):
    image.setup_firmadyne(str(img), world.binaries, world.cfg.SCRIPT_DIR, etc)


def _tree(root):
    out = {}
    for d, dirs, files in os.walk(str(root)):
        for n in dirs + files:
            p = os.path.join(d, n)
            rel = os.path.relpath(p, str(root))
            st = os.lstat(p)
            data = (open(p, "rb").read() if stat.S_ISREG(st.st_mode) else
                    os.readlink(p) if stat.S_ISLNK(st.st_mode) else None)
            out[rel] = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), data)
    return out


@pytest.mark.parametrize("etc", ["true", "false"])
@pytest.mark.parametrize("umask", [0o022, 0o077])
def test_setup_block_produces_what_the_old_block_produced(world, tmp_path, etc, umask):
    old_img, new_img = _fake_image(tmp_path, "old"), _fake_image(tmp_path, "new")
    old_mask = os.umask(umask)
    try:
        res = _run_old(world, old_img, etc)
        assert res.returncode == 0, res.stderr
        _run_new(world, new_img, etc == "true")
    finally:
        os.umask(old_mask)
    old, new = _tree(old_img), _tree(new_img)
    # mknod -m 666 vs. the stand-ins: compare the requested mode instead
    old.pop("firmadyne/ttyS1")
    new.pop("firmadyne/ttyS1")
    assert world.devices == [("ttyS1", 0o666, 4, 65)]
    assert new == old


@pytest.mark.characterization
def test_old_block_wrote_through_a_symlink_inferfile_can_create(world, tmp_path):
    """inferFile.sh, run chroot'ed, turns a kernel `init=/firmadyne/console`
    string into `ln -s /bin/<a binary> /firmadyne/console` (inferFile.sh:33-41:
    the path does not exist yet, so a binary mentioning "console" is linked
    there). The old host-side `cp` followed that absolute link on the HOST.
    Here the link points straight at a host file of the test."""
    img = _fake_image(tmp_path, "old")
    os.symlink(str(world.host / "victim"), str(img / "firmadyne/console"))
    res = _run_old(world, img)
    assert res.returncode == 0, res.stderr
    assert (world.host / "victim").read_bytes() == (world.bin / "console").read_bytes()   # host file overwritten
    assert _mode(world.host / "victim") & 0o111                                           # and made executable
    assert os.path.islink(str(img / "firmadyne/console"))


@pytest.mark.parametrize("name", ["console", "busybox", "libnvram.so", "preInit.sh", "network.sh",
                                  "run_service.sh", "debug.sh", "ttyS1"])
def test_new_block_replaces_such_symlinks(world, tmp_path, name):
    img = _fake_image(tmp_path, "new")
    os.symlink(str(world.host / "victim"), str(img / "firmadyne" / name))
    _run_new(world, img, etc=False)              # with the sed edits too
    assert (world.host / "victim").read_bytes() == b"host data\n"
    assert _mode(world.host / "victim") == 0o644 or not _mode(world.host / "victim") & 0o111
    p = img / "firmadyne" / name
    assert not p.is_symlink() and p.is_file()


def test_relative_symlink_and_symlinked_firmadyne_stay_inside_the_image(world, tmp_path):
    img = _fake_image(tmp_path, "new")
    (img / "firmadyne").rmdir()
    (img / "elsewhere").mkdir()
    os.symlink("/elsewhere", str(img / "firmadyne"))          # re-rooted at the image
    os.symlink("../../../../../../../../.." + str(world.host / "victim"), str(img / "elsewhere/console"))
    _run_new(world, img)
    assert (world.host / "victim").read_bytes() == b"host data\n"
    assert (img / "elsewhere/console").read_bytes() == (world.bin / "console").read_bytes()


@pytest.mark.parametrize("target", ["absolute", "relative"])
def test_edit_file_refuses_a_symlink(tmp_path, target):
    """The FIRMAE_ETC=false `sed -i` edits: a guest script replaced by a symlink
    (to a host file) is refused; the target stays unchanged."""
    d = tmp_path / "img/firmadyne"
    d.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_bytes(b"sleep 60\n/firmadyne/sh\n")
    os.symlink(str(victim) if target == "absolute" else "../../victim", str(d / "network.sh"))
    fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(image.ImageError, match="cannot open /firmadyne/network.sh"):
            image.edit_file(fd, "network.sh", dict(image.ETC_OFF_EDITS)["network.sh"], "/firmadyne/network.sh")
    finally:
        os.close(fd)
    assert victim.read_bytes() == b"sleep 60\n/firmadyne/sh\n"
    assert os.path.islink(str(d / "network.sh"))


@pytest.mark.parametrize("planted", ["symlink", "file", "fifo", "none"])
def test_make_char_device_removes_the_old_entry_and_uses_the_dir_fd(tmp_path, monkeypatch, planted):
    """The real make_char_device (the fixture replaces it: mknod needs root),
    with os.mknod recorded: whatever had the name is gone before mknod, which
    gets a bare name relative to the directory descriptor (never a path that
    could follow a symlink), the exact mode and device numbers, umask 0."""
    d = tmp_path / "img/firmadyne"
    d.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_bytes(b"host data\n")
    p = d / "ttyS1"
    if planted == "symlink":
        os.symlink(str(victim), str(p))
    elif planted == "file":
        p.write_bytes(b"x")
    elif planted == "fifo":
        os.mkfifo(str(p))
    calls = []
    real_mknod = os.mknod

    def mknod(path, mode=0o600, device=0, *, dir_fd=None):
        mask = os.umask(0o077)
        os.umask(mask)
        calls.append((path, mode, device, dir_fd, mask))
        assert isinstance(dir_fd, int) and os.path.samestat(os.fstat(dir_fd), os.stat(str(d)))
        try:
            os.lstat(path, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(17, "File exists")         # what mknod(2) does
        real_mknod(path, stat.S_IFIFO | 0o600, dir_fd=dir_fd)  # a stand-in node (no root)
    monkeypatch.setattr(image.os, "mknod", mknod)
    fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY)
    try:
        image.make_char_device(fd, "ttyS1", 0o666, 4, 65)
        assert calls == [("ttyS1", stat.S_IFCHR | 0o666, os.makedev(4, 65), fd, 0)]
    finally:
        os.close(fd)
    assert victim.read_bytes() == b"host data\n"
    assert not os.path.islink(str(p)) and stat.S_ISFIFO(os.lstat(str(p)).st_mode)
    assert sorted(os.listdir(str(tmp_path))) == ["img", "victim"]


def test_make_char_device_refuses_a_directory(tmp_path, monkeypatch):
    d = tmp_path / "firmadyne"
    (d / "ttyS1").mkdir(parents=True)
    monkeypatch.setattr(image.os, "mknod", lambda *a, **k: pytest.fail("mknod called"))
    fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(image.ImageError, match="is a directory"):
            image.make_char_device(fd, "ttyS1", 0o666, 4, 65)
    finally:
        os.close(fd)


def test_directory_in_place_of_a_file_is_an_error(world, tmp_path):
    img = _fake_image(tmp_path, "new")
    (img / "firmadyne/console").mkdir()
    with pytest.raises(image.ImageError, match="is a directory"):
        _run_new(world, img)


def test_symlink_from_infer_file_through_the_whole_flow(world):
    """End to end: what inferFile.sh leaves in /firmadyne is replaced."""
    world.infer = lambda mnt: os.symlink(str(world.host / "victim"), str(mnt / "firmadyne/console"))
    world.build()
    assert (world.host / "victim").read_bytes() == b"host data\n"
    assert not (world.mnt / "firmadyne/console").is_symlink()


# ---------------------------------------------------------------- copying results out

def _results_image(tmp_path):
    img = tmp_path / "img"
    (img / "firmadyne").mkdir(parents=True)
    work = tmp_path / "work"
    work.mkdir()
    return img, work


def test_init_symlink_is_refused(tmp_path):
    img, work = _results_image(tmp_path)
    (tmp_path / "secret").write_text("root:x:0:0\n")
    os.symlink(str(tmp_path / "secret"), str(img / "firmadyne/init"))
    with pytest.raises(image.ImageError, match="symlink"):
        image.take_result(str(img), "init", str(work), move=True)
    assert not os.path.lexists(str(work / "init"))


def test_init_fifo_is_refused_without_blocking(tmp_path):
    img, work = _results_image(tmp_path)
    os.mkfifo(str(img / "firmadyne/init"))
    with pytest.raises(image.ImageError, match="not a regular file"):
        image.take_result(str(img), "init", str(work), move=True)


def test_missing_init_is_an_error_as_mv_was(tmp_path):
    img, work = _results_image(tmp_path)
    with pytest.raises(image.ImageError, match="No such file"):
        image.take_result(str(img), "init", str(work), move=True)


def test_oversized_init_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(image, "MAX_RESULT_BYTES", 10)
    img, work = _results_image(tmp_path)
    (img / "firmadyne/init").write_bytes(b"x" * 11)
    with pytest.raises(image.ImageError, match="larger than 10 bytes"):
        image.take_result(str(img), "init", str(work), move=True)


def test_init_replaces_a_symlink_in_the_work_dir(tmp_path):
    img, work = _results_image(tmp_path)
    (img / "firmadyne/init").write_bytes(b"/sbin/init\n")
    (tmp_path / "target").write_text("keep\n")
    os.symlink(str(tmp_path / "target"), str(work / "init"))
    assert image.take_result(str(img), "init", str(work), move=True)
    assert (work / "init").read_bytes() == b"/sbin/init\n" and not (work / "init").is_symlink()
    assert (tmp_path / "target").read_text() == "keep\n"
    assert not os.path.lexists(str(img / "firmadyne/init"))
    assert sorted(os.listdir(str(work))) == ["init"]          # no temporary file left


@pytest.mark.parametrize("kind", ["symlink", "fifo", "dir", "missing"])
def test_service_that_is_not_a_regular_file_is_skipped(tmp_path, kind):
    img, work = _results_image(tmp_path)
    p = img / "firmadyne/service"
    if kind == "symlink":
        (tmp_path / "secret").write_text("x")
        os.symlink(str(tmp_path / "secret"), str(p))
    elif kind == "fifo":
        os.mkfifo(str(p))
    elif kind == "dir":
        p.mkdir()
    assert image.take_result(str(img), "service", str(work), move=False) is False
    assert not os.path.lexists(str(work / "service"))


def test_service_is_copied_not_moved(tmp_path):
    img, work = _results_image(tmp_path)
    (img / "firmadyne/service").write_bytes(b"/bin/boa")
    assert image.take_result(str(img), "service", str(work), move=False)
    assert (work / "service").read_bytes() == b"/bin/boa"
    assert (img / "firmadyne/service").exists()


def test_firmadyne_replaced_by_a_symlink_to_the_host_is_resolved_inside(tmp_path):
    img, work = _results_image(tmp_path)
    (img / "firmadyne").rmdir()
    host = tmp_path / "hostdir"
    host.mkdir()
    (host / "init").write_text("host\n")
    os.symlink(str(host), str(img / "firmadyne"))        # absolute: means <img>/<host path>
    with pytest.raises(image.ImageError):
        image.take_result(str(img), "init", str(work), move=True)
    assert (host / "init").exists()                      # not touched (not moved out)


# ---------------------------------------------------------------- top-level helpers

def test_put_top_replaces_a_planted_symlink(tmp_path):
    img = tmp_path / "img"
    img.mkdir()
    (tmp_path / "victim").write_text("host\n")
    os.symlink(str(tmp_path / "victim"), str(img / "busybox"))
    src = tmp_path / "bb"
    src.write_bytes(b"bb")
    src.chmod(0o755)
    image.put_top(str(img), str(src), "busybox")
    assert (tmp_path / "victim").read_text() == "host\n"
    assert (img / "busybox").read_bytes() == b"bb" and not (img / "busybox").is_symlink()
    image.remove_top(str(img), "busybox")
    with pytest.raises(image.ImageError, match="No such file"):
        image.remove_top(str(img), "busybox")
    image.remove_top(str(img), "busybox", missing_ok=True)


def test_put_top_without_the_tool_is_an_error(tmp_path):
    with pytest.raises(image.ImageError, match="bash-static not found"):
        image.put_top(str(tmp_path), None, "bash-static")


@pytest.mark.parametrize("planted", ["dir", "symlink", "sub"])
def test_existing_firmadyne_fails_as_mkdir_did(tmp_path, planted):
    img = tmp_path / "img"
    img.mkdir()
    if planted == "dir":
        (img / "firmadyne").mkdir()
    elif planted == "symlink":
        os.symlink("/tmp", str(img / "firmadyne"))
    with pytest.raises(image.ImageError, match="File exists") if planted != "sub" else contextlib.nullcontext():
        image.make_firmadyne_dirs(str(img))
    if planted == "sub":
        assert sorted(os.listdir(str(img / "firmadyne"))) == ["libnvram", "libnvram.override"]


# ---------------------------------------------------------------- the wrapper

def _wrapper(repo_root, args, cwd=None, env=None):
    return subprocess.run(["bash", str(repo_root / "scripts/makeImage.sh")] + args, cwd=str(cwd or repo_root),
                          env=env, capture_output=True, text=True, timeout=60)


def test_wrapper_is_thin(repo_root):
    data = (repo_root / "scripts/makeImage.sh").read_bytes()
    assert b"\r\n" not in data
    lines = [l for l in data.decode().splitlines() if l and not l.startswith("#")]
    assert lines == ['FIRMAE_HOME="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null && pwd)"',
                     'exec python3 -I "${FIRMAE_HOME}/firmae/image.py" "$@"']
    assert os.access(str(repo_root / "scripts/makeImage.sh"), os.X_OK)


@pytest.mark.parametrize("how", ["relative", "dot-slash", "absolute"])
def test_wrapper_finds_its_installation_with_cdpath_exported(repo_root, tmp_path, how):
    """With CDPATH exported, a plain `cd` prints the directory it found, and
    that output became part of FIRMAE_HOME. A copy of the wrapper in a fake
    installation whose image.py reports the path it was started from."""
    inst = tmp_path / "inst"
    (inst / "scripts").mkdir(parents=True)
    (inst / "firmae").mkdir()
    wrapper = inst / "scripts/makeImage.sh"
    wrapper.write_bytes((repo_root / "scripts/makeImage.sh").read_bytes())
    wrapper.chmod(0o755)
    (inst / "firmae/image.py").write_text("import sys\nprint('IMAGE_PY=' + sys.argv[0])\n")
    decoy = tmp_path / "decoy"
    (decoy / "scripts").mkdir(parents=True)        # CDPATH entry with the same relative names
    (decoy / "inst" / "scripts").mkdir(parents=True)
    cmd = {"relative": ["bash", "inst/scripts/makeImage.sh"],
           "dot-slash": ["./scripts/makeImage.sh"],
           "absolute": [str(wrapper)]}[how]
    cwd = tmp_path if how == "relative" else inst
    res = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=60,
                         env=dict(os.environ, CDPATH="%s:%s:." % (decoy, tmp_path)))
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout.splitlines() == ["IMAGE_PY=%s/firmae/image.py" % os.path.realpath(str(inst))]


@pytest.mark.parametrize("args", [[], ["abc"], ["-1"], ["1x", "mipsel"], [""]])
def test_wrapper_usage_errors(repo_root, args):
    res = _wrapper(repo_root, args)
    assert res.returncode == 1
    assert "Usage: makeImage.sh <image ID> [<architecture>]" in res.stdout


@pytest.mark.skipif(sys.platform.startswith("linux") and os.geteuid() == 0, reason="runs as root")
def test_wrapper_requires_root(repo_root):
    res = _wrapper(repo_root, ["1", "mipsel", "file.zip"])
    assert res.returncode == 1
    assert "Error: This script requires root privileges!" in res.stdout


@pytest.mark.skipif(sys.platform.startswith("linux") and os.geteuid() == 0, reason="runs as root")
def test_hostile_cwd_and_pythonpath_are_ignored(repo_root, tmp_path):
    evil = tmp_path / "evil"
    for pkg in ("firmae", "scripts"):
        (evil / pkg).mkdir(parents=True)
        (evil / pkg / "__init__.py").write_text("raise SystemExit('hijacked')\n")
    (evil / "re.py").write_text("raise SystemExit('hijacked')\n")
    res = _wrapper(repo_root, ["1", "mipsel"], cwd=evil,
                   env=dict(os.environ, PYTHONPATH=str(evil), PYTHONSTARTUP=str(evil / "re.py")))
    assert "hijacked" not in res.stdout + res.stderr
    assert "requires root" in res.stdout


def test_main_checks_order(monkeypatch, capsys):
    monkeypatch.setattr(image.os, "geteuid", lambda: 1000)
    assert image.main(["x"]) == 1 and "Usage" in capsys.readouterr().out
    assert image.main(["1"]) == 1 and "requires root" in capsys.readouterr().out
    monkeypatch.setattr(image.os, "geteuid", lambda: 0)
    assert image.main(["1"]) == 1 and "missing <architecture>" in capsys.readouterr().out


def test_main_maps_errors_to_exit_codes(world, monkeypatch, capsys):
    monkeypatch.setattr(image.os, "geteuid", lambda: 0)
    monkeypatch.setattr(image.config, "load", lambda root: world.cfg)
    monkeypatch.setattr(image, "raise_on_sigterm", lambda: None)
    assert image.main(["1", "mipsel", "f.zip"], root=world.root) == 0
    world.rc["tar"] = 2
    assert image.main(["1", "mipsel"], root=world.root) == 2
    assert "tar failed with exit 2" in capsys.readouterr().out
    world.rc.clear()

    def interrupt(argv):
        raise KeyboardInterrupt
    world.hooks["tar"] = interrupt
    assert image.main(["1", "mipsel"], root=world.root) == 130
    assert not world.mounted and not world.loops
