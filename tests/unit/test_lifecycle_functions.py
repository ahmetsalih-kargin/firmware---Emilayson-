"""Lifecycle helpers in firmae.config (REFACTORING_PLAN Phase 3):
qemu_pids/stop_qemu, wait_for_exit, add_partition timeout, release_emulation.

The "QEMU" processes are harmless sleepers whose command line looks like a
QEMU of a given image; nothing real is emulated, mounted or detached.
"""

import os
import shutil
import subprocess
import time

import pytest

pytestmark = pytest.mark.linux

SLEEPER = "import signal,time\n%s\ntime.sleep(600)"


def alive(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except FileNotFoundError:
        return False


@pytest.fixture
def fake_qemus(tmp_path):
    procs = []

    def start(name, image=None, ignore_term=False):
        code = SLEEPER % ("signal.signal(signal.SIGTERM, signal.SIG_IGN)" if ignore_term else "")
        args = 'exec -a %s python3 -c "$1"' % name
        if image:
            args += ' -drive "file=%s"' % image
        p = subprocess.Popen(["bash", "-c", args, "_", code])
        procs.append(p)
        return p

    yield start
    for p in procs:
        if p.poll() is None:
            p.kill()
        p.wait()


def wait_started(procs):
    """Wait until every fake process has exec'd (its cmdline shows the name)."""
    for p in procs:
        for _ in range(100):
            try:
                with open("/proc/%d/cmdline" % p.pid, "rb") as f:
                    if f.read().startswith(b"qemu-system-"):
                        break
            except FileNotFoundError:
                break
            time.sleep(0.05)


def cfg(repo_root, script, env=None, extra_path=None):
    e = dict(os.environ)
    e.pop("FIRMAE_DOCKER", None)
    if extra_path:
        e["PATH"] = "%s:%s" % (extra_path, e["PATH"])
    e.update(env or {})
    return subprocess.run(["bash", "-c", "source ./firmae.config && " + script],
                          cwd=repo_root, env=e, capture_output=True, text=True, timeout=120)


def test_stop_qemu_stops_only_the_given_image(repo_root, fake_qemus):
    mine = fake_qemus("qemu-system-arm", "/w/scratch/1/image.raw")
    stubborn = fake_qemus("qemu-system-mips", "/w/scratch/1/image.raw", ignore_term=True)
    other_iid = fake_qemus("qemu-system-arm", "/w/scratch/11/image.raw")
    mipsel = fake_qemus("qemu-system-mipsel", "/w/scratch/2/image.raw")
    sentinel = fake_qemus("qemu-system-arm-SENTINEL")       # Phase 0 sentinel: no image
    wait_started([mine, stubborn, other_iid, mipsel, sentinel])

    res = cfg(repo_root, "qemu_pids 1")
    assert sorted(map(int, res.stdout.split())) == sorted([mine.pid, stubborn.pid])

    t0 = time.time()
    res = cfg(repo_root, "QEMU_STOP_GRACE=1; stop_qemu 1")
    assert res.returncode == 0, res.stderr
    assert time.time() - t0 < 10
    for p in (mine, stubborn):
        p.wait(timeout=5)
    assert stubborn.returncode == -9            # ignored SIGTERM -> SIGKILL after the grace
    for p in (other_iid, mipsel, sentinel):
        assert alive(p.pid), "an unrelated QEMU was stopped"


def test_stop_qemu_without_qemu_is_a_noop(repo_root):
    assert cfg(repo_root, "stop_qemu 424242; echo ok").stdout.strip() == "ok"


def test_wait_for_exit_kills_at_the_deadline(repo_root):
    t0 = time.time()
    res = cfg(repo_root, '{ sleep 600 > /dev/null 2>&1 & p=$!; wait_for_exit $p 1; '
                         'kill -0 $p 2>/dev/null && echo alive || echo gone; }')
    assert res.stdout.strip() == "gone"
    assert time.time() - t0 < 10


def stub(d, name, body):
    p = d / name
    p.write_text("#!/bin/bash\n" + body + "\n")
    p.chmod(0o755)


def test_add_partition_gives_up_instead_of_waiting_forever(repo_root, tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "log"
    stub(bindir, "losetup", 'echo "losetup $*" >> %s; [ "$1" = --find ] && echo /dev/no-such-loop9' % log)
    t0 = time.time()
    res = cfg(repo_root, "PARTITION_TIMEOUT=1; add_partition /x/image.raw", extra_path=bindir)
    assert res.returncode == 1 and res.stdout == ""
    assert "did not appear" in res.stderr
    assert log.read_text().splitlines() == ["losetup --find --show --partscan /x/image.raw",
                                            "losetup -d /dev/no-such-loop9"]
    assert time.time() - t0 < 10


def test_add_partition_waits_until_the_device_is_really_ready(repo_root, tmp_path):
    """Regression (found in review): after `losetup --partscan` the node can exist
    and then be re-created while udev works on it; mount then failed with ENOENT.
    The device must be ready, udev settled, and still ready afterwards."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "log"
    stub(bindir, "losetup", 'echo /dev/fakeloop0')
    stub(bindir, "udevadm", 'echo "udevadm $*" >> %s' % log)
    script = '''
        PARTITION_TIMEOUT=10
        seq=(0 0 1 0 1 1); n=0                       # not ready, not ready, ready, GONE, ready, ready
        partition_ready () { local r=${seq[n]:-1}; n=$((n+1)); [ "$r" = 1 ]; }
        add_partition /x/image.raw > "%s"            # not in $(...): the counter must live in this shell
        echo "`cat "%s"` calls=$n"
    ''' % (tmp_path / "out", tmp_path / "out")
    res = cfg(repo_root, script, extra_path=bindir)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "/dev/fakeloop0p1 calls=6"      # did not return at the first ready answer
    assert log.read_text().splitlines() == ["udevadm settle --timeout=10"] * 2


def test_mount_partition_retries_a_failing_mount(repo_root, tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    state = tmp_path / "n"
    state.write_text("0")
    stub(bindir, "mount", 'n=$(($(cat %s)+1)); echo $n > %s; echo "mount $*" >> %s; [ $n -ge 3 ]' % (state, state, tmp_path / "log"))
    stub(bindir, "sleep", "exit 0")
    res = cfg(repo_root, 'mount_partition /dev/loop1p1 /mnt/x; echo rc=$?', extra_path=bindir)
    assert res.stdout.strip() == "rc=0"
    assert (tmp_path / "log").read_text().count("mount /dev/loop1p1 /mnt/x") == 3
    state.write_text("-100")                               # never succeeds
    res = cfg(repo_root, 'mount_partition /dev/loop1p1 /mnt/x; echo rc=$?', extra_path=bindir)
    assert res.stdout.strip() == "rc=1"


def test_partition_ready_needs_a_block_device_with_a_size(repo_root, tmp_path):
    res = cfg(repo_root, 'partition_ready /nonexistent && echo yes || echo no')
    assert res.stdout.strip() == "no"
    (tmp_path / "plain_file").write_text("x")
    assert cfg(repo_root, 'partition_ready "%s" && echo yes || echo no' % (tmp_path / "plain_file")).stdout.strip() == "no"


def test_release_emulation_frees_everything_of_one_image(repo_root, tmp_path, fake_qemus):
    root = tmp_path / "FirmAE"
    (root / "scratch" / "1" / "image").mkdir(parents=True)
    (root / "scratch" / "1" / "image.raw").write_text("")
    shutil.copy(repo_root / "firmae.config", root)
    img = str(root / "scratch" / "1" / "image.raw")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "log"
    rec = 'echo "$(basename $0) $*" >> %s' % log
    stub(bindir, "mountpoint", rec + "; exit 0")
    stub(bindir, "umount", rec)
    stub(bindir, "losetup", rec + '; [ "$1" = -j ] && echo "/dev/loop5: []: (%s)" && echo "/dev/loop6: []: (%s)"' % (img, img))
    stub(bindir, "ip", rec + '; [ "$1" = -o ] && printf "%s\\n" "4: tap1_0: <UP>" "5: tap1_0.2@tap1_0: <UP>" "6: tap11_0: <UP>" "7: eth0: <UP>"')
    stub(bindir, "rm", rec)
    for fw in ("iptables", "ip6tables"):          # release_emulation also removes firewall rules
        stub(bindir, fw, "exit 1")
    qemu = fake_qemus("qemu-system-arm", img)
    other = fake_qemus("qemu-system-arm", str(root / "scratch" / "11" / "image.raw"))
    wait_started([qemu, other])

    res = cfg(root, "QEMU_STOP_GRACE=1; release_emulation 1; release_emulation 1", extra_path=bindir)
    assert res.returncode == 0, res.stderr
    qemu.wait(timeout=5)
    assert alive(other.pid)
    calls = log.read_text().splitlines()
    first = calls[: len(calls) // 2]            # release_emulation is idempotent: same calls twice
    assert first == [
        "mountpoint -q %s/scratch/1/image" % root,
        "umount %s/scratch/1/image" % root,
        "losetup -j %s" % img,
        "losetup -d /dev/loop5",
        "losetup -d /dev/loop6",
        "ip -o link show",
        "ip link delete tap1_0.2",
        "ip link delete tap1_0",
        "rm -f %s/scratch/1/run/*.sock /tmp/qemu.1 /tmp/qemu.1.S1" % root,
    ]
