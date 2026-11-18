"""Lifecycle helpers in firmae.config (REFACTORING_PLAN Phase 3):
qemu_pids/stop_qemu, wait_for_exit, add_partition timeout, release_emulation.

The "QEMU" processes are harmless sleepers whose command line looks like a
QEMU of a given image; nothing real is emulated, mounted or detached.

Hermetic: every test that looks for or stops QEMU processes runs firmae.config
from its own installation under tmp_path, and qemu_pids matches only that
installation's full SCRATCH_DIR path -- a real emulation on this machine (even
of the same IID) can never be matched, let alone signalled.
"""

import os
import shutil
import subprocess
import time

import pytest

pytestmark = pytest.mark.linux

SLEEPER = "import signal,time\n%s\ntime.sleep(600)"


@pytest.fixture
def install(repo_root, tmp_path):
    """An installation of its own: <tmp>/inst.a[1]/FirmAE (regex characters in
    the path on purpose) with scratch/<IID>/image.raw for IIDs 1, 2, 11."""
    root = tmp_path / "inst.a[1]" / "FirmAE"
    for iid in ("1", "2", "11"):
        (root / "scratch" / iid).mkdir(parents=True)
        (root / "scratch" / iid / "image.raw").write_text("")
    shutil.copy(repo_root / "firmae.config", root)
    return root


def image(root, iid):
    return "%s/scratch/%s/image.raw" % (root, iid)


def alive(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
        return False   # gone, or reaped while /proc/<pid>/stat was read (empty/truncated)


@pytest.fixture
def fake_qemus(tmp_path):
    procs = []

    def start(name, image=None, ignore_term=False, drive="if=ide,format=raw,file=%s"):
        """image: path in the -drive argument (as scripts/run.<arch>.sh write it)."""
        code = SLEEPER % ("signal.signal(signal.SIGTERM, signal.SIG_IGN)" if ignore_term else "")
        argv = ["bash", "-c", 'exec -a "$1" python3 -c "$2" "${@:3}"', "_", name, code]
        if image:
            argv += ["-drive", drive % image]
        p = subprocess.Popen(argv)
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


def test_stop_qemu_stops_only_the_given_image(install, fake_qemus):
    arm = "if=none,file=%s,format=raw,id=rootfs"            # run.armel.sh's -drive
    mine = fake_qemus("qemu-system-arm", image(install, 1), drive=arm)
    stubborn = fake_qemus("qemu-system-mips", image(install, 1), ignore_term=True)
    other_iid = fake_qemus("qemu-system-arm", image(install, 11))
    mipsel = fake_qemus("qemu-system-mipsel", image(install, 2))
    backup = fake_qemus("qemu-system-arm", image(install, 1) + ".old")
    sentinel = fake_qemus("qemu-system-arm-SENTINEL")       # Phase 0 sentinel: no image
    wait_started([mine, stubborn, other_iid, mipsel, backup, sentinel])

    res = cfg(install, "qemu_pids 1")
    assert sorted(map(int, res.stdout.split())) == sorted([mine.pid, stubborn.pid])

    t0 = time.time()
    res = cfg(install, "QEMU_STOP_GRACE=1; stop_qemu 1")
    assert res.returncode == 0, res.stderr
    assert time.time() - t0 < 10
    for p in (mine, stubborn):
        p.wait(timeout=5)
    assert stubborn.returncode == -9            # ignored SIGTERM -> SIGKILL after the grace
    for p in (other_iid, mipsel, backup, sentinel):
        assert alive(p.pid), "an unrelated QEMU was stopped"


def test_another_installations_qemu_of_the_same_iid_survives(install, tmp_path, fake_qemus):
    """Regression (review): qemu_pids matched ".*/scratch/<IID>/image\\.raw", so
    stop_qemu/release_emulation (as root) stopped the QEMU of another FirmAE
    copy on the host that used the same IID. "instXa[1]" also matches the
    regex "inst.a[1]" -- the comparison must be a fixed string."""
    other = tmp_path / "instXa[1]" / "FirmAE"
    (other / "scratch" / "1").mkdir(parents=True)
    (other / "scratch" / "1" / "image.raw").write_text("")
    theirs = fake_qemus("qemu-system-mipsel", image(other, 1))
    theirs_arm = fake_qemus("qemu-system-arm", image(other, 1), drive="if=none,file=%s,format=raw,id=rootfs")
    mine = fake_qemus("qemu-system-mipsel", image(install, 1))
    wait_started([theirs, theirs_arm, mine])
    assert cfg(install, "qemu_pids 1").stdout.split() == [str(mine.pid)]
    res = cfg(install, "QEMU_STOP_GRACE=1; stop_qemu 1")
    assert res.returncode == 0, res.stderr
    mine.wait(timeout=5)
    assert alive(theirs.pid) and alive(theirs_arm.pid)


def test_qemu_pids_accepts_another_spelling_of_the_same_image(install, tmp_path, fake_qemus):
    """run.sh started from scratch/<IID>/ sources ../../firmae.config: through a
    symlinked directory the path differs as a string but names the same file."""
    link = tmp_path / "link"
    os.symlink(str(install), str(link))
    mine = fake_qemus("qemu-system-mipsel", image(link, 1))
    wait_started([mine])
    assert cfg(install, "qemu_pids 1").stdout.split() == [str(mine.pid)]


def test_stop_qemu_without_qemu_is_a_noop(install):
    assert cfg(install, "stop_qemu 424242; echo ok").stdout.strip() == "ok"


def test_scratch_pids_finds_only_this_installations_processes(install, tmp_path, fake_qemus):
    """scripts/delete.sh: every process of the image (QEMU, run.sh, ...), and
    nothing of another installation or another IID."""
    other = tmp_path / "instXa[1]" / "FirmAE"
    qemu = fake_qemus("qemu-system-mipsel", image(install, 1))
    run_sh = fake_qemus("qemu-system-helper", "%s/scratch/1/run.sh" % install)
    theirs = fake_qemus("qemu-system-mipsel", image(other, 1))
    iid11 = fake_qemus("qemu-system-mipsel", image(install, 11))
    wait_started([qemu, run_sh, theirs, iid11])
    assert sorted(map(int, cfg(install, "scratch_pids 1").stdout.split())) == sorted([qemu.pid, run_sh.pid])


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
    stub(bindir, "mount", 'n=$(($(cat %s)+1)); echo $n > %s; echo "mount $*" >> %s; '
         'printf "<%%s>" "$@" >> %s; echo >> %s; [ $n -ge 3 ]'
         % (state, state, tmp_path / "log", tmp_path / "argv", tmp_path / "argv"))
    stub(bindir, "sleep", "exit 0")
    res = cfg(repo_root, 'mount_partition /dev/loop1p1 /mnt/x; echo rc=$?', extra_path=bindir)
    assert res.stdout.strip() == "rc=0"
    # host-side mount of the untrusted image: its device nodes and setuid bits
    # are inert; no noexec (makeImage.sh chroot-executes /busybox from it)
    assert (tmp_path / "log").read_text().count("mount -o nodev,nosuid /dev/loop1p1 /mnt/x") == 3
    assert "noexec" not in (tmp_path / "log").read_text()
    # the exact argument vector of every attempt: the options are one -o argument
    assert (tmp_path / "argv").read_text().splitlines() == ["<-o><nodev,nosuid></dev/loop1p1></mnt/x>"] * 3
    state.write_text("-100")                               # never succeeds
    res = cfg(repo_root, 'mount_partition /dev/loop1p1 /mnt/x; echo rc=$?', extra_path=bindir)
    assert res.stdout.strip() == "rc=1"


# ------------------------------------------------------------ check_network

def network_stubs(tmp_path, curl_ok=False, ping_ok=False):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "net_log"
    stub(bindir, "curl", 'echo "curl $*" >> %s; %s' % (log, "exit 0" if curl_ok else "exit 7"))
    stub(bindir, "ping", 'echo "ping $*" >> %s; %s' % (log, "exit 0" if ping_ok else "exit 1"))
    stub(bindir, "sleep", "exit 0")                        # the 10 s start delay and the 1 s pauses
    return bindir, log


@pytest.mark.parametrize("call", ["check_network false", 'check_network "" false',
                                  "check_network", 'IP=""; check_network ${IP} false'])
def test_check_network_without_an_ip_returns_at_once(repo_root, tmp_path, call):
    """run_mode.sh `run` called check_network with an empty IP: the for loop never
    ran, the clock never advanced and the function spun at 100% CPU forever."""
    bindir, log = network_stubs(tmp_path)
    t0 = time.time()
    res = cfg(repo_root, "CHECK_TIMEOUT=3600; " + call, extra_path=bindir)
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["None", "false", "false", "-1", "-1"]
    assert time.time() - t0 < 10
    assert not log.exists()                                # nothing was probed


def test_check_network_gives_up_after_check_timeout(repo_root, tmp_path):
    bindir, log = network_stubs(tmp_path)
    t0 = time.time()
    res = cfg(repo_root, "CHECK_TIMEOUT=2; check_network 192.0.2.1 192.0.2.2 false", extra_path=bindir)
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["None", "false", "false", "-1", "-1"]
    assert time.time() - t0 < 20
    calls = log.read_text()
    assert "curl --max-time 2 --output /dev/null --silent http://192.0.2.2" in calls


def test_check_network_reports_the_web_server(repo_root, tmp_path):
    bindir, _ = network_stubs(tmp_path, curl_ok=True)
    res = cfg(repo_root, "CHECK_TIMEOUT=60; check_network 192.0.2.7 false", extra_path=bindir)
    out = res.stdout.split()
    assert out[:3] == ["192.0.2.7", "true", "true"] and float(out[4]) >= 0


def fast_clock(bindir, tmp_path, step):
    """date stub: `date +%s` advances `step` seconds per call."""
    clock = tmp_path / "clock"
    clock.write_text("0")
    stub(bindir, "date", 'if [ "$1" = "+%%s" ]; then n=$(cat %s); echo $n; echo $((n+%d)) > %s; '
                         'else echo 0.0; fi' % (clock, step, clock))


def pinged(log):
    return [l.split()[-1] for l in log.read_text().splitlines() if l.startswith("ping ")]


def test_check_network_probes_at_most_check_max_ips(repo_root, tmp_path):
    """The addresses come from the guest: hundreds of them must not make one
    round take far longer than CHECK_TIMEOUT."""
    bindir, log = network_stubs(tmp_path)
    fast_clock(bindir, tmp_path, 10)
    ips = " ".join("192.0.2.%d" % i for i in range(1, 41))
    res = cfg(repo_root, "CHECK_TIMEOUT=360; echo $CHECK_MAX_IPS; check_network %s false" % ips, extra_path=bindir)
    assert res.returncode == 0, res.stderr
    assert res.stdout.split()[0] == "8"
    assert res.stdout.split()[1:] == ["None", "false", "false", "-1", "-1"]
    assert sorted(set(pinged(log))) == sorted("192.0.2.%d" % i for i in range(1, 9))


def test_check_network_checks_the_deadline_after_every_address(repo_root, tmp_path):
    """START=0, first check 100, then +100 per address: with CHECK_TIMEOUT=250
    the deadline passes after the second address -- the rest of the round is
    not probed (it was: the clock was read only once per round)."""
    bindir, log = network_stubs(tmp_path)
    fast_clock(bindir, tmp_path, 100)
    res = cfg(repo_root, "CHECK_TIMEOUT=250; check_network 192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4 false",
              extra_path=bindir)
    assert res.returncode == 0, res.stderr
    assert pinged(log) == ["192.0.2.1", "192.0.2.2"]


def test_run_mode_run_with_unknown_ip_does_not_spin(repo_root, tmp_path):
    """run_mode.sh run <IID> ... with IP "" (network not reachable): the
    background check_network ends at once instead of looping forever."""
    root = tmp_path / "FirmAE"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(repo_root / "firmae.config", root)
    shutil.copy(repo_root / "scripts" / "run_mode.sh", root / "scripts")
    work = root / "scratch" / "987"
    work.mkdir(parents=True)
    # stays up a moment: run_mode.sh's EXIT trap kills a still-running check_network,
    # so its own output proves it ended by itself
    (work / "run.sh").write_text('#!/bin/bash\necho emulation-ran\npython3 -c "import time; time.sleep(2)"\n')
    (work / "run.sh").chmod(0o755)
    bindir, log = network_stubs(tmp_path)
    e = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    e.pop("FIRMAE_DOCKER", None)
    t0 = time.time()
    res = subprocess.run(["bash", "-c", 'bash scripts/run_mode.sh run 987 mipsel "" "" false false 127.0.0.1; wait'],
                         cwd=root, env=e, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    assert "emulation-ran" in res.stdout
    assert "None false false -1 -1" in res.stdout
    assert time.time() - t0 < 20
    assert not log.exists()


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
    # same IID, another installation (tmp_path/Other/scratch/1)
    other_install = fake_qemus("qemu-system-arm", str(tmp_path / "Other" / "scratch" / "1" / "image.raw"))
    wait_started([qemu, other, other_install])

    res = cfg(root, "QEMU_STOP_GRACE=1; release_emulation 1; release_emulation 1", extra_path=bindir)
    assert res.returncode == 0, res.stderr
    qemu.wait(timeout=5)
    assert alive(other.pid) and alive(other_install.pid)
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


# ------------------------------------------- Docker mode without /dev:/dev (SECURITY.md S7)
# In the narrowed container add_partition attaches the image's partition with an
# offset (no --partscan, no block major 259) and makes the loop device's nodes
# itself (no udev). Everything here runs against a fake /sys and stubbed
# losetup, sfdisk, mknod and rm: no device node is created or removed, nothing
# is attached.

def mountinfo(tmp_path, *fstypes):
    p = tmp_path / "mountinfo"
    lines = ["22 1 0:21 / /proc rw - proc proc rw"]
    for n, fs in enumerate(fstypes):
        lines.append("%d 1 0:%d / /dev rw,nosuid - %s %s rw" % (30 + n, 40 + n, fs, fs))
    p.write_text("\n".join(lines) + "\n")
    return p


GOOD_DUMP = """label: dos
label-id: 0x5f3d2a1b
device: {img}
unit: sectors
sector-size: 512

{img}1 : start=        2048, size=     2095104, type=83
"""


def node_env(tmp_path, fstype="tmpfs", docker=True, dump=None, img_size=1 << 30):
    sysb = tmp_path / "sys" / "block"
    (sysb / "loop9999").mkdir(parents=True, exist_ok=True)
    (sysb / "loop9999" / "dev").write_text("7:9999\n")
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "log"
    for name in ("mknod", "rm"):
        stub(bindir, name, 'echo "%s $*" >> %s' % (name, log))
    img = tmp_path / "image.raw"
    with open(img, "wb") as f:
        f.truncate(img_size)                       # sparse
    (tmp_path / "dump").write_text(GOOD_DUMP.format(img=img) if dump is None else dump)
    stub(bindir, "sfdisk", '[ "$1" = --dump ] && [ "$2" = "%s" ] && cat "%s"' % (img, tmp_path / "dump"))
    pre = 'SYS_BLOCK="%s"; MOUNTINFO="%s"; LOOP_REGISTRY="%s"; ' % (sysb, mountinfo(tmp_path, fstype),
                                                                  tmp_path / "registry")
    env = {"FIRMAE_DOCKER": "true"} if docker else {}
    return pre, env, bindir, log, img


def logged(log):
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.parametrize("fstypes, docker, expected", [
    (("tmpfs",), True, "yes"),                 # the container's own /dev
    (("devtmpfs",), True, "no"),               # FIRMAE_DOCKER_PRIVILEGED: the host's /dev
    (("tmpfs", "devtmpfs"), True, "no"),       # the last mount on /dev counts
    (("devtmpfs", "tmpfs"), True, "yes"),
    ((), True, "no"),                          # nothing mounted on /dev: unknown, do nothing
    (("tmpfs",), False, "no"),                 # host mode: never
])
def test_manage_dev_nodes(repo_root, tmp_path, fstypes, docker, expected):
    mi = mountinfo(tmp_path, *fstypes)
    res = cfg(repo_root, 'MOUNTINFO="%s"; _manage_dev_nodes && echo yes || echo no' % mi,
              env={"FIRMAE_DOCKER": "true"} if docker else None)
    assert res.stdout.strip() == expected


def test_manage_dev_nodes_with_a_missing_mountinfo_is_no(repo_root, tmp_path):
    res = cfg(repo_root, 'MOUNTINFO="%s"; _manage_dev_nodes && echo yes || echo no' % (tmp_path / "none"),
              env={"FIRMAE_DOCKER": "true"})
    assert res.stdout.strip() == "no"


# ---- _dev_node: loop devices (major 7) only

def test_dev_node_makes_a_missing_loop_node_from_sysfs(repo_root, tmp_path):
    pre, env, bindir, log, _ = node_env(tmp_path)
    node = tmp_path / "loop9999"
    res = cfg(repo_root, pre + '_dev_node "%s" "$SYS_BLOCK/loop9999/dev"; echo rc=$?' % node,
              env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=0"
    assert logged(log) == ["rm -f %s" % node, "mknod -m 0660 %s b 7 9999" % node]


@pytest.mark.parametrize("content", [
    "259:0",            # the NVMe disk on many hosts (audit finding): never
    "8:0", "253:0", "1:3", "70:1",
    "", "7", "7:", "a:b", "7:1 x", "7:1;touch /tmp/x", "7:12345678", "07x:1",
])
def test_dev_node_refuses_everything_but_a_loop_device(repo_root, tmp_path, content):
    pre, env, bindir, log, _ = node_env(tmp_path)
    bad = tmp_path / "bad_dev"
    bad.write_text(content)
    res = cfg(repo_root, pre + '_dev_node "%s/n" "%s"; echo rc=$?' % (tmp_path, bad), env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=1" and logged(log) == []


def test_dev_node_missing_sysfs_file_is_an_error(repo_root, tmp_path):
    pre, env, bindir, log, _ = node_env(tmp_path)
    res = cfg(repo_root, pre + '_dev_node "%s/n" "%s/none"; echo rc=$?' % (tmp_path, tmp_path),
              env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=1" and logged(log) == []


def test_dev_node_replaces_a_node_that_is_not_the_right_block_device(repo_root, tmp_path):
    """/dev/null exists but is a character device: it is "stale" for a block
    node and is replaced (rm and mknod are stubs: nothing is touched)."""
    pre, env, bindir, log, _ = node_env(tmp_path)
    res = cfg(repo_root, pre + '_dev_node /dev/null "$SYS_BLOCK/loop9999/dev"; echo rc=$?',
              env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=0"
    assert logged(log) == ["rm -f /dev/null", "mknod -m 0660 /dev/null b 7 9999"]


def test_dev_node_keeps_a_matching_loop_node(repo_root, tmp_path):
    import stat as st_
    blk = next(("/dev/loop%d" % i for i in range(8) if os.path.exists("/dev/loop%d" % i)
                and st_.S_ISBLK(os.stat("/dev/loop%d" % i).st_mode)), None)
    if blk is None:
        pytest.skip("no /dev/loopN to compare with")
    st = os.stat(blk)
    pre, env, bindir, log, _ = node_env(tmp_path)
    (tmp_path / "match").write_text("%d:%d\n" % (os.major(st.st_rdev), os.minor(st.st_rdev)))
    res = cfg(repo_root, pre + '_dev_node %s "%s"; echo rc=$?' % (blk, tmp_path / "match"),
              env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=0" and logged(log) == []


# ---- _image_partition: the untrusted partition table

def image_partition(repo_root, tmp_path, dump=None, img_size=1 << 30, sfdisk_fails=False):
    pre, env, bindir, log, img = node_env(tmp_path, dump=dump, img_size=img_size)
    if sfdisk_fails:
        stub(bindir, "sfdisk", "exit 1")
    res = cfg(repo_root, pre + '_image_partition "%s"; echo rc=$?' % img, env=env, extra_path=bindir)
    return res.stdout.split()


def test_image_partition_of_the_makeimage_layout(repo_root, tmp_path):
    assert image_partition(repo_root, tmp_path) == ["1048576", str(2095104 * 512), "rc=0"]


def test_image_partition_partition_may_end_exactly_at_the_end_of_the_file(repo_root, tmp_path):
    size = (2048 + 2095104) * 512
    assert image_partition(repo_root, tmp_path, img_size=size)[-1] == "rc=0"
    assert image_partition(repo_root, tmp_path, img_size=size - 1) == ["rc=1"]


HOSTILE = {
    "gpt": GOOD_DUMP.replace("label: dos", "label: gpt"),
    "no label": GOOD_DUMP.replace("label: dos\n", ""),
    "no unit": GOOD_DUMP.replace("unit: sectors\n", ""),
    "other unit": GOOD_DUMP.replace("unit: sectors", "unit: cylinders"),
    "4k sectors": GOOD_DUMP.replace("sector-size: 512", "sector-size: 4096"),
    "two partitions": GOOD_DUMP + "{img}2 : start=     2097152, size=        2048, type=83\n",
    "no partition": GOOD_DUMP.split("\n{img}1")[0] + "\n",
    "type 7": GOOD_DUMP.replace("type=83", "type=7"),
    "bootable": GOOD_DUMP.replace("type=83", "type=83, bootable"),
    "start 0": GOOD_DUMP.replace("start=        2048", "start=           0"),
    "size 0": GOOD_DUMP.replace("size=     2095104", "size=           0"),
    "past the end": GOOD_DUMP.replace("size=     2095104", "size=     2097152"),
    "huge": GOOD_DUMP.replace("size=     2095104", "size=9999999999999"),
    "negative": GOOD_DUMP.replace("start=        2048", "start=       -2048"),
    "unknown key": GOOD_DUMP.replace("unit: sectors", "unit: sectors\nfirst-lba: 34"),
    "garbage line": GOOD_DUMP + "$(touch /tmp/firmae-pwned)\n",
    "injected value": GOOD_DUMP.replace("type=83", "type=83; rm -rf /"),
    "empty": "",
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_image_partition_refuses_anything_unexpected(repo_root, tmp_path, name):
    img = tmp_path / "image.raw"
    assert image_partition(repo_root, tmp_path, dump=HOSTILE[name].format(img=img)) == ["rc=1"], name
    assert not os.path.exists("/tmp/firmae-pwned")


def test_image_partition_sfdisk_failure_is_an_error(repo_root, tmp_path):
    assert image_partition(repo_root, tmp_path, sfdisk_fails=True) == ["rc=1"]


@pytest.mark.skipif(not (shutil.which("sfdisk") or os.path.exists("/sbin/sfdisk")) or
                    not os.path.exists("/sbin/fdisk"), reason="needs fdisk and sfdisk")
def test_image_partition_of_a_real_image_made_like_makeimage(repo_root, tmp_path):
    """The table image.py's fdisk script writes (FDISK_INPUT), read by the real sfdisk."""
    img = tmp_path / "real.raw"
    with open(img, "wb") as f:
        f.truncate(64 << 20)
    subprocess.run(["/sbin/fdisk", str(img)], input=b"o\nn\np\n1\n\n\nw\n",
                   capture_output=True, timeout=60)
    e = dict(os.environ)
    e.pop("FIRMAE_DOCKER", None)
    e["PATH"] = "/usr/sbin:/sbin:" + e["PATH"]
    res = subprocess.run(["bash", "-c", 'source ./firmae.config && _image_partition "$1"', "_", str(img)],
                         cwd=repo_root, env=e, capture_output=True, text=True, timeout=60)
    assert res.stdout.split() == ["1048576", str(((64 << 20) // 512 - 2048) * 512)], res.stderr


# ---- attaching

LOSETUP_STUB = '''echo "losetup $*" >> %(log)s
if [ "$1" = --find ] && [ $# = 1 ]; then echo "%(find)s"; exit 0; fi
if [ "$1" = --offset ]; then n=$(( $(cat %(c)s) + 1 )); echo $n > %(c)s
  [ $n -le %(fails)d ] && { echo busy >&2; exit 1; }; echo "$6"; exit 0; fi
exit 0'''


def attach_stubs(bindir, log, show_fails=0, find_out="/dev/loop9999"):
    count = bindir / "count"
    count.write_text("0")
    stub(bindir, "losetup", LOSETUP_STUB % {"log": log, "find": find_out, "c": count, "fails": show_fails})
    stub(bindir, "sleep", "exit 0")
    stub(bindir, "udevadm", "exit 0")


ATTACH = "losetup --offset 1048576 --sizelimit %d --show /dev/loop9999 %%s" % (2095104 * 512)


def test_docker_add_partition_attaches_the_partition_with_an_offset(repo_root, tmp_path):
    pre, env, bindir, log, img = node_env(tmp_path)
    attach_stubs(bindir, log)
    res = cfg(repo_root, pre + 'partition_ready () { [ -n "$1" ]; }; add_partition "%s"' % img,
              env=env, extra_path=bindir)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "/dev/loop9999p1"
    assert logged(log) == [
        "losetup --find",
        "rm -f /dev/loop9999", "mknod -m 0660 /dev/loop9999 b 7 9999",
        ATTACH % img,
        # the "p1" name the callers strip: the SAME loop device, not a partition
        "rm -f /dev/loop9999p1", "mknod -m 0660 /dev/loop9999p1 b 7 9999",
    ]
    assert "partscan" not in log.read_text() and "259" not in log.read_text()
    # recorded for release_container_loops: device, inode and path of the image
    assert (tmp_path / "registry").read_text() == "/dev/loop9999 %d %s\n" % (os.stat(img).st_ino, img)


def test_docker_add_partition_with_a_bad_table_attaches_nothing(repo_root, tmp_path):
    pre, env, bindir, log, img = node_env(tmp_path, dump=HOSTILE["two partitions"].format(img="x"))
    attach_stubs(bindir, log)
    res = cfg(repo_root, pre + 'add_partition "%s"; echo rc=$?' % img, env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=1"
    assert "unexpected partition table" in res.stderr
    assert logged(log) == []


def test_docker_attach_retries_when_another_container_took_the_device(repo_root, tmp_path):
    pre, env, bindir, log, img = node_env(tmp_path)
    attach_stubs(bindir, log, show_fails=2)
    res = cfg(repo_root, pre + '_attach_partition_loop "%s"; echo rc=$?' % img, env=env, extra_path=bindir)
    assert res.stdout.split() == ["/dev/loop9999", "rc=0"]
    assert [l for l in logged(log) if l.startswith("losetup --offset")] == [ATTACH % img] * 3
    attach_stubs(bindir, log, show_fails=99)
    res = cfg(repo_root, pre + '_attach_partition_loop "%s"; echo rc=$?' % img, env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=1"                    # gives up after 5 tries


@pytest.mark.parametrize("find_out", ["garbage", "/dev/loop9999 /dev/sda", "/dev/sda", "/dev/loop",
                                      "/dev/loop12345678", "/dev/loop1p1"])
def test_docker_attach_refuses_an_unexpected_device_name(repo_root, tmp_path, find_out):
    pre, env, bindir, log, img = node_env(tmp_path)
    attach_stubs(bindir, log, find_out=find_out)
    res = cfg(repo_root, pre + '_attach_partition_loop "%s"; echo rc=$?' % img, env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=1"
    assert not [l for l in logged(log) if l.startswith(("mknod", "rm", "losetup --offset"))]


@pytest.mark.parametrize("fstype, docker", [("tmpfs", False), ("devtmpfs", True)])
def test_add_partition_without_node_management_is_unchanged(repo_root, tmp_path, fstype, docker):
    """Host mode, and Docker mode with the host's /dev: the old single
    `losetup --find --show --partscan` call, and never a mknod, rm or sfdisk."""
    pre, env, bindir, log, _ = node_env(tmp_path, fstype=fstype, docker=docker)
    stub(bindir, "losetup", 'echo "losetup $*" >> %s; echo /dev/loop9999' % log)
    stub(bindir, "sfdisk", 'echo "sfdisk $*" >> %s' % log)
    stub(bindir, "udevadm", "exit 0")
    res = cfg(repo_root, pre + 'partition_ready () { true; }; add_partition /x/image.raw',
              env=env, extra_path=bindir)
    assert res.stdout.strip() == "/dev/loop9999p1"
    assert logged(log) == ["losetup --find --show --partscan /x/image.raw"]


@pytest.mark.parametrize("fstype, docker, removes", [("tmpfs", True, True), ("devtmpfs", True, False),
                                                     ("tmpfs", False, False)])
def test_del_partition_removes_the_p1_name_only_when_it_made_it(repo_root, tmp_path, fstype, docker,
                                                                 removes):
    pre, env, bindir, log, _ = node_env(tmp_path, fstype=fstype, docker=docker)
    for name in ("losetup", "dmsetup", "sleep"):
        stub(bindir, name, "exit 0")
    res = cfg(repo_root, pre + 'del_partition /dev/loop9999; echo rc=$?', env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=0"
    assert logged(log) == (["rm -f /dev/loop9999p1"] if removes else [])


# ---- release_container_loops: what docker-helper runs before `docker stop`

def release(repo_root, tmp_path, registry, backing):
    """backing: {device: "<inode> <file>"} as `losetup -l -O BACK-INO,BACK-FILE` shows it."""
    pre, env, bindir, log, _ = node_env(tmp_path)
    cases = "".join('  %s) echo "%s";;\n' % (d, b) for d, b in backing.items())
    stub(bindir, "losetup", 'echo "losetup $*" >> %s\nif [ "$1" = -l ]; then case "${@: -1}" in\n%s'
                            'esac; fi\nexit 0' % (log, cases))
    (tmp_path / "registry").write_text(registry)
    res = cfg(repo_root, pre + "release_container_loops; echo rc=$?", env=env, extra_path=bindir)
    return res, [l for l in logged(log) if not l.startswith("losetup -l")]


def test_release_detaches_only_devices_still_backed_by_the_recorded_file(repo_root, tmp_path):
    reg = ("/dev/loop3 111 /work/FirmAE/scratch/1/image.raw\n"
           "/dev/loop4 222 /work/FirmAE/scratch/1/image.raw\n"     # now another file (inode)
           "/dev/loop5 333 /work/FirmAE/scratch/1/image.raw\n"     # already detached
           "/dev/loop6 444 /work/FirmAE/scratch/2/image.raw\n")    # now another path
    res, calls = release(repo_root, tmp_path, reg, {
        "/dev/loop3": "111 /work/FirmAE/scratch/1/image.raw",
        "/dev/loop4": "999 /work/FirmAE/scratch/1/image.raw",
        "/dev/loop6": "444 /work/FirmAE/scratch/3/image.raw"})
    assert res.stdout.strip() == "rc=0"
    assert calls == ["losetup -d /dev/loop3", "rm -f /dev/loop3p1", "rm -f %s" % (tmp_path / "registry")]


@pytest.mark.parametrize("line", ["/dev/sda 111 /x", "/dev/loop3 abc /x", "garbage", "/dev/loop3p1 111 /x",
                                  "/dev/loop12345678 111 /x"])
def test_release_ignores_malformed_registry_lines(repo_root, tmp_path, line):
    res, calls = release(repo_root, tmp_path, line + "\n", {"/dev/sda": "111 /x", "/dev/loop3": "111 /x"})
    assert res.stdout.strip() == "rc=0"
    assert not [c for c in calls if c.startswith("losetup -d")]


def test_release_without_a_registry_does_nothing(repo_root, tmp_path):
    pre, env, bindir, log, _ = node_env(tmp_path)
    stub(bindir, "losetup", 'echo "losetup $*" >> %s' % log)
    res = cfg(repo_root, pre + "release_container_loops; echo rc=$?", env=env, extra_path=bindir)
    assert res.stdout.strip() == "rc=0" and logged(log) == []
