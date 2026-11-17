"""firmae/check.py, firmae/hostfwd.py, firmae/procutil.py (REFACTORING_PLAN 4.5):
the emulation check that scripts/check_emulation.sh did in Bash.

* Bash <-> Python equivalence: read_hostfwd (scripts/hostfwd_check.sh) and
  qemu_pids / pid_running (firmae.config, hostfwd_check.sh) stay in Bash for
  scripts/run_mode.sh; both copies are run on the same input here.
* the check itself in this process with a fake clock (run.sh, curl, ping,
  ss are real processes / stubs), and the wrapper end to end (signals, exit
  codes, sys.path hygiene).

No root, no QEMU: "QEMU" is a Python process renamed with `exec -a`.
"""

import os
import shutil
import signal
import subprocess
import time

import pytest

from firmae import check, config, hostfwd, procutil

linux = pytest.mark.linux
pytestmark = linux
IID = "5"


def stub(d, name, body):
    p = d / name
    p.write_text("#!/bin/bash\n" + body + "\n")
    p.chmod(0o755)


class FakeClock:
    """whole seconds advance 10 s per reading (as the old `date` stub did);
    sleep only yields briefly"""

    def __init__(self):
        self.t = 0
        self.slept = []

    def now(self):
        n = self.t
        self.t += 10
        return n

    def precise(self):
        return 0.0

    def sleep(self, seconds):
        self.slept.append(seconds)
        time.sleep(min(seconds, 0.01))


# A process that /proc shows as this image's QEMU (argv[0] qemu-system-*,
# -drive ...file=<image>); writes "<pgid> <SigIgn>" to --ready, then waits.
FAKE_QEMU = r'''
import os, sys, time
args = sys.argv[1:]
ready = args[args.index("--ready") + 1] if "--ready" in args else None
if "--ignore-term" in args:
    import signal
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if ready:
    ign = [l.split()[1] for l in open("/proc/self/status") if l.startswith("SigIgn:")][0]
    with open(ready + ".tmp", "w") as f:
        f.write("%d %s\n" % (os.getpgrp(), ign))
    os.rename(ready + ".tmp", ready)
time.sleep(float(args[args.index("--life") + 1]) if "--life" in args else 60)
'''


@pytest.fixture
def procs():
    started = []

    def start(argv, **kw):
        kw.setdefault("stdout", subprocess.DEVNULL)
        kw.setdefault("stderr", subprocess.DEVNULL)
        p = subprocess.Popen(argv, **kw)
        started.append(p)
        return p
    yield start
    for p in started:
        if p.poll() is None:
            p.kill()
        p.wait(timeout=30)


def wait_for(cond, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    raise AssertionError("condition not met within %ss" % timeout)


def renamed(procs, name, args, fake):
    """a process whose argv[0] is `name`, followed by `args` (as QEMU's)"""
    p = procs(["bash", "-c", 'exec -a "$0" python3 "$@"', name, str(fake)] + list(args))
    wait_for(lambda: (procutil.read_cmdline(p.pid) or [""])[0] == name)
    return p


# ======================================================================
# Bash <-> Python equivalence
# ======================================================================

BASH_READ_HOSTFWD = r'''
source "$1"; shift
for f in "$@"; do
  if read_hostfwd "$f"; then echo "ok ${HOSTFWD_HTTP:-x} ${HOSTFWD_HTTPS:-x}"; else echo "rej ${HOSTFWD_HTTP:-x} ${HOSTFWD_HTTPS:-x}"; fi
done
'''

HOSTFWD_CASES = [
    b"tcp 80 10123\ntcp 443 10124\ntcp 8080 10125\nudp 161 10126\n",
    b"tcp 80 10123",                                   # no final newline
    b"tcp 80 10123\n\n\n",                             # trailing newlines are stripped
    b"tcp 80 10123\n\ntcp 443 10124\n",                # an empty line inside
    b"\n",
    b"",
    b"tcp 443 10124\n",
    b"udp 80 10123\n",                                 # udp/80 is not the web port
    b"tcp 443 10124\ntcp 443 10125\n",
    b"tcp 80 10000\ntcp 443 19999\n",
    b"tcp 80 9999\n",
    b"tcp 80 20000\n",
    b"tcp 65535 10000\n",
    b"tcp 65536 10000\n",
    b"tcp 00000 10000\n",
    b"tcp 080 010123\n",                               # 6 digits
    b"tcp 080 10123\ntcp 00443 10124\n",
    b"tcp 8\x000 10123\x00\n",                         # NULs are dropped
    b"\x00" * 5000 + b"tcp 80 10123\n",                # ... but count for the first 4097 bytes
    b"tcp 80 10123\n" + b"udp 1 10000\n" * 63,         # 64 lines
    b"tcp 80 10123\n" + b"udp 1 10000\n" * 64,         # 65 lines
    b"tcp 80 10123\n" + b"udp 1 10000\n" * 400,        # oversized
    (b"udp 1 10000\n" * 342)[:4095] + b"\n",           # cut inside a line
    b"tcp 80 10123\n" + b"#" * 4083,                   # 4096 bytes, bad line
    b"tcp 80 10123\n".ljust(4096, b"\n") + b"\n",      # 4097 bytes, trailing newlines
    b"tcp 80 10123\r\n",
    b"tcp 80 10123 \n",
    b" tcp 80 10123\n",
    b"tcp  80 10123\n",
    b"TCP 80 10123\n",
    b"tcp 80 +10123\n",
    b"tcp 80 0x2723\n",
    b"tcp 80 $(id)\n",
    b"tcp \xd9\xa080 10123\n",                         # non-ASCII digit
    b"tcp 80 10123\ngarbage\n",
    b"icmp 80 10123\n",
]


def py_read_hostfwd(path):
    r = hostfwd.read_hostfwd(str(path))
    if r is None:
        return "rej x x"
    return "ok %s %s" % tuple("x" if p is None else p for p in r)


@pytest.mark.parametrize("locale", ["C", "C.UTF-8"])
def test_read_hostfwd_accepts_exactly_what_the_bash_copy_accepts(repo_root, tmp_path, locale):
    files = []
    for i, data in enumerate(HOSTFWD_CASES):
        p = tmp_path / ("case%d" % i)
        p.write_bytes(data)
        files.append(p)
    target = tmp_path / "target"
    target.write_bytes(HOSTFWD_CASES[0])
    os.symlink(str(target), str(tmp_path / "symlink"))
    (tmp_path / "dir").mkdir()
    os.mkfifo(str(tmp_path / "fifo"))
    unreadable = tmp_path / "unreadable"
    unreadable.write_bytes(HOSTFWD_CASES[0])
    unreadable.chmod(0)
    files += [unreadable] if os.geteuid() != 0 else []
    files += [tmp_path / "symlink", tmp_path / "dir", tmp_path / "fifo", tmp_path / "missing"]
    env = dict(os.environ, LC_ALL=locale)
    res = subprocess.run(["bash", "-c", BASH_READ_HOSTFWD, "_", str(repo_root / "scripts" / "hostfwd_check.sh")]
                         + [str(f) for f in files], capture_output=True, text=True, timeout=60, env=env)
    assert res.returncode == 0, res.stderr
    bash = res.stdout.splitlines()
    py = [py_read_hostfwd(f) for f in files]
    assert len(bash) == len(files)
    assert py == bash
    # the cases really exercise both outcomes
    assert py[0] == "ok 10123 10124" and py.count("rej x x") > 10 and py[-4:] == ["rej x x"] * 4


def test_qemu_pids_matches_the_same_processes_as_the_bash_copy(repo_root, tmp_path, procs):
    scratch = tmp_path / "FirmAE" / "scratch"
    for iid in ("5", "55"):
        (scratch / iid).mkdir(parents=True)
        (scratch / iid / "image.raw").write_text("")
    link = tmp_path / "link"
    os.symlink(str(scratch), str(link))
    fake = tmp_path / "fake.py"
    fake.write_text(FAKE_QEMU)
    img = "%s/5/image.raw" % scratch
    cases = [   # (argv[0], arguments, expected match)
        ("qemu-system-mipsel", ["-drive", "if=ide,format=raw,file=%s" % img], True),
        ("/usr/bin/qemu-system-arm", ["-drive", "if=none,file=%s,format=raw,id=rootfs" % img], True),
        ("qemu-system-mips", ["-drive", "file=%s," % img], True),
        ("qemu-system-mips", ["-drive", "if=ide,file=%s\nsecond line" % img], True),
        ("qemu-system-mips", ["-drive", "x\nfile=%s" % img], False),        # only the first line counts
        ("qemu-system-mips", ["-drive", "file=%s/5/image.raw" % link], True),  # same file, other spelling
        ("qemu-system-mips", ["-drive", "file=%s/55/image.raw" % scratch], False),
        ("qemu-system-mips", ["-drive", "file=/elsewhere/scratch/5/image.raw"], False),
        ("qemu-system-mips", ["-drive", "file=scratch/5/image.raw"], False),
        ("qemu-system-mips", ["-drive", "file=%sX" % img], False),
        ("qemu-system-mips", ["-drive", "xfile=%s" % img], False),
        ("qemu-systemX-mips", ["-drive", "file=%s" % img], False),
        ("notqemu", ["-drive", "file=%s" % img], False),
        ("qemu-system-mips", ["file=%s" % img], True),
    ]
    want = set()
    ours = set()
    for name, args, match in cases:
        p = renamed(procs, name, args, fake)
        ours.add(str(p.pid))
        if match:
            want.add(str(p.pid))
    res = subprocess.run(["bash", "-c", 'source ./firmae.config && SCRATCH_DIR="$1" && qemu_pids 5', "_", str(scratch)],
                         cwd=str(repo_root), capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    bash = set(res.stdout.split()) & ours
    py = set(procutil.qemu_pids(str(scratch), "5")) & ours
    assert py == bash == want


def test_pid_running_agrees_with_the_bash_copy(repo_root, procs):
    zombie = procs(["true"])
    wait_for(lambda: open("/proc/%d/stat" % zombie.pid).read().rsplit(") ", 1)[1][0] == "Z")
    alive = procs(["sleep", "30"])
    cases = [str(os.getpid()), str(alive.pid), str(zombie.pid), "999999999", "abc", "", "1x"]
    script = 'source "$1"; shift; for p in "$@"; do pid_running "$p" && echo y || echo n; done'
    res = subprocess.run(["bash", "-c", script, "_", str(repo_root / "scripts" / "hostfwd_check.sh")] + cases,
                         capture_output=True, text=True, timeout=60)
    assert res.stdout.split() == ["y" if procutil.pid_running(c) else "n" for c in cases]
    assert res.stdout.split() == ["y", "y", "n", "n", "n", "n", "n"]


def test_constants_equal_the_bash_values(repo_root):
    text = (repo_root / "firmae.config").read_text()
    assert "QEMU_STOP_GRACE=%d " % procutil.QEMU_STOP_GRACE in text
    assert "CHECK_MAX_IPS=%d\n" % config.DEFAULT_CHECK_MAX_IPS in text
    assert config.load(str(repo_root)).CHECK_MAX_IPS == 8
    sh = (repo_root / "scripts" / "hostfwd_check.sh").read_text()
    for name in ("HOSTFWD_PORT_MIN", "HOSTFWD_PORT_MAX", "HOSTFWD_MAX_BYTES", "HOSTFWD_MAX_LINES"):
        assert "%s=%d\n" % (name, getattr(hostfwd, name)) in sh


# ======================================================================
# procutil: stopping
# ======================================================================

def test_stop_qemu_terms_then_kills_only_this_image(tmp_path, procs):
    scratch = tmp_path / "scratch"
    for iid in ("5", "6"):
        (scratch / iid).mkdir(parents=True)
    fake = tmp_path / "fake.py"
    fake.write_text(FAKE_QEMU)
    polite = renamed(procs, "qemu-system-mips", ["-drive", "file=%s/5/image.raw" % scratch], fake)
    stubborn = renamed(procs, "qemu-system-mips", ["-drive", "file=%s/5/image.raw" % scratch, "--ignore-term"], fake)
    other = renamed(procs, "qemu-system-mips", ["-drive", "file=%s/6/image.raw" % scratch], fake)
    time.sleep(0.3)        # let the stubborn one install its SIGTERM handler
    slept = []
    procutil.stop_qemu(str(scratch), "5", sleep=lambda s: (slept.append(s), time.sleep(0.01)))
    assert polite.wait(timeout=10) == -signal.SIGTERM
    assert stubborn.wait(timeout=10) == -signal.SIGKILL
    assert other.poll() is None
    assert len(slept) == 20 and set(slept) == {0.5}        # 10 s grace in 0.5 s steps


def test_wait_for_exit_kills_at_the_deadline(procs):
    p = procs(["sleep", "60"])
    slept = []
    assert procutil.wait_for_exit(p, 30, sleep=slept.append) == -signal.SIGKILL
    assert len(slept) == 60
    q = procs(["true"])
    assert procutil.wait_for_exit(q, 30, sleep=lambda s: time.sleep(0.01)) == 0
    assert procutil.wait_for_exit(None, 30) is None


# ======================================================================
# firmae.check in this process
# ======================================================================

@pytest.fixture
def world(repo_root, tmp_path, monkeypatch, capsys, procs):
    root = tmp_path / "FirmAE"
    root.mkdir()
    shutil.copy(repo_root / "firmae.config", root)
    work = root / "scratch" / IID
    work.mkdir(parents=True)
    (work / "image.raw").write_text("")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    netlog = tmp_path / "net_log"
    stub(bindir, "curl", 'echo "curl $*" >> %s; [ -n "${CURL_OK:-}" ] && [ "${@: -1}" = "$CURL_OK" ]' % netlog)
    stub(bindir, "ping", 'echo "ping $*" >> %s; [ -n "${PING_OK:-}" ]' % netlog)
    fake = tmp_path / "fake.py"
    fake.write_text(FAKE_QEMU)
    monkeypatch.setenv("PATH", "%s:%s" % (bindir, os.environ["PATH"]))
    monkeypatch.delenv("FIRMAE_DOCKER", raising=False)

    class W:
        pass
    w = W()
    w.root, w.work, w.tmp, w.fake, w.bindir = root, work, tmp_path, fake, bindir

    def set_run_sh(body):
        (work / "run.sh").write_text("#!/bin/bash\n%s\n" % body)
        (work / "run.sh").chmod(0o755)
    w.run_sh = set_run_sh
    set_run_sh("echo started; echo to-stderr >&2")

    def run(argv=(IID, "mipsel"), clock=None, curl_ok=None, ping_ok=False):
        for k, v in (("CURL_OK", curl_ok), ("PING_OK", "1" if ping_ok else None)):
            if v:
                monkeypatch.setenv(k, v)
            else:
                monkeypatch.delenv(k, raising=False)
        if netlog.exists():
            netlog.unlink()
        capsys.readouterr()
        w.clock = clock or FakeClock()
        rc = check.main(["./scripts/check_emulation.sh"] + list(argv), root=str(root), clock=w.clock)
        out, err = capsys.readouterr()
        w.calls = netlog.read_text().splitlines() if netlog.exists() else []
        w.state = {n: (work / n).read_text() for n in check.STATE_FILES if (work / n).exists()}
        return rc, out, err
    w.run = run

    def qemu(args=()):
        return renamed(procs, "qemu-system-mipsel",
                       ["-drive", "if=ide,format=raw,file=%s/image.raw" % work] + list(args), fake)
    w.qemu = qemu
    return w


def tap(w, *ips):
    (w.work / "isDhcp").write_text("false")
    (w.work / "ip_num").write_text(str(len(ips)))
    for i, ip in enumerate(ips):
        (w.work / ("ip.%d" % i)).write_text(ip)


def test_output_contract_tap(world):
    tap(world, "192.168.0.1")
    rc, out, _ = world.run(curl_ok="http://192.168.0.1", ping_ok=True)
    assert rc == 0
    lines = out.splitlines()
    assert lines[0] == "===== Check inferred emulation start ====="
    assert lines[1] == "[*] Inferred network: terminating after 360 secs..."
    assert lines[2] == "[*] Waiting web service... from 192.168.0.1: terminating after 360 secs..."
    assert lines[-1] == "=====  Check inferred emulation end  ====="
    assert world.state == {"ping": "true\n", "time_ping": "0\n", "ip": "192.168.0.1\n",
                           "web": "true\n", "time_web": "0\n"}
    assert world.calls == ["curl --max-time 2 --output /dev/null --silent http://192.168.0.1",
                           "ping -c 1 192.168.0.1"]
    # run.sh's stdout and stderr, nothing else
    assert (world.work / "emulation.log").read_text() == "started\nto-stderr\n"
    assert world.clock.slept[:2] == [10, 10]       # after run.sh, and before probing


def test_ping_only_writes_no_web_files_and_nothing_answers_writes_nothing(world):
    tap(world, "192.168.0.1")
    world.run(ping_ok=True)
    assert set(world.state) == {"ping", "time_ping", "ip"}
    world.run()
    assert world.state == {}


def test_stale_results_of_an_earlier_run_are_removed(world, tmp_path):
    """DD: they used to survive a run in which the check failed."""
    tap(world)
    outside = tmp_path / "outside"
    outside.write_text("keep")
    for name in ("ping", "time_ping", "ip", "web"):
        (world.work / name).write_text("true\n")
    os.symlink(str(outside), str(world.work / "time_web"))
    rc, out, _ = world.run()
    assert rc == 0 and world.state == {}
    assert not os.path.lexists(str(world.work / "time_web"))
    assert outside.read_text() == "keep"


def test_results_and_log_are_not_written_through_symlinks(world, tmp_path):
    tap(world, "192.168.0.1")
    victims = {}
    for name in ("emulation.log",):
        v = tmp_path / ("victim-" + name)
        v.write_text("precious")
        os.symlink(str(v), str(world.work / name))
        victims[name] = v
    for name in check.STATE_FILES:
        v = tmp_path / ("victim-" + name)
        v.write_text("precious")
        os.symlink(str(v), str(world.work / name))
        victims[name] = v
    rc, _, _ = world.run(curl_ok="http://192.168.0.1")
    assert rc == 0 and world.state["web"] == "true\n"
    for name, v in victims.items():
        assert v.read_text() == "precious"
        assert not os.path.islink(str(world.work / name))
    assert (world.work / "emulation.log").read_text() == "started\nto-stderr\n"
    for name in check.STATE_FILES:
        assert not os.path.islink(str(world.work / name))


def test_write_state_refuses_a_symlink_that_reappears(tmp_path, monkeypatch):
    d = os.open(str(tmp_path), os.O_RDONLY)
    target = tmp_path / "target"
    target.write_text("x")
    real_unlink = os.unlink

    def racing_unlink(name, dir_fd=None):
        real_unlink(name, dir_fd=dir_fd)
        os.symlink(str(target), name, dir_fd=dir_fd)
    (tmp_path / "web").write_text("old")
    monkeypatch.setattr(check.os, "unlink", racing_unlink)
    try:
        with pytest.raises(FileExistsError):
            check.write_state(d, "web", "true\n")
    finally:
        monkeypatch.undo()
        os.close(d)
    assert target.read_text() == "x"


@pytest.mark.parametrize("ip_num,n_files,expected", [
    ("300", 300, 8), ("3", 3, 3), ("08", 8, 8), ("00003", 8, 8), ("99999999999999999999999", 10, 8),
    ("abc", 3, 0), ("", 3, 0), (" 3", 3, 0), ("3\r", 3, 0), ("3\n\n", 3, 3), ("0", 3, 0), ("-1", 3, 0),
])
def test_ip_num_is_parsed_as_before(world, ip_num, n_files, expected):
    (world.work / "ip_num").write_text(ip_num)
    for i in range(n_files):
        (world.work / ("ip.%d" % i)).write_text("10.0.0.%d\n" % (i + 1))
    world.run()
    probed = sorted({c.split()[-1] for c in world.calls if c.startswith("ping ")})
    assert probed == sorted("10.0.0.%d" % (i + 1) for i in range(expected))


def test_ip_num_larger_than_the_bound_counts_as_garbled(world):
    (world.work / "ip_num").write_text("0" * (check.MAX_IP_NUM_BYTES + 1))
    (world.work / "ip.0").write_text("10.0.0.1")
    world.run()
    assert world.calls == []


def test_invalid_guest_addresses_are_skipped_with_a_warning(world):
    """DD: ip.N must hold IPv4 addresses (it is written from the guest's serial log)."""
    tap(world, "10.0.0.1", "10.0.0.2 10.0.0.3", "-oProxyCommand=x", "999.1.1.1", "10.0.0.4\x00",
        "http://evil/ 1.2.3\t*", "fe80::1", "١.1.1.1")
    rc, out, _ = world.run()
    probed = sorted({c.split()[-1] for c in world.calls if c.startswith("ping ")})
    assert probed == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    assert "from 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4: terminating" in out
    for name, bad in (("ip.2", "-oProxyCommand=x"), ("ip.3", "999.1.1.1"), ("ip.5", "http://evil/"),
                      ("ip.5", "1.2.3"), ("ip.5", "*"), ("ip.6", "fe80::1")):
        assert "[!] %s: %r is not an IPv4 address: skipped" % (name, bad.encode()) in out
    assert out.count("is not an IPv4 address: skipped") == 7
    assert not any("evil" in c or "Proxy" in c for c in world.calls)


@pytest.mark.parametrize("bad,reason", [
    ("127.0.0.2", "loopback"), ("127.0.0.1", "loopback"), ("0.0.0.0", "0.0.0.0/8"), ("0.1.2.3", "0.0.0.0/8"),
    ("224.0.0.1", "multicast"), ("169.254.3.4", "link-local"), ("240.1.1.1", "reserved"),
    ("255.255.255.255", "limited broadcast"),
])
def test_guest_addresses_the_host_must_not_probe_are_skipped(world, bad, reason):
    """audit B1: ip.0 = 127.0.0.2 (guest log ifa:0x0200007f) was curled and
    pinged as root: the host's own service answered, web=true."""
    tap(world, bad, "10.0.0.1")
    rc, out, _ = world.run(curl_ok="http://%s" % bad, ping_ok=True)
    line = next(l for l in out.splitlines() if l.startswith("[!] ip.0: %s is " % bad))
    assert reason in line and line.endswith(", not a guest address: skipped")
    assert not any(bad in c for c in world.calls)
    assert world.calls[0] == "curl --max-time 2 --output /dev/null --silent http://10.0.0.1"
    assert world.state.get("ip") == "10.0.0.1\n" and "web" not in world.state


def test_usable_guest_ip_definition():
    for ip in ("10.0.0.1", "192.168.0.1", "8.8.8.8", "100.64.0.1", "223.255.255.255", "169.253.0.1"):
        assert check.usable_guest_ip(ip)
    for ip in ("127.0.0.2", "0.0.0.0", "0.255.255.255", "224.0.0.0", "239.1.1.1", "169.254.0.0",
               "240.0.0.0", "255.255.255.254", "255.255.255.255", "nonsense", ""):
        assert not check.usable_guest_ip(ip)


def _local_non_loopback_address():
    """An address of this host outside 127/8 (the source address of a route), or None."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return ip if check.usable_guest_ip(ip) else None


def test_host_has_address_uses_bind():
    assert check.host_has_address("127.0.0.1")
    assert check.host_has_address("127.0.0.2")         # all of 127/8 is local on Linux
    assert not check.host_has_address("192.0.2.123")   # TEST-NET-1, never assigned here
    ip = _local_non_loopback_address()
    if ip is not None:
        assert check.host_has_address(ip)


def test_host_has_address_treats_an_address_in_use_as_local(monkeypatch):
    import errno
    import socket

    class S:
        def __init__(self, err):
            self.err, self.closed = err, False

        def bind(self, addr):
            raise OSError(self.err, os.strerror(self.err))

        def close(self):
            self.closed = True
    made = []
    for err, local in ((errno.EADDRINUSE, True), (errno.EADDRNOTAVAIL, False), (errno.EACCES, True)):
        monkeypatch.setattr(check.socket, "socket", lambda *a: made.append(S(err)) or made[-1])
        assert check.host_has_address("10.0.0.1") is local
        assert made[-1].closed


def test_check_network_skips_addresses_of_this_host(capsys):
    """At probe time: an address assigned to the host (bind test) is not probed."""
    calls = []
    r = check.check_network(["127.0.0.2", "192.0.2.123"], 30, clock=FakeClock(),
                            run=lambda argv: calls.append(argv[-1]) or False)
    assert calls and set(calls) == {"http://192.0.2.123", "https://192.0.2.123", "192.0.2.123"}
    err = capsys.readouterr().err
    assert err.count("[!] 127.0.0.2 is an address of this host, not the guest's: not probed") == 1
    assert r.ip == "None"


def test_check_network_rechecks_at_probe_time_and_stops_when_only_host_addresses_remain(capsys):
    local = set()
    calls = []

    def run(argv):
        calls.append(argv[-1])
        local.add("10.0.0.1")              # e.g. the address appears on a host interface
        return False
    clock = FakeClock()
    check.check_network(["10.0.0.1"], 3600, clock=clock, run=run, is_local=lambda ip: ip in local)
    assert calls == ["http://10.0.0.1", "https://10.0.0.1", "10.0.0.1"]   # one round, then stop
    assert "10.0.0.1 is an address of this host" in capsys.readouterr().err


def test_a_local_non_loopback_address_in_ip_n_is_not_probed(world):
    ip = _local_non_loopback_address()
    if ip is None:
        pytest.skip("no non-loopback IPv4 address on this host")
    tap(world, ip)
    rc, out, err = world.run(curl_ok="http://%s" % ip, ping_ok=True)
    assert rc == 0 and world.calls == [] and world.state == {}
    assert "%s is an address of this host" % ip in err


def test_bind_check_is_off_when_nonlocal_bind_is_enabled(monkeypatch, capsys):
    monkeypatch.setattr(check, "_nonlocal_bind", lambda: True)
    assert check.local_address_check() is None
    assert "ip_nonlocal_bind is on" in capsys.readouterr().err
    monkeypatch.setattr(check, "_nonlocal_bind", lambda: False)
    assert check.local_address_check() is check.host_has_address


def test_guest_address_files_that_are_symlinks_or_huge_are_ignored(world, tmp_path):
    tap(world, "10.0.0.1", "10.0.0.2", "10.0.0.3")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("10.9.9.9")
    (world.work / "ip.1").unlink()
    os.symlink(str(elsewhere), str(world.work / "ip.1"))
    (world.work / "ip.2").write_text("10.0.0.3 " * 1000)
    rc, out, _ = world.run()
    probed = sorted({c.split()[-1] for c in world.calls if c.startswith("ping ")})
    assert probed == ["10.0.0.1"]
    assert "ip.2 is larger than 4096 bytes: ignored" in out


@pytest.mark.parametrize("content,dhcp", [
    ("true", True), ("true\n", True), (" true \n", True), ("false", False), ("", False),
    ("untrue", False), ("true\ntrue", False), ("TRUE", False),
])
def test_isdhcp_is_true_only_for_exactly_true(world, content, dhcp):
    """DD: was `egrep -sq true` (any line containing "true")."""
    (world.work / "isDhcp").write_text(content)
    (world.work / "ip_num").write_text("0")
    rc, out, _ = world.run()
    assert ("on 127.0.0.1 port(s)" in out) == dhcp
    assert ("hostfwd is missing or invalid" in out) == dhcp


def test_symlinked_isdhcp_is_not_dhcp(world, tmp_path):
    t = tmp_path / "t"
    t.write_text("true")
    os.symlink(str(t), str(world.work / "isDhcp"))
    rc, out, _ = world.run()
    assert "from : terminating" in out


def test_run_sh_runs_in_our_process_group_with_sigint_ignored(world, tmp_path):
    """As a bash background job: same process group, SIGINT/SIGQUIT ignored,
    stdin /dev/null."""
    ready = tmp_path / "ready"
    world.run_sh('exec -a qemu-system-mipsel python3 %s -drive file=%s/image.raw --ready %s --life 60'
                 % (world.fake, world.work, ready))
    tap(world)

    class Clock(FakeClock):
        def sleep(self, seconds):
            if not ready.exists():
                wait_for(ready.exists)
            super().sleep(seconds)
    rc, out, _ = world.run(clock=Clock())
    assert rc == 0
    pgid, ign = ready.read_text().split()
    assert int(pgid) == os.getpgrp()
    mask = int(ign, 16)
    assert mask & (1 << (signal.SIGINT - 1)) and mask & (1 << (signal.SIGQUIT - 1))
    assert not mask & (1 << (signal.SIGTERM - 1)) and not mask & (1 << (signal.SIGHUP - 1))
    # finish(): stop_qemu SIGTERMed this image's "QEMU" (here: run.sh itself)
    assert procutil.qemu_pids(str(world.root / "scratch"), IID) == []


def test_finish_stops_this_images_qemu_and_waits_for_run_sh(world, procs):
    tap(world)
    q = world.qemu()
    world.run_sh("exec sleep 60")
    rc, out, _ = world.run()
    assert rc == 0
    assert q.wait(timeout=10) == -signal.SIGTERM
    # run.sh did not end by itself: SIGKILL after 30 s (60 polls of 0.5 s)
    assert world.clock.slept.count(0.5) >= 60


def test_signal_between_the_check_and_the_cleanup_still_cleans_up_once(world, monkeypatch):
    """audit B4: a SIGTERM after _check returned but before finish() had set
    `cleaning` raised _Signalled inside finish(): it escaped main() (exit 1,
    traceback) and stop_qemu never ran. Injected exactly there: the first
    finish() call is interrupted on entry, as on_signal would do it."""
    tap(world)
    stops = []
    monkeypatch.setattr(check.procutil, "stop_qemu", lambda *a, **k: stops.append(a))
    real_finish = check._Run.finish
    entered = []

    def finish(self):
        entered.append(self.cleaning)
        if len(entered) == 1:
            self.cleaning = False          # the window as it was before the fix
            self.on_signal(signal.SIGTERM, None)
        return real_finish(self)
    monkeypatch.setattr(check._Run, "finish", finish)
    rc, out, err = world.run()
    assert rc == 143
    assert len(stops) == 1 and stops[0][1] == IID
    assert "Check inferred emulation end" not in out


def test_cleanup_is_marked_before_finish_after_a_normal_check(world, monkeypatch):
    """The fix itself: once _check has returned, a signal no longer raises."""
    tap(world)
    seen = []
    real_finish = check._Run.finish

    def finish(self):
        seen.append(self.cleaning)
        self.on_signal(signal.SIGTERM, None)     # only recorded now
        return real_finish(self)
    monkeypatch.setattr(check._Run, "finish", finish)
    rc, out, _ = world.run()
    assert seen == [True] and rc == 143


def test_signals_are_blocked_while_run_sh_is_forked(world, monkeypatch):
    """audit B2: a signal between fork and `ctx.child = ...` must stay pending,
    or the cleanup would not know run.sh. At the moment Popen runs, SIGINT,
    SIGTERM and SIGHUP are blocked in this thread; afterwards they are not."""
    tap(world)
    masks = []
    real_popen = check.subprocess.Popen

    def popen(argv, *a, **k):
        if argv[0].endswith("/run.sh"):           # not curl / ping (subprocess.run)
            masks.append(signal.pthread_sigmask(signal.SIG_BLOCK, []))
        return real_popen(argv, *a, **k)
    monkeypatch.setattr(check.subprocess, "Popen", popen)
    before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    rc, _, _ = world.run()
    assert rc == 0 and len(masks) == 1
    assert {signal.SIGINT, signal.SIGTERM, signal.SIGHUP} <= set(masks[0])
    assert signal.pthread_sigmask(signal.SIG_BLOCK, []) == before
    assert not {signal.SIGINT, signal.SIGTERM, signal.SIGHUP} & set(before)


def test_missing_run_sh_is_reported_in_the_log(world):
    tap(world, "10.0.0.1")
    (world.work / "run.sh").unlink()
    rc, out, err = world.run(curl_ok="http://10.0.0.1")
    assert rc == 0 and "Check inferred emulation end" in out
    assert "run.sh: No such file or directory" in (world.work / "emulation.log").read_text()
    assert world.state["web"] == "true\n"          # as before: the check itself still ran


def test_dhcp_ownership_failure_is_logged_and_ends_the_check(world, procs):
    (world.work / "isDhcp").write_text("true")
    (world.work / "hostfwd").write_text("tcp 80 10123\ntcp 443 10124\n")
    world.qemu()
    stub(world.bindir, "ss", "exit 1")
    rc, out, err = world.run(curl_ok="http://127.0.0.1:10123")
    assert rc == 0 and world.state == {}
    assert "on 127.0.0.1 port(s) 10123/10124 (guest 80/443)" in out
    assert "no listener found on port 10123 (web=false)" in err
    assert "answer on 127.0.0.1:10123 does not count; web check stopped" in err
    assert world.calls == ["curl --noproxy * --max-time 2 --output /dev/null --silent http://127.0.0.1:10123"]


def test_dhcp_without_web_port_mapping_probes_nothing_and_does_not_wait(world):
    (world.work / "isDhcp").write_text("true")
    (world.work / "hostfwd").write_text("udp 161 10126\n")
    rc, out, _ = world.run()
    assert "port(s) -/- (guest 80/443)" in out
    assert world.calls == [] and world.state == {}
    assert world.clock.slept == [10]                # no second `sleep 10`, no probe loop


def test_tap_without_addresses_does_not_wait_either(world):
    tap(world)
    world.run()
    assert world.clock.slept == [10] and world.calls == []


def test_probe_loop_is_bounded_by_check_timeout(world):
    tap(world, "10.0.0.1")
    world.run()
    pings = [c for c in world.calls if c.startswith("ping")]
    # now() advances 10 s per reading; start=0, first `current`=10, deadline 360
    assert len(pings) == 36


def test_usage_and_bad_arguments(world):
    for argv in ((), (IID,), (IID, "mipsel", "x")):
        rc, out, _ = world.run(argv)
        assert rc == 1 and out == "./scripts/check_emulation.sh: Usage: ./check_emulation.sh [iid] [arch]\n"
    for iid in ("abc", "-1", "5/../6", ""):
        rc, out, err = world.run((iid, "mipsel"))
        assert rc == 1 and "Invalid image number" in err and "start" not in out
    rc, out, _ = world.run((IID, "anything"))               # the architecture is not used
    assert rc == 0


def test_symlinked_work_directory_is_refused(world, tmp_path):
    real = tmp_path / "real"
    world.work.rename(real)
    os.symlink(str(real), str(world.work))
    rc, out, err = world.run()
    assert rc == 1 and "start" not in out and "symlink" in err
    assert not (real / "emulation.log").exists()


def test_elapsed_is_formatted_like_bc():
    assert check.elapsed(0.0, 0.0) == "0"
    assert check.elapsed(12.5, 0.25) == "12.250000000"
    assert check.elapsed(0.5, 0.0) == ".500000000"


# ======================================================================
# the wrapper, end to end
# ======================================================================

@pytest.fixture
def tree(repo_root, tmp_path):
    root = tmp_path / "FirmAE"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(repo_root / "firmae.config", root)
    shutil.copytree(repo_root / "firmae", root / "firmae", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(repo_root / "scripts" / "check_emulation.sh", root / "scripts")
    (root / "scripts" / "check_emulation.sh").chmod(0o755)
    work = root / "scratch" / IID
    work.mkdir(parents=True)
    (work / "image.raw").write_text("")
    (work / "isDhcp").write_text("false")
    (work / "ip_num").write_text("0")
    fake = tmp_path / "fake.py"
    fake.write_text(FAKE_QEMU)
    env = dict(os.environ)
    for v in ("FIRMAE_DOCKER", "PYTHONPATH"):
        env.pop(v, None)
    return root, work, env, fake


def test_wrapper_is_thin_executable_and_lf(repo_root):
    p = repo_root / "scripts" / "check_emulation.sh"
    data = p.read_bytes()
    assert b"\r" not in data and data.splitlines()[0] == b"#!/bin/bash"
    assert b'exec python3 -I "${FIRMAE_HOME}/firmae/check.py" "$0" "$@"' in data
    assert b"PYTHONPATH=" not in data and b"-m firmae" not in data
    assert len(data.splitlines()) < 20
    assert os.access(str(p), os.X_OK)


def test_wrapper_normal_run(tree):
    root, work, env, _ = tree
    (work / "run.sh").write_text("#!/bin/bash\necho hello\n")
    (work / "run.sh").chmod(0o755)
    (work / "web").write_text("true\n")                       # stale
    res = subprocess.run(["./scripts/check_emulation.sh", IID, "mipsel"], cwd=str(root), env=env,
                         capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stderr
    assert res.stdout.splitlines() == [
        "===== Check inferred emulation start =====",
        "[*] Inferred network: terminating after 360 secs...",
        "[*] Waiting web service... from : terminating after 360 secs...",
        "=====  Check inferred emulation end  =====",
    ]
    assert (work / "emulation.log").read_text() == "hello\n"
    assert not (work / "web").exists()


def _cdpath_decoy(tmp_path):
    decoy = tmp_path / "decoy"
    (decoy / "scripts").mkdir(parents=True)
    (decoy / "firmae").mkdir()
    return decoy


def test_wrapper_with_cdpath_exported(tree, tmp_path):
    """audit B6: `cd "$(dirname ...)/.."` with CDPATH exported printed the
    directory found via CDPATH, and FIRMAE_HOME became "<dir>\\n<dir>" (or
    another tree). Started as scripts/check_emulation.sh (no ./), so CDPATH applies."""
    root, work, env, _ = tree
    (work / "run.sh").write_text("#!/bin/bash\necho hello\n")
    (work / "run.sh").chmod(0o755)
    decoy = _cdpath_decoy(tmp_path)
    res = subprocess.run(["bash", "scripts/check_emulation.sh", IID, "mipsel"], cwd=str(root),
                         env=dict(env, CDPATH="%s:" % decoy), capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout.splitlines()[-1] == "=====  Check inferred emulation end  ====="
    assert (work / "emulation.log").read_text() == "hello\n"


@pytest.mark.parametrize("name", ["check_emulation.sh", "run.armel.sh", "run.mipseb.sh", "run.mipsel.sh"])
def test_wrappers_find_the_installation_with_cdpath_exported(repo_root, tmp_path, name):
    """The FIRMAE_HOME line of every python3 -I wrapper (B6), run with the exec
    replaced by an echo (no QEMU): relative, ./-relative and absolute starts."""
    root = tmp_path / "inst"
    (root / "scripts").mkdir(parents=True)
    text = (repo_root / "scripts" / name).read_text()
    lines = [l for l in text.splitlines() if l.startswith("FIRMAE_HOME=")]
    assert len(lines) == 1 and "CDPATH= cd -- " in lines[0] and ">/dev/null" in lines[0]
    (root / "scripts" / name).write_text("#!/bin/bash\n%s\nprintf '%%s' \"${FIRMAE_HOME}\"\n" % lines[0])
    decoy = _cdpath_decoy(tmp_path)
    for argv in (["bash", "scripts/" + name], ["bash", "./scripts/" + name], ["bash", str(root / "scripts" / name)]):
        res = subprocess.run(argv, cwd=str(root), env=dict(os.environ, CDPATH="%s:" % decoy),
                             capture_output=True, text=True, timeout=60)
        assert res.returncode == 0 and res.stdout == str(root), (argv, res.stdout, res.stderr)


def test_wrapper_usage(tree, tmp_path):
    root, work, env, _ = tree
    res = subprocess.run([str(root / "scripts" / "check_emulation.sh")], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 1
    assert res.stdout == "%s: Usage: ./check_emulation.sh [iid] [arch]\n" % (root / "scripts" / "check_emulation.sh")


@pytest.mark.parametrize("sig,code,to_group", [
    (signal.SIGINT, 130, True), (signal.SIGTERM, 143, True), (signal.SIGHUP, 129, True),
    (signal.SIGTERM, 143, False), (signal.SIGINT, 130, False),
])
def test_wrapper_signals_clean_up_and_exit_like_the_bash_traps(tree, tmp_path, sig, code, to_group):
    """Ctrl-C (SIGINT to the whole group: run.sh ignores it like a bash
    background job, its "QEMU" is stopped by stop_qemu) or a signal to the
    checker alone: this image's QEMU is stopped, run.sh reaped, 130/143/129."""
    root, work, env, fake = tree
    ready = tmp_path / "ready"
    (work / "run.sh").write_text("#!/bin/bash\nexec -a qemu-system-mipsel python3 %s -drive file=%s/image.raw "
                                 "--ready %s --life 120\n" % (fake, work, ready))
    (work / "run.sh").chmod(0o755)
    p = subprocess.Popen(["./scripts/check_emulation.sh", IID, "mipsel"], cwd=str(root), env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        wait_for(ready.exists, timeout=30)
        pgid, _ = ready.read_text().split()
        assert int(pgid) == p.pid                       # run.sh is in the checker's group
        qemu = procutil.qemu_pids(str(root / "scratch"), IID)
        assert len(qemu) == 1
        if to_group:
            os.killpg(p.pid, sig)
        else:
            os.kill(p.pid, sig)
        out, err = p.communicate(timeout=60)
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=30)
    assert p.returncode == code, err
    assert b"Check inferred emulation end" not in out
    assert procutil.qemu_pids(str(root / "scratch"), IID) == []


def _evil_tree(base, marker, name):
    d = base / name
    (d / "firmae").mkdir(parents=True)
    body = 'open(%r, "a").write("SHADOWED %%s\\n" %% __name__)\n' % str(marker)
    (d / "firmae" / "__init__.py").write_text(body)
    for mod in ("check", "config", "errors", "hostfwd", "procutil"):
        (d / "firmae" / (mod + ".py")).write_text(body + "raise SystemExit(0)\n")
    for mod in ("subprocess", "os", "re", "signal", "ipaddress", "socket", "errno", "shutil", "stat", "time",
                "sitecustomize"):
        (d / (mod + ".py")).write_text(body + "raise SystemExit(0)\n")
    return d


def test_hostile_cwd_and_pythonpath_cannot_replace_the_code(tree, tmp_path):
    root, work, env, _ = tree
    marker = tmp_path / "marker"
    evil = _evil_tree(tmp_path, marker, "evil")
    evil2 = _evil_tree(tmp_path, marker, "evil2")
    # the package's own directory as cwd too (firmae/config.py there must not shadow anything)
    for cwd in (evil, root / "firmae"):
        res = subprocess.run([str(root / "scripts" / "check_emulation.sh"), "bad"], cwd=str(cwd),
                             env=dict(env, PYTHONPATH=str(evil2)), capture_output=True, text=True, timeout=60)
        assert res.returncode == 1 and "Usage: ./check_emulation.sh" in res.stdout, res.stderr
    assert not marker.exists(), marker.read_text() if marker.exists() else ""
