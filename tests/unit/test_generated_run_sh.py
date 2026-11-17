"""Execute scratch/<IID>/run.sh as makeNetwork.py writes it -- the wrapper,
scripts/emulate.sh and emulation.conf -- with every system command stubbed,
and check that it cleans up on every exit path (REFACTORING_PLAN 3.2): normal
end, SIGTERM, Ctrl-C (SIGINT to the process group), START_NET failure, image
preparation failure. No root, no real QEMU, mount or TAP.
(Equality with the old generated script: test_emulate_equivalence.py.)
"""

import os
import re
import signal
import socket
import subprocess
import time

import pytest

from emulation_world import World
from scripts import makeNetwork as mn

pytestmark = pytest.mark.linux

USER = os.environ.get("USER", "root")


@pytest.fixture
def world(repo_root, tmp_path, firmae_env, iptables_stubs):
    w = World(tmp_path, repo_root, iptables_stubs)
    w.install(mn.qemuCmd(1, [("192.168.0.1", "eth0", None, None, "br0")], [], "normal",
                         "mips", "el", "rdinit=/firmadyne/preInit.sh", False))
    return w


def qemu_pid(w):
    return int(next(c for c in w.calls() if c.startswith("qemu start")).split()[-1])


def gone(pid):
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        return True


def test_normal_end_tears_the_network_down_once(world):
    p = world.start(QEMU_EXIT_AFTER="1")
    out, _ = p.communicate(timeout=60)
    assert p.returncode == 0, out
    c = world.calls()
    assert "tunctl -t tap1_0 -u %s" % USER in c
    assert c[-2:] == ["ip link set tap1_0 down", "tunctl -d tap1_0"]
    assert c.count("tunctl -d tap1_0") == 1
    assert c.count("del_partition /dev/fakeloop0") == 1
    assert "qemu exit" in c
    assert out.rstrip().endswith("Done!")


@pytest.mark.parametrize("how,expected_rc", [("sigterm", 143), ("ctrl-c", 130), ("sighup", 129)])
def test_interrupt_stops_qemu_and_cleans_up(world, how, expected_rc):
    p = world.start()
    world.wait_for("qemu start")
    q = qemu_pid(world)
    if how == "sigterm":
        p.send_signal(signal.SIGTERM)            # only the script, like `kill <pid>`
    elif how == "sighup":
        p.send_signal(signal.SIGHUP)
    else:
        os.killpg(p.pid, signal.SIGINT)          # the whole foreground group, like Ctrl-C
    out, _ = p.communicate(timeout=30)
    assert p.returncode == expected_rc, out
    c = world.calls()
    assert "qemu got TERM" in c
    assert c[-2:] == ["ip link set tap1_0 down", "tunctl -d tap1_0"]
    for _ in range(50):
        if gone(q):
            break
        time.sleep(0.1)
    assert gone(q)


def test_the_started_pid_is_the_emulation(world):
    """check_emulation.sh / run_mode.sh keep the PID of run.sh and wait for it:
    the wrapper execs emulate.sh, so that PID is QEMU's parent and lives until
    the cleanup has finished."""
    p = world.start(QEMU_LOG_ARGS="1")
    world.wait_for("qemu env ")
    env_line = next(c for c in world.calls() if c.startswith("qemu env "))
    assert env_line.endswith("ppid=%d" % p.pid)
    with open("/proc/%d/cmdline" % p.pid, "rb") as f:
        argv = f.read().split(b"\0")
    assert argv[1:5] == [b"./scripts/emulate.sh", b"./scratch/1/run.sh", b"1", b"."]
    p.send_signal(signal.SIGTERM)
    p.communicate(timeout=30)
    assert world.calls()[-1] == "tunctl -d tap1_0"   # cleanup done before the PID went away


def test_qemu_pids_still_finds_this_images_qemu(world, tmp_path):
    """qemu_pids (firmae.config): argv[0] qemu-system-*, an argument with
    file=<SCRATCH_DIR>/<IID>/image.raw."""
    world.stub("qemu-system-mipsel",
               'echo "qemu start $$" >> "$LOG"\n'
               'exec -a "$0" python3 -c "import time; time.sleep(60)" "$@"')
    p = world.start()
    try:
        world.wait_for("qemu start")
        q = qemu_pid(world)
        for _ in range(50):
            res = subprocess.run(["bash", "-c", "source ./firmae.config && qemu_pids 1"],
                                 cwd=str(world.root), env=world.env, capture_output=True,
                                 text=True, timeout=30)
            if res.stdout.split() == [str(q)]:
                break
            time.sleep(0.1)
        assert res.stdout.split() == [str(q)], res
    finally:
        p.send_signal(signal.SIGTERM)
        p.communicate(timeout=30)
    assert p.returncode == 143


@pytest.mark.parametrize("how", ["normal", "sigterm"])
def test_isolation_is_in_place_while_qemu_runs_and_gone_afterwards(world, how):
    p = world.start(QEMU_EXIT_AFTER="1") if how == "normal" else world.start()
    if how == "sigterm":
        world.wait_for("qemu start")
        p.send_signal(signal.SIGTERM)
    p.communicate(timeout=60)
    log = world.calls(firewall=True)
    first_fw = next(i for i, c in enumerate(log) if c.startswith("iptables -I INPUT"))
    qemu = next(i for i, c in enumerate(log) if c.startswith("qemu start"))
    removed = max(i for i, c in enumerate(log) if c.startswith("iptables -D FORWARD"))
    assert first_fw < qemu < removed
    assert log.index("tunctl -t tap1_0 -u %s" % USER) < first_fw
    assert world.rules.read_text() == ""


def test_start_net_failure_still_removes_what_was_created(world):
    p = world.start(FAIL_TUNCTL="1")
    out, _ = p.communicate(timeout=60)
    assert p.returncode != 0
    c = world.calls()
    assert not any(x.startswith("qemu start") for x in c)
    assert "tunctl -d tap1_0" in c               # was skipped before: set -e exited first
    assert not any(x.startswith("qemu start") for x in world.calls(firewall=True))


def test_image_preparation_failure_releases_the_loop_device(world):
    p = world.start(FAIL_MOUNT="1")
    out, _ = p.communicate(timeout=60)
    assert p.returncode != 0
    c = world.calls()
    assert "del_partition /dev/fakeloop0" in c   # loop device was leaked before
    assert not any(x.startswith("tunctl") for x in c)


@pytest.mark.parametrize("mode,kernel_args,debug_lines", [
    ("run.sh", "user_debug=0 firmadyne.syscall=1", 1),
    ("run_debug.sh", "user_debug=0 firmadyne.syscall=1", 3),
    ("run_analyze.sh", "user_debug=31 firmadyne.syscall=32", 1),
    ("run_boot.sh", "user_debug=0 firmadyne.syscall=1", 1),
])
def test_the_mode_comes_from_the_name_run_sh_was_started_as(world, mode, kernel_args, debug_lines):
    p = world.start(mode, QEMU_EXIT_AFTER="0.3", QEMU_LOG_ARGS="1")
    out, _ = p.communicate(timeout=60)
    assert p.returncode == 0, out
    args = next(c for c in world.calls() if c.startswith("qemu args "))
    assert args.startswith("qemu args -s -S -m 1024 ") == (mode == "run_boot.sh")
    assert (" %s -serial " % kernel_args) in args
    debug = (world.image / "firmadyne" / "debug.sh").read_text()
    assert debug.count("\n") == debug_lines and debug.startswith("#!/firmadyne/sh\n")


def test_manual_start_from_below_the_firmae_directory(world):
    for cwd in (world.root / "scratch", world.work):
        p = world.start(cwd=cwd, QEMU_EXIT_AFTER="0.3")
        out, _ = p.communicate(timeout=60)
        assert p.returncode == 0, out
    lonely = world.base / "x" / "y" / "z"
    lonely.mkdir(parents=True)
    p = world.start(cwd=lonely)
    out, _ = p.communicate(timeout=60)
    assert p.returncode == 1 and "Could not find 'firmae.config'" in out


DHCP_NET = [("10.0.2.15", "eth0", None, None, "br0")]


def free_ports(n, exclude=()):
    found = []
    start = mn.HOSTFWD_PORT_MIN + (os.getpid() * 7919) % 9000
    for p in list(range(start, mn.HOSTFWD_PORT_MAX + 1)) + list(range(mn.HOSTFWD_PORT_MIN, start)):
        if p not in exclude and mn.hostPortIsFree("tcp", p) and mn.hostPortIsFree("udp", p):
            found.append(p)
            if len(found) == n:
                return found
    pytest.skip("no free ports in the hostfwd range")


def test_user_network_run_sh_passes_loopback_hostfwd_to_qemu(world):
    """REFACTORING_PLAN 5.1: QEMU gets the chosen loopback host ports, not
    host port = guest port."""
    hf = [("tcp", 80, 10004), ("tcp", 443, 10005), ("udp", 161, 10006)]
    world.install(mn.qemuCmd(1, DHCP_NET, [("udp", "0.0.0.0", 161)], "normal", "mips", "el",
                             "rdinit=/firmadyne/preInit.sh", True, hf))
    p = world.start(QEMU_EXIT_AFTER="1", QEMU_LOG_ARGS="1")
    out, _ = p.communicate(timeout=60)
    if "(hostfwd) is in use" in out:
        pytest.skip("10004/10005 are taken on this host")
    assert p.returncode == 0, out
    args = next(c for c in world.calls() if c.startswith("qemu args "))
    assert ("-netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:10004-:80,"
            "hostfwd=tcp:127.0.0.1:10005-:443,hostfwd=udp:127.0.0.1:10006-:161 ") in args
    assert args.endswith(" " + mn.emulationQemuNetwork(world.data.read_text()))


def test_user_network_run_sh_stops_before_qemu_if_a_host_port_is_taken(world):
    taken, other = free_ports(2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", taken))
    s.listen(1)
    try:
        world.install(mn.qemuCmd(1, DHCP_NET, [], "normal", "mips", "el",
                                 "rdinit=/firmadyne/preInit.sh", True,
                                 [("tcp", 80, other), ("tcp", 443, taken)]))
        p = world.start(QEMU_EXIT_AFTER="1")
        out, _ = p.communicate(timeout=60)
    finally:
        s.close()
    assert p.returncode == 1, out
    assert "127.0.0.1:%d (hostfwd) is in use" % taken in out
    assert not any(c.startswith("qemu start") for c in world.calls())
    assert out.rstrip().endswith("Done!")            # cleanup() ran


def test_a_taken_udp_port_is_not_checked(world):
    """As before: only TCP host ports are pre-checked (a UDP bind is not a listener)."""
    taken, a, b = free_ports(3)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", taken))
    try:
        world.install(mn.qemuCmd(1, DHCP_NET, [("udp", "0.0.0.0", 161)], "normal", "mips", "el",
                                 "rdinit=/firmadyne/preInit.sh", True,
                                 [("tcp", 80, a), ("tcp", 443, b), ("udp", 161, taken)]))
        p = world.start(QEMU_EXIT_AFTER="0.3")
        out, _ = p.communicate(timeout=60)
    finally:
        s.close()
    assert p.returncode == 0, out


def norm(calls, pid):
    return [re.sub(r"^qemu start [0-9]+$", "qemu start PID", c.replace("ppid=%d" % pid, "ppid=RUNSH"))
            for c in calls]


@pytest.mark.parametrize("cwd", ["firmae_dir", "scratch_dir"])     # (an id "root" would mean: needs root)
def test_exported_cdpath_changes_nothing(world, tmp_path, cwd):
    """audit B6: with CDPATH exported, `cd dir` prints the directory it found
    via CDPATH and a $(cd ... && pwd) result is corrupted. The run.sh wrapper
    has no cd; emulate.sh sources firmae.config through ./, ../ or ../../
    (dot-relative: CDPATH is not consulted). A decoy tree on CDPATH that has
    every name the scripts cd into must not be used."""
    decoy = tmp_path / "decoy"
    for d in ("scripts", "scratch/1", "FirmAE", "firmae"):
        (decoy / d).mkdir(parents=True, exist_ok=True)
    start_dir = world.root if cwd == "firmae_dir" else world.root / "scratch"
    ref = world.start(cwd=start_dir, QEMU_EXIT_AFTER="0.3", QEMU_LOG_ARGS="1")
    ref_out, _ = ref.communicate(timeout=60)
    ref_calls = norm(world.calls(), ref.pid)
    world.log.write_text("")
    p = world.start(cwd=start_dir, QEMU_EXIT_AFTER="0.3", QEMU_LOG_ARGS="1",
                    CDPATH="%s:%s" % (decoy, decoy / "scratch"))
    out, _ = p.communicate(timeout=60)
    assert p.returncode == ref.returncode == 0, out
    assert out == ref_out and norm(world.calls(), p.pid) == ref_calls
    assert str(decoy) not in out and not any(str(decoy) in c for c in world.calls())
