"""scripts/run_mode.sh with DHCP / user-network images (audit of 5.1): there
"ip" is 127.0.0.1, the HOST, and the guest is reachable only through the
loopback ports in scratch/<IID>/hostfwd. analyze and debug are refused (their
tools would target the host's own services as root), run probes only the
mapped port of this image's QEMU. TAP images behave as before.
All commands are stubs; nothing is emulated."""

import os
import shutil
import subprocess
import time

import pytest

from scripts import makeNetwork as mn

pytestmark = pytest.mark.linux

FAKE_QEMU = r'''
import socket, sys, time
args = sys.argv[1:]
ports = [int(p) for p in args[args.index("--ports") + 1].split(",") if p]
socks = []
for p in ports:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", p))
    s.listen(8)
    socks.append(s)
print("emulation-ran", flush=True)
time.sleep(float(args[args.index("--life") + 1]))
'''


def stub(d, name, body):
    p = d / name
    p.write_text("#!/bin/bash\n" + body + "\n")
    p.chmod(0o755)


def free_ports(n):
    found = []
    start = mn.HOSTFWD_PORT_MIN + (os.getpid() * 104729) % 9000
    for p in list(range(start, mn.HOSTFWD_PORT_MAX + 1)) + list(range(mn.HOSTFWD_PORT_MIN, start)):
        if mn.hostPortIsFree("tcp", p) and mn.hostPortIsFree("udp", p):
            found.append(p)
            if len(found) == n:
                return found
    pytest.skip("no free ports in the hostfwd range")


@pytest.fixture
def world(repo_root, tmp_path):
    root = tmp_path / "FirmAE"
    (root / "scripts").mkdir(parents=True)
    (root / "analyses").mkdir()
    shutil.copy(repo_root / "firmae.config", root)
    for name in ("run_mode.sh", "hostfwd_check.sh"):
        shutil.copy(repo_root / "scripts" / name, root / "scripts")
    work = root / "scratch" / "9"
    work.mkdir(parents=True)
    (work / "image.raw").write_text("")
    log = tmp_path / "log"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    rec = 'echo "$(basename "$0") $*" >> %s' % log
    # curl "answers" only for $CURL_OK; the URL is the last argument
    stub(bindir, "curl", 'echo "curl ${@: -1}" >> %s; [ -n "${CURL_OK:-}" ] && [ "${@: -1}" = "$CURL_OK" ]' % log)
    stub(bindir, "ping", rec + "; exit 1")
    stub(bindir, "sleep", "exec /bin/sleep 0.05")
    for script in ("run_analyze.sh", "run_debug.sh", "run_boot.sh"):
        stub(work, script, rec)
    stub(root / "analyses", "analyses_all.sh", rec)
    stub(root, "debug.py", rec)
    (work / "ip").write_text("127.0.0.1\n")
    fake = tmp_path / "fakeqemu.py"
    fake.write_text(FAKE_QEMU)
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    env.pop("FIRMAE_DOCKER", None)

    def run(mode, dhcp, ip="127.0.0.1", web="true", ping="true", curl_ok=None, run_sh=None, timeout=60):
        (work / "isDhcp").write_text("true" if dhcp else "false")
        stub(work, "run.sh", run_sh or (rec + "; /bin/sleep 1"))
        if log.exists():
            log.unlink()
        e = dict(env, CURL_OK=curl_ok) if curl_ok else env
        # `wait`: collect the background web check's output too
        res = subprocess.run(["bash", "-c", 'bash scripts/run_mode.sh "$@"; rc=$?; wait; exit $rc', "_",
                              mode, "9", "mipsel", "brand", ip, web, ping, "127.0.0.1"],
                             cwd=root, env=e, capture_output=True, text=True, timeout=timeout)
        calls = log.read_text().splitlines() if log.exists() else []
        return res, calls

    def qemu_run_sh(ports, life):
        """run.sh that becomes this image's (fake) QEMU, listening on `ports`"""
        return ('exec -a qemu-system-mipsel python3 %s -drive if=ide,format=raw,file=%s '
                '--ports %s --life %s' % (fake, work / "image.raw", ",".join(map(str, ports)), life))
    run.work = work
    run.qemu_run_sh = qemu_run_sh
    return run


def test_dhcp_analyze_is_refused_without_running_any_tool(world):
    res, calls = world("analyze", dhcp=True)
    assert res.returncode == 60, res.stdout + res.stderr          # ExitCode.ANALYSIS
    assert "Analysis is not supported for DHCP/user-network images" in res.stderr
    assert calls == []                      # no run_analyze.sh, no analyses_all.sh, no curl/ping


def test_dhcp_analyze_is_refused_even_without_web(world):
    res, calls = world("analyze", dhcp=True, web="false", ping="false")
    assert res.returncode == 60 and calls == []


def test_dhcp_debug_is_refused_with_the_right_reason(world):
    res, calls = world("debug", dhcp=True)
    assert res.returncode == 50, res.stdout + res.stderr          # ExitCode.UNREACHABLE
    assert "Debug mode is not supported for DHCP/user-network images" in res.stderr
    assert "Network unreachable" not in res.stdout + res.stderr
    assert calls == []


def test_dhcp_run_probes_only_the_mapped_port_of_this_qemu(world):
    h80, h443 = free_ports(2)
    (world.work / "hostfwd").write_text("tcp 80 %d\ntcp 443 %d\n" % (h80, h443))
    res, calls = world("run", dhcp=True, curl_ok="http://127.0.0.1:%d" % h80,
                       run_sh=world.qemu_run_sh([h80, h443], 3))
    assert res.returncode == 0, res.stdout + res.stderr
    assert "emulation-ran" in res.stdout
    assert "127.0.0.1 true true" in res.stdout
    assert calls and all(c in ("curl http://127.0.0.1:%d" % h80, "curl https://127.0.0.1:%d" % h443)
                         for c in calls), calls
    assert not any(c.startswith("ping") for c in calls)


def test_dhcp_run_without_mapping_probes_nothing(world):
    res, calls = world("run", dhcp=True, curl_ok="http://127.0.0.1")
    assert res.returncode == 0
    assert "hostfwd is missing or invalid" in res.stdout
    assert [c for c in calls if c.startswith(("curl", "ping"))] == []


def test_tap_run_is_unchanged(world):
    """TAP: check_network on the guest IP (curl + ping), as before."""
    (world.work / "hostfwd").write_text("tcp 80 10123\n")       # ignored in TAP mode
    res, calls = world("run", dhcp=False, ip="192.0.2.7")
    assert res.returncode == 0, res.stderr
    assert "run.sh " in calls
    probes = [c for c in calls if c.startswith(("curl", "ping"))]
    assert "curl http://192.0.2.7" in probes and "ping -c 1 192.0.2.7" in probes
    assert not any("127.0.0.1" in c for c in probes)


def test_tap_analyze_and_debug_still_run_their_tools(world):
    (world.work / "ip").write_text("192.0.2.7\n")               # what check_emulation.sh recorded
    res, calls = world("analyze", dhcp=False, ip="192.0.2.7", curl_ok="http://192.0.2.7", timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "run_analyze.sh " in calls
    assert "analyses_all.sh 9 brand 192.0.2.7 127.0.0.1" in calls
    res, calls = world("debug", dhcp=False, ip="192.0.2.7", curl_ok="http://192.0.2.7", timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "run_debug.sh " in calls and "debug.py 9" in calls


def test_tap_debug_without_ping_still_says_network_unreachable(world):
    res, calls = world("debug", dhcp=False, ip="", ping="false")
    assert res.returncode == 0 and "Network unreachable" in res.stdout and calls == []
