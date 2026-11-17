"""REFACTORING_PLAN 4.4 (minimal): run.sh stopped being Bash generated from a
template. It is now a fixed wrapper that execs scripts/emulate.sh, which reads
the per-image values from scratch/<IID>/emulation.conf.

This module proves that nothing changed at run time: the OLD generated run.sh
(rendered by a frozen copy of makeNetwork.py at 38d1bb0, the last commit with
the template, tests/fixtures/legacy/) and the NEW wrapper + emulate.sh +
emulation.conf are executed in identical stubbed worlds
(tests/unit/emulation_world.py), and everything observable is compared:
every command the stubs saw, in order, with its arguments (sudo/tunctl/ip,
mount/umount, del_partition, iptables, the complete QEMU argv and
environment, QEMU's parent PID), stdout/stderr, the exit status, the files
written into the image and the firewall state afterwards.
"""

import importlib.util
import os
import re
import signal
import socket
import time

import pytest

from emulation_world import World
from scripts import makeNetwork as mn

pytestmark = pytest.mark.linux

INIT = "rdinit=/firmadyne/preInit.sh"
LEGACY_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "legacy",
                           "makeNetwork_38d1bb0.py")


def legacy_module():
    spec = importlib.util.spec_from_file_location("legacy_makeNetwork_38d1bb0", LEGACY_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LEGACY = legacy_module()


def fixture_args(read_fixture, name, arch, end):
    data = read_fixture("serial/serial_%s.log" % name)
    ports = mn.findPorts(data, end)
    ifaces = mn.findNonLoInterfaces(data, end)
    netlist = mn.getNetworkList(data, ifaces, mn.findMacChanges(data, end))
    filtered, network_type = mn.checkNetwork(netlist)
    is_user = any(mn.isDhcpIp(ip) for (ip, _, _, _, _) in filtered)
    return (1, filtered, ports, network_type, arch, end, INIT, is_user)


def test_the_frozen_legacy_generator_is_the_one_of_the_goldens(read_fixture, firmae_env):
    """The reference is right: the frozen copy renders the Phase 0 goldens."""
    for name, arch, end in (("armel_dir868l", "arm", "el"), ("mipseb_wnap320", "mips", "eb")):
        out = LEGACY.qemuCmd(*fixture_args(read_fixture, name, arch, end))
        assert out == read_fixture("generated/run_sh_%s.expected" % name).decode()


# (layout, FIRMAE_NET at generation time) -> qemuCmd arguments; hf = hostfwd rules
def layout_args(layout, read_fixture, hf):
    if layout == "armel_dir868l":        # TAP, VLAN 1, one NIC (arm + FIRMAE_NET)
        return fixture_args(read_fixture, "armel_dir868l", "arm", "el")
    if layout == "mipseb_wnap320":       # TAP, three placeholder NICs
        return fixture_args(read_fixture, "mipseb_wnap320", "mips", "eb")
    if layout == "dhcp":                 # user network; TAPs are still created
        net = [("10.0.2.15", "eth0", None, None, "br0"), ("192.168.0.1", "eth7", 3, None, "br1")]
        return (1, net, [("udp", "0.0.0.0", 161)], "normal", "mips", "el", INIT, True, hf)
    if layout == "dhcp_arm":
        net = [("10.0.2.15", "eth0", None, "00:11:22:33:44:55", "br0")]
        return (1, net, [], "normal", "arm", "el", INIT, True, hf)
    if layout in ("tap_vlans_nonet", "tap_vlans"):   # several TAPs, VLANs; route add without FIRMAE_NET
        net = [("192.168.0.1", "eth0", 2, None, "br0"), ("192.168.1.1", "eth1", None, None, "br1"),
               ("10.10.0.1", "eth3", 0, None, "br3")]
        return (1, net, [], "bridge", "mips", "el", "init=/firmadyne/preInit.sh", False)
    if layout == "no_network":
        return (1, [], [], "None", "mips", "el", INIT, False)
    raise KeyError(layout)


def free_port(exclude=()):
    for p in range(mn.HOSTFWD_PORT_MIN + (os.getpid() * 13) % 9000, mn.HOSTFWD_PORT_MAX):
        if p not in exclude and mn.hostPortIsFree("tcp", p) and mn.hostPortIsFree("udp", p):
            return p
    pytest.skip("no free port in the hostfwd range")


def run(world, variant):
    """Run the installed emulation in `variant`; everything observable, with
    the world's own paths and PIDs normalised."""
    extra = {"QEMU_LOG_ARGS": "1"}
    cwd = argv0 = None
    name = "run.sh"
    if variant in ("run_debug.sh", "run_analyze.sh", "run_boot.sh"):
        name = variant
    signalled = variant in ("sigterm", "ctrl-c", "bg_sigint")
    if not signalled:
        extra["QEMU_EXIT_AFTER"] = "0.3"
    background = variant.startswith("bg_")     # as firmae/check.py starts it
    if variant.startswith("fail_tunctl"):
        extra["FAIL_TUNCTL"] = variant.split(":")[1]
    if variant == "fail_mount":
        extra["FAIL_MOUNT"] = "1"
    if variant == "cwd_scratch":
        cwd = world.root / "scratch"
    if variant == "cwd_work":
        cwd = world.work
    if variant == "no_config":
        cwd = world.base / "a" / "b" / "c"
        cwd.mkdir(parents=True)
    p = world.start(name, cwd=cwd, argv0=argv0, background=background, **extra)
    if variant == "sigterm":
        world.wait_for("qemu start")
        p.send_signal(signal.SIGTERM)
    elif variant == "ctrl-c":                  # foreground (run_mode.sh "run"): the group gets SIGINT
        world.wait_for("qemu start")
        os.killpg(p.pid, signal.SIGINT)
    elif variant == "bg_sigint":
        # SIGINT was ignored on entry: it must change nothing (QEMU, a stub
        # here, ignores it too); then stop_qemu's SIGTERM ends the emulation
        world.wait_for("qemu start")
        os.killpg(p.pid, signal.SIGINT)
        time.sleep(1)
        assert p.poll() is None
        p.send_signal(signal.SIGTERM)
    out, _ = p.communicate(timeout=90)

    def norm(text):
        text = text.replace(str(world.root), "ROOT").replace(str(world.base), "BASE")
        text = text.replace("ppid=%d" % p.pid, "ppid=RUNSH")
        return re.sub(r"qemu start [0-9]+", "qemu start PID", text)
    isolation = world.work / "isolation"
    return {
        "rc": p.returncode,
        "output": norm(out),
        "calls": [norm(c) for c in world.calls(firewall=True)],
        "guest": world.guest_files(),
        "firewall": world.rules.read_text(),
        "isolation": isolation.read_text() if isolation.exists() else None,
        "sockets_dir": oct((world.work / "run").stat().st_mode & 0o777)
                       if (world.work / "run").exists() else None,
    }


SCENARIOS = [
    ("armel_dir868l", "run.sh"), ("armel_dir868l", "run_debug.sh"),
    ("armel_dir868l", "run_analyze.sh"), ("armel_dir868l", "run_boot.sh"),
    ("armel_dir868l", "sigterm"), ("armel_dir868l", "cwd_scratch"), ("armel_dir868l", "cwd_work"),
    ("armel_dir868l", "no_config"), ("armel_dir868l", "ctrl-c"),
    ("armel_dir868l", "bg_sigint"), ("armel_dir868l", "bg_qemu_exit"),
    ("dhcp", "bg_sigint"), ("dhcp", "bg_qemu_exit"),
    ("mipseb_wnap320", "run.sh"), ("mipseb_wnap320", "run_debug.sh"),
    ("mipseb_wnap320", "run_analyze.sh"), ("mipseb_wnap320", "run_boot.sh"),
    ("mipseb_wnap320", "fail_mount"), ("mipseb_wnap320", "fail_tunctl:1"),
    ("dhcp", "run.sh"), ("dhcp", "run_debug.sh"), ("dhcp", "sigterm"), ("dhcp", "port_taken"),
    ("dhcp", "fail_tunctl:tap1_1"),
    ("dhcp_arm", "run.sh"), ("dhcp_arm", "run_boot.sh"),
    ("tap_vlans_nonet", "run.sh"), ("tap_vlans_nonet", "fail_tunctl:tap1_1"),
    ("tap_vlans", "run.sh"), ("tap_vlans", "fail_tunctl:tap1_2"), ("tap_vlans", "sigterm"),
    ("no_network", "run.sh"),
]


@pytest.mark.parametrize("layout,variant", SCENARIOS,
                         ids=["%s-%s" % s for s in SCENARIOS])
def test_old_run_sh_and_new_emulate_sh_do_exactly_the_same(
        layout, variant, tmp_path, repo_root, iptables_stubs, read_fixture, firmae_env):
    firmae_env(net="false" if layout == "tap_vlans_nonet" else "true")
    held = None
    exclude = ()
    if variant == "port_taken":
        held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        taken = free_port()
        held.bind(("127.0.0.1", taken))
        held.listen(1)
        exclude = (taken,)
    try:
        first = taken if held else free_port()
        rest = [free_port(exclude=(first,) + exclude)]
        rest.append(free_port(exclude=(first, rest[0]) + exclude))
        hf = [("tcp", 80, rest[0]), ("tcp", 443, first), ("udp", 161, rest[1])]
        args = layout_args(layout, read_fixture, hf)

        old = World(tmp_path / "old", repo_root, iptables_stubs)
        old.install_legacy(LEGACY.qemuCmd(*args))
        new = World(tmp_path / "new", repo_root, iptables_stubs)
        new.install(mn.qemuCmd(*args))

        a = run(old, variant)
        b = run(new, variant)
    finally:
        if held:
            held.close()
    assert b == a
    # and the scenario really exercised what it is named after
    if variant == "no_config":
        assert a["rc"] == 1 and "Could not find 'firmae.config'" in a["output"]
        return
    if variant == "port_taken":
        assert a["rc"] == 1 and "(hostfwd) is in use" in a["output"]
    elif variant.startswith("fail_") :
        assert a["rc"] != 0 and not any(c.startswith("qemu start") for c in a["calls"])
    elif variant in ("sigterm", "bg_sigint"):
        assert a["rc"] == 143 and "qemu got TERM" in a["calls"]
    elif variant == "ctrl-c":
        assert a["rc"] == 130 and "qemu got TERM" in a["calls"]
    else:
        assert a["rc"] == 0, a["output"]
        assert "qemu exit" in a["calls"]
        assert any(c.endswith("ppid=RUNSH") for c in a["calls"])     # exec kept the PID
    assert a["output"].rstrip().endswith("Done!")


def test_scenarios_cover_both_network_modes_and_every_run_mode():
    layouts = {l for (l, _) in SCENARIOS}
    variants = {v for (_, v) in SCENARIOS}
    assert {"armel_dir868l", "mipseb_wnap320", "dhcp"} <= layouts
    assert {"run.sh", "run_debug.sh", "run_analyze.sh", "run_boot.sh", "sigterm"} <= variants
