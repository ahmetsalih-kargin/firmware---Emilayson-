"""Characterization tests for the run.sh generator in scripts/makeNetwork.py.

The two end-to-end tests feed a real serial log through the parsers and
qemuCmd() and compare the result byte-for-byte with the run.sh that FirmAE
generated for the same firmware in Phase 0. Any refactoring of the QEMU or
network code must keep these passing (or change them deliberately).
"""

import re

import pytest

from scripts import makeNetwork as mn

pytestmark = pytest.mark.characterization


@pytest.mark.parametrize("name,arch,end", [
    ("armel_dir868l", "arm", "el"),
    ("mipseb_wnap320", "mips", "eb"),
])
def test_generated_run_sh_matches_phase0_output(name, arch, end, read_fixture, firmae_env):
    data = read_fixture("serial/serial_%s.log" % name)
    ports = mn.findPorts(data, end)
    ifaces = mn.findNonLoInterfaces(data, end)
    netlist = mn.getNetworkList(data, ifaces, mn.findMacChanges(data, end))
    filtered, network_type = mn.checkNetwork(netlist)
    is_user = any(mn.isDhcpIp(ip) for (ip, _, _, _, _) in filtered)

    out = mn.qemuCmd(1, filtered, ports, network_type, arch, end,
                     "rdinit=/firmadyne/preInit.sh", is_user)

    assert out == read_fixture("generated/run_sh_%s.expected" % name).decode()


def test_arm_with_firmae_net_uses_single_nic(firmae_env):
    out = mn.qemuNetworkConfig("arm", [], False, [])
    assert out == "-device virtio-net-device,netdev=net0 -netdev socket,id=net0,listen=127.0.0.1:20000"


def test_placeholder_nics_listen_on_loopback_in_a_per_image_port_range(firmae_env):
    """Phase 5 (SECURITY.md S8): placeholder NICs used the fixed ports 2000-2003 on
    ALL interfaces, so two emulations collided and the sockets were reachable
    from the LAN. Now: 127.0.0.1, ports 20000 + 4*(IID % 10000) + n."""
    net = [("192.168.0.1", "eth0", None, None, "br0")]
    out = mn.qemuNetworkConfig("mips", net, False, [], iid=7)
    assert out == (
        "-device e1000,netdev=net0 -netdev tap,id=net0,ifname=${TAPDEV_0},script=no "
        "-device e1000,netdev=net1 -netdev socket,id=net1,listen=127.0.0.1:20029 "
        "-device e1000,netdev=net2 -netdev socket,id=net2,listen=127.0.0.1:20030 "
        "-device e1000,netdev=net3 -netdev socket,id=net3,listen=127.0.0.1:20031")


def test_placeholder_port_ranges_of_different_images_do_not_overlap():
    ranges = [set(mn.placeholderPort(iid, i) for i in range(4)) for iid in range(0, 200)]
    assert all(not (a & b) for n, a in enumerate(ranges) for b in ranges[n + 1:])
    assert all(1024 < min(r) and max(r) < 65536 for r in ranges + [set(mn.placeholderPort(9999, i) for i in range(4))])
    assert mn.placeholderPort(987654, 3) == mn.placeholderPort(7654, 3) <= 65535


def test_user_network_is_isolated_and_forwards_on_loopback_only(firmae_env):
    """Phase 5 (SECURITY.md S8): DHCP-mode firmware used to get hostfwd on ports
    80/443 of ALL interfaces and unrestricted access to the host's network."""
    net = [("10.0.2.15", "eth0", None, None, "br0")]
    out = mn.qemuArchNetworkConfig(0, 0, "mips", net[0], True,
                                   [("tcp", "0.0.0.0", 8080), ("udp", "0.0.0.0", 80)],
                                   hostfwd=[("tcp", 80, 10000), ("tcp", 443, 10001),
                                            ("tcp", 8080, 10002)])
    assert out == ("-device e1000,netdev=net0 -netdev user,id=net0,restrict=on,"
                   "hostfwd=tcp:127.0.0.1:10000-:80,hostfwd=tcp:127.0.0.1:10001-:443,"
                   "hostfwd=tcp:127.0.0.1:10002-:8080")
    assert "restrict=on" in out
    rules = re.findall(r"hostfwd=[^, ]+", out)
    assert len(rules) == 3
    assert all(r.startswith("hostfwd=tcp:127.0.0.1:") for r in rules)
    assert "hostfwd=tcp::" not in out and "hostfwd=udp::" not in out
    assert "0.0.0.0" not in out and "hostfwd=tcp:-" not in out


def test_user_network_without_hostfwd_chooses_loopback_ports(firmae_env):
    """hostfwd=None: the ports come from chooseHostPorts() -- guest 80, 443 and
    the extra guest ports (80 is never repeated), on free host ports in
    HOSTFWD_PORT_MIN..MAX, loopback only. hostfwd=[]: restrict=on and no rule
    (another NIC carries the forwards)."""
    net = [("10.0.2.15", "eth0", None, None, "br0")]
    out = mn.qemuArchNetworkConfig(0, 0, "mips", net[0], True,
                                   [("tcp", "0.0.0.0", 8080), ("udp", "0.0.0.0", 80)], iid=7)
    assert "restrict=on" in out
    rules = re.findall(r"hostfwd=(\w+):127\.0\.0\.1:(\d+)-:(\d+)", out)
    assert [(p, int(g)) for (p, _h, g) in rules] == [("tcp", 80), ("tcp", 443), ("tcp", 8080)]
    hosts = [int(h) for (_p, h, _g) in rules]
    assert len(set(hosts)) == 3
    assert all(mn.HOSTFWD_PORT_MIN <= h <= mn.HOSTFWD_PORT_MAX for h in hosts)
    assert out.count("hostfwd=") == 3 and "hostfwd=tcp::" not in out

    none = mn.qemuArchNetworkConfig(0, 0, "mips", net[0], True, [("tcp", "0.0.0.0", 8080)],
                                    hostfwd=[])
    assert none == "-device e1000,netdev=net0 -netdev user,id=net0,restrict=on"


def test_unmatched_interface_is_guessed_by_position(firmae_env, capsys):
    net = [("192.168.0.1", "br0", None, None, "br0")]   # ifaceNo("br0") == 0 -> matched
    assert "ifname=${TAPDEV_0}" in mn.qemuNetworkConfig("mips", net, False, [])
    net = [("192.168.0.1", "lan", None, None, "lan")]   # ifaceNo("lan") == -1 -> guessed
    out = mn.qemuNetworkConfig("mips", net, False, [])
    assert "Warning: Unmatched interface" in capsys.readouterr().out
    assert out.startswith("-device e1000,netdev=net0 -netdev tap,id=net0,ifname=${TAPDEV_0}")


def test_vlan_start_and_stop_network_snippets(firmae_env):
    net = [("192.168.0.1", "eth0", 2, None, "br0")]
    start = mn.startNetwork(net)
    stop = mn.stopNetwork(net)
    assert "sudo tunctl -t ${TAPDEV_0} -u ${USER}" in start
    assert "HOSTNETDEV_0=${TAPDEV_0}.2" in start
    assert "sudo ip addr add 192.168.0.2/24 dev ${HOSTNETDEV_0}" in start
    assert "sudo ip link delete ${HOSTNETDEV_0}" in stop
    assert "sudo tunctl -d ${TAPDEV_0}" in stop


def test_template_sockets_are_in_a_private_directory(firmae_env):
    """Phase 5 (SECURITY.md S12): the QEMU monitor (code execution with QEMU's
    privileges) was a predictable /tmp/qemu.<IID> socket."""
    out = mn.qemuCmd(1, [("192.168.0.1", "eth0", None, None, "br0")], [], "normal",
                     "mips", "el", "rdinit=/firmadyne/preInit.sh", False)
    assert "-monitor unix:${WORK_DIR}/run/monitor.sock,server,nowait" in out
    assert "-serial unix:${WORK_DIR}/run/serial1.sock,server,nowait" in out
    assert "/tmp/qemu" not in out
    assert out.index("mkdir -p ${WORK_DIR}/run\nchmod 0700 ${WORK_DIR}/run") < out.index("-monitor unix:")


def test_template_cleans_up_on_every_exit_path(firmae_env):
    """Phase 3: QEMU runs in the background under a cleanup trap (was a
    foreground `qemu ... | true` with STOP_NET reached only on a normal end)."""
    out = mn.qemuCmd(1, [("192.168.0.1", "eth0", None, None, "br0")], [], "normal",
                     "mips", "el", "rdinit=/firmadyne/preInit.sh", False)
    qemu_last_line = [l for l in out.splitlines() if "-netdev" in l][-1]
    assert qemu_last_line.endswith(" &")
    code = [l for l in out.splitlines() if not l.lstrip().startswith("#")]
    # no pipeline into `true` any more (`wait ... || true` is fine)
    assert not any(" | true" in l and " || true" not in l for l in code)
    assert "trap cleanup EXIT" in out
    for sig, code in (("INT", 130), ("TERM", 143), ("HUP", 129)):
        assert "trap 'exit %d' %s" % (code, sig) in out
    # STOP_NET lives in stop_net(), which only cleanup() calls -- exactly once
    assert out.count("sudo tunctl -d ${TAPDEV_0}") == 1
    assert out.index("stop_net () {") < out.index("sudo tunctl -d ${TAPDEV_0}") < out.index("cleanup () {")
    assert out.index("NET_STARTED=true") < out.index("sudo tunctl -t ${TAPDEV_0}")


def test_unsupported_architectures_raise(firmae_env):
    with pytest.raises(Exception, match="armeb currently not supported"):
        mn.qemuCmd(1, [], [], "None", "arm", "eb", "", False)
    with pytest.raises(Exception, match="valid endianness"):
        mn.qemuCmd(1, [], [], "None", "mips", "xx", "", False)
    with pytest.raises(Exception, match="Unsupported architecture"):
        mn.qemuCmd(1, [], [], "None", "ppc", "eb", "", False)


def test_debug_py_and_cleanup_use_the_private_socket_directory(repo_root):
    """The serial socket debug.py connects to moved with the QEMU command line."""
    assert "scratch/%d/run/serial1.sock" in (repo_root / "debug.py").read_text()
    assert "/tmp/qemu" not in (repo_root / "debug.py").read_text()
    assert '"${SCRATCH_DIR}/${1}"/run/*.sock' in (repo_root / "firmae.config").read_text()
