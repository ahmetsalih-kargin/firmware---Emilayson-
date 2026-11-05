"""Characterization tests for the run.sh generator in scripts/makeNetwork.py.

The two end-to-end tests feed a real serial log through the parsers and
qemuCmd() and compare the result byte-for-byte with the run.sh that FirmAE
generated for the same firmware in Phase 0. Any refactoring of the QEMU or
network code must keep these passing (or change them deliberately).
"""

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
    assert out == "-device virtio-net-device,netdev=net0 -netdev socket,id=net0,listen=:2000"


def test_mips_placeholder_nics_listen_on_all_interfaces(firmae_env):
    """KNOWN ISSUE (SECURITY.md S8): placeholder NICs bind fixed ports 2000-2003
    on all host interfaces; two emulations on one host collide."""
    net = [("192.168.0.1", "eth0", None, None, "br0")]
    out = mn.qemuNetworkConfig("mips", net, False, [])
    assert out == (
        "-device e1000,netdev=net0 -netdev tap,id=net0,ifname=${TAPDEV_0},script=no "
        "-device e1000,netdev=net1 -netdev socket,id=net1,listen=:2001 "
        "-device e1000,netdev=net2 -netdev socket,id=net2,listen=:2002 "
        "-device e1000,netdev=net3 -netdev socket,id=net3,listen=:2003")


def test_user_network_hostfwd_binds_all_interfaces(firmae_env):
    """KNOWN ISSUE (SECURITY.md S8): DHCP-mode firmware gets hostfwd on host
    ports 80/443 of ALL interfaces, without restrict=on."""
    net = [("10.0.2.15", "eth0", None, None, "br0")]
    out = mn.qemuArchNetworkConfig(0, 0, "mips", net[0], True,
                                   [("tcp", "0.0.0.0", 8080), ("udp", "0.0.0.0", 80)])
    assert out == ("-device e1000,netdev=net0 -netdev user,id=net0,"
                   "hostfwd=tcp::80-:80,hostfwd=tcp::443-:443,hostfwd=tcp::8080-:8080")
    assert "restrict=on" not in out


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


def test_template_known_issues(firmae_env):
    """KNOWN ISSUE locked in until Phase 5: predictable /tmp sockets (S12)."""
    out = mn.qemuCmd(1, [("192.168.0.1", "eth0", None, None, "br0")], [], "normal",
                     "mips", "el", "rdinit=/firmadyne/preInit.sh", False)
    assert "-monitor unix:/tmp/qemu.${IID},server,nowait" in out
    assert "-serial unix:/tmp/qemu.${IID}.S1,server,nowait" in out


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
