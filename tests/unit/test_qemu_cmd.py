"""Characterization tests for the emulation generator in scripts/makeNetwork.py.

The two end-to-end tests feed a real serial log through the parsers and
qemuCmd() and compare the resulting scratch/<IID>/emulation.conf byte-for-byte
with the golden files. Until Phase 4.4 qemuCmd() returned a generated run.sh;
those Phase 0 goldens (run_sh_*.expected) stay as the reference of
tests/unit/test_emulate_equivalence.py, which runs the old script and the new
wrapper + scripts/emulate.sh side by side. Here, the QEMU network arguments
emulate.sh builds from the new data are also checked against the network
arguments of the Phase 0 run.sh.
"""

import re

import pytest

from scripts import makeNetwork as mn

pytestmark = pytest.mark.characterization

INIT = "rdinit=/firmadyne/preInit.sh"


def fixture_emulation(read_fixture, name, arch, end):
    data = read_fixture("serial/serial_%s.log" % name)
    ports = mn.findPorts(data, end)
    ifaces = mn.findNonLoInterfaces(data, end)
    netlist = mn.getNetworkList(data, ifaces, mn.findMacChanges(data, end))
    filtered, network_type = mn.checkNetwork(netlist)
    # process(): no unusable or host-colliding guest address (audit B1); the
    # two real fixtures have none, so the goldens are unchanged
    usable = mn.usableNetworkList(filtered)
    assert usable == filtered
    is_user = any(mn.isDhcpIp(ip) for (ip, _, _, _, _) in usable)
    return mn.qemuCmd(1, usable, ports, network_type, arch, end, INIT, is_user)


@pytest.mark.parametrize("name,arch,end", [
    ("armel_dir868l", "arm", "el"),
    ("mipseb_wnap320", "mips", "eb"),
])
def test_generated_emulation_data_matches_the_golden(name, arch, end, read_fixture, firmae_env):
    out = fixture_emulation(read_fixture, name, arch, end)
    assert out == read_fixture("generated/emulation_%s.expected" % name).decode()


@pytest.mark.parametrize("name,arch,end", [
    ("armel_dir868l", "arm", "el"),
    ("mipseb_wnap320", "mips", "eb"),
])
def test_the_data_gives_the_phase0_values(name, arch, end, read_fixture, firmae_env):
    """Every per-image value of the Phase 0 run.sh is in the data, unchanged."""
    old = read_fixture("generated/run_sh_%s.expected" % name).decode()
    spec = mn.parseEmulation(fixture_emulation(read_fixture, name, arch, end))
    assert "ARCHEND=%s%s\n" % (spec["arch"], spec["endian"]) in old
    for key, path in (("network_type", "network_type"), ("net_bridge", "net_bridge"),
                      ("net_interface", "net_interface")):
        assert 'echo "%s" > ${WORK_DIR}/image/firmadyne/%s\n' % (spec[key], path) in old
    assert " %s rw debug " % spec["qemu_init"] in old
    # the NIC arguments: those of the old QEMU line, without the trailing " &"
    old_net = [l for l in old.splitlines() if "-netdev" in l][-1].strip()[:-2]
    assert mn.renderNics(spec["arch"], spec["nics"], spec["hostfwd"]) == old_net
    for (host_ip, guest_ip, vlan) in spec["nets"]:
        assert "sudo ip addr add %s/24 dev ${HOSTNETDEV_0}" % host_ip in old
        if vlan is None:
            assert "type vlan id" not in old
        else:
            assert "type vlan id %d\n" % vlan in old


def test_run_sh_is_the_fixed_wrapper(read_fixture):
    assert mn.runShWrapper(1) == read_fixture("generated/run_sh_wrapper.expected").decode()
    assert mn.runShWrapper(42) == mn.runShWrapper(1).replace(" 1 ", " 42 ").replace(
        "for image 1.", "for image 42.")
    for bad in ("1", 1.0, True, -1, 2**31, "1; id"):
        with pytest.raises(mn.UnsafeValue):
            mn.runShWrapper(bad)


def test_the_wrapper_has_no_logic_of_its_own():
    """run.sh only finds firmae.config like the old script did (., .., ../..)
    and execs emulate.sh with its own name, unresolved."""
    text = mn.runShWrapper(7)
    code = [l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert code == [
        "for FIRMAE_ROOT in . .. ../..; do",
        'if [ -e "${FIRMAE_ROOT}/firmae.config" ]; then',
        'exec /bin/bash "${FIRMAE_ROOT}/scripts/emulate.sh" "${0}" 7 "${FIRMAE_ROOT}"',
        "fi",
        "done",
        "echo \"Error: Could not find 'firmae.config'!\"",
        "exit 1",
    ]


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
    nics, _ = mn.nicLayout("mips", net, False, [], iid=7)
    assert nics == [("tap", 0), ("socket", 20029), ("socket", 20030), ("socket", 20031)]


def test_placeholder_port_ranges_of_different_images_do_not_overlap():
    ranges = [set(mn.placeholderPort(iid, i) for i in range(4)) for iid in range(0, 200)]
    assert all(not (a & b) for n, a in enumerate(ranges) for b in ranges[n + 1:])
    assert all(1024 < min(r) and max(r) < 65536 for r in ranges + [set(mn.placeholderPort(9999, i) for i in range(4))])
    assert mn.placeholderPort(987654, 3) == mn.placeholderPort(7654, 3) <= 65535
    # the range emulate.sh accepts for NIC=socket
    assert mn.placeholderPort(0, 0) == mn.PLACEHOLDER_PORT_MIN
    assert mn.placeholderPort(9999, 3) == mn.PLACEHOLDER_PORT_MAX


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


def test_vlan_and_host_address_are_recorded_per_network(firmae_env):
    """Was: startNetwork()/stopNetwork() snippets; the commands are now in
    emulate.sh (start_net/stop_net), the data says what they act on."""
    net = [("192.168.0.1", "eth0", 2, None, "br0"), ("10.0.0.255", "eth1", None, None, "br1")]
    spec = mn.parseEmulation(mn.qemuCmd(1, net, [], "normal", "mips", "el", INIT, False))
    assert spec["nets"] == [("192.168.0.2", "192.168.0.1", 2), ("10.0.0.254", "10.0.0.255", None)]
    assert spec["firmae_net"] is True


def test_firmae_net_is_recorded_as_it_was_at_generation_time(firmae_env):
    net = [("192.168.0.1", "eth0", 2, None, "br0")]
    firmae_env(net="false")
    assert "\nGEN_FIRMAE_NET=false\n" in mn.qemuCmd(1, net, [], "normal", "mips", "el", INIT, False)
    firmae_env(net="true")
    assert "\nGEN_FIRMAE_NET=true\n" in mn.qemuCmd(1, net, [], "normal", "mips", "el", INIT, False)


def test_emulate_sh_keeps_the_sockets_in_a_private_directory(repo_root):
    """Phase 5 (SECURITY.md S12): the QEMU monitor (code execution with QEMU's
    privileges) was a predictable /tmp/qemu.<IID> socket."""
    out = (repo_root / "scripts" / "emulate.sh").read_text()
    assert '-monitor "unix:${WORK_DIR}/run/monitor.sock,server,nowait"' in out
    assert '-serial "unix:${WORK_DIR}/run/serial1.sock,server,nowait"' in out
    assert "/tmp/qemu" not in out
    assert out.index('mkdir -p "${WORK_DIR}/run"\nchmod 0700 "${WORK_DIR}/run"') < out.index("-monitor ")


def test_emulate_sh_cleans_up_on_every_exit_path(repo_root):
    """Phase 3: QEMU runs in the background under a cleanup trap (was a
    foreground `qemu ... | true` with STOP_NET reached only on a normal end).
    The runtime behaviour is tested in test_generated_run_sh.py and
    test_emulate_equivalence.py; this pins the structure."""
    out = (repo_root / "scripts" / "emulate.sh").read_text()
    code = [l for l in out.splitlines() if not l.lstrip().startswith("#")]
    assert '    "${QEMU}" "${QEMU_ARGS[@]}" &' in code
    assert '    QEMU_AUDIO_DRV=none "${QEMU}" "${QEMU_ARGS[@]}" &' in code
    assert not any(" | true" in l and " || true" not in l for l in code)
    assert "trap cleanup EXIT" in out
    for sig, rc in (("INT", 130), ("TERM", 143), ("HUP", 129)):
        assert "trap 'exit %d' %s" % (rc, sig) in out
    # stop_net is defined once and called only by cleanup()
    assert [l.strip() for l in code].count("stop_net") == 1
    assert out.index("stop_net () {") < out.index("cleanup () {") < out.index("trap cleanup EXIT")
    assert out.index("NET_STARTED=true\nstart_net\n") > out.index("trap cleanup EXIT")
    for word in ("eval", "source \"${EMU_FILE}\"", ". \"${EMU_FILE}\""):
        assert word not in "\n".join(code)


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
