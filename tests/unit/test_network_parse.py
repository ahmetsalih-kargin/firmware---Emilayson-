"""Characterization tests for the log parsers and network inference in
scripts/makeNetwork.py.

These tests lock in what the code does TODAY (2026-11-04, master 653565b),
including behaviour that is known to be wrong. Tests that document a bug say
so in their docstring and in REFACTORING_PLAN.md; when a later phase fixes
the bug, the test is updated in the same commit.
"""

import pytest

from scripts import makeNetwork as mn

pytestmark = pytest.mark.characterization


def line(msg, ts="1.000000"):
    """One kernel log line in the format the FirmAE kernel prints."""
    return "[%12s] firmadyne: %s" % (ts, msg)


def log(*msgs):
    return ("\n".join(line(m) for m in msgs) + "\n").encode()


# --------------------------------------------------------------------------
# Real serial logs captured in Phase 0 (see tests/fixtures/README.md)
# --------------------------------------------------------------------------

REAL = {
    "armel_dir868l": dict(
        end="el",
        ifaces=[("br0", "192.168.0.1"), ("br1", "192.168.7.1"), ("eth0", "10.0.2.15")],
        netlist=[("192.168.0.1", "eth0", 1, None, "br0")],
        filtered=[("192.168.0.1", "eth0", 1, None, "br0")],
        network_type="normal",
    ),
    "mipseb_wnap320": dict(
        end="eb",
        ifaces=[("brtrunk", "192.168.0.100")],
        netlist=[("192.168.0.100", "eth0", None, None, "brtrunk")],
        filtered=[("192.168.0.100", "eth0", None, None, "brtrunk")],
        network_type="normal",
    ),
}


@pytest.mark.parametrize("name", sorted(REAL))
def test_real_log_interfaces(name, read_fixture, firmae_env):
    exp = REAL[name]
    data = read_fixture("serial/serial_%s.log" % name)
    ifaces = mn.findNonLoInterfaces(data, exp["end"])
    assert ifaces == exp["ifaces"]
    netlist = mn.getNetworkList(data, ifaces, mn.findMacChanges(data, exp["end"]))
    assert netlist == exp["netlist"]
    assert mn.checkNetwork(netlist) == (exp["filtered"], exp["network_type"])


@pytest.mark.parametrize("name", sorted(REAL))
def test_real_log_ports_are_never_found(name, read_fixture):
    """KNOWN BUG: the FirmAE 4.1 kernels log `inet_bind[...]: proto:SOCK_X, port:N`,
    but findPorts() only matches the older `ip:port: 0x<ip>:<port>` format.
    Both real firmware images bind many ports (80, 443, 22, 161, ...) yet the
    result is empty, so DHCP-mode hostfwd falls back to the hard-coded 80/443."""
    data = read_fixture("serial/serial_%s.log" % name)
    assert b"inet_bind" in data
    assert mn.findPorts(data, REAL[name]["end"]) == []


# --------------------------------------------------------------------------
# Individual parsers
# --------------------------------------------------------------------------

def test_strip_timestamps_removes_prefix():
    assert mn.stripTimestamps(log("abc", "def")) == [b"abc", b"def", b""]


def test_find_ports_legacy_format_and_dedup_by_port():
    data = log(
        "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:80",
        "inet_bind[PID: 1 (httpd)]: proto:SOCK_DGRAM, ip:port: 0x0100a8c0:80",
        "inet_bind[PID: 2 (snmpd)]: proto:SOCK_DGRAM, ip:port: 0x00000000:161",
    )
    # de-duplicated by port number only; the first protocol seen wins
    assert mn.findPorts(data, "el") == [("tcp", "192.168.0.1", 80), ("udp", "0.0.0.0", 161)]


@pytest.mark.parametrize("end,hexaddr", [("el", "0x0100a8c0"), ("eb", "0xc0a80001")])
def test_non_lo_interfaces_endianness_and_filtering(end, hexaddr):
    lo = "0x0100007f" if end == "el" else "0x7f000001"
    data = log(
        "__inet_insert_ifa[PID: 1 (ip)]: device:lo ifa:%s" % lo,
        "__inet_insert_ifa[PID: 1 (ip)]: device:eth1 ifa:0x00000000",
        "__inet_insert_ifa[PID: 1 (ip)]: device:br0 ifa:%s" % hexaddr,
    )
    assert mn.findNonLoInterfaces(data, end) == [("br0", "192.168.0.1")]


def test_mac_changes_big_endian():
    data = log("ioctl_SIOCSIFHWADDR[PID: 1 (ifconfig)]: dev:eth0 mac:0x0011 0x22334455")
    assert mn.findMacChanges(data, "eb") == [("eth0", "00:11:22:33:44:55")]


def test_ifaces_for_bridge_excludes_bridge_itself():
    data = log(
        "br_add_if[PID: 1 (brctl)]: br:br0 dev:eth0",
        "br_add_if[PID: 1 (brctl)]: br:br0 dev:br0",
        "br_dev_ioctl[PID: 1 (brctl)]: br:br0 dev:eth1",
        "br_add_if[PID: 1 (brctl)]: br:br1 dev:eth2",
    )
    assert mn.findIfacesForBridge(data, "br0") == ["eth0", "eth1"]


def test_vlan_info_for_dev():
    data = log(
        "register_vlan_dev[PID: 1 (vconfig)]: dev:eth0.1 vlan_id:1",
        "register_vlan_dev[PID: 1 (vconfig)]: dev:eth0.2 vlan_id:2",
    )
    assert mn.findVlanInfoForDev(data, "eth0.2") == [2]
    assert mn.findVlanInfoForDev(data, "eth9") == []


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

@pytest.mark.parametrize("dev,no", [("eth0", 0), ("eth3", 3), ("br0", 0), ("eth0.1", 0), ("lo", -1)])
def test_iface_no(dev, no):
    assert mn.ifaceNo(dev) == no


@pytest.mark.parametrize("ip,dhcp", [("10.0.2.15", True), ("20.45.150.190", True),
                                     ("192.168.0.1", False)])
def test_is_dhcp_ip(ip, dhcp):
    assert mn.isDhcpIp(ip) is dhcp


@pytest.mark.parametrize("guest,host", [("192.168.0.1", "192.168.0.2"),
                                        ("192.168.0.0", "192.168.0.1"),
                                        ("192.168.0.100", "192.168.0.99")])
def test_convert_to_host_ip(guest, host):
    assert mn.convertToHostIp(guest) == host


@pytest.mark.parametrize("value,expected", [("armel", ("arm", "el")), ("mipseb", ("mips", "eb")),
                                            ("mipsel", ("mips", "el")), ("x86", (None, None))])
def test_arch_end(value, expected):
    assert mn.archEnd(value) == expected


# --------------------------------------------------------------------------
# checkNetwork(): one test per branch
# --------------------------------------------------------------------------

N = lambda ip, dev, vlan=None, br="br0": (ip, dev, vlan, None, br)


@pytest.mark.parametrize("netlist,expected,ntype", [
    # router: bridge + eth present -> eth (DHCP side) dropped
    ([N("192.168.1.1", "br0"), N("10.0.2.15", "eth0", br="br1")],
     [N("192.168.1.1", "eth0")], "bridge"),
    # linksys: same dev, DHCP 10.0.2.x address dropped
    ([N("192.168.1.252", "eth0"), N("10.0.2.15", "eth0")],
     [N("192.168.1.252", "eth0")], "normal"),
    # vlan ethernet preferred
    ([N("192.168.0.1", "eth0", vlan=1), N("192.168.0.1", "eth1")],
     [N("192.168.0.1", "eth0", vlan=1)], "normal"),
    # plain ethernet
    ([N("192.168.0.1", "eth0")], [N("192.168.0.1", "eth0")], "normal"),
    # ethernet with invalid IP -> forced 192.168.0.1, "reload"
    ([N("10.0.0.0", "eth0")], [N("192.168.0.1", "eth0")], "reload"),
    # bridge only -> bridge mapped onto eth0..eth3
    ([N("192.168.0.1", "br0"), N("192.168.1.1", "br1", br="br1")],
     [N("192.168.0.1", "eth0"), N("192.168.1.1", "eth1", br="br1")], "bridge"),
    # bridge only with invalid IP
    ([N("10.0.0.0", "br0")], [N("192.168.0.1", "eth0")], "bridgereload"),
    # nothing found -> default network
    ([], [N("192.168.0.1", "eth0")], "default"),
])
def test_check_network_branches(netlist, expected, ntype, firmae_env):
    assert mn.checkNetwork(netlist) == (expected, ntype)


def test_check_network_without_firmae_net_is_passthrough(firmae_env):
    firmae_env(net="false")
    netlist = [N("10.0.2.15", "eth0"), N("192.168.0.1", "br0")]
    assert mn.checkNetwork(netlist) == (netlist, "None")


def test_get_network_list_without_firmae_net_prunes_duplicate_ips(firmae_env):
    firmae_env(net="false")
    data = log("br_add_if[PID: 1 (brctl)]: br:br0 dev:eth0",
               "br_add_if[PID: 1 (brctl)]: br:br0 dev:eth1")
    netlist = mn.getNetworkList(data, [("br0", "192.168.0.1")], [])
    assert netlist == [("192.168.0.1", "eth0", None, None, "br0")]
