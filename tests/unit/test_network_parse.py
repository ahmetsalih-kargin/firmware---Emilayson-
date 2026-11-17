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


A = "0.0.0.0"      # the 4.1 format logs no address
REAL_PORTS = {
    # 40 inet_bind lines: port 0 (mDNSResponder, arpmonitor, ntpclient) and the
    # ephemeral fakedns:63481 and httpd:49152 are dropped, repeats collapse
    "armel_dir868l": [
        ("udp", A, 19541), ("udp", A, 5353), ("tcp", A, 4433), ("tcp", A, 443),
        ("udp", A, 67), ("udp", A, 5355), ("udp", A, 137), ("tcp", A, 53),
        ("udp", A, 53), ("tcp", A, 8181), ("tcp", A, 80), ("udp", A, 1900),
        ("tcp", A, 8182)],
    # 20 lines, 11 of them ntpclient port 0
    "mipseb_wnap320": [
        ("tcp", A, 80), ("tcp", A, 443), ("tcp", A, 22), ("udp", A, 161),
        ("udp", A, 137), ("udp", A, 138)],
}


@pytest.mark.parametrize("name", sorted(REAL))
def test_real_log_ports(name, read_fixture):
    """REFACTORING_PLAN 2.10: the FirmAE 4.1 kernels log
    `inet_bind[...]: proto:SOCK_X, port:N`; findPorts() only knew the older
    `ip:port: 0x<ip>:<port>` format and always returned []."""
    data = read_fixture("serial/serial_%s.log" % name)
    assert mn.findPorts(data, REAL[name]["end"]) == REAL_PORTS[name]


# --------------------------------------------------------------------------
# Individual parsers
# --------------------------------------------------------------------------

def test_strip_timestamps_removes_prefix():
    assert mn.stripTimestamps(log("abc", "def")) == [b"abc", b"def", b""]


def test_find_ports_legacy_format_and_dedup_by_proto_and_port():
    data = log(
        "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:80",
        "inet_bind[PID: 1 (httpd)]: proto:SOCK_DGRAM, ip:port: 0x0100a8c0:80",
        "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x0200a8c0:80",
        "inet_bind[PID: 2 (snmpd)]: proto:SOCK_DGRAM, ip:port: 0x00000000:161",
    )
    # one entry per (proto, port) -- was per port only, so udp/80 vanished
    # behind tcp/80; the first address seen wins
    assert mn.findPorts(data, "el") == [("tcp", "192.168.0.1", 80), ("udp", "192.168.0.1", 80),
                                        ("udp", "0.0.0.0", 161)]
    assert mn.findPorts(data, "eb")[0] == ("tcp", "1.0.168.192", 80)


def test_find_ports_both_formats_in_one_log():
    data = log(
        "inet_bind[PID: 644 (fakedns)]: proto:SOCK_STREAM, port:8080",
        "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:8080",   # repeat
        "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:81",
        "inet_bind[PID: 2 (dnsmasq)]: proto:SOCK_DGRAM, port:53",
    )
    assert mn.findPorts(data, "el") == [("tcp", "0.0.0.0", 8080), ("tcp", "192.168.0.1", 81),
                                        ("udp", "0.0.0.0", 53)]


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


# --------------------------------------------------------------------------
# Acceptable guest addresses (audit B1): the guest reports its addresses in
# the serial log; the host probes them as root and routes them to a TAP
# device. One definition at three layers: makeNetwork.isGuestIpv4,
# firmae.check.usable_guest_ip, emu_guest_ipv4 in scripts/emulate.sh.
# --------------------------------------------------------------------------

def el(ip):
    """__inet_insert_ifa hex of `ip` as a little-endian guest logs it"""
    import socket
    import struct
    return "0x%08x" % struct.unpack("<I", socket.inet_aton(ip))[0]


UNUSABLE = [
    ("127.0.0.2", "loopback"), ("127.255.255.254", "loopback"),
    ("0.1.2.3", "0.0.0.0/8"), ("0.255.255.255", "0.0.0.0/8"),
    ("224.0.0.1", "multicast"), ("239.255.255.250", "multicast"),
    ("169.254.0.1", "link-local"), ("169.254.255.254", "link-local"),
    ("240.0.0.1", "reserved"), ("255.255.255.254", "reserved"),
    ("255.255.255.255", "limited broadcast"),
]
USABLE = ["192.168.0.1", "10.0.2.15", "172.16.0.1", "8.8.8.8", "1.0.0.0", "126.255.255.255",
          "128.0.0.0", "169.253.255.255", "169.255.0.1", "223.255.255.255", "100.64.0.1",
          "192.0.2.1", "10.0.0.255"]


@pytest.mark.parametrize("ip,reason", UNUSABLE)
def test_unusable_guest_addresses_are_dropped_by_the_parser(ip, reason, capsys):
    """Was: only 127.0.0.1 and 0.0.0.0 were dropped; ifa:0x0200007f (127.0.0.2)
    became ip.0 and was curled / pinged on the host."""
    data = log("__inet_insert_ifa[PID: 1 (ip)]: device:lo ifa:0x0100007f",
               "__inet_insert_ifa[PID: 1 (ip)]: device:eth1 ifa:%s" % el(ip),
               "__inet_insert_ifa[PID: 1 (ip)]: device:br0 ifa:0x0100a8c0")
    capsys.readouterr()
    assert mn.findNonLoInterfaces(data, "el") == [("br0", "192.168.0.1")]
    out = capsys.readouterr().out
    assert "skipped interface address %s of eth1" % ip in out and reason in out
    assert "127.0.0.1" not in out              # lo: dropped silently, as before
    assert not mn.isGuestIpv4(ip) and reason in mn.unusableGuestIpReason(ip)


def test_usable_guest_addresses_are_kept_by_the_parser(capsys):
    data = log(*["__inet_insert_ifa[PID: 1 (ip)]: device:eth%d ifa:%s" % (i % 10, el(ip))
                 for i, ip in enumerate(USABLE)])
    assert mn.findNonLoInterfaces(data, "el") == [("eth%d" % (i % 10), ip) for i, ip in enumerate(USABLE)]
    assert "Warning" not in capsys.readouterr().out


def test_unusable_address_warnings_are_bounded(capsys):
    data = log(*["__inet_insert_ifa[PID: 1 (ip)]: device:eth0 ifa:0x%02x00007f" % (i + 2) for i in range(50)])
    assert mn.findNonLoInterfaces(data, "el") == []
    out = capsys.readouterr().out
    assert out.count("skipped interface address") == mn.MAX_WARNINGS
    assert "skipped %d more unusable interface addresses" % (50 - mn.MAX_WARNINGS) in out


@pytest.mark.parametrize("layout,kept", [
    # guest .1 -> host .2 and guest .2 -> host .1: the second one would be probed
    # on the host's own TAP address; the first entry of a colliding pair is kept
    (["192.168.0.1", "192.168.0.2"], ["192.168.0.1"]),
    (["192.168.0.2", "192.168.0.1"], ["192.168.0.2"]),
    (["192.168.0.1", "10.0.0.1", "192.168.0.2", "10.0.0.2"], ["192.168.0.1", "10.0.0.1"]),
    # .0 -> host .1; guest .1 would be that host address
    (["192.168.0.0", "192.168.0.1"], ["192.168.0.0"]),
    # the same guest address on two devices (FIRMAE_NET) is no collision
    (["192.168.0.1", "192.168.0.1"], ["192.168.0.1", "192.168.0.1"]),
    (["192.168.0.1", "192.168.1.1", "192.168.0.3"], ["192.168.0.1", "192.168.1.1", "192.168.0.3"]),
])
def test_guest_address_equal_to_a_host_address_is_dropped(layout, kept, capsys):
    nets = [N(ip, "eth%d" % i) for i, ip in enumerate(layout)]
    res = mn.dropHostIpCollisions(nets)
    assert [n[0] for n in res] == kept
    hosts = {mn.convertToHostIp(n[0]) for n in res}
    assert not hosts & {n[0] for n in res}
    out = capsys.readouterr().out
    assert out.count("collides with a host-side TAP address") == len(layout) - len(kept)


def test_usable_network_list_drops_classes_and_collisions(capsys):
    nets = [N("127.0.0.2", "eth0"), N("192.168.0.1", "eth1"), N("224.0.0.1", "eth2"), N("192.168.0.2", "eth3")]
    assert mn.usableNetworkList(nets) == [N("192.168.0.1", "eth1")]
    out = capsys.readouterr().out
    assert "127.0.0.2" in out and "loopback" in out and "multicast" in out and "collides" in out


def _sample_addresses():
    import random
    rnd = random.Random(1234)
    ips = [ip for ip, _ in UNUSABLE] + USABLE + ["0.0.0.0", "127.0.0.1", "127.0.0.0", "9.255.255.255",
                                                  "169.254.0.0", "223.0.0.0", "239.0.0.0", "254.1.1.1"]
    ips += ["%d.%d.%d.%d" % tuple(rnd.randrange(256) for _ in range(4)) for _ in range(1500)]
    # first-octet and 169.x sweeps: every class boundary
    ips += ["%d.1.2.3" % a for a in range(256)] + ["169.%d.0.1" % b for b in range(256)]
    return ips


@pytest.mark.linux
def test_the_three_layers_share_one_definition(repo_root):
    """isGuestIpv4 (makeNetwork), usable_guest_ip (firmae/check.py) and
    emu_guest_ipv4 (scripts/emulate.sh) accept exactly the same addresses."""
    import re
    import subprocess
    from firmae import check
    ips = _sample_addresses()
    py = [mn.isGuestIpv4(ip) for ip in ips]
    assert py == [check.usable_guest_ip(ip) for ip in ips]
    text = (repo_root / "scripts" / "emulate.sh").read_text()
    # the character lists and patterns, and the two functions, as emulate.sh has them
    defs = [l for l in text.splitlines() if re.match(r"EMU_(D|NZ|AN|NUM|RE_IPV4|RE_OCTET)=", l)]
    funcs = [re.search(r"^%s \(\) \{\n.*?^\}\n" % f, text, re.S | re.M) for f in ("emu_ipv4", "emu_guest_ipv4")]
    assert len(defs) == 6 and all(funcs)
    script = "\n".join(defs) + "\n" + "".join(f.group(0) for f in funcs)
    script += 'for ip in "$@"; do emu_guest_ipv4 "$ip" && echo y || echo n; done\n'
    res = subprocess.run(["bash", "-c", script, "_"] + ips, capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["y" if ok else "n" for ok in py]
    assert py.count(True) > 100 and py.count(False) > 100
