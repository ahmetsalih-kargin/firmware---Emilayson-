"""REFACTORING_PLAN 2.10 and 5.1: port discovery from the serial log and the
user-network (DHCP mode) host ports.

* findPorts() reads both inet_bind formats (4.1 kernels: `port:N`, older:
  `ip:port: 0x<ip>:<port>`), drops port 0 and ephemeral ports, de-duplicates
  per (proto, port), is bounded and linear on hostile input.
* hostfwd host ports are free loopback ports from HOSTFWD_PORT_MIN..MAX (was:
  host port = guest port 80/443/..., so a host web server blocked QEMU, two
  analyses collided and check_emulation.sh could report the host's own port 80
  as the guest's web UI). The mapping is recorded in scratch/<IID>/hostfwd.
* check_emulation.sh in DHCP mode probes only the recorded host ports and no
  longer writes ping=true unconditionally.

No root, no QEMU: system commands are stubs.
"""

import os
import re
import shutil
import socket
import subprocess
import time

import pytest

from scripts import makeNetwork as mn

INIT = "rdinit=/firmadyne/preInit.sh"
DHCP_NET = ("10.0.2.15", "eth0", None, None, "br0")
TAP_NET = ("192.168.0.1", "eth0", None, None, "br0")
linux = pytest.mark.linux


def line(msg, ts="1.000000"):
    return "[%12s] firmadyne: %s" % (ts, msg)


def log(*msgs):
    return ("\n".join(line(m) for m in msgs) + "\n").encode()


def bind41(port, proto="STREAM", comm="httpd"):
    return "inet_bind[PID: 7 (%s)]: proto:SOCK_%s, port:%s" % (comm, proto, port)


def always_free(proto, port):
    return True


# --------------------------------------------------------------------------
# findPorts
# --------------------------------------------------------------------------

def test_port_zero_ephemeral_and_repeats_are_dropped():
    data = log(bind41(0, "DGRAM"), bind41(80), bind41(80), bind41(80, "DGRAM"),
               bind41(32767), bind41(32768), bind41(49152), bind41(63481), bind41(65535),
               bind41(1), bind41("00022"))
    assert mn.findPorts(data, "el") == [("tcp", "0.0.0.0", 80), ("udp", "0.0.0.0", 80),
                                        ("tcp", "0.0.0.0", 32767), ("tcp", "0.0.0.0", 1),
                                        ("tcp", "0.0.0.0", 22)]


def test_out_of_range_ports_are_skipped_with_a_warning(capsys):
    data = log(bind41(65536), bind41("000080"), bind41("9" * 5000), bind41(8080))
    assert mn.findPorts(data, "el") == [("tcp", "0.0.0.0", 8080)]
    assert capsys.readouterr().out.count("skipped invalid inet_bind record") == 3


def test_result_is_capped(capsys):
    data = log(*[bind41(1000 + i) for i in range(5000)])
    res = mn.findPorts(data, "el")
    assert res == [("tcp", "0.0.0.0", 1000 + i) for i in range(mn.MAX_PORTS)]
    assert capsys.readouterr().out.count("bound ports") == 1


def test_order_is_first_bind_and_deterministic():
    msgs = [bind41(p, proto) for p in (8080, 22, 443, 22, 8080) for proto in ("DGRAM", "STREAM")]
    data = log(*msgs)
    first = mn.findPorts(data, "el")
    assert first == mn.findPorts(data, "el")
    assert [(p, n) for (p, _, n) in first] == [("udp", 8080), ("tcp", 8080), ("udp", 22),
                                               ("tcp", 22), ("udp", 443), ("tcp", 443)]


@pytest.mark.parametrize("bad", [
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:8080;touch /tmp/x",
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:8080 $(id)",
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:`id`",
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:-1",
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:0x50",
    "inet_bind[PID: 7 (x)]: proto:SOCK_RAW, port:8080",
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port: 8080",
    "inet_bind[PID: 7 (x]y)]: proto:SOCK_STREAM, port:8080",
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, ip:port: 0xzz:8080",
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:8080:9",
    "xinet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:8080",
])
def test_hostile_lines_yield_nothing(bad):
    assert mn.findPorts(log(bad), "el") == []


def test_a_newline_cannot_smuggle_text_into_a_record():
    # a record is one line: the text after "\n" is a line of its own and no record
    data = log("inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:8080\n;reboot;\r",
               "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:8081\r")
    assert mn.findPorts(data, "el") == [("tcp", "0.0.0.0", 8080), ("tcp", "0.0.0.0", 8081)]


def test_shell_metacharacters_in_the_process_name_do_not_matter():
    data = log(bind41(8080, comm="$(reboot);`id`|&>"))
    assert mn.findPorts(data, "el") == [("tcp", "0.0.0.0", 8080)]


def test_hostile_log_is_parsed_in_linear_time():
    """Long digit runs, near-miss lines and a huge single line: no backtracking."""
    junk = [bind41("9" * 200000)] * 50
    junk += ["inet_bind[" + "[" * 200000 + "]: proto:SOCK_STREAM, port:1"] * 20
    junk += ["inet_bind[PID: 1 (x)]: proto:SOCK_STREAM, ip:port: 0x" + "0" * 200000 + ":80"] * 20
    junk += [bind41(1000 + i % 30000) for i in range(200000)]
    data = log(*junk) + b"inet_bind[" + b"9" * (8 * 1024 * 1024) + b"\n"
    t = time.monotonic()
    res = mn.findPorts(data, "el")
    assert time.monotonic() - t < 20
    assert len(res) == mn.MAX_PORTS


# --------------------------------------------------------------------------
# host port choice
# --------------------------------------------------------------------------

def test_hostfwd_range_avoids_placeholders_and_ephemeral_ports():
    placeholders = range(mn.placeholderPort(0, 0), mn.placeholderPort(9999, 3) + 1)
    assert mn.HOSTFWD_PORT_MAX < placeholders.start
    assert mn.placeholderPort(987654321, 3) in placeholders
    assert 1024 < mn.HOSTFWD_PORT_MIN and mn.HOSTFWD_PORT_MAX < mn.EPHEMERAL_PORT_MIN
    assert mn.HOSTFWD_BLOCK >= 2 + mn.MAX_FORWARD_PORTS


def test_host_ports_map_80_443_and_the_extra_ports():
    ports = [("tcp", "0.0.0.0", 8080), ("udp", "0.0.0.0", 161), ("tcp", "0.0.0.0", 80)]
    hf = mn.chooseHostPorts(3, ports, isFree=always_free)
    base = mn.HOSTFWD_PORT_MIN + 3 * mn.HOSTFWD_BLOCK
    assert hf == [("tcp", 80, base), ("tcp", 443, base + 1), ("tcp", 8080, base + 2),
                  ("udp", 161, base + 3)]
    assert mn.chooseHostPorts(3, ports, isFree=always_free) == hf          # deterministic


def test_different_images_get_different_host_ports():
    ports = [("tcp", "0.0.0.0", 1000 + i) for i in range(100)]          # full MAX_FORWARD_PORTS
    sets = {iid: {h for (_, _, h) in mn.chooseHostPorts(iid, ports, isFree=always_free)}
            for iid in range(0, 250)}
    assert all(len(s) == 2 + mn.MAX_FORWARD_PORTS for s in sets.values())
    ids = sorted(sets)
    assert all(not (sets[a] & sets[b]) for n, a in enumerate(ids) for b in ids[n + 1:])
    for s in sets.values():
        assert all(mn.HOSTFWD_PORT_MIN <= h <= mn.HOSTFWD_PORT_MAX for h in s)


def test_scan_wraps_around_the_range():
    last_block = mn.HOSTFWD_PORT_MAX + 1 - mn.HOSTFWD_BLOCK
    taken = set(range(last_block, mn.HOSTFWD_PORT_MAX + 1))
    hf = mn.chooseHostPorts(249, [], isFree=lambda proto, p: p not in taken)
    assert hf == [("tcp", 80, mn.HOSTFWD_PORT_MIN), ("tcp", 443, mn.HOSTFWD_PORT_MIN + 1)]


def test_no_free_port_is_a_clear_error():
    with pytest.raises(mn.HostPortError, match="no free port on 127.0.0.1"):
        mn.chooseHostPorts(1, [], isFree=lambda proto, p: False)


def test_a_taken_port_is_skipped_real_socket():
    first = mn.chooseHostPorts(7, [])[0][2]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            s.bind(("127.0.0.1", first))
        except OSError:
            pytest.skip("port %d is busy on this host" % first)
        s.listen(1)
        assert not mn.hostPortIsFree("tcp", first)
        hf = mn.chooseHostPorts(7, [])
        assert first not in [h for (_, _, h) in hf]
        assert all(mn.hostPortIsFree(p, h) for (p, _, h) in hf)
    finally:
        s.close()
    assert mn.hostPortIsFree("tcp", first)


def test_a_taken_udp_port_is_skipped_real_socket():
    first = mn.chooseHostPorts(8, [("udp", "0.0.0.0", 161)])[2][2]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            s.bind(("127.0.0.1", first))
        except OSError:
            pytest.skip("port %d is busy on this host" % first)
        hf = mn.chooseHostPorts(8, [("udp", "0.0.0.0", 161)])
        assert hf[2][0] == "udp" and hf[2][2] != first
    finally:
        s.close()


@pytest.mark.parametrize("hf", [
    [("tcp", 80, 80)],                              # the guest port number on the host
    [("tcp", 80, mn.HOSTFWD_PORT_MAX + 1)],
    [("tcp", 80, 10000), ("tcp", 443, 10000)],      # one host port twice
    [("tcp", 0, 10000)],
    [("icmp", 80, 10000)],
    [("tcp", "80", 10000)],
    [("tcp", 80, True)],
    [("tcp", 80, "10000;id")],
    [("tcp", 80)],
    ("tcp", 80, 10000),
    [("tcp", 1000 + i, 10000 + i) for i in range(3 + mn.MAX_FORWARD_PORTS)],
])
def test_qemucmd_refuses_bad_hostfwd_rules(hf, firmae_env):
    with pytest.raises(mn.UnsafeValue):
        mn.qemuCmd(1, [DHCP_NET], [], "normal", "mips", "el", INIT, True, hf)


# --------------------------------------------------------------------------
# generated run.sh
# --------------------------------------------------------------------------

def hostfwd_rules(script):
    return re.findall(r"hostfwd=(tcp|udp):([0-9.]*):([0-9]+)-:([0-9]+)", script)


def test_user_network_run_sh_forwards_loopback_host_ports(firmae_env):
    hf = [("tcp", 80, 10120), ("tcp", 443, 10121), ("tcp", 8080, 10122), ("udp", 161, 10123)]
    out = mn.qemuCmd(3, [DHCP_NET], [("tcp", "0.0.0.0", 8080), ("udp", "0.0.0.0", 161)],
                     "normal", "mips", "el", INIT, True, hf)
    assert "-netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:10120-:80," \
           "hostfwd=tcp:127.0.0.1:10121-:443,hostfwd=tcp:127.0.0.1:10122-:8080," \
           "hostfwd=udp:127.0.0.1:10123-:161 " in out
    assert hostfwd_rules(out) == [(p, "127.0.0.1", str(h), str(g)) for (p, g, h) in hf]
    # the run.sh pre-check covers the TCP host ports
    assert "for HOSTFWD_PORT in 10120 10121 10122; do" in out


def test_user_network_chooses_ports_when_none_are_given(firmae_env):
    out = mn.qemuCmd(1, [DHCP_NET], [], "normal", "mips", "el", INIT, True)
    rules = hostfwd_rules(out)
    assert [(p, g) for (p, _, _, g) in rules] == [("tcp", "80"), ("tcp", "443")]
    assert all(a == "127.0.0.1" and mn.HOSTFWD_PORT_MIN <= int(h) <= mn.HOSTFWD_PORT_MAX
               for (_, a, h, _) in rules)


def test_only_one_user_nic_carries_the_forwards(firmae_env):
    """QEMU cannot bind one host port for two NICs; every user NIC used to get
    the same 80/443 rules. The NIC with the DHCP address gets them."""
    net = [("192.168.0.1", "eth0", None, None, "br0"), ("10.0.2.15", "eth1", None, None, "br1")]
    hf = [("tcp", 80, 10000), ("tcp", 443, 10001)]
    out = mn.qemuNetworkConfig("mips", net, True, [], 0, hf)
    nics = out.split(" -device ")
    assert nics[0].endswith("-netdev user,id=net0,restrict=on")
    assert "id=net1,restrict=on,hostfwd=tcp:127.0.0.1:10000-:80,hostfwd=tcp:127.0.0.1:10001-:443" in nics[1]
    assert out.count("hostfwd=") == 2


def user_netdevs(script):
    """{netdev id: [(proto, host, guest)]} of every `-netdev user` in the QEMU arguments."""
    out = {}
    for m in re.finditer(r"-netdev user,id=(net[0-9]+)((?:,[^ ]*)?)", script):
        out[m.group(1)] = [(p, int(h), int(g)) for (p, a, h, g) in
                           re.findall(r"hostfwd=(tcp|udp):([0-9.]*):([0-9]+)-:([0-9]+)", m.group(2))]
    return out


LAYOUTS = {
    # audit t2.py: the guessed eth7 replaced the DHCP NIC the rules were on
    "guessed-replaces-dhcp": [("192.168.0.1", "eth7", None, None, "br0"), ("10.0.2.15", "eth0", None, None, "br1")],
    # audit t1.py: arm + FIRMAE_NET has one NIC; the DHCP network is not placed
    "dhcp-second": [("192.168.0.1", "eth0", None, None, "br0"), ("10.0.2.15", "eth1", None, None, "br1")],
    "dhcp-eth5": [("10.0.2.15", "eth5", None, None, "br0")],
    "dhcp-then-guessed": [("10.0.2.15", "eth0", None, None, "br0"), ("192.168.0.1", "eth7", None, None, "br1")],
    "two-dhcp": [("10.0.2.15", "eth0", None, None, "br0"), ("10.0.2.16", "eth0", None, None, "br1")],
    "one-dhcp": [DHCP_NET],
}


@pytest.mark.parametrize("arch", ["mips", "arm"])
@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_recorded_rules_are_exactly_the_rules_in_the_qemu_arguments(arch, layout, firmae_env):
    """Audit finding: for some layouts the rules vanished from the QEMU
    arguments while scratch/<IID>/hostfwd still announced them."""
    hf = [("tcp", 80, 10280), ("tcp", 443, 10281), ("udp", 161, 10282)]
    script, placed = mn.qemuCmdAndHostfwd(7, LAYOUTS[layout], [("udp", "0.0.0.0", 161)], "normal",
                                          arch, "el", INIT, True, hf)
    netdevs = user_netdevs(script)
    carrying = [n for n, rules in netdevs.items() if rules]
    assert len(carrying) == 1                       # exactly one NIC, never zero
    assert netdevs[carrying[0]] == [(p, h, g) for (p, g, h) in placed]
    assert placed == hf
    assert mn.hostfwdRulesIn(script) == placed      # what process() records
    assert "for HOSTFWD_PORT in 10280 10281; do" in script


@pytest.mark.parametrize("arch", ["mips", "arm"])
def test_the_rules_go_to_the_placed_dhcp_nic(arch, firmae_env):
    net = LAYOUTS["dhcp-then-guessed"] if arch == "mips" else LAYOUTS["one-dhcp"]
    hf = [("tcp", 80, 10000), ("tcp", 443, 10001)]
    netdevs = user_netdevs(mn.qemuNetworkConfig(arch, net, True, [], 0, hf))
    assert netdevs["net0"] == [("tcp", 10000, 80), ("tcp", 10001, 443)]


def test_no_placed_nic_means_no_rules_and_no_file_content(firmae_env):
    hf = [("tcp", 80, 10000), ("tcp", 443, 10001)]
    args, placed = mn.qemuNetworkConfigAndHostfwd("mips", [], True, [], 0, hf)
    assert placed == [] and "hostfwd" not in args
    assert mn.hostfwdCheck(placed) == "" and mn.hostfwdText(placed) == ""


def test_tap_mode_reports_no_rules(firmae_env):
    script, placed = mn.qemuCmdAndHostfwd(1, [TAP_NET], [], "normal", "mips", "el", INIT, False,
                                          [("tcp", 80, 10000)])
    assert placed == [] and "hostfwd" not in script.lower()
    assert mn.hostfwdRulesIn(script) == []


def test_process_writes_no_file_when_run_sh_has_no_rules(tmp_path, monkeypatch, firmae_env):
    """The file is derived from the generated run.sh: no rule there, no file."""
    monkeypatch.setattr(mn, "qemuCmd", lambda *a, **k: "#!/bin/true\n")
    work = generate(tmp_path, monkeypatch, log(*HOSTILE_LOG))
    assert (work / "isDhcp").read_text() == "true"
    assert not (work / "hostfwd").exists()


def test_process_records_what_qemu_gets_for_the_audit_layout(tmp_path, monkeypatch, firmae_env):
    """mips, eth7 guessed onto NIC 0 over the DHCP eth0 (audit t2.py). FIRMAE_NET
    off: checkNetwork() would otherwise drop the 10.0.2.x network."""
    firmae_env(net="false")
    work = generate(tmp_path, monkeypatch, log(
        "__inet_insert_ifa[PID: 1 (ip)]: device:eth7 ifa:0x0100a8c0",
        "__inet_insert_ifa[PID: 1 (udhcpc)]: device:eth0 ifa:0x0f02000a", bind41(8080)))
    netdevs = user_netdevs((work / "run.sh").read_text())
    rules = [l.split() for l in (work / "hostfwd").read_text().splitlines()]
    carried = [r for rs in netdevs.values() for r in rs]
    assert carried == [(p, int(h), int(g)) for (p, g, h) in rules]
    assert [int(g) for (_, g, _) in rules] == [80, 443, 8080]


def test_hostfwd_block_uses_the_whole_iid():
    """Audit: with iid % 250, IIDs 250 apart always shared a block."""
    blocks = 250
    assert sorted(mn.hostfwdBlock(i) for i in range(blocks)) == list(range(blocks))
    for base in (0, 1, 7, 249, 1000, 123456):
        assert len({mn.hostfwdBlock(base + k * blocks) for k in range(10)}) == 10
    assert all(0 <= mn.hostfwdBlock(i) < blocks for i in (-1, -250, 10 ** 30))


def test_tap_mode_has_no_hostfwd_and_no_precheck(firmae_env):
    out = mn.qemuCmd(1, [TAP_NET], [("tcp", "0.0.0.0", 8080)], "normal", "mips", "el", INIT, False,
                     [("tcp", 80, 10000)])
    assert "hostfwd" not in out.lower()
    assert "isolate_guest_network ${IID}\n\n# QEMU runs" in out


HOSTILE_LOG = [
    "__inet_insert_ifa[PID: 1 (udhcpc)]: device:eth0 ifa:0x0f02000a",
    "inet_bind[PID: 7 ($(touch PWNED))]: proto:SOCK_STREAM, port:8080",
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:8081;touch PWNED",
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:8082\n`touch PWNED`",
    "inet_bind[PID: 7 (x)]: proto:SOCK_DGRAM, port:%s" % ("9" * 1000),
    "inet_bind[PID: 7 (x)]: proto:SOCK_STREAM, port:80",
]


def generate(tmp_path, monkeypatch, serial, iid=4, web=False):
    """process() on a fake serial log: inferNetwork() and check_emulation.sh
    are replaced, everything between (parsers, network choice, port choice,
    run.sh, scratch/<IID>/hostfwd) is the real code."""
    scratch = tmp_path / "scratch"
    work = scratch / str(iid)
    work.mkdir(parents=True, exist_ok=True)
    (work / "init").write_text("/sbin/init\n")
    monkeypatch.setattr(mn, "SCRATCHDIR", str(scratch))

    def infer(iid_, arch, end, init):
        ports = mn.findPorts(serial, end)
        ifaces = mn.findNonLoInterfaces(serial, end)
        return INIT, mn.getNetworkList(serial, ifaces, mn.findMacChanges(serial, end)), None, None, ports
    monkeypatch.setattr(mn, "inferNetwork", infer)
    checks = []

    def fake_call(argv, *a, **k):
        checks.append(argv)
        if web:
            (work / "web").write_text("true\n")
        return 0
    monkeypatch.setattr(mn.subprocess, "call", fake_call)
    mn.process(iid, "mips", "el", True, str(work / "run.sh"))
    assert checks == [["./scripts/check_emulation.sh", str(iid), "mipsel"]]
    return work


def test_process_writes_run_sh_and_the_mapping_file(tmp_path, monkeypatch, firmae_env):
    work = generate(tmp_path, monkeypatch, log(*HOSTILE_LOG))
    assert (work / "isDhcp").read_text() == "true"
    script = (work / "run.sh").read_text()
    mapping = (work / "hostfwd").read_text()
    lines = mapping.splitlines()
    assert mapping.endswith("\n")
    assert all(re.fullmatch(r"(tcp|udp) [0-9]{1,5} [0-9]{1,5}", l) for l in lines)
    rules = [l.split() for l in lines]
    # 8080 (hostile process name, valid record) and 8082 (the text after the
    # embedded "\n" is a separate, ignored line) are real binds; 8081 is not
    assert [(p, int(g)) for (p, g, _) in rules] == [("tcp", 80), ("tcp", 443), ("tcp", 8080),
                                                    ("tcp", 8082)]
    assert all(mn.HOSTFWD_PORT_MIN <= int(h) <= mn.HOSTFWD_PORT_MAX for (_, _, h) in rules)
    # run.sh forwards exactly what the file records
    assert hostfwd_rules(script) == [(p, "127.0.0.1", h, g) for (p, g, h) in rules]
    assert not re.search(r"hostfwd=tcp:127\.0\.0\.1:(80|443)-", script)
    # nothing of the hostile lines got into the script
    assert "PWNED" not in script and "999" not in script and "8081" not in script


@linux
def test_generated_user_mode_run_sh_is_valid_bash(tmp_path, monkeypatch, firmae_env):
    work = generate(tmp_path, monkeypatch, log(*HOSTILE_LOG))
    res = subprocess.run(["bash", "-n", str(work / "run.sh")], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


def test_process_in_tap_mode_removes_a_stale_mapping(tmp_path, monkeypatch, firmae_env):
    scratch = tmp_path / "scratch" / "4"
    scratch.mkdir(parents=True)
    (scratch / "hostfwd").write_text("tcp 80 10160\n")
    work = generate(tmp_path, monkeypatch, log(
        "__inet_insert_ifa[PID: 1 (ip)]: device:eth0 ifa:0x0100a8c0", bind41(80)), web=True)
    assert (work / "isDhcp").read_text() == "false"
    assert not (work / "hostfwd").exists()
    assert "hostfwd" not in (work / "run.sh").read_text()


@linux
def test_mapping_file_is_not_written_through_a_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("keep")
    os.symlink(str(target), str(tmp_path / "hostfwd"))
    with pytest.raises(OSError):
        mn.writeStateFile(str(tmp_path / "hostfwd"), "tcp 80 10000\n")
    assert target.read_text() == "keep"
    mn.removeStateFile(str(tmp_path / "hostfwd"))         # removes the link, not the target
    assert not os.path.lexists(str(tmp_path / "hostfwd")) and target.read_text() == "keep"
    os.mkfifo(str(tmp_path / "fifo"))
    # O_NONBLOCK: no reader -> ENXIO at once instead of blocking
    with pytest.raises(OSError):
        mn.writeStateFile(str(tmp_path / "fifo"), "x")
    os.mkdir(str(tmp_path / "dir"))
    with pytest.raises(OSError):
        mn.writeStateFile(str(tmp_path / "dir"), "x")


def test_mapping_file_format():
    assert mn.hostfwdText([("tcp", 80, 10000), ("udp", 161, 10003)]) == "tcp 80 10000\nudp 161 10003\n"
    assert mn.hostfwdText([]) == ""


@linux
def test_run_sh_precheck_stops_on_a_taken_port(tmp_path):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    taken = s.getsockname()[1]
    try:
        for ports, rc in (([("tcp", 80, taken)], 1), ([("udp", 161, taken)], 0)):
            script = tmp_path / "pre.sh"
            script.write_text("set -e\n" + mn.hostfwdCheck(ports) + "\necho reached\n")
            res = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30)
            assert res.returncode == rc, res.stderr
            if rc:
                assert "127.0.0.1:%d (hostfwd) is in use" % taken in res.stderr
                assert "reached" not in res.stdout
    finally:
        s.close()



# --------------------------------------------------------------------------
# check_emulation.sh, DHCP branch
# --------------------------------------------------------------------------

# A stand-in for this image's QEMU: argv[0] "qemu-system-mipsel" and the
# -drive argument that qemu_pids (firmae.config) looks for; it listens on the
# given loopback ports like QEMU's hostfwd sockets.
FAKE_QEMU = r'''
import socket, sys, time
args = sys.argv[1:]
ports = [int(p) for p in args[args.index("--ports") + 1].split(",") if p]
life = float(args[args.index("--life") + 1]) if "--life" in args else 600
socks = []
for p in ports:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", p))
    s.listen(8)
    socks.append(s)
time.sleep(life)
'''

LISTENER = r'''
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(8)
time.sleep(600)
'''


def free_ports(n):
    """n free TCP ports inside the hostfwd range (they must pass read_hostfwd)."""
    found = []
    start = mn.HOSTFWD_PORT_MIN + (os.getpid() * 7919) % 9000
    for p in list(range(start, mn.HOSTFWD_PORT_MAX + 1)) + list(range(mn.HOSTFWD_PORT_MIN, start)):
        if mn.hostPortIsFree("tcp", p) and mn.hostPortIsFree("udp", p):
            found.append(p)
            if len(found) == n:
                return found
    pytest.skip("no free ports in the hostfwd range")


def wait_listening(port, timeout=10):
    for _ in range(int(timeout / 0.05)):
        if not mn.hostPortIsFree("tcp", port):
            return
        time.sleep(0.05)
    raise AssertionError("nothing listens on %d" % port)


def stub(d, name, body):
    p = d / name
    p.write_text("#!/bin/bash\n" + body + "\n")
    p.chmod(0o755)


@pytest.fixture
def procs():
    started = []

    def start(argv):
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        started.append(p)
        return p
    yield start
    for p in started:
        if p.poll() is None:
            p.kill()
        p.wait()


@pytest.fixture
def dhcp_check(repo_root, tmp_path, procs):
    root = tmp_path / "FirmAE"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(repo_root / "firmae.config", root)
    for name in ("check_emulation.sh", "hostfwd_check.sh"):
        shutil.copy(repo_root / "scripts" / name, root / "scripts")
    work = root / "scratch" / "5"
    work.mkdir(parents=True)
    (work / "image.raw").write_text("")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    netlog = tmp_path / "net_log"
    # curl succeeds only for the URL in $CURL_OK (whoever listens there "answers");
    # the last argument is the URL
    stub(bindir, "curl", 'echo "curl ${@: -1}" >> %s; [ -n "${CURL_OK:-}" ] && [ "${@: -1}" = "$CURL_OK" ]' % netlog)
    stub(bindir, "ping", 'echo "ping $*" >> %s; exit 0' % netlog)
    stub(bindir, "sleep", "exit 0")
    clock = tmp_path / "clock"
    clock.write_text("0")
    stub(bindir, "date", 'if [ "$1" = "+%%s" ]; then n=$(cat %s); echo $n; echo $((n+10)) > %s; '
                         'else echo 0.0; fi' % (clock, clock))
    fake = tmp_path / "fakeqemu.py"
    fake.write_text(FAKE_QEMU)
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    env.pop("FIRMAE_DOCKER", None)

    def qemu(ports, iid="5"):
        """this image's (fake) QEMU, listening on `ports`"""
        p = procs(["bash", "-c", 'exec -a qemu-system-mipsel python3 "$@"', "_", str(fake), "-drive",
                   "if=ide,format=raw,file=%s/scratch/%s/image.raw" % (root, iid),
                   "--ports", ",".join(str(x) for x in ports)])
        for x in ports:
            wait_listening(x)
        return p

    def foreign(port):
        """some other program holding a hostfwd port"""
        p = procs(["python3", "-c", LISTENER, str(port)])
        wait_listening(port)
        return p

    def run(hostfwd, isdhcp="true", curl_ok=None, ips=(), run_sh="exit 0"):
        (work / "run.sh").write_text("#!/bin/bash\n%s\n" % run_sh)
        (work / "run.sh").chmod(0o755)
        (work / "isDhcp").write_text(isdhcp)
        (work / "ip_num").write_text(str(len(ips)))
        for i, ip in enumerate(ips):
            (work / ("ip.%d" % i)).write_text(ip)
        if hostfwd is not None:
            if isinstance(hostfwd, bytes):
                (work / "hostfwd").write_bytes(hostfwd)
            else:
                (work / "hostfwd").write_text(hostfwd)
        for name in ("ping", "web", "ip", "time_ping", "time_web"):
            if (work / name).exists():
                (work / name).unlink()
        if netlog.exists():
            netlog.unlink()
        e = dict(env, CURL_OK=curl_ok) if curl_ok else env
        res = subprocess.run(["bash", "./scripts/check_emulation.sh", "5", "mipsel"], cwd=root, env=e,
                             capture_output=True, text=True, timeout=120)
        assert res.returncode == 0, res.stdout + res.stderr
        assert "Check inferred emulation end" in res.stdout
        calls = netlog.read_text().splitlines() if netlog.exists() else []
        state = {n: (work / n).read_text().strip() for n in ("ping", "web", "ip", "time_ping", "time_web")
                 if (work / n).exists()}
        return calls, state, res
    run.work = work
    run.qemu = qemu
    run.foreign = foreign
    return run


def mapping(h80, h443):
    return "tcp 80 %d\ntcp 443 %d\ntcp 8080 %d\nudp 161 %d\n" % (h80, h443, h443 + 1, h443 + 2)


@linux
def test_dhcp_check_reaches_the_guest_only_through_the_mapped_port(dhcp_check):
    h80, h443 = free_ports(2)
    dhcp_check.qemu([h80, h443])
    calls, state, _ = dhcp_check(mapping(h80, h443), curl_ok="http://127.0.0.1:%d" % h80)
    assert calls == ["curl http://127.0.0.1:%d" % h80]
    assert state["web"] == "true" and state["ping"] == "true" and state["ip"] == "127.0.0.1"
    assert state["time_ping"] == state["time_web"]


@linux
def test_dhcp_check_https_only_and_unreachable_guest(dhcp_check):
    h80, h443 = free_ports(2)
    dhcp_check.qemu([h80, h443])
    calls, state, _ = dhcp_check(mapping(h80, h443), curl_ok="https://127.0.0.1:%d" % h443)
    assert calls[-2:] == ["curl http://127.0.0.1:%d" % h80, "curl https://127.0.0.1:%d" % h443]
    assert state["web"] == "true"
    # nobody answers: no web, and -- unlike before -- no ping=true either
    dhcp_check.qemu([h80, h443])           # finish() stopped the first one
    calls, state, _ = dhcp_check(mapping(h80, h443))
    assert calls and set(calls) == {"curl http://127.0.0.1:%d" % h80, "curl https://127.0.0.1:%d" % h443}
    assert state == {}


@linux
def test_dhcp_check_never_probes_the_hosts_own_ports_or_pings(dhcp_check):
    """Was: ping=true written at once, then check_network 127.0.0.1, i.e.
    `curl http://127.0.0.1` -- any web server on the host's port 80 made the
    firmware count as emulated."""
    h80, h443 = free_ports(2)
    for curl_ok in ("http://127.0.0.1", "http://127.0.0.1:80", None):
        dhcp_check.qemu([h80, h443])
        calls, state, _ = dhcp_check(mapping(h80, h443), curl_ok=curl_ok)
        assert not any(c.startswith("ping") for c in calls)
        assert set(calls) == {"curl http://127.0.0.1:%d" % h80, "curl https://127.0.0.1:%d" % h443}
        assert "web" not in state and "ping" not in state


@linux
def test_foreign_listener_and_dead_emulation_is_not_web(dhcp_check):
    """Audit finding (fp.sh): another program holds the hostfwd port, so run.sh's
    pre-check exits 1 and QEMU never starts -- the check used to curl the port
    anyway and wrote web=true ping=true ip=127.0.0.1 for the other program."""
    h80, h443 = free_ports(2)
    dhcp_check.foreign(h80)
    calls, state, res = dhcp_check(
        mapping(h80, h443), curl_ok="http://127.0.0.1:%d" % h80,
        run_sh='echo "Error: host port 127.0.0.1:%d (hostfwd) is in use" >&2; exit 1' % h80)
    assert state == {}
    assert calls == []                          # nothing probed once the emulation is gone
    assert "emulation of image 5 is not running" in res.stderr


@linux
def test_foreign_listener_while_this_qemu_runs_is_not_web(dhcp_check):
    """This image's QEMU runs (on other ports), but the port that answers
    belongs to another process: not this firmware's web UI."""
    h80, h443, other = free_ports(3)
    dhcp_check.foreign(h80)
    dhcp_check.qemu([other])
    calls, state, res = dhcp_check(mapping(h80, h443), curl_ok="http://127.0.0.1:%d" % h80)
    assert calls == ["curl http://127.0.0.1:%d" % h80]
    assert state == {}
    assert "port %d belongs to PID" % h80 in res.stderr


@linux
def test_another_images_qemu_on_the_port_is_not_web(dhcp_check):
    """Two images whose blocks meet: image 7's QEMU answers on a port image 5
    recorded; image 5's own QEMU runs as well."""
    h80, h443, other = free_ports(3)
    (dhcp_check.work.parent / "7").mkdir()
    (dhcp_check.work.parent / "7" / "image.raw").write_text("")
    dhcp_check.qemu([h80], iid="7")
    dhcp_check.qemu([other])
    calls, state, res = dhcp_check(mapping(h80, h443), curl_ok="http://127.0.0.1:%d" % h80)
    assert state == {} and "not to the QEMU of image 5" in res.stderr


@linux
def test_no_qemu_yet_but_run_sh_alive_probes_nothing(dhcp_check):
    h80, h443 = free_ports(2)
    dhcp_check.foreign(h80)
    calls, state, _ = dhcp_check(mapping(h80, h443), curl_ok="http://127.0.0.1:%d" % h80,
                                 run_sh='python3 -c "import time; time.sleep(30)"')
    assert calls == [] and state == {}


@linux
def test_without_owner_information_the_answer_does_not_count(dhcp_check, tmp_path):
    """ss shows no owner (not available / not allowed): stay on the safe side."""
    h80, h443 = free_ports(2)
    dhcp_check.qemu([h80, h443])
    stub(tmp_path / "bin", "ss", "exit 0")
    calls, state, res = dhcp_check(mapping(h80, h443), curl_ok="http://127.0.0.1:%d" % h80)
    assert state == {} and "no listener found on port %d" % h80 in res.stderr
    dhcp_check.qemu([h80, h443])
    stub(tmp_path / "bin", "ss", 'echo "LISTEN 0 8 127.0.0.1:%d 0.0.0.0:*"' % h80)
    calls, state, res = dhcp_check(mapping(h80, h443), curl_ok="http://127.0.0.1:%d" % h80)
    assert state == {} and "owner of port %d unknown" % h80 in res.stderr


@pytest.mark.parametrize("bad", [
    None,                                       # no file at all
    "",
    "tcp 80 80\n",                              # host port 80: outside the hostfwd range
    "tcp 80 22\n",
    "tcp 80 20000\n",                           # placeholder range
    "tcp 80 0\n",
    "tcp 80 99999\n",
    "tcp 80 123456\n",
    "tcp 80 10123\r\n",
    "tcp 80 10123 \n",
    " tcp 80 10123\n",
    "tcp  80 10123\n",
    "tcp 80 10123;curl http://127.0.0.1\n",
    "tcp 80 $(id)\n",
    "tcp 80 `id`\n",
    "tcp 80 10123\ntcp 80 10124\n",             # ambiguous
    "tcp 80 10123\ngarbage\n",                  # one bad line rejects the file
    "tcp 0 10123\n",
    "icmp 80 10123\n",
    "tcp 80 +10123\n",
    "tcp 80 0x2723\n",
    "tcp 80 10123\n" + "udp 1 10000\n" * 100,   # too many lines
    "tcp 80 10123\n" + "#" * 5000,              # too large
])
@linux
def test_dhcp_check_rejects_a_bad_mapping_file(dhcp_check, bad):
    calls, state, res = dhcp_check(bad, curl_ok="http://127.0.0.1:10123")
    assert calls == []
    assert state == {}
    assert "hostfwd is missing or invalid" in res.stdout


@linux
def test_dhcp_check_drops_nul_bytes_of_the_mapping_file(dhcp_check):
    h80, = free_ports(1)
    dhcp_check.qemu([h80])
    calls, state, res = dhcp_check(b"tcp 80 %d\x00\n" % h80, curl_ok="http://127.0.0.1:%d" % h80)
    assert "missing or invalid" not in res.stdout
    assert calls == ["curl http://127.0.0.1:%d" % h80] and state["web"] == "true"


@linux
def test_dhcp_check_refuses_a_symlinked_mapping_file(dhcp_check, tmp_path):
    real = tmp_path / "elsewhere"
    real.write_text(mapping(10123, 10124))
    os.symlink(str(real), str(dhcp_check.work / "hostfwd"))
    calls, state, _ = dhcp_check(None, curl_ok="http://127.0.0.1:10123")
    assert calls == [] and state == {}


@linux
def test_dhcp_check_with_only_udp_or_extra_ports_probes_nothing(dhcp_check):
    calls, state, _ = dhcp_check("tcp 8080 10125\nudp 161 10126\n", curl_ok="http://127.0.0.1:10125")
    assert calls == [] and state == {}


@linux
def test_dhcp_check_leading_zeros_are_decimal(dhcp_check):
    h80, h443 = free_ports(2)
    dhcp_check.qemu([h80, h443])
    calls, state, _ = dhcp_check("tcp 080 %d\ntcp 00443 %d\n" % (h80, h443),
                                 curl_ok="https://127.0.0.1:%d" % h443)
    assert calls[-1] == "curl https://127.0.0.1:%d" % h443 and state["web"] == "true"


@linux
def test_tap_branch_ignores_the_mapping_file(dhcp_check):
    """TAP mode is unchanged: the guest IPs from ip.N, check_network with ping."""
    calls, state, _ = dhcp_check(mapping(10123, 10124), isdhcp="false", ips=("192.168.0.1",))
    assert "ping -c 1 192.168.0.1" in calls
    assert "curl http://192.168.0.1" in calls
    assert not any("127.0.0.1" in c for c in calls)
    assert state["ping"] == "true" and state["ip"] == "192.168.0.1" and "web" not in state


def test_shell_and_python_hostfwd_ranges_agree(repo_root):
    text = (repo_root / "scripts" / "hostfwd_check.sh").read_text()
    assert "HOSTFWD_PORT_MIN=%d\n" % mn.HOSTFWD_PORT_MIN in text
    assert "HOSTFWD_PORT_MAX=%d\n" % mn.HOSTFWD_PORT_MAX in text
    check = (repo_root / "scripts" / "check_emulation.sh").read_text()
    assert 'echo true > ${WORK_DIR}/ping\nelse' not in check     # no unconditional ping=true
    assert "read_hostfwd ()" not in check and "check_hostfwd ()" not in check   # one copy only
