"""scratch/<IID>/emulation.conf is derived from the guest's serial log and
read by scripts/emulate.sh as root (REFACTORING_PLAN 4.4). The read side must
hold even against a file that makeNetwork.py's write-time checks would never
produce: emulate.sh refuses it before any command runs (no mount, no TAP, no
QEMU), and parseEmulation() -- the Python mirror of its grammar -- refuses the
same files. Also: how process() writes run.sh, emulation.conf and hostfwd.
"""

import os
import stat
import subprocess

import pytest

from scripts import makeNetwork as mn

INIT = "rdinit=/firmadyne/preInit.sh"
GOOD_NET = [("192.168.0.1", "eth0", None, None, "br0")]
DHCP_NET = [("10.0.2.15", "eth0", None, None, "br0")]
HF = [("tcp", 80, 10004), ("tcp", 443, 10005), ("udp", 161, 10006)]


def good_tap():
    return mn.qemuCmd(1, GOOD_NET, [], "normal", "mips", "el", INIT, False)


def good_dhcp():
    return mn.qemuCmd(1, DHCP_NET, [("udp", "0.0.0.0", 161)], "normal", "mips", "el", INIT, True, HF)


def replace(text, old, new):
    assert old in text, (old, text)
    return text.replace(old, new, 1)


M = "MARKER"     # replaced by the path of a file that must never be created

# (name, base: "tap"/"dhcp", function text -> broken text, expected message)
BROKEN = [
    ("bridge-cmdsubst", "tap", lambda t: replace(t, "NET_BRIDGE=br0", "NET_BRIDGE=br0$(touch M)"), "invalid NET_BRIDGE"),
    ("bridge-backtick", "tap", lambda t: replace(t, "NET_BRIDGE=br0", "NET_BRIDGE=`touch M`"), "invalid NET_BRIDGE"),
    ("iface-too-long", "tap", lambda t: replace(t, "NET_INTERFACE=eth0", "NET_INTERFACE=" + "e" * 16), "invalid NET_INTERFACE"),
    ("iface-dash", "tap", lambda t: replace(t, "NET_INTERFACE=eth0", "NET_INTERFACE=-n"), "invalid NET_INTERFACE"),
    ("init-quote", "tap", lambda t: replace(t, "QEMU_INIT=" + INIT, 'QEMU_INIT=rdinit=/x" -device foo "'), "invalid QEMU_INIT"),
    ("init-space", "tap", lambda t: replace(t, "QEMU_INIT=" + INIT, "QEMU_INIT=init=/x rw;touch M"), "invalid QEMU_INIT"),
    ("network-type", "tap", lambda t: replace(t, "NETWORK_TYPE=normal", "NETWORK_TYPE=normal;touch M"), "invalid NETWORK_TYPE"),
    ("net-semicolon", "tap", lambda t: replace(t, "NET=192.168.0.2 192.168.0.1 -", "NET=192.168.0.2 192.168.0.1 1;touch M"), "invalid NET"),
    ("net-octet", "tap", lambda t: replace(t, "NET=192.168.0.2", "NET=192.168.0.256"), "invalid address"),
    ("net-leading-zero", "tap", lambda t: replace(t, "NET=192.168.0.2", "NET=192.168.0.02"), "invalid address"),
    ("net-vlan", "tap", lambda t: replace(t, "192.168.0.1 -", "192.168.0.1 4095"), "invalid VLAN"),
    ("net-two-spaces", "tap", lambda t: replace(t, "NET=192.168.0.2 192", "NET=192.168.0.2  192"), "invalid NET"),
    ("nic-tap-no-net", "tap", lambda t: replace(t, "NIC=tap 0", "NIC=tap 1"), "has no NET record"),
    ("nic-socket-port", "tap", lambda t: replace(t, "NIC=socket 20005", "NIC=socket 2000"), "invalid placeholder port"),
    ("nic-script", "tap", lambda t: replace(t, "NIC=tap 0", "NIC=tap 0,script=/tmp/x"), "invalid NIC"),
    ("five-nics", "tap", lambda t: t + "NIC=socket 20009\n", "more than 4 NIC"),
    ("iid-other-image", "tap", lambda t: replace(t, "IID=1", "IID=2"), "not 1"),
    ("iid-twice", "tap", lambda t: t + "IID=1\n", "IID given twice"),
    ("arch-twice", "tap", lambda t: t + "ARCH=mips\n", "ARCH given twice"),
    ("armeb", "tap", lambda t: replace(replace(t, "ARCH=mips", "ARCH=arm"), "ENDIAN=el", "ENDIAN=eb"), "unsupported architecture"),
    ("format", "tap", lambda t: replace(t, "FORMAT=1", "FORMAT=2"), "unknown format"),
    ("missing-init", "tap", lambda t: replace(t, "QEMU_INIT=" + INIT + "\n", ""), "no QEMU_INIT"),
    ("unknown-key", "tap", lambda t: t + "PATH=/tmp\n", "unknown record PATH"),
    ("lowercase-key", "tap", lambda t: t + "nic=user\n", "not a KEY=value"),
    ("empty-line", "tap", lambda t: t + "\n", "not a KEY=value"),
    ("crlf", "tap", lambda t: t.replace("\n", "\r\n"), "unknown format"),
    ("leading-space", "tap", lambda t: replace(t, "IID=1", " IID=1"), "not a KEY=value"),
    ("long-line", "tap", lambda t: t + "# " + "x" * 5000 + "\n", "too long"),
    ("many-lines", "tap", lambda t: t + "#\n" * 300, "more than 256 lines"),
    ("gen-firmae-net", "tap", lambda t: replace(t, "GEN_FIRMAE_NET=true", "GEN_FIRMAE_NET=touch"), "invalid GEN_FIRMAE_NET"),
    ("hostfwd-host-port", "dhcp", lambda t: replace(t, "HOSTFWD=tcp 80 10004", "HOSTFWD=tcp 80 80"), "out of range"),
    ("hostfwd-twice", "dhcp", lambda t: replace(t, "HOSTFWD=tcp 443 10005", "HOSTFWD=tcp 443 10004"), "forwarded twice"),
    ("hostfwd-proto", "dhcp", lambda t: replace(t, "HOSTFWD=udp", "HOSTFWD=icmp"), "invalid HOSTFWD"),
    ("hostfwd-guest-0", "dhcp", lambda t: replace(t, "HOSTFWD=tcp 80 ", "HOSTFWD=tcp 0 "), "out of range"),
    ("hostfwd-extra-option", "dhcp", lambda t: replace(t, "HOSTFWD=tcp 80 10004", "HOSTFWD=tcp 80 10004,guestfwd=x"), "invalid HOSTFWD"),
    ("hostfwd-no-carrier", "dhcp", lambda t: replace(t, "NIC=user fwd", "NIC=user"), "exactly one"),
    ("carrier-no-hostfwd", "tap", lambda t: replace(t, "NIC=tap 0", "NIC=user fwd"), "without HOSTFWD"),
    ("octal-number", "dhcp", lambda t: replace(t, "HOSTFWD=tcp 80 10004", "HOSTFWD=tcp 080 10004"), "invalid HOSTFWD"),
    ("arith-injection", "dhcp", lambda t: replace(t, "HOSTFWD=tcp 80 10004", "HOSTFWD=tcp a[$(touch${IFS}M)] 10004"), "invalid HOSTFWD"),
]

# audit B1: NET addresses the host must not put on a TAP device, route or
# probe -- as guest and as host address (isGuestIpv4 / emu_guest_ipv4)
UNUSABLE_NET = ["127.0.0.1", "127.0.0.2", "0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.255",
                "169.254.1.1", "240.0.0.1", "255.255.255.254", "255.255.255.255"]
for _ip in UNUSABLE_NET:
    BROKEN.append(("net-guest-%s" % _ip, "tap",
                   lambda t, ip=_ip: replace(t, "NET=192.168.0.2 192.168.0.1 -", "NET=192.168.0.2 %s -" % ip),
                   "NET address is loopback"))
    BROKEN.append(("net-host-%s" % _ip, "tap",
                   lambda t, ip=_ip: replace(t, "NET=192.168.0.2 192.168.0.1 -", "NET=%s 192.168.0.1 -" % ip),
                   "NET address is loopback"))
BROKEN += [
    ("net-guest-is-own-host", "tap", lambda t: replace(t, "NET=192.168.0.2 192.168.0.1 -", "NET=192.168.0.1 192.168.0.1 -"),
     "guest address 192.168.0.1 is also a host address"),
    # guest .1 / .2 -> host .2 / .1 (convertToHostIp): each guest is the other's host
    ("net-guest-is-other-host", "tap", lambda t: t + "NET=192.168.0.1 192.168.0.2 -\n",
     "guest address 192.168.0.1 is also a host address"),
]


@pytest.mark.parametrize("name,base,breaker,message", BROKEN, ids=[b[0] for b in BROKEN])
def test_parse_emulation_refuses_what_emulate_sh_refuses(name, base, breaker, message, firmae_env):
    text = breaker(good_tap() if base == "tap" else good_dhcp())
    with pytest.raises(mn.UnsafeValue):
        mn.parseEmulation(text, iid=1)


def test_parse_emulation_round_trips(firmae_env):
    for text in (good_tap(), good_dhcp(), mn.qemuCmd(0, [], [], "None", "arm", "el", INIT, False)):
        assert mn.emulationText(mn.parseEmulation(text)) == text
    assert mn.hostfwdRulesIn(good_dhcp()) == HF
    assert mn.hostfwdRulesIn(good_tap()) == []
    assert mn.hostfwdRulesIn("#!/bin/true\n") == []      # comments only: no record, no rule
    with pytest.raises(mn.UnsafeValue):
        mn.hostfwdRulesIn("HOSTFWD=tcp 80 80\n")


@pytest.fixture
def world(repo_root, tmp_path, firmae_env, iptables_stubs):
    from emulation_world import World
    return World(tmp_path / "w", repo_root, iptables_stubs)


def run(world):
    p = subprocess.run([str(world.run_sh)], cwd=str(world.root),
                       env=dict(world.env, QEMU_EXIT_AFTER="0"),
                       capture_output=True, text=True, timeout=60)
    return p


@pytest.mark.linux
@pytest.mark.parametrize("name,base,breaker,message", BROKEN, ids=[b[0] for b in BROKEN])
def test_emulate_sh_refuses_a_bad_file_before_doing_anything(name, base, breaker, message,
                                                             world, tmp_path, firmae_env):
    marker = tmp_path / "PWNED"
    text = breaker(good_tap() if base == "tap" else good_dhcp()).replace(M, str(marker))
    world.install(text)
    p = run(world)
    assert p.returncode == 1, p.stdout + p.stderr
    assert message in p.stderr, p.stderr
    assert "not starting the emulation" in p.stderr
    assert world.calls(firewall=True) == []           # no mount, TAP, firewall or QEMU
    assert not marker.exists()
    assert not (world.work / "run").exists()          # nothing created either
    assert "Done!" not in p.stdout                    # the cleanup trap was not even set


@pytest.mark.linux
def test_the_unbroken_files_run(world, firmae_env):
    for text in (good_tap(), good_dhcp()):
        world.install(text)
        p = run(world)
        if "(hostfwd) is in use" in p.stderr:
            pytest.skip("10004/10005 are taken on this host")
        assert p.returncode == 0, p.stdout + p.stderr


@pytest.mark.linux
@pytest.mark.parametrize("how", ["symlink", "missing", "fifo", "directory"])
def test_emulate_sh_refuses_a_data_file_that_is_not_a_regular_file(how, world, tmp_path, firmae_env):
    world.install(good_tap())
    world.data.unlink()
    if how == "symlink":
        other = tmp_path / "elsewhere.conf"
        other.write_text(good_tap())
        os.symlink(str(other), str(world.data))
    elif how == "fifo":
        os.mkfifo(str(world.data))
    elif how == "directory":
        world.data.mkdir()
    p = run(world)
    assert p.returncode == 1 and "not a regular file" in p.stderr
    assert world.calls(firewall=True) == []


@pytest.mark.linux
@pytest.mark.parametrize("args", [
    [],
    ["./scratch/1/run.sh", "1"],
    ["./scratch/1/run.sh", "1;id", "."],
    ["./scratch/1/run.sh", "01", "."],
    ["./scratch/1/run.sh", "1", "/tmp"],
    ["./scratch/1/run.sh", "1", "../../.."],
])
def test_emulate_sh_checks_its_own_arguments(args, world, firmae_env):
    world.install(good_tap())
    p = subprocess.run(["bash", "./scripts/emulate.sh"] + args, cwd=str(world.root),
                       env=world.env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 1 and p.stderr.startswith(("Usage:", "Error: invalid"))
    assert world.calls(firewall=True) == []


# --------------------------------------------------------------------------
# process(): what makeNetwork.py writes
# --------------------------------------------------------------------------

@pytest.fixture
def proc(tmp_path, monkeypatch, firmae_env):
    t = tmp_path / "1"
    t.mkdir()
    (t / "init").write_text("/etc/rcS\n")
    monkeypatch.setattr(mn, "SCRATCHDIR", str(tmp_path))
    monkeypatch.setattr(mn, "SCRIPTDIR", "/nonexistent")
    monkeypatch.setattr(mn.subprocess, "call", lambda *a, **k: 0)   # check_emulation.sh
    monkeypatch.setattr(mn, "checkNetwork", lambda n: (n, "normal"))
    monkeypatch.setattr(mn, "chooseHostPorts", lambda iid, ports, **k: list(HF))
    return t, monkeypatch


@pytest.mark.parametrize("net", ["tap", "dhcp"])
def test_process_writes_wrapper_data_and_mapping(proc, net):
    t, monkeypatch = proc
    network = GOOD_NET if net == "tap" else DHCP_NET
    ports = [("udp", "0.0.0.0", 161)]
    monkeypatch.setattr(mn, "inferNetwork", lambda *a: (INIT, network, None, None, ports))
    mn.process(1, "mips", "el", False, str(t / "run.sh"))
    assert (t / "run.sh").read_text() == mn.runShWrapper(1)
    assert stat.S_IMODE(os.stat(str(t / "run.sh")).st_mode) == 0o755
    data = (t / mn.EMULATION_FILE).read_text()
    assert data == mn.qemuCmd(1, network, ports, "normal", "mips", "el", INIT, net == "dhcp",
                              HF if net == "dhcp" else None)
    assert stat.S_IMODE(os.stat(str(t / mn.EMULATION_FILE)).st_mode) == 0o644
    if net == "dhcp":
        assert (t / "hostfwd").read_text() == mn.hostfwdText(mn.hostfwdRulesIn(data)) == mn.hostfwdText(HF)
    else:
        assert not (t / "hostfwd").exists()


@pytest.mark.parametrize("ip", ["127.0.0.2", "0.1.2.3", "224.0.0.1", "169.254.1.1", "240.0.0.1",
                                "255.255.255.255"])
def test_write_time_check_refuses_unusable_guest_addresses(ip, firmae_env):
    with pytest.raises(mn.UnsafeValue):
        mn.qemuCmd(1, [(ip, "eth0", None, None, "br0")], [], "normal", "mips", "el", INIT, False)
    spec = mn.parseEmulation(good_tap())
    spec["nets"] = [("192.168.0.2", ip, None)]
    with pytest.raises(mn.UnsafeValue, match="network"):
        mn.checkEmulation(spec)


def test_write_time_check_refuses_a_guest_address_equal_to_a_host_address(firmae_env):
    two = [("192.168.0.1", "eth0", None, None, "br0"), ("192.168.0.2", "eth1", None, None, "br1")]
    with pytest.raises(mn.UnsafeValue, match="equal to a host address"):
        mn.qemuCmd(1, two, [], "normal", "mips", "el", INIT, False)


def test_process_drops_unusable_and_colliding_networks_and_still_writes(proc, capsys):
    """audit B1: guest 192.168.0.1 and 192.168.0.2 would get the host TAP
    addresses .2 and .1; 127.0.0.2 is the host's loopback. The run goes on
    with the one usable network instead of failing or probing the host."""
    t, monkeypatch = proc
    nets = [("127.0.0.2", "eth2", None, None, "br2"), ("192.168.0.1", "eth0", None, None, "br0"),
            ("192.168.0.2", "eth1", None, None, "br1")]
    monkeypatch.setattr(mn, "inferNetwork", lambda *a: (INIT, nets, None, None, []))
    mn.process(1, "mips", "el", False, str(t / "run.sh"))
    data = (t / mn.EMULATION_FILE).read_text()
    assert data == good_tap()
    assert [l for l in data.splitlines() if l.startswith("NET=")] == ["NET=192.168.0.2 192.168.0.1 -"]
    assert (t / "ip_num").read_text() == "1" and (t / "ip.0").read_text() == "192.168.0.1"
    assert not (t / "ip.1").exists()
    out = capsys.readouterr().out
    assert "dropped network ('127.0.0.2'" in out and "loopback" in out
    assert "dropped network ('192.168.0.2'" in out and "collides with a host-side TAP address" in out


@pytest.mark.linux
@pytest.mark.parametrize("name", ["run.sh", mn.EMULATION_FILE])
def test_process_does_not_write_through_a_symlink(proc, tmp_path, name):
    t, monkeypatch = proc
    monkeypatch.setattr(mn, "inferNetwork", lambda *a: (INIT, GOOD_NET, None, None, []))
    victim = tmp_path / "victim"
    victim.write_text("keep\n")
    os.symlink(str(victim), str(t / name))
    with pytest.raises(OSError):
        mn.process(1, "mips", "el", False, str(t / "run.sh"))
    assert victim.read_text() == "keep\n"
