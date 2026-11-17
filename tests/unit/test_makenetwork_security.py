"""Regression tests for the hardening of scripts/makeNetwork.py.

The serial log and the image file system are written by the (untrusted)
emulated firmware, and the final emulation (run.sh -> scripts/emulate.sh,
reading scratch/<IID>/emulation.conf) runs as root on the host:
- log values must never become shell code (command injection),
- malformed log lines must not crash makeNetwork,
- symlinks/special files the guest plants in the image must not redirect a
  host write (Python side and emulate.sh side),
- reads are bounded and lossless.
"""

import os
import subprocess
import sys

import pytest

from scripts import makeNetwork as mn


def line(msg, ts="1.000000"):
    return "[%12s] firmadyne: %s" % (ts, msg)


def log(*msgs):
    return ("\n".join(line(m) for m in msgs) + "\n").encode("utf-8", "surrogateescape")


GOOD_NET = [("192.168.0.1", "eth0", None, None, "br0")]
INIT = "rdinit=/firmadyne/preInit.sh"


# --------------------------------------------------------------------------
# Parsing boundary: whitelist of interface names, ranges of numbers
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["eth0", "br0", "eth0.1", "brtrunk", "guest-lan1", "wlan0",
                                  "br-lan", "ra0", "apcli0", "vlan1", "wl0.1", "eth0:1",
                                  "a" * 15])
def test_real_interface_names_are_accepted(name):
    assert mn.isIfname(name)
    data = log("__inet_insert_ifa[PID: 1 (ip)]: device:%s ifa:0x0100a8c0" % name)
    assert mn.findNonLoInterfaces(data, "el") == [(name, "192.168.0.1")]


BAD_NAMES = ["br0$(touch${IFS}/tmp/x)", "br0`id`", 'br0";id;"', "br0;id", "a" * 16,
             "br0|id", "br0&", "br0>x", "$IFS", ".1", "-x", "br0'x", "br0\\x"]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_malicious_interface_names_are_skipped_with_a_warning(name, capsys):
    data = log("__inet_insert_ifa[PID: 1 (ip)]: device:%s ifa:0x0100a8c0" % name,
               "__inet_insert_ifa[PID: 1 (ip)]: device:br1 ifa:0x0101a8c0")
    assert mn.findNonLoInterfaces(data, "el") == [("br1", "192.168.1.1")]
    assert "skipped invalid interface address record" in capsys.readouterr().out
    assert not mn.isIfname(name)


def test_non_utf8_interface_name_is_skipped():
    data = b"[ 1.0] firmadyne: __inet_insert_ifa[PID: 1 (ip)]: device:br\xff0 ifa:0x0100a8c0\n"
    assert mn.findNonLoInterfaces(data, "el") == []


def test_bridge_member_names_are_validated(capsys):
    data = log("br_add_if[PID: 1 (brctl)]: br:br0 dev:eth0`touch /tmp/x`",
               'br_dev_ioctl[PID: 1 (brctl)]: br:br0 dev:eth1"; id; "',
               "br_add_if[PID: 1 (brctl)]: br:br0 dev:eth2")
    assert mn.findIfacesForBridge(data, "br0") == ["eth2"]
    assert "skipped invalid bridge member record" in capsys.readouterr().out


@pytest.mark.parametrize("brif", ["br(", "br[0", "br0+", "br.0", "*"])
def test_regex_metacharacters_in_names_are_literal(brif):
    """Used to raise re.error ("br(") or match other bridges ("br.0" ~ "brX0")."""
    data = log("br_add_if[PID: 1 (brctl)]: br:%s dev:eth0" % brif,
               "br_add_if[PID: 1 (brctl)]: br:brX0 dev:eth1",
               "register_vlan_dev[PID: 1 (vconfig)]: dev:%s vlan_id:3" % brif)
    assert mn.findIfacesForBridge(data, brif) == ["eth0"]
    assert mn.findVlanInfoForDev(data, brif) == [3]
    if brif == "br.0":
        assert mn.findIfacesForBridge(data, "br.0") == ["eth0"]


@pytest.mark.parametrize("vid", ["4095", "99999", "9" * 5000])
def test_out_of_range_vlan_ids_are_skipped(vid):
    data = log("register_vlan_dev[PID: 1 (vconfig)]: dev:eth0 vlan_id:%s" % vid,
               "register_vlan_dev[PID: 1 (vconfig)]: dev:eth0 vlan_id:4094")
    assert mn.findVlanInfoForDev(data, "eth0") == [4094]


HEX40 = "f" * 40


def test_oversized_hex_does_not_crash_the_parsers(capsys):
    """struct.pack(">I", ...) raised struct.error on > 32-bit values."""
    data = log("__inet_insert_ifa[PID: 1 (ip)]: device:br0 ifa:0x%s" % HEX40,
               "__inet_insert_ifa[PID: 1 (ip)]: device:br1 ifa:0x0101a8c0",
               "ioctl_SIOCSIFHWADDR[PID: 1 (ifconfig)]: dev:eth0 mac:0x%s 0x22334455" % HEX40,
               "ioctl_SIOCSIFHWADDR[PID: 1 (ifconfig)]: dev:eth0 mac:0x0011 0x%s" % HEX40,
               "ioctl_SIOCSIFHWADDR[PID: 1 (ifconfig)]: dev:eth1 mac:0x0011 0x22334455",
               "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x%s:80" % HEX40,
               "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:%s" % ("9" * 5000),
               "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:65536",
               "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:8080")
    assert mn.findNonLoInterfaces(data, "el") == [("br1", "192.168.1.1")]
    assert mn.findMacChanges(data, "eb") == [("eth1", "00:11:22:33:44:55")]
    assert mn.findPorts(data, "el") == [("tcp", "192.168.0.1", 8080)]
    # leading zeros are fine: the value, not the length, decides
    assert mn.findNonLoInterfaces(log("__inet_insert_ifa[PID: 1 (ip)]: device:br0 ifa:0x000000100a8c0"),
                                  "el") == [("br0", "192.168.0.1")]


def test_warnings_are_rate_limited(capsys):
    data = log(*["__inet_insert_ifa[PID: 1 (ip)]: device:x;%d ifa:0x1" % i for i in range(1000)])
    assert mn.findNonLoInterfaces(data, "el") == []
    out = capsys.readouterr().out
    assert out.count("\n") == mn.MAX_WARNINGS + 1
    assert "skipped %d more" % (1000 - mn.MAX_WARNINGS) in out


# --------------------------------------------------------------------------
# qemuCmd(): nothing unchecked reaches the template
# --------------------------------------------------------------------------

def test_valid_inputs_pass(firmae_env):
    mn.checkQemuCmdInputs(1, [("10.0.2.15", "eth0", 4094, "00:11:22:33:44:55", "br-lan")],
                          [("tcp", "0.0.0.0", 8080)], "bridgereload", "init=/firmadyne/preInit.sh")
    out = mn.qemuCmd(0, [], [], "default", "mips", "el", INIT, False)
    assert "\nNET_BRIDGE=\n" in out and "\nNET=" not in out
    assert mn.parseEmulation(out)["net_bridge"] == ""


@pytest.mark.parametrize("kw", [
    dict(network=[("192.168.0.1", "eth0", None, None, "br0$(id)")]),
    dict(network=[("192.168.0.1", "eth0`id`", None, None, "br0")]),
    dict(network=[("192.168.0.1;id", "eth0", None, None, "br0")]),
    dict(network=[("192.168.0.256", "eth0", None, None, "br0")]),
    dict(network=[("192.168.0.1", "eth0", "1;id", None, "br0")]),
    dict(network=[("192.168.0.1", "eth0", True, None, "br0")]),
    dict(network=[("192.168.0.1", "eth0", 5000, None, "br0")]),
    dict(network=[("192.168.0.1", "eth0", None, "00:11:22:33:44:55;id", "br0")]),
    dict(network=[("192.168.0.1", "eth0", None, None)]),
    dict(ports=[("tcp;id", "0.0.0.0", 80)]),
    dict(ports=[("tcp", "0.0.0.0", "80")]),
    dict(ports=[("tcp", "0.0.0.0", 70000)]),
    dict(network_type='normal"; id; "'),
    dict(qemuInitValue='rdinit=/x" -device foo "'),
    dict(qemuInitValue="init=/$(id)"),
    dict(qemuInitValue="init=/x\nNIC=user fwd"),
    dict(iid="1;id"),
])
def test_unsafe_values_are_refused(kw, firmae_env):
    args = dict(iid=1, network=GOOD_NET, ports=[], network_type="normal",
                arch="mips", endianness="el", qemuInitValue=INIT, isUserNetwork=False)
    args.update(kw)
    with pytest.raises(mn.UnsafeValue):
        mn.qemuCmd(**args)


# --------------------------------------------------------------------------
# run.sh executed with stubbed commands (tests/unit/emulation_world.py)
# --------------------------------------------------------------------------

@pytest.fixture
def run_world(repo_root, tmp_path, firmae_env, iptables_stubs):
    from emulation_world import World
    w = World(tmp_path / "w", repo_root, iptables_stubs)

    def run(emulation):
        w.install(emulation)
        p = subprocess.run([str(w.run_sh)], cwd=str(w.root), env=dict(w.env, QEMU_EXIT_AFTER="0"),
                           capture_output=True, text=True, timeout=60)
        return p, w.calls()
    return run, w.image


def malicious_log(marker):
    return log(
        "__inet_insert_ifa[PID: 1 (ip)]: device:br0$(touch${IFS}%s) ifa:0x0100a8c0" % marker,
        "__inet_insert_ifa[PID: 1 (ip)]: device:br0`touch${IFS}%s` ifa:0x0100a8c0" % marker,
        "__inet_insert_ifa[PID: 1 (ip)]: device:br0 ifa:0x0100a8c0",
        "br_add_if[PID: 1 (brctl)]: br:br0 dev:eth0`touch %s`" % marker,
        'br_add_if[PID: 1 (brctl)]: br:br0 dev:eth0";touch %s;"' % marker,
        "br_add_if[PID: 1 (brctl)]: br:br0 dev:eth0",
        "register_vlan_dev[PID: 1 (vconfig)]: dev:eth0 vlan_id:%s" % ("9" * 50),
        "ioctl_SIOCSIFHWADDR[PID: 1 (ifconfig)]: dev:eth0;touch${IFS}%s mac:0x0011 0x22334455" % marker,
        "inet_bind[PID: 1 (httpd)]: proto:SOCK_STREAM, ip:port: 0x%s:80" % HEX40,
    )


linux = pytest.mark.linux


@linux
def test_injection_from_the_serial_log_does_not_execute(run_world, tmp_path):
    run, image = run_world
    marker = tmp_path / "PWNED"
    data = malicious_log(marker)
    ports = mn.findPorts(data, "el")
    ifaces = mn.findNonLoInterfaces(data, "el")
    netlist = mn.getNetworkList(data, ifaces, mn.findMacChanges(data, "el"))
    filtered, network_type = mn.checkNetwork(netlist)
    assert filtered == [("192.168.0.1", "eth0", None, None, "br0")]
    emulation = mn.qemuCmd(1, filtered, ports, network_type, "mips", "el", INIT, False)

    p, calls = run(emulation)
    assert p.returncode == 0, p.stdout + p.stderr
    assert any(c.startswith("qemu start") for c in calls)
    assert not marker.exists()
    assert (image / "firmadyne" / "net_bridge").read_text() == "br0\n"
    assert (image / "firmadyne" / "net_interface").read_text() == "eth0\n"
    assert (image / "firmadyne" / "network_type").read_text() == "normal\n"


@linux
def test_with_the_python_checks_disabled_emulate_sh_still_refuses(run_world, tmp_path, monkeypatch):
    """Negative control of the old template (where this payload ran): with
    both write-time checks switched off the payload reaches emulation.conf,
    and the read-side whitelist of emulate.sh stops before any command."""
    run, _ = run_world
    marker = tmp_path / "PWNED"
    monkeypatch.setattr(mn, "checkQemuCmdInputs", lambda *a: None)
    monkeypatch.setattr(mn, "checkEmulation", lambda *a: None)
    emulation = mn.qemuCmd(1, [("192.168.0.1", "eth0", None, None, "br0$(touch${IFS}%s)" % marker)],
                           [], "normal", "mips", "el", INIT, False)
    assert "$(touch" in emulation
    p, calls = run(emulation)
    assert p.returncode == 1
    assert "invalid NET_BRIDGE" in p.stderr
    assert not marker.exists()
    assert calls == []                       # not even the image was attached


@linux
def test_run_sh_refuses_a_symlinked_firmadyne_directory(run_world, tmp_path):
    run, image = run_world
    host = tmp_path / "host_etc"
    host.mkdir()
    (host / "network_type").write_text("host file\n")
    (image / "firmadyne").rmdir()
    (image / "firmadyne").symlink_to(host)
    p, calls = run(mn.qemuCmd(1, GOOD_NET, [], "normal", "mips", "el", INIT, False))
    assert p.returncode != 0
    assert "is not a plain directory" in p.stdout + p.stderr
    assert (host / "network_type").read_text() == "host file\n"
    assert sorted(os.listdir(host)) == ["network_type"]
    assert "del_partition /dev/fakeloop0" in calls          # cleanup still ran
    assert not any(c.startswith("qemu start") for c in calls)


@linux
@pytest.mark.parametrize("name", ["network_type", "net_bridge", "net_interface", "debug.sh"])
def test_run_sh_refuses_symlinked_target_files(run_world, tmp_path, name):
    run, image = run_world
    host = tmp_path / "host_file"
    host.write_text("host file\n")
    (image / "firmadyne" / name).symlink_to(host)
    p, _ = run(mn.qemuCmd(1, GOOD_NET, [], "normal", "mips", "el", INIT, False))
    assert p.returncode != 0
    assert "is not a regular file" in p.stderr
    assert host.read_text() == "host file\n"


@linux
def test_run_sh_refuses_a_fifo_target(run_world):
    """`echo > fifo` would block run.sh forever (and a device node would write
    to a host device)."""
    run, image = run_world
    os.mkfifo(str(image / "firmadyne" / "debug.sh"))
    p, _ = run(mn.qemuCmd(1, GOOD_NET, [], "normal", "mips", "el", INIT, False))
    assert p.returncode != 0
    assert "is not a regular file" in p.stderr


# --------------------------------------------------------------------------
# Python side: writes into the image after the guest has run
# --------------------------------------------------------------------------

@pytest.fixture
def target(tmp_path):
    t = tmp_path / "scratch" / "1"
    (t / "image" / "firmadyne").mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    (host / "victim").write_bytes(b"host data\n")
    return t, host


def test_firmadyne_file_accepts_regular_and_missing_files(target):
    t, _ = target
    (t / "image/firmadyne/preInit.sh").write_text("#!/bin/sh\n")
    assert mn.firmadyneFile(str(t), "preInit.sh") == os.path.realpath(str(t / "image/firmadyne/preInit.sh"))
    assert mn.firmadyneFile(str(t), "nvram_files").endswith("/image/firmadyne/nvram_files")


@pytest.mark.parametrize("how", ["dir", "file", "dangling", "fifo", "directory"])
def test_firmadyne_file_refuses_redirections(target, how):
    t, host = target
    fd = t / "image" / "firmadyne"
    if how == "dir":
        fd.rmdir()
        fd.symlink_to(host)
        name = "victim"
    elif how == "file":
        (fd / "preInit.sh").symlink_to(host / "victim")
        name = "preInit.sh"
    elif how == "dangling":
        (fd / "nvram_files").symlink_to(host / "new")
        name = "nvram_files"
    elif how == "fifo":
        os.mkfifo(str(fd / "network_type"))
        name = "network_type"
    else:
        (fd / "network_type").mkdir()
        name = "network_type"
    with pytest.raises(mn.UnsafeImagePath):
        mn.firmadyneFile(str(t), name)


def test_image_file_detects_a_changed_layout(target):
    t, host = target
    (t / "image/etc").mkdir()
    (t / "image/etc/rcS").write_text("x\n")
    before = mn.imageFile(str(t / "image"), "/etc/rcS")
    (t / "image/etc/rcS").unlink()
    (t / "image/etc").rmdir()
    (host / "rcS").write_text("host\n")
    (t / "image/etc").symlink_to(host)           # absolute -> re-rooted in the image
    with pytest.raises(mn.UnsafeImagePath):
        mn.imageFile(str(t / "image"), "/etc/rcS", expected=before)


def test_open_image_file_does_not_follow_a_symlink(target):
    t, host = target
    link = t / "image/firmadyne/x"
    link.symlink_to(host / "victim")
    with pytest.raises(OSError):
        mn.openImageFile(str(link), "ab")
    assert (host / "victim").read_bytes() == b"host data\n"


@pytest.fixture
def infer(target, monkeypatch, firmae_env):
    """inferNetwork() with mount, `file`, emulation and inferDefault stubbed."""
    t, host = target
    calls = []
    monkeypatch.setattr(mn, "SCRATCHDIR", str(t.parent))
    monkeypatch.setattr(mn, "SCRIPTDIR", "/nonexistent")
    monkeypatch.setattr(mn, "mountImage", lambda d: calls.append("mount") or "/dev/loop9p1")
    monkeypatch.setattr(mn, "umountImage", lambda d, l: calls.append("umount"))
    monkeypatch.setattr(mn.subprocess, "check_output", lambda argv, **kw: b"POSIX shell script, ASCII text\n")
    guest = []                                   # actions of the "guest" during emulation

    def emulate(argv, timeout, **kw):
        if argv[0].endswith("inferDefault.py"):   # run through run_with_timeout as well
            calls.append("inferDefault")
            return 0, False
        calls.append("emulate")
        for g in guest:
            g()
        return 0, True
    monkeypatch.setattr(mn, "run_with_timeout", emulate)
    (t / "qemu.initial.serial.log").write_bytes(
        log("__inet_insert_ifa[PID: 1 (ip)]: device:eth0 ifa:0x0100a8c0"))
    (t / "image/etc").mkdir()
    return t, host, calls, guest


def test_infer_network_appends_and_keeps_the_original_bytes(infer):
    t, _, calls, _ = infer
    original = b"#!/bin/sh\necho \xff\xfe not utf-8\nmount -a\n"
    (t / "image/etc/rcS").write_bytes(original)
    qemuInit, netlist, targetFile, targetData, ports = mn.inferNetwork(1, "mips", "el", "/etc/rcS")
    assert targetData == original                # was: the non-UTF-8 line dropped
    assert targetFile[0] == "/etc/rcS"
    assert (t / "image/etc/rcS").read_bytes().startswith(original)
    assert b"/firmadyne/network.sh &" in (t / "image/etc/rcS").read_bytes()
    assert (t / "image/firmadyne/network_type").read_bytes() == b"None"
    assert netlist == [("192.168.0.1", "eth0", None, None, "eth0")]
    assert calls == ["mount", "umount", "emulate", "mount", "inferDefault", "umount"]


def test_infer_network_refuses_a_symlinked_firmadyne_and_unmounts(infer):
    t, host, calls, _ = infer
    (t / "image/etc/rcS").write_text("#!/bin/sh\n")
    (t / "image/firmadyne").rmdir()
    (t / "image/firmadyne").symlink_to(host)
    with pytest.raises(mn.UnsafeImagePath):
        mn.inferNetwork(1, "mips", "el", "/etc/rcS")
    assert os.listdir(host) == ["victim"]
    assert calls == ["mount", "umount"]


def test_infer_network_skips_an_init_that_is_not_a_regular_file(infer, capsys):
    t, _, calls, _ = infer
    os.mkfifo(str(t / "image/etc/rcS"))           # `file` would say "fifo (named pipe)"
    assert mn.inferNetwork(1, "mips", "el", "/etc/rcS") is None
    assert "skipping init /etc/rcS" in capsys.readouterr().out
    assert calls == ["mount", "umount"]


def test_guest_planted_nvram_files_symlink_is_refused(infer):
    """inferDefault.py copies into /firmadyne/nvram_files; a dangling symlink
    planted by the guest made os.path.exists() false and the copy hit the host."""
    t, host, calls, guest = infer
    (t / "image/etc/rcS").write_text("#!/bin/sh\n")
    guest.append(lambda: (t / "image/firmadyne/nvram_files").symlink_to(host / "planted"))
    with pytest.raises(mn.UnsafeImagePath):
        mn.inferNetwork(1, "mips", "el", "/etc/rcS")
    assert "inferDefault" not in calls
    assert calls[-1] == "umount"
    assert not (host / "planted").exists()


def _process(t, monkeypatch, targetFile, targetData):
    (t / "init").write_text("/etc/rcS\n")
    monkeypatch.setattr(mn, "SCRATCHDIR", str(t.parent))
    monkeypatch.setattr(mn, "mountImage", lambda d: "/dev/loop9p1")
    monkeypatch.setattr(mn, "umountImage", lambda d, l: None)
    monkeypatch.setattr(mn, "inferNetwork",
                        lambda *a: (INIT, [], targetFile, targetData, []))
    monkeypatch.setattr(mn, "checkNetwork", lambda n: ([], "None"))
    return mn.process(1, "mips", "el", False, str(t / "run.sh"))


def test_process_restores_the_init_script_byte_for_byte(target, monkeypatch):
    t, _ = target
    (t / "image/etc").mkdir()
    rcs = t / "image/etc/rcS"
    rcs.write_bytes(b"orig \xff\n/firmadyne/network.sh &\n")
    path = mn.imageFile(str(t / "image"), "/etc/rcS")
    assert _process(t, monkeypatch, ("/etc/rcS", path), b"orig \xff\n") is False
    assert rcs.read_bytes() == b"orig \xff\n"


def test_process_does_not_restore_through_a_guest_planted_symlink(target, monkeypatch, capsys):
    t, host = target
    (t / "image/etc").mkdir()
    (t / "image/etc/rcS").write_text("x\n")
    path = mn.imageFile(str(t / "image"), "/etc/rcS")
    # the guest replaces /etc by a link to a host directory while it runs
    (t / "image/etc/rcS").unlink()
    (t / "image/etc").rmdir()
    (t / "image/etc").symlink_to(host)
    os.rename(str(host / "victim"), str(host / "rcS"))
    _process(t, monkeypatch, ("/etc/rcS", path), b"orig\n")
    assert (host / "rcS").read_bytes() == b"host data\n"
    assert "not restoring /etc/rcS" in capsys.readouterr().out


def test_process_does_not_restore_through_a_symlinked_file(target, monkeypatch):
    t, host = target
    rel = "/firmadyne/preInit.sh"
    path = mn.firmadyneFile(str(t), "preInit.sh")
    (t / "image/firmadyne/preInit.sh").symlink_to(host / "victim")
    _process(t, monkeypatch, (rel, path), b"orig\n")
    assert (host / "victim").read_bytes() == b"host data\n"


# --------------------------------------------------------------------------
# Bounded, lossless reads; small edge cases
# --------------------------------------------------------------------------

def test_serial_log_read_is_bounded(tmp_path, capsys):
    f = tmp_path / "serial.log"
    f.write_bytes(b"line one\nline two\nline three is cut")
    assert mn.readLimited(str(f), limit=25) == b"line one\nline two\n"
    assert "only the first 25 are parsed" in capsys.readouterr().out
    assert mn.readLimited(str(f)) == f.read_bytes()


def test_read_with_exception_is_lossless_and_bounded(tmp_path):
    f = tmp_path / "rcS"
    f.write_bytes(b"a\n\xff\xfe\nb\n")
    assert mn.readWithException(str(f)) == b"a\n\xff\xfe\nb\n"
    assert mn.readWithException(str(tmp_path / "missing")) == b""
    with pytest.raises(mn.UnsafeImagePath):
        mn.readWithException(str(f), limit=3)


@pytest.mark.parametrize("argv,outfile", [
    (["-i", "0", "-o", "-a", "mipsel"], "/w/scratch/0/run.sh"),   # was: outfile=True
    (["-i", "7", "-q", "-o", "-a", "armel"], "/w/scratch/7/run.sh"),
])
def test_main_builds_the_output_path_for_every_iid(monkeypatch, argv, outfile):
    seen = []
    monkeypatch.setattr(mn, "getWorkDir", lambda: "/w")
    monkeypatch.setattr(mn, "process", lambda *a: seen.append(a))
    monkeypatch.setattr(sys, "argv", ["makeNetwork.py"] + argv)
    assert mn.main() is None                     # exit status unchanged (0)
    assert seen[0][4] == outfile


def test_main_without_iid_fails_clearly(monkeypatch):
    monkeypatch.setattr(mn, "getWorkDir", lambda: "/w")
    monkeypatch.setattr(sys, "argv", ["makeNetwork.py", "-o", "-a", "mipsel"])
    with pytest.raises(Exception, match="No image id"):
        mn.main()
