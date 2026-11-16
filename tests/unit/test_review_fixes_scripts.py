"""Regression tests for the independent security review of makeNetwork.py,
inferDefault.py and makeImage.sh (guest-controlled input must stay bounded and
must not inject anything)."""

import gc
import io
import os
import random
import re
import shutil
import subprocess
import sys
import warnings

import pytest

from scripts import makeNetwork as mn


def line(msg, ts="1.000000"):
    return "[%12s] firmadyne: %s" % (ts, msg)


def log(*msgs):
    return ("\n".join(line(m) for m in msgs) + "\n").encode()


INIT = "rdinit=/firmadyne/preInit.sh"
GOOD = ("192.168.0.1", "eth0", None, None, "br0")


# --------------------------------------------------------------------------
# 1. validators: "$" matched before a trailing newline
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["eth0", "br-lan", "eth0.1", "eth0:1"])
def test_isifname_rejects_a_trailing_newline(value):
    assert mn.isIfname(value)
    assert not mn.isIfname(value + "\n")
    assert not mn.isIfname(value + "\r\n")


def test_other_patterns_reject_a_trailing_newline():
    assert mn.isIpv4("10.0.0.1") and not mn.isIpv4("10.0.0.1\n")
    assert mn.MAC_RE.match("00:11:22:33:44:55")
    assert not mn.MAC_RE.match("00:11:22:33:44:55\n")
    assert mn.QEMU_INIT_RE.match("rdinit=/firmadyne/preInit.sh")
    assert not mn.QEMU_INIT_RE.match("rdinit=/firmadyne/preInit.sh\n")


@pytest.mark.parametrize("kw", [
    dict(network=[("192.168.0.1\n", "eth0", None, None, "br0")]),
    dict(network=[("192.168.0.1", "eth0\n", None, None, "br0")]),
    dict(network=[("192.168.0.1", "eth0", None, None, "br0\n")]),
    dict(network=[("192.168.0.1", "eth0", None, "00:11:22:33:44:55\n", "br0")]),
    dict(qemuInitValue=INIT + "\n"),
    dict(ports=[("tcp", "0.0.0.0\n", 80)]),
])
def test_qemucmd_refuses_values_with_a_trailing_newline(kw, firmae_env):
    args = dict(iid=1, network=[GOOD], ports=[], network_type="normal", arch="mips",
                endianness="el", qemuInitValue=INIT, isUserNetwork=False)
    args.update(kw)
    with pytest.raises(mn.UnsafeValue):
        mn.qemuCmd(**args)


def test_no_validation_pattern_in_the_module_uses_dollar():
    for name in ("IFNAME_RE", "MAC_RE", "IPV4_RE", "QEMU_INIT_RE"):
        assert getattr(mn, name).pattern.endswith(r"\Z"), name


# --------------------------------------------------------------------------
# 2. hostfwd list is bounded, port 0 is refused
# --------------------------------------------------------------------------

def test_find_ports_drops_port_zero():
    data = log("inet_bind[PID: 1 (x)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:0",
               "inet_bind[PID: 1 (x)]: proto:SOCK_STREAM, ip:port: 0x0100a8c0:8080")
    assert mn.findPorts(data, "el") == [("tcp", "192.168.0.1", 8080)]


def test_qemucmd_refuses_port_zero(firmae_env):
    with pytest.raises(mn.UnsafeValue):
        mn.qemuCmd(1, [GOOD], [("tcp", "0.0.0.0", 0)], "normal", "mips", "el", INIT, True)


def test_forward_ports_filter_dedupe_and_cap(capsys):
    ports = [("tcp", "0.0.0.0", p) for p in (80, 443, 0, 70000, 22, 22)]
    ports += [("udp", "0.0.0.0", 22)]
    ports += [("tcp", "0.0.0.0", 1000 + i) for i in range(10000)]
    res = mn.forwardPorts(ports, warn=True)
    assert res[:2] == [("tcp", 22), ("udp", 22)]
    assert len(res) == mn.MAX_FORWARD_PORTS
    assert len(set(res)) == len(res)
    assert capsys.readouterr().out.count("ports to forward") == 1


def test_user_network_hostfwd_argument_stays_small(firmae_env, capsys):
    firmae_env()
    ports = [("tcp", "0.0.0.0", 1000 + i) for i in range(50000)]
    out = mn.qemuNetworkConfig("mips", [("10.0.2.15", "eth0", None, None, "br0")], True, ports, 1)
    assert out.count("hostfwd=") == 2 + mn.MAX_FORWARD_PORTS
    assert len(out) < 4096
    assert capsys.readouterr().out.count("ports to forward") == 1


# --------------------------------------------------------------------------
# 3. number of networks
# --------------------------------------------------------------------------

def test_network_limit_matches_the_nic_count():
    assert mn.MAX_NETWORKS == 4      # interfaceNum of qemuNetworkConfig


def test_qemucmd_refuses_more_networks_than_nics(firmae_env):
    nets = [("10.0.%d.1" % i, "eth%d" % i, None, None, "br%d" % i) for i in range(5)]
    with pytest.raises(mn.UnsafeValue):
        mn.qemuCmd(1, nets, [], "normal", "mips", "el", INIT, False)


def test_interface_records_are_capped(capsys):
    data = log(*["__inet_insert_ifa[PID: 1 (ip)]: device:eth0 ifa:0x%08x" % (0x0100a8c0 + (i << 16))
                 for i in range(1, 2000)])
    assert len(mn.findNonLoInterfaces(data, "el")) == mn.MAX_INTERFACES
    assert "interfaces with an address" in capsys.readouterr().out


@pytest.fixture
def proc(tmp_path, monkeypatch, firmae_env):
    t = tmp_path / "1"
    t.mkdir()
    (t / "init").write_text("/etc/rcS\n")
    monkeypatch.setattr(mn, "SCRATCHDIR", str(tmp_path))
    monkeypatch.setattr(mn, "SCRIPTDIR", "/nonexistent")
    monkeypatch.setattr(mn.subprocess, "call", lambda *a, **k: 0)   # check_emulation.sh
    return t


def test_process_clips_networks_and_ip_files(proc, monkeypatch, capsys):
    nets = [("10.%d.0.1" % i, "eth%d" % (i % 4), None, None, "br%d" % i) for i in range(1, 3000)]
    seen = []
    monkeypatch.setattr(mn, "inferNetwork", lambda *a: (INIT, nets, None, None, []))
    monkeypatch.setattr(mn, "checkNetwork", lambda n: (n, "normal"))
    monkeypatch.setattr(mn, "qemuCmd", lambda iid, net, *a: seen.append(net) or "#!/bin/true\n")
    mn.process(1, "mips", "el", False, str(proc / "run.sh"))
    assert len(seen[0]) == mn.MAX_NETWORKS
    assert (proc / "ip_num").read_text() == "4"
    assert sorted(p.name for p in proc.glob("ip.*")) == ["ip.0", "ip.1", "ip.2", "ip.3"]
    assert "only the first 4 are used" in capsys.readouterr().out


def test_process_closes_every_file(proc, monkeypatch):
    monkeypatch.setattr(mn, "inferNetwork", lambda *a: (INIT, [GOOD], None, None, []))
    monkeypatch.setattr(mn, "checkNetwork", lambda n: (n, "normal"))
    (proc / "web").write_text("false")
    gc.collect()
    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        mn.process(1, "mips", "el", False, str(proc / "run.sh"))
        gc.collect()
    assert mn.readWebFlag(str(proc / "web")) is False
    assert mn.readWebFlag(str(proc / "missing")) is False


# --------------------------------------------------------------------------
# 6. inferDefault.py call: timeout, image is always unmounted
# --------------------------------------------------------------------------

def _infer_tree(tmp_path, monkeypatch, runner):
    t = tmp_path / "1"
    (t / "image/firmadyne").mkdir(parents=True)
    (t / "image/etc").mkdir()
    (t / "image/etc/rcS").write_text("#!/bin/sh\n")
    (t / "qemu.initial.serial.log").write_bytes(
        log("__inet_insert_ifa[PID: 1 (ip)]: device:eth0 ifa:0x0100a8c0"))
    calls = []
    monkeypatch.setattr(mn, "SCRATCHDIR", str(tmp_path))
    monkeypatch.setattr(mn, "SCRIPTDIR", "/nonexistent")
    monkeypatch.setattr(mn, "mountImage", lambda d: calls.append("mount") or "/dev/loop9p1")
    monkeypatch.setattr(mn, "umountImage", lambda d, l: calls.append("umount"))
    monkeypatch.setattr(mn.subprocess, "check_output", lambda argv, **kw: b"POSIX shell script\n")
    monkeypatch.setattr(mn, "run_with_timeout", lambda argv, timeout, **kw: runner(calls, argv, timeout))
    return calls


def test_infer_default_timeout_does_not_fail_the_stage(tmp_path, monkeypatch, capsys, firmae_env):
    def runner(calls, argv, timeout):
        if argv[0].endswith("inferDefault.py"):
            calls.append(("inferDefault", timeout))
            return -2, True                         # timed out
        calls.append("emulate")
        return 0, True
    calls = _infer_tree(tmp_path, monkeypatch, runner)
    res = mn.inferNetwork(1, "mips", "el", "/etc/rcS")
    assert res is not None and res[1] == [("192.168.0.1", "eth0", None, None, "eth0")]
    assert calls[-2:] == [("inferDefault", mn.INFER_DEFAULT_TIMEOUT), "umount"]
    assert mn.INFER_DEFAULT_TIMEOUT <= 600
    assert "inferDefault.py timed out" in capsys.readouterr().out


def test_infer_default_unmounts_when_the_runner_raises(tmp_path, monkeypatch, firmae_env):
    def runner(calls, argv, timeout):
        if argv[0].endswith("inferDefault.py"):
            raise KeyboardInterrupt
        return 0, True
    calls = _infer_tree(tmp_path, monkeypatch, runner)
    with pytest.raises(KeyboardInterrupt):
        mn.inferNetwork(1, "mips", "el", "/etc/rcS")
    assert calls == ["mount", "umount", "mount", "umount"]


# --------------------------------------------------------------------------
# 4./5. inferDefault.py
# --------------------------------------------------------------------------

@pytest.fixture
def inf(repo_root):
    sys.path.insert(0, str(repo_root / "scripts"))
    import inferDefault
    yield inferDefault
    sys.path.remove(str(repo_root / "scripts"))


def _write_log(tmp_path, keys):
    work = tmp_path / "7"
    work.mkdir(exist_ok=True)
    (work / "qemu.initial.serial.log").write_bytes(
        b"".join(b"[NVRAM] %d %s\n" % (len(k), k) for k in keys))


def test_key_list_is_deduplicated_in_order_and_bounded(inf, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(inf, "MAX_KEYS", 5)
    monkeypatch.setattr(inf, "MAX_KEY_BYTES", 8)
    keys = [b"b", b"a", b"b", b"x" * 9, b"c", b"d", b"e", b"f", b"g", b"a"]
    _write_log(tmp_path, keys)
    assert inf.GetKeyList("7", str(tmp_path)) == [b"b", b"a", b"c", b"d", b"e"]
    err = capsys.readouterr().err
    assert "longer than 8 bytes" in err and "more than 5 distinct" in err


def test_huge_key_count_is_capped(inf, tmp_path, capsys):
    _write_log(tmp_path, [b"key%d" % i for i in range(60000)])
    assert len(inf.GetKeyList("7", str(tmp_path))) == inf.MAX_KEYS


def test_overlong_declared_length_is_not_a_crash(inf, tmp_path):
    work = tmp_path / "7"
    work.mkdir()
    (work / "qemu.initial.serial.log").write_bytes(b"[NVRAM] " + b"9" * 5000 + b" abc\n")
    assert inf.GetKeyList("7", str(tmp_path)) == [b"abc"]


def _naive(keys, data):
    return sum(1 for k in keys if k in data)


def test_matcher_equals_naive_substring_count(inf):
    rnd = random.Random(7)
    for _ in range(300):
        keys = list({bytes(rnd.choice(b"ab_") for _ in range(rnd.randint(0, 6)))
                     for _ in range(rnd.randint(1, 25))})
        data = bytes(rnd.choice(b"ab_") for _ in range(rnd.randint(0, 80)))
        assert inf.count_keys(io.BytesIO(data), keys) == _naive(keys, data), (keys, data)


def test_matcher_counts_nested_and_overlapping_keys_and_chunk_borders(inf, monkeypatch):
    keys = [b"ab", b"abc", b"abcd", b"cde", b"de", b"zz"]
    data = b"..abcde.."
    assert inf.count_keys(io.BytesIO(data), keys) == 5            # zz absent
    monkeypatch.setattr(inf, "CHUNK", 3)
    assert inf.count_keys(io.BytesIO(data), keys) == 5


def test_matcher_handles_deep_and_binary_keys(inf):
    keys = [b"a" * i + b"b" for i in range(1, 257)] + [b"a" * i for i in range(1, 257)]
    keys += [b"\x00\xff[]()|?*.\\", b"(?:"]
    data = b"a" * 300 + b"b" + b"\x00\xff[]()|?*.\\"
    assert inf.count_keys(io.BytesIO(data), keys) == _naive(keys, data)


def test_matcher_is_reusable_across_files(inf):
    m = inf.KeyMatcher([b"one", b"two", b"on"])
    assert inf.count_keys(io.BytesIO(b"one"), m) == 2
    assert inf.count_keys(io.BytesIO(b"two"), m) == 1
    assert inf.count_keys(io.BytesIO(b"xx"), m) == 0


def test_scan_cost_does_not_grow_with_the_key_count(inf):
    """40000 keys over 1 MB took ~7.6 s with `key in data` per key; the matcher
    needs a fraction of a second (generous bound, not a benchmark)."""
    import time
    keys = [b"nvram_key_%d_x" % i for i in range(40000)]
    data = os.urandom(1 << 20)
    t = time.time()
    assert inf.count_keys(io.BytesIO(data), keys) == 0
    assert time.time() - t < 3


@pytest.mark.parametrize("name", ["a b", "line\nbreak", "tab\tname", "ctl\x01", "ls x"])
def test_nvram_files_skips_unsafe_names(inf, tmp_path, monkeypatch, capsys, name):
    work = tmp_path / "7"
    root = work / "image"
    (root / "firmadyne").mkdir(parents=True)
    keys = [b"k%d" % i for i in range(12)]
    _write_log(tmp_path, keys)
    data = b"\0".join(keys)
    (root / name).write_bytes(data)
    (root / "good").write_bytes(data)
    monkeypatch.setattr(inf, "file_type", lambda p: "ASCII_text")
    found = inf.GetDefaultFiles(keys, str(root))
    assert len(found) == 2
    inf.Log("7", keys, found, str(root), str(tmp_path))
    text = (work / "nvram_files").read_bytes()
    assert text == b"/good 12 ASCII_text\n"
    assert (root / "firmadyne" / "nvram_files").read_bytes() == text
    assert "unsafe name" in capsys.readouterr().err


def test_file_type_has_no_whitespace(inf, monkeypatch):
    monkeypatch.setattr(inf.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, 0, stdout=b"ELF 32-bit,\tx y\nz\n"))
    assert inf.file_type("/x") == "ELF_32-bit,_x_y_z"


# --------------------------------------------------------------------------
# 8. makeImage.sh: /bin/a may be a FIFO, a symlink or a device planted by the guest
# --------------------------------------------------------------------------

@pytest.fixture
def make_image_part(repo_root, tmp_path):
    """The /bin/a block of makeImage.sh run against a fake image tree (no root,
    no mount)."""
    src = (repo_root / "scripts/makeImage.sh").read_text()
    helper = re.search(r"image_path \(\) \{.*?\n\}\n", src, re.S).group(0)
    block = re.search(r"INJECTION_CHECKER=.*?chmod a\+x \"\$\{INJECTION_CHECKER\}\"\n", src, re.S).group(0)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy(str(repo_root / "scripts/imagepath.py"), str(scripts / "imagepath.py"))
    (scripts / "injectionChecker.sh").write_text("#!/bin/sh\necho checker\n")
    image = tmp_path / "image"
    (image / "bin").mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    (host / "victim").write_text("host data\n")
    script = tmp_path / "part.sh"
    script.write_text("set -e\nset -u\n" + helper + block)

    def run():
        return subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=20,
                              env=dict(os.environ, IMAGE_DIR=str(image), SCRIPT_DIR=str(scripts)))
    return image, host, run


def _installed(image):
    f = image / "bin" / "a"
    return (f.is_file() and not f.is_symlink() and f.read_text().endswith("echo checker\n")
            and os.access(str(f), os.X_OK))


def test_fifo_at_bin_a_does_not_block(make_image_part):
    image, _, run = make_image_part
    os.mkfifo(str(image / "bin" / "a"))
    res = run()                                   # timeout=20: the old cp blocked forever
    assert res.returncode == 0, res.stderr
    assert _installed(image)


def test_symlink_at_bin_a_is_replaced_not_followed(make_image_part):
    image, host, run = make_image_part
    os.symlink(str(host / "victim"), str(image / "bin" / "a"))
    assert run().returncode == 0
    assert (host / "victim").read_text() == "host data\n"
    assert _installed(image)


def test_symlink_to_a_fifo_at_bin_a(make_image_part):
    image, host, run = make_image_part
    os.mkfifo(str(host / "fifo"))
    os.symlink(str(host / "fifo"), str(image / "bin" / "a"))
    assert run().returncode == 0
    assert _installed(image)


def test_bin_symlinked_to_the_host_stays_inside_the_image(make_image_part):
    image, host, run = make_image_part
    (image / "bin").rmdir()
    (image / "usr").mkdir()
    (image / "usr" / "bin").mkdir()
    os.symlink("/usr/bin", str(image / "bin"))      # absolute: re-rooted at the image
    assert run().returncode == 0
    assert (image / "usr/bin/a").read_text().endswith("echo checker\n")


def test_bin_that_is_not_a_directory_is_an_error(make_image_part):
    image, _, run = make_image_part
    (image / "bin").rmdir()
    (image / "bin").write_text("not a dir")
    res = run()
    assert res.returncode != 0
    assert "not a directory" in res.stdout


def test_other_writes_of_make_image_target_a_fresh_directory(repo_root):
    """firmadyne/ is created with `mkdir` (fails if the firmware already has it),
    so cp/mknod/touch into it cannot meet a planted FIFO/symlink."""
    src = (repo_root / "scripts/makeImage.sh").read_text()
    assert re.search(r'^mkdir "\$\{IMAGE_DIR\}/firmadyne/"$', src, re.M)
    assert not re.search(r"^mkdir -p .*firmadyne", src, re.M)
