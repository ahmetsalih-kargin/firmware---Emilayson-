"""Tests for firmae/hwprofile.py (static hardware dependency profile + CLI).

Every tarball is synthetic, built in tmp_path. Nothing here needs root, QEMU
or the real firmae.hwserial (it is replaced through sys.modules).
"""

import gzip
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tarfile
import time
import types
import zlib

import pytest

try:
    import lzma
except ImportError:
    lzma = None
try:
    import resource
except ImportError:
    resource = None

from firmae import hwprofile as hp


# ---------------------------------------------------------------- helpers

def elf(payload=b"", machine=8, big_endian=True):
    """Minimal 32-bit ELF header followed by `payload` (a fake .rodata)."""
    e = ">" if big_endian else "<"
    ident = b"\x7fELF" + bytes([1, 2 if big_endian else 1, 1]) + b"\x00" * 9
    return ident + struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0) + payload


def make_tar(path, members, mode="w:gz", fmt=tarfile.GNU_FORMAT):
    """members: (name, kind, payload); kind in file/dir/sym/lnk/chr/blk
    (payload of chr/blk: (major, minor))."""
    with tarfile.open(str(path), mode, format=fmt) as tar:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
                continue
            if kind == "dir":
                info.type = tarfile.DIRTYPE
            elif kind == "sym":
                info.type, info.linkname = tarfile.SYMTYPE, payload
            elif kind == "lnk":
                info.type, info.linkname = tarfile.LNKTYPE, payload
            elif kind in ("chr", "blk"):
                info.type = tarfile.CHRTYPE if kind == "chr" else tarfile.BLKTYPE
                info.devmajor, info.devminor = payload
            tar.addfile(info)
    return str(path)


def tree(root):
    """Every path below root (files, dirs, links) with its type, for before/after."""
    out = set()
    for dirpath, dirnames, filenames in os.walk(str(root)):
        for n in dirnames + filenames:
            p = os.path.join(dirpath, n)
            out.add((os.path.relpath(p, str(root)), stat.S_IFMT(os.lstat(p).st_mode)))
    return out


def empty_static():
    return {"scanned_members": 0, "scanned_files": 0, "elf_files": 0, "bytes_scanned": 0,
            "truncated": False, "limits_hit": [], "device_paths": {}, "sys_proc_paths": {},
            "ioctl_hints": {}, "kernel_modules": [], "device_nodes": []}


def is_clean(s, limit=256):
    return isinstance(s, str) and len(s) <= limit and all(0x20 <= ord(c) < 0x7F for c in s)


def all_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from all_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from all_strings(v)


@pytest.fixture
def fake_hwserial(monkeypatch):
    """install(fn) -> firmae.hwserial with scan_serial_logs=fn; calls are recorded."""
    calls = []

    def install(fn):
        mod = types.ModuleType("firmae.hwserial")

        def scan_serial_logs(paths):
            calls.append(list(paths))
            return fn(paths)
        mod.scan_serial_logs = scan_serial_logs
        monkeypatch.setitem(sys.modules, "firmae.hwserial", mod)
        return calls
    return install


# ---------------------------------------------------------------- tables

def _sample(pattern):
    return pattern[:-1] + "0" if pattern.endswith("*") else pattern


@pytest.mark.parametrize("pattern,cls", hp.PATH_RULES)
def test_every_path_rule_row(pattern, cls):
    """Each row is reachable (not shadowed by an earlier row) and gives its class."""
    assert hp.classify_path(_sample(pattern)) == cls


@pytest.mark.parametrize("path,cls", [
    ("/dev/i2c-1", "i2c"), ("/dev/spidev0.0", "spi"), ("/dev/gpio/in", "gpio"),
    ("/sys/class/gpio/export", "gpio"), ("/dev/watchdog", "watchdog"), ("/dev/wdt", "watchdog"),
    ("/dev/leds", "led"), ("/sys/class/leds/power/brightness", "led"), ("/dev/mtdblock3", "mtd"),
    ("/dev/nvram", "nvram"), ("/dev/ttyS0", "uart"), ("/dev/ttyUSB1", "uart"), ("/dev/ttyAMA0", "uart"),
    ("/dev/tty", hp.IGNORE), ("/dev/tty1", hp.IGNORE), ("/dev/null", hp.IGNORE),
    ("/dev/pts/0", hp.IGNORE), ("/dev/brcmboard", "other"), ("/proc/meminfo", None),
    ("/sys/devices/platform", None),
])
def test_classify_path_examples(path, cls):
    assert hp.classify_path(path) == cls


MODULE_EXAMPLES = {
    "sys-watchdog.ko": "watchdog", "softdog.ko": "other", "bcm_wdt.ko": "watchdog",
    "i2c-core.ko": "i2c", "spidev.ko": "spi", "gpio-keys.ko": "gpio", "leds-gpio.ko": "led",
    "ledtrig-timer.ko": "led", "wl.ko": "wlan", "ath9k.ko": "wlan", "mac80211.ko": "wlan",
    "et.ko": "ethernet", "ctf.ko": "ethernet", "nand.ko": "mtd", "m25p80.ko": "mtd",
    "ehci-hcd.ko": "usb", "usb-storage.ko": "usb", "nf_conntrack.ko": "netfilter",
    "xt_mark.ko": "netfilter", "emf.ko": "other", "foo.ko.gz": "other",
}


@pytest.mark.parametrize("name,cls", sorted(MODULE_EXAMPLES.items()))
def test_module_classification(name, cls):
    assert hp.classify_module(name) == cls


def test_module_examples_cover_every_rule_class():
    assert {c for c, _ in hp.MODULE_RULES} | {"other"} == set(MODULE_EXAMPLES.values())
    assert set(hp.MODULE_CLASSES) == set(MODULE_EXAMPLES.values())


# per peripheral: how to put static evidence for it, and a dynamic failure
CLASS_EXAMPLES = {
    "i2c": "/dev/i2c-0", "spi": "/dev/spidev0.0", "gpio": "/dev/gpio", "watchdog": "/dev/watchdog",
    "led": "/dev/led", "mtd": "/dev/mtd0", "nvram": "/dev/nvram", "uart": "/dev/ttyS0",
    "wlan": "wl.ko", "other": "/dev/brcmboard",
}
EXPECTED_REFERENCED = {
    "i2c": "unsupported", "spi": "unsupported", "gpio": "referenced", "watchdog": "referenced",
    "led": "referenced", "mtd": "covered", "nvram": "covered", "uart": "covered",
    "wlan": "referenced", "other": "referenced",
}


def _static_for(cls):
    s = empty_static()
    ex = CLASS_EXAMPLES[cls]
    if ex.endswith(".ko"):
        s["kernel_modules"] = [{"name": ex, "class": hp.classify_module(ex)}]
    else:
        s["device_paths"] = {ex: {"count": 2, "files": ["./bin/x"]}}
    return s


def _failure_for(cls):
    ex = CLASS_EXAMPLES[cls]
    if ex.endswith(".ko"):
        return {"events": {"module_load_failed": {"count": 1, "samples": ["insmod: can't insert '%s'" % ex]}}}
    return {"devices": {ex: {"errors": 3}}}


def test_status_table_covers_every_peripheral():
    assert set(hp.PERIPHERAL_SUPPORT) == set(hp.PERIPHERALS) == set(CLASS_EXAMPLES)
    assert {k: v[0] for k, v in hp.PERIPHERAL_SUPPORT.items()} == EXPECTED_REFERENCED


@pytest.mark.parametrize("cls", hp.PERIPHERALS)
def test_status_rows(cls):
    nothing = hp.build_profile(empty_static())["peripherals"][cls]
    assert nothing == {"status": "not-referenced", "evidence": []}

    ref = hp.build_profile(_static_for(cls))["peripherals"][cls]
    assert ref["status"] == EXPECTED_REFERENCED[cls]
    assert ref["evidence"] and all(is_clean(e) for e in ref["evidence"])

    # with a log that shows no error for it: unchanged
    assert hp.build_profile(_static_for(cls), {"devices": {}, "events": {}})["peripherals"][cls]["status"] \
        == EXPECTED_REFERENCED[cls]

    # a runtime failure wins over everything, also over "covered" (and without static evidence)
    for static in (_static_for(cls), empty_static()):
        failing = hp.build_profile(static, _failure_for(cls))["peripherals"][cls]
        assert failing["status"] == "failing"


@pytest.mark.parametrize("event,cls", sorted(hp.EVENT_CLASSES.items()))
def test_class_events_mark_failing(event, cls):
    dyn = {"events": {event: {"count": 2, "samples": ["boom"]}}}
    p = hp.build_profile(_static_for(cls), dyn)
    assert p["peripherals"][cls]["status"] == "failing"
    assert any(event in e for e in p["peripherals"][cls]["evidence"])


def test_open_failed_samples_are_classified_and_general_events_become_notes():
    dyn = {"events": {
        "device_open_failed": {"count": 1, "samples": ["open /dev/i2c-0 failed: No such device"]},
        "segfault": {"count": 4, "samples": ["httpd[12]: segfault at 0"]},
        "no_such_device": {"count": 1, "samples": ["nothing to classify here"]},
    }}
    p = hp.build_profile(empty_static(), dyn)
    assert p["peripherals"]["i2c"]["status"] == "failing"
    assert any("segfault x4" in n for n in p["notes"])
    assert any("no_such_device x1" in n for n in p["notes"])


def test_generic_paths_are_counted_but_never_evidence():
    s = empty_static()
    s["device_paths"] = {p: {"count": 1, "files": ["./x"]} for p in
                         ("/dev/null", "/dev/console", "/dev/urandom", "/dev/tty", "/dev/pts/1", "/dev/shm/x")}
    p = hp.build_profile(s)
    assert all(v["status"] == "not-referenced" for v in p["peripherals"].values())
    assert len(p["static"]["device_paths"]) == 6


@pytest.mark.parametrize("dynamic", [
    {}, {"devices": "junk", "events": ["x"]}, {"devices": {"/dev/gpio": "x", 3: {}}, "events": {"gpio_error": 7}},
    {"devices": {"/dev/gpio": {"errors": -1}}, "events": {"gpio_error": {"count": "9", "samples": "s"}}},
    {"devices": {"/dev/gpio": {"errors": True}}},
])
def test_dynamic_with_missing_or_wrong_keys(dynamic):
    p = hp.build_profile(empty_static(), dynamic)
    assert p["peripherals"]["gpio"]["status"] in ("not-referenced", "referenced")
    assert set(p) == {"schema", "static", "dynamic", "peripherals", "notes"}


def test_profile_top_level_and_ioctl_note():
    p = hp.build_profile(empty_static())
    assert p["schema"] == 1 and p["dynamic"] is None
    assert hp.NOTE_IOCTL in p["notes"]
    assert set(p["peripherals"]) == set(hp.PERIPHERALS)


# ---------------------------------------------------------------- matching

def test_matches_equal_whole_content_for_every_split():
    data = (b"x" * 1000 + b" /dev/a//dev/b \x00/sys/class/gpio/gpio7/value\x00" + b"y" * 700 +
            b"/dev/gpio\x00I2C_RDWR\x00" + b"z" * 600 + b"(/dev/spidev1.0)")
    whole = list(hp.iter_matches([data]))
    assert ("path", b"/dev/a//dev/b") in whole and ("ioctl", b"I2C_RDWR") in whole
    for split in range(900, len(data), 7):
        assert list(hp.iter_matches([data[:split], data[split:]])) == whole, split
    assert list(hp.iter_matches([data[i:i + 13] for i in range(0, len(data), 13)])) == whole


def test_lookbehind_rejects_embedded_paths():
    got = [v for _, v in hp.iter_matches([b"/mnt/dev/foo x/dev/bar ;/dev/ok MYI2C_RDWR"])]
    assert got == [b"/dev/ok"]


def test_path_and_ioctl_from_elf_and_script(tmp_path):
    rodata = b"\x00/dev/gpio\x00/dev/i2c-%d\x00/sys/class/gpio/export\x00I2C_RDWR\x00WDIOC_KEEPALIVE\x00"
    script = b"#!/bin/sh\necho 1 > /dev/watchdog\ncat /proc/mtd\nmount /proc/meminfo\n"
    tar = make_tar(tmp_path / "1.tar.gz", [
        ("./usr/sbin/gpiod", "file", elf(rodata)),
        ("./etc/init.d/rcS", "file", script),
    ])
    s = hp.scan_tarball(tar)
    assert s["elf_files"] == 1 and s["scanned_files"] == 2 and s["truncated"] is False
    assert s["device_paths"]["/dev/gpio"] == {"count": 1, "files": ["./usr/sbin/gpiod"]}
    assert "/dev/i2c-" in s["device_paths"]
    assert s["device_paths"]["/dev/watchdog"]["files"] == ["./etc/init.d/rcS"]
    assert set(s["sys_proc_paths"]) == {"/sys/class/gpio/export", "/proc/mtd"}   # /proc/meminfo ignored
    assert set(s["ioctl_hints"]) == {"I2C_RDWR", "WDIOC_KEEPALIVE"}
    p = hp.build_profile(s)["peripherals"]
    assert p["gpio"]["status"] == "referenced" and p["i2c"]["status"] == "unsupported"
    assert p["mtd"]["status"] == "covered" and p["spi"]["status"] == "not-referenced"


def test_string_across_block_boundary(tmp_path):
    data = b"\x00" * (hp.CHUNK - 5) + b"/dev/spidev0.0\x00" + b"\x01" * 100
    tar = make_tar(tmp_path / "1.tar.gz", [("./bin/spi", "file", data)])
    s = hp.scan_tarball(tar)
    assert list(s["device_paths"]) == ["/dev/spidev0.0"]
    assert s["bytes_scanned"] == len(data)


def test_count_is_per_file_and_samples_are_bounded(tmp_path):
    members = [("./bin/f%d" % i, "file", b"/dev/gpio /dev/gpio /dev/gpio") for i in range(7)]
    s = hp.scan_tarball(make_tar(tmp_path / "1.tar.gz", members))
    assert s["device_paths"]["/dev/gpio"]["count"] == 7
    assert s["device_paths"]["/dev/gpio"]["files"] == ["./bin/f%d" % i for i in range(5)]


# ---------------------------------------------------------------- members

def test_kernel_modules(tmp_path):
    names = ["sys-watchdog.ko", "i2c-core.ko", "spidev.ko", "wl.ko", "nf_conntrack.ko", "et.ko", "foo.ko"]
    members = [("./lib/modules/2.6.36/%s" % n, "file", b"\x7fELF") for n in names]
    members.append(("./lib/modules/link.ko", "sym", "foo.ko"))         # symlink: not a module file
    s = hp.scan_tarball(make_tar(tmp_path / "1.tar.gz", members))
    assert s["kernel_modules"] == sorted(({"name": n, "class": hp.classify_module(n)} for n in names),
                                         key=lambda m: m["name"])
    p = hp.build_profile(s)["peripherals"]
    assert p["watchdog"]["status"] == "referenced" and p["wlan"]["status"] == "referenced"
    assert p["spi"]["status"] == "unsupported"


def test_device_nodes(tmp_path):
    tar = make_tar(tmp_path / "1.tar.gz", [
        ("./dev", "dir", None),
        ("./dev/mtd0", "chr", (90, 0)),
        ("./dev/mtdblock0", "blk", (31, 0)),
        ("dev/i2c-0", "chr", (89, 0)),
    ])
    s = hp.scan_tarball(tar)
    assert s["device_nodes"] == [
        {"path": "/dev/i2c-0", "type": "c", "major": 89, "minor": 0},
        {"path": "/dev/mtd0", "type": "c", "major": 90, "minor": 0},
        {"path": "/dev/mtdblock0", "type": "b", "major": 31, "minor": 0},
    ]
    assert s["scanned_files"] == 0
    p = hp.build_profile(s)["peripherals"]
    assert p["i2c"]["status"] == "unsupported" and p["mtd"]["status"] == "covered"


def test_symlinks_and_hardlinks_are_never_read(tmp_path, monkeypatch):
    secret = tmp_path / "host_secret"
    secret.write_bytes(b"/dev/i2c-7")
    tar = make_tar(tmp_path / "1.tar.gz", [
        ("./bin/real", "file", b"/dev/gpio"),
        ("./bin/hard", "lnk", "./bin/real"),
        ("./bin/soft", "sym", str(secret)),
        ("./bin/up", "sym", "../../../../../../" + str(secret)),
    ])
    read = []
    orig = tarfile.TarFile.extractfile

    def spy(self, member):
        read.append(member.name)
        return orig(self, member)
    monkeypatch.setattr(tarfile.TarFile, "extractfile", spy)
    s = hp.scan_tarball(tar)
    assert read == ["./bin/real"]
    assert s["device_paths"] == {"/dev/gpio": {"count": 1, "files": ["./bin/real"]}}
    assert s["scanned_members"] == 4 and s["scanned_files"] == 1


def test_traversal_and_absolute_names_write_nothing(tmp_path, monkeypatch):
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(str(work))
    escape = tmp_path / "escaped"
    tar = make_tar(tmp_path / "1.tar.gz", [
        ("../../../../../../../../.." + str(escape) + "/evil", "file", b"/dev/gpio"),
        (str(escape) + "/abs", "file", b"/dev/gpio"),
        ("/etc/cron.d/evil", "file", b"/dev/watchdog"),
        ("../x", "sym", "/etc/passwd"),
        ("./dev/../../nodes", "chr", (1, 3)),
    ])
    before_tmp, before_cwd = tree(tmp_path), tree(work)
    s = hp.scan_tarball(tar)
    assert tree(tmp_path) == before_tmp and tree(work) == before_cwd == set()
    assert not escape.exists()
    assert s["device_paths"]["/dev/gpio"]["count"] == 2
    assert s["device_nodes"][0]["path"] == "/dev/../../nodes"          # a label only


def test_control_characters_and_long_names_are_sanitized(tmp_path):
    long_name = "./bin/" + "A" * 5000
    evil = "./bin/x\x1b[31m\n\r\x07\udcff\N{LATIN SMALL LETTER U WITH DIAERESIS}.ko"
    tar = make_tar(tmp_path / "1.tar.gz", [
        (long_name, "file", b"/dev/gpio"),
        (evil, "file", b"/dev/gpio /dev/" + b"q" * 1000),
    ], fmt=tarfile.PAX_FORMAT)
    s = hp.scan_tarball(tar)
    files = s["device_paths"]["/dev/gpio"]["files"]
    assert len(files) == 2 and all(is_clean(f) for f in files)
    assert files[0].endswith("...") and len(files[0]) == 256
    assert files[1].startswith("./bin/x?[31m???")
    assert all(is_clean(k) for k in s["device_paths"])
    assert s["kernel_modules"] and is_clean(s["kernel_modules"][0]["name"])
    text = hp._dumps(hp.build_profile(s))
    assert all(is_clean(x, 10 ** 6) for x in all_strings(json.loads(text)))
    assert all(0x20 <= b < 0x7F or b == 0x0A for b in text.encode("ascii"))


def test_sanitize():
    assert hp.sanitize("a\x00b\x7f\N{LATIN SMALL LETTER DOTLESS I}") == "a?b???"
    assert hp.sanitize(b"\xff\x1bok") == "??ok"
    assert len(hp.sanitize("x" * 10000)) == 256
    assert hp.sanitize("short", 3) == "..."


# ---------------------------------------------------------------- limits

def _many_files(tmp_path, n, payload=b"/dev/gpio"):
    return make_tar(tmp_path / "1.tar.gz", [("./f%d" % i, "file", payload) for i in range(n)])


def test_limit_members(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "MAX_MEMBERS", 3)
    s = hp.scan_tarball(_many_files(tmp_path, 10))
    assert s["scanned_members"] == 3 and s["truncated"] and s["limits_hit"] == ["members"]


def test_limit_file_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "MAX_FILE_BYTES", 10)
    tar = make_tar(tmp_path / "1.tar.gz", [("./big", "file", b"x" * 20 + b"/dev/gpio"),
                                           ("./small", "file", b"/dev/wdt")])
    s = hp.scan_tarball(tar)
    assert "/dev/gpio" not in s["device_paths"] and "/dev/wdt" in s["device_paths"]
    assert s["limits_hit"] == ["file_bytes"] and s["truncated"]
    assert s["bytes_scanned"] == 10 + 8


def test_limit_total_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "MAX_TOTAL_BYTES", 100)
    tar = make_tar(tmp_path / "1.tar.gz", [("./a", "file", b"x" * 80),
                                           ("./b", "file", b"y" * 50 + b"/dev/gpio" + b"y" * 21),
                                           ("./c", "file", b"/dev/wdt"),
                                           ("./lib/m.ko", "file", b"z")])
    s = hp.scan_tarball(tar)
    assert s["bytes_scanned"] == 100 and s["device_paths"] == {}
    assert s["limits_hit"] == ["total_bytes"] and s["scanned_members"] == 4
    assert s["kernel_modules"] == [{"name": "m.ko", "class": "other"}]     # headers still listed


def test_limit_stream_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "MAX_STREAM_BYTES", 20000)
    tar = make_tar(tmp_path / "1.tar.gz", [("./a", "file", b"/dev/gpio"),
                                           ("./bomb", "file", b"\x00" * 100000),
                                           ("./c", "file", b"/dev/wdt")])
    s = hp.scan_tarball(tar)
    assert "stream_bytes" in s["limits_hit"] and s["truncated"]
    assert "/dev/gpio" in s["device_paths"] and "/dev/wdt" not in s["device_paths"]


def test_limit_header_size(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "MAX_HEADER_READ", 1024)
    tar = make_tar(tmp_path / "1.tar.gz", [("./ok", "file", b"/dev/gpio"),
                                           ("./" + "n" * 3000, "file", b"/dev/wdt")])
    s = hp.scan_tarball(tar)
    assert s["limits_hit"] == ["header_size"] and s["scanned_members"] == 1
    assert list(s["device_paths"]) == ["/dev/gpio"]


def test_limit_time(tmp_path):
    tar = _many_files(tmp_path, 5)
    s = hp.scan_tarball(tar, deadline=time.monotonic() - 1)
    assert s["truncated"] and s["limits_hit"] == ["time"] and s["scanned_members"] == 0


def test_limit_time_mid_scan(tmp_path, monkeypatch):
    tar = _many_files(tmp_path, 50)
    clock = {"t": 0.0}

    def fake_monotonic():
        clock["t"] += 1.0
        return clock["t"]
    monkeypatch.setattr(hp, "time", types.SimpleNamespace(monotonic=fake_monotonic))
    s = hp.scan_tarball(tar, deadline=40.0)
    assert s["limits_hit"] == ["time"] and 0 < s["scanned_members"] < 50
    assert s["device_paths"]["/dev/gpio"]["count"] >= 1


@pytest.mark.parametrize("table,key", [("device_paths", "keys:device_paths"),
                                       ("sys_proc_paths", "keys:sys_proc_paths")])
def test_limit_keys(tmp_path, monkeypatch, table, key):
    monkeypatch.setattr(hp, "MAX_KEYS", 2)
    prefix = b"/dev/v" if table == "device_paths" else b"/sys/v"
    payload = b" ".join(prefix + b"%d" % i for i in range(5))
    s = hp.scan_tarball(make_tar(tmp_path / "1.tar.gz", [("./a", "file", payload), ("./b", "file", payload)]))
    assert len(s[table]) == 2 and all(e["count"] == 2 for e in s[table].values())
    assert s["limits_hit"] == [key] and s["truncated"]


def test_limit_keys_modules_nodes_ioctls(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "MAX_KEYS", 1)
    tar = make_tar(tmp_path / "1.tar.gz", [
        ("./a.ko", "file", b"I2C_RDWR I2C_SLAVE"), ("./b.ko", "file", b"x"),
        ("./dev/x", "chr", (1, 1)), ("./dev/y", "chr", (1, 2)),
    ])
    s = hp.scan_tarball(tar)
    assert len(s["kernel_modules"]) == len(s["device_nodes"]) == len(s["ioctl_hints"]) == 1
    assert s["limits_hit"] == ["keys:device_nodes", "keys:ioctl_hints", "keys:kernel_modules"]


def test_truncated_stream_gives_partial_result(tmp_path):
    members = [("./f%03d" % i, "file", os.urandom(2000) + b"/dev/gpio") for i in range(60)]
    tar = make_tar(tmp_path / "1.tar.gz", members)
    data = open(tar, "rb").read()
    cut = tmp_path / "cut.tar.gz"
    cut.write_bytes(data[:len(data) // 2])
    s = hp.scan_tarball(str(cut))
    assert s["limits_hit"] == ["read_error"] and s["truncated"]
    assert 0 < s["device_paths"]["/dev/gpio"]["count"] < 60


@pytest.mark.parametrize("content", [b"", b"not a tarball at all" * 50,
                                     b"\x1f\x8b\x08\x00garbage-garbage-garbage" * 20,
                                     gzip.compress(b"plain text, not a tar archive\n" * 100)])
def test_unreadable_tarball_raises(tmp_path, content):
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(content)
    with pytest.raises(hp.TarballError):
        hp.scan_tarball(str(bad))


def test_plain_and_other_compressions(tmp_path):
    for mode, name in (("w", "1.tar"), ("w:bz2", "1.tar.bz2"), ("w:xz", "1.tar.xz")):
        tar = make_tar(tmp_path / name, [("./a", "file", b"/dev/gpio")], mode=mode)
        assert "/dev/gpio" in hp.scan_tarball(tar)["device_paths"], name


def test_member_size_multiple_of_512(tmp_path):
    """tarfile seeks back one byte after such a member (reader's history window)."""
    tar = make_tar(tmp_path / "1.tar.gz", [("./a", "file", b"/dev/gpio".ljust(1024, b"\x00")),
                                           ("./b", "file", b"/dev/wdt".ljust(512, b"\x00")),
                                           ("./c", "file", b"/dev/led")])
    s = hp.scan_tarball(tar)
    assert set(s["device_paths"]) == {"/dev/gpio", "/dev/wdt", "/dev/led"} and not s["truncated"]


@pytest.mark.parametrize("data", [
    b"a" * (1 << 20), b"/" * (1 << 20), b"/dev/" * (1 << 18), b"/dev/" + b"a" * (1 << 20),
    b"/dev/a" * (1 << 18), b"I2C_" * (1 << 18), b"GPIO" + b"A" * (1 << 20), b"MEM" * (1 << 19),
    b"/sys/" + b"/" * (1 << 20),
])
def test_regex_is_linear_on_hostile_input(data):
    t = time.monotonic()
    for _ in hp.iter_matches([data[i:i + hp.CHUNK] for i in range(0, len(data), hp.CHUNK)]):
        pass
    assert time.monotonic() - t < 2.0


def test_hostile_file_scan_time(tmp_path):
    tar = make_tar(tmp_path / "1.tar.gz", [("./a", "file", b"/dev/" * (1 << 18)),
                                           ("./b", "file", b"/dev/" + b"x" * (1 << 20))])
    t = time.monotonic()
    s = hp.scan_tarball(tar)
    assert time.monotonic() - t < 2.0
    assert all(len(k) <= 256 for k in s["device_paths"])


# ---------------------------------------------------------------- output + CLI

def _tar(tmp_path):
    return make_tar(tmp_path / "7.tar.gz", [
        ("./sbin/gpio", "file", elf(b"\x00/dev/gpio\x00/dev/nvram\x00")),
        ("./etc/inittab", "file", b"ttyS0::respawn:/bin/sh\n/dev/ttyS0\n"),
        ("./dev/mtd0", "chr", (90, 0)),
    ])


def test_cli_static_only(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(sys.modules, "firmae.hwserial", None)     # must not even be imported
    out = tmp_path / "hw.json"
    assert hp.main(["--tar", _tar(tmp_path), "--out", str(out)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1 and lines[0].startswith("hwprofile: ") and "gpio=referenced" in lines[0]
    prof = json.loads(out.read_text())
    assert set(prof) == {"schema", "static", "dynamic", "peripherals", "notes"}
    assert prof["dynamic"] is None
    per = prof["peripherals"]
    assert (per["gpio"]["status"], per["nvram"]["status"], per["mtd"]["status"], per["uart"]["status"],
            per["i2c"]["status"]) == ("referenced", "covered", "covered", "covered", "not-referenced")
    assert stat.S_IMODE(os.stat(str(out)).st_mode) & 0o137 == 0
    assert [p for p in os.listdir(str(tmp_path)) if ".tmp-" in p] == []


def test_json_is_valid_and_deterministic(tmp_path):
    tar = _tar(tmp_path)
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert hp.main(["--tar", tar, "--out", str(a)]) == 0
    assert hp.main(["--tar", tar, "--out", str(b)]) == 0
    text = a.read_text()
    assert text == b.read_text()
    assert json.dumps(json.loads(text), sort_keys=True, indent=2) + "\n" == text


def test_cli_with_fake_hwserial(tmp_path, fake_hwserial):
    calls = fake_hwserial(lambda paths: {"devices": {"/dev/gpio": {"errors": 2}},
                                         "events": {"kernel_panic": {"count": 1, "samples": ["\x1bpanic"]}}})
    out = tmp_path / "hw.json"
    log = tmp_path / "qemu.final.serial.log"
    log.write_text("x")
    assert hp.main(["--tar", _tar(tmp_path), "--out", str(out), "--serial-log", str(log)]) == 0
    assert calls == [[str(log)]]
    prof = json.loads(out.read_text())
    assert prof["peripherals"]["gpio"]["status"] == "failing"
    assert any("kernel_panic x1: ?panic" in n for n in prof["notes"])


def test_cli_hwserial_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "firmae.hwserial", None)
    out = tmp_path / "hw.json"
    assert hp.main(["--tar", _tar(tmp_path), "--out", str(out), "--serial-log", str(tmp_path / "l")]) == 0
    prof = json.loads(out.read_text())
    assert prof["dynamic"] is None and any("hwserial unavailable" in n for n in prof["notes"])
    assert len(capsys.readouterr().out.splitlines()) == 1


@pytest.mark.parametrize("behaviour", ["raise", "not-a-dict"])
def test_cli_hwserial_broken(tmp_path, fake_hwserial, behaviour):
    def fn(paths):
        if behaviour == "raise":
            raise RuntimeError("bad log")
        return ["nope"]
    fake_hwserial(fn)
    out = tmp_path / "hw.json"
    assert hp.main(["--tar", _tar(tmp_path), "--out", str(out), "--serial-log", "l"]) == 0
    prof = json.loads(out.read_text())
    assert prof["dynamic"] is None and any("dynamic section empty" in n for n in prof["notes"])


def test_cli_update_keeps_static(tmp_path, fake_hwserial):
    out = tmp_path / "hw.json"
    assert hp.main(["--tar", _tar(tmp_path), "--out", str(out)]) == 0
    first = json.loads(out.read_text())
    fake_hwserial(lambda paths: {"devices": {"/dev/mtd0": {"errors": 1}},
                                 "events": {"gpio_error": {"count": 3, "samples": ["gpio fail"]}}})
    assert hp.main(["--update", "--out", str(out), "--serial-log", "a.log", "--serial-log", "b.log"]) == 0
    second = json.loads(out.read_text())
    assert second["static"] == first["static"]
    assert second["dynamic"]["devices"] == {"/dev/mtd0": {"errors": 1}}
    assert second["peripherals"]["gpio"]["status"] == "failing"
    assert second["peripherals"]["mtd"]["status"] == "failing"
    assert second["peripherals"]["nvram"]["status"] == "covered"
    assert any("--update" in n for n in second["notes"])


@pytest.mark.parametrize("content", [None, "not json", '{"schema": 1}', "[]"])
def test_cli_update_without_usable_profile(tmp_path, fake_hwserial, content):
    fake_hwserial(lambda paths: {})
    out = tmp_path / "hw.json"
    if content is not None:
        out.write_text(content)
    assert hp.main(["--update", "--out", str(out), "--serial-log", "a.log"]) == 1


@pytest.mark.parametrize("argv", [
    [], ["--out", "x.json"], ["--tar", "a.tar.gz"], ["--update", "--out", "x.json"],
    ["--update", "--tar", "a", "--out", "x", "--serial-log", "l"],
    ["--tar", "a", "--out", "x", "--timeout", "0"], ["--tar", "a", "--out", "x", "--timeout", "nan"],
    ["--tar", "a", "--out", "x", "--bogus"], ["--tar", "a", "--out", "x", "--mem-limit-mb", "-1"],
    ["--tar", "a", "--out", "x", "--mem-limit-mb", "lots"],
])
def test_cli_usage_errors(argv, capsys):
    assert hp.main(argv) == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("content", [b"", b"\x1f\x8b\x08\x00broken" * 30, b"junk" * 100])
def test_cli_corrupt_tarball_exit_1(tmp_path, capsys, content):
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(content)
    out = tmp_path / "hw.json"
    assert hp.main(["--tar", str(bad), "--out", str(out)]) == 1
    captured = capsys.readouterr()
    assert "error" in captured.err and captured.out == ""
    assert not out.exists()


def test_cli_missing_tarball_exit_1(tmp_path):
    assert hp.main(["--tar", str(tmp_path / "none.tar.gz"), "--out", str(tmp_path / "o.json")]) == 1


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="POSIX symlinks")
def test_output_symlink_is_refused(tmp_path, capsys):
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    out = tmp_path / "hw.json"
    os.symlink(str(victim), str(out))
    assert hp.main(["--tar", _tar(tmp_path), "--out", str(out)]) == 1
    assert "symlink" in capsys.readouterr().err
    assert victim.read_text() == "keep me" and os.path.islink(str(out))
    with pytest.raises(hp.HwProfileError):
        hp.write_profile(str(out), {"schema": 1})
    # --update does not read through it either
    assert hp.main(["--update", "--out", str(out), "--serial-log", "l"]) == 1


def test_output_not_regular_and_unwritable(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    with pytest.raises(hp.HwProfileError):
        hp.write_profile(str(d), {"schema": 1})
    with pytest.raises(hp.HwProfileError):
        hp.write_profile(str(tmp_path / "missing" / "x.json"), {"schema": 1})


def test_write_profile_replaces_existing_file(tmp_path):
    out = tmp_path / "hw.json"
    out.write_text("old")
    hp.write_profile(str(out), {"b": 1, "a": [1, 2]})
    assert out.read_text() == '{\n  "a": [\n    1,\n    2\n  ],\n  "b": 1\n}\n'


# ---------------------------------------------------------------- hostile headers
# Raw tar blocks built by hand: tarfile cannot write these shapes itself.

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _hdr(name, size, typ=tarfile.REGTYPE):
    t = tarfile.TarInfo(name)
    t.size, t.type = size, typ
    return t.tobuf(format=tarfile.GNU_FORMAT)      # GNU: base-256 sizes beyond 8 GiB


def _pad(data):
    return data + b"\0" * (-len(data) % 512)


def _pax(records, typ=tarfile.XHDTYPE):
    out = b""
    for k, v in records:
        body = b" %s=%s\n" % (k, v)
        n = len(body) + 1
        while len(str(n)) + len(body) != n:
            n += 1
        out += str(n).encode() + body
    return _hdr("././@PaxHeader", len(out), typ) + _pad(out)


def _file(name, payload):
    return _hdr(name, len(payload)) + _pad(payload)


END = b"\0" * 1024

SPARSE10 = [(b"GNU.sparse.major", b"1"), (b"GNU.sparse.minor", b"0"), (b"GNU.sparse.name", b"sp"),
            (b"GNU.sparse.realsize", b"10")]


def _write_gz(path, parts):
    with gzip.open(str(path), "wb", compresslevel=1) as z:
        for p in parts:
            z.write(p)
    return str(path)


def _sparse10_bomb(path, map_mib):
    """pax GNU.sparse 1.0 member whose map claims 4e9 entries; map_mib MiB of
    "999\\n" follow (tarfile reads them 512 bytes at a time into a list)."""
    chunk = b"999\n" * (1 << 18)                 # 1 MiB
    return _write_gz(path, [_pax(SPARSE10), _hdr("GNUSparseFile.0/sp", 1 << 40), b"4000000000\n"]
                     + [chunk] * map_mib)


def _chksum(buf):
    buf[148:156] = b" " * 8
    buf[148:156] = b"%06o\0 " % sum(buf)
    return bytes(buf)


def _old_sparse(name, ext_blocks):
    """GNU 'S' sparse header followed by `ext_blocks` extension blocks full of
    (offset, size) pairs; all but the last say "more follow". With 0 blocks
    the header itself says "more follow" and the data simply ends."""
    t = tarfile.TarInfo(name)
    t.size = 0
    buf = bytearray(t.tobuf(format=tarfile.GNU_FORMAT))
    buf[156:157] = tarfile.GNUTYPE_SPARSE
    buf[386:410] = b"%011o\0%011o\0" % (0, 1)
    buf[482] = 1                                    # isextended
    buf[483:495] = b"%011o\0" % 1                   # real size
    head = _chksum(buf)
    ext = bytearray(512)
    for i in range(21):
        ext[i * 24:i * 24 + 24] = b"%011o\0%011o\0" % (i + 1, 1)
    last = bytes(ext)
    ext[504] = 1
    if not ext_blocks:
        return head
    return head + bytes(ext) * (ext_blocks - 1) + last


def test_sparse10_map_is_bounded(tmp_path):
    tar = _sparse10_bomb(tmp_path / "sp.tar.gz", 4)
    t = time.monotonic()
    s = hp.scan_tarball(tar)
    assert time.monotonic() - t < 5
    assert s["limits_hit"] == ["header_size"] and s["truncated"] and s["scanned_members"] == 0


def test_sparse10_small_member_is_listed_not_scanned(tmp_path):
    sparse = (_pax(SPARSE10) + _hdr("GNUSparseFile.0/sp", 1024) + _pad(b"1\n0\n10\n")
              + _pad(b"/dev/i2c-0"))
    tar = _write_gz(tmp_path / "sp.tar.gz", [sparse, _file("./b", b"/dev/gpio"), END])
    s = hp.scan_tarball(tar)
    assert s["scanned_members"] == 2 and s["limits_hit"] == ["sparse_member"]
    assert list(s["device_paths"]) == ["/dev/gpio"]


def test_old_gnu_sparse_extension_blocks_are_bounded(tmp_path):
    tar = _write_gz(tmp_path / "s.tar.gz", [_file("./a", b"/dev/gpio"), _old_sparse("s", 4096)])
    s = hp.scan_tarball(tar)
    assert s["limits_hit"] == ["header_size"] and s["scanned_members"] == 1
    assert "/dev/gpio" in s["device_paths"]


def test_old_gnu_sparse_small_and_truncated(tmp_path):
    ok = _write_gz(tmp_path / "s.tar.gz", [_old_sparse("s", 2), _file("./b", b"/dev/wdt"), END])
    s = hp.scan_tarball(ok)
    assert s["scanned_members"] == 2 and s["limits_hit"] == ["sparse_member"]
    assert list(s["device_paths"]) == ["/dev/wdt"]
    # extension flagged but the archive ends: tarfile raises IndexError -> clean TarballError
    cut = _write_gz(tmp_path / "c.tar.gz", [_old_sparse("s", 0)])
    with pytest.raises(hp.TarballError):
        hp.scan_tarball(cut)
    assert hp.main(["--tar", cut, "--out", str(tmp_path / "o.json")]) == 1


def test_global_pax_headers_are_bounded(tmp_path):
    parts = [_file("./a", b"/dev/gpio")]
    for j in range(20):
        parts.append(_pax([(b"k%d_%d" % (j, i), b"v") for i in range(100)], tarfile.XGLTYPE))
        parts.append(_file("./f%d" % j, b"x"))
    tar = _write_gz(tmp_path / "g.tar.gz", parts + [END])
    s = hp.scan_tarball(tar)
    assert s["limits_hit"] == ["pax_headers"] and 1 < s["scanned_members"] < 21


def test_pax_chain_gives_partial_result_not_traceback(tmp_path, capsys):
    tar = _write_gz(tmp_path / "pc.tar.gz", [_file("./a", b"/dev/gpio")]
                    + [_pax([(b"comment", b"x")])] * 3000 + [_file("./b", b"x"), END])
    s = hp.scan_tarball(tar)
    assert s["truncated"] and set(s["limits_hit"]) <= {"header_nesting", "header_size"}
    assert s["scanned_members"] == 1 and "/dev/gpio" in s["device_paths"]
    out = tmp_path / "pc.json"
    assert hp.main(["--tar", tar, "--out", str(out)]) == 0
    assert "Traceback" not in capsys.readouterr().err
    assert json.loads(out.read_text())["static"]["truncated"] is True


@pytest.mark.parametrize("exc,reason", [(RecursionError, "header_nesting"), (MemoryError, "memory")])
def test_recursion_and_memory_errors_give_partial_result(tmp_path, monkeypatch, exc, reason):
    tar = _many_files(tmp_path, 5)
    orig = tarfile.TarFile.next
    state = {"n": 0}

    def flaky(self):
        state["n"] += 1
        if state["n"] > 3:
            raise exc()
        return orig(self)
    monkeypatch.setattr(tarfile.TarFile, "next", flaky)
    s = hp.scan_tarball(tar)
    assert s["limits_hit"] == [reason] and s["scanned_members"] >= 1
    # also before the first member: still a (empty) partial result, not an error
    state["n"] = 10
    s = hp.scan_tarball(tar)
    assert s["limits_hit"] == [reason]


def _xz_with_dict_byte(tar_bytes, dict_byte):
    """xz stream whose LZMA2 block header claims dictionary size `dict_byte`
    (39 -> 3 GiB); the CRC of the block header is fixed up."""
    c = lzma.LZMACompressor(format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE,
                            filters=[{"id": lzma.FILTER_LZMA2, "preset": 0, "dict_size": 1 << 20}])
    d = bytearray(c.compress(tar_bytes) + c.flush())
    size = (d[12] + 1) * 4
    head = d[12:12 + size]
    i = head.index(b"\x21\x01", 2)
    head[i + 2] = dict_byte
    head[-4:] = struct.pack("<I", zlib.crc32(bytes(head[:-4])))
    d[12:12 + size] = head
    return bytes(d)


@pytest.mark.skipif(lzma is None, reason="no lzma")
def test_xz_dictionary_beyond_memlimit_stops(tmp_path):
    body = _file("./a", b"/dev/gpio") + END
    ok = tmp_path / "ok.tar.xz"
    ok.write_bytes(_xz_with_dict_byte(body, 20))            # 4 MiB: fine
    assert "/dev/gpio" in hp.scan_tarball(str(ok))["device_paths"]
    bad = tmp_path / "bad.tar.xz"
    bad.write_bytes(_xz_with_dict_byte(body, 39))           # 3 GiB
    s = hp.scan_tarball(str(bad))
    assert s["limits_hit"] == ["xz_memory"] and s["scanned_members"] == 0


@pytest.mark.skipif(lzma is None, reason="no lzma")
def test_xz_multi_stream_and_padding(tmp_path):
    a = lzma.compress(_file("./a", b"/dev/gpio"))
    b = lzma.compress(_file("./b", b"/dev/wdt") + END)
    p = tmp_path / "m.tar.xz"
    p.write_bytes(a + b + b"\0" * 16)
    s = hp.scan_tarball(str(p))
    assert set(s["device_paths"]) == {"/dev/gpio", "/dev/wdt"} and not s["truncated"]


# ---------------------------------------------------------------- CLI memory limit (subprocess)

def _cli(args, code=None, timeout=60):
    env = dict(os.environ, PYTHONPATH=REPO)
    argv = [sys.executable, "-m", "firmae.hwprofile"] + args if code is None else \
        [sys.executable, "-c", code] + args
    return subprocess.run(argv, cwd=REPO, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout)


needs_rlimit = pytest.mark.skipif(resource is None or not sys.platform.startswith("linux"),
                                  reason="RLIMIT_AS (Linux)")


@needs_rlimit
def test_cli_sparse10_bomb_under_small_rlimit(tmp_path):
    tar = _sparse10_bomb(tmp_path / "sp.tar.gz", 64)
    out = tmp_path / "sp.json"
    r = _cli(["--tar", tar, "--out", str(out), "--mem-limit-mb", "300"])
    assert r.returncode == 0, r.stderr
    assert b"Traceback" not in r.stderr
    assert json.loads(out.read_text())["static"]["limits_hit"] == ["header_size"]


@needs_rlimit
@pytest.mark.skipif(lzma is None, reason="no lzma")
def test_cli_xz_bomb_under_small_rlimit(tmp_path):
    bad = tmp_path / "bad.tar.xz"
    bad.write_bytes(_xz_with_dict_byte(_file("./a", b"/dev/gpio") + END, 39))
    out = tmp_path / "x.json"
    r = _cli(["--tar", str(bad), "--out", str(out), "--mem-limit-mb", "300"])
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text())["static"]["limits_hit"] == ["xz_memory"]


@needs_rlimit
def test_cli_rlimit_catches_what_the_bounds_miss(tmp_path):
    """Second layer alone: with the header bound switched off, the sparse map
    grows until the memory guard (75% of RLIMIT_AS) stops the scan; the CLI
    writes a partial profile ("memory"), exit 0, in a few seconds.
    (This used to run into the hard limit itself; there CPython sometimes spun
    for minutes re-raising the MemoryError inside tarfile.)"""
    # 48 MiB of map need ~450 MB as Python objects, far above the 200 MiB limit.
    tar = _sparse10_bomb(tmp_path / "sp.tar.gz", 48)
    out = tmp_path / "sp.json"
    code = ("import sys; from firmae import hwprofile as hp; hp.MAX_HEADER_BYTES = 1 << 50; "
            "sys.exit(hp.main(sys.argv[1:], set_rlimit=True))")
    t = time.monotonic()
    r = _cli(["--tar", tar, "--out", str(out), "--mem-limit-mb", "200", "--timeout", "30"],
             code=code, timeout=120)
    took = time.monotonic() - t
    what = "rc=%d %.1fs stdout=%r stderr=%r" % (r.returncode, took, r.stdout[-2000:], r.stderr[-4000:])
    assert r.returncode == 0, what
    assert b"Traceback" not in r.stderr, what
    assert json.loads(out.read_text())["static"]["limits_hit"] == ["memory"], what
    assert took < 25, what


@needs_rlimit
def test_cli_hard_deadline_ends_a_stuck_process(tmp_path):
    """Whatever the main thread is stuck in, the CLI ends HARD_GRACE seconds
    after --timeout with exit 1 and no traceback."""
    code = ("import sys, time; from firmae import hwprofile as hp; hp.HARD_GRACE = 0.5; "
            "hp.scan_tarball = lambda *a, **k: time.sleep(60); "
            "sys.exit(hp.main(sys.argv[1:], set_rlimit=True))")
    t = time.monotonic()
    r = _cli(["--tar", _tar(tmp_path), "--out", str(tmp_path / "o.json"), "--timeout", "1"],
             code=code, timeout=30)
    assert r.returncode == 1 and time.monotonic() - t < 15
    assert r.stdout == b"" and b"Traceback" not in r.stderr


@pytest.mark.skipif(not os.path.exists("/proc/self/statm") or not hasattr(os, "pread"),
                    reason="Linux /proc")
def test_memory_guard_stops_the_scan(tmp_path, monkeypatch):
    fd = os.open("/proc/self/statm", os.O_RDONLY)
    try:
        monkeypatch.setattr(hp, "_MEM_GUARD", [1, fd])         # any process is above 1 byte
        tar = make_tar(tmp_path / "1.tar.gz", [("./a", "file", b"x" * (1 << 17))])
        s = hp.scan_tarball(tar)
        assert s["limits_hit"] == ["memory"]
        monkeypatch.setattr(hp, "_MEM_GUARD", [0, None])        # off: library default
        assert hp.scan_tarball(tar)["limits_hit"] == []
    finally:
        os.close(fd)


def test_memory_error_drops_the_reserve(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "_RESERVE", [bytearray(16)])

    def boom(self):
        raise MemoryError()
    monkeypatch.setattr(tarfile.TarFile, "next", boom)
    s = hp.scan_tarball(_many_files(tmp_path, 2))
    assert s["limits_hit"] == ["memory"] and hp._RESERVE == []


@needs_rlimit
def test_cli_sets_rlimit_only_as_entry_point(tmp_path):
    code = ("import resource, sys; from firmae import hwprofile as hp; "
            "before = resource.getrlimit(resource.RLIMIT_AS)[0]; "
            "rc = hp.main(sys.argv[1:]); "
            "assert resource.getrlimit(resource.RLIMIT_AS)[0] == before; "
            "rc2 = hp.main(sys.argv[1:], set_rlimit=True); "
            "assert resource.getrlimit(resource.RLIMIT_AS)[0] == 333 << 20; "
            "sys.exit(rc or rc2)")
    r = _cli(["--tar", _tar(tmp_path), "--out", str(tmp_path / "o.json"), "--mem-limit-mb", "333"],
             code=code)
    assert r.returncode == 0, r.stderr


# ---------------------------------------------------------------- CLI errors

def test_cli_unexpected_error_is_one_line(tmp_path, monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("kaput\x1b[2J")
    monkeypatch.setattr(hp, "build_profile", boom)
    assert hp.main(["--tar", _tar(tmp_path), "--out", str(tmp_path / "o.json")]) == 1
    err = capsys.readouterr().err
    assert err.splitlines() == ["hwprofile: error: unexpected RuntimeError: kaput?[2J"]


@pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
def test_cli_does_not_swallow_interrupts(tmp_path, monkeypatch, exc):
    def stop(*a, **k):
        raise exc()
    monkeypatch.setattr(hp, "scan_tarball", stop)
    with pytest.raises(exc):
        hp.main(["--tar", _tar(tmp_path), "--out", str(tmp_path / "o.json")])


# ---------------------------------------------------------------- dynamic counters

def _module_log(names):
    return {"modules": {n: {"errors": 1} for n in names},
            "events": {"module_load_failed": {"count": len(names),
                                              "samples": ["insmod: can't insert '%s'" % n
                                                          for n in names[:5]]}}}


def test_module_counters_classify_beyond_the_samples():
    names = ["m%d.ko" % i for i in range(5)] + ["bcm_wdt.ko", "i2c-bcm.ko"]
    p = hp.build_profile(empty_static(), _module_log(names))
    per = p["peripherals"]
    assert per["watchdog"]["status"] == "failing" and per["i2c"]["status"] == "failing"
    assert "runtime module bcm_wdt.ko errors=1" in per["watchdog"]["evidence"]
    assert not any("module_load_failed" in n for n in p["notes"])      # classified
    # the same log without the counters (older hwserial): samples only, the 6th is missed
    old = _module_log(names)
    del old["modules"]
    assert hp.build_profile(empty_static(), old)["peripherals"]["watchdog"]["status"] == "not-referenced"


def test_module_counters_unclassified_become_a_note_and_events_still_count():
    dyn = _module_log(["m0.ko", "m1.ko"])
    dyn["events"]["gpio_error"] = {"count": 1, "samples": ["gpio: x"]}
    dyn["modules"]["gpio-keys.ko"] = {"errors": 0}
    p = hp.build_profile(empty_static(), dyn)
    assert any("module_load_failed x2" in n for n in p["notes"])
    assert p["peripherals"]["gpio"]["status"] == "failing"
    assert "runtime module gpio-keys.ko (no errors)" in p["peripherals"]["gpio"]["evidence"]


def test_device_counters_with_modules_key_skip_samples():
    dyn = {"modules": {}, "devices": {"/dev/i2c-0": {"errors": 2}},
           "events": {"device_open_failed": {"count": 2, "samples": ["open /dev/spidev0.0 failed"]}}}
    per = hp.build_profile(empty_static(), dyn)["peripherals"]
    assert per["i2c"]["status"] == "failing" and per["spi"]["status"] == "not-referenced"


def test_cli_passes_deadline_to_hwserial(tmp_path, monkeypatch):
    seen = []
    mod = types.ModuleType("firmae.hwserial")

    def scan_serial_logs(paths, deadline=None):
        seen.append(deadline)
        return {"modules": {"bcm_wdt.ko": {"errors": 3}}}
    mod.scan_serial_logs = scan_serial_logs
    monkeypatch.setitem(sys.modules, "firmae.hwserial", mod)
    out = tmp_path / "hw.json"
    t = time.monotonic()
    assert hp.main(["--tar", _tar(tmp_path), "--out", str(out), "--serial-log", "l", "--timeout", "50"]) == 0
    assert len(seen) == 1 and t < seen[0] <= time.monotonic() + 50
    assert json.loads(out.read_text())["peripherals"]["watchdog"]["status"] == "failing"


# ---------------------------------------------------------------- profile size

def test_profile_size_is_bounded_and_peripherals_complete(tmp_path):
    body = (b"\0".join(b"/dev/vendor_node_%04d_%s" % (i, b"x" * 200) for i in range(2000)) + b"\0" +
            b"\0".join(b"/sys/devices/platform/%04d_%s" % (i, b"y" * 200) for i in range(2000)))
    with tarfile.open(str(tmp_path / "big.tar.gz"), "w:gz") as tf:
        for j in range(5):
            ti = tarfile.TarInfo("./usr/lib/" + "d" * 240 + "/lib%d.so" % j)
            ti.size = len(body)
            tf.addfile(ti, io.BytesIO(body))
    out = tmp_path / "big.json"
    assert hp.main(["--tar", str(tmp_path / "big.tar.gz"), "--out", str(out)]) == 0
    assert os.path.getsize(str(out)) <= hp.MAX_PROFILE_BYTES
    prof = json.loads(out.read_text())
    assert "profile_size" in prof["static"]["limits_hit"] and prof["static"]["truncated"]
    assert set(prof["peripherals"]) == set(hp.PERIPHERALS)
    assert prof["peripherals"]["other"]["status"] == "referenced"
    assert prof["static"]["device_paths"]            # trimmed, not emptied


def test_fit_profile_keeps_peripherals_and_top_entries():
    s = empty_static()
    s["device_paths"] = {"/dev/v%04d" % i: {"count": i, "files": ["./f%d" % j for j in range(5)]}
                         for i in range(500)}
    dyn = {"devices": {"/dev/d%04d" % i: {"errors": i} for i in range(500)}, "events": {}}
    p = hp.build_profile(s, dyn)
    peripherals = json.loads(json.dumps(p["peripherals"]))
    hp.fit_profile(p, 20000)
    assert len(hp._dumps(p)) <= 20000
    assert p["peripherals"] == peripherals
    assert "/dev/v0499" in p["static"]["device_paths"] and "/dev/d0499" in p["dynamic"]["devices"]
    assert p["static"]["limits_hit"] == ["profile_size"]
    small = hp.build_profile(empty_static())
    assert hp.fit_profile(small) == hp.build_profile(empty_static())    # untouched when it fits
