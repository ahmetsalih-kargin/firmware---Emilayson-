"""Unit tests for firmae.hwserial (hardware failure traces in serial logs)."""

import json
import os
import time

import pytest

from firmae import hwserial
from firmae.hwserial import scan_serial_log, scan_serial_logs

FIX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "fixtures", "serial")


def fx(name):
    return os.path.join(FIX, name)


def counts(res):
    return {k: v["count"] for k, v in res["events"].items()}


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


@pytest.mark.parametrize("fixture,kind,n", [
    ("hw_hook.log", "hook_register_failed", 3),
    ("hw_nosuch.log", "no_such_device", 5),
    ("hw_module.log", "module_load_failed", 1),
    ("hw_mtd.log", "mtd_error", 2),
    ("hw_segv.log", "segfault", 1),
    ("hw_watchdog.log", "watchdog_error", 2),
    ("hw_gpio.log", "gpio_error", 2),
    ("hw_panic.log", "kernel_panic", 1),
    ("hw_open.log", "device_open_failed", 1),
])
def test_each_event_kind(fixture, kind, n):
    res = scan_serial_log(fx(fixture))
    c = counts(res)
    assert c[kind] == n
    assert sum(c.values()) == n          # one kind per line, nothing else fires
    assert res["events"][kind]["samples"]


def test_all_keys_always_present():
    res = scan_serial_log(fx("hw_clean.log"))
    assert set(res["events"]) == {
        "device_open_failed", "no_such_device", "hook_register_failed",
        "module_load_failed", "segfault", "kernel_panic", "mtd_error",
        "watchdog_error", "gpio_error"}
    assert set(res) == {"logs", "events", "devices", "modules", "respawn", "truncated"}


def test_clean_log_all_zero():
    res = scan_serial_log(fx("hw_clean.log"))
    assert all(v == 0 for v in counts(res).values())
    assert res["devices"] == {} and res["respawn"] == {} and res["modules"] == {}
    assert res["logs"][0]["error"] is None and res["logs"][0]["lines"] == 4


def test_insmod_hint_is_not_a_module_failure():
    res = scan_serial_log(fx("hw_module.log"))
    assert res["modules"] == {"nf_nat_proto_gre.ko": {"errors": 1}}
    assert all("iptables" not in s for s in res["events"]["module_load_failed"]["samples"])


def test_device_path_extraction():
    res = scan_serial_log(fx("hw_nosuch.log"))
    assert res["devices"] == {"/dev/nvram": {"errors": 2}}
    res = scan_serial_log(fx("hw_mtd.log"))
    assert res["devices"] == {"/dev/mtdblock/4": {"errors": 1}, "/dev/mtd5": {"errors": 1}}


def test_trace_lines_are_not_events_but_feed_respawn():
    res = scan_serial_log(fx("hw_respawn.log"))
    assert counts(res)["no_such_device"] == 0
    assert res["respawn"] == {"ntpclient": 12}


def test_respawn_top_20_and_threshold(tmp_path):
    lines = []
    for n in range(30):
        for i in range(10 + n):
            lines.append("[ 1.0] firmadyne: sys_socket[PID: %d (p%02d)]: x" % (i, n))
    lines.append("[ 1.0] firmadyne: sys_socket[PID: 1 (rare)]: x")
    p = write(tmp_path, "r.log", ("\n".join(lines) + "\n").encode())
    res = scan_serial_log(p)
    assert len(res["respawn"]) == 20
    assert "rare" not in res["respawn"] and res["respawn"]["p29"] == 39


def test_execve_names_counted(tmp_path):
    p = write(tmp_path, "e.log", b"firmadyne: do_execve: /bin/foo\n" * 11)
    assert scan_serial_log(p)["respawn"] == {"foo": 11}


def test_sanitization_ansi_nul_invalid_utf8():
    res = scan_serial_log(fx("hw_binary.log"))
    assert counts(res)["no_such_device"] == 1
    assert res["devices"] == {"/dev/nvram": {"errors": 1}}
    for s in res["events"]["no_such_device"]["samples"]:
        assert all(0x20 <= ord(ch) <= 0x7e for ch in s)
    res = scan_serial_log(fx("hw_watchdog.log"))
    for s in res["events"]["watchdog_error"]["samples"]:
        assert "\x1b" not in s and "[1;" not in s and "\r" not in s


def test_sample_limits(tmp_path):
    body = b"".join(b"/dev/x%d: No such device " % i + b"A" * 500 + b"\n" for i in range(50))
    res = scan_serial_log(write(tmp_path, "s.log", body))
    ev = res["events"]["no_such_device"]
    assert ev["count"] == 50
    assert len(ev["samples"]) == 5
    assert all(len(s) <= 200 for s in ev["samples"])


def test_huge_single_line_bounded_and_fast(tmp_path):
    data = b"A" * (8 * 1024 * 1024) + b" /dev/nvram: No such device\n/dev/nvram: No such device\n"
    p = write(tmp_path, "big.log", data)
    t = time.time()
    res = scan_serial_log(p)
    assert time.time() - t < 2.0
    assert res["logs"][0]["truncated"] is True       # over-long line clipped
    assert res["logs"][0]["lines"] == 2
    assert counts(res)["no_such_device"] == 1        # tail of the clipped line skipped


def test_bad_regex_input_is_fast(tmp_path):
    evil = (b"/dev/" + b"a/" * 500000 + b"\x1b[" + b"1;" * 100000 + b" "
            + b"firmadyne: x[PID: " + b"9" * 100000)
    p = write(tmp_path, "evil.log", evil + b"\n" + (b"[ " * 200000) + b"\n")
    t = time.time()
    scan_serial_log(p)
    assert time.time() - t < 2.0


def test_byte_limit_truncates(tmp_path, monkeypatch):
    monkeypatch.setattr(hwserial, "MAX_LOG_BYTES", 10000)
    p = write(tmp_path, "t.log", b"/dev/nvram: No such device\n" * 1000)
    res = scan_serial_log(p)
    assert res["truncated"] is True and res["logs"][0]["truncated"] is True
    assert res["logs"][0]["bytes"] <= 10000
    assert 0 < counts(res)["no_such_device"] < 1000


def test_exact_size_is_not_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(hwserial, "MAX_LOG_BYTES", 27 * 3)
    p = write(tmp_path, "t.log", b"/dev/nvram: No such device\n" * 3)
    res = scan_serial_log(p)
    assert res["truncated"] is False and counts(res)["no_such_device"] == 3


def test_device_count_bounded(tmp_path):
    body = b"".join(b"/dev/d%d: No such device\n" % i for i in range(800))
    res = scan_serial_log(write(tmp_path, "d.log", body))
    assert len(res["devices"]) == 500
    assert res["events"]["no_such_device"]["count"] == 800


def test_missing_directory_symlink_errors(tmp_path):
    good = write(tmp_path, "g.log", b"Kernel panic\n")
    d = tmp_path / "dir"
    d.mkdir()
    link = tmp_path / "link.log"
    try:
        os.symlink(good, str(link))
    except (OSError, NotImplementedError):
        link = None
    paths = [str(tmp_path / "missing.log"), str(d)] + ([str(link)] if link else [])
    res = scan_serial_logs(paths + [good])
    errs = [l["error"] for l in res["logs"]]
    assert all(e for e in errs[:-1]) and errs[-1] is None
    assert [l["name"] for l in res["logs"]][0] == "missing.log"
    assert counts(res)["kernel_panic"] == 1          # symlink target not read twice


def test_fifo_rejected(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("no mkfifo")
    f = str(tmp_path / "fifo.log")
    os.mkfifo(f)
    assert scan_serial_log(f)["logs"][0]["error"] == "not a regular file"


def test_bad_inputs_do_not_raise():
    assert scan_serial_logs([None])["logs"][0]["error"]
    assert scan_serial_logs(None)["logs"] == []
    assert scan_serial_logs([])["events"]["segfault"]["count"] == 0


def test_name_is_basename_only():
    res = scan_serial_log(fx("hw_clean.log"))
    assert res["logs"][0]["name"] == "hw_clean.log"


def test_multiple_logs_merged():
    res = scan_serial_logs([fx("hw_nosuch.log"), fx("hw_hook.log"), fx("hw_nosuch.log")])
    assert [l["name"] for l in res["logs"]] == ["hw_nosuch.log", "hw_hook.log", "hw_nosuch.log"]
    assert counts(res)["no_such_device"] == 10 and counts(res)["hook_register_failed"] == 3
    assert res["devices"]["/dev/nvram"]["errors"] == 4
    assert len(res["events"]["no_such_device"]["samples"]) <= 5


def test_deterministic():
    paths = [fx("hw_respawn.log"), fx("hw_mtd.log"), fx("hw_nosuch.log")]
    a = json.dumps(scan_serial_logs(paths), sort_keys=True)
    b = json.dumps(scan_serial_logs(paths), sort_keys=True)
    assert a == b


def test_existing_real_fixtures_do_not_crash():
    for n in ("serial_armel_dir868l.log", "serial_mipseb_wnap320.log"):
        res = scan_serial_log(fx(n))
        assert res["logs"][0]["error"] is None
        assert counts(res)["kernel_panic"] == 0


# ---------------------------------------------------------------- hardening 2

def run(tmp_path, lines, **kw):
    body = "\n".join(lines) + "\n"
    return scan_serial_log(write(tmp_path, "x.log", body.encode()), **kw)


def noise(n):
    return ["some harmless boot noise"] * n


def test_modules_full_counters_beyond_five_samples(tmp_path):
    lines = ["[ 1.%d] insmod: can't insert '/lib/modules/unrel%d.ko': unknown symbol in module" % (i, i)
             for i in range(5)]
    lines += ["insmod: can't insert '/lib/modules/bcm_wdt.ko': Operation not permitted"] * 3
    lines += ["insmod: can't insert '/lib/modules/i2c-core.ko': File exists",
              "bcm_gpio: disagrees about version of symbol module_layout",
              "insmod: can't insert 'noname': failure"]
    res = run(tmp_path, lines)
    mods = res["modules"]
    assert len(res["events"]["module_load_failed"]["samples"]) == 5
    assert mods["bcm_wdt.ko"] == {"errors": 3}
    assert mods["i2c-core.ko"] == {"errors": 1}
    assert mods["bcm_gpio"] == {"errors": 1}
    assert all(("unrel%d.ko" % i) in mods for i in range(5))
    assert res["events"]["module_load_failed"]["count"] == 11
    assert res["truncated"] is False


def test_module_names_are_sanitised_and_bounded(tmp_path):
    long_name = "a" * 100 + ".ko"
    lines = ["insmod: can't insert '/lib/modules/%s': x" % long_name,
             "insmod: can't insert '/lib/../../etc/passwd.ko': x",
             "insmod: can't insert '/lib/modules/we ird;$(id).ko': x"]
    mods = run(tmp_path, lines)["modules"]
    assert mods
    for name in mods:
        assert 1 <= len(name) <= 64
        assert all(ch.isalnum() or ch in "_.+-" for ch in name)
    assert "passwd.ko" in mods and "/" not in "".join(mods)


def test_module_table_bounded_and_marks_truncated(tmp_path):
    lines = ["insmod: can't insert '/m/mod%d.ko': x" % i for i in range(600)]
    res = run(tmp_path, lines)
    assert len(res["modules"]) == 500
    assert res["truncated"] is True
    assert res["logs"][0]["truncated"] is False
    assert res["events"]["module_load_failed"]["count"] == 600


def test_devices_counted_for_every_event_kind(tmp_path):
    lines = [
        "/bin/sh: can't open /dev/ttyS1: No such file",
        "/dev/nvram: No such device",
        "mtd: write failed on /dev/mtd3",
        "watchdog: /dev/watchdog: Error in opening the device",
        "gpio: cannot request /dev/gpio",
        "insmod: can't insert 'x.ko': no /dev/foo",
        "Kernel panic: cannot mount /dev/root",
    ]
    res = run(tmp_path, lines)
    assert res["devices"] == {
        "/dev/ttyS1": {"errors": 1}, "/dev/nvram": {"errors": 1},
        "/dev/mtd3": {"errors": 1}, "/dev/watchdog": {"errors": 1},
        "/dev/gpio": {"errors": 1}, "/dev/foo": {"errors": 1},
        "/dev/root": {"errors": 1}}
    assert sum(counts(res).values()) == 7


@pytest.mark.parametrize("line", [
    "gpio-keys: no error",
    "mtd: ecc check finished, 0 errors",
    "watchdog: heartbeat ok error_count=0",
    "watchdog: errors: 0 failures=0",
    "failsafe: waiting for gpio button",
    "mtd0: scanned without error",
    "gpio: zero errors, no failures",
    "[ 3.0] gpio-keys: Error count: 0",
    "mtd: errorless partition",
])
def test_false_positive_lines_not_counted(tmp_path, line):
    res = run(tmp_path, [line])
    assert sum(counts(res).values()) == 0, counts(res)


@pytest.mark.parametrize("line,kind", [
    ("watchdog: error_count=3", "watchdog_error"),
    ("gpio: request failed", "gpio_error"),
    ("gpio_error: -5", "gpio_error"),
    ("mtd: read failure at 0x100", "mtd_error"),
    ("gpio: no error but request failed", "gpio_error"),
    ("mtd: partition not found", "mtd_error"),
    ("mtd: 10 errors", "mtd_error"),
    ("watchdog: timeout while feeding", "watchdog_error"),
])
def test_true_positive_lines_still_counted(tmp_path, line, kind):
    assert counts(run(tmp_path, [line]))[kind] == 1


def test_oops_panic_sequence_is_one_incident(tmp_path):
    lines = (["[ 1.0] Unable to handle kernel NULL pointer dereference at 0x0",
              "[ 1.1] Internal error: Oops: 17 [#1] SMP ARM"] + noise(10)
             + ["[ 1.2] Kernel panic - not syncing: Fatal exception"] + noise(5)
             + ["[ 1.3] Kernel panic - not syncing: again"])
    res = run(tmp_path, lines)
    assert counts(res)["kernel_panic"] == 1
    assert len(res["events"]["kernel_panic"]["samples"]) == 4   # samples keep the context


def test_panic_window_edges(tmp_path):
    def gap(n):
        return ["Kernel panic - a"] + noise(n - 1) + ["Kernel panic - b"]
    assert counts(run(tmp_path, gap(50)))["kernel_panic"] == 1    # 50 lines apart: same
    assert counts(run(tmp_path, gap(51)))["kernel_panic"] == 2    # 51: new incident
    chain = ["Kernel panic - a"] + noise(39) + ["Kernel panic - b"] + noise(39) + ["Kernel panic - c"]
    assert counts(run(tmp_path, chain))["kernel_panic"] == 1      # sliding window
    assert counts(run(tmp_path, ["Kernel panic - a"] + noise(200) + ["Kernel panic - b"]))["kernel_panic"] == 2


def test_fake_oops_can_suppress_real_panic_documented(tmp_path):
    lines = ["Oops: fake"] + noise(10) + ["Kernel panic - not syncing: real"]
    assert counts(run(tmp_path, lines))["kernel_panic"] == 1


def test_segfault_kernel_plus_shell_is_one_crash(tmp_path):
    k = "[ 5.0] do_page_fault(): sending SIGSEGV to hostapd for invalid read access from 00000004"
    sh = "/bin/sh: line 1:  123 Segmentation fault      hostapd"
    assert counts(run(tmp_path, [k, sh]))["segfault"] == 1
    assert counts(run(tmp_path, [k] + noise(39) + [sh]))["segfault"] == 1    # 40 lines apart (MIPS reg dump)
    assert counts(run(tmp_path, [k] + noise(40) + [sh]))["segfault"] == 2    # 41: separate
    assert counts(run(tmp_path, [sh]))["segfault"] == 1                     # shell line alone
    assert counts(run(tmp_path, [k, k, sh]))["segfault"] == 2               # two crashes
    assert counts(run(tmp_path, [k, sh, sh]))["segfault"] == 2              # one absorbed only
    assert counts(run(tmp_path, [sh, k]))["segfault"] == 2                  # wrong order: not merged
    assert counts(run(tmp_path, [k] + noise(50) + [k, sh]))["segfault"] == 2


def test_deadline_in_the_past(tmp_path):
    p = write(tmp_path, "d.log", b"Kernel panic\n" * 10)
    res = scan_serial_logs([p, p], deadline=hwserial._now() - 1.0)
    assert res["truncated"] is True
    assert all(l["truncated"] and l["lines"] == 0 for l in res["logs"])
    assert counts(res)["kernel_panic"] == 0
    res = scan_serial_log(p, deadline=hwserial._now() + 3600)
    assert res["truncated"] is False and counts(res)["kernel_panic"] == 1


def test_deadline_stops_mid_file(tmp_path, monkeypatch):
    monkeypatch.setattr(hwserial, "_BLOCK", 100)
    ticks = iter(range(1, 10000))
    monkeypatch.setattr(hwserial, "_now", lambda: next(ticks))
    data = b"/dev/nvram: No such device\n" * 200
    res = scan_serial_log(write(tmp_path, "m.log", data), deadline=6)
    assert res["truncated"] is True and res["logs"][0]["truncated"] is True
    assert 0 < res["logs"][0]["bytes"] < len(data)
    assert 0 < counts(res)["no_such_device"] < 200


def test_blank_lines_are_fast(tmp_path):
    p = write(tmp_path, "nl.log", b"\n" * (16 * 1024 * 1024))
    t = time.time()
    res = scan_serial_log(p)
    assert time.time() - t < 4.0                       # 64 MiB budget is 15 s
    assert res["logs"][0]["lines"] == 16 * 1024 * 1024 and res["truncated"] is False
    p = write(tmp_path, "crlf.log", b"\r\n" * (4 * 1024 * 1024))
    t = time.time()
    scan_serial_log(p)
    assert time.time() - t < 4.0


def test_typical_log_is_fast(tmp_path):
    unit = (b"[  12.345678] eth0: link up, 1000 Mbps full duplex, flow control off ok\n"
            b"[  12.350000] firmadyne: sys_socket[PID: 77 (udevd)]: family:1, type:2, protocol:0\n"
            b"Starting httpd ... done and some more words to pad the line out\n")
    data = unit * (8 * 1024 * 1024 // len(unit))
    p = write(tmp_path, "typ.log", data)
    t = time.time()
    res = scan_serial_log(p)
    assert time.time() - t < 6.0                       # 64 MiB budget is 30 s
    assert sum(counts(res).values()) == 0


def test_hostile_line_with_many_keywords_is_fast(tmp_path):
    line = (b"gpio mtd watchdog " + b"errors: 0 " * 400 + b"failed " * 200 + b"no error " * 200)
    big = b"error " * (8 * 1024 * 1024 // 6)
    data = (line + b"\n") * 200 + big + b"\n"
    t = time.time()
    scan_serial_log(write(tmp_path, "h.log", data))
    assert time.time() - t < 2.0


def test_trace_prefix_cannot_hide_serious_events(tmp_path):
    pre = "[ 1.0] firmadyne: sys_socket[PID: 1 (x)]: "
    res = run(tmp_path, [pre + "Kernel panic - not syncing",
                         pre + "sending SIGSEGV to foo",
                         pre + "insmod: can't insert 'evil.ko'"])
    c = counts(res)
    assert c["kernel_panic"] == 1 and c["segfault"] == 1 and c["module_load_failed"] == 1
    assert "evil.ko" in res["modules"]


def test_real_trace_shape_is_strict(tmp_path):
    pre = "[ 1.0] firmadyne: sys_socket[PID: 1 (x)]: "
    # genuine trace shape: generic errors inside are not events
    assert sum(counts(run(tmp_path, [pre + "cannot open /dev/foo: No such device"])).values()) == 0
    # not at line start, wrong separators, junk function names: all real lines
    for bad in ("cannot open /dev/foo " + pre,
                "xx firmadyne: sys_socket[PID: 1 (x)]: cannot open /dev/foo",
                "firmadyne: sys_socket [PID: 1 (x)]: cannot open /dev/foo",
                "firmadyne: sys socket[PID: 1 (x)]: cannot open /dev/foo",
                "firmadyne: sys_socket[PID: 1 (x)] cannot open /dev/foo",
                "firmadyne: SYS_socket[PID: 1 (x)]: cannot open /dev/foo",
                "firmadyne: sys_socket[PID: 1x (x)]: cannot open /dev/foo"):
        assert counts(run(tmp_path, [bad]))["device_open_failed"] == 1, bad
    # near-trace lines do not feed respawn either
    lines = ["xx firmadyne: sys_socket[PID: %d (spoof)]: y" % i for i in range(30)]
    assert run(tmp_path, lines)["respawn"] == {}


# ---------------------------------------------------------------- phase 6.2: exec trace

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden_hwserial.json")


def _no_bytes(res):
    """`logs[].bytes` depends on the checkout's line endings (hw_watchdog.log is
    CRLF under Windows autocrlf); everything else must be identical."""
    res = json.loads(json.dumps(res))
    for entry in res["logs"]:
        entry.pop("bytes")
    return res


def test_pre_62_fixtures_give_identical_results():
    """Output of commit ad1aad7 (before the exec trace) for every older fixture."""
    with open(GOLDEN) as f:
        golden = json.load(f)
    names = sorted(n for n in os.listdir(FIX) if n.endswith(".log") and n != "hw_analyze.log")
    assert names == golden["fixtures"]
    for n in names:
        res = scan_serial_log(fx(n))
        assert "exec" not in res
        assert _no_bytes(res) == _no_bytes(golden["scan"][n]), n
        assert res["logs"][0]["bytes"] == os.path.getsize(fx(n))
    merged = scan_serial_logs([fx(n) for n in names])
    assert _no_bytes(merged) == _no_bytes(golden["merged"])


ANALYZE_EXEC = {
    "lines": 27,
    "commands": {"Kernel": 1, "awk": 1, "cat": 3, "dd": 1, "echo": 2, "event": 2, "flash_erase": 1,
                 "gpioset": 1, "i2cdetect": 1, "i2cdump": 1, "init": 1, "ledctrl": 1, "mkdir": 2,
                 "modprobe": 2, "mount": 2, "seama": 1, "sh": 2, "xmldbc": 1},
    "device_args": {
        "/dev/b": {"count": 1, "commands": ["cat"]},
        "/dev/gpio": {"count": 1, "commands": ["cat"]},
        "/dev/gpiochip0": {"count": 1, "commands": ["gpioset"]},
        "/dev/led1": {"count": 1, "commands": ["ledctrl"]},
        "/dev/mtd12": {"count": 1, "commands": []},
        "/dev/mtd3": {"count": 1, "commands": ["dd"]},
        "/dev/mtd5": {"count": 2, "commands": ["sh", "flash_erase"]},
        "/dev/mtdblock/4": {"count": 3, "commands": ["mount", "event", "seama"]},
        "/dev/net": {"count": 1, "commands": ["mkdir"]},
        "/dev/nvram": {"count": 1, "commands": ["echo"]},
        "/dev/ttyS1": {"count": 1, "commands": ["cat"]},
        "/dev/watchdog": {"count": 1, "commands": ["cat"]},
    },
    "hw_tools": {"flash_erase": 1, "gpioset": 1, "i2cdetect": 1, "i2cdump": 1, "ledctrl": 1},
    "truncated": True,           # the 5000-byte line was clipped at MAX_LINE_BYTES
}


def test_analyze_fixture_exact_exec_section():
    res = scan_serial_log(fx("hw_analyze.log"))
    assert res["exec"] == ANALYZE_EXEC
    assert res["logs"][0]["truncated"] is True and res["truncated"] is True


def test_analyze_fixture_hostile_lines_add_nothing():
    ex = scan_serial_log(fx("hw_analyze.log"))["exec"]
    devs = set(ex["device_args"])
    # envp lines, continuation lines, mid-line / malformed prefixes, redirection
    # targets, traversal, unbalanced quotes, benign pseudo devices, clipped tails
    for bad in ("/dev/i2c-0", "/dev/spidev0.0", "/dev/i2c-1", "/dev/i2c-2", "/dev/i2c-3",
                "/dev/i2c-4", "/dev/i2c-5", "/dev/i2c-6", "/dev/i2c-7", "/dev/i2c-9",
                "/dev/watchdog2", "/dev/led0", "/dev/mtd7", "/dev/mtd8", "/dev/mtd9",
                "/dev/mtd10", "/dev/mtd11", "/dev/mtd0", "/dev/mtd1", "/dev/null", "/dev/zero",
                "/dev/console", "/dev/tty", "/dev/tty1", "/dev/ttyp0", "/dev/pts", "/dev/pts/0",
                "/dev/urandom", "/dev/x", "/dev/my"):
        assert bad not in devs, bad
    assert not any(".." in d or "/etc/" in d or "'" in d or '"' in d or "$" in d for d in devs)
    assert not any(c.startswith(("i2cget", "i2cset")) for c in ex["commands"])
    assert "envp:" not in ex["commands"] and "HOME" not in "".join(ex["commands"])
    for name in list(ex["commands"]) + [c for v in ex["device_args"].values() for c in v["commands"]]:
        assert 1 <= len(name) <= 64 and all(ch.isalnum() or ch in "_.+-" for ch in name)


def test_analyze_fixture_events():
    res = scan_serial_log(fx("hw_analyze.log"))
    # "event WPS.ERROR ... /var/gpio_ctrl" and "echo cannot open /dev/nvram" are
    # command lines, not errors; the panic printed as a command still counts
    assert counts(res) == {"device_open_failed": 0, "no_such_device": 0, "hook_register_failed": 0,
                           "module_load_failed": 0, "segfault": 0, "kernel_panic": 1, "mtd_error": 1,
                           "watchdog_error": 0, "gpio_error": 0}
    assert res["devices"] == {"/dev/mtd5": {"errors": 1}}
    assert res["respawn"] == {} and res["modules"] == {}


def test_exec_lines_are_exempt_from_generic_kinds_only(tmp_path):
    pre = "[ANALYZE] [PID: 1 (sh)]: "
    body = ["echo cannot open /dev/foo", "echo /dev/nvram: No such device", "echo gpio failed",
            "echo mtd error", "echo watchdog error"]
    assert sum(counts(run(tmp_path, body)).values()) == 5     # without the prefix: five events
    res = run(tmp_path, [pre + b for b in body])
    assert sum(counts(res).values()) == 0 and res["devices"] == {}
    res = run(tmp_path, [pre + "Kernel panic - x", pre + "sending SIGSEGV to y",
                         pre + "insmod: can't insert 'evil.ko': x"])
    c = counts(res)
    assert c["kernel_panic"] == 1 and c["segfault"] == 1 and c["module_load_failed"] == 1
    assert res["exec"]["lines"] == 3 and "evil.ko" in res["modules"]


def test_exec_absent_without_exec_lines_present_with_any(tmp_path):
    assert "exec" not in run(tmp_path, ["[ANALYZE] mid", "x [ANALYZE] [PID: 1 (a)]: ls"])
    res = run(tmp_path, ["[ANALYZE] [PID: 1 (a)]: "])
    assert res["exec"] == {"lines": 1, "commands": {}, "device_args": {}, "hw_tools": {},
                           "truncated": False}


@pytest.mark.parametrize("token,dev", [
    ("/dev/mtd0", "/dev/mtd0"), ("/dev/mtdblock/4", "/dev/mtdblock/4"), ("/dev/gpio/", "/dev/gpio"),
    ("'/dev/i2c-0'", "/dev/i2c-0"), ('"/dev/spidev0.1"', "/dev/spidev0.1"),
    ("if=/dev/mtd2", "/dev/mtd2"), ("of=/dev/mtd3", "/dev/mtd3"), ("/dev/ttyS0", "/dev/ttyS0"),
    ("/dev/ttyUSB0", "/dev/ttyUSB0"), ("/dev/ttyAMA1", "/dev/ttyAMA1"),
    ("/dev/a/b/c/d/e", "/dev/a/b/c/d/e"),
    ("/dev/../etc/shadow", None), ("/dev/./mtd0", None), ("/dev/mtd/../x", None), ("/dev//mtd1", None),
    ("/dev/", None), ("/dev", None), ("/devx/mtd0", None), ("x/dev/mtd0", None), ("'/dev/x\"", None),
    ('"/dev/my', None), ("/dev/a b", None), ("/dev/a$b", None), ("/dev/a/b/c/d/e/f", None),
    ("/dev/" + "a" * 41, None), ("/dev/null", None), ("/dev/zero", None), ("/dev/console", None),
    ("/dev/tty", None), ("/dev/tty3", None), ("/dev/ttyp0", None), ("/dev/pts", None),
    ("/dev/pts/2", None), ("/dev/urandom", None), ("/dev/fd/1", None), ("of=/dev/null", None),
    (None, None), (b"/dev/mtd0", None), ("/dev/mtd0" + "/x" * 200, None),
])
def test_exec_device_arg(token, dev):
    assert hwserial.exec_device_arg(token) == dev


def test_exec_redirection_targets_are_not_device_args(tmp_path):
    res = run(tmp_path, ["[ANALYZE] [PID: 1 (sh)]: cmd > /dev/mtd1 >> /dev/mtd2 < /dev/mtd3 "
                         "2> /dev/mtd4 2>> /dev/mtd5 &> /dev/mtd6 >| /dev/mtd7 "
                         ">/dev/mtd9 2>/dev/mtd10 /dev/mtd11"])
    assert set(res["exec"]["device_args"]) == {"/dev/mtd11"}
    # "2>&1" becomes "2>" "1": only the "1" is skipped, the next argument counts
    res = run(tmp_path, ["[ANALYZE] [PID: 1 (sh)]: cmd 2>&1 /dev/mtd8"])
    assert set(res["exec"]["device_args"]) == {"/dev/mtd8"}


def test_exec_busybox_applet_and_separators(tmp_path):
    res = run(tmp_path, ["[ANALYZE] [PID: 1 (sh)]: /bin/busybox flash_erase /dev/mtd1 0 0",
                         "[ANALYZE] [PID: 2 (sh)]: busybox",
                         "[ANALYZE] [PID: 3 (sh)]: umount /dev/mtd2;cat /dev/mtd3|grep x&&ls (/dev/mtd4)"])
    ex = res["exec"]
    assert ex["commands"] == {"flash_erase": 1, "busybox": 1, "umount": 1}
    assert ex["hw_tools"] == {"flash_erase": 1}
    assert set(ex["device_args"]) == {"/dev/mtd1", "/dev/mtd2", "/dev/mtd3", "/dev/mtd4"}


def test_exec_device_counted_once_per_line_commands_bounded(tmp_path):
    lines = ["[ANALYZE] [PID: %d (sh)]: tool%d /dev/mtd0 /dev/mtd0 /dev/mtd0" % (i, i) for i in range(10)]
    entry = run(tmp_path, lines)["exec"]["device_args"]["/dev/mtd0"]
    assert entry == {"count": 10, "commands": ["tool0", "tool1", "tool2"]}


def test_exec_kernel_cap_drops_the_last_token(tmp_path):
    def line(total):
        pre = "[ANALYZE] [PID: 1 (sh)]: cat "
        return pre + "x" * (total - len(pre) - len(" /dev/mtd1")) + " /dev/mtd1"
    assert len(line(399)) == 399 and len(line(400)) == 400
    assert "/dev/mtd1" in run(tmp_path, [line(399)])["exec"]["device_args"]
    assert run(tmp_path, [line(400)])["exec"]["device_args"] == {}
    # a line clipped at MAX_LINE_BYTES: the partial last token is not used either
    head = "[ANALYZE] [PID: 1 (sh)]: cat /dev/mtd2 "
    big = head + "y" * (hwserial.MAX_LINE_BYTES - len(head) - len(" /dev/mtd9")) + " /dev/mtd9"
    assert len(big) == hwserial.MAX_LINE_BYTES          # what is kept ends in a valid "/dev/mtd9"
    res = run(tmp_path, [big + "9999"])
    assert res["logs"][0]["truncated"] is True
    assert set(res["exec"]["device_args"]) == {"/dev/mtd2"}


def test_exec_tables_are_capped(tmp_path):
    lines = ["[ANALYZE] [PID: %d (sh)]: cmd%d /dev/d%d /dev/e%d" % (i, i, i, i) for i in range(3000)]
    res = run(tmp_path, lines)
    ex = res["exec"]
    assert ex["lines"] == 3000
    assert len(ex["commands"]) == hwserial.MAX_EXEC_COMMANDS
    assert len(ex["device_args"]) == hwserial.MAX_EXEC_DEVICES
    assert ex["truncated"] is True
    assert res["truncated"] is False and res["logs"][0]["truncated"] is False   # top level unchanged
    # the tables keep the first names; counting of known names goes on
    res = run(tmp_path, lines + ["[ANALYZE] [PID: 1 (sh)]: cmd0 /dev/d0"] * 5)
    assert res["exec"]["commands"]["cmd0"] == 6 and res["exec"]["device_args"]["/dev/d0"]["count"] == 6


def test_exec_overflow_flag_each_table_alone(tmp_path):
    def ex_for(lines):
        res = run(tmp_path, lines)
        assert res["truncated"] is False
        return res["exec"]
    # exactly at the caps: nothing dropped, not truncated
    ex = ex_for(["[ANALYZE] [PID: 1 (sh)]: c /dev/d%d" % i for i in range(hwserial.MAX_EXEC_DEVICES)])
    assert len(ex["device_args"]) == hwserial.MAX_EXEC_DEVICES and ex["truncated"] is False
    ex = ex_for(["[ANALYZE] [PID: 1 (sh)]: cmd%d" % i for i in range(hwserial.MAX_EXEC_COMMANDS)])
    assert len(ex["commands"]) == hwserial.MAX_EXEC_COMMANDS and ex["truncated"] is False
    # one past the device cap, a single command name: only device_args overflows
    ex = ex_for(["[ANALYZE] [PID: 1 (sh)]: c /dev/d%d" % i for i in range(hwserial.MAX_EXEC_DEVICES + 1)])
    assert list(ex["commands"]) == ["c"] and len(ex["device_args"]) == hwserial.MAX_EXEC_DEVICES
    assert ex["truncated"] is True
    # one past the command cap, no device arguments: only commands overflows
    ex = ex_for(["[ANALYZE] [PID: 1 (sh)]: cmd%d" % i for i in range(hwserial.MAX_EXEC_COMMANDS + 1)])
    assert ex["device_args"] == {} and len(ex["commands"]) == hwserial.MAX_EXEC_COMMANDS
    assert ex["truncated"] is True


def test_exec_hw_tools_whitelist(tmp_path):
    lines = ["[ANALYZE] [PID: 1 (sh)]: %s x" % t for t in sorted(hwserial.HW_TOOLS)]
    lines += ["[ANALYZE] [PID: 1 (sh)]: %s x" % t for t in ("i2cget2", "spidev", "gpio-keys", "dd", "flash")]
    ex = run(tmp_path, lines)["exec"]
    assert ex["hw_tools"] == {t: 1 for t in hwserial.HW_TOOLS}


def test_exec_prefix_is_strict(tmp_path):
    for bad in ("x[ANALYZE] [PID: 1 (sh)]: i2cget", "[ANALYZE]  [PID: 1 (sh)]: i2cget",
                "[ANALYZE] [PID: 1 (sh)] : i2cget", "[ANALYZE] [PID: (sh)]: i2cget",
                "[ANALYZE] [PID: 12345678901 (sh)]: i2cget", "[ANALYZE] [PID: 1 (%s)]: i2cget" % ("n" * 33),
                "[ANALYZE] [PID: 1 (a)b)]: i2cget", "[ANALYZE] [pid: 1 (sh)]: i2cget",
                "[   1.000] [ANALYZE] [PID: 1 (sh)]: i2cget",
                "[ANALYZE] [PID: x (sh)]: [ANALYZE] [PID: 1 (sh)]: i2cget",
                "[ANALYZE] [PID: 1 (sh)]:[ANALYZE] [PID: 1 (sh)]: i2cget"):
        assert "exec" not in run(tmp_path, [bad]), bad
    for good in ("[ANALYZE] [PID: 1 ()]: i2cget", "[ANALYZE] [PID: 1 (kworker/u2:1)]: i2cget",
                 "[ANALYZE] [PID: 1 (a b [c])]: i2cget", "\x1b[0m[ANALYZE] [PID: 1 (sh)]: i2cget\r"):
        assert run(tmp_path, [good])["exec"]["hw_tools"] == {"i2cget": 1}, good


def test_exec_merged_over_logs_and_marked_when_a_log_is_cut(tmp_path, monkeypatch):
    p = write(tmp_path, "a.log", b"[ANALYZE] [PID: 1 (sh)]: flash_erase /dev/mtd1 0 0\n" * 4)
    res = scan_serial_logs([p, p])
    assert res["exec"]["lines"] == 8 and res["exec"]["device_args"]["/dev/mtd1"]["count"] == 8
    assert res["exec"]["truncated"] is False
    monkeypatch.setattr(hwserial, "MAX_LOG_BYTES", 100)
    res = scan_serial_log(p)
    assert res["truncated"] is True and res["exec"]["truncated"] is True


def test_exec_deterministic_and_json_clean():
    a = json.dumps(scan_serial_log(fx("hw_analyze.log")), sort_keys=True)
    assert a == json.dumps(scan_serial_log(fx("hw_analyze.log")), sort_keys=True)
    assert all(0x20 <= ord(ch) <= 0x7e for ch in a)


def test_exec_hostile_volume_is_fast(tmp_path):
    toks = " ".join("/dev/x%d" % i for i in range(70))
    unit = ("[ANALYZE] [PID: 1 (sh)]: flash_erase %s > /dev/null 2>&1 'q\" ;|&()`\n" % toks).encode()
    data = unit * (16 * 1024 * 1024 // len(unit))
    p = write(tmp_path, "v.log", data)
    t = time.time()
    res = scan_serial_log(p)
    assert time.time() - t < 10.0                     # 64 MiB budget: about 4x this
    assert res["exec"]["lines"] == len(data) // len(unit)
    assert len(res["exec"]["device_args"]) <= hwserial.MAX_EXEC_DEVICES
