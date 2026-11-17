"""Tests for firmae/hwreport.py (aggregate hardware report over scratch/<IID>/).

Every scratch tree is synthetic, built in tmp_path. Nothing here needs root, QEMU
or a real firmware. Files under scratch/<IID>/ are treated as hostile.
"""

import csv
import io
import json
import os
import re
import subprocess
import sys

import pytest

from firmae import config, hwprofile, hwreport, pipeline

pytestmark = pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "mkfifo"),
                                reason="POSIX (O_NOFOLLOW, FIFOs)")

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KINDS = hwprofile.PERIPHERALS


def profile(**statuses):
    """A hand-made profile; kinds not named are not-referenced."""
    return {"schema": 1, "static": {}, "dynamic": {}, "notes": [],
            "peripherals": {k: {"status": statuses.get(k, "not-referenced"), "evidence": []}
                            for k in KINDS}}


def fw(root, iid, brand="Acme", name="router.bin", arch="mipseb", result="true", ping="true",
       web="true", prof=None, raw_profile=None):
    d = root / str(iid)
    d.mkdir()
    for fname, value in (("brand", brand), ("name", name), ("architecture", arch),
                         ("result", result), ("ping", ping), ("web", web)):
        if value is not None:
            data = value if isinstance(value, bytes) else (value + "\n").encode()
            (d / fname).write_bytes(data)
    if raw_profile is not None:
        (d / "hw_profile.json").write_bytes(raw_profile)
    elif prof is not None:
        (d / "hw_profile.json").write_text(json.dumps(prof))
    return d


def run(root, *args):
    return hwreport.main(["--scratch", str(root)] + list(args))


def report(root):
    return hwreport.build_report(str(root))


def rows_by_iid(rep):
    return {r["iid"]: r for r in rep["firmware"]}


@pytest.fixture
def scratch(tmp_path):
    root = tmp_path / "scratch"
    root.mkdir()
    return root


@pytest.fixture
def sample(scratch):
    fw(scratch, 1, "Dlink", "DIR-868L", "armel", prof=profile(i2c="unsupported", gpio="referenced"))
    fw(scratch, 2, "Netgear", "WNAP320", "mipseb", web="false", ping="false", result="false",
       prof=profile(gpio="failing", watchdog="covered", spi="unsupported"))
    fw(scratch, 10, "Tplink", "WR841", "mipsel", prof=profile())
    fw(scratch, 11, "Tplink", "NoProfile", "mipsel")
    return scratch


# ------------------------------------------------------------------ constants

def test_constants_match_pipeline_and_config():
    assert set(hwreport.STATUSES) == set(pipeline.HW_STATUSES)
    assert set(hwreport.PERIPHERALS) == set(pipeline.HW_KINDS)
    assert tuple(hwreport.LOUD) == tuple(pipeline.HW_LOUD)
    assert hwreport.ARCHS == tuple(config.VALID_ARCHS)


# ------------------------------------------------------------------ aggregates

def test_aggregates_golden(sample):
    agg = report(sample)["aggregate"]
    assert agg["total"] == 4
    assert agg["profile"] == {"ok": 3, "missing": 1, "invalid": 0}
    assert agg["without_profile"] == 1
    assert agg["flag_true"] == {"result": 3, "ping": 3, "web": 3}
    assert agg["arch"] == {"armel": 1, "mipseb": 1, "mipsel": 2, "other": 0, "missing": 0}
    ps = agg["peripheral_status"]
    assert ps["i2c"] == {"not-referenced": 2, "referenced": 0, "failing": 0, "covered": 0,
                         "unsupported": 1, "missing": 1, "invalid": 0}
    assert ps["gpio"]["referenced"] == 1 and ps["gpio"]["failing"] == 1
    assert ps["watchdog"]["covered"] == 1
    assert ps["spi"]["unsupported"] == 1
    for kind in KINDS:                                      # every row counted once per peripheral
        assert sum(ps[kind].values()) == 4
    cross = agg["web_crosstab"]
    assert cross["i2c"]["unsupported"] == {"web_true": 1, "web_false": 0}   # unsupported but web=true
    assert cross["spi"]["unsupported"] == {"web_true": 0, "web_false": 1}
    assert cross["gpio"]["failing"] == {"web_true": 0, "web_false": 1}
    assert cross["gpio"]["unsupported"] == {"web_true": 0, "web_false": 0}
    unsup = agg["unsupported_firmware"]
    assert [(u["iid"], u["peripherals"], u["web"]) for u in unsup] == [
        (1, ["i2c"], True), (2, ["spi"], False)]
    assert [(u["iid"], u["peripherals"]) for u in agg["failing_firmware"]] == [(2, ["gpio"])]


def test_rows_sorted_numerically_and_fields(sample):
    rep = report(sample)
    assert [r["iid"] for r in rep["firmware"]] == [1, 2, 10, 11]       # 10 after 2
    r = rows_by_iid(rep)[2]
    assert (r["brand"], r["name"], r["arch"]) == ("Netgear", "WNAP320", "mipseb")
    assert (r["result"], r["ping"], r["web"]) == (False, False, False)
    assert r["profile"] == "ok" and list(r["peripherals"]) == list(KINDS)
    assert rows_by_iid(rep)[11]["peripherals"] == dict.fromkeys(KINDS, "missing")


def test_real_build_profile_unsupported(scratch):
    prof = hwprofile.build_profile({"device_paths": {"/dev/i2c-0": {"count": 3},
                                                     "/dev/gpio": {"count": 1}}})
    fw(scratch, 5, prof=prof)
    r = rows_by_iid(report(scratch))[5]
    assert r["peripherals"]["i2c"] == "unsupported" and r["peripherals"]["gpio"] == "referenced"
    assert r["profile"] == "ok" and r["dynamic"] is False
    assert report(scratch)["aggregate"]["unsupported_firmware"][0]["iid"] == 5


def test_unsupported_never_presented_as_success(sample):
    md = hwreport.render_md(report(sample))
    section = md.split("## Firmware with an UNSUPPORTED peripheral")[1].split("## ")[0]
    assert "1 Dlink" in section and "web=true" in section and "Not a success" in section


# ------------------------------------------------------------- missing / invalid

def test_missing_files_and_profile_exit_zero(scratch, capsys):
    (scratch / "3").mkdir()                               # empty IID directory
    assert run(scratch, "--format", "csv") == 0
    row = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))[0]
    assert row["arch"] == "missing" and row["profile"] == "missing" and row["web"] == "false"
    assert row["brand"] == "" and row["gpio"] == "missing"


def test_invalid_profiles(scratch):
    huge = b'{"peripherals": {}, "pad": "' + b"A" * hwprofile.MAX_PROFILE_BYTES + b'"}'
    deep = b"[" * 100000 + b"]" * 100000
    bad = {
        20: b"{not json",
        21: b"[1, 2]",
        22: json.dumps({"peripherals": [1]}).encode(),
        23: b"\xff\xfe\x00",
        24: huge,
        25: deep,
        26: b"",
        27: b'{"x": 1e999999999999}x',
    }
    for iid, raw in bad.items():
        fw(scratch, iid, raw_profile=raw)
    # symlink, FIFO, directory in place of the profile
    d = fw(scratch, 30)
    (d / "hw_profile.json").symlink_to(d / "brand")
    d = fw(scratch, 31)
    os.mkfifo(str(d / "hw_profile.json"))
    d = fw(scratch, 32)
    (d / "hw_profile.json").mkdir()
    rows = rows_by_iid(report(scratch))
    for iid in list(bad) + [30, 31, 32]:
        assert rows[iid]["profile"] == "invalid", iid
        assert set(rows[iid]["peripherals"].values()) == {"invalid"}, iid
    agg = report(scratch)["aggregate"]
    assert agg["profile"]["invalid"] == len(bad) + 3 and agg["without_profile"] == 0


def test_profile_at_exact_cap_is_read(scratch):
    base = json.dumps(profile(gpio="failing"))
    pad = hwprofile.MAX_PROFILE_BYTES - len(base) - 2
    raw = base[:-1] + ', "pad": "' + "A" * (pad - 12) + '"}'
    raw = raw.encode()
    assert len(raw) <= hwprofile.MAX_PROFILE_BYTES
    fw(scratch, 4, raw_profile=raw)
    assert rows_by_iid(report(scratch))[4]["peripherals"]["gpio"] == "failing"


def test_symlinked_and_fifo_text_files(scratch):
    d = fw(scratch, 6, brand=None, name=None, web=None)
    (scratch / "secret").write_text("true\n")
    (d / "web").symlink_to(scratch / "secret")            # would read "true" through the link
    os.mkfifo(str(d / "brand"))                           # open must not block
    (d / "name").write_bytes(b"x" * (hwreport.MAX_LINE_BYTES + 1))
    r = rows_by_iid(report(scratch))[6]
    assert r["web"] is False and r["brand"] == "" and r["name"] == ""


def test_text_file_exactly_at_cap(scratch):
    fw(scratch, 7, name=b"n" * hwreport.MAX_LINE_BYTES)
    r = rows_by_iid(report(scratch))[7]
    assert r["name"] == "n" * (hwreport.MAX_NAME - 3) + "..."


# ------------------------------------------------------------------ directory walk

def test_symlinked_iid_dir_and_odd_names(scratch, tmp_path):
    fw(scratch, 1, prof=profile())
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "brand").write_text("Evil\n")
    (scratch / "2").symlink_to(outside, target_is_directory=True)
    (scratch / "3").symlink_to(scratch / "nonexistent")   # dangling
    for odd in ("abc", "0", "-1", "007", "1.5", "1e3", "٣", "12 ", " 12", "x1"):
        (scratch / odd).mkdir()
        (scratch / odd / "brand").write_text("Odd\n")
    (scratch / "9").write_text("regular file named like an IID")
    (scratch / "99999999999999999999").mkdir()            # too many digits
    (scratch / "notes.txt").write_text("x")
    rep = report(scratch)
    assert [r["iid"] for r in rep["firmware"]] == [1]
    info = rep["aggregate"]["scan"]
    assert info["skipped_not_directory"] == 3 and info["skipped_non_iid"] == 12


def test_iid_cap(scratch, monkeypatch):
    monkeypatch.setattr(hwreport, "MAX_IIDS", 3)
    for i in (5, 3, 1, 4, 2):
        fw(scratch, i)
    rep = report(scratch)
    assert [r["iid"] for r in rep["firmware"]] == [1, 2, 3]            # the smallest, deterministic
    assert rep["aggregate"]["scan"]["iids_dropped_over_cap"] == 2
    assert "WARNING: incomplete scan" in hwreport.render_md(rep)


def test_entry_cap(scratch, monkeypatch):
    monkeypatch.setattr(hwreport, "MAX_ENTRIES", 4)
    for i in range(1, 9):
        fw(scratch, i)
    rep = report(scratch)
    assert len(rep["firmware"]) <= 4 and rep["aggregate"]["scan"]["entries_truncated"] is True


def test_unreadable_root(tmp_path, capsys):
    assert hwreport.main(["--scratch", str(tmp_path / "nope")]) == 2
    f = tmp_path / "file"
    f.write_text("x")
    assert hwreport.main(["--scratch", str(f)]) == 2
    assert "cannot read scratch root" in capsys.readouterr().err


def test_usage_errors():
    with pytest.raises(SystemExit) as e:
        hwreport.main(["--format", "xml"])
    assert e.value.code == 2


def test_empty_root(scratch, capsys):
    assert run(scratch) == 0
    assert "firmware: 0" in capsys.readouterr().out
    assert report(scratch)["aggregate"]["total"] == 0


# ------------------------------------------------------------------ untrusted values

def test_unknown_statuses_become_invalid(scratch):
    prof = profile()
    prof["peripherals"]["gpio"]["status"] = "UNSUPPORTED"                 # wrong case
    prof["peripherals"]["i2c"]["status"] = "ok\x1b[31m; rm -rf /"
    prof["peripherals"]["spi"]["status"] = ["unsupported"]
    prof["peripherals"]["led"] = "covered"                                # not a dict
    prof["peripherals"]["mtd"] = {"evidence": []}                         # no status
    prof["peripherals"]["wlan"]["status"] = 7
    del prof["peripherals"]["uart"]
    prof["peripherals"]["bogus"] = {"status": "unsupported"}              # unknown kind: ignored
    fw(scratch, 8, prof=prof)
    r = rows_by_iid(report(scratch))[8]["peripherals"]
    assert [r[k] for k in ("gpio", "i2c", "spi", "led", "mtd", "wlan")] == ["invalid"] * 6
    assert r["uart"] == "missing" and "bogus" not in r
    agg = report(scratch)["aggregate"]
    assert agg["unsupported_firmware"] == []
    out = hwreport.render_json(report(scratch)) + hwreport.render_md(report(scratch))
    assert "\x1b" not in out and "rm -rf" not in out


def test_architecture_and_booleans(scratch):
    fw(scratch, 1, arch="x86_64")
    fw(scratch, 2, arch="mipsel\x1b[2J")
    fw(scratch, 3, arch=None)
    fw(scratch, 4, arch="armel", result="True", ping="1", web="true false")
    fw(scratch, 5, arch="armel", result=b"true", ping=b"true\r\n", web=b" true ")
    rows = rows_by_iid(report(scratch))
    assert [rows[i]["arch"] for i in (1, 2, 3)] == ["other", "other", "missing"]
    assert [rows[4][k] for k in hwreport.BOOL_FILES] == [False, False, False]
    assert [rows[5][k] for k in hwreport.BOOL_FILES] == [True, True, True]


HOSTILE = [
    "=HYPERLINK(\"http://evil\",\"x\")", "+1+1", "-2+3", "@SUM(A1)", "=cmd|' /C calc'!A0",
    "a | b | c", "line1\nline2\r\n| injected | row |", "\x1b[31mred\x1b]0;title\x07",
    "<script>alert(1)</script>", "[x](javascript:alert(1))", "`code` *bold* _it_ # h",
    "A" * 10000, "‮txt.exe", "tab\there", "&amp; &#x3c;",
]


@pytest.mark.parametrize("fmt", ["md", "csv", "json"])
def test_hostile_text_every_format(scratch, capsys, fmt):
    for i, text in enumerate(HOSTILE, 1):
        fw(scratch, i, brand=text.encode("utf-8", "replace"), name=text.encode("utf-8", "replace"),
           prof=profile(i2c="unsupported"))
    assert run(scratch, "--format", fmt) == 0
    out = capsys.readouterr().out
    assert all(c == "\n" or 0x20 <= ord(c) < 0x7F for c in out)      # no ESC, CR, tab, non-ASCII
    if fmt == "md":
        assert "<" not in out.replace("&lt;", "")             # no raw HTML in Markdown
    if fmt == "json":
        data = json.loads(out)
        for r in data["firmware"]:
            assert len(r["brand"]) <= hwreport.MAX_BRAND and len(r["name"]) <= hwreport.MAX_NAME
    elif fmt == "csv":
        rows = list(csv.reader(io.StringIO(out)))
        assert len(rows) == len(HOSTILE) + 1
        assert {len(r) for r in rows} == {9 + len(KINDS)}            # newlines did not add rows
        for r in rows[1:]:
            for cell in (r[1], r[2]):
                assert not cell.startswith(("=", "+", "-", "@", "\t", "\r"))
        assert rows[1][1].startswith("'=HYPERLINK")
        assert rows[3][1].startswith("'-2")
    else:
        lines = out.split("\n")
        table = [ln for ln in lines if ln.startswith("| ") and ln.count("|") > 5]
        per_fw = [ln for ln in table if re.match(r"\| \d+ \|", ln)]
        assert len(per_fw) == len(HOSTILE)
        # same number of unescaped pipes in every row: a hostile pipe cannot add a cell
        counts = {len(re.findall(r"(?<!\\)\|", ln)) for ln in per_fw}
        assert counts == {8 + len(KINDS) + 1}
        assert not any(ln.startswith("| injected") for ln in lines)
        assert "](javascript" not in out and "\\[x\\]" in out


def test_csv_formula_prefix_helper():
    for bad in ("=1", "+1", "-1", "@a", "\tx", "\rx"):
        assert hwreport.csv_cell(bad) == "'" + bad
    assert hwreport.csv_cell("DIR-868L") == "DIR-868L" and hwreport.csv_cell("") == ""


def test_csv_cell_leading_whitespace_values():
    # spreadsheets skip leading blanks, so a space-prefixed formula must be escaped too
    assert hwreport.csv_cell(" =1+1") == "' =1+1"
    assert hwreport.csv_cell("  @x") == "'  @x"
    assert hwreport.csv_cell("\t-2") == "'\t-2"
    assert hwreport.csv_cell("   ") == "   " and hwreport.csv_cell(" a=1") == " a=1"


def test_csv_render_escapes_whitespace_prefixed_formulas(scratch):
    for iid, brand, name in ((1, " =1+1", "  @x"), (2, "\t-2", "\t=cmd")):
        fw(scratch, iid, brand=brand, name=name)
    rows = list(csv.reader(io.StringIO(hwreport.render_csv(report(scratch)))))[1:]
    assert [(r[1], r[2]) for r in rows] == [("'=1+1", "'@x"), ("'-2", "'=cmd")]


def test_text_cleanup(scratch):
    fw(scratch, 1, brand=b"Br\x00and\xff\xfe\nsecond line", name=b"  \x1b[0m  spaced  ")
    r = rows_by_iid(report(scratch))[1]
    assert r["brand"] == "Br?and??"                                   # first line only
    assert r["name"] == "?[0m  spaced"                                # leading blanks stripped


# ------------------------------------------------------------------ determinism

def test_deterministic_output_all_formats(sample, capsys):
    outs = {}
    for fmt in ("md", "csv", "json"):
        run(sample, "--format", fmt)
        first = capsys.readouterr().out
        run(sample, "--format", fmt)
        assert capsys.readouterr().out == first and first.endswith("\n")
        outs[fmt] = first
    data = json.loads(outs["json"], object_pairs_hook=lambda p: p)   # preserves key order
    top = [k for k, _ in data]
    assert top == ["firmware", "aggregate"]
    agg = dict(data)["aggregate"]
    assert [k for k, _ in agg] == ["total", "profile", "without_profile", "flag_true", "arch",
                                   "peripheral_status", "web_crosstab", "unsupported_firmware",
                                   "failing_firmware", "scan"]
    ps = dict(agg)["peripheral_status"]
    assert [k for k, _ in ps] == list(KINDS)
    assert [k for k, _ in ps[0][1]] == list(hwreport.ALL_STATUSES)
    # creation order of directories must not matter
    assert outs["csv"].splitlines()[1].startswith("1,Dlink,DIR-868L,armel,true,true,true,ok,true,")


def test_markdown_sections(sample):
    md = hwreport.render_md(report(sample))
    for heading in ("# FirmAE hardware report", "## Summary", "## Firmware with an UNSUPPORTED",
                    "## Firmware with a FAILING", "## Peripheral by status",
                    "## Emulation outcome (web)", "## Per firmware"):
        assert heading in md
    assert "- without profile: 1" in md and "- firmware: 4" in md
    assert "- 2 Netgear / WNAP320 (web=false): spi" in md.replace("\\", "")


# ------------------------------------------------------------------ --out

def test_out_writes_file(sample, tmp_path, capsys):
    out = tmp_path / "report.json"
    assert run(sample, "--format", "json", "--out", str(out)) == 0
    assert capsys.readouterr().out == ""
    assert json.loads(out.read_text())["aggregate"]["total"] == 4


def test_out_existing_file_refused_by_default(sample, tmp_path, capsys):
    out = tmp_path / "report.csv"
    out.write_text("precious")
    assert run(sample, "--format", "csv", "--out", str(out)) == 2
    assert out.read_text() == "precious"
    assert "already exists" in capsys.readouterr().err
    assert run(sample, "--format", "csv", "--out", str(out), "--force") == 0
    assert out.read_text() != "precious"


def test_out_force_overwrites_without_trailing_garbage(sample, tmp_path):
    out = tmp_path / "report.csv"
    out.write_text("old" * 100000)
    assert run(sample, "--format", "csv", "--out", str(out), "--force") == 0
    fresh = tmp_path / "fresh.csv"
    assert run(sample, "--format", "csv", "--out", str(fresh)) == 0
    assert out.read_bytes() == fresh.read_bytes() and out.read_bytes().startswith(b"iid,brand,")
    # --force on a missing path simply creates it
    new = tmp_path / "new.csv"
    assert run(sample, "--format", "csv", "--out", str(new), "--force") == 0
    assert new.read_bytes() == fresh.read_bytes()


def test_out_refuses_symlink(sample, tmp_path, capsys):
    target = tmp_path / "victim"
    target.write_text("keep me")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert run(sample, "--out", str(link)) == 2
    assert run(sample, "--out", str(link), "--force") == 2
    assert target.read_text() == "keep me" and link.is_symlink()
    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "created-through-link")
    assert run(sample, "--out", str(dangling)) == 2
    assert not (tmp_path / "created-through-link").exists()
    assert "hwreport:" in capsys.readouterr().err


def test_out_refuses_hardlink_fifo_dir(sample, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    hard = tmp_path / "hard"
    os.link(str(victim), str(hard))
    for extra in ((), ("--force",)):
        assert run(sample, "--out", str(hard), *extra) == 2 and victim.read_text() == "keep me"
    fifo = tmp_path / "fifo"
    os.mkfifo(str(fifo))
    for extra in ((), ("--force",)):
        assert run(sample, "--out", str(fifo), *extra) == 2
        assert run(sample, "--out", str(tmp_path), *extra) == 2
    assert run(sample, "--out", str(tmp_path / "no" / "dir" / "x")) == 2


# ------------------------------------------------------------------ CLI as a process

def test_cli_process_stdout_and_exit_code(sample):
    env = dict(os.environ, PYTHONPATH=REPO)
    res = subprocess.run([sys.executable, "-m", "firmae.hwreport", "--scratch", str(sample),
                          "--format", "json"], cwd=REPO, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=120)
    assert res.returncode == 0 and res.stderr == b""
    assert json.loads(res.stdout)["aggregate"]["total"] == 4
    res = subprocess.run([sys.executable, "-m", "firmae.hwreport", "--help"], cwd=REPO, env=env,
                         stdout=subprocess.PIPE, timeout=120)
    assert res.returncode == 0 and b"never counted as success" in res.stdout


def test_default_scratch_falls_back(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no config")
    monkeypatch.setattr(config, "load", boom)
    assert hwreport.default_scratch() == "scratch"


def test_fifo_with_data_is_not_read(scratch):
    """A FIFO that already holds "true" must not count: only regular files are read."""
    d = fw(scratch, 12, brand=None, web=None)
    os.mkfifo(str(d / "web"))
    keep = os.open(str(d / "web"), os.O_RDWR)            # a writer, so a read would return data
    try:
        os.write(keep, b"true\n")
        assert rows_by_iid(report(scratch))[12]["web"] is False
    finally:
        os.close(keep)
