"""Tests for analyses/fuzzer/fwscan.py, the shell-free replacement for the
fuzzer's `find | strings | grep` pipelines (SECURITY.md S1, REFACTORING_PLAN 2.1).
"""

import os
import signal
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "analyses", "fuzzer"))
import fwscan  # noqa: E402

BINARY = (b"\x7fELF\x00\x01\x02index.cgi\x00ab\x00login.cgi\x00?user=\x00pass=\x00"
          b"X-Auth:\x00Cookie:\x00tiny\x00urn:schemas-upnp-org:service:WANIPConnection:1\x00"
          b"\xff\xfe" * 10)


def make_tree(root, names_exec=("www/cgi-bin/apply.cgi", "sbin/httpcgi")):
    for rel in names_exec:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(BINARY)
        p.chmod(0o755)
    (root / "www" / "index.htm").write_text('<form action="apply.cgi"><input name="a"></form>')
    (root / "www" / "hnap").mkdir()
    (root / "www" / "hnap" / "GetDeviceSettings.xml").write_text("<soap:Envelope>\n</soap:Envelope>\n")
    (root / "www" / "app.js").write_text('result_xml.Set("/x/Enabled", "false");')
    (root / "etc").mkdir()
    (root / "etc" / "upnpd.conf").write_bytes(BINARY)
    return root


# ---------------------------------------------------------------- security

def test_file_names_are_never_executed(tmp_path, monkeypatch):
    """A firmware file name containing shell syntax must not run anything."""
    fw = tmp_path / "1"
    marker = tmp_path / "PWNED"
    evil = fw / "www" / ("a;touch %s;cgi" % marker)
    evil.parent.mkdir(parents=True)
    evil.write_bytes(BINARY)
    evil.chmod(0o755)
    monkeypatch.chdir(tmp_path)

    found = fwscan.find_entries("./1", "*cgi*", executable=True)
    assert found == ["./1/www/a;touch %s;cgi" % marker]
    assert fwscan.strings_matching(found[0], r"^/?[A-Za-z0-9]+\.cgi$") == ["index.cgi", "login.cgi"]
    assert fwscan.grep_files("./1", rb"cgi") == found
    assert not marker.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinks_out_of_the_tree_are_not_read(tmp_path):
    secret = tmp_path / "host_secret"
    secret.write_text("action= TOPSECRET result_xml.Set")
    fw = tmp_path / "fw"
    fw.mkdir()
    (fw / "evil.cgi").symlink_to(secret)
    (fw / "evil.htm").symlink_to(secret)
    assert fwscan.strings_of(str(fw / "evil.cgi")) == []
    assert fwscan.grep_files(str(fw), rb"action=", ignore_case=True) == []
    assert fwscan.grep_lines(str(fw), rb"TOPSECRET") == []
    # the symlink itself is still listed by find_entries, like `find`
    assert fwscan.find_entries(str(fw), "*.cgi") == [str(fw / "evil.cgi")]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_fifos_and_devices_do_not_block(tmp_path):
    fw = tmp_path / "fw"
    fw.mkdir()
    os.mkfifo(fw / "pipe.htm")
    (fw / "real.htm").write_text("action=x")
    signal.alarm(10)          # fail instead of hanging forever if a FIFO is opened
    try:
        assert fwscan.grep_files(str(fw), rb"action=", ignore_case=True) == [str(fw / "real.htm")]
        assert fwscan.strings_of(str(fw / "pipe.htm")) == []
    finally:
        signal.alarm(0)


# ---------------------------------------------------------------- behaviour

def test_strings_follow_gnu_rules(tmp_path):
    f = tmp_path / "b"
    f.write_bytes(b"abc\x00abcd\x00tab\there\x00\x80\x81longer string\n")
    assert fwscan.strings_of(str(f)) == ["abcd", "tab\there", "longer string"]


def test_strings_matching_sorts_and_dedups(tmp_path):
    f = tmp_path / "b"
    f.write_bytes(b"zeta.cgi\x00alpha.cgi\x00zeta.cgi\x00nope.cgi.bak\x00")
    assert fwscan.strings_matching(str(f), r"^/?[A-Za-z0-9]+\.cgi$") == ["alpha.cgi", "zeta.cgi"]


def test_missing_root_yields_nothing(tmp_path):
    assert fwscan.find_entries(str(tmp_path / "nope"), "*") == []
    assert fwscan.grep_files(str(tmp_path / "nope"), rb"x") == []
    assert fwscan.strings_of(str(tmp_path / "nope")) == []


def test_long_printable_run_with_trailing_binary_is_linear(tmp_path):
    """A regex `[...]*\\Z` search was quadratic here (4 MB took hours)."""
    import time
    f = tmp_path / "big"
    f.write_bytes(b"a" * (4 << 20) + b"\x00tail string")
    t = time.time()
    got = fwscan.strings_of(str(f))
    assert time.time() - t < 10
    assert [len(s) for s in got] == [4 << 20, 11]


@pytest.mark.parametrize("buf,tail", [
    (b"", b""), (b"abc", b"abc"), (b"abc\x00", b""), (b"ab\x00cd\t e", b"cd\t e"),
    (b"\xffabc ~", b"abc ~"), (b"abc\x7f", b""), (b"abc\x1f", b""),
])
def test_printable_tail(buf, tail):
    import re
    assert fwscan._printable_tail(buf) == tail
    assert fwscan._printable_tail(buf) == re.compile(rb"[\t\x20-\x7e]*\Z").search(buf).group(0)


# ------------------------------------------------- equivalence with GNU tools

def sh(cmd, cwd):
    """Run the ORIGINAL pipeline (benign file names only) for comparison."""
    out = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True).stdout
    return out.split("\n")[:-1]


@pytest.mark.linux
@pytest.mark.parametrize("regex", [r"^/?[A-Za-z0-9]+\.cgi$", r"^(\?)?[A-Za-z0-9]+=$",
                                   r"^(\?)?[A-Za-z0-9]+:$"])
def test_equivalent_to_strings_grep_sort_uniq(tmp_path, regex):
    root = make_tree(tmp_path / "1")
    path = "./1/www/cgi-bin/apply.cgi"
    old = sh("strings %s | grep -P '%s' | sort | uniq" % (path, regex), tmp_path)
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert fwscan.strings_matching(path, regex) == sorted(old)
    finally:
        os.chdir(old_cwd)


@pytest.mark.linux
@pytest.mark.parametrize("old_cmd,kwargs", [
    ('find ./1 -executable -iname "*cgi*"', dict(pattern="*cgi*", executable=True)),
    ('find ./1 -iname "*.cgi"', dict(pattern="*.cgi")),
    ('find ./1 -name "*upnp*"', dict(pattern="*upnp*", ignore_case=False)),
])
def test_equivalent_to_find(tmp_path, monkeypatch, old_cmd, kwargs):
    make_tree(tmp_path / "1")
    old = sorted(sh(old_cmd, tmp_path))
    monkeypatch.chdir(tmp_path)
    assert fwscan.find_entries("./1", **kwargs) == old


@pytest.mark.linux
@pytest.mark.parametrize("old_cmd,regex", [
    ('egrep -ril "action=" ./1', rb"action="),
    ('egrep -ril "result_xml.Set" ./1', rb"result_xml.Set"),
])
def test_equivalent_to_grep_ril(tmp_path, monkeypatch, old_cmd, regex):
    make_tree(tmp_path / "1")
    old = sorted(sh(old_cmd, tmp_path))
    monkeypatch.chdir(tmp_path)
    assert fwscan.grep_files("./1", regex, ignore_case=True) == old
