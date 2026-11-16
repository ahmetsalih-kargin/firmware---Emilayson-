"""Robustness of analyses/fuzzer/fuzzer.py and analyses/analyses_all.sh against
hostile firmware content and guest-written logs (no network, no emulation)."""

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "analyses" / "fuzzer"))
pytest.importorskip("bs4")
pytest.importorskip("requests")
fuzzer = pytest.importorskip("fuzzer")


# ---------------------------------------------------------------- comments

CASES = [
    b"a<!-- x -->b",
    b"a<!--\nmulti\nline\n-->b<!--two-->c",
    b"unclosed <!-- never ends",
    b"<!-->x-->y",
    b"<!---->",
    b"no comments",
    b"<!-- a --> <!-- b",
]


@pytest.mark.parametrize("data", CASES)
def test_strip_html_comments_matches_dotall_regex(data):
    assert fuzzer.strip_html_comments(data) == re.sub(b"<!--.*?-->", b"", data, flags=re.DOTALL)


def test_strip_html_comments_is_linear_on_unclosed_markers():
    data = b"<!--" * 500000
    t = time.time()
    assert fuzzer.strip_html_comments(data) == data
    assert time.time() - t < 5


def test_readhtml_removes_multiline_comments(tmp_path):
    f = tmp_path / "a.htm"
    f.write_bytes(b"<p>x</p><!-- <form action='/evil'>\n</form> --><p>y</p>")
    assert fuzzer.readHTML(str(f)) == "<p>x</p><p>y</p>"


def test_readhtml_non_utf8_raises_decode_error(tmp_path):
    f = tmp_path / "a.htm"
    f.write_bytes(b"\xff\xfe\x80")
    with pytest.raises(UnicodeDecodeError):
        fuzzer.readHTML(str(f))


# ---------------------------------------------------------------- serial log

def test_parse_execve_index():
    p = fuzzer.parse_execve_index
    assert p("[ANALYZE] d34d7", 10) == 7
    assert p("[ANALYZE] D34D123", 10) == 1          # trailing digits dropped
    assert p("[ANALYZE] d34d", 10) is None           # no digits
    assert p("[ANALYZE] d34dxyz", 10) is None
    assert p("[ANALYZE] d34d" + "9" * 5000, 10) is None   # int() would raise / be huge
    assert p("[ANALYZE] d34d10", 10) == 10           # == length: caller must bound-check


def test_get_execve_log_skips_hostile_lines(tmp_path, monkeypatch):
    (tmp_path / "qemu.final.serial.log").write_bytes(
        b"[ANALYZE] d34d\n"
        b"[ANALYZE] d34d" + b"9" * 6000 + b"\n"
        b"[ANALYZE] something d34d3 run\n"
        b"[ANALYZE] D34D3\n"
        b"noise d34d5\n"
        b"[ANALYZE] d34d4\n")
    monkeypatch.setattr(fuzzer, "WORK_DIR", str(tmp_path))
    assert fuzzer.get_execve_log(10) == [3, 4]


def test_main_ignores_index_equal_to_dummy_length(monkeypatch, capsys):
    dummy = [["cookie", 80, "i:"], ["cookie", 81, "i:"]]
    fuzzed = []
    monkeypatch.setattr(fuzzer, "preprocess", lambda: None)
    monkeypatch.setattr(fuzzer, "get_open_port", lambda: [{"port": "80"}])
    monkeypatch.setattr(fuzzer, "extract_image", lambda: None)
    monkeypatch.setattr(fuzzer, "get_information", lambda: ({}, {}, [], {}))
    monkeypatch.setattr(fuzzer, "clear_image", lambda: None)
    monkeypatch.setattr(fuzzer, "send_dummy", lambda *a: dummy)
    monkeypatch.setattr(fuzzer.time, "sleep", lambda s: None)
    monkeypatch.setattr(fuzzer, "get_execve_log", lambda n: [0, 2, 99, 1])
    monkeypatch.setattr(fuzzer, "fuzz", fuzzed.append)
    fuzzer.main()
    assert fuzzed == [dummy[0], dummy[1]]


def test_main_cleans_up_when_get_information_raises(monkeypatch):
    calls = []
    monkeypatch.setattr(fuzzer, "preprocess", lambda: None)
    monkeypatch.setattr(fuzzer, "get_open_port", lambda: [{"port": "80"}])
    monkeypatch.setattr(fuzzer, "extract_image", lambda: calls.append("extract"))
    monkeypatch.setattr(fuzzer, "clear_image", lambda: calls.append("clear"))

    def boom():
        raise RuntimeError("boom")

    monkeypatch.setattr(fuzzer, "get_information", boom)
    with pytest.raises(RuntimeError):
        fuzzer.main()
    assert calls == ["extract", "clear"]


# ---------------------------------------------------------------- html / hnap

@pytest.mark.parametrize("line,expected", [
    ('result_xml.Set("a/b/Enabled", "false");', ("Enabled", "false")),
    ('result_xml.Set("a/b/Name", "x,y");', ("Name", "x,y")),          # extra comma: was ValueError
    ('result_xml.Set("a/b/Name", "");', None),
    ('result_xml.Set("a/b/Name", x);', None),
    ('result_xml.Set("a/b/Name", ");', None),
    ('result_xml.Set(a,b);', None),                                    # short value: was IndexError
    ('result_xml.Set(a,);', None),
])
def test_parse_hnap_set(line, expected):
    assert fuzzer.parse_hnap_set(line) == expected


def test_get_information_skips_non_utf8_files(tmp_path, monkeypatch):
    root = tmp_path / "1"
    (root / "www" / "hnap").mkdir(parents=True)
    (root / "www" / "bad.htm").write_bytes(b"action=\xff\xfe<form action='/x'>")
    (root / "www" / "bad.js").write_bytes(b"result_xml.Set \xff\xfe")
    (root / "www" / "hnap" / "Bad.xml").write_bytes(b"<soap:Envelope>\xff\xfe")
    (root / "www" / "good.htm").write_text('<form action="/go"><input name="a" value="1"></form> action=')
    (root / "www" / "good.js").write_text('result_xml.Set("p/Mode", "DENY", 1);\nresult_xml.Set("p/Ok", "Disable");')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fuzzer, "IID", "1")
    monkeypatch.setattr(fuzzer, "key_value_map", {})
    cgi_map, hnap_map, ssdp, action_map = fuzzer.get_information()
    assert hnap_map == {}
    assert action_map == {"/go": [["get", {"a": "1"}]]}
    assert fuzzer.key_value_map == {"Ok": "Enable"}


# ---------------------------------------------------------------- sockets

class FakeSock:
    instances = []

    def __init__(self, *a):
        self.closed = False
        self.fail = FakeSock.fail
        FakeSock.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.closed = True

    def settimeout(self, t):
        pass

    def connect(self, addr):
        if self.fail:
            raise OSError("refused")

    def send(self, data):
        return len(data)

    def recv(self, n):
        return b"reply"

    def sendto(self, data, addr):
        if self.fail:
            raise OSError("unreachable")


@pytest.fixture
def fake_socket(monkeypatch):
    FakeSock.instances = []
    FakeSock.fail = False
    ns = type("S", (), {"socket": FakeSock, "AF_INET": 2, "SOCK_STREAM": 1, "SOCK_DGRAM": 2})
    monkeypatch.setattr(fuzzer, "socket", ns)
    monkeypatch.setattr(fuzzer.time, "sleep", lambda s: None)
    monkeypatch.setattr(fuzzer, "TARGET", "192.0.2.1")
    return FakeSock


def test_send_packet_closes_socket(fake_socket):
    assert fuzzer.send_packet(80, "x") == b"reply"
    assert fake_socket.instances[0].closed


def test_send_packet_closes_socket_on_error(fake_socket):
    fake_socket.fail = True
    assert fuzzer.send_packet(80, "x") == b""
    assert fake_socket.instances[0].closed


def test_send_packet_does_not_swallow_keyboard_interrupt(fake_socket, monkeypatch):
    monkeypatch.setattr(FakeSock, "recv", lambda self, n: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        fuzzer.send_packet(80, "x")


def test_send_udp_packet_closes_socket_and_survives_errors(fake_socket):
    fuzzer.send_udp_packet(1900, "x")
    assert fake_socket.instances[0].closed
    fake_socket.fail = True
    fuzzer.send_udp_packet(1900, "x")
    assert fake_socket.instances[1].closed


# ---------------------------------------------------------------- tar

def test_extract_image_does_not_restore_owner_or_permissions(tmp_path, monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fuzzer, "IID", "7")
    monkeypatch.setattr(fuzzer.subprocess, "run", fake_run)
    fuzzer.extract_image()
    argv = seen["argv"]
    assert argv[0] == "tar"
    assert "--no-same-owner" in argv and "--no-same-permissions" in argv
    assert argv[argv.index("-C") + 1] == "./7"


# ---------------------------------------------------------------- shell script

@pytest.mark.skipif(sys.platform == "win32", reason="needs bash")
class TestAnalysesAll:
    def _setup(self, tmp_path, rsf=None, fuzzer_rc=0):
        w = tmp_path / "w"
        (w / "fuzzer").mkdir(parents=True)
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "sleep").write_text("#!/bin/bash\nexit 0\n")
        (tmp_path / "bin" / "sleep").chmod(0o755)
        (w / "firmae.config").write_text('get_scratch() { echo "%s/scratch/$1"; }\n' % tmp_path)
        shutil_copy = (REPO / "analyses" / "analyses_all.sh").read_bytes()
        (w / "analyses_all.sh").write_bytes(shutil_copy)
        for name, body in [("initializer.py", "exit 3"), ("nmap.sh", "exit 0"),
                           ("fuzzer/fuzzer.py", 'echo "$#" >> "%s/argc"; exit %d' % (tmp_path, fuzzer_rc))]:
            p = w / name
            p.write_text("#!/bin/bash\n%s\n" % body)
            p.chmod(0o755)
        if rsf is not None:
            (w / "routersploit").mkdir()
            p = w / "routersploit" / "rsf.py"
            p.write_text("#!/bin/bash\n%s\n" % rsf)
            p.chmod(0o755)
        return w

    def _run(self, w, tmp_path, brand="netgear"):
        env = dict(os.environ, PATH="%s/bin:%s" % (tmp_path, os.environ["PATH"]))
        res = subprocess.run(["bash", "analyses_all.sh", "5", brand, "192.0.2.1", "x"],
                             cwd=w, env=env, capture_output=True, text=True)
        log = tmp_path / "scratch" / "5" / "analysis_log"
        return res, log

    def test_missing_rsf_does_not_abort(self, tmp_path):
        w = self._setup(tmp_path)
        res, log = self._run(w, tmp_path)
        assert res.returncode == 0, res.stderr
        assert (log / "result").read_text() == "true\n"
        steps = (log / "steps").read_text().splitlines()
        assert steps == ["initializer 3", "nmap 0", "fuzzer_ci 0", "fuzzer_bof 0", "rsf 127"]
        assert "rsf.py not found" in res.stdout

    def test_failing_rsf_is_recorded_and_result_still_written(self, tmp_path):
        w = self._setup(tmp_path, rsf="exit 5", fuzzer_rc=2)
        res, log = self._run(w, tmp_path)
        assert res.returncode == 0, res.stderr
        assert (log / "result").read_text() == "true\n"
        steps = (log / "steps").read_text().splitlines()
        assert "fuzzer_ci 2" in steps and "fuzzer_bof 2" in steps and "rsf 5" in steps

    def test_empty_brand_does_not_shift_arguments(self, tmp_path):
        w = self._setup(tmp_path, rsf="exit 0")
        res, log = self._run(w, tmp_path, brand="")
        assert res.returncode == 0, res.stderr
        assert (tmp_path / "argc").read_text().split() == ["6", "6"]
        assert "rsf 0" in (log / "steps").read_text().splitlines()
