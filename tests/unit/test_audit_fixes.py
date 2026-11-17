"""Regression tests for the problems found in the Phase 5 review: memory use of the
firmware scanner, copies in getArch, orphaned processes after a normal exit,
SQL built from firmware text, shell use in helper scripts."""

import importlib.util
import os
import random
import subprocess
import sys
import time
import tracemalloc
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "analyses", "fuzzer"))
import fwscan  # noqa: E402
from scripts import getArch  # noqa: E402
from scripts.procgroup import run_with_timeout  # noqa: E402


# ----------------------------------------------------------- fwscan streaming

@pytest.fixture
def small_chunks(monkeypatch):
    monkeypatch.setattr(fwscan, "CHUNK", 7)
    monkeypatch.setattr(fwscan, "OVERLAP", 16)


def test_iter_strings_equals_a_whole_file_scan_for_any_block_size(tmp_path, small_chunks):
    rnd = random.Random(1)
    alphabet = b"abc XYZ\t\x00\x01\n\xff~"
    for n in range(40):
        data = bytes(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 300)))
        f = tmp_path / ("f%d" % n)
        f.write_bytes(data)
        expected = [m.decode("ascii") for m in fwscan._PRINTABLE.findall(data)]
        assert list(fwscan.iter_strings(str(f))) == expected, data


def test_string_and_match_straddling_a_block_boundary(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"\x00" * (fwscan.CHUNK - 3) + b"abcdefgh\x00" + b"x" * 5 + b"\x00" * (fwscan.CHUNK - 3) + b"acts")
    assert list(fwscan.iter_strings(str(f))) == ["abcdefgh", "xxxxx", "acts"]     # last one ends at EOF
    f.unlink()
    g = tmp_path / "g"
    g.write_bytes(b"\x00" * (fwscan.CHUNK - 3) + b"action=" + b"\x00" * 10)
    assert fwscan.grep_files(str(tmp_path), rb"action=") == [str(g)]


def test_overlong_printable_run_is_reported_in_pieces_not_buffered(tmp_path, monkeypatch):
    monkeypatch.setattr(fwscan, "CHUNK", 8)
    monkeypatch.setattr(fwscan, "MAX_RUN", 20)
    f = tmp_path / "f"
    f.write_bytes(b"a" * 100)
    pieces = list(fwscan.iter_strings(str(f)))
    assert "".join(pieces) == "a" * 100 and len(pieces) > 1


def test_scanning_a_large_file_needs_bounded_memory(tmp_path):
    big = tmp_path / "big.bin"
    block = os.urandom(1 << 20)
    with open(big, "wb") as f:
        for _ in range(48):
            f.write(block)
        f.write(b"\x00result_xml.Set\x00")
    tracemalloc.start()
    try:
        assert fwscan.grep_files(str(tmp_path), rb"result_xml.Set", ignore_case=True) == [str(big)]
        count = sum(1 for _ in fwscan.iter_strings(str(big)))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert count > 0
    assert peak < 16 << 20, "peak %d MB for a 48 MB file" % (peak >> 20)      # was about the file size and more


def test_grep_lines_still_returns_the_matching_lines(tmp_path):
    (tmp_path / "a.xml").write_bytes(b"x\n<soap:Envelope a/hnap/Foo.xml>\ny\n")
    (tmp_path / "b.xml").write_bytes(b"nothing\n")
    assert fwscan.grep_lines(str(tmp_path), rb"soap:Envelope") == \
        [(str(tmp_path / "a.xml"), "<soap:Envelope a/hnap/Foo.xml>")]


# ----------------------------------------------------------- getArch copies

def test_getarch_copies_only_the_header_of_a_member(tmp_path, monkeypatch):
    import io
    import tarfile
    monkeypatch.setattr(getArch, "HEAD_BYTES", 1024)
    tar = tmp_path / "1.tar.gz"
    with tarfile.open(tar, "w:gz") as t:
        data = b"\x00" * (3 << 20)
        info = tarfile.TarInfo("./bin/busybox")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    sizes = []
    real = subprocess.check_output
    monkeypatch.setattr(getArch.subprocess, "check_output",
                        lambda argv, **kw: (sizes.append(os.path.getsize(argv[1])), real(argv, **kw))[1])
    getArch.detect(str(tar))
    assert sizes == [1024]


# ----------------------------------------------------------- process groups

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
def test_normal_exit_leaves_no_background_process_behind(tmp_path):
    pidfile = tmp_path / "pid"
    rc, timed_out = run_with_timeout(["bash", "-c", "sleep 600 & echo $! > %s" % pidfile], 10)
    assert (rc, timed_out) == (0, False)
    pid = int(pidfile.read_text())
    for _ in range(50):
        try:
            with open("/proc/%d/stat" % pid) as f:
                if f.read().split(")")[-1].split()[0] == "Z":
                    break
        except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
            # reaped while /proc/<pid>/stat was being opened or read
            # (ENOENT / ESRCH / empty or truncated content): the process is gone
            break
        time.sleep(0.1)
    else:
        pytest.fail("background process %d survived" % pid)


# ----------------------------------------------------------- extractor SQL

def load_extractor():
    pytest.importorskip("magic")
    pytest.importorskip("binwalk")
    path = os.path.join(os.path.dirname(__file__), "..", "..", "sources", "extractor", "extractor.py")
    spec = importlib.util.spec_from_file_location("fw_extractor", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeDB:
    def __init__(self):
        self.executed = []

    def cursor(self):
        db = self

        class Cur:
            def execute(self, sql, params=None):
                db.executed.append((sql, params))

            def close(self):
                pass
        return Cur()

    def commit(self):
        pass

    def rollback(self):
        pass


def test_firmware_text_never_becomes_sql():
    ext = load_extractor()
    item = types.SimpleNamespace(database=FakeDB(), tag=5,
                                 UPDATABLE_FIELDS=ext.ExtractionItem.UPDATABLE_FIELDS)
    evil = "Linux kernel '; DROP TABLE image; --"
    assert ext.ExtractionItem.update_database(item, "kernel_version", evil) is True
    sql, params = item.database.executed[0]
    assert sql == "UPDATE image SET kernel_version=%s WHERE id=%s"
    assert params == (evil, 5) and "DROP" not in sql
    with pytest.raises(ValueError):
        ext.ExtractionItem.update_database(item, "kernel_version=1; DROP TABLE image; --", "x")
    assert len(item.database.executed) == 1


def test_update_database_without_a_working_cursor_does_not_raise_nameerror():
    ext = load_extractor()

    class Broken(FakeDB):
        def cursor(self):
            raise RuntimeError("connection lost")
    item = types.SimpleNamespace(database=Broken(), tag=1,
                                 UPDATABLE_FIELDS=ext.ExtractionItem.UPDATABLE_FIELDS)
    assert ext.ExtractionItem.update_database(item, "kernel_extracted", "True") is False


# ----------------------------------------------------------- helper scripts

@pytest.mark.linux
def test_infer_kernel_writes_what_the_old_shell_pipeline_wrote(repo_root, tmp_path):
    (tmp_path / "images").mkdir()
    (tmp_path / "scratch" / "3").mkdir(parents=True)
    (tmp_path / "images" / "3.kernel").write_bytes(
        b"\x00junk\x00Linux version 4.1.17 (gcc)\x00\"console=ttyS0 init=/sbin/preinit\"\x00"
        b"other init=/etc/rcS\x00noise\x00")
    res = subprocess.run([sys.executable, str(repo_root / "scripts/inferKernel.py"), "3"],
                         cwd=tmp_path, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    old = subprocess.run(
        "strings images/3.kernel | grep \"init=/\" | sed -e 's/^\"//' -e 's/\"$//'",
        shell=True, cwd=tmp_path, capture_output=True, text=True).stdout
    assert (tmp_path / "scratch/3/kernelCmd").read_text() == old
    assert (tmp_path / "scratch/3/kernelVersion").read_text() == "Linux version 4.1.17 (gcc)\n"
    assert (tmp_path / "scratch/3/kernelInit").read_text().split() == ["init=/sbin/preinit", "init=/etc/rcS"]
    bad = subprocess.run([sys.executable, str(repo_root / "scripts/inferKernel.py"), "3;id"],
                         cwd=tmp_path, capture_output=True, text=True)
    assert bad.returncode != 0


def test_helper_scripts_do_not_use_a_shell(repo_root):
    for rel in ("debug.py", "scripts/inferKernel.py", "scripts/inferDefault.py",
                "scripts/makeNetwork.py", "docker-helper.py", "firmae/pipeline.py"):
        for line in (repo_root / rel).read_text().splitlines():
            code = line.split("#")[0]
            assert "os.system(" not in code and "shell=True" not in code, (rel, line)


def test_console_c_checks_the_result_of_open(repo_root):
    assert 'if ((fd = open("/firmadyne/ttyS1", O_RDWR, 0)) == -1) {' in \
        (repo_root / "sources/console/console.c").read_text()


def test_database_password_comes_from_the_environment(repo_root):
    for rel in ("scripts/util.py", "scripts/tar2db.py", "scripts/getArch.py", "sources/extractor/extractor.py"):
        text = (repo_root / rel).read_text()
        assert 'password="firmadyne"' not in text, rel
        assert 'os.environ.get("FIRMAE_DB_PASSWORD", "firmadyne")' in text, rel
