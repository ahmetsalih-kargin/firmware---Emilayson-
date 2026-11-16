"""scripts/tar2db.py: streaming hashes, no swallowed DB errors, exit codes."""

import hashlib
import io
import tarfile

import pytest

pytest.importorskip("psycopg2")
from scripts import tar2db  # noqa: E402


class Cur:
    def __init__(self, db):
        self.db = db
        self.rows = []

    def execute(self, sql, params=None):
        self.db.log.append((sql, params))
        if self.db.fail_on and self.db.fail_on in sql:
            raise RuntimeError("db boom")
        self.rows = []
        if "SELECT id,hash" in sql:
            self.rows = [(7, h) for h in params["hashes"] if h in self.db.known]
        elif "INSERT INTO object (" in sql:
            self.rows = [(100 + len(self.db.log),)]

    def executemany(self, sql, seq):
        seq = list(seq)
        self.db.log.append((sql, seq))
        if self.db.fail_on and self.db.fail_on in sql:
            raise RuntimeError("db boom")

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class DB:
    def __init__(self, known=(), fail_on=None):
        self.log, self.known, self.fail_on = [], set(known), fail_on
        self.committed = self.rolled_back = self.closed = False

    def cursor(self):
        return Cur(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def make_tar(path):
    with tarfile.open(path, "w:gz") as t:
        for name, data in (("./a", b"same"), ("./b", b"same"), ("./c", b"other")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        ln = tarfile.TarInfo("./l")
        ln.type = tarfile.SYMTYPE
        ln.linkname = "a"
        t.addfile(ln)


def test_hashes_are_streamed(tmp_path, monkeypatch):
    p = tmp_path / "x.tar.gz"
    make_tar(p)

    class NoRead(io.BytesIO):
        def read(self, n=-1):
            assert n != -1 and n <= 65536, "whole member read into memory"
            return super().read(n)
    orig = tarfile.TarFile.extractfile
    monkeypatch.setattr(tarfile.TarFile, "extractfile",
                        lambda self, m: NoRead(orig(self, m).read()))
    files, links = tar2db.getFileHashes(str(p))
    assert files[0][1] == hashlib.md5(b"same").hexdigest()
    assert links == [("/l", "a")]


def test_process_keeps_every_name_and_commits(tmp_path, monkeypatch):
    p = tmp_path / "5.tar.gz"
    make_tar(p)
    db = DB()
    monkeypatch.setattr(tar2db.psycopg2, "connect", lambda **kw: db)
    tar2db.process(5, str(p))
    assert db.committed and db.closed
    names = [r["filename"] for sql, seq in db.log if isinstance(seq, list) for r in seq]
    assert sorted(names) == ["/a", "/b", "/c", "/l"]      # duplicates of content kept


def test_queries_are_parametrised_and_idempotent():
    db = DB()
    tar2db.getOids([("/a", "h1", 0, 0, 0)], db.cursor())
    for sql, params in db.log:
        assert "h1" not in sql
    assert any("ON CONFLICT (hash) DO NOTHING" in s for s, _ in db.log)
    db = DB()
    tar2db.insertObjectToImage(1, [(("/a", 0, 0, 0), 2)], [], db.cursor())
    assert "ON CONFLICT (oid, iid, filename) DO NOTHING" in db.log[0][0]


def test_empty_tar_has_valid_sql():
    db = DB()
    assert tar2db.getOids([], db.cursor()) == {}
    assert db.log == []


def test_db_error_rolls_back_and_exits_nonzero(tmp_path, monkeypatch, capsys):
    p = tmp_path / "5.tar.gz"
    make_tar(p)
    db = DB(fail_on="INSERT INTO object_to_image")
    monkeypatch.setattr(tar2db.psycopg2, "connect", lambda **kw: db)
    monkeypatch.setattr("sys.argv", ["tar2db.py", "-f", str(p)])
    assert tar2db.main() == 1
    assert db.rolled_back and not db.committed and db.closed
    assert "db boom" in capsys.readouterr().err


def test_iid_taken_from_file_name(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(tar2db, "process", lambda iid, f: seen.append(iid))
    monkeypatch.setattr("sys.argv", ["tar2db.py", "-f", "images/42.tar.gz"])
    assert tar2db.main() == 0 and seen == [42]


def test_missing_iid_is_usage_error(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["tar2db.py", "-f", "nonumber.tar.gz"])
    assert tar2db.main() == 2
    assert "usage" in capsys.readouterr().err
