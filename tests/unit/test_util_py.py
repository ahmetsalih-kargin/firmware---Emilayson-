"""scripts/util.py: 'no record' (empty, exit 0) vs database error (stderr, exit 1)."""

import hashlib

import pytest

psycopg2 = pytest.importorskip("psycopg2")
from scripts import util  # noqa: E402

MD5_ABC = hashlib.md5(b"abc").hexdigest()


class Cur:
    def __init__(self, db):
        self.db = db

    def execute(self, sql, params=None):
        self.db.log.append((sql, params))
        if self.db.err:
            raise psycopg2.OperationalError("down")

    def fetchone(self):
        return self.db.row

    def close(self):
        pass


class DB:
    def __init__(self, row=None, err=False):
        self.row, self.err, self.log, self.closed = row, err, [], False

    def cursor(self):
        return Cur(self)

    def close(self):
        self.closed = True


@pytest.fixture
def fw(tmp_path):
    p = tmp_path / "fw.bin"
    p.write_bytes(b"abc")
    return str(p)


def patch(monkeypatch, db):
    monkeypatch.setattr(util.psycopg2, "connect", lambda **kw: db)


def test_found_and_not_found(monkeypatch, fw, capsys):
    db = DB(row=(9,))
    patch(monkeypatch, db)
    assert util.get_iid(fw, "h") == 9
    sql, params = db.log[0]
    assert "%s" in sql and MD5_ABC not in sql and params == (MD5_ABC,) and db.closed
    patch(monkeypatch, DB(row=None))
    assert util.get_iid(fw, "h") == ""
    assert util.main(["util.py", "get_iid", fw, "h"]) == 0
    assert capsys.readouterr().out == "\n"


def test_database_error_is_not_no_record(monkeypatch, fw, capsys):
    db = DB(err=True)
    patch(monkeypatch, db)
    with pytest.raises(psycopg2.Error):
        util.get_iid(fw, "h")
    assert db.closed
    assert util.main(["util.py", "get_iid", fw, "h"]) == 1
    cap = capsys.readouterr()
    assert cap.out == "" and "down" in cap.err
    assert util.main(["util.py", "get_brand", fw, "h"]) == 1


def test_get_brand(monkeypatch, fw):
    db = DB(row=("netgear",))
    patch(monkeypatch, db)
    assert util.get_brand(fw, "h") == "netgear"
    assert db.log[0][1] == (MD5_ABC,)


def test_check_connection(monkeypatch):
    patch(monkeypatch, DB())
    assert util.check_connection("h") == 0

    def boom(**kw):
        raise psycopg2.OperationalError("x")
    monkeypatch.setattr(util.psycopg2, "connect", boom)
    assert util.check_connection("h") == 1
    assert util.main(["util.py", "check_connection", "_", "h"]) == 1
