"""FIRMAE_DB_PORT selects the PostgreSQL port of every FirmAE database
connection; unset, libpq's own default (PGPORT, else 5432) applies as before."""

import importlib.util
import re
import shutil
import subprocess
import sys
import types

import pytest

CONNECTING = ("scripts/util.py", "scripts/tar2db.py", "scripts/getArch.py",
              "sources/extractor/extractor.py")


def connect_calls(text):
    """The argument text of every psycopg2.connect(...) call."""
    out = []
    for m in re.finditer(r"psycopg2\.connect\(", text):
        depth, i = 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        out.append(text[m.end():i - 1])
    return out


@pytest.mark.parametrize("rel", CONNECTING)
def test_every_connection_takes_the_port_from_firmae_db_port(repo_root, rel):
    text = (repo_root / rel).read_text()
    calls = connect_calls(text)
    assert calls, rel
    for args in calls:
        assert ('port=os.environ.get("FIRMAE_DB_PORT") or None' in args
                or "port=db_port()" in args), (rel, args)
        assert not re.search(r"port\s*=\s*['\"]?5432", args)


@pytest.fixture
def util(repo_root, monkeypatch):
    seen = []
    fake = types.ModuleType("psycopg2")
    fake.Error = Exception

    class Conn:
        def close(self):
            pass

    def connect(**kw):
        seen.append(kw)
        return Conn()
    fake.connect = connect
    monkeypatch.setitem(sys.modules, "psycopg2", fake)
    spec = importlib.util.spec_from_file_location("fa_util", repo_root / "scripts/util.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, seen


@pytest.mark.parametrize("value, expected", [(None, None), ("", None), ("5434", "5434")])
def test_util_connect_port(util, monkeypatch, value, expected):
    mod, seen = util
    monkeypatch.delenv("FIRMAE_DB_PORT", raising=False)
    if value is not None:
        monkeypatch.setenv("FIRMAE_DB_PORT", value)
    assert mod.check_connection("10.0.0.1") == 0
    assert seen[-1]["port"] == expected and seen[-1]["host"] == "10.0.0.1"


def test_psycopg2_drops_a_none_port(monkeypatch):
    """port=None must mean "not given" (libpq default), not an empty port."""
    ext = pytest.importorskip("psycopg2.extensions")
    assert "port" not in ext.make_dsn(dbname="firmware", host="h", port=None)
    assert "port=5434" in ext.make_dsn(dbname="firmware", host="h", port="5434")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("value, expected", [(None, "UNSET"), ("", "UNSET"), ("5434", "5434")])
def test_firmae_config_exports_pgport_for_psql(repo_root, value, expected):
    env = {"PATH": "/usr/bin:/bin"}
    if value is not None:
        env["FIRMAE_DB_PORT"] = value
    res = subprocess.run(["bash", "-c", 'source ./firmae.config && echo "${PGPORT-UNSET}"'],
                         cwd=repo_root, env=env, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == expected
