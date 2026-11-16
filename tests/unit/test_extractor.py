"""sources/extractor/extractor.py: temp-dir cleanup and psql_check failure."""

import importlib.util
import os
import sys

import pytest

pytest.importorskip("magic")
pytest.importorskip("binwalk")
pytest.importorskip("psycopg2")


@pytest.fixture
def ext():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "sources", "extractor", "extractor.py")
    spec = importlib.util.spec_from_file_location("fw_extractor_t", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_item(ext, tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00" * 64)
    extractor = ext.Extractor(str(fw), None, numproc=False)
    item = ext.ExtractionItem(extractor, str(fw), 0)
    item._check_blacklist = lambda: False
    return item


def test_temp_removed_and_cwd_restored_on_normal_run(ext, tmp_path, monkeypatch):
    item = make_item(ext, tmp_path)
    seen = {}

    def fake(self):
        seen["temp"] = self.temp
        assert os.getcwd() == os.path.realpath(self.temp)
        return False
    monkeypatch.setattr(ext.ExtractionItem, "_extract_in_temp", fake)
    monkeypatch.chdir(tmp_path)
    item.extract()
    assert not os.path.exists(seen["temp"]) and item.temp is None
    assert os.getcwd() == str(tmp_path)


@pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_temp_removed_on_interrupt_or_error(ext, tmp_path, monkeypatch, exc):
    item = make_item(ext, tmp_path)
    seen = {}

    def fake(self):
        seen["temp"] = self.temp
        raise exc()
    monkeypatch.setattr(ext.ExtractionItem, "_extract_in_temp", fake)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(exc):
        item.extract()
    assert not os.path.exists(seen["temp"])
    assert os.getcwd() == str(tmp_path)


def test_psql_check_failure_reports_and_main_exits_nonzero(ext, monkeypatch, capsys, tmp_path):
    import psycopg2

    def boom(**kw):
        raise psycopg2.OperationalError("no server")
    monkeypatch.setattr(psycopg2, "connect", boom)
    assert ext.psql_check("1.2.3.4") is False
    assert "no server" in capsys.readouterr().err
    monkeypatch.setattr(sys, "argv", ["extractor.py", "-sql", "1.2.3.4",
                                      str(tmp_path / "in"), str(tmp_path / "out")])
    assert ext.main() == 1


def test_psql_check_closes_connection(ext, monkeypatch):
    import psycopg2

    class C:
        closed = False

        def close(self):
            C.closed = True
    monkeypatch.setattr(psycopg2, "connect", lambda **kw: C())
    assert ext.psql_check("h") is True and C.closed
