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


# ------------------------------- unprivileged extraction (FIRMAE_EXTRACT_USER, SECURITY.md S9)

def test_binwalk_run_as_root_only_when_root(ext, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert ext.binwalk_args() == ["--run-as=root", "--preserve-symlinks", "-e", "-r"]
    monkeypatch.setattr(os, "geteuid", lambda: 999)
    assert ext.binwalk_args() == ["--preserve-symlinks", "-e", "-r"]


def test_binwalk_scan_gets_binwalk_args(ext, tmp_path, monkeypatch):
    item = make_item(ext, tmp_path)
    item.temp = str(tmp_path)
    seen = {}
    monkeypatch.setattr(ext, "binwalk_args", lambda: ["--marker"])

    def scan(*args, **kw):
        seen["args"] = args
        return []
    monkeypatch.setattr(ext.binwalk, "scan", scan)
    item._extract_in_temp()
    assert seen["args"] == (item.item, "--marker", "-C", str(tmp_path))


def make_tree(root):
    """A small rootfs as the unprivileged extractor leaves it: mode 000 file,
    unreadable directory, setuid file, symlinks, a hard link."""
    for d in ("bin", "etc", "lib", "usr/sbin"):
        os.makedirs(os.path.join(root, d))
    with open(os.path.join(root, "bin", "busybox"), "wb") as f:
        f.write(b"\x7fELF")
    os.chmod(os.path.join(root, "bin", "busybox"), 0o4755)
    os.symlink("busybox", os.path.join(root, "bin", "sh"))
    os.symlink("/var/run", os.path.join(root, "etc", "run"))
    os.link(os.path.join(root, "bin", "busybox"), os.path.join(root, "bin", "ash"))
    with open(os.path.join(root, "etc", "shadow"), "w") as f:
        f.write("root::0:0")
    os.chmod(os.path.join(root, "etc", "shadow"), 0)
    with open(os.path.join(root, "usr", "sbin", "httpd"), "w") as f:
        f.write("x")
    os.chmod(os.path.join(root, "usr", "sbin"), 0)          # unreadable directory


def members(path):
    import tarfile
    with tarfile.open(path) as tar:
        return [(m.name, m.type, m.mode, m.linkname, m.size) for m in tar.getmembers()]


@pytest.mark.skipif(getattr(os, "geteuid", lambda: 0)() == 0, reason="the unprivileged path")
def test_archive_rootfs_unprivileged_keeps_modes_and_reads_unreadable_entries(ext, tmp_path):
    import shutil
    import tarfile
    root = str(tmp_path / "root")
    make_tree(root)
    try:
        check_archive(ext, tmp_path, root)
    finally:                                    # pytest must be able to remove the tree
        os.chmod(os.path.join(root, "usr", "sbin"), 0o755)


def check_archive(ext, tmp_path, root):
    import shutil
    import tarfile
    got = ext.archive_rootfs(str(tmp_path / "12"), root)
    assert got == str(tmp_path / "12.tar.gz")
    m = {name: (typ, mode, link, size) for name, typ, mode, link, size in members(got)}
    assert m["./etc/shadow"][1] == 0 and m["./etc/shadow"][3] == 9           # content was read
    assert m["./usr/sbin"][1] == 0 and "./usr/sbin/httpd" in m              # descended into it
    assert m["./bin/busybox"][1] == 0o4755
    assert m["./bin/sh"][0] == tarfile.SYMTYPE and m["./bin/sh"][2] == "busybox"
    assert m["./etc/run"][2] == "/var/run"
    assert {m["./bin/ash"][0], m["./bin/busybox"][0]} == {tarfile.LNKTYPE, tarfile.REGTYPE}
    # same members as shutil.make_archive of the (now readable) tree, modes aside
    ref = shutil.make_archive(str(tmp_path / "ref"), "gztar", root_dir=root)
    strip = lambda ms: [(n, t, l, s) for n, t, _, l, s in ms]
    assert strip(members(got)) == strip(members(ref))


def test_archive_rootfs_as_root_is_make_archive(ext, tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(ext.shutil, "make_archive",
                        lambda base, fmt, root_dir: seen.update(a=(base, fmt, root_dir)) or base + ".tar.gz")
    assert ext.archive_rootfs("/o/12", "/r") == "/o/12.tar.gz"
    assert seen["a"] == ("/o/12", "gztar", "/r")


def test_done_list_counts_as_extracted(ext, tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00" * 64)
    out = tmp_path / "out"
    out.mkdir()
    e = ext.Extractor(str(fw), str(out), rootfs=True, kernel=False, numproc=False, done=["fw.bin_x.kernel"])
    item = ext.ExtractionItem(e, str(fw), 0)
    assert item.status == (True, False)                     # kernel not wanted; rootfs not done
    e2 = ext.Extractor(str(fw), str(out), rootfs=True, kernel=False, numproc=False,
                       done=[os.path.basename(item.get_rootfs_path())])
    assert ext.ExtractionItem(e2, str(fw), 0).status == (True, True)


def test_main_reads_the_done_list(ext, tmp_path, monkeypatch):
    lst = tmp_path / "done.list"
    lst.write_text("12.tar.gz\n\n12.kernel\n")
    seen = {}

    class E:
        def __init__(self, *a):
            seen["done"] = a[-1]

        def extract(self):
            pass
    monkeypatch.setattr(ext, "Extractor", E)
    monkeypatch.setattr(sys, "argv", ["extractor.py", "-d", "--done-list", str(lst),
                                      str(tmp_path / "in"), str(tmp_path / "out")])
    assert ext.main() == 0
    assert seen["done"] == ["12.tar.gz", "12.kernel"]


@pytest.mark.parametrize("euid, staging, umask", [(999, True, 0), (0, True, None), (999, False, None)])
def test_main_clears_the_umask_only_in_unprivileged_staging(ext, tmp_path, monkeypatch, euid, staging, umask):
    """Measured in phase 2: not as root the umask masked the image's modes (0775 ->
    0755). Cleared only in FIRMAE_EXTRACT_USER's staging mode (--done-list), not
    when a user runs the extractor directly into images/."""
    calls = []
    lst = tmp_path / "done.list"
    lst.write_text("")
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    monkeypatch.setattr(os, "umask", lambda m: calls.append(m) or 0o22)

    class E:
        def __init__(self, *a):
            pass

        def extract(self):
            pass
    monkeypatch.setattr(ext, "Extractor", E)
    extra = ["--done-list", str(lst)] if staging else []
    monkeypatch.setattr(sys, "argv", ["extractor.py", "-d"] + extra + [str(tmp_path / "in"), str(tmp_path / "out")])
    assert ext.main() == 0
    assert calls == ([] if umask is None else [umask])
