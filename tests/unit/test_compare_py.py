"""util/compare.py: no shell, no import-time work, own loop device only."""

import importlib.util
import os
import subprocess

import pytest


@pytest.fixture
def cmp_mod(repo_root):
    spec = importlib.util.spec_from_file_location("fw_compare", repo_root / "util" / "compare.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)          # must not do any work or call os.system
    return mod


def test_no_shell_in_source(repo_root):
    src = (repo_root / "util" / "compare.py").read_text()
    assert "os.system" not in src and "shell=True" not in src
    assert "/dev/loop0" not in src and "/dev/mapper" not in src


def test_helpers(cmp_mod):
    assert cmp_mod.firmware_name("./images/b/12.tar.gz") == "12"
    assert cmp_mod.brand_of("images/netgear/12.tar.gz") == "netgear"
    assert cmp_mod.brand_of("./images/12.tar.gz") == ""
    assert cmp_mod.skip_dir("/dev/x") and cmp_mod.skip_dir("/tmp/dev") and not cmp_mod.skip_dir("/etc")
    assert not cmp_mod.skip_dir("")


def test_getimage_matches_whole_directory_name(cmp_mod, tmp_path, monkeypatch):
    (tmp_path / "scratch" / "112").mkdir(parents=True)
    (tmp_path / "scratch" / "112" / "image.raw").write_text("x")
    monkeypatch.chdir(tmp_path)
    assert cmp_mod.getimage("12.tar.gz") is None
    assert cmp_mod.getimage("112.tar.gz").endswith("112/image.raw")


EVIL = "a b;$(touch PWNED)`id`'.conf"


def test_copy_does_not_follow_symlinks(cmp_mod, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("host data")
    link = tmp_path / "ln"
    os.symlink(secret, link)
    dst = tmp_path / "out"
    cmp_mod.copy_file(str(link), str(dst))
    assert os.path.islink(dst)
    # an existing symlink at the destination is replaced, not written through
    (tmp_path / "plain").write_text("p")
    cmp_mod.copy_file(str(tmp_path / "plain"), str(dst))
    assert not os.path.islink(dst) and secret.read_text() == "host data"


def test_compare_trees_weird_names_and_outputs(cmp_mod, tmp_path):
    tar = tmp_path / "tar"
    img = tmp_path / "img"
    for d in (tar / "etc", img / "etc", img / "dev", img / "new"):
        d.mkdir(parents=True)
    (tar / "etc" / EVIL).write_text("old\n")
    (img / "etc" / EVIL).write_text("new\n")
    (tar / "etc" / "same").write_text("s")
    (img / "etc" / "same").write_text("s")
    (img / "new" / EVIL).write_text("n")
    (img / "dev" / "skipme").write_text("n")
    os.symlink("/etc/passwd", img / "etc" / "lnk")
    res = tmp_path / "res"
    cmp_mod.compare_trees(str(tar), str(img), str(res))
    assert (res / "etc" / EVIL).read_text() == "new\n"
    assert "old" in (res / "etc" / (EVIL + ".diff")).read_text()
    assert (res / "new" / (EVIL + ".new")).exists()
    assert os.path.islink(res / "etc" / "lnk.new")
    assert not (res / "etc" / "same").exists() and not (res / "dev").exists()
    assert not list(tmp_path.glob("**/PWNED"))


def test_compare_uses_own_loop_device_and_cleans_up(cmp_mod, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "image.raw").write_bytes(b"raw")
    (tmp_path / "t.tar.gz").write_bytes(b"x")
    calls = []

    def fake(argv, **kw):
        assert isinstance(argv, list) and not kw.get("shell")
        calls.append(argv)
        if argv[0] == "losetup" and "--find" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout="/dev/loop7\n")
        return subprocess.CompletedProcess(argv, 0, stdout="")
    monkeypatch.setattr(cmp_mod.subprocess, "run", fake)
    monkeypatch.setattr(cmp_mod, "_wait_for_node", lambda p: None)
    seen = {}
    monkeypatch.setattr(cmp_mod, "compare_trees", lambda *a: seen.setdefault("args", a))
    cmp_mod.compare("b", "t.tar.gz", "image.raw")
    names = [c[0] for c in calls]
    assert names == ["tar", "losetup", "mount", "umount", "losetup"]
    tar = calls[0]
    assert "--no-same-owner" in tar and "--no-same-permissions" in tar
    assert calls[1][:4] == ["losetup", "--find", "--show", "--partscan"]
    mount = calls[2]
    assert mount[2].count("nodev") == 1 and "nosuid" in mount[2] and mount[3] == "/dev/loop7p1"
    assert calls[4] == ["losetup", "-d", "/dev/loop7"]
    assert (tmp_path / "work" / "b" / "t" / "image").is_dir()
    assert not list(tmp_path.glob("compare_work_*"))


def test_loop_detached_and_workdir_kept_if_umount_fails(cmp_mod, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "image.raw").write_bytes(b"raw")
    calls = []

    def fake(argv, **kw):
        calls.append(argv)
        if argv[0] == "losetup" and "--find" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout="/dev/loop3\n")
        return subprocess.CompletedProcess(argv, 1 if argv[0] == "umount" else 0, stdout="")
    monkeypatch.setattr(cmp_mod.subprocess, "run", fake)
    monkeypatch.setattr(cmp_mod, "_wait_for_node", lambda p: None)
    monkeypatch.setattr(cmp_mod, "compare_trees", lambda *a: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.raises(RuntimeError):
        cmp_mod.compare("b", "t.tar.gz", "image.raw")
    assert calls[-1] == ["losetup", "-d", "/dev/loop3"]
    assert list(tmp_path.glob("compare_work_*"))      # still mounted: never rmtree it
