"""scripts/inferDefault.py on an untrusted image: symlinks, FIFOs and other
non-regular files are never read (a link to /proc/kcore used to be read whole
by root), files are scanned in bounded chunks, paths are computed relative to
the image root, and nothing is written through a symlink the guest planted.

No real /proc/kcore is touched: a FIFO without writer stands in for "a file
whose read never returns" (the old code blocked on it forever).
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.linux

IID = "5"
KEYS = [b"lan_ipaddr", b"lan_netmask", b"wan_proto", b"http_passwd", b"time_zone",
        b"wl0_ssid", b"wl0_channel", b"dhcp_start", b"dhcp_end", b"router_name",
        b"fw_version", b"ntp_server"]
DEFAULTS = b"\0".join(k + b"=x" for k in KEYS)


@pytest.fixture
def scripts_dir(repo_root):
    sys.path.insert(0, str(repo_root / "scripts"))
    yield repo_root / "scripts"
    sys.path.remove(str(repo_root / "scripts"))


@pytest.fixture
def tree(tmp_path):
    """tmp_path/FirmAE with scratch/<IID>/{qemu.initial.serial.log,image/}, and a
    stub `file` that records its arguments."""
    root = tmp_path / "FirmAE"
    work = root / "scratch" / IID
    image = work / "image"
    (image / "firmadyne").mkdir(parents=True)
    (image / "etc").mkdir()
    log = b"".join(b"[NVRAM] %d %s\n" % (len(k), k) for k in KEYS)
    (work / "qemu.initial.serial.log").write_bytes(b"boot\n" + log + b"[NVRAM] x bad\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    f = bindir / "file"
    f.write_text('#!/bin/bash\necho "$*" >> %s\necho "ASCII text"\n' % (tmp_path / "file_calls"))
    f.chmod(0o755)
    return root


def run(repo_root, root, timeout=30):
    env = dict(os.environ, PATH="%s:%s" % (root.parent / "bin", os.environ["PATH"]))
    return subprocess.run([sys.executable, str(repo_root / "scripts/inferDefault.py"), IID],
                          cwd=root, env=env, capture_output=True, text=True, timeout=timeout)


def image(root):
    return root / "scratch" / IID / "image"


def test_regular_default_file_is_found_and_output_format_is_kept(repo_root, tree):
    (image(tree) / "etc" / "nvram.default").write_bytes(b"junk" + DEFAULTS)
    res = run(repo_root, tree)
    assert res.returncode == 0, res.stderr
    work = tree / "scratch" / IID
    assert (work / "nvram_keys").read_bytes() == b"%d\n" % len(KEYS) + b"".join(k + b"\n" for k in KEYS)
    assert (work / "nvram_files").read_text() == "/etc/nvram.default %d ASCII_text\n" % len(KEYS)
    assert (image(tree) / "firmadyne" / "nvram_files").read_text() == (work / "nvram_files").read_text()
    # `file` is told not to follow symlinks
    assert (tree.parent / "file_calls").read_text().split()[:3] == ["-b", "-h", "--"]


def test_symlinks_fifos_and_firmadyne_are_never_read(repo_root, tree, tmp_path):
    img = image(tree)
    outside = tmp_path / "host_secret"
    outside.write_bytes(DEFAULTS)                         # would match if followed
    os.symlink(str(outside), img / "etc" / "to_host")
    os.symlink("/proc/kcore", img / "kcore")              # never opened (not even lstat'ed through)
    os.symlink("/dev/zero", img / "zero")                 # endless if followed
    host_fifo = tmp_path / "fifo"
    os.mkfifo(host_fifo)                                  # no writer: a read blocks forever
    os.symlink(str(host_fifo), img / "etc" / "blocks")
    os.mkfifo(img / "etc" / "fifo_in_image")
    os.symlink(str(tmp_path), img / "dirlink")            # directory symlink: not descended
    (img / "firmadyne" / "own").write_bytes(DEFAULTS)     # FirmAE's own directory is skipped
    res = run(repo_root, tree, timeout=60)
    assert res.returncode == 0, res.stderr
    assert not (tree / "scratch" / IID / "nvram_files").exists()
    assert not (tree.parent / "file_calls").exists()


def test_path_with_a_second_image_component(repo_root, tree):
    d = image(tree) / "usr" / "image" / "cfg"
    d.mkdir(parents=True)
    (d / "image.defaults").write_bytes(DEFAULTS)
    res = run(repo_root, tree)
    assert res.returncode == 0, res.stderr
    # the old i.split("image")[1] produced "/usr/"
    assert (tree / "scratch" / IID / "nvram_files").read_text() == \
        "/usr/image/cfg/image.defaults %d ASCII_text\n" % len(KEYS)


def test_planted_nvram_files_symlink_does_not_redirect_the_copy(repo_root, tree, tmp_path):
    (image(tree) / "etc" / "nvram.default").write_bytes(DEFAULTS)
    victim = tmp_path / "victim"
    victim.write_text("host file\n")
    os.symlink(str(victim), image(tree) / "firmadyne" / "nvram_files")
    res = run(repo_root, tree)
    assert res.returncode == 0, res.stderr
    assert victim.read_text() == "host file\n"
    dst = image(tree) / "firmadyne" / "nvram_files"
    assert not dst.is_symlink() and dst.read_text().startswith("/etc/nvram.default ")


def test_symlinked_firmadyne_directory_is_refused(repo_root, tree, tmp_path):
    (image(tree) / "etc" / "nvram.default").write_bytes(DEFAULTS)
    os.rmdir(image(tree) / "firmadyne")
    host_dir = tmp_path / "host_dir"
    host_dir.mkdir()
    os.symlink(str(host_dir), image(tree) / "firmadyne")
    res = run(repo_root, tree)
    assert res.returncode != 0
    assert list(host_dir.iterdir()) == []


def test_too_few_keys_writes_nothing(repo_root, tree):
    (tree / "scratch" / IID / "qemu.initial.serial.log").write_bytes(b"[NVRAM] 3 abc\n")
    assert run(repo_root, tree).returncode == 0
    assert not (tree / "scratch" / IID / "nvram_keys").exists()


def test_invalid_image_id_is_rejected(repo_root, tree):
    env = dict(os.environ)
    res = subprocess.run([sys.executable, str(repo_root / "scripts/inferDefault.py"), "5/../.."],
                         cwd=tree, env=env, capture_output=True, text=True, timeout=30)
    assert res.returncode == 2


def test_scan_is_chunked_bounded_and_finds_keys_across_chunks(scripts_dir, monkeypatch, tmp_path):
    import inferDefault as inf
    monkeypatch.setattr(inf, "CHUNK", 4)
    p = tmp_path / "f"
    p.write_bytes(b"xx" + b"lan_ipaddr" + b"yyyyyyyy" + b"wan_proto")
    with open(p, "rb") as f:
        assert inf.count_keys(f, [b"lan_ipaddr", b"wan_proto", b"absent"]) == 2
    with open(p, "rb") as f:                              # only the first 12 bytes are scanned
        assert inf.count_keys(f, [b"lan_ipaddr", b"wan_proto"], limit=12) == 1
    with open(p, "rb") as f:                              # b"" matched any data before
        assert inf.count_keys(f, [b""]) == 1


def test_serial_log_is_read_bounded(scripts_dir, monkeypatch, tmp_path):
    import inferDefault as inf
    work = tmp_path / IID
    work.mkdir()
    lines = b"".join(b"[NVRAM] %d %s\n" % (len(k), k) for k in KEYS)
    (work / "qemu.initial.serial.log").write_bytes(lines)
    monkeypatch.setattr(inf, "MAX_LOG_BYTES", len(lines.split(b"\n")[0]) + 1)
    assert inf.GetKeyList(IID, str(tmp_path)) == [KEYS[0]]
    os.unlink(work / "qemu.initial.serial.log")
    os.symlink("/dev/zero", work / "qemu.initial.serial.log")     # not followed
    assert inf.GetKeyList(IID, str(tmp_path)) == []
