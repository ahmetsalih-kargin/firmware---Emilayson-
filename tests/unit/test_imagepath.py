"""Tests for scripts/imagepath.py (REFACTORING_PLAN 2.3, SECURITY.md S5)."""

import os
import subprocess
import sys

import pytest

from scripts.imagepath import SymlinkLoop, resolve_in_root

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX symlinks")


@pytest.fixture
def image(tmp_path):
    root = tmp_path / "image"
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "etc").mkdir()
    return root


def test_plain_path(image):
    assert resolve_in_root(str(image), "/etc/rcS") == str(image / "etc" / "rcS")


def test_relative_symlink_stays_inside(image):
    (image / "bin").symlink_to("usr/bin")
    assert resolve_in_root(str(image), "/bin/a") == str(image / "usr" / "bin" / "a")


def test_absolute_symlink_is_rerooted_into_the_image(image, tmp_path):
    """The attack: bin -> <absolute host dir>. On the host, cp would write
    into that host directory; resolved like chroot it lands inside the image."""
    host_dir = tmp_path / "host_bin"
    host_dir.mkdir()
    (image / "bin").symlink_to(str(host_dir))
    resolved = resolve_in_root(str(image), "/bin/a")
    assert resolved == str(image) + str(host_dir) + "/a"
    assert resolved.startswith(str(image) + os.sep)


def test_absolute_symlink_to_usr_bin_like_chroot(image):
    (image / "bin").symlink_to("/usr/bin")
    assert resolve_in_root(str(image), "/bin/a") == str(image / "usr" / "bin" / "a")


def test_dotdot_cannot_leave_the_root(image):
    (image / "etc" / "up").symlink_to("../../../../../../tmp")
    assert resolve_in_root(str(image), "/../../etc/passwd") == str(image / "etc" / "passwd")
    assert resolve_in_root(str(image), "/etc/up/x") == str(image / "tmp" / "x")


def test_final_component(image):
    (image / "etc" / "rcS").symlink_to("/sbin/init")
    assert resolve_in_root(str(image), "/etc/rcS") == str(image / "sbin" / "init")
    assert resolve_in_root(str(image), "/etc/rcS", follow_final=False) == str(image / "etc" / "rcS")


def test_intermediate_symlinks_are_followed_even_without_follow_final(image):
    (image / "init.d").symlink_to("/etc")
    assert (resolve_in_root(str(image), "/init.d/rcS", follow_final=False)
            == str(image / "etc" / "rcS"))


def test_symlink_loop_is_reported(image):
    (image / "a").symlink_to("b")
    (image / "b").symlink_to("a")
    with pytest.raises(SymlinkLoop):
        resolve_in_root(str(image), "/a/x")


def test_cli(image, repo_root):
    (image / "bin").symlink_to("/usr/bin")
    script = str(repo_root / "scripts" / "imagepath.py")
    out = subprocess.run([sys.executable, script, str(image), "/bin/a"],
                         capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.strip() == str(image / "usr" / "bin" / "a")
    out = subprocess.run([sys.executable, script, str(image), "/bin", "--no-follow-final"],
                         capture_output=True, text=True)
    assert out.stdout.strip() == str(image / "bin")
    (image / "x").symlink_to("x")
    out = subprocess.run([sys.executable, script, str(image), "/x/y"], capture_output=True, text=True)
    assert out.returncode == 1 and "symbolic links" in out.stderr
