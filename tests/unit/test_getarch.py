"""Tests for scripts/getArch.py (REFACTORING_PLAN 2.2, SECURITY.md S3).

Uses the real `file` utility, so it runs on Linux only.
"""

import glob
import io
import os
import struct
import tarfile
import tempfile

import pytest

from scripts import getArch

pytestmark = pytest.mark.linux


def elf(machine, big_endian):
    """Minimal 32-bit ELF executable header that `file` recognises."""
    e = ">" if big_endian else "<"
    ident = b"\x7fELF" + bytes([1, 2 if big_endian else 1, 1]) + b"\x00" * 9
    return ident + struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0)


MIPS, ARM = 8, 40


def make_tar(path, members):
    """members: list of (name, kind, payload); kind in file/dir/sym/lnk."""
    with tarfile.open(path, "w:gz") as tar:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                tar.addfile(info)
            elif kind == "lnk":
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                tar.addfile(info)
    return str(path)


@pytest.mark.parametrize("machine,big,expected", [
    (MIPS, True, "mipseb"), (MIPS, False, "mipsel"), (ARM, False, "armel"),
])
def test_detects_architecture(tmp_path, machine, big, expected):
    tar = make_tar(tmp_path / "1.tar.gz", [
        ("./bin", "dir", None),
        ("./bin/busybox", "file", elf(machine, big)),
    ])
    archend, filetype, names = getArch.detect(tar)
    assert archend == expected
    assert "ELF 32-bit" in filetype
    assert names == ["./bin", "./bin/busybox"]


def test_first_candidate_with_architecture_wins_and_others_are_skipped(tmp_path):
    tar = make_tar(tmp_path / "1.tar.gz", [
        ("./etc/passwd", "file", b"root::0:0::/:/bin/sh\n"),       # not a candidate
        ("./bin/sh", "sym", "busybox"),                             # symlink: no data
        ("./bin/readme", "file", b"plain text\n"),                  # no architecture
        ("./bin/busybox", "file", elf(MIPS, False)),
        ("./sbin/init", "file", elf(ARM, False)),
    ])
    assert getArch.detect(tar)[0] == "mipsel"


def test_hard_link_member_is_read_through_its_target(tmp_path):
    tar = make_tar(tmp_path / "1.tar.gz", [
        ("./usr/lib/real", "file", elf(ARM, False)),
        ("./bin/busybox", "lnk", "./usr/lib/real"),
    ])
    assert getArch.detect(tar)[0] == "armel"


def test_no_architecture_found(tmp_path):
    tar = make_tar(tmp_path / "1.tar.gz", [("./bin/script", "file", b"#!/bin/sh\necho\n")])
    assert getArch.detect(tar)[0] is None


def test_path_traversal_member_writes_nothing(tmp_path):
    """SECURITY.md S3: '../' members (which also match the '/bin/' filter) used
    to be extracted by tarfile.extract() relative to /tmp/<IID>."""
    escape_target = tmp_path / "outside" / "bin"
    rel = os.path.relpath(escape_target, tempfile.gettempdir())
    tar = make_tar(tmp_path / "1.tar.gz", [
        ("../../../../../../../../.." + str(escape_target) + "/evil", "file", b"x"),
        (rel + "/evil2", "file", b"x"),
        ("/" + str(escape_target).lstrip("/") + "/evil3", "file", b"x"),
    ])
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "firmae-arch-*")))
    assert getArch.detect(tar)[0] is None
    assert not (tmp_path / "outside").exists()
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "firmae-arch-*")))
    assert after == before, "temporary directory was not removed"


def test_member_name_is_not_used_in_file_output(tmp_path):
    """The old code ran `file /tmp/IID/<member>`, so a member path containing
    e.g. 'ARM' or 'MSB' could change the detected architecture."""
    tar = make_tar(tmp_path / "1.tar.gz", [("./bin/ARM_MSB_tool", "file", elf(MIPS, False))])
    archend, filetype, _ = getArch.detect(tar)
    assert archend == "mipsel"
    assert "ARM_MSB_tool" not in filetype


@pytest.mark.parametrize("path,iid", [("./images/12.tar.gz", "12"), ("/x/images/3.tar.gz", "3")])
def test_iid_from_path(path, iid):
    assert getArch.iid_from_path(path) == iid


def test_iid_from_path_rejects_non_numeric():
    with pytest.raises(ValueError):
        getArch.iid_from_path("./images/1;rm -rf.tar.gz")
