#!/usr/bin/env python3
"""Infer the architecture (armel/mipseb/...) of an extracted rootfs tarball.

Usage: getArch.py <images/IID.tar.gz> <psql_ip>
Prints e.g. "mipseb" on success, nothing on failure; records the result in the
database and in scratch/<IID>/{fileList,fileType}.

Security (SECURITY.md S3): the tarball comes from untrusted firmware. Members
are never extracted into the file system tree. The content of each candidate
regular file is copied, one at a time, into a private temporary directory
(mode 0700, random name) and inspected with `file`; the directory is always
removed. Member names are never used as paths.
"""

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

archMap = {
    "MIPS64": "mips64",
    "MIPS": "mips",
    "ARM64": "arm64",
    "ARM": "arm",
    "Intel 80386": "intel",
    "x86-64": "intel64",
    "PowerPC": "ppc",
    "unknown": "unknown",
}

endMap = {"LSB": "el", "MSB": "eb"}

# Members whose type is worth checking, in the order the tar lists them.
BINARY_HINTS = ["/busybox", "/alphapd", "/boa", "/http", "/hydra", "/helia", "/webs"]
DIR_HINTS = ["/sbin/", "/bin/"]


def getArch(filetype):
    for arch in archMap:
        if filetype.find(arch) != -1:
            return archMap[arch]
    return None


def getEndian(filetype):
    for endian in endMap:
        if filetype.find(endian) != -1:
            return endMap[endian]
    return None


def is_candidate(name):
    return (any(name.find(b) != -1 for b in BINARY_HINTS)
            or any(name.find(p) != -1 for p in DIR_HINTS))


def file_type_of(tar, member, workdir):
    """`file` output for one member's content, or None if it has no content.

    Only regular files and hard links carry data; symlinks, directories and
    device nodes were never reported with an architecture by `file` (it does
    not dereference symlinks by default), so skipping them keeps behaviour.
    """
    if not (member.isfile() or member.islnk()):
        return None
    try:
        src = tar.extractfile(member)
    except (KeyError, tarfile.TarError):
        return None
    if src is None:
        return None
    target = os.path.join(workdir, "member")
    with src, open(target, "wb") as dst:
        shutil.copyfileobj(src, dst)
    try:
        return subprocess.check_output(["file", target]).decode(errors="replace")
    finally:
        os.unlink(target)


def detect(tar_path):
    """Return (archend, filetype, all_member_names). archend is None if unknown."""
    names = []
    with tarfile.open(tar_path, "r") as tar, tempfile.TemporaryDirectory(prefix="firmae-arch-") as workdir:
        members = tar.getmembers()
        names = [m.name for m in members]
        for member in members:
            if not is_candidate(member.name):
                continue
            filetype = file_type_of(tar, member, workdir)
            if filetype is None:
                continue
            arch, endian = getArch(filetype), getEndian(filetype)
            if arch and endian:
                return arch + endian, filetype, names
    return None, None, names


def iid_from_path(tar_path):
    base = os.path.basename(tar_path)
    iid = base[: base.find(".")]
    if not iid.isdigit():
        raise ValueError("cannot derive a numeric image id from %r" % tar_path)
    return iid


def write_file_list(iid, names):
    with open("scratch/" + iid + "/fileList", "w") as f:
        for filename in names:
            try:
                f.write(filename + "\n")
            except UnicodeEncodeError:
                continue


def record(iid, archend, filetype, psql_ip):
    import psycopg2
    dbh = psycopg2.connect(database="firmware", user="firmadyne", password="firmadyne", host=psql_ip)
    try:
        cur = dbh.cursor()
        cur.execute("UPDATE image SET arch = %s WHERE id = %s;", (archend, int(iid)))
        dbh.commit()
    finally:
        dbh.close()
    with open("scratch/" + iid + "/fileType", "w") as f:
        f.write(filetype)


def main(argv):
    infile, psql_ip = argv[1], argv[2]
    iid = iid_from_path(infile)
    archend, filetype, names = detect(infile)
    write_file_list(iid, names)
    if archend:
        print(archend)
        record(iid, archend, filetype, psql_ip)


if __name__ == "__main__":
    main(sys.argv)
