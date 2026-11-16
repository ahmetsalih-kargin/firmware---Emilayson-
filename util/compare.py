"""Compare an extracted firmware tarball with the filesystem image that the
emulation produced (evaluation helper, not part of the main pipeline).

Needs root (losetup/mount). File names come from the firmware, so nothing is
ever passed through a shell and symlinks are never followed.
"""

import filecmp
import os
import shutil
import subprocess
import sys
import tempfile
import time

fileList = [
    "image",
    "image.raw",
    "mipsel",
    "mipseb",
    "armel",
    "armeb",
    "qemu.final.serial.log",
    "run.sh",
    "serial.log",
    ".qemu.final.serial.log.swp",
]

folderwhitelist = ["/dev", "/share"]

# directories of the mounted image that are not compared
SKIPPED_PREFIXES = ("/dev", "/share", "/tmp/dev", "/usr/dev")


def log(data):
    with open("compare_log.txt", "a") as f:
        f.write(data + "\n")


def firmware_name(tarfile):
    """'./images/12.tar.gz' -> '12'"""
    return os.path.basename(tarfile)[: os.path.basename(tarfile).find(".tar.gz")]


def brand_of(tarfile):
    """Brand = first directory below ./images, '' for a flat layout."""
    rel = os.path.relpath(tarfile, "images")
    parts = rel.split(os.sep)
    return parts[0] if len(parts) > 1 and parts[0] != ".." else ""


def result_dir(brand, tarfile):
    return os.path.join("work", brand, firmware_name(tarfile))


def getimage(tarfile):
    tarfilename = tarfile[: tarfile.find(".tar.gz")]
    for dirname, dirnames, filenames in os.walk("./scratch"):
        for filename in filenames:
            if os.path.basename(dirname) == tarfilename and filename == "image.raw":
                return os.path.join(dirname, filename)


def skip_dir(rootdir):
    """rootdir is the directory inside the image, e.g. '/etc' ('' for root)."""
    return rootdir.startswith(SKIPPED_PREFIXES)


def copy_file(src, dst):
    """Copy a file (a symlink is copied as a link, never followed). An
    existing destination is replaced, never written through."""
    if os.path.lexists(dst):
        os.remove(dst)
    if os.path.islink(src):
        os.symlink(os.readlink(src), dst)
    else:
        shutil.copy(src, dst)


def files_equal(a, b):
    """Compare two paths without following symlinks."""
    if os.path.islink(a) or os.path.islink(b):
        return (os.path.islink(a) and os.path.islink(b)
                and os.readlink(a) == os.readlink(b))
    return filecmp.cmp(a, b, shallow=False)


def is_comparable(path):
    """Regular files and symlinks only (a FIFO or device would block/hang)."""
    return os.path.islink(path) or os.path.isfile(path)


def write_diff(a, b, out):
    """Write `diff a b` into the file `out`."""
    if os.path.islink(a) or os.path.islink(b):
        with open(out, "w") as f:
            for p in (a, b):
                f.write("%s -> %s\n" % (p, os.readlink(p) if os.path.islink(p) else "(not a symlink)"))
        return
    with open(out, "w") as f:
        res = subprocess.run(["diff", "--", a, b], stdout=f)
    if res.returncode > 1:
        print("[-] diff failed for " + b)


def extract_tar(tarfile, dest):
    subprocess.run(
        ["tar", "xzf", os.path.abspath(tarfile), "-C", dest,
         "--no-same-owner", "--no-same-permissions"],
        check=True)


def _wait_for_node(path, timeout=5.0):
    """Partition nodes appear shortly after losetup --partscan."""
    end = time.time() + timeout
    while not os.path.exists(path):
        if time.time() > end:
            raise OSError("partition device %s did not appear" % path)
        time.sleep(0.1)


def attach_loop(imagefile):
    """Attach the image to a free loop device and return its name."""
    res = subprocess.run(
        ["losetup", "--find", "--show", "--partscan", imagefile],
        check=True, stdout=subprocess.PIPE, universal_newlines=True)
    dev = res.stdout.strip()
    if not dev.startswith("/dev/"):
        raise OSError("unexpected losetup output: %r" % res.stdout)
    return dev


def checkExist(brand, tarfile, imagefile):
    resultDir = result_dir(brand, tarfile)
    work = tempfile.mkdtemp(prefix="compare_work_", dir=".")
    try:
        tardir = os.path.join(work, "tar")
        os.makedirs(tardir)
        extract_tar(tarfile, tardir)

        for dirname, dirnames, filenames in os.walk(tardir):
            for filename in filenames:
                if filename.find("preinit") != -1:
                    filepath = os.path.join(dirname, filename)
                    print("[*] find init file : " + filepath)
                    dstfilepath = os.path.join(resultDir, os.path.relpath(filepath, tardir))
                    os.makedirs(os.path.dirname(dstfilepath), exist_ok=True)
                    copy_file(filepath, dstfilepath)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def compareconf(brand, tarfile, imagefile):
    resultDir = result_dir(brand, tarfile)
    for dirname, dirnames, filenames in os.walk(os.path.dirname(imagefile)):
        for filename in filenames:
            if filename not in fileList:
                src = os.path.join(dirname, filename)
                print("[*] find config file : " + src)
                os.makedirs(resultDir, exist_ok=True)
                copy_file(src, os.path.join(resultDir, filename))


def compare_trees(tardir, imagedir, resultDir):
    for dirname, dirnames, filenames in os.walk(imagedir):
        rel = os.path.relpath(dirname, imagedir)
        rootdir = "" if rel == "." else "/" + rel
        if skip_dir(rootdir):
            continue
        for filename in filenames:
            if filename.endswith("ttyS1"):
                continue
            tarfilepath = os.path.join(tardir, rootdir.lstrip("/"), filename)
            imagefilepath = os.path.join(dirname, filename)
            resultfilefolder = os.path.join(resultDir, rootdir.lstrip("/"))

            if not is_comparable(imagefilepath):
                continue

            if not os.path.lexists(tarfilepath):
                os.makedirs(resultfilefolder, exist_ok=True)
                copy_file(imagefilepath, os.path.join(resultfilefolder, filename + ".new"))
            elif is_comparable(tarfilepath) and not files_equal(tarfilepath, imagefilepath):
                os.makedirs(resultfilefolder, exist_ok=True)
                copy_file(imagefilepath, os.path.join(resultfilefolder, filename))
                write_diff(tarfilepath, imagefilepath,
                           os.path.join(resultfilefolder, filename + ".diff"))


def compare(brand, tarfile, imagefile):
    resultDir = os.path.join(result_dir(brand, tarfile), "image")
    os.makedirs(resultDir, exist_ok=True)

    work = tempfile.mkdtemp(prefix="compare_work_", dir=".")
    loopdev = None
    mounted = False
    try:
        tardir = os.path.join(work, "tar")
        mnt = os.path.join(work, "image")
        os.makedirs(tardir)
        os.makedirs(mnt)
        extract_tar(tarfile, tardir)

        rawimage = os.path.join(work, "image.raw")
        shutil.copyfile(imagefile, rawimage)

        loopdev = attach_loop(rawimage)
        part = loopdev + "p1"
        _wait_for_node(part)
        subprocess.run(["mount", "-o", "ro,nodev,nosuid,noexec", part, mnt], check=True)
        mounted = True

        compare_trees(tardir, mnt, resultDir)
    finally:
        if mounted:
            mounted = subprocess.run(["umount", mnt]).returncode != 0
        if loopdev:
            # only the device this run attached
            subprocess.run(["losetup", "-d", loopdev])
        if mounted:
            print("[-] %s is still mounted; not deleting it" % mnt)
        else:
            shutil.rmtree(work, ignore_errors=True)


def main():
    for dirname, dirnames, filenames in os.walk("./images"):
        for filename in filenames:
            if filename.endswith(".tar.gz"):
                imagefile = getimage(filename)
                tarfile = os.path.join(dirname, filename)

                if imagefile is None:
                    log("[*] can't found - " + tarfile)
                    continue

                brand = brand_of(tarfile)
                print("[*] compare now - " + tarfile)
                # checkExist(brand, tarfile, imagefile)
                try:
                    compare(brand, tarfile, imagefile)
                    compareconf(brand, tarfile, imagefile)
                except (subprocess.CalledProcessError, OSError) as e:
                    print("[-] %s: %s" % (tarfile, e), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
