"""Characterization tests for the bash helpers in firmae.config and for the
initial-emulation QEMU command lines in scripts/run.<arch>.sh.

QEMU is never started: a stub `qemu-system-*` on PATH records its argv.
Needs Linux + an LF checkout (marker `linux`), no root.
"""

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.linux, pytest.mark.characterization]


def bash(repo_root, script, env=None):
    """Run `script` in bash after sourcing firmae.config from the repo root."""
    full_env = dict(os.environ)
    full_env.pop("FIRMAE_DOCKER", None)
    full_env.update(env or {})
    res = subprocess.run(["bash", "-c", "source ./firmae.config && " + script],
                         cwd=repo_root, env=full_env, capture_output=True, text=True,
                         timeout=30)
    return res


# --------------------------------------------------------------------------
# firmae.config helper functions
# --------------------------------------------------------------------------

@pytest.mark.parametrize("arch,qemu,machine,disk,kernel", [
    ("armel", "qemu-system-arm", "virt", "/dev/vda1", "zImage.armel"),
    ("mipseb", "qemu-system-mips", "malta", "/dev/sda1", "vmlinux.mipseb.4"),
    ("mipsel", "qemu-system-mipsel", "malta", "/dev/sda1", "vmlinux.mipsel.4"),
])
def test_arch_tables(repo_root, arch, qemu, machine, disk, kernel):
    res = bash(repo_root, 'get_qemu {0}; get_qemu_machine {0}; get_qemu_disk {0}; get_kernel {0}'
               .format(arch))
    assert res.returncode == 0, res.stderr
    assert res.stdout.splitlines() == [qemu, machine, disk,
                                       "%s/binaries//%s" % (repo_root, kernel)]


def test_check_arch_uses_inverted_return_codes(repo_root):
    """check_arch returns 1 for a VALID architecture and 0 for an invalid one."""
    res = bash(repo_root, 'check_arch armel; echo $?; check_arch x86; echo $?; check_arch ""; echo $?')
    assert res.stdout.split() == ["1", "0", "0"]


def test_get_scratch_ignores_its_argument(repo_root):
    """KNOWN BUG (firmae.config:233): get_scratch uses the global $IID, not $1."""
    res = bash(repo_root, 'IID=7; get_scratch 3')
    assert res.stdout.strip() == "%s/scratch/7" % repo_root


def test_mipseb_kill_pattern_also_matches_mipsel(repo_root):
    """KNOWN BUG (measured in Phase 0): check_emulation.sh kills
    `ps aux | grep $(get_qemu mipseb)`; that pattern is a prefix of the
    mipsel binary name, so a mipseb run kills mipsel emulations too."""
    res = bash(repo_root, 'get_qemu mipseb')
    pattern = res.stdout.strip()
    assert pattern == "qemu-system-mips"
    assert pattern in "qemu-system-mipsel"


# --------------------------------------------------------------------------
# scripts/run.<arch>.sh — initial emulation command line
# --------------------------------------------------------------------------

@pytest.fixture
def qemu_stub(tmp_path):
    """Directory with fake qemu-system-* binaries that dump argv, one per line."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    out = tmp_path / "argv.txt"
    for name in ("qemu-system-arm", "qemu-system-mips", "qemu-system-mipsel"):
        stub = bindir / name
        stub.write_text('#!/bin/sh\n{ echo "$0"; for a in "$@"; do echo "$a"; done; } > "%s"\n' % out)
        stub.chmod(0o755)
    return bindir, out


APPEND = ("firmadyne.syscall=1 root={disk} console=ttyS0 "
          "nandsim.parts=64,64,64,64,64,64,64,64,64,64 rdinit=/firmadyne/preInit.sh "
          "rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=true FIRMAE_NVRAM=true "
          "FIRMAE_KERNEL=true FIRMAE_ETC=true user_debug=31")


def expected_argv(r, arch):
    common_tail = ["-serial", "file:%s/scratch/1/qemu.initial.serial.log" % r,
                   "-serial", "unix:/tmp/qemu.1.S1,server,nowait",
                   "-monitor", "unix:/tmp/qemu.1,server,nowait",
                   "-display", "none"]
    img = "%s/scratch/1/image.raw" % r
    if arch == "armel":
        return (["qemu-system-arm", "-m", "256", "-M", "virt",
                 "-kernel", "%s/binaries//zImage.armel" % r,
                 "-drive", "if=none,file=%s,format=raw,id=rootfs" % img,
                 "-device", "virtio-blk-device,drive=rootfs",
                 "-append", APPEND.format(disk="/dev/vda1")] + common_tail +
                ["-device", "virtio-net-device,netdev=net0", "-netdev", "user,id=net0"])
    binary = {"mipseb": "qemu-system-mips", "mipsel": "qemu-system-mipsel"}[arch]
    # run.mipseb.sh numbers its NICs net1..net4, run.mipsel.sh net0..net3
    ids = range(1, 5) if arch == "mipseb" else range(0, 4)
    nics = []
    for i in ids:
        nics += ["-device", "e1000,netdev=net%d" % i, "-netdev", "user,id=net%d" % i]
    return ([binary, "-m", "256", "-M", "malta",
             "-kernel", "%s/binaries//vmlinux.%s.4" % (r, arch),
             "-drive", "if=ide,format=raw,file=%s" % img,
             "-append", APPEND.format(disk="/dev/sda1")] + common_tail + nics)


@pytest.mark.parametrize("arch", ["armel", "mipseb", "mipsel"])
def test_initial_emulation_argv(repo_root, qemu_stub, arch):
    bindir, out = qemu_stub
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    env.pop("FIRMAE_DOCKER", None)
    res = subprocess.run(["bash", "scripts/run.%s.sh" % arch, "1", "rdinit=/firmadyne/preInit.sh"],
                         cwd=repo_root, env=env, capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    argv = out.read_text().splitlines()
    argv[0] = Path(argv[0]).name
    assert argv == expected_argv(str(repo_root), arch)
