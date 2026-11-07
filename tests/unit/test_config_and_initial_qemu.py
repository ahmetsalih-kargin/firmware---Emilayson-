"""Characterization tests for the bash helpers in firmae.config and for the
initial-emulation QEMU command lines in scripts/run.<arch>.sh.

QEMU is never started: a stub `qemu-system-*` on PATH records its argv.
Needs Linux + an LF checkout (marker `linux`), no root.
"""

import os
import shutil
import stat
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
    """r: the project root the script ran in (a temporary copy, see `project`)."""
    common_tail = ["-serial", "file:%s/scratch/1/qemu.initial.serial.log" % r,
                   "-serial", "unix:%s/scratch/1/run/serial1.sock,server,nowait" % r,
                   "-monitor", "unix:%s/scratch/1/run/monitor.sock,server,nowait" % r,
                   "-display", "none"]
    img = "%s/scratch/1/image.raw" % r
    if arch == "armel":
        return (["qemu-system-arm", "-m", "256", "-M", "virt",
                 "-kernel", "%s/binaries//zImage.armel" % r,
                 "-drive", "if=none,file=%s,format=raw,id=rootfs" % img,
                 "-device", "virtio-blk-device,drive=rootfs",
                 "-append", APPEND.format(disk="/dev/vda1")] + common_tail +
                ["-device", "virtio-net-device,netdev=net0", "-netdev", "user,id=net0,restrict=on"])
    binary = {"mipseb": "qemu-system-mips", "mipsel": "qemu-system-mipsel"}[arch]
    # run.mipseb.sh numbers its NICs net1..net4, run.mipsel.sh net0..net3
    ids = range(1, 5) if arch == "mipseb" else range(0, 4)
    nics = []
    for i in ids:
        nics += ["-device", "e1000,netdev=net%d" % i, "-netdev", "user,id=net%d,restrict=on" % i]
    return ([binary, "-m", "256", "-M", "malta",
             "-kernel", "%s/binaries//vmlinux.%s.4" % (r, arch),
             "-drive", "if=ide,format=raw,file=%s" % img,
             "-append", APPEND.format(disk="/dev/sda1")] + common_tail + nics)


@pytest.fixture
def project(repo_root, tmp_path):
    """A throw-away project tree: the scripts create scratch/<IID>/run/ in it."""
    root = tmp_path / "FirmAE"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(repo_root / "firmae.config", root)
    for arch in ("armel", "mipseb", "mipsel"):
        shutil.copy(repo_root / "scripts" / ("run.%s.sh" % arch), root / "scripts")
    (root / "scratch" / "1").mkdir(parents=True)
    return root


def run_initial(project, qemu_stub, arch, fw_net="true", iid="1"):
    bindir, out = qemu_stub
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    env.pop("FIRMAE_DOCKER", None)
    cfg = project / "firmae.config"
    cfg.write_text(cfg.read_text().replace("FIRMAE_NET=true", "FIRMAE_NET=" + fw_net, 1))
    res = subprocess.run(["bash", "scripts/run.%s.sh" % arch, iid, "rdinit=/firmadyne/preInit.sh"],
                         cwd=project, env=env, capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    argv = out.read_text().splitlines()
    argv[0] = Path(argv[0]).name
    return argv


@pytest.mark.parametrize("arch", ["armel", "mipseb", "mipsel"])
def test_initial_emulation_argv(project, qemu_stub, arch):
    argv = run_initial(project, qemu_stub, arch)
    assert argv == expected_argv(str(project), arch)


@pytest.mark.parametrize("arch", ["armel", "mipseb", "mipsel"])
def test_initial_emulation_is_isolated_and_sockets_are_private(project, qemu_stub, arch):
    """Phase 5 (SECURITY.md S8, S12): untrusted firmware runs here for the first
    time -- it must not reach the host or the outside world, and the monitor
    socket must not sit in /tmp."""
    argv = run_initial(project, qemu_stub, arch)
    netdevs = [a for a in argv if a.startswith("user,id=")]
    assert netdevs and all(a.endswith(",restrict=on") for a in netdevs)
    assert not any("/tmp/qemu" in a for a in argv)
    run_dir = project / "scratch" / "1" / "run"
    assert run_dir.is_dir() and stat.S_IMODE(run_dir.stat().st_mode) == 0o700


@pytest.mark.parametrize("arch,expected_ports", [
    ("armel", [20000 + 7 * 4 + n for n in range(4)]),
    ("mipseb", [20000 + 7 * 4 + n for n in range(4)]),
    ("mipsel", [20000 + 7 * 4 + n for n in range(4)]),
])
def test_placeholder_nics_without_firmae_net_listen_on_loopback(project, qemu_stub, arch, expected_ports):
    (project / "scratch" / "7").mkdir()
    argv = run_initial(project, qemu_stub, arch, fw_net="false", iid="7")
    listens = [a for a in argv if a.startswith("socket,id=")]
    assert [a.split("listen=")[1] for a in listens] == ["127.0.0.1:%d" % p for p in expected_ports]


def test_stale_sockets_are_removed_before_start(project, qemu_stub):
    run_dir = project / "scratch" / "1" / "run"
    run_dir.mkdir()
    (run_dir / "monitor.sock").write_text("stale")
    run_initial(project, qemu_stub, "mipsel")
    assert not (run_dir / "monitor.sock").exists()
