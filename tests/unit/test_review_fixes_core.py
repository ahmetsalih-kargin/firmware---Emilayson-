"""Fixes from the independent review (core): scripts/check_emulation.sh limits
the guest-supplied address count, secure_workdir refuses a symlinked work
directory. System commands are stubs; nothing is emulated or signalled."""

import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.linux


def stub(d, name, body):
    p = d / name
    p.write_text("#!/bin/bash\n" + body + "\n")
    p.chmod(0o755)


@pytest.fixture
def check_world(repo_root, tmp_path):
    root = tmp_path / "FirmAE"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(repo_root / "firmae.config", root)
    shutil.copy(repo_root / "scripts" / "check_emulation.sh", root / "scripts")
    work = root / "scratch" / "5"
    work.mkdir(parents=True)
    (work / "run.sh").write_text("#!/bin/bash\nexit 0\n")
    (work / "run.sh").chmod(0o755)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "net_log"
    stub(bindir, "curl", 'echo "curl $*" >> %s; exit 7' % log)
    stub(bindir, "ping", 'echo "ping $*" >> %s; exit 1' % log)
    stub(bindir, "sleep", "exit 0")
    clock = tmp_path / "clock"                 # `date +%s` advances 10 s per call
    clock.write_text("0")
    stub(bindir, "date", 'if [ "$1" = "+%%s" ]; then n=$(cat %s); echo $n; echo $((n+10)) > %s; '
                         'else echo 0.0; fi' % (clock, clock))
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    env.pop("FIRMAE_DOCKER", None)

    def run(ip_num, n_files):
        (work / "ip_num").write_text(ip_num + "\n")
        for i in range(n_files):
            (work / ("ip.%d" % i)).write_text("10.0.%d.%d\n" % (i // 250, i % 250 + 1))
        if log.exists():
            log.unlink()
        res = subprocess.run(["bash", "./scripts/check_emulation.sh", "5", "mipsel"], cwd=root, env=env,
                             capture_output=True, text=True, timeout=120)
        probed = sorted({l.split()[-1] for l in log.read_text().splitlines() if l.startswith("ping ")}) \
            if log.exists() else []
        return res, probed
    return run


@pytest.mark.parametrize("ip_num,n_files,expected", [
    ("300", 300, 8),          # guest-made: only the first CHECK_MAX_IPS are probed
    ("3", 3, 3),
    ("08", 8, 8),             # not an octal error under set -e
    ("99999999999999999999999", 10, 8),
    ("abc", 3, 0),            # garbled: no address, check_network returns at once
])
def test_check_emulation_limits_the_address_count(check_world, ip_num, n_files, expected):
    res, probed = check_world(ip_num, n_files)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Check inferred emulation end" in res.stdout
    assert len(probed) == expected
    assert probed == sorted("10.0.0.%d" % (i + 1) for i in range(expected))


def test_secure_workdir_refuses_a_symlink(repo_root, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    target.chmod(0o777)
    os.symlink(str(target), str(scratch / "1"))
    res = subprocess.run(
        ["bash", "-c", 'source ./firmae.config && SCRATCH_DIR="$1" && secure_workdir "$2"; echo rc=$?',
         "_", str(scratch), str(scratch / "1")],
        cwd=repo_root, capture_output=True, text=True, timeout=30)
    assert res.stdout.strip() == "rc=1"
    assert "symlink" in res.stderr
    assert (os.stat(target).st_mode & 0o777) == 0o777       # the target was not touched


def test_secure_workdir_leaves_symlink_targets_inside_alone(repo_root, tmp_path):
    """A symlink inside scratch/<IID> (lstat mode 0777) must not make chmod
    change its target."""
    scratch = tmp_path / "scratch"
    work = scratch / "1"
    work.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("x")
    outside.chmod(0o666)
    os.symlink(str(outside), str(work / "link"))
    res = subprocess.run(
        ["bash", "-c", 'source ./firmae.config && SCRATCH_DIR="$1" && secure_workdir "$2"; echo rc=$?',
         "_", str(scratch), str(work)],
        cwd=repo_root, capture_output=True, text=True, timeout=30)
    assert res.stdout.strip() == "rc=0", res.stderr
    assert (os.stat(outside).st_mode & 0o777) == 0o666
