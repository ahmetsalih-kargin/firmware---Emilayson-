"""Fixes from the independent review (core): the emulation check
(scripts/check_emulation.sh -> firmae/check.py) limits the guest-supplied
address count, secure_workdir refuses a symlinked work directory. System
commands are stubs; nothing is emulated or signalled."""

import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.linux


def stub(d, name, body):
    p = d / name
    p.write_text("#!/bin/bash\n" + body + "\n")
    p.chmod(0o755)


class FakeClock:
    """firmae.check.Clock without waiting: whole seconds advance 10 s per
    reading (as the old `date` stub did), sleep does not wait."""

    def __init__(self):
        self.t = 0

    def now(self):
        n = self.t
        self.t += 10
        return n

    def precise(self):
        return 0.0

    def sleep(self, seconds):
        pass


@pytest.fixture
def check_world(repo_root, tmp_path, monkeypatch, capsys):
    """firmae.check (scripts/check_emulation.sh since REFACTORING_PLAN 4.5) in
    this process with a fake clock; curl and ping are stubs."""
    from firmae import check
    root = tmp_path / "FirmAE"
    root.mkdir()
    shutil.copy(repo_root / "firmae.config", root)
    work = root / "scratch" / "5"
    work.mkdir(parents=True)
    (work / "run.sh").write_text("#!/bin/bash\nexit 0\n")
    (work / "run.sh").chmod(0o755)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "net_log"
    stub(bindir, "curl", 'echo "curl $*" >> %s; exit 7' % log)
    stub(bindir, "ping", 'echo "ping $*" >> %s; exit 1' % log)
    monkeypatch.setenv("PATH", "%s:%s" % (bindir, os.environ["PATH"]))
    monkeypatch.delenv("FIRMAE_DOCKER", raising=False)

    def run(ip_num, n_files):
        (work / "ip_num").write_text(ip_num + "\n")
        for i in range(n_files):
            (work / ("ip.%d" % i)).write_text("10.0.%d.%d\n" % (i // 250, i % 250 + 1))
        if log.exists():
            log.unlink()
        capsys.readouterr()
        rc = check.main(["./scripts/check_emulation.sh", "5", "mipsel"], root=str(root), clock=FakeClock())
        out, err = capsys.readouterr()
        res = subprocess.CompletedProcess([], rc, out, err)
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
