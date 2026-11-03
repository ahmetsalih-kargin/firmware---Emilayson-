"""analyses/nmap.sh finds its target and leaves the XML report where
fuzzer.py reads it (REFACTORING_PLAN 2.7). nmap and sudo are stubs."""

import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.linux


@pytest.fixture
def env(repo_root, tmp_path):
    # a throw-away FirmAE tree: nmap.sh + firmae.config, scratch/1
    root = tmp_path / "FirmAE"
    (root / "analyses").mkdir(parents=True)
    shutil.copy(repo_root / "firmae.config", root / "firmae.config")
    shutil.copy(repo_root / "analyses" / "nmap.sh", root / "analyses" / "nmap.sh")
    (root / "scratch" / "1").mkdir(parents=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "sudo").write_text('#!/bin/sh\nexec "$@"\n')
    calls = tmp_path / "nmap_args"
    (bindir / "nmap").write_text(
        '#!/bin/sh\necho "$@" > "%s"\n'
        'while [ $# -gt 0 ]; do [ "$1" = -oA ] && echo "<nmaprun/>" > "$2.xml"; shift; done\n'
        'echo "Nmap done"\n' % calls)
    for f in bindir.iterdir():
        f.chmod(0o755)
    e = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    e.pop("FIRMAE_DOCKER", None)
    return root, e, calls


def run(root, e, *args):
    return subprocess.run(["bash", "./nmap.sh", *args], cwd=root / "analyses", env=e,
                          capture_output=True, text=True, timeout=30)


def test_uses_target_argument_and_writes_report_for_fuzzer(env):
    root, e, calls = env
    res = run(root, e, "1", "192.168.0.1")
    assert res.returncode == 0, res.stdout + res.stderr
    assert calls.read_text().split()[-3:] == ["192.168.0.1", "-oA", str(root / "scratch/1/nmap-basic-tcp")]
    assert (root / "scratch/1/analysis_log/nmap_log.txt").read_text() == "<nmaprun/>\n"
    assert (root / "scratch/1/nmap-basic-tcp.txt").exists()


def test_falls_back_to_recorded_ip(env):
    root, e, calls = env
    (root / "scratch/1/ip").write_text("192.168.0.100\n")
    assert run(root, e, "1").returncode == 0
    assert "192.168.0.100" in calls.read_text()


def test_no_ip_and_bad_iid_fail_cleanly(env):
    root, e, calls = env
    res = run(root, e, "1")
    assert res.returncode == 1 and "no target IP" in res.stdout
    res = run(root, e, "1;id", "1.2.3.4")
    assert res.returncode == 1 and not calls.exists()
