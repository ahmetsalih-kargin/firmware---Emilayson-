"""run_logged() in run.sh (REFACTORING_PLAN 2.9): stdout and stderr go to the
log; failures show the log tail and stop with the command's exit code."""

import re
import subprocess

import pytest

pytestmark = pytest.mark.linux


@pytest.fixture
def run_logged(repo_root):
    text = (repo_root / "run.sh").read_text()
    m = re.search(r"^function run_logged\(\)\n\{\n.*?^\}\n", text, re.S | re.M)
    assert m, "run_logged not found in run.sh"
    return m.group(0)


def bash(func, body, cwd):
    return subprocess.run(["bash", "-c", "set -e\nset -u\n" + func + body],
                          cwd=cwd, capture_output=True, text=True, timeout=30)


def test_success_captures_both_streams(run_logged, tmp_path):
    res = bash(run_logged, 'run_logged out.log sh -c "echo to-stdout; echo to-stderr >&2"\necho after\n',
               tmp_path)
    assert res.returncode == 0
    assert res.stdout == "after\n" and res.stderr == ""
    assert (tmp_path / "out.log").read_text() == "to-stdout\nto-stderr\n"


def test_failure_shows_tail_and_keeps_exit_code(run_logged, tmp_path):
    res = bash(run_logged, 'run_logged out.log sh -c "echo boom >&2; exit 7"\necho NOT-REACHED\n',
               tmp_path)
    assert res.returncode == 7
    assert "NOT-REACHED" not in res.stdout
    assert "sh failed (exit 7)" in res.stderr and "boom" in res.stderr


def test_env_prefix_form(run_logged, tmp_path):
    res = bash(run_logged, 'run_logged out.log env FOO=bar sh -c \'echo "$FOO"\'\n', tmp_path)
    assert res.returncode == 0
    assert (tmp_path / "out.log").read_text() == "bar\n"


def test_no_reversed_redirections_left(repo_root):
    """Regression guard for `2>&1 > file` (stderr to terminal) in log redirects."""
    for rel in ("run.sh", "scripts/check_emulation.sh"):
        for line in (repo_root / rel).read_text().splitlines():
            if line.lstrip().startswith("#"):
                continue
            if "2>&1 >" in line and "/dev/null" not in line:
                pytest.fail("%s: %s" % (rel, line.strip()))
