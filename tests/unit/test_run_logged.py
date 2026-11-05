"""Regression guards for the log redirections (REFACTORING_PLAN 2.9). The
run_logged() shell function became firmae/pipeline.py's _step() in Phase 4;
its behaviour is tested in test_pipeline.py."""

import pytest

pytestmark = pytest.mark.linux


def test_no_reversed_redirections_left(repo_root):
    """`2>&1 > file` sends stderr to the terminal and keeps it out of the log."""
    for rel in ("run.sh", "scripts/check_emulation.sh", "scripts/run_mode.sh"):
        for line in (repo_root / rel).read_text().splitlines():
            if line.lstrip().startswith("#"):
                continue
            if "2>&1 >" in line and "/dev/null" not in line:
                pytest.fail("%s: %s" % (rel, line.strip()))
