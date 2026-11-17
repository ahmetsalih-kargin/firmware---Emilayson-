"""secure_workdir() in firmae.config (REFACTORING_PLAN 2.4, SECURITY.md S2)."""

import os
import re
import stat
import subprocess

import pytest

pytestmark = pytest.mark.linux


def mode(p):
    return stat.S_IMODE(os.lstat(p).st_mode)


def test_secure_workdir_removes_world_writable_bits(repo_root, tmp_path):
    scratch = tmp_path / "scratch"
    work = scratch / "1"
    (work / "analysis_log").mkdir(parents=True)
    for p in (work, work / "analysis_log"):
        p.chmod(0o777)
    run_sh = work / "run.sh"
    run_sh.write_text("#!/bin/bash\n")
    run_sh.chmod(0o777)
    (work / "result").write_text("true\n")
    (work / "result").chmod(0o666)

    res = subprocess.run(
        ["bash", "-c", 'source ./firmae.config && SCRATCH_DIR="$1" && secure_workdir "$2"',
         "_", str(scratch), str(work)],
        cwd=repo_root, capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr

    assert mode(work) == 0o755
    assert mode(work / "analysis_log") == 0o755
    assert mode(run_sh) == 0o755           # still executable, no longer writable by others
    assert mode(work / "result") == 0o644
    st, parent = os.stat(work), os.stat(scratch)
    assert (st.st_uid, st.st_gid) == (parent.st_uid, parent.st_gid)


def test_no_world_writable_chmod_left_in_host_scripts(repo_root):
    """Regression guard: the old `chmod -R a+rwx` / `chmod a+rw` must not come back."""
    for rel in ("run.sh", "scripts/makeImage.sh", "firmae/image.py"):
        text = (repo_root / rel).read_text()
        assert "a+rwx" not in text and "a+rw " not in text and 'a+rw "' not in text, rel
    # makeImage's host side (Python since 4.3): no group/world-writable chmod of
    # anything in scratch/<IID> (image.raw, init, service)
    text = (repo_root / "firmae/image.py").read_text()
    for m in re.finditer(r"\b(?:f?chmod)\([^)]*?(0o[0-7]+)\)", text):
        assert not int(m.group(1), 8) & 0o022, m.group(0)


def test_make_image_leaves_its_results_not_writable_by_others(tmp_path):
    from firmae import image
    img, work = tmp_path / "img", tmp_path / "work"
    (img / "firmadyne").mkdir(parents=True)
    work.mkdir()
    (img / "firmadyne/init").write_text("/sbin/init\n")
    (img / "firmadyne/init").chmod(0o777)
    (img / "firmadyne/service").write_text("/bin/boa")
    (img / "firmadyne/service").chmod(0o666)
    old = os.umask(0)
    try:
        image.take_result(str(img), "init", str(work), move=True)
        image.take_result(str(img), "service", str(work), move=False)
    finally:
        os.umask(old)
    assert mode(work / "init") == 0o644
    assert mode(work / "service") == 0o644
