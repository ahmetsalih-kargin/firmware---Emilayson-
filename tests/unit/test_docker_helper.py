"""docker-helper.py builds docker command lines without a shell
(REFACTORING_PLAN 2.6, SECURITY.md S6). Docker itself is never called."""

import importlib.util
import subprocess

import pytest

pytest.importorskip("coloredlogs")
pytest.importorskip("psycopg2")

EVIL = "fw$(touch PWNED);`id`.bin"


@pytest.fixture
def dh(repo_root, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("docker_helper", repo_root / "docker-helper.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    calls = []

    def fake(argv, *args, **kwargs):
        assert not kwargs.get("shell"), "shell=True used"
        assert isinstance(argv, list), "command passed as a string"
        calls.append(argv)
        return b"CONTAINER ID   IMAGE   NAMES\n"

    monkeypatch.setattr(mod.sp, "check_output", fake)
    monkeypatch.setattr(mod.sp, "call", fake)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(mod.util, "get_iid", lambda path, ip: "")
    (tmp_path / "scratch").mkdir()
    (tmp_path / "scratch" / (EVIL + ".log")).write_text("[*] start\n\n")
    helper = mod.docker_helper(str(tmp_path))
    calls.clear()
    return helper, calls, tmp_path


def test_check_mode_passes_names_as_arguments(dh):
    helper, calls, root = dh
    helper.run_core(0, "-c", "d;link", "/fw dir/" + EVIL, "docker0_x")
    run, exe = calls[0], calls[1]
    assert run[:4] == ["docker", "run", "-dit", "--rm"]
    assert "/fw dir:/work/firmwares" in run
    assert exe[:4] == ["docker", "exec", "-d", "docker0_x"]
    assert exe[4:6] == ["bash", "-c"]
    script = exe[6]
    assert EVIL not in script and "d;link" not in script     # never pasted into the script
    assert exe[7:] == ["_", "-c", "d;link", EVIL]              # positional parameters $1..$3
    assert '> "/work/FirmAE/scratch/$3.log" 2>&1' in script


def test_positional_parameters_are_not_evaluated_by_bash(dh, tmp_path):
    """Run the in-container script with a fake run.sh to prove $3 stays inert."""
    helper, _, _ = dh
    work = tmp_path / "work"
    work.mkdir()
    (work / "run.sh").write_text('#!/bin/sh\nprintf "%s|" "$@"\n')
    (work / "run.sh").chmod(0o755)
    script = helper.RUN_IN_CONTAINER.replace("/work/FirmAE", str(work))
    out = subprocess.run(["bash", "-c", script, "_", "-c", "d;link", EVIL],
                         cwd=tmp_path, capture_output=True, text=True)
    assert out.stdout == "-c|d;link|/work/firmwares/%s|" % EVIL
    assert not (tmp_path / "PWNED").exists() and not (work / "PWNED").exists()


def test_debug_mode_is_interactive(dh):
    helper, calls, _ = dh
    helper.run_core(0, "-d", "auto", "/fw/" + EVIL, "docker0_x")
    assert calls[1][:4] == ["docker", "exec", "-it", "docker0_x"]
    assert calls[1][-3:] == ["-d", "auto", EVIL]


def test_run_command_and_script(dh):
    helper, calls, _ = dh
    helper.run_command("core1", "ls; id")
    helper.run_script("core1", "some/dir/x.sh")
    assert calls == [["docker", "exec", "core1", "bash", "-c", "ls; id"],
                     ["docker", "cp", "some/dir/x.sh", "core1:/"],
                     ["docker", "exec", "core1", "/x.sh"]]
