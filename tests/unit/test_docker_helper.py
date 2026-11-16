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


# ---------------------------------------------------------- hardening fixes

import os  # noqa: E402
import time  # noqa: E402

import pytest  # noqa: E402,F811


def _mod(helper):
    return type(helper).__init__.__globals__


def test_waits_for_iid_instead_of_giving_up_on_first_empty_answer(dh, monkeypatch):
    helper, calls, root = dh
    mod = _mod(helper)
    answers = iter([""] * 20 + [5])
    n = []
    monkeypatch.setattr(mod["util"], "get_iid", lambda p, ip: (n.append(1), next(answers))[1])
    (root / "images").mkdir()
    (root / "images" / "5.tar.gz").write_text("x")
    seen = {}

    def fake_check(firmware, name, brand, iid, is_emulation=True, since=None):
        seen["since"] = since
        return True
    monkeypatch.setattr(helper, "check_result", fake_check)
    helper.run_core(0, "-c", "b", "/fw/x.bin", "docker0_x")
    assert len(n) == 21 and isinstance(seen["since"], float)


def test_iid_never_appearing_is_a_failure_and_db_errors_are_retried(dh, monkeypatch):
    helper, calls, root = dh
    mod = _mod(helper)

    def boom(p, ip):
        raise RuntimeError("db down")
    monkeypatch.setattr(mod["util"], "get_iid", boom)
    helper.IID_WAIT_SECONDS = 5
    assert helper._run_core(0, "-c", "b", "/fw/x.bin", "docker0_x") == ("docker0_x", False)


def test_check_result_ignores_stale_result_file(dh):
    helper, _, root = dh
    d = root / "scratch" / "7"
    d.mkdir()
    res = d / "result"
    res.write_text("true")
    os.utime(res, (1000, 1000))
    assert helper.check_result("fw", "d", "b", 7, True, since=time.time()) is False
    os.utime(res, None)
    assert helper.check_result("fw", "d", "b", 7, True, since=time.time() - 5) is True
    res.write_text("false")
    assert helper.check_result("fw", "d", "b", 7, True, since=time.time() - 5) is False


def test_parse_firmware_list_skips_bad_lines(dh):
    mod = _mod(dh[0])
    out = mod["parse_firmware_list"](["asus,/a/x.bin", "", "garbage", ",/p", "b,", "c,/d,ir/y.bin"])
    assert out == [["asus", "/a/x.bin"], ["c", "/d,ir/y.bin"]]


def test_runner_reports_failure_and_always_stops_container(dh, monkeypatch, tmp_path):
    helper, calls, root = dh
    mod = _mod(helper)
    fw = tmp_path / "x.bin"
    fw.write_text("x")
    stopped = []
    monkeypatch.setattr(helper, "stop_core", lambda n: stopped.append(n))

    def explode(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(helper, "_run_core", explode)
    assert mod["runner"]((0, helper, "-c", "b", str(fw))) is False
    assert stopped == ["docker0_x.bin"]
    monkeypatch.setattr(helper, "_run_core", lambda *a: ("n", True))
    assert mod["runner"]((0, helper, "-c", "b", str(fw))) is True
    assert mod["runner"]((0, helper, "-c", "b", str(tmp_path / "missing"))) is False


def test_batch_exits_nonzero_when_a_firmware_fails(dh, monkeypatch, tmp_path):
    helper, calls, root = dh
    mod = _mod(helper)
    fw = tmp_path / "x.bin"
    fw.write_text("x")
    lst = tmp_path / "fw.list"
    lst.write_text("b,%s\nbad line\n\nb,%s\n" % (fw, tmp_path / "nothere"))

    class Res:
        def __init__(self, v):
            self.v = v

        def get(self):
            return self.v

    class Pool:
        def __init__(self, n):
            pass

        def apply_async(self, fn, args):
            return Res(fn(*args))

        def close(self):
            pass

        def join(self):
            pass
    monkeypatch.setattr(mod["mp"], "Pool", Pool)
    monkeypatch.setattr(mod["docker_helper"], "_run_core", lambda *a: ("n", True))
    monkeypatch.setattr(mod["docker_helper"], "stop_core", lambda self, n: b"")
    monkeypatch.chdir(root)
    monkeypatch.setattr(mod["sys"], "argv", ["docker-helper.py", "-ec", "b", str(lst)])
    with pytest.raises(SystemExit) as e:
        mod["main"]()
    assert e.value.code == 1                       # the missing firmware failed
    lst.write_text("b,%s\n" % fw)
    mod["main"]()                                  # all good: returns normally
