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

    real_run = subprocess.run      # mod.sp IS subprocess: other callers keep the real one

    def fake_run(argv, *args, **kwargs):      # docker exec ... pgrep: still running
        if isinstance(argv, list) and argv[:1] == ["docker"]:
            assert not kwargs.get("shell")
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0)
        return real_run(argv, *args, **kwargs)
    monkeypatch.setattr(mod.sp, "run", fake_run)
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


# ---------------------------------------------------------- database port (FIRMAE_DB_PORT)

@pytest.mark.parametrize("env, expected", [
    ({}, []),
    ({"FIRMAE_DB_PORT": "5434"}, ["-e", "FIRMAE_DB_PORT"]),
    ({"FIRMAE_DB_PASSWORD": "pw", "FIRMAE_DB_PORT": "5434"},
     ["-e", "FIRMAE_DB_PASSWORD", "-e", "FIRMAE_DB_PORT"]),
])
def test_database_settings_are_passed_by_name(dh, monkeypatch, env, expected):
    helper, calls, _ = dh
    for name in ("FIRMAE_DB_PASSWORD", "FIRMAE_DB_PORT"):
        monkeypatch.delenv(name, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    helper.run_core(0, "-d", "auto", "/fw/x.bin", "docker0_x")
    run = calls[0]
    image = run.index("fcore")
    passed = [a for i, a in enumerate(run[:image]) if a == "-e" or (i and run[i - 1] == "-e")]
    assert passed == expected
    # only the names: the values never appear on the docker command line
    assert all(v not in run for v in env.values())


# ---------------------------------------------------------- pipeline that ends without a result

def test_check_result_stops_when_the_pipeline_ended_without_a_result(dh, monkeypatch):
    """Measured in Docker mode: makeImage.sh failed, no result file was written and
    docker-helper waited the full 2400 s. Now it stops once run.sh is gone."""
    helper, calls, root = dh
    mod = _mod(helper)
    seen = []

    def gone(argv, *a, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 1)
    monkeypatch.setattr(mod["sp"], "run", gone)
    assert helper.check_result("fw", "docker0_x", "b", 9, True, since=time.time()) is False
    assert seen and seen[0] == ["docker", "exec", "docker0_x", "pgrep", "-f", "python3 -m firmae"]
    assert len(seen) == 1                       # stopped at the first check


def test_check_result_reads_a_result_written_just_before_the_pipeline_ended(dh, monkeypatch):
    helper, calls, root = dh
    mod = _mod(helper)
    d = root / "scratch" / "9"
    d.mkdir()

    def gone(argv, *a, **kw):
        (d / "result").write_text("true")       # finished between the two looks
        return subprocess.CompletedProcess(argv, 1)
    monkeypatch.setattr(mod["sp"], "run", gone)
    assert helper.check_result("fw", "docker0_x", "b", 9, True, since=time.time() - 5) is True


@pytest.mark.parametrize("outcome", [0, 2, "oserror", "timeout"])
def test_pipeline_running_is_assumed_when_unknown(dh, monkeypatch, outcome):
    helper, calls, root = dh
    mod = _mod(helper)

    def run(argv, *a, **kw):
        if outcome == "oserror":
            raise OSError("no docker")
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(argv, 60)
        return subprocess.CompletedProcess(argv, outcome)
    monkeypatch.setattr(mod["sp"], "run", run)
    assert helper.pipeline_running("docker0_x") is True


def test_check_result_keeps_waiting_while_the_pipeline_runs(dh, monkeypatch):
    helper, calls, root = dh
    helper_mod = _mod(helper)
    n = []
    monkeypatch.setattr(helper, "pipeline_running", lambda name: (n.append(1), True)[1])
    assert helper.check_result("fw", "docker0_x", "b", 9, True, since=time.time()) is False
    assert len(n) == 2400 // helper.PIPELINE_CHECK_SECONDS


# ---------------------------------------------------------- container privileges (SECURITY.md S7)

def run_argv_of(dh, monkeypatch, privileged):
    helper, calls, _ = dh
    for name in ("FIRMAE_DB_PASSWORD", "FIRMAE_DB_PORT", "FIRMAE_DOCKER_PRIVILEGED"):
        monkeypatch.delenv(name, raising=False)
    if privileged is not None:
        monkeypatch.setenv("FIRMAE_DOCKER_PRIVILEGED", privileged)
    helper.run_core(0, "-d", "auto", "/fw dir/x.bin", "docker0_x")
    return calls[0], helper.firmae_root


def test_default_run_argv_is_the_narrowed_set(dh, monkeypatch):
    run, root = run_argv_of(dh, monkeypatch, None)
    assert run == ["docker", "run", "-dit", "--rm",
                   "-v", "%s:/work/FirmAE" % root, "-v", "/fw dir:/work/firmwares",
                   "--cap-add", "SYS_ADMIN", "--cap-add", "NET_ADMIN",
                   "--device", "/dev/loop-control", "--device", "/dev/net/tun",
                   "--device-cgroup-rule", "b 7:* rmw",
                   "--name", "docker0_x", "fcore"]
    assert not any("privileged" in a for a in run) and "/dev:/dev" not in run
    # block major 259 is also the NVMe disk: never allowed (audit finding)
    assert not any("259" in a for a in run)


@pytest.mark.parametrize("value", ["0", "", "yes", "true"])
def test_only_exactly_1_enables_privileged(dh, monkeypatch, value):
    run, _ = run_argv_of(dh, monkeypatch, value)
    assert "--privileged=true" not in run and "/dev:/dev" not in run


def test_privileged_escape_hatch_restores_the_old_flags_exactly(dh, monkeypatch):
    run, root = run_argv_of(dh, monkeypatch, "1")
    assert run == ["docker", "run", "-dit", "--rm",
                   "-v", "/dev:/dev",
                   "-v", "%s:/work/FirmAE" % root, "-v", "/fw dir:/work/firmwares",
                   "--privileged=true",
                   "--name", "docker0_x", "fcore"]


@pytest.mark.parametrize("privileged", [None, "1"])
def test_env_names_come_right_after_run_in_both_modes(dh, monkeypatch, privileged):
    helper, calls, _ = dh
    monkeypatch.delenv("FIRMAE_DB_PASSWORD", raising=False)
    monkeypatch.delenv("FIRMAE_DOCKER_PRIVILEGED", raising=False)
    if privileged:
        monkeypatch.setenv("FIRMAE_DOCKER_PRIVILEGED", privileged)
    monkeypatch.setenv("FIRMAE_DB_PORT", "5434")
    helper.run_core(0, "-d", "auto", "/fw/x.bin", "docker0_x")
    assert calls[0][4:6] == ["-e", "FIRMAE_DB_PORT"]


# ---------------------------------------------------------- AppArmor (docker-default denies mount)

@pytest.mark.parametrize("daemon, privileged, setting, expected", [
    (False, False, None, []),
    (None, False, None, []),                                   # unknown: try without
    (False, False, "unconfined", []),                          # nothing to opt out of
    (True, True, None, []),                                    # --privileged is unconfined
    (True, False, "unconfined", ["--security-opt", "apparmor=unconfined"]),
])
def test_apparmor_flags(dh, daemon, privileged, setting, expected):
    mod = _mod(dh[0])
    assert mod["apparmor_flags"](daemon, privileged, setting) == expected


@pytest.mark.parametrize("setting", [None, "", "1", "yes", "Unconfined", "unconfined "])
def test_apparmor_without_an_explicit_opt_in_refuses_with_a_clear_message(dh, setting):
    mod = _mod(dh[0])
    with pytest.raises(mod["DockerSetupError"]) as e:
        mod["apparmor_flags"](True, False, setting)
    assert "FIRMAE_DOCKER_APPARMOR=unconfined" in str(e.value)


@pytest.mark.parametrize("out, expected", [
    (b'["name=seccomp,profile=builtin","name=cgroupns"]', False),
    (b'["name=apparmor","name=seccomp,profile=builtin"]', True),
    (b'null', None), (b'not json', None), (b'{"a": 1}', None),
])
def test_daemon_has_apparmor_parses_docker_info(dh, monkeypatch, out, expected):
    mod = _mod(dh[0])
    seen = []
    monkeypatch.setattr(mod["sp"], "check_output", lambda argv, **kw: (seen.append(argv), out)[1])
    assert mod["daemon_has_apparmor"]() is expected
    assert seen == [["docker", "info", "--format", "{{json .SecurityOptions}}"]]


def test_daemon_has_apparmor_when_docker_fails_is_unknown(dh, monkeypatch):
    mod = _mod(dh[0])

    def boom(argv, **kw):
        raise OSError("no docker")
    monkeypatch.setattr(mod["sp"], "check_output", boom)
    assert mod["daemon_has_apparmor"]() is None


def test_apparmor_host_gets_the_opt_in_flag_and_privileged_ignores_it(dh, monkeypatch):
    helper, calls, root = dh
    helper.daemon_apparmor = True
    for name in ("FIRMAE_DB_PASSWORD", "FIRMAE_DB_PORT", "FIRMAE_DOCKER_PRIVILEGED"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FIRMAE_DOCKER_APPARMOR", "unconfined")
    helper.run_core(0, "-d", "auto", "/fw/x.bin", "docker0_x")
    run = calls[0]
    assert run[-5:] == ["--security-opt", "apparmor=unconfined", "--name", "docker0_x", "fcore"]
    calls.clear()
    monkeypatch.setenv("FIRMAE_DOCKER_PRIVILEGED", "1")
    helper.run_core(0, "-d", "auto", "/fw/x.bin", "docker0_x")
    assert "--security-opt" not in calls[0] and "--privileged=true" in calls[0]


def test_apparmor_host_without_opt_in_does_not_start_a_container(dh, monkeypatch, tmp_path):
    helper, calls, root = dh
    mod = _mod(helper)
    helper.daemon_apparmor = True
    monkeypatch.delenv("FIRMAE_DOCKER_APPARMOR", raising=False)
    monkeypatch.delenv("FIRMAE_DOCKER_PRIVILEGED", raising=False)
    fw = tmp_path / "x.bin"
    fw.write_text("x")
    monkeypatch.setattr(helper, "stop_core", lambda n: b"")
    assert mod["runner"]((0, helper, "-c", "b", str(fw))) is False
    assert not [c for c in calls if c[:2] == ["docker", "run"]]


# ---------------------------------------------------------- stopping (loop devices are the kernel's)

def test_stop_core_terminates_the_pipeline_releases_loops_then_stops(dh, monkeypatch):
    helper, calls, _ = dh
    states = iter([True, True, False])
    monkeypatch.setattr(helper, "pipeline_running", lambda name: next(states))
    helper.stop_core("docker0_x")
    docker = [c for c in calls if c[:1] == ["docker"]]
    assert docker == [
        ["docker", "exec", "docker0_x", "pkill", "-TERM", "-f", "python3 -m firmae"],
        ["docker", "exec", "docker0_x", "bash", "-c",
         "cd /work/FirmAE && source ./firmae.config && release_container_loops"],
        ["docker", "stop", "docker0_x"],
    ]


def test_stop_core_without_a_running_pipeline_does_not_wait(dh, monkeypatch):
    helper, calls, _ = dh
    mod = _mod(helper)
    real_run = subprocess.run

    def run(argv, *a, **kw):
        if argv[:1] == ["docker"]:
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 1 if "pkill" in argv else 0)
        return real_run(argv, *a, **kw)
    monkeypatch.setattr(mod["sp"], "run", run)
    waited = []
    monkeypatch.setattr(helper, "pipeline_running", lambda name: waited.append(1) or True)
    helper.stop_core("docker0_x")
    assert waited == []
    assert calls[-1] == ["docker", "stop", "docker0_x"]


def test_stop_core_still_stops_when_docker_exec_fails(dh, monkeypatch):
    helper, calls, _ = dh
    mod = _mod(helper)

    def run(argv, *a, **kw):
        raise OSError("docker exec failed")
    monkeypatch.setattr(mod["sp"], "run", run)
    helper.stop_core("docker0_x")
    assert calls[-1] == ["docker", "stop", "docker0_x"]
