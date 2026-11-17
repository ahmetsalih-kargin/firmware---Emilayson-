"""The hardware profile steps of firmae/pipeline.py (REFACTORING_PLAN 6.1).

firmae/hwprofile.py is written by someone else and may not exist yet: here it
is a stub in the temporary project tree (`python3 -m firmae.hwprofile` runs with
the project as working directory, so the stub is what gets imported). What is
tested is the pipeline side: arguments, order, the steps never deciding the
outcome of a run, the environment switches, and the one-line summary that
prints only known keys and known values of an untrusted file.
"""

import io
import json
import os
import shutil
import time

import pytest

from firmae import config
from firmae.errors import ExitCode
from firmae.log import Reporter
from firmae.pipeline import Pipeline

# the helpers of test_pipeline.py (tests/unit is on sys.path: no __init__.py)
from test_pipeline import IID, STUBS, fw, project, proc_gone, run  # noqa: F401

pytestmark = pytest.mark.linux

HW_STUB = r'''
import json, os, shutil, sys, time
proj = os.environ["PROJECT"]
argv = sys.argv[1:]
out = argv[argv.index("--out") + 1]
with open(os.path.join(proj, "hw_calls"), "a") as f:
    f.write(json.dumps({
        "argv": argv,
        "image_done": os.path.exists(os.path.join(proj, "image_done")),
        "ping": os.path.exists(os.path.join(os.path.dirname(out), "ping")),
    }) + "\n")
if os.environ.get("STUB_HW_SLEEP"):
    time.sleep(float(os.environ["STUB_HW_SLEEP"]))
if os.environ.get("STUB_HW_WRITE"):
    shutil.copyfile(os.environ["STUB_HW_WRITE"], out)
print("stub hwprofile says hello")
sys.exit(int(os.environ.get("STUB_HW_RC", "0")))
'''

NET_EXTRA = '''
if not os.environ.get('STUB_NO_SERIAL'):
    for n in ('qemu.initial.serial.log', 'qemu.final.serial.log'):
        open(os.path.join(d, n), 'w').write('boot\\n')
'''

GOOD = {"schema": 1, "static": {}, "dynamic": {}, "notes": [],
        "peripherals": {"gpio": {"status": "failing", "evidence": []},
                        "watchdog": {"status": "failing", "evidence": []},
                        "nvram": {"status": "covered", "evidence": []},
                        "i2c": {"status": "not-referenced", "evidence": []},
                        "spi": {"status": "not-referenced", "evidence": []}}}


@pytest.fixture
def hw(project, monkeypatch, tmp_path):
    (project / "firmae").mkdir()
    (project / "firmae" / "__init__.py").write_text("")
    (project / "firmae" / "hwprofile.py").write_text(HW_STUB)
    (project / "scripts/makeNetwork.py").write_text(STUBS["scripts/makeNetwork.py"] + NET_EXTRA)
    for var in ("FIRMAE_HWPROFILE", "FIRMAE_TIMEOUT_HWPROFILE", "STUB_HW_RC", "STUB_HW_SLEEP",
                "STUB_HW_WRITE", "STUB_NO_SERIAL"):
        monkeypatch.delenv(var, raising=False)
    return project


def calls(project):
    p = project / "hw_calls"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def profile_source(tmp_path, content):
    """A file the stub copies to --out. content: dict (JSON) or bytes."""
    p = tmp_path / "profile.src"
    p.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
    return str(p)


def hw_lines(out):
    return [l for l in out.splitlines() if l.startswith("[hw]")]


# ------------------------------------------------------------- arguments, order

def test_static_then_dynamic_with_the_documented_arguments(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    code, out, work = run(hw)
    assert code == ExitCode.OK
    first, second = calls(hw)
    out_json = str(work / "hw_profile.json")
    assert first["argv"] == ["--tar", str(hw / "images" / ("%s.tar.gz" % IID)), "--out", out_json,
                             "--timeout", "240"]
    assert first["image_done"] is False and first["ping"] is False       # before the image is built
    assert second["argv"] == ["--update", "--out", out_json,
                              "--serial-log", str(work / "qemu.initial.serial.log"),
                              "--serial-log", str(work / "qemu.final.serial.log"), "--timeout", "240"]
    assert second["image_done"] is True and second["ping"] is True       # after makeNetwork
    assert "stub hwprofile says hello" in (work / "hwprofile.log").read_text()
    assert not (work / "time_hwprofile").exists()                        # existing time_* files unchanged
    for t in ("extract", "arch", "tar", "image", "network"):
        assert (work / ("time_" + t)).exists()


def test_the_static_log_is_replaced_and_the_dynamic_one_appended(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    _, _, work = run(hw)
    assert (work / "hwprofile.log").read_text().count("stub hwprofile says hello") == 2


def test_only_existing_serial_logs_are_passed(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    (hw / "scripts/makeNetwork.py").write_text(
        STUBS["scripts/makeNetwork.py"] +
        "\nopen(os.path.join(d, 'qemu.final.serial.log'), 'w').write('x')\n")
    code, _, work = run(hw)
    assert code == ExitCode.OK
    second = calls(hw)[1]["argv"]
    assert second.count("--serial-log") == 1
    assert second[second.index("--serial-log") + 1] == str(work / "qemu.final.serial.log")


def test_no_serial_log_skips_the_dynamic_step(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    monkeypatch.setenv("STUB_NO_SERIAL", "1")
    code, out, _ = run(hw)
    assert code == ExitCode.OK
    assert [c["argv"][0] for c in calls(hw)] == ["--tar"]


def test_no_static_profile_skips_the_dynamic_step(hw):
    code, _, _ = run(hw)                    # the stub writes nothing
    assert code == ExitCode.OK
    assert [c["argv"][0] for c in calls(hw)] == ["--tar"]


def test_network_failure_without_serial_logs_keeps_its_code_and_skips_the_dynamic_step(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    monkeypatch.setenv("STUB_NET_RC", "2")
    code, out, work = run(hw)
    assert code == ExitCode.NETWORK
    assert [c["argv"][0] for c in calls(hw)] == ["--tar"]       # the failing stub writes no serial log
    assert "[hw] gpio=failing" in out       # the summary is shown on failure paths too


NET_FAIL_WITH_LOGS = STUBS["scripts/makeNetwork.py"].replace(
    "if os.environ.get('STUB_NET_RC', '0') != '0':",
    "d0 = os.path.join('scratch', sys.argv[sys.argv.index('-i') + 1])\n"
    "open(os.path.join(d0, 'qemu.initial.serial.log'), 'w').write('boot\\n')\n"
    "if os.environ.get('STUB_NET_RC', '0') != '0':")


def test_network_failure_runs_the_dynamic_step_after_the_release_and_keeps_the_code(hw, monkeypatch, tmp_path):
    (hw / "scripts/makeNetwork.py").write_text(NET_FAIL_WITH_LOGS)
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    monkeypatch.setenv("STUB_NET_RC", "2")
    order = []
    pipe_cls = Pipeline
    real_bash = pipe_cls._bash_fn
    real_dyn = pipe_cls._hwprofile_dynamic

    def bash(self, name, *a):
        order.append(name)
        return real_bash(self, name, *a)

    def dyn(self):
        order.append("dynamic")
        return real_dyn(self)
    monkeypatch.setattr(pipe_cls, "_bash_fn", bash)
    monkeypatch.setattr(pipe_cls, "_hwprofile_dynamic", dyn)
    code, out, work = run(hw)
    assert code == ExitCode.NETWORK == 40 and "network boom" in out
    assert [c["argv"][0] for c in calls(hw)] == ["--tar", "--update"]
    assert calls(hw)[1]["argv"].count("--serial-log") == 1
    assert order.index("dynamic") > len(order) - 1 - order[::-1].index("release_emulation")
    assert len(hw_lines(out)) == 1 and out.rindex("[hw]") > out.index("network boom")
    assert not (work / "run_debug.sh").exists()


def test_network_timeout_also_runs_the_dynamic_step(hw, monkeypatch, tmp_path):
    from firmae import pipeline
    (hw / "scripts/makeNetwork.py").write_text(
        NET_FAIL_WITH_LOGS.replace("print('network boom')", "import time; time.sleep(60)"))
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    monkeypatch.setenv("STUB_NET_RC", "2")
    monkeypatch.setenv("FIRMAE_TIMEOUT_NETWORK", "2")
    monkeypatch.setattr(pipeline, "STAGE_GRACE", 1)
    code, _, _ = run(hw)
    assert code == ExitCode.TIMEOUT
    assert [c["argv"][0] for c in calls(hw)] == ["--tar", "--update"]


@pytest.mark.parametrize("make_exc", [KeyboardInterrupt, lambda: SystemExit(143)],
                         ids=["KeyboardInterrupt", "SystemExit"])
def test_signal_during_the_network_step_does_not_run_the_dynamic_step(hw, monkeypatch, tmp_path, make_exc):
    from firmae import pipeline
    (hw / "scripts/makeNetwork.py").write_text(NET_FAIL_WITH_LOGS)
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    real = pipeline.run_with_timeout

    def spy(argv, timeout, **kw):
        if "makeNetwork.py" in " ".join(argv):
            raise make_exc()
        return real(argv, timeout, **kw)
    monkeypatch.setattr(pipeline, "run_with_timeout", spy)
    cfg = config.load(str(hw))
    out = io.StringIO()
    pipe = Pipeline(cfg, "check", "dlink", Reporter(out=out, color=False))
    with pytest.raises((KeyboardInterrupt, SystemExit)):
        pipe.run_firmware(fw(hw))
    assert [c["argv"][0] for c in calls(hw)] == ["--tar"]
    assert pipe._lock_fd is None and pipe._fw_lock_fd is None


# -------------------------------------------------- stale profile, static failure

def test_static_failure_removes_the_old_profile_and_skips_dynamic_and_summary(hw, monkeypatch):
    work = hw / "scratch" / IID
    work.mkdir(parents=True)
    (work / "hw_profile.json").write_text(json.dumps(GOOD))
    monkeypatch.setenv("STUB_HW_RC", "1")
    code, out, _ = run(hw)
    assert code == ExitCode.OK
    assert [c["argv"][0] for c in calls(hw)] == ["--tar"]
    assert not (work / "hw_profile.json").exists()
    assert hw_lines(out) == [] and "failed with exit 1" in out


def test_the_old_profile_is_removed_before_the_static_step(hw, monkeypatch, tmp_path):
    work = hw / "scratch" / IID
    work.mkdir(parents=True)
    (work / "hw_profile.json").write_text("OLD")
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    run(hw)
    assert "OLD" not in (work / "hw_profile.json").read_text()


def test_an_old_symlinked_profile_is_unlinked_not_followed(hw, monkeypatch, tmp_path):
    target = tmp_path / "keepme.json"
    target.write_text("keep")
    work = hw / "scratch" / IID
    work.mkdir(parents=True)
    os.symlink(target, work / "hw_profile.json")
    monkeypatch.setenv("STUB_HW_RC", "1")
    run(hw)
    assert not os.path.lexists(work / "hw_profile.json") and target.read_text() == "keep"


def test_web_unreachable_keeps_exit_50(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    monkeypatch.setenv("STUB_WEB", "false")
    code, out, _ = run(hw)
    assert code == ExitCode.UNREACHABLE and len(hw_lines(out)) == 1


# --------------------------------------------------------------- never fatal

def test_cli_failure_never_stops_the_run_or_changes_the_exit_code(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    monkeypatch.setenv("STUB_HW_RC", "1")
    code, out, work = run(hw)
    assert code == ExitCode.OK
    assert (work / "result").read_text() == "true\n"
    assert len(calls(hw)) == 1             # static failed: no dynamic update of a profile that is not there
    assert out.count("hardware profile (") == 1 and "failed with exit 1" in out
    assert "(hwprofile)" in out and "hwprofile.log" in out
    assert os.path.islink(work / "run_debug.sh")


def test_dynamic_failure_alone_is_only_a_warning(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    from firmae import pipeline
    real = pipeline.run_with_timeout

    def spy(argv, timeout, **kw):
        if "--update" in argv:
            argv = ["python3", "-c", "import sys; print('dyn boom'); sys.exit(3)"]
        return real(argv, timeout, **kw)
    monkeypatch.setattr(pipeline, "run_with_timeout", spy)
    code, out, work = run(hw)
    assert code == ExitCode.OK and "(hwprofile-dynamic) failed with exit 3" in out
    assert "dyn boom" in (work / "hwprofile.log").read_text()


def test_cli_usage_error_exit_2_is_also_only_a_warning(hw, monkeypatch):
    monkeypatch.setenv("STUB_HW_RC", "2")
    code, out, _ = run(hw)
    assert code == ExitCode.OK and "failed with exit 2" in out


def test_missing_module_is_only_a_warning(hw):
    shutil.rmtree(hw / "firmae")
    code, out, work = run(hw)
    assert code == ExitCode.OK
    assert "hardware profile (hwprofile) failed with exit 1" in out
    assert "No module named" in (work / "hwprofile.log").read_text()
    assert (work / "result").read_text() == "true\n"


def test_missing_python_is_only_a_warning(hw, monkeypatch):
    from firmae import pipeline
    real = pipeline.run_with_timeout

    def spy(argv, timeout, **kw):
        if "firmae.hwprofile" in argv:
            raise FileNotFoundError("python3")
        return real(argv, timeout, **kw)
    monkeypatch.setattr(pipeline, "run_with_timeout", spy)
    code, out, _ = run(hw)
    assert code == ExitCode.OK and "hardware profile (hwprofile) not done" in out


def test_a_hanging_cli_is_stopped_and_the_run_succeeds(hw, monkeypatch):
    from firmae import pipeline
    monkeypatch.setattr(pipeline, "HWPROFILE_GRACE", 1)
    monkeypatch.setenv("FIRMAE_TIMEOUT_HWPROFILE", "1")
    monkeypatch.setenv("STUB_HW_SLEEP", "60")
    t0 = time.time()
    code, out, work = run(hw)
    assert code == ExitCode.OK and time.time() - t0 < 40
    assert "hardware profile (hwprofile) timed out after 1s" in out
    assert (work / "result").read_text() == "true\n"
    assert calls(hw)[0]["argv"][-2:] == ["--timeout", "1"]          # 80% of 1 s, but at least 1


# ----------------------------------------------------------- environment

def test_switch_off_runs_neither_step_and_does_not_summarise_an_old_profile(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("FIRMAE_HWPROFILE", "0")
    work = hw / "scratch" / IID
    work.mkdir(parents=True)
    (work / "hw_profile.json").write_text(json.dumps(GOOD))
    code, out, _ = run(hw)
    assert code == ExitCode.OK
    assert calls(hw) == [] and "hardware profile" not in out and hw_lines(out) == []
    assert not (work / "hwprofile.log").exists()
    assert json.loads((work / "hw_profile.json").read_text()) == GOOD


@pytest.mark.parametrize("value", ["", "1", "true", "junk"])
def test_anything_but_0_leaves_it_on(hw, monkeypatch, value):
    monkeypatch.setenv("FIRMAE_HWPROFILE", value)
    run(hw)
    assert len(calls(hw)) == 1


@pytest.mark.parametrize("value,expected", [
    ("junk", "240"), ("-5", "240"), ("", "240"), ("1.5", "240"), ("²", "240"),    # default 300 * 0.8
    ("10", "8"), ("59", "47"), ("300", "240"), ("100", "80"), ("1", "1"), ("2", "1"),
    ("1000", "800"), (" 90 ", "72"),
    ("9" * 5000, "240"),                      # invalid: the default (300) applies
    ("99999999", str(7 * 24 * 3600 * 8 // 10)),   # cut to a week
])
def test_timeout_variable_is_validated_like_the_stage_timeouts(hw, monkeypatch, value, expected):
    monkeypatch.setenv("FIRMAE_TIMEOUT_HWPROFILE", value)
    code, _, _ = run(hw)
    assert code == ExitCode.OK
    argv = calls(hw)[0]["argv"]
    assert argv[-2:] == ["--timeout", expected]


def test_timeout_zero_means_no_outer_limit_but_the_cli_keeps_a_default_budget(hw, monkeypatch):
    from firmae import pipeline
    seen = []
    real = pipeline.run_with_timeout

    def spy(argv, timeout, **kw):
        if "firmae.hwprofile" in argv:
            seen.append(timeout)
        return real(argv, timeout, **kw)
    monkeypatch.setattr(pipeline, "run_with_timeout", spy)
    monkeypatch.setenv("FIRMAE_TIMEOUT_HWPROFILE", "0")
    run(hw)
    assert seen == [None] and calls(hw)[0]["argv"][-2:] == ["--timeout", "240"]


@pytest.mark.parametrize("value", ["10", "59", "300", "0", "9" * 5000])
def test_inner_budget_is_never_longer_than_the_outer_limit(hw, monkeypatch, value):
    from firmae import pipeline
    monkeypatch.setenv("FIRMAE_TIMEOUT_HWPROFILE", value)
    outer = pipeline.stage_timeout("hwprofile", pipeline.HWPROFILE_TIMEOUT)
    run(hw)
    inner = int(calls(hw)[0]["argv"][-1])
    assert inner >= 1 and (outer is None or inner <= outer)


@pytest.mark.parametrize("stage", ["TAR2DB", "IMAGE", "NETWORK", "HWPROFILE"])
def test_stage_timeout_survives_absurd_values(monkeypatch, stage):
    from firmae.pipeline import stage_timeout, MAX_STAGE_TIMEOUT
    name = "FIRMAE_TIMEOUT_" + stage
    monkeypatch.setenv(name, "7" * 5000)
    assert stage_timeout(stage, 123) == 123              # invalid -> the default, as for "junk"
    monkeypatch.setenv(name, "9" * 12)
    assert stage_timeout(stage, 123) == MAX_STAGE_TIMEOUT == 7 * 24 * 3600
    monkeypatch.setenv(name, "0" * 5000 + "45")
    assert stage_timeout(stage, 123) == 45
    monkeypatch.setenv(name, "0" * 5000)
    assert stage_timeout(stage, 123) is None             # 0: no limit
    monkeypatch.setenv(name, "junk")
    assert stage_timeout(stage, 123) == 123


def test_outer_timeout_is_the_variable_itself(hw, monkeypatch):
    from firmae import pipeline
    seen = []
    real = pipeline.run_with_timeout

    def spy(argv, timeout, **kw):
        if "firmae.hwprofile" in argv:
            seen.append(timeout)
        return real(argv, timeout, **kw)
    monkeypatch.setattr(pipeline, "run_with_timeout", spy)
    run(hw)
    assert seen == [pipeline.HWPROFILE_TIMEOUT] == [300]


def test_check_mode_skip_does_not_touch_the_profile(hw):
    work = hw / "scratch" / IID
    work.mkdir(parents=True)
    (work / "result").write_text("true\n")
    (work / "hw_profile.json").write_text(json.dumps(GOOD))
    before = os.stat(work / "hw_profile.json")
    code, out, _ = run(hw)
    assert code == ExitCode.OK and calls(hw) == [] and hw_lines(out) == []
    after = os.stat(work / "hw_profile.json")
    assert (before.st_mtime_ns, before.st_size) == (after.st_mtime_ns, after.st_size)


# ------------------------------------------------------------------- summary

def test_summary_line(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, GOOD))
    _, out, _ = run(hw)
    assert hw_lines(out) == ["[hw] gpio=failing watchdog=failing nvram=covered i2c=not-referenced "
                             "spi=not-referenced (scratch/%s/hw_profile.json)" % IID]


def test_summary_shows_unsupported_and_failing_first(hw, monkeypatch, tmp_path):
    prof = {"peripherals": {k: {"status": s} for k, s in
                            [("gpio", "covered"), ("watchdog", "referenced"), ("i2c", "unsupported"),
                             ("nvram", "failing"), ("wlan", "not-referenced")]}}
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, prof))
    _, out, _ = run(hw)
    assert hw_lines(out)[0].startswith("[hw] nvram=failing i2c=unsupported gpio=covered "
                                       "watchdog=referenced wlan=not-referenced (")


def test_summary_prints_only_known_keys_and_values(hw, monkeypatch, tmp_path):
    esc = "\x1b[31mPWNED\x1b[0m"
    prof = {"schema": esc, "notes": [esc],
            "peripherals": {
                "gpio": {"status": esc, "evidence": [esc]},                  # unknown value: dropped
                "watchdog": {"status": ["failing"]},                         # unhashable: dropped
                "nvram": {"status": "covered", "evidence": [esc]},           # kept; evidence never printed
                "i2c": {"status": "unsupported\n[+] fake line"},             # dropped
                esc: {"status": "failing"},                                  # unknown key: dropped
                "spi\x1b[2J": {"status": "failing"},
                "led": "failing", "mtd": None, "uart": {"status": 7}, "wlan": {}}}
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, prof))
    code, out, _ = run(hw)
    assert code == ExitCode.OK
    assert hw_lines(out) == ["[hw] nvram=covered (scratch/%s/hw_profile.json)" % IID]
    assert "\x1b[31m" not in out and "PWNED" not in out and "fake line" not in out
    assert "\x1b[2J" not in out


def test_summary_is_silent_when_nothing_in_the_profile_is_usable(hw, monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, {"peripherals": {"gpio": {"status": "bogus"}}}))
    code, out, _ = run(hw)
    assert code == ExitCode.OK and hw_lines(out) == []


@pytest.mark.parametrize("content", [
    b"{not json", b"", b"\xff\xfe\x00bad utf8", b"[1, 2, 3]", b'"just a string"', b'{"peripherals": []}',
    b"[" * 200000 + b"]" * 200000,                                         # RecursionError in the parser
    b'{"peripherals": {"gpio": {"status": "covered"}}, "pad": "' + b"a" * (9 << 20) + b'"}',   # > 8 MiB
], ids=["bad-json", "empty", "bad-utf8", "list", "string", "peripherals-list", "deep-nesting", "over-8MiB"])
def test_broken_or_oversized_profiles_give_the_fixed_warning_and_no_failure(hw, monkeypatch, tmp_path, content):
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, content))
    code, out, work = run(hw)
    assert code == ExitCode.OK
    assert hw_lines(out) == ["[hw] profil okunamadı (scratch/%s/hw_profile.json)" % IID]
    assert (work / "result").read_text() == "true\n"


def test_the_warning_contains_nothing_from_the_file(hw, monkeypatch, tmp_path):
    esc = b"\x1b[31mPWNED\x1b[0m"
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, b'{"peripherals": "' + esc + b'", "x": ' + esc))
    _, out, _ = run(hw)
    assert "PWNED" not in out and "\x1b[31m" not in out and len(hw_lines(out)) == 1


def test_a_profile_between_4_and_8_MiB_is_read(hw, monkeypatch, tmp_path):
    head = b'{"peripherals": {"gpio": {"status": "covered"}}, "pad": "'
    tail = b'"}'
    body = head + b"a" * ((7 << 20) - len(head) - len(tail)) + tail
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, body))
    _, out, _ = run(hw)
    assert hw_lines(out) == ["[hw] gpio=covered (scratch/%s/hw_profile.json)" % IID]


def test_a_profile_just_inside_the_size_limit_is_read(hw, monkeypatch, tmp_path):
    head = b'{"peripherals": {"gpio": {"status": "covered"}}, "pad": "'
    tail = b'"}'
    body = head + b"a" * ((8 << 20) - len(head) - len(tail)) + tail
    assert len(body) == 8 << 20
    monkeypatch.setenv("STUB_HW_WRITE", profile_source(tmp_path, body))
    _, out, _ = run(hw)
    assert hw_lines(out) == ["[hw] gpio=covered (scratch/%s/hw_profile.json)" % IID]


def test_a_symlinked_profile_is_not_read(hw, tmp_path):
    secret = tmp_path / "elsewhere.json"
    secret.write_text(json.dumps(GOOD))
    work = hw / "scratch" / IID
    work.mkdir(parents=True)
    os.symlink(secret, work / "hw_profile.json")
    code, out, _ = run(hw)
    assert code == ExitCode.OK and hw_lines(out) == []
    assert "gpio=" not in out


def test_a_fifo_as_profile_does_not_block_the_run(hw):
    work = hw / "scratch" / IID
    work.mkdir(parents=True)
    os.mkfifo(work / "hw_profile.json")
    t0 = time.time()
    code, out, _ = run(hw)
    assert code == ExitCode.OK and hw_lines(out) == [] and time.time() - t0 < 30


def test_a_symlinked_log_is_not_written_through(hw, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    work = hw / "scratch" / IID
    work.mkdir(parents=True)
    os.symlink(victim, work / "hwprofile.log")
    code, out, _ = run(hw)
    assert code == ExitCode.OK and victim.read_text() == "keep"
    assert "hardware profile (hwprofile) not done" in out


# ------------------------------------------------- signals are not swallowed

@pytest.mark.parametrize("make_exc", [KeyboardInterrupt, lambda: SystemExit(143)],
                         ids=["KeyboardInterrupt", "SystemExit-from-SIGTERM"])
def test_interrupt_and_sigterm_exit_are_not_swallowed(hw, monkeypatch, make_exc):
    from firmae import pipeline
    real = pipeline.run_with_timeout

    def spy(argv, timeout, **kw):
        if "firmae.hwprofile" in argv:
            raise make_exc()
        return real(argv, timeout, **kw)
    monkeypatch.setattr(pipeline, "run_with_timeout", spy)
    cfg = config.load(str(hw))
    pipe = Pipeline(cfg, "check", "dlink", Reporter(out=io.StringIO(), color=False))
    with pytest.raises((KeyboardInterrupt, SystemExit)):
        pipe.run_firmware(fw(hw))
    assert pipe._lock_fd is None and pipe._fw_lock_fd is None          # cleanup still ran
    assert not (hw / "image_done").exists()                            # the run did not go on


def test_keyboard_interrupt_during_the_cli_stops_its_process_group(hw, monkeypatch):
    """The real run_with_timeout: an interrupt while the CLI runs kills its group."""
    import subprocess
    (hw / "firmae" / "hwprofile.py").write_text(
        "import os, time\nopen(os.path.join(os.environ['PROJECT'], 'hw_pid'), 'w').write(str(os.getpid()))\n"
        "time.sleep(60)\n")
    real_wait = subprocess.Popen.wait
    state = {"raised": False}

    def wait(self, timeout=None):
        if "firmae.hwprofile" in self.args and not state["raised"]:
            for _ in range(150):                       # until the CLI is really running
                if (hw / "hw_pid").exists():
                    break
                time.sleep(0.1)
            state["raised"] = True
            raise KeyboardInterrupt
        return real_wait(self, timeout)
    monkeypatch.setattr(subprocess.Popen, "wait", wait)
    cfg = config.load(str(hw))
    pipe = Pipeline(cfg, "check", "dlink", Reporter(out=io.StringIO(), color=False))
    with pytest.raises(KeyboardInterrupt):
        pipe.run_firmware(fw(hw))
    pid = int((hw / "hw_pid").read_text())
    for _ in range(50):
        if proc_gone(pid):
            break
        time.sleep(0.1)
    else:
        pytest.fail("the profile CLI survived the interrupt")
