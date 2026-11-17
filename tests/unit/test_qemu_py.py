"""firmae/qemu.py (REFACTORING_PLAN 4.2): the initial emulation that
scripts/run.<arch>.sh used to start.

golden_qemu_initial.json holds the argv of the ORIGINAL Bash scripts, captured
with a fake qemu-system-* before they were replaced (54 cases: 3 architectures x
FIRMAE_NET x FIRMAE_KERNEL x image IDs, plus empty / spaced QEMU_INIT and the
other FIRMAE_* switches off). Real QEMU is never started.
"""

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from firmae import qemu
from scripts.procgroup import stop_group

HERE = Path(__file__).resolve().parent
GOLDEN = json.loads((HERE / "golden_qemu_initial.json").read_text())
ARCHS = ("armel", "mipseb", "mipsel")
ROOT = "/R"
INIT = "rdinit=/firmadyne/preInit.sh"


def _build(c, root=ROOT):
    return qemu.build_initial_argv(
        c["arch"], c["iid"], c["init"], firmae_net=c["net"], firmae_nvram=c["nvram"],
        firmae_kernel=c["kernel"], firmae_etc=c["etc"],
        binary_dir=root + "/binaries/", scratch_dir=root + "/scratch")


def _id(g):
    c = g["case"]
    return "%s-net%s-k%s-%s-%s" % (c["arch"], c["net"], c["kernel"], c["iid"], "i%d" % len(c["init"]))


# --------------------------------------------------------------- pure, any platform

@pytest.mark.parametrize("g", GOLDEN, ids=_id)
def test_argv_matches_what_the_bash_scripts_ran(g):
    assert _build(g["case"]) == [a.replace("@ROOT@", ROOT) for a in g["argv"]]


def test_golden_set_covers_every_branch():
    cases = [g["case"] for g in GOLDEN]
    for arch in ARCHS:
        sub = [c for c in cases if c["arch"] == arch]
        assert {c["net"] for c in sub} == {"true", "false"}
        assert {c["kernel"] for c in sub} == {"true", "false"}
        assert {c["nvram"] for c in sub} == {"true", "false"}
        assert "" in {c["init"] for c in sub} and any(" " in c["init"] for c in sub)
    assert {g["audio"] for g in GOLDEN if g["case"]["arch"] == "armel"} == {"AUDIO=none"}
    assert {g["audio"] for g in GOLDEN if g["case"]["arch"] != "armel"} == {"AUDIO=unset"}


def test_audio_driver_is_set_for_arm_only_and_input_env_is_not_modified():
    environ = {"PATH": "/x"}
    assert qemu.initial_env("armel", environ) == {"PATH": "/x", "QEMU_AUDIO_DRV": "none"}
    assert qemu.initial_env("mipsel", environ) == {"PATH": "/x"}
    assert environ == {"PATH": "/x"}


def test_build_is_pure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = sorted(os.listdir(tmp_path))
    _build(GOLDEN[0]["case"], root=str(tmp_path / "does-not-exist"))
    assert sorted(os.listdir(tmp_path)) == before


def test_network_isolation_options_are_kept():
    for g in GOLDEN:
        argv = _build(g["case"])
        users = [a for a in argv if a.startswith("user,id=")]
        socks = [a for a in argv if a.startswith("socket,id=")]
        assert all(a.endswith(",restrict=on") for a in users)
        assert all("listen=127.0.0.1:" in a for a in socks)
        assert bool(users) == (g["case"]["net"] == "true") and bool(socks) != bool(users)
        assert not any("hostfwd" in a or "/tmp/qemu" in a for a in argv)


@pytest.mark.parametrize("arch", ["x86", "armeb", "", "ARMEL", "armel ", "../armel"])
def test_invalid_arch_is_rejected(arch):
    with pytest.raises(qemu.QemuError, match="Invalid architecture") as e:
        _build(dict(arch=arch, iid="1", init=INIT, net="true", nvram="true", kernel="true", etc="true"))
    assert e.value.code == 1
    for fn in (qemu.qemu_binary, qemu.qemu_machine, qemu.qemu_disk):
        with pytest.raises(qemu.QemuError):
            fn(arch)


@pytest.mark.parametrize("iid", ["", "abc", "-1", "1;rm -rf /", "1 2", "$(id)", "1\n", "١٢", "../1", "1.5"])
def test_invalid_image_id_is_rejected(iid):
    with pytest.raises(qemu.QemuError, match="Invalid image number") as e:
        _build(dict(arch="armel", iid=iid, init=INIT, net="true", nvram="true", kernel="true", etc="true"))
    assert e.value.code == 1


@pytest.mark.parametrize("field", ["net", "kernel"])
def test_switches_must_be_true_or_false(field):
    c = dict(GOLDEN[0]["case"], arch="mipsel", **{field: "yes"})
    with pytest.raises(qemu.QemuError):
        _build(c)


def test_sock_base_follows_bash_arithmetic():
    assert qemu.sock_base("7") == 20028
    assert qemu.sock_base("10001") == 20004
    assert qemu.sock_base("007") == 20028          # octal, like $((007))
    assert qemu.sock_base("010") == 20000 + 8 * 4
    assert qemu.sock_base("0") == 20000
    # "08"/"09": see test_intentional_differences_from_the_old_scripts


def test_main_usage_errors(capsys):
    assert qemu.main(["initial", "armel", "abc", INIT]) == 1
    assert capsys.readouterr().out == "Usage: run.armel.sh <image ID>\n"
    assert qemu.main(["initial", "armel", "1"]) == 1          # set -u: QEMU_INIT missing
    assert "unbound variable" in capsys.readouterr().err
    assert qemu.main(["initial", "x86", "1", INIT]) == 1
    assert "Invalid architecture" in capsys.readouterr().err
    assert qemu.main([]) == 1 and qemu.main(["final", "armel", "1", INIT]) == 1


def test_prepare_workdir(tmp_path):
    work = tmp_path / "scratch" / "5"                 # does not exist yet: mkdir -p
    qemu.prepare_workdir(str(work))
    run = work / "run"
    assert stat.S_IMODE(run.stat().st_mode) == 0o700
    (run / "a.sock").write_text("")
    (run / "keep.txt").write_text("")
    (run / ".hidden.sock").write_text("")
    qemu.prepare_workdir(str(work))
    assert sorted(p.name for p in run.iterdir()) == [".hidden.sock", "keep.txt"]   # glob rules of `rm -f run/*.sock`


# --------------------------------------------------------------- Bash <-> Python


@pytest.mark.linux
@pytest.mark.parametrize("kernel", ["true", "false"])
@pytest.mark.parametrize("arch", ARCHS)
def test_helpers_equal_the_bash_functions(repo_root, arch, kernel):
    script = ('FIRMAE_KERNEL=%s; get_qemu %s; get_qemu_machine %s; get_qemu_disk %s; '
              'get_kernel %s; echo "$BINARY_DIR"' % ((kernel,) + (arch,) * 4))
    env = dict(os.environ)
    env.pop("FIRMAE_DOCKER", None)
    res = subprocess.run(["bash", "-c", "source ./firmae.config && " + script], cwd=str(repo_root),
                         env=env, capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    b_qemu, b_machine, b_disk, b_kernel, binary_dir = res.stdout.splitlines()
    assert qemu.qemu_binary(arch) == b_qemu
    assert qemu.qemu_machine(arch) == b_machine
    assert qemu.qemu_disk(arch) == b_disk
    assert qemu.kernel_path(arch, kernel, binary_dir) == b_kernel
    assert qemu.binary_dir_of(str(repo_root)) == binary_dir


@pytest.mark.linux
def test_arch_list_equals_check_arch(repo_root):
    res = subprocess.run(["bash", "-c", 'source ./firmae.config; for a in armel mipseb mipsel armeb x86 "";'
                          ' do check_arch "$a"; echo "$a:$?"; done'], cwd=str(repo_root),
                         capture_output=True, text=True, timeout=30)
    valid = {l.split(":")[0] for l in res.stdout.splitlines() if l.endswith(":1")}
    assert valid == set(qemu.ARCHS) == set(ARCHS)


# --------------------------------------------------------------- wrapper end to end

STUB = r'''#!/bin/sh
out="$STUB_OUT"
{
  echo "pid=$$"; echo "ppid=$PPID"; env | grep -E "^(PYTHON|MY_)" | sort > "$out.env"
  echo "pgid=$(ps -o pgid= -p $$ | tr -d ' ')"
  echo "cwd=$(pwd)"
  echo "audio=${QEMU_AUDIO_DRV-unset}"
  echo "sigign=$(grep SigIgn /proc/self/status | cut -f2)"
  echo "argv0=$0"
  for a in "$@"; do echo "arg=$a"; done
} > "$out.tmp"
mv "$out.tmp" "$out"
case "$STUB_MODE" in
  exit) exit "${STUB_RC:-0}" ;;
  wait)
    trap 'echo got-int > "$out.sig"; exit 42' INT
    : > "$out.ready"
    while :; do sleep 0.05; done ;;
esac
'''


@pytest.fixture
def tree(repo_root, tmp_path):
    """A copy of the project (wrappers + package + config) and fake QEMUs."""
    root = tmp_path / "FirmAE"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(repo_root / "firmae.config", root)
    shutil.copytree(repo_root / "firmae", root / "firmae", ignore=shutil.ignore_patterns("__pycache__"))
    for arch in ARCHS:
        shutil.copy(repo_root / "scripts" / ("run.%s.sh" % arch), root / "scripts")
        (root / "scripts" / ("run.%s.sh" % arch)).chmod(0o755)
    (root / "scratch" / "1").mkdir(parents=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for n in ("qemu-system-arm", "qemu-system-mips", "qemu-system-mipsel"):
        (bindir / n).write_text(STUB)
        (bindir / n).chmod(0o755)
    out = tmp_path / "stub.txt"
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]), STUB_OUT=str(out), STUB_MODE="exit")
    for v in ("FIRMAE_DOCKER", "PYTHONPATH"):
        env.pop(v, None)
    return root, env, out


def _read(out):
    d = {"arg": []}
    for line in out.read_text().splitlines():
        k, _, v = line.partition("=")
        if k == "arg":
            d["arg"].append(v)
        else:
            d[k] = v
    return d


def _set_cfg(root, **kv):
    cfg = root / "firmae.config"
    text = cfg.read_text()
    for k, v in kv.items():
        text = text.replace("%s=true" % k, "%s=%s" % (k, v), 1)
    cfg.write_text(text)


@pytest.mark.linux
@pytest.mark.parametrize("g", GOLDEN, ids=_id)
def test_wrapper_runs_the_golden_argv(tree, g):
    root, env, out = tree
    c = g["case"]
    (root / "scratch" / c["iid"]).mkdir(exist_ok=True)
    _set_cfg(root, FIRMAE_NET=c["net"], FIRMAE_NVRAM=c["nvram"], FIRMAE_KERNEL=c["kernel"], FIRMAE_ETC=c["etc"])
    res = subprocess.run([str(root / "scripts" / ("run.%s.sh" % c["arch"])), c["iid"], c["init"]],
                         cwd=str(root), env=env, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    d = _read(out)
    want = [a.replace("@ROOT@", str(root)) for a in g["argv"]]
    assert os.path.basename(d["argv0"]) == want[0]
    assert d["arg"] == want[1:]
    assert d["audio"] == g["audio"].split("=", 1)[1]
    assert (root / "scratch" / c["iid"] / "run").is_dir()


@pytest.mark.linux
@pytest.mark.parametrize("arch", ARCHS)
def test_wrapper_does_not_depend_on_the_working_directory(tree, tmp_path, arch):
    root, env, out = tree
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    # cwd is neither the project nor its parent (the old scripts needed ./firmae.config there)
    # and the QEMU stub must see the cwd unchanged
    res = subprocess.run([str(root / "scripts" / ("run.%s.sh" % arch)), "1", INIT],
                         cwd=str(elsewhere), env=env, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    d = _read(out)
    assert d["cwd"] == str(elsewhere)
    assert any(a.startswith("file:%s/scratch/1/" % root) for a in d["arg"])
    # a relative path to the wrapper works too
    res = subprocess.run(["bash", os.path.relpath(str(root / "scripts" / ("run.%s.sh" % arch)), str(elsewhere)),
                          "1", INIT], cwd=str(elsewhere), env=env, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr


@pytest.mark.linux
def test_exit_status_of_qemu_is_the_exit_status_of_the_script(tree):
    root, env, out = tree
    env.update(STUB_RC="17")
    res = subprocess.run([str(root / "scripts/run.mipsel.sh"), "1", INIT], cwd=str(root), env=env,
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 17


@pytest.mark.linux
@pytest.mark.parametrize("arch", ARCHS)
def test_qemu_replaces_the_script_no_process_in_between(tree, arch):
    """The fake QEMU has the PID of the process the caller started (bash -> python3
    -> qemu by exec), so its parent is the caller and its process group is the
    one run_with_timeout() created -- SIGINT/SIGKILL of the group reach it directly."""
    root, env, out = tree
    proc = subprocess.Popen([str(root / "scripts" / ("run.%s.sh" % arch)), "1", INIT], cwd=str(root), env=env,
                            start_new_session=True)
    assert proc.wait(timeout=60) == 0
    d = _read(out)
    assert int(d["pid"]) == proc.pid
    assert int(d["ppid"]) == os.getpid()
    assert int(d["pgid"]) == proc.pid


@pytest.mark.linux
def test_qemu_does_not_inherit_python_signal_dispositions(tree):
    root, env, out = tree
    assert subprocess.run([str(root / "scripts/run.armel.sh"), "1", INIT], cwd=str(root), env=env, timeout=60).returncode == 0
    ignored = int(_read(out)["sigign"], 16)
    assert not ignored & (1 << (signal.SIGPIPE - 1))
    assert not ignored & (1 << (signal.SIGXFSZ - 1))


@pytest.mark.linux
@pytest.mark.parametrize("arch", ARCHS)
def test_sigint_reaches_qemu(tree, arch):
    root, env, out = tree
    env.update(STUB_MODE="wait")
    proc = subprocess.Popen([str(root / "scripts" / ("run.%s.sh" % arch)), "1", INIT], cwd=str(root), env=env,
                            start_new_session=True)
    ready = Path(str(out) + ".ready")
    deadline = time.time() + 30
    while not ready.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert ready.exists()
    stop_group(proc, signal.SIGINT, grace=10)         # what run_with_timeout does
    assert proc.returncode == 42                      # the stub's INT trap ran in the QEMU process itself
    assert Path(str(out) + ".sig").read_text().strip() == "got-int"


@pytest.mark.linux
def test_sigint_kill_fallback_kills_qemu_that_ignores_sigint(tree):
    root, env, out = tree
    (Path(str(out)).parent / "bin" / "qemu-system-mipsel").write_text(
        '#!/bin/sh\ntrap "" INT\n: > "$STUB_OUT.ready"\nwhile :; do sleep 0.05; done\n')
    proc = subprocess.Popen([str(root / "scripts/run.mipsel.sh"), "1", INIT], cwd=str(root), env=env,
                            start_new_session=True)
    ready = Path(str(out) + ".ready")
    deadline = time.time() + 30
    while not ready.exists() and time.time() < deadline:
        time.sleep(0.05)
    stop_group(proc, signal.SIGINT, grace=1)
    assert proc.returncode == -signal.SIGKILL


@pytest.mark.linux
@pytest.mark.parametrize("args,stdout_has", [
    (["abc", INIT], "Usage: run.armel.sh <image ID>"),
    (["-1", INIT], "Usage: run.armel.sh <image ID>"),
    (["1;id", INIT], "Usage: run.armel.sh <image ID>"),
    ([], "Usage: run.armel.sh <image ID>"),
])
def test_wrapper_usage_errors_exit_1_without_starting_qemu(tree, args, stdout_has):
    root, env, out = tree
    res = subprocess.run([str(root / "scripts/run.armel.sh")] + args, cwd=str(root), env=env,
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 1 and stdout_has in res.stdout
    assert not out.exists()


@pytest.mark.linux
def test_missing_qemu_exits_127_and_missing_init_exits_1(tree, tmp_path):
    root, env, out = tree
    bare = tmp_path / "bare"          # python3, bash and dirname, but no QEMU
    bare.mkdir()
    for tool in ("python3", "dirname", "bash"):
        (bare / tool).symlink_to(shutil.which(tool))
    env = dict(env, PATH=str(bare))
    res = subprocess.run([str(root / "scripts/run.mipsel.sh"), "1", INIT], cwd=str(root), env=env,
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 127 and "command not found" in res.stderr
    res = subprocess.run([str(root / "scripts/run.mipsel.sh"), "1"], cwd=str(root), env=env,
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 1


@pytest.mark.linux
def test_invalid_arch_and_iid_through_python_exit_1(tree):
    root, env, out = tree
    env = dict(env, PYTHONPATH=str(root))
    for args in (["initial", "x86", "1", INIT], ["initial", "armel", "x", INIT], ["bogus"], []):
        res = subprocess.run([sys.executable, "-m", "firmae.qemu"] + args, cwd=str(root), env=env,
                             capture_output=True, text=True, timeout=60)
        assert res.returncode == 1, args
    assert not out.exists()


@pytest.mark.linux
def test_wrappers_are_thin_executable_and_lf(repo_root):
    for arch in ARCHS:
        p = repo_root / "scripts" / ("run.%s.sh" % arch)
        data = p.read_bytes()
        assert b"\r" not in data
        assert data.splitlines()[0] == b"#!/bin/bash"
        assert ("exec python3 -I \"${FIRMAE_HOME}/firmae/qemu.py\" initial %s \"$@\"" % arch).encode() in data
        assert b"-m firmae" not in data and b"PYTHONPATH=" not in data
        assert len(data.splitlines()) < 20
        assert b"qemu-system" not in data.replace(b"firmae/qemu.py", b"")
    assert os.access(str(repo_root / "scripts/run.armel.sh"), os.X_OK)


# --------------------------------------------------------------- hostile working directory / PYTHONPATH

def _evil_tree(base, marker, name="evil"):
    """A directory full of look-alikes. Anything that imports one of them writes `marker`."""
    d = base / name
    (d / "firmae").mkdir(parents=True)
    body = 'open(%r, "a").write("SHADOWED %%s\n" %% __name__)\n' % str(marker)
    (d / "firmae" / "__init__.py").write_text(body)
    for mod in ("qemu", "config", "errors", "log", "state"):
        (d / "firmae" / (mod + ".py")).write_text(body + "raise SystemExit(0)\n")
    # stdlib look-alikes: they only matter if the directory is on sys.path
    for mod in ("subprocess", "os", "glob", "re", "signal", "sys", "errno", "json", "sitecustomize", "usercustomize"):
        (d / (mod + ".py")).write_text(body + "raise SystemExit(0)\n")
    return d


@pytest.mark.linux
@pytest.mark.parametrize("arch", ARCHS)
def test_hostile_cwd_and_pythonpath_cannot_replace_the_code(tree, tmp_path, arch):
    root, env, out = tree
    marker = tmp_path / "marker"
    evil = _evil_tree(tmp_path, marker)
    evil2 = _evil_tree(tmp_path, marker, "evil-pythonpath")
    env = dict(env, PYTHONPATH=str(evil2), PYTHONSTARTUP=str(evil / "os.py"))
    res = subprocess.run([str(root / "scripts" / ("run.%s.sh" % arch)), "1", INIT], cwd=str(evil), env=env,
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    assert not marker.exists(), marker.read_text() if marker.exists() else ""
    assert out.exists()                              # the real code ran and started the (fake) QEMU
    assert _read(out)["cwd"] == str(evil)            # ... still in the caller's directory


@pytest.mark.linux
def test_python_variables_reach_qemu_unchanged(tree):
    """-I ignores PYTHON* for the interpreter only; QEMU's environment is the caller's."""
    root, env, out = tree
    env = dict(env, PYTHONPATH="/nonexistent", PYTHONFOO="bar", PYTHONHASHSEED="3", MY_VAR="x y")
    assert subprocess.run([str(root / "scripts/run.mipseb.sh"), "1", INIT], cwd=str(root), env=env, timeout=60).returncode == 0
    seen = Path(str(out) + ".env").read_text().splitlines()
    assert seen == ["MY_VAR=x y", "PYTHONFOO=bar", "PYTHONHASHSEED=3", "PYTHONPATH=/nonexistent"]


@pytest.mark.linux
def test_script_directory_and_cwd_are_not_on_sys_path(tree, tmp_path):
    root, env, out = tree
    qpy = str(root / "firmae" / "qemu.py")
    probe = tmp_path / "probe.py"
    probe.write_text("import json, runpy, sys\n"
                     "sys.argv = [%r, 'bogus']\n"
                     "sys.path.insert(0, '')\n"
                     "sys.path.insert(0, %r)\n"
                     "try:\n    runpy.run_path(%r, run_name='__main__')\nexcept SystemExit:\n    pass\n"
                     "print(json.dumps(sys.path))\n" % (qpy, str(root / "firmae"), qpy))
    res = subprocess.run([sys.executable, "-I", str(probe)], cwd=str(root / "firmae"), capture_output=True, text=True, timeout=60)
    paths = json.loads(res.stdout.splitlines()[-1])
    assert "" not in paths and str(root / "firmae") not in paths
    assert paths[-1] == str(root)                    # the installation directory comes last


# --------------------------------------------------------------- intentional differences

QUIRKS = json.loads((HERE / "golden_old_quirks.json").read_text())
INTENTIONAL = [q for q in QUIRKS if q["qemu_started"]
               and (q["case"]["iid"] in ("08", "09") or q["case"]["net"] not in ("true", "false"))]
ALREADY_REJECTED = [q for q in QUIRKS if not q["qemu_started"]]


def _qid(q):
    return "%(arch)s-iid%(iid)s-net%(net)s" % q["case"]


def test_the_old_scripts_really_accepted_these_inputs():
    """Recorded from the HEAD scripts (golden_old_quirks.json, fake QEMU):
    - IID 08/09 with FIRMAE_NET=true: "value too great for base" was printed, rc stayed 0
      and QEMU was STARTED (SOCK_BASE is only used by the socket NICs);
    - FIRMAE_NET=1 / 0 (anything but true/false): run as a command ("1: command not
      found" = false) and QEMU started with the socket NICs. (FIRMAE_NET=yes ran
      /usr/bin/yes and hung forever; not recorded.)"""
    assert INTENTIONAL
    assert any("too great for base" in q["stderr"] for q in INTENTIONAL)
    assert any("command not found" in q["stderr"] for q in INTENTIONAL)
    assert {q["case"]["net"] for q in INTENTIONAL} >= {"true", "1", "0"}


@pytest.mark.linux
@pytest.mark.parametrize("q", ALREADY_REJECTED, ids=_qid)
def test_what_the_old_scripts_already_rejected_is_still_rejected(tree, q):
    """IID 08/09 with FIRMAE_NET=false: SOCK_BASE stayed unset, `set -u` aborted (rc 1)."""
    root, env, out = tree
    c = q["case"]
    (root / "scratch" / c["iid"]).mkdir(exist_ok=True)
    _set_cfg(root, FIRMAE_NET=c["net"])
    res = subprocess.run([str(root / "scripts" / ("run.%s.sh" % c["arch"])), c["iid"], "rdinit=/x"],
                         cwd=str(root), env=env, capture_output=True, text=True, timeout=60)
    assert q["rc"] == res.returncode == 1 and not out.exists()


@pytest.mark.linux
@pytest.mark.parametrize("q", INTENTIONAL, ids=_qid)
def test_intentional_differences_from_the_old_scripts(tree, q):
    """DELIBERATE behaviour change (not equivalence): the new code refuses a
    non-canonical IID and a FIRMAE_NET that is not exactly true/false (exit 1,
    QEMU not started). IDs come from the database as integers, and the shipped
    firmae.config sets FIRMAE_NET/NVRAM/KERNEL/ETC to true."""
    root, env, out = tree
    c = q["case"]
    (root / "scratch" / c["iid"]).mkdir(exist_ok=True)
    _set_cfg(root, FIRMAE_NET=c["net"])
    res = subprocess.run([str(root / "scripts" / ("run.%s.sh" % c["arch"])), c["iid"], "rdinit=/x"],
                         cwd=str(root), env=env, capture_output=True, text=True, timeout=60)
    assert res.returncode == 1 and not out.exists()


@pytest.mark.linux
@pytest.mark.parametrize("q", [q for q in QUIRKS if q["case"]["iid"] == "007"], ids=_qid)
def test_leading_zero_iid_that_bash_reads_as_octal_stays_equivalent(q):
    c = q["case"]
    argv = qemu.build_initial_argv(c["arch"], c["iid"], "rdinit=/x", firmae_net=c["net"], firmae_nvram="true",
                                   firmae_kernel="true", firmae_etc="true",
                                   binary_dir="@ROOT@/binaries/", scratch_dir="@ROOT@/scratch")
    assert q["qemu_started"] and argv[1:] == q["argv"]


def test_shipped_config_defaults_are_exactly_true(repo_root):
    text = (repo_root / "firmae.config").read_text().splitlines()
    for var in ("FIRMAE_NET", "FIRMAE_NVRAM", "FIRMAE_KERNEL", "FIRMAE_ETC"):
        assert "%s=true" % var in text
