"""analyses/analyses_all.sh + analyses/browser_user.sh (SECURITY.md S11):
FIRMAE_BROWSER_USER runs only the initializer line through setpriv, in a
per-run 0700 directory; unset, the script behaves as before. setpriv, sleep and
the analysis tools are stubs; the "browser user" is the current user."""

import os
import re
import shutil
import stat
import subprocess

import pytest

pytestmark = pytest.mark.linux
pwd = pytest.importorskip("pwd")

ME = pwd.getpwuid(os.getuid())

SETPRIV_STUB = r"""#!/bin/bash
printf '%s\n' "$*" >> "$TESTLOG/setpriv_calls"
while [ "$1" != "--" ]; do shift; done
shift
exec "$@"
"""

# the log path is written into the stub: under FIRMAE_BROWSER_USER it gets a fresh environment
INITIALIZER_STUB = r"""#!/bin/bash
L="%s"
{ echo "args=$*"; echo "uid=$(id -u)"; env | sort; } > "$L/initializer_env" 2>/dev/null || true
{ echo "pid=$$"; echo "sid=$(ps -o sid= -p $$ | tr -d ' ')"; echo "stdin=$(readlink /proc/$$/fd/0)"
  for f in /proc/$$/fd/*; do echo "fd=$(readlink "$f")"; done; } > "$L/initializer_proc" 2>/dev/null || true
echo "initializer ran"
exit "$(cat "$L/initializer_rc" 2>/dev/null || echo 0)"
"""

# pgrep: "processes alive" while $TESTLOG/pgrep_live counts down; pkill: logged
PGREP_STUB = r"""#!/bin/bash
f="%s/pgrep_live"; n=$(cat "$f" 2>/dev/null || echo 0)
if [ "$n" -gt 0 ]; then echo $((n - 1)) > "$f"; exit 0; fi
exit 1
"""
PKILL_STUB = '#!/bin/bash\necho "$*" >> "%s/pkill_calls"\n'


@pytest.fixture
def tree(repo_root, tmp_path):
    proj = tmp_path / "proj"
    ana = proj / "analyses"
    (ana / "fuzzer").mkdir(parents=True)
    for name in ("analyses_all.sh", "browser_user.sh"):
        shutil.copy(repo_root / "analyses" / name, ana / name)
    (proj / "firmae.config").write_text('get_scratch() { echo "%s/scratch/$1"; }\n' % tmp_path)
    stubs = {ana / "initializer.py": INITIALIZER_STUB % (tmp_path / "log"), ana / "nmap.sh": "#!/bin/bash\nexit 0\n",
             ana / "fuzzer" / "fuzzer.py": "#!/bin/bash\nexit 0\n",
             tmp_path / "bin" / "sleep": "#!/bin/bash\nexit 0\n",
             tmp_path / "bin" / "setpriv": SETPRIV_STUB,
             tmp_path / "bin" / "pgrep-stub": PGREP_STUB % (tmp_path / "log"),
             tmp_path / "bin" / "pkill-stub": PKILL_STUB % (tmp_path / "log")}
    for p, body in stubs.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        p.chmod(0o755)
    log = tmp_path / "log"
    log.mkdir()
    return tmp_path


def run_all(tree, **env):
    e = {"PATH": "%s:%s" % (tree / "bin", os.environ["PATH"]), "TESTLOG": str(tree / "log"),
         "BROWSER_SETPRIV": str(tree / "bin" / "setpriv"), "FIRMAE_BROWSER_TMP": str(tree / "bbase"),
         "BROWSER_PGREP": str(tree / "bin" / "pgrep-stub"), "BROWSER_PKILL": str(tree / "bin" / "pkill-stub"),
         "SECRET_OF_ROOT": "x", "LANG": "C.UTF-8"}
    e.update(env)
    # stdin is a pipe (as root's terminal would be something other than /dev/null)
    res = subprocess.run(["bash", "./analyses_all.sh", "77", "dlink", "192.168.0.1", "127.0.0.1"],
                         cwd=str(tree / "proj" / "analyses"), env=e, capture_output=True, text=True,
                         input="", timeout=120)
    logdir = tree / "scratch" / "77" / "analysis_log"
    steps = dict(l.split() for l in (logdir / "steps").read_text().splitlines())
    return res, steps, logdir


def setpriv_calls(tree):
    p = tree / "log" / "setpriv_calls"
    return p.read_text().splitlines() if p.exists() else []


def test_unset_runs_the_initializer_directly(tree):
    res, steps, logdir = run_all(tree)
    assert res.returncode == 0, res.stderr
    assert steps["initializer"] == "0" and steps["nmap"] == "0"
    assert setpriv_calls(tree) == []
    env = (tree / "log" / "initializer_env").read_text()
    assert "SECRET_OF_ROOT=x" in env                 # full environment, as before
    assert (logdir / "initializer_log").read_text() == "initializer ran\n"
    assert not (tree / "bbase").exists()


def test_unset_path_is_the_original_line(repo_root):
    text = (repo_root / "analyses" / "analyses_all.sh").read_text()
    line = ('    { time ./initializer.py "$BRAND" "$TARGET" > "$LOG_DIR/initializer_log" 2>&1 ; } '
            '2> "$LOG_DIR/initializer_time" || rc=$?')
    assert line in text.splitlines()
    assert text.count("./initializer.py") == 2      # the original line + the setpriv one


def test_set_runs_only_the_initializer_through_setpriv(tree):
    res, steps, logdir = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name)
    assert res.returncode == 0, res.stderr
    assert steps["initializer"] == "0" and steps["nmap"] == "0" and steps["fuzzer_ci"] == "0"
    calls = setpriv_calls(tree)
    prefix = "--reuid=%d --regid=%d --init-groups --no-new-privs -- env -i " % (ME.pw_uid, ME.pw_gid)
    assert len(calls) == 2 and all(c.startswith(prefix) for c in calls)
    assert calls[0].endswith("test -r ./initializer.py -a -x ./initializer.py")
    assert calls[1].endswith("./initializer.py dlink 192.168.0.1")
    env = dict(l.split("=", 1) for l in (tree / "log" / "initializer_env").read_text().splitlines()
               if "=" in l and not l.startswith("args="))
    run_dir = env["HOME"]
    assert os.path.dirname(run_dir) == str(tree / "bbase")
    assert env["FIRMAE_BROWSER_PROFILE_DIR"] == run_dir + "/profile"
    assert env["SE_CACHE_PATH"] == run_dir + "/cache" and env["TMPDIR"] == run_dir + "/tmp"
    assert env["USER"] == ME.pw_name and "SECRET_OF_ROOT" not in env
    assert "FIRMAE_CHROME_NO_SANDBOX" not in env
    # the redirect stays on the caller's side; the run directory is gone afterwards
    assert (logdir / "initializer_log").read_text() == "initializer ran\n"
    assert os.listdir(str(tree / "bbase")) == []
    assert stat.S_IMODE(os.stat(str(tree / "bbase")).st_mode) == 0o711


def test_no_sandbox_override_is_passed_through(tree):
    run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name, FIRMAE_CHROME_NO_SANDBOX="1")
    assert "FIRMAE_CHROME_NO_SANDBOX=1" in (tree / "log" / "initializer_env").read_text()


@pytest.mark.parametrize("user, text", [("no-such-user-firmae-xyz", "no such user"),
                                        ("root", "uid 0")])
def test_bad_user_never_runs_the_initializer(tree, user, text):
    res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=user)
    assert res.returncode == 0
    assert steps["initializer"] == "2" and steps["nmap"] == "0"     # the other steps still run
    assert text in res.stdout and "never as root" in res.stdout
    assert not (tree / "log" / "initializer_env").exists()


def test_unsafe_base_is_refused(tree):
    (tree / "elsewhere").mkdir()
    os.symlink(str(tree / "elsewhere"), str(tree / "bbase"))
    res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name)
    # refused by the symlink check itself (the mode check, which sees the
    # symlink's own 0777, would refuse it too)
    assert steps["initializer"] == "2" and "(symlink?); refusing" in res.stdout
    assert os.listdir(str(tree / "elsewhere")) == []
    assert not (tree / "log" / "initializer_env").exists()


def test_writable_base_is_refused(tree):
    (tree / "bbase").mkdir()
    os.chmod(str(tree / "bbase"), 0o777)
    res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name)
    assert steps["initializer"] == "2" and "writable" in res.stdout


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
def test_inaccessible_initializer_is_reported(tree):
    os.chmod(str(tree / "proj" / "analyses" / "initializer.py"), 0)
    res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name)
    assert steps["initializer"] == "126" and "must be accessible" in res.stdout
    assert os.listdir(str(tree / "bbase")) == []


def proc_info(tree):
    lines = (tree / "log" / "initializer_proc").read_text().splitlines()
    info = {}
    for l in lines:
        k, v = l.split("=", 1)
        info.setdefault(k, []).append(v)
    return info


def test_initializer_runs_in_its_own_session_with_stdin_from_dev_null(tree):
    res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name)
    assert steps["initializer"] == "0", res.stdout
    info = proc_info(tree)
    assert info["sid"] == info["pid"]                     # session leader: no controlling tty of root
    assert info["stdin"] == ["/dev/null"]
    assert not [f for f in info["fd"] if f == str(tree / "bbase")]      # the lock fd is not inherited


def test_initializer_exit_status_is_passed_through(tree):
    (tree / "log" / "initializer_rc").write_text("7")
    res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name)
    assert steps["initializer"] == "7" and steps["nmap"] == "0"


def test_leftover_processes_of_the_user_are_killed(tree):
    (tree / "log" / "pgrep_live").write_text("2")
    res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name)
    assert steps["initializer"] == "0", res.stdout
    assert (tree / "log" / "pkill_calls").read_text().splitlines()[0] == "-KILL -U %d" % ME.pw_uid


def test_survivors_stop_the_initializer(tree):
    (tree / "log" / "pgrep_live").write_text("100000")
    res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name)
    assert steps["initializer"] == "2" and "survive SIGKILL" in res.stdout
    assert not (tree / "log" / "initializer_env").exists()


def test_own_uid_is_never_killed_without_the_test_hook(repo_root, tmp_path):
    # pkill/pgrep on PATH are stubs: even with the guard broken (mutation
    # checks), the real pkill must never kill the test user's processes
    b = tmp_path / "safebin"
    b.mkdir()
    (b / "pkill").write_text('#!/bin/bash\necho "$*" >> "%s/pkill_calls"\n' % tmp_path)
    (b / "pgrep").write_text("#!/bin/bash\nexit 0\n")
    (b / "sleep").write_text("#!/bin/bash\nexit 0\n")
    for p in b.iterdir():
        p.chmod(0o755)
    script = 'source "$1"; BROWSER_UID=$(id -u); browser_kill_user; echo "rc=$?"'
    e = {"PATH": "%s:%s" % (b, os.environ["PATH"])}
    res = subprocess.run(["bash", "-c", script, "_", str(repo_root / "analyses" / "browser_user.sh")],
                         env=e, capture_output=True, text=True, timeout=60)
    assert res.stdout.strip() == "rc=1"
    assert not (tmp_path / "pkill_calls").exists()


def test_a_second_initializer_waits_for_the_lock(tree):
    import fcntl
    base = tree / "bbase"
    base.mkdir(mode=0o711)
    os.chmod(str(base), 0o711)
    fd = os.open(str(base), os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name, FIRMAE_BROWSER_LOCK_WAIT="0")
    finally:
        os.close(fd)
    assert steps["initializer"] == "2" and "holds" in res.stdout
    assert not (tree / "log" / "initializer_env").exists()


def test_setsid_without_wait_is_refused(tree):
    old = tree / "bin" / "old-setsid"
    old.write_text("#!/bin/bash\necho 'usage: setsid [options] <program>'\n")
    old.chmod(0o755)
    res, steps, _ = run_all(tree, FIRMAE_BROWSER_USER=ME.pw_name, BROWSER_SETSID=str(old))
    assert steps["initializer"] == "2" and "--wait" in res.stdout


def userns(repo_root, tmp_path, restrict=None, clone=None, **env):
    files = []
    for name, value in (("restrict", restrict), ("clone", clone)):
        p = tmp_path / name
        if value is not None:
            p.write_text(value + "\n")
        files.append(str(p))
    script = 'source "$1"; browser_userns_warning "$2" "$3"'
    e = {"PATH": os.environ["PATH"], "FIRMAE_BROWSER_USER": "firmae-browser"}
    e.update(env)
    res = subprocess.run(["bash", "-c", script, "_", str(repo_root / "analyses" / "browser_user.sh")] + files,
                         env=e, capture_output=True, text=True, timeout=30)
    assert res.returncode == 0
    return res.stdout


def test_userns_warning(repo_root, tmp_path):
    out = userns(repo_root, tmp_path, restrict="1")
    assert "kernel.apparmor_restrict_unprivileged_userns=1" in out
    assert "AppArmor profile" in out and "FIRMAE_CHROME_NO_SANDBOX=1" in out
    assert "does not change system settings" in out
    assert "unprivileged_userns_clone=0" in userns(repo_root, tmp_path, restrict="0", clone="0")
    assert userns(repo_root, tmp_path, restrict="0", clone="1") == ""
    assert userns(repo_root, tmp_path) == ""                          # no such sysctl (WSL, older kernels)
    assert userns(repo_root, tmp_path, restrict="1", FIRMAE_CHROME_NO_SANDBOX="1") == ""


def test_userns_warning_is_printed_by_analyses_all(tree, monkeypatch):
    # the real sysctl path is used there; only check the call is wired in
    text = (tree / "proj" / "analyses" / "analyses_all.sh").read_text()
    assert re.search(r"browser_prepare .*\n\s+browser_userns_warning\n", text)


# ------------------------------------------------------- install.sh block

def install_block(repo_root):
    text = (repo_root / "install.sh").read_text()
    m = re.search(r"^# BEGIN unprivileged-users$.*?^# END unprivileged-users$", text, re.M | re.S)
    assert m
    return m.group(0)


def run_block(repo_root, tmp_path, existing="", **env):
    b = tmp_path / "ibin"
    b.mkdir(exist_ok=True)
    (b / "sudo").write_text('#!/bin/bash\necho "sudo $*" >> "%s/calls"\n' % tmp_path)
    (b / "getent").write_text('#!/bin/bash\n[[ " %s " == *" $2 "* ]]\n' % existing)
    for p in b.iterdir():
        p.chmod(0o755)
    e = {"PATH": "%s:%s" % (b, os.environ["PATH"])}
    e.update(env)
    res = subprocess.run(["bash", "-c", install_block(repo_root)], env=e, capture_output=True, text=True,
                         timeout=30)
    assert res.returncode == 0, res.stderr
    calls = tmp_path / "calls"
    return calls.read_text().splitlines() if calls.exists() else []


def test_install_creates_no_users_by_default(repo_root, tmp_path):
    assert run_block(repo_root, tmp_path) == []
    assert run_block(repo_root, tmp_path, FIRMAE_CREATE_USERS="0") == []


def test_install_creates_the_two_system_users_on_request(repo_root, tmp_path):
    calls = run_block(repo_root, tmp_path, FIRMAE_CREATE_USERS="1")
    opts = "--system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin"
    assert calls == ["sudo useradd %s firmae-extract" % opts, "sudo useradd %s firmae-browser" % opts]


def test_install_skips_existing_users(repo_root, tmp_path):
    calls = run_block(repo_root, tmp_path, existing="firmae-extract", FIRMAE_CREATE_USERS="1")
    assert len(calls) == 1 and calls[0].endswith(" firmae-browser")
