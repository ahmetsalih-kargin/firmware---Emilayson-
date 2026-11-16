"""firmae/ pipeline (REFACTORING_PLAN Phase 4): exit codes, stage names, results
and per-firmware independence. The real firmae.config is used; the stage
scripts are stubs whose behaviour is chosen with STUB_* environment variables,
in a temporary project tree (IID 987654, so nothing real can be touched).
"""

import io
import os
import shutil
import stat
import time

import pytest

from firmae import config, __main__ as cli
from firmae.errors import ExitCode
from firmae.log import Reporter
from firmae.pipeline import Pipeline

pytestmark = pytest.mark.linux

IID = "987654"

STUBS = {
    "sources/extractor/extractor.py": """#!/bin/bash
echo "$@" >> "$PROJECT/extractor_calls"
mkdir -p images
if [ "${STUB_EXTRACT_RC:-0}" != 0 ]; then exit $STUB_EXTRACT_RC; fi
[ -n "${STUB_NO_TARBALL:-}" ] || : > images/${STUB_IID:-%(iid)s}.tar.gz
""",
    "scripts/util.py": """#!/bin/bash
case "$1" in
  get_iid) echo -n "${STUB_IID-%(iid)s}";;
  get_brand) echo "dlink";;
  check_connection) exit ${STUB_DB_RC:-0};;
esac
""",
    "scripts/getArch.py": '#!/bin/bash\necho -n "${STUB_ARCH-mipsel}"\n',
    "scripts/inferKernel.py": "#!/bin/bash\nexit 0\n",
    "scripts/tar2db.py": "import os, sys\nsys.exit(int(os.environ.get('STUB_TAR2DB_RC', '0')))\n",
    "scripts/makeImage.sh": """#!/bin/bash
echo "building image for $1 $2 $3"
if [ "${STUB_IMAGE_RC:-0}" != 0 ]; then echo "image boom"; exit $STUB_IMAGE_RC; fi
touch "$PROJECT/image_done"
""",
    "scripts/makeNetwork.py": """import os, sys
if os.environ.get('STUB_NET_RC', '0') != '0':
    print('network boom'); sys.exit(int(os.environ['STUB_NET_RC']))
iid = sys.argv[sys.argv.index('-i') + 1]
d = os.path.join('scratch', iid)
open(os.path.join(d, 'ping'), 'w').write('true\\n')
open(os.path.join(d, 'ip'), 'w').write('192.168.0.1\\n')
open(os.path.join(d, 'web'), 'w').write(os.environ.get('STUB_WEB', 'true') + '\\n')
""",
}


@pytest.fixture
def project(repo_root, tmp_path, monkeypatch):
    root = tmp_path / "FirmAE"
    root.mkdir()
    shutil.copy(repo_root / "firmae.config", root)
    for rel, body in STUBS.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body % {"iid": IID} if "%(iid)s" in body else body)
        p.chmod(0o755)
    monkeypatch.delenv("FIRMAE_DOCKER", raising=False)
    monkeypatch.setenv("PROJECT", str(root))
    monkeypatch.setenv("STUB_IID", IID)
    return root


def fw(project, name="DIR-868L.zip"):
    """A firmware file (the pipeline hashes it for its lock); content = name."""
    d = project.parent / "x"
    d.mkdir(exist_ok=True)
    p = d / name
    if not p.exists():
        p.write_text(name)
    return str(p)


def run(project, option="check", firmware=None, brand="dlink"):
    firmware = firmware or fw(project)
    cfg = config.load(str(project))
    out = io.StringIO()
    pipe = Pipeline(cfg, option, brand, Reporter(out=out, color=False))
    code = pipe.run_firmware(firmware)
    return code, out.getvalue(), project / "scratch" / IID


def test_success(project):
    code, out, work = run(project)
    assert code == ExitCode.OK
    assert (work / "result").read_text() == "true\n"
    assert (work / "architecture").read_text() == "mipsel\n"
    assert (work / "name").read_text() == "DIR-868L\n"
    assert (work / "brand").read_text() == "dlink\n"
    for t in ("extract", "arch", "tar", "image", "network"):
        assert float((work / ("time_" + t)).read_text()) >= 0
    for mode in ("debug", "analyze", "boot"):
        assert os.readlink(work / ("run_%s.sh" % mode)) == "./run.sh"
    assert "[*] %s emulation start!!!" % fw(project) in out
    assert "[+] Web service on 192.168.0.1" in out
    assert "[IID] %s\n[MODE] check" % IID in out
    assert (work / "makeImage.log").read_text() == "building image for %s mipsel DIR-868L\n" % IID
    # extractor: -nk then -nf, brand passed as -b
    calls = (project / "extractor_calls").read_text().splitlines()
    assert [c.split()[5] for c in calls] == ["-nk", "-nf"]
    assert calls[0].startswith("-b dlink -sql 127.0.0.1 -np")


def test_log_file_has_timestamp_level_iid_and_stage(project):
    _, _, work = run(project)
    lines = (work / "firmae.log").read_text().splitlines()
    assert lines, "no log"
    assert all(" [iid=" in l for l in lines)
    assert any("[iid=-][start] %s emulation start!!!" % fw(project) in l for l in lines)   # buffered until the id was known
    assert any("INFO  [iid=%s][arch] get architecture done!!!" % IID in l for l in lines)
    assert any("[iid=%s][network] infer network start!!!" % IID in l for l in lines)
    assert lines[0][:4].isdigit() and "T" in lines[0][:20]


def test_web_unreachable_is_exit_50_and_result_false(project, monkeypatch):
    monkeypatch.setenv("STUB_WEB", "false")
    code, out, work = run(project)
    assert code == ExitCode.UNREACHABLE == 50
    assert (work / "result").read_text() == "false\n"
    assert "[-] Web unreachable" in out
    assert "Web service on" not in out


def test_rootfs_not_extracted(project, monkeypatch):
    monkeypatch.setenv("STUB_NO_TARBALL", "1")
    code, out, work = run(project)
    assert code == ExitCode.EXTRACTION == 10
    assert (work / "result").read_text() == "extraction fail\n"
    assert "[-] Extracting root filesystem failed!" in out
    assert not (project / "image_done").exists()


def test_extractor_error_exit(project, monkeypatch):
    monkeypatch.setenv("STUB_EXTRACT_RC", "5")
    code, out, _ = run(project)
    assert code == ExitCode.EXTRACTION
    assert "extractor.py (-nk) failed with exit 5" in out


def test_no_image_id(project, monkeypatch):
    monkeypatch.setenv("STUB_IID", "")
    code, out, _ = run(project)
    assert code == ExitCode.IMAGE_ID == 11
    assert "[-] extractor.py failed!" in out
    assert not (project / "scratch" / IID).exists()


@pytest.mark.parametrize("arch,text", [("", "get architecture fail"),
                                       ("x86", "not valid architecture : x86")])
def test_architecture_failures(project, monkeypatch, arch, text):
    monkeypatch.setenv("STUB_ARCH", arch)
    code, out, work = run(project)
    assert code == ExitCode.ARCH == 20
    assert (work / "result").read_text() == text + "\n"
    assert not (project / "image_done").exists()


def test_image_failure_shows_log_tail_and_skips_network(project, monkeypatch):
    monkeypatch.setenv("STUB_IMAGE_RC", "3")
    code, out, work = run(project)
    assert code == ExitCode.IMAGE == 30
    assert "makeImage.sh failed (exit 3); last lines of" in out
    assert "image boom" in out
    assert not (work / "ping").exists()       # makeNetwork never ran


def test_network_failure(project, monkeypatch):
    monkeypatch.setenv("STUB_NET_RC", "2")
    code, out, work = run(project)
    assert code == ExitCode.NETWORK == 40
    assert "network boom" in out
    assert not (work / "run_debug.sh").exists()


def test_docker_mode_database_check(project, monkeypatch):
    monkeypatch.setenv("FIRMAE_DOCKER", "true")
    monkeypatch.setenv("STUB_DB_RC", "1")
    # firmae.config switches to the fixed /work/FirmAE paths in Docker mode; only
    # the early check matters here
    cfg = config.load(str(project))
    out = io.StringIO()
    code = Pipeline(cfg, "check", "dlink", Reporter(out=out, color=False)).run_firmware(fw(project, "a.zip"))
    assert code == ExitCode.DATABASE
    assert "docker container failed to connect to the hosts' postgresql!" in out.getvalue()


def test_check_mode_skips_firmware_that_already_succeeded(project):
    work = project / "scratch" / IID
    work.mkdir(parents=True)
    (work / "result").write_text("true\n")
    code, out, _ = run(project)
    assert code == ExitCode.OK
    assert not (project / "image_done").exists()


def test_check_mode_skip_rewrites_the_result_for_docker_helper(project):
    """docker-helper.py ignores a result older than its run (mtime): the skip
    path must leave a fresh result with the same content."""
    work = project / "scratch" / IID
    work.mkdir(parents=True)
    (work / "result").write_text("true\n")
    os.utime(work / "result", (1000, 1000))
    t0 = time.time()
    code, _, _ = run(project)
    assert code == ExitCode.OK and not (project / "image_done").exists()
    assert (work / "result").read_text() == "true\n"
    assert os.path.getmtime(work / "result") >= t0 - 1


def test_unreadable_firmware_is_reported_as_such(project, tmp_path):
    missing = str(tmp_path / "no-such-firmware.bin")
    code, out, _ = run(project, firmware=missing, brand="auto")
    assert code == ExitCode.EXTRACTION
    assert "cannot read firmware %s" % missing in out
    assert "database" not in out
    assert not (project / "extractor_calls").exists()


def test_check_mode_reruns_after_a_failed_result(project):
    work = project / "scratch" / IID
    work.mkdir(parents=True)
    (work / "result").write_text("false\n")
    code, _, work = run(project)
    assert code == ExitCode.OK and (project / "image_done").exists()


def test_brand_auto_is_resolved_per_firmware_without_sticking(project):
    cfg = config.load(str(project))
    pipe = Pipeline(cfg, "check", "auto", Reporter(out=io.StringIO(), color=False))
    pipe.run_firmware(fw(project, "a.zip"))
    pipe.run_firmware(fw(project, "b.zip"))
    assert pipe.brand == "auto"               # the old script overwrote BRAND after the first file
    calls = (project / "extractor_calls").read_text().splitlines()
    assert all(c.startswith("-b dlink ") for c in calls)


# ---------------------------------------------------------------- command line

def test_usage(capsys):
    assert cli.main([]) == ExitCode.USAGE
    assert "Usage: ./run.sh [mode]... [brand] [firmware|firmware_directory]" in capsys.readouterr().out
    assert cli.main(["-x", "a", "b"]) == ExitCode.USAGE


def test_needs_root(project, monkeypatch, capsys):
    monkeypatch.chdir(project)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert cli.main(["-c", "dlink", "/x/a.zip"]) == ExitCode.PRIVILEGE
    assert "This script must run with 'root' privilege" in capsys.readouterr().out


def test_directory_processes_every_file_and_reports_the_first_failure(project, tmp_path, monkeypatch):
    fw = tmp_path / "fw"
    fw.mkdir()
    for name in ("a.bin", "b.bin", "c.bin"):
        (fw / name).write_text("x")
    # each file gets its own image id (987654..6); b.bin yields no rootfs tarball
    ids = {"a.bin": "987654", "b.bin": "987655", "c.bin": "987656"}
    (project / "scripts/util.py").write_text(
        '#!/bin/bash\ncase "$1" in get_iid) case "$2" in %s esac;; esac\n' %
        " ".join('*%s) echo -n %s;;' % kv for kv in ids.items()))
    (project / "sources/extractor/extractor.py").write_text("""#!/bin/bash
f="${@: -2:1}"
echo "$f" >> "$PROJECT/extractor_calls"
mkdir -p images
case "$f" in
  *a.bin) : > images/987654.tar.gz;;
  *c.bin) : > images/987656.tar.gz;;
esac
""")
    monkeypatch.chdir(project)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    code = cli.main(["-c", "dlink", str(fw)])
    seen = [os.path.basename(l) for l in (project / "extractor_calls").read_text().splitlines()]
    assert seen == ["a.bin", "a.bin", "b.bin", "b.bin", "c.bin", "c.bin"]     # -nk and -nf for each
    results = {i: (project / "scratch" / i / "result").read_text().strip() for i in ids.values()}
    assert results == {"987654": "true", "987655": "extraction fail", "987656": "true"}
    assert code == ExitCode.EXTRACTION


def test_debug_mode_rejects_a_directory(project, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(project)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert cli.main(["-d", "dlink", str(tmp_path)]) == ExitCode.USAGE
    assert "select firmware file on debug mode!" in capsys.readouterr().out


# ---------------------------------------------------------------- config

def test_config_matches_firmae_config(project):
    cfg = config.load(str(project))
    assert (cfg.FIRMAE_NET, cfg.FIRMAE_BOOT, cfg.TIMEOUT, cfg.CHECK_TIMEOUT) == ("true", "true", 360, 360)
    assert cfg.SCRATCH_DIR == str(project / "scratch")
    assert cfg.PSQL_IP == "127.0.0.1"
    assert cfg.scratch(7) == str(project / "scratch" / "7")


def test_valid_archs_match_check_arch(repo_root):
    import subprocess
    for arch in config.VALID_ARCHS + ("x86", ""):
        rc = subprocess.run(["bash", "-c", 'source ./firmae.config && check_arch "$1"', "_", arch],
                            cwd=repo_root, capture_output=True).returncode
        assert (rc == 1) == (arch in config.VALID_ARCHS)     # check_arch returns 1 for VALID


# ------------------------------------------------- audit fixes (Phase 5 review)

def test_log_labels_do_not_carry_over_to_the_next_firmware(tmp_path):
    r = Reporter(out=io.StringIO(), color=False)
    r.bind("111", str(tmp_path / "a.log"))
    r.info("first firmware", "arch")
    r.close()
    r.info("second firmware started", "start")          # image id not known yet
    r.bind("222", str(tmp_path / "b.log"))
    r.close()
    first_line = (tmp_path / "b.log").read_text().splitlines()[0]
    assert "[iid=-][start] second firmware started" in first_line and "111" not in first_line


def test_unicode_digits_are_not_an_image_id(project, monkeypatch):
    monkeypatch.setenv("STUB_IID", "²")            # "²".isdigit() is True
    code, out, _ = run(project)
    assert code == ExitCode.IMAGE_ID
    assert not (project / "scratch" / IID).exists()


def test_a_hanging_helper_times_out_instead_of_hanging_forever(project, monkeypatch):
    from firmae import pipeline
    monkeypatch.setattr(pipeline, "CAPTURE_TIMEOUT", 1)
    (project / "scripts/util.py").write_text("#!/bin/bash\nsleep 30\n")
    code, out, _ = run(project)
    assert code == ExitCode.TIMEOUT == 124
    assert "util.py timed out after 1s" in out


# ------------------------------------------------- stage time limits

def test_a_hanging_stage_is_stopped_and_reports_timeout(project, monkeypatch):
    """makeImage.sh (and a child it started) hang: the whole process group is
    stopped at the limit and the firmware fails with exit 124."""
    from firmae import pipeline
    monkeypatch.setattr(pipeline, "STAGE_GRACE", 1)
    monkeypatch.setenv("FIRMAE_TIMEOUT_IMAGE", "1")
    (project / "scripts/makeImage.sh").write_text(
        '#!/bin/bash\necho "hanging now"\nsleep 300 &\necho $! > "$PROJECT/child_pid"\n'
        'trap "" INT\nwait\n')                                     # ignores SIGINT -> SIGKILL after the grace
    t0 = time.time()
    code, out, work = run(project)
    assert code == ExitCode.TIMEOUT == 124
    assert time.time() - t0 < 30
    assert "makeImage.sh timed out after 1s; last lines of" in out
    assert "hanging now" in out
    child = int((project / "child_pid").read_text())
    for _ in range(50):                                            # killed with its group
        if not os.path.exists("/proc/%d" % child) or open("/proc/%d/stat" % child).read().split(")")[-1].split()[0] == "Z":
            break
        time.sleep(0.1)
    else:
        pytest.fail("the stage's child survived the timeout")
    assert not (work / "ping").exists()                            # makeNetwork never ran


def test_stage_timeouts_default_and_override(project, monkeypatch):
    from firmae import pipeline
    monkeypatch.delenv("FIRMAE_TIMEOUT_NETWORK", raising=False)
    seen = {}
    real = pipeline.run_with_timeout

    def spy(argv, timeout, **kw):
        seen[os.path.basename(argv[2] if argv[0] == "python3" else argv[0])] = timeout
        return real(argv, timeout, **kw)
    monkeypatch.setattr(pipeline, "run_with_timeout", spy)
    (project / "scripts/makeImage.sh").write_text(
        '#!/bin/bash\nprintf "/sbin/rcS\\n/sbin/preinit\\n/firmadyne/preInit.sh\\n" > scratch/$1/init\n')
    code, _, _ = run(project)
    assert code == ExitCode.OK
    # 3 init candidates x (TIMEOUT 360 + CHECK_TIMEOUT 360 + margin) + base
    assert seen == {"tar2db.py": pipeline.TAR2DB_TIMEOUT, "makeImage.sh": pipeline.IMAGE_TIMEOUT,
                    "makeNetwork.py": pipeline.NETWORK_BASE_TIMEOUT + 3 * (720 + pipeline.NETWORK_PER_INIT_MARGIN),
                    "extractor.py": pipeline.EXTRACT_TIMEOUT}
    assert seen["makeNetwork.py"] > 3 * 420                        # measured: ~420 s per candidate
    monkeypatch.setenv("FIRMAE_TIMEOUT_NETWORK", "0")              # 0: no limit
    monkeypatch.setenv("FIRMAE_TIMEOUT_TAR2DB", "77")
    monkeypatch.setenv("FIRMAE_TIMEOUT_IMAGE", "junk")             # ignored
    shutil.rmtree(project / "scratch")
    assert run(project)[0] == ExitCode.OK
    assert (seen["makeNetwork.py"], seen["tar2db.py"], seen["makeImage.sh"]) == (None, 77, pipeline.IMAGE_TIMEOUT)


# ------------------------------------------------- helper exit codes

def test_database_error_on_image_id_lookup_is_not_no_image_id(project):
    (project / "scripts/util.py").write_text(
        '#!/bin/bash\ncase "$1" in get_iid) echo "util.py: get_iid failed: boom" >&2; exit 1;; esac\n')
    code, out, _ = run(project)
    assert code == ExitCode.DATABASE
    assert "image id lookup failed (util.py get_iid exit 1" in out
    assert "is the database reachable" not in out          # util.py's own message says why
    assert not (project / "scratch" / IID).exists()


def test_database_error_on_brand_lookup(project):
    (project / "scripts/util.py").write_text(
        '#!/bin/bash\ncase "$1" in get_brand) exit 1;; get_iid) echo -n %s;; esac\n' % IID)
    cfg = config.load(str(project))
    out = io.StringIO()
    code = Pipeline(cfg, "check", "auto", Reporter(out=out, color=False)).run_firmware(fw(project, "a.zip"))
    assert code == ExitCode.DATABASE
    assert "brand lookup failed" in out.getvalue()
    assert not (project / "extractor_calls").exists()


def test_unknown_brand_still_runs_without_brand_argument(project):
    (project / "scripts/util.py").write_text(
        '#!/bin/bash\ncase "$1" in get_brand) echo "";; get_iid) echo -n %s;; esac\n' % IID)
    cfg = config.load(str(project))
    code = Pipeline(cfg, "check", "auto", Reporter(out=io.StringIO(), color=False)).run_firmware(fw(project, "a.zip"))
    assert code == ExitCode.OK
    assert (project / "extractor_calls").read_text().splitlines()[0].startswith("-sql ")


@pytest.mark.parametrize("stdout,code,result", [("", ExitCode.ARCH, "get architecture fail\n"),
                                                 ("mipsel", ExitCode.DATABASE, None)])
def test_getarch_failure_exit_code_is_not_ignored(project, stdout, code, result):
    (project / "scripts/getArch.py").write_text('#!/bin/bash\necho -n "%s"\nexit 1\n' % stdout)
    got, out, work = run(project)
    assert got == code
    assert "getArch.py" in out
    if result is None:
        assert not (work / "result").exists()
    else:
        assert (work / "result").read_text() == result
    assert not (project / "image_done").exists()


def test_database_connect_timeout_is_set_for_helpers(project, monkeypatch):
    monkeypatch.delenv("PGCONNECT_TIMEOUT", raising=False)
    assert config.load(str(project)).env()["PGCONNECT_TIMEOUT"] == "30"
    monkeypatch.setenv("PGCONNECT_TIMEOUT", "5")                 # an explicit setting wins
    assert config.load(str(project)).env()["PGCONNECT_TIMEOUT"] == "5"


def test_many_firmwares_leak_neither_file_descriptors_nor_memory(project):
    """40 firmwares through one Pipeline: open fds and resident memory stay flat."""
    cfg = config.load(str(project))
    pipe = Pipeline(cfg, "check", "dlink", Reporter(out=io.StringIO(), color=False))
    fds = lambda: len(os.listdir("/proc/self/fd"))
    def rss():
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") // 1024

    def one(i):
        assert pipe.run_firmware(fw(project, "fw%d.zip" % i)) == ExitCode.OK
        shutil.rmtree(project / "scratch")

    for i in range(5):                   # warm-up (imports, caches)
        one(i)
    fd0, rss0 = fds(), rss()
    for i in range(40):
        one(i)
    assert fds() == fd0
    assert rss() - rss0 < 4096           # KB; the measured growth over 40 runs is 0
