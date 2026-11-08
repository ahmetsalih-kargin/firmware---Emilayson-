"""The host-side pipeline that run.sh used to implement, stage by stage:

    extract rootfs -> image id -> extract kernel -> architecture ->
    QEMU image -> network inference + check -> result -> mode (analyze/debug/run/boot)

The stage scripts themselves (extractor.py, getArch.py, makeImage.sh,
makeNetwork.py, ...) are still the existing ones; they are called with argument
lists (no shell) and their output goes to the same per-stage log files as before.
What changed is error handling: every failure has an exit code and a stage name,
a failed firmware does not stop the others, and whatever the exit path (error,
Ctrl-C, SIGTERM) the image's QEMU, mount, loop devices and TAP interfaces are
released.
"""

import os
import subprocess
import time

from scripts.procgroup import run_with_timeout

from .config import VALID_ARCHS
from .errors import ExitCode, FirmAEError
from .state import State

EXTRACT_TIMEOUT = 300       # seconds, as before
CAPTURE_TIMEOUT = 600       # helper scripts (database lookups, architecture detection)
RELEASE_TIMEOUT = 180       # cleanup of one image's resources
EXTRACT_GRACE = 30          # SIGKILL this long after SIGINT (was: no escalation)
LOG_TAIL_LINES = 20


class Pipeline:
    def __init__(self, cfg, option, brand, reporter):
        self.cfg = cfg
        self.option = option            # check | analyze | run | debug | boot
        self.brand = brand
        self.say = reporter
        self.iid = None
        self.state = None

    # ------------------------------------------------------------------ helpers

    def _bash_fn(self, name, *args):
        """Call a function of firmae.config (secure_workdir, release_emulation)."""
        try:
            return subprocess.run(
                ["bash", "-c", 'source ./firmae.config && "$@"', "_", name] + [str(a) for a in args],
                cwd=self.cfg.root, env=self.cfg.env(), stdout=subprocess.DEVNULL,
                timeout=RELEASE_TIMEOUT).returncode
        except subprocess.TimeoutExpired:
            self.say.error("%s timed out after %ds" % (name, RELEASE_TIMEOUT))
            return int(ExitCode.TIMEOUT)

    def _capture(self, argv):
        """Run a helper script, return its stdout; stderr goes to the terminal."""
        try:
            res = subprocess.run(argv, cwd=self.cfg.root, env=self.cfg.env(),
                                 stdout=subprocess.PIPE, timeout=CAPTURE_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise FirmAEError("helper", ExitCode.TIMEOUT,
                              "%s timed out after %ds" % (os.path.basename(argv[0]), CAPTURE_TIMEOUT))
        return res.returncode, res.stdout.decode(errors="replace").strip()

    def _extract(self, flag, infile, brand_args):
        argv = (["./sources/extractor/extractor.py"] + brand_args +
                ["-sql", self.cfg.PSQL_IP, "-np", flag, infile, "images"])
        rc, timed_out = run_with_timeout(
            argv, EXTRACT_TIMEOUT, grace=EXTRACT_GRACE, cwd=self.cfg.root, env=self.cfg.env(),
            stdout=subprocess.DEVNULL)
        if timed_out:
            raise FirmAEError("extract", ExitCode.TIMEOUT,
                              "extractor.py (%s) timed out after %ds" % (flag, EXTRACT_TIMEOUT))
        if rc != 0:
            raise FirmAEError("extract", ExitCode.EXTRACTION,
                              "extractor.py (%s) failed with exit %d" % (flag, rc))

    def _step(self, stage, argv, logname, code, env=None):
        """Run one stage with stdout+stderr in scratch/<IID>/<logname>; on failure
        show the log tail and raise."""
        logpath = self.state.path(logname)
        self.say.debug("%s: %s -> %s" % (stage, " ".join(argv), logname))
        with open(logpath, "w") as log:
            rc, _ = run_with_timeout(argv, None, cwd=self.cfg.root, env=env or self.cfg.env(),
                                     stdout=log, stderr=subprocess.STDOUT)
        if rc != 0:
            self.say.error("%s failed (exit %d); last lines of %s:" % (os.path.basename(argv[0]), rc, logpath), stage)
            try:
                with open(logpath, errors="replace") as f:
                    for line in f.readlines()[-LOG_TAIL_LINES:]:
                        self.say.plain(line.rstrip("\n"))
            except OSError:
                pass
            raise FirmAEError(stage, code, "%s failed with exit %d" % (os.path.basename(argv[0]), rc))

    # ------------------------------------------------------------------- run

    def run_firmware(self, infile):
        """Process one firmware file. Returns an ExitCode; never raises FirmAEError."""
        self.iid = None
        self.state = None
        try:
            return self._run(infile)
        except FirmAEError as e:
            self.say.error(e.message, e.stage)
            if e.result_text is not None and self.state is not None:
                self.state.write("result", e.result_text)
            return e.code
        finally:
            if self.iid is not None:
                # QEMU, mount, loop devices, TAP/VLAN, /tmp sockets of this image only
                self._bash_fn("release_emulation", self.iid)
            self.say.close()

    def _run(self, infile):
        cfg, say = self.cfg, self.say
        say.info("%s emulation start!!!" % infile, "start")

        brand = self.brand
        if brand == "auto":
            _, brand = self._capture(["./scripts/util.py", "get_brand", infile, cfg.PSQL_IP])
        if brand == "auto":
            raise FirmAEError("start", ExitCode.USAGE, "Invalid brand %s" % infile)

        if os.environ.get("FIRMAE_DOCKER"):
            rc, _ = self._capture(["./scripts/util.py", "check_connection", "_", cfg.PSQL_IP])
            if rc != 0:
                raise FirmAEError("start", ExitCode.DATABASE,
                                  "docker container failed to connect to the hosts' postgresql!")

        brand_args = ["-b", brand] if brand else []
        # bash: `basename ${INFILE%.*}` -- strip from the LAST dot of the whole path
        stem = infile[:infile.rfind(".")] if "." in infile else infile
        filename = os.path.basename(stem)

        # -------- extract filesystem
        t_start = time.time()
        self._extract("-nk", infile, brand_args)

        _, iid = self._capture(["./scripts/util.py", "get_iid", infile, cfg.PSQL_IP])
        if not (iid.isascii() and iid.isdigit()):    # str.isdigit() also accepts e.g. "²"
            raise FirmAEError("extract", ExitCode.IMAGE_ID, "extractor.py failed!")
        self.iid = iid

        # -------- extract kernel
        self._extract("-nf", infile, brand_args)

        workdir = cfg.scratch(iid)
        os.makedirs(workdir, exist_ok=True)
        self._bash_fn("secure_workdir", workdir)
        self.state = st = State(workdir)
        say.bind(iid, st.path("firmae.log"))
        st.write("name", filename)
        st.write("brand", brand)
        os.sync()

        if self.option == "check" and st.exists("result"):
            if st.flag("result"):
                return ExitCode.OK
            st.remove("result")

        tarball = os.path.join(cfg.root, "images", "%s.tar.gz" % iid)
        if not os.path.exists(tarball):
            raise FirmAEError("extract", ExitCode.EXTRACTION,
                              "Extracting root filesystem failed!", result_text="extraction fail")
        say.info("Extract done!!!", "extract")
        st.write_time("extract", time.time() - t_start)

        # -------- architecture
        t_start = time.time()
        _, arch = self._capture(["./scripts/getArch.py", tarball, cfg.PSQL_IP])
        st.write("architecture", arch)
        if os.path.exists(os.path.join(cfg.root, "images", "%s.kernel" % iid)):
            rc, _ = self._capture(["./scripts/inferKernel.py", iid])
            if rc != 0:
                say.error("inferKernel.py exit %d (continuing)" % rc, "arch")
        if not arch:
            raise FirmAEError("arch", ExitCode.ARCH, "Get architecture failed!",
                              result_text="get architecture fail")
        if arch not in VALID_ARCHS:
            raise FirmAEError("arch", ExitCode.ARCH, "Unknown architecture! - %s" % arch,
                              result_text="not valid architecture : %s" % arch)
        say.ok("get architecture done!!!", "arch")
        say.ok("Start emulation!!!", "emulate")
        say.plain("\n[IID] %s\n[%sMODE%s] %s" % (iid, "\033[33m" if say.color else "",
                                                 "\033[0m" if say.color else "", self.option))
        st.write_time("arch", time.time() - t_start)

        # -------- QEMU image + network inference
        if not st.flag("web"):
            t = time.time()
            self._step("tar2db", ["python3", "-u", "./scripts/tar2db.py", "-i", iid, "-f",
                                  "./images/%s.tar.gz" % iid, "-h", cfg.PSQL_IP],
                       "tar2db.log", ExitCode.IMAGE)
            st.write_time("tar", time.time() - t)

            t = time.time()
            self._step("image", ["./scripts/makeImage.sh", iid, arch, filename],
                       "makeImage.log", ExitCode.IMAGE)
            st.write_time("image", time.time() - t)

            t = time.time()
            say.info("infer network start!!!", "network")
            self._step("network", ["python3", "-u", "./scripts/makeNetwork.py", "-i", iid, "-q",
                                   "-o", "-a", arch],
                       "makeNetwork.log", ExitCode.NETWORK)
            for mode in ("debug", "analyze", "boot"):
                try:
                    os.symlink("./run.sh", st.path("run_%s.sh" % mode))
                except FileExistsError:
                    pass
            st.write_time("network", time.time() - t)
        else:
            say.info("%s already succeed emulation!!!" % infile, "network")

        ip = ""
        ping = st.flag("ping")
        web = st.flag("web")
        if ping:
            ip = st.read("ip", "")
            say.ok("Network reachable on %s!" % ip, "result")
        if web:
            say.ok("Web service on %s" % ip, "result")
            st.write("result", "true")
        else:
            st.write("result", "false")

        if self.option == "check":
            if not web:
                raise FirmAEError("result", ExitCode.UNREACHABLE, "Web unreachable")
            return self._finish()

        rc = self._run_mode(iid, arch, brand, ip, web, ping)
        if rc != 0:
            return ExitCode(rc) if rc in ExitCode._value2member_map_ else ExitCode.INTERNAL
        if (self.option == "analyze" and not web) or (self.option == "debug" and not ping):
            raise FirmAEError("result", ExitCode.UNREACHABLE,
                              "Web unreachable" if self.option == "analyze" else "Network unreachable")
        return self._finish()

    def _finish(self):
        self.say.info("cleanup", "done")
        self.say.plain("======================================")
        return ExitCode.OK

    def _run_mode(self, iid, arch, brand, ip, web, ping):
        """analyze / debug / run / boot: interactive and terminal-bound, kept as
        shell (scripts/run_mode.sh); it runs in our process group so Ctrl-C reaches it."""
        t = time.time()
        proc = subprocess.Popen(["bash", "scripts/run_mode.sh", self.option, iid, arch, brand, ip,
                                 "true" if web else "false", "true" if ping else "false",
                                 self.cfg.PSQL_IP],
                                cwd=self.cfg.root, env=self.cfg.env())
        try:
            rc = proc.wait()
        except BaseException:
            # Ctrl-C normally reaches run_mode.sh itself (same process group); a
            # SIGTERM to us only does not -- stop it, then let the caller clean up
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            raise
        if self.option == "analyze":
            self.state.write_time("analyze", time.time() - t)
        return rc
