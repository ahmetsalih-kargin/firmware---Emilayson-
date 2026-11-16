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

import fcntl
import hashlib
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

# Upper bounds of the stages (seconds). Generous on purpose: they only turn a
# hang into an error. FIRMAE_TIMEOUT_<STAGE> (TAR2DB, IMAGE, NETWORK) overrides
# them; 0 means no limit.
TAR2DB_TIMEOUT = 3600
IMAGE_TIMEOUT = 3600
# makeNetwork.py tries every init candidate (scratch/<IID>/init) in turn, each
# with an initial emulation (TIMEOUT) and a check run (10 s + CHECK_TIMEOUT +
# cleanup); measured ~420 s for one candidate with TIMEOUT=CHECK_TIMEOUT=360.
NETWORK_BASE_TIMEOUT = 900
NETWORK_PER_INIT_MARGIN = 300
STAGE_GRACE = 60            # SIGKILL this long after SIGINT: makeNetwork's cleanup trap needs time

LOCK_NAME = ".firmae.lock"  # in scratch/<IID>/; flock'ed while an image is processed
# scratch/.locks/<md5 of the firmware>.lock: flock'ed before the first stage.
# The image id is only known after `extractor.py -nk` (which already writes
# images/<IID>.tar.gz), so it cannot guard that step. The md5 is the key the
# database maps to the image id (util.py get_iid), so two runs that would get
# the same IID always contend for the same firmware lock.
FIRMWARE_LOCK_DIR = ".locks"
HASH_BLOCK = 1 << 20


def firmware_digest(path):
    """md5 of the file's content, read in blocks (firmware can be large)."""
    try:                         # an identity key, not a security measure (FIPS hosts)
        h = hashlib.md5(usedforsecurity=False)
    except TypeError:            # Python < 3.9
        h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(HASH_BLOCK), b""):
            h.update(block)
    return h.hexdigest()


def stage_timeout(stage, default):
    """default, or FIRMAE_TIMEOUT_<STAGE> when set to a non-negative integer (0: none)."""
    value = os.environ.get("FIRMAE_TIMEOUT_%s" % stage.upper(), "").strip()
    if value.isascii() and value.isdigit():
        return int(value) or None
    return default


class Pipeline:
    def __init__(self, cfg, option, brand, reporter):
        self.cfg = cfg
        self.option = option            # check | analyze | run | debug | boot
        self.brand = brand
        self.say = reporter
        self.iid = None
        self.state = None
        self._lock_fd = None             # scratch/<IID>/.firmae.lock
        self._fw_lock_fd = None          # scratch/.locks/<md5>.lock

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _flock(path, what, dir_fd=None):
        """Open `path` (never through a symlink) and flock it without waiting.
        The kernel drops the lock when we die (no stale lock files); the fd is
        not inherited by the stages. Returns the fd; raises BUSY when another
        process holds it."""
        try:
            fd = os.open(os.path.basename(path) if dir_fd is not None else path,
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dir_fd)
        except OSError as e:
            raise FirmAEError("lock", ExitCode.INTERNAL, "cannot open lock file %s: %s" % (path, e))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            holder = ""
            try:
                holder = os.pread(fd, 32, 0).decode(errors="replace").strip()
            except OSError:
                pass
            os.close(fd)
            if isinstance(e, BlockingIOError):
                raise FirmAEError("lock", ExitCode.BUSY,
                                  "%s is being processed by another FirmAE run%s "
                                  "(lock %s); skipping this firmware" %
                                  (what, " (pid %s)" % holder if holder.isdigit() else "", path))
            raise FirmAEError("lock", ExitCode.INTERNAL, "cannot lock %s: %s" % (path, e))
        try:                     # informational only: who holds it
            os.ftruncate(fd, 0)
            os.pwrite(fd, ("%d\n" % os.getpid()).encode(), 0)
        except OSError:
            pass
        return fd

    def _acquire_firmware_lock(self, infile, digest):
        """flock scratch/.locks/<md5>.lock before the first stage: a second run
        of the same firmware must not run even `extractor.py -nk` (it rewrites
        images/<IID>.tar.gz while the first run uses it)."""
        locks = os.path.join(self.cfg.SCRATCH_DIR, FIRMWARE_LOCK_DIR)
        path = os.path.join(locks, digest + ".lock")
        try:
            os.makedirs(locks, mode=0o755, exist_ok=True)
            # O_NOFOLLOW on the directory too: a symlinked .locks must not make
            # root create files elsewhere
            dfd = os.open(locks, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as e:
            raise FirmAEError("lock", ExitCode.INTERNAL, "cannot open lock directory %s: %s" % (locks, e))
        try:
            self._fw_lock_fd = self._flock(path, "firmware %s" % infile, dir_fd=dfd)
        finally:
            os.close(dfd)

    def _acquire_lock(self, workdir, iid):
        """flock scratch/<IID>/.firmae.lock. Kept besides the firmware lock: it
        is what anything else that works on scratch/<IID> can take, and it costs
        nothing. Every FirmAE run of this IID holds the firmware lock first (same
        md5), so between FirmAE runs this one is never the one that is busy."""
        self._lock_fd = self._flock(os.path.join(workdir, LOCK_NAME), "image %s" % iid)

    def _release_lock(self):
        for name in ("_lock_fd", "_fw_lock_fd"):    # reverse order of acquisition
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)                 # closing the only fd drops the flock
                setattr(self, name, None)

    def _network_timeout(self):
        """Bound for makeNetwork.py: base + per init candidate (see NETWORK_BASE_TIMEOUT)."""
        try:
            with open(self.state.path("init"), errors="replace") as f:
                # same count as makeNetwork's read().split("\n")[:-1]
                candidates = f.read().count("\n")
        except OSError:
            candidates = 0
        per_init = self.cfg.TIMEOUT + self.cfg.CHECK_TIMEOUT + NETWORK_PER_INIT_MARGIN
        return stage_timeout("network", NETWORK_BASE_TIMEOUT + max(1, candidates) * per_init)

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

    def _show_tail(self, logpath):
        try:
            with open(logpath, errors="replace") as f:
                for line in f.readlines()[-LOG_TAIL_LINES:]:
                    self.say.plain(line.rstrip("\n"))
        except OSError:
            pass

    def _step(self, stage, argv, logname, code, env=None, timeout=None):
        """Run one stage with stdout+stderr in scratch/<IID>/<logname>; on failure
        show the log tail and raise. After `timeout` seconds the stage's whole
        process group is stopped (SIGINT, SIGKILL STAGE_GRACE later)."""
        logpath = self.state.path(logname)
        name = os.path.basename(argv[2] if argv[0] == "python3" and len(argv) > 2 else argv[0])
        self.say.debug("%s: %s -> %s" % (stage, " ".join(argv), logname))
        with open(logpath, "w") as log:
            rc, timed_out = run_with_timeout(argv, timeout, grace=STAGE_GRACE, cwd=self.cfg.root,
                                             env=env or self.cfg.env(),
                                             stdout=log, stderr=subprocess.STDOUT)
        if timed_out:
            self.say.error("%s timed out after %ds; last lines of %s:" % (name, timeout, logpath), stage)
            self._show_tail(logpath)
            raise FirmAEError(stage, ExitCode.TIMEOUT, "%s timed out after %ds" % (name, timeout))
        if rc != 0:
            self.say.error("%s failed (exit %d); last lines of %s:" % (os.path.basename(argv[0]), rc, logpath), stage)
            self._show_tail(logpath)
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
            # Only with the lock held: without it the image's QEMU, mount, loop
            # devices and TAPs may belong to another run that is still using them.
            if self.iid is not None and self._lock_fd is not None:
                # QEMU, mount, loop devices, TAP/VLAN, /tmp sockets of this image only
                self._bash_fn("release_emulation", self.iid)
            self._release_lock()         # after the release: nobody may start on half-freed resources
            self.say.close()

    def _run(self, infile):
        cfg, say = self.cfg, self.say
        say.info("%s emulation start!!!" % infile, "start")

        # The lock key; reading the file here also tells an unreadable firmware
        # apart from a database failure of util.py (which hashes it too).
        try:
            digest = firmware_digest(infile)
        except OSError as e:
            raise FirmAEError("start", ExitCode.EXTRACTION, "cannot read firmware %s: %s" % (infile, e))

        brand = self.brand
        if brand == "auto":
            rc, brand = self._capture(["./scripts/util.py", "get_brand", infile, cfg.PSQL_IP])
            # rc != 0: the lookup failed (the firmware was readable a moment ago,
            # so most likely the database; util.py printed why); rc == 0 with ""
            # is "no brand known", which continues without -b as before
            if rc != 0:
                raise FirmAEError("start", ExitCode.DATABASE,
                                  "brand lookup failed (util.py get_brand exit %d; its error is shown above)" % rc)
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
        # Before the first stage that writes: a run that cannot get this lock
        # touches nothing (BUSY, no extractor, no release_emulation).
        self._acquire_firmware_lock(infile, digest)
        t_start = time.time()
        self._extract("-nk", infile, brand_args)

        rc, iid = self._capture(["./scripts/util.py", "get_iid", infile, cfg.PSQL_IP])
        if rc != 0:      # a database error is not "no image id"
            raise FirmAEError("extract", ExitCode.DATABASE,
                              "image id lookup failed (util.py get_iid exit %d; its error is shown above)" % rc)
        if not (iid.isascii() and iid.isdigit()):    # str.isdigit() also accepts e.g. "²"
            raise FirmAEError("extract", ExitCode.IMAGE_ID, "extractor.py failed!")
        self.iid = iid

        # The firmware lock already excludes other FirmAE runs of this image;
        # the image lock is taken before scratch/<IID> is used.
        workdir = cfg.scratch(iid)
        os.makedirs(workdir, exist_ok=True)
        if self._bash_fn("secure_workdir", workdir) != 0:
            # e.g. scratch/<IID> is a symlink: nothing may be written through it
            raise FirmAEError("lock", ExitCode.INTERNAL, "cannot secure %s (see above)" % workdir)
        self._acquire_lock(workdir, iid)
        # A previous run killed with SIGKILL dropped its locks but may have left
        # its QEMU (own session), mount, loop devices or TAPs behind. With the
        # locks held, whatever is left of this image is stale: free it once.
        self._bash_fn("release_emulation", iid)

        # -------- extract kernel
        self._extract("-nf", infile, brand_args)

        self.state = st = State(workdir)
        say.bind(iid, st.path("firmae.log"))
        st.write("name", filename)
        st.write("brand", brand)
        os.sync()

        if self.option == "check" and st.exists("result"):
            if st.flag("result"):
                # rewrite it unchanged: docker-helper.py only trusts a result
                # written after the run started (mtime), else this already
                # emulated image would be reported as failed
                with open(st.path("result"), "rb") as f:
                    previous = f.read()
                with open(st.path("result"), "wb") as f:
                    f.write(previous)
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
        rc, arch = self._capture(["./scripts/getArch.py", tarball, cfg.PSQL_IP])
        st.write("architecture", arch)
        if rc != 0 and arch:
            # detected, then failed: getArch.py records the result in the database last
            raise FirmAEError("arch", ExitCode.DATABASE,
                              "getArch.py found %s but failed with exit %d (database update?)" % (arch, rc))
        if rc != 0:
            raise FirmAEError("arch", ExitCode.ARCH, "getArch.py failed with exit %d" % rc,
                              result_text="get architecture fail")
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
                       "tar2db.log", ExitCode.IMAGE, timeout=stage_timeout("tar2db", TAR2DB_TIMEOUT))
            st.write_time("tar", time.time() - t)

            t = time.time()
            self._step("image", ["./scripts/makeImage.sh", iid, arch, filename],
                       "makeImage.log", ExitCode.IMAGE, timeout=stage_timeout("image", IMAGE_TIMEOUT))
            st.write_time("image", time.time() - t)

            t = time.time()
            say.info("infer network start!!!", "network")
            self._step("network", ["python3", "-u", "./scripts/makeNetwork.py", "-i", iid, "-q",
                                   "-o", "-a", arch],
                       "makeNetwork.log", ExitCode.NETWORK, timeout=self._network_timeout())
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
