"""Building the QEMU disk image of one firmware (REFACTORING_PLAN 4.3, minimal
scope): the flow of the old scripts/makeImage.sh, driven from Python.

    python3 -I firmae/image.py <image ID> <architecture> [<file name>]

scripts/makeImage.sh is a thin wrapper around that line (same arguments, exit 0
on success, non-zero on failure). The steps, their order and the external
tools are those of the old script: qemu-img, /sbin/fdisk (same input), the
loop/partition/mount functions of firmae.config (called through bash, not
reimplemented), mkfs.ext2, GNU tar, chroot ... /bash-static /inferFile.sh,
chroot ... /busybox ash /fixImage.sh, e2fsck -y, sync. Every command is an
argument list (no shell parses a value), runs in a process group of its own
that cannot outlive image.py (see _Group) and has a time limit.

What is new:

* Cleanup on every exit path. The image is unmounted and its loop devices are
  released in reverse order whatever happens -- a failing step, an exception,
  Ctrl-C, SIGTERM, SIGHUP (run.sh's release_emulation stays as a backup).
* The firmware file system is untrusted, and so is everything the chroot'ed
  scripts create from its data. inferFile.sh, for example, turns a kernel
  `init=/firmadyne/console` string into `ln -s /bin/<x> /firmadyne/console`;
  the old `cp ... ${IMAGE_DIR}/firmadyne/console` then followed that link on
  the HOST and overwrote the host's /bin/<x>. Every host-side write into the
  image now resolves its directory with chroot semantics
  (scripts/imagepath.resolve_in_root), opens each directory with O_NOFOLLOW,
  removes whatever has the final name and creates a fresh file with
  O_CREAT|O_EXCL|O_NOFOLLOW; modes are set on the descriptor, the FIRMAE_ETC
  `sed -i` edits are done here on a descriptor too.
* firmadyne/init and firmadyne/service are copied out of the image only if
  they are regular files (no symlink, FIFO, device) of bounded size.
"""

import contextlib
import errno
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

if not __package__:
    # Started as a file by scripts/makeImage.sh (python3 -I .../firmae/image.py):
    # only the installation directory may provide `firmae` and `scripts`, and it
    # comes LAST so that it can never shadow the standard library (see qemu.py).
    _HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.getcwd()) not in (_HERE, os.getcwd())]
    sys.path.append(os.path.dirname(_HERE))

from firmae import config  # noqa: E402
from firmae.errors import FirmAEError  # noqa: E402
from scripts import imagepath  # noqa: E402
from scripts.procgroup import raise_on_sigterm  # noqa: E402

EXIT_FAILURE = 1
EXIT_NOT_EXECUTABLE = 126
EXIT_NOT_FOUND = 127

FDISK = "/sbin/fdisk"
FDISK_INPUT = b"o\nn\np\n1\n\n\nw\n"     # echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk
IMAGE_SIZE = "1G"

# results inferFile.sh writes with `echo` (a list of paths / one command line)
MAX_RESULT_BYTES = 1 << 20
MAX_SCRIPT_BYTES = 16 << 20       # preInit.sh & co. before the FIRMAE_ETC edits

# seconds; the stage as a whole is limited by pipeline.IMAGE_TIMEOUT
T_SHORT = 120          # qemu-img, fdisk, chown, umount, secure_workdir, get_binary
T_PARTITION = 120      # add_partition waits up to PARTITION_TIMEOUT (30 s) + udev settle
T_MOUNT = 60           # mount_partition: 5 tries
T_MKFS = 600
T_TAR = 1800
T_CHROOT = 1800        # inferFile.sh / fixImage.sh run find/grep over the whole image
T_SYNC = 600
T_FSCK = 1200
STOP_GRACE = 5         # SIGTERM -> SIGKILL for a child's process group
GUARD_REAP = 1         # waiting for the killed guard of a command (see _Group)

# Cleanup (Held.release) runs inside the pipeline's grace period: on a stage
# timeout, Ctrl-C or SIGTERM, pipeline.run_with_timeout signals our process
# group and SIGKILLs it pipeline.STAGE_GRACE (60) seconds later. Worst case
# from that signal to our exit:
#   stopping the interrupted command  run_overhead(STOP_GRACE) = 2*5 + 1 = 11
#   + all of Held.release()           CLEANUP_BUDGET                    = 36
#   = 47 s < 60 s (test_cleanup_fits_in_the_pipeline_grace).
# Every cleanup command gets min(its cap, time left - its own stop overhead)
# and is skipped when nothing is left, so release() never exceeds the budget.
CLEANUP_BUDGET = 36
CLEANUP_STOP_GRACE = 2  # SIGTERM -> SIGKILL for a cleanup command
T_CLEANUP_UMOUNT = 10   # umount while cleaning up
T_CLEANUP_LAZY = 5      # umount -l (does not wait for the file system)
T_CLEANUP = 60          # cap of del_partition while cleaning up (normally ~1 s)


_clock = time.monotonic


def run_overhead(grace):
    """Longest time run() can take beyond its timeout: SIGTERM wait, SIGKILL
    wait (both `grace`), reaping the guard."""
    return 2 * grace + GUARD_REAP

# what the old script's `(! ${FIRMAE_ETC})` did to the guest scripts (sed -i, in order)
_SLEEP_60 = (b"sleep 60", b"sleep 15")
_SLEEP_120 = (b"sleep 120", b"sleep 30")
_FIRMADYNE_SH = (b"/firmadyne/sh", b"/bin/sh")
_BUSYBOX_VAR = (b"BUSYBOX=/firmadyne/busybox", b"BUSYBOX=")
ETC_OFF_EDITS = (
    ("preInit.sh", (_FIRMADYNE_SH, _BUSYBOX_VAR)),
    ("network.sh", (_SLEEP_60, _FIRMADYNE_SH, _BUSYBOX_VAR)),
    ("run_service.sh", (_SLEEP_120, _FIRMADYNE_SH, _BUSYBOX_VAR)),
)
GUEST_SCRIPTS = ("preInit.sh", "network.sh", "run_service.sh")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class ImageError(Exception):
    def __init__(self, message, code=EXIT_FAILURE):
        super().__init__(message)
        self.code = code


def say(msg):
    print(msg, flush=True)


def _exit_code(rc):
    """What `set -e` made the old script exit with when a command failed."""
    if rc < 0:
        return 128 - rc             # killed by a signal, as bash reports it
    return rc if 0 < rc < 256 else EXIT_FAILURE


def current_umask():
    mask = os.umask(0)
    os.umask(mask)
    return mask


# ---------------------------------------------------------------- child processes

def _signal_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _stop(proc, pgid, grace):
    """SIGTERM the command's process group, SIGKILL it `grace` seconds later.
    Waits a bounded time only: a process stuck in D state (seen with fdisk)
    must not keep us from unmounting."""
    _signal_group(pgid, signal.SIGTERM)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    _signal_group(pgid, signal.SIGKILL)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass


PR_SET_PDEATHSIG = 1        # <linux/prctl.h>


def _load_prctl():
    """libc's prctl, looked up before any fork (nothing is loaded in the child)."""
    try:
        import ctypes
        return ctypes.CDLL(None, use_errno=True).prctl
    except (ImportError, OSError, AttributeError):
        return None


_PRCTL = _load_prctl()

# The guard: leader of the command's process group, ignores SIGINT/SIGTERM/
# SIGHUP and reads a pipe only image.py can write to. The read ends with EOF
# when image.py is gone -- however it died, SIGKILL included -- and the guard
# then SIGKILLs its whole group.
GUARD = ["/bin/sh", "-c", "trap '' INT TERM HUP; while read -r _; do :; done; kill -s KILL 0"]


class _Group:
    """The process group of one command: no process of it can outlive image.py.

    The children used to run with start_new_session=True: shielded from the
    group signals of the pipeline (pipeline.run_with_timeout SIGINTs, later
    SIGKILLs the group of makeImage.sh), so that a cleanup umount is not cut
    short -- but a SIGKILL of image.py then left tar or the chroot'ed scripts
    running against the mounted image. Now each command is a member of a
    process group (same session) led by a guard process; the pipeline's group
    signals still do not reach it, but
      * the guard SIGKILLs the group as soon as image.py has exited (EOF on its
        pipe), which covers the grandchildren (find/grep of inferFile.sh, ...);
      * the command itself also has PR_SET_PDEATHSIG(SIGKILL);
      * close() SIGKILLs the group after every command, normal exit included."""

    def __init__(self):
        rfd, self._wfd = os.pipe()          # both non-inheritable
        try:
            self.guard = subprocess.Popen(GUARD, stdin=rfd, stdout=subprocess.DEVNULL,
                                          close_fds=True, preexec_fn=self._guard_setup)
        except BaseException:
            os.close(self._wfd)
            raise
        finally:
            os.close(rfd)
        self.pgid = self.guard.pid
        self._parent = os.getpid()

    @staticmethod
    def _guard_setup():
        os.setpgid(0, 0)

    def preexec(self):
        """In the command's child process, before exec."""
        os.setpgid(0, self.pgid)
        if _PRCTL is not None:
            _PRCTL(PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0)
        if os.getppid() != self._parent:    # image.py died before the prctl
            os._exit(EXIT_FAILURE)

    def close(self):
        _signal_group(self.pgid, signal.SIGKILL)   # nothing it started may outlive it
        os.close(self._wfd)
        try:
            self.guard.wait(timeout=GUARD_REAP)
        except subprocess.TimeoutExpired:
            pass


def run(argv, timeout, stdin=None, env=None, cwd=None, capture=False, grace=None):
    """Run argv (a list; no shell) in a guarded process group (_Group). Returns
    (returncode, stdout bytes or None). On a timeout, or on any exception while
    waiting (Ctrl-C, SystemExit from SIGTERM/SIGHUP), the whole group is
    stopped first (SIGTERM, SIGKILL `grace` seconds later, default STOP_GRACE);
    in any case the group is SIGKILLed before returning. At most
    timeout + run_overhead(grace) seconds. stdout/stderr go to ours
    (makeImage.log) unless captured; stdin is /dev/null unless given."""
    grace = STOP_GRACE if grace is None else grace
    sys.stdout.flush()
    sys.stderr.flush()
    name = os.path.basename(argv[0])
    group = _Group()
    try:
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL if stdin is None else stdin,
                                    stdout=subprocess.PIPE if capture else None,
                                    env=env, cwd=cwd, preexec_fn=group.preexec)
        except FileNotFoundError:
            raise ImageError("%s: command not found" % argv[0], EXIT_NOT_FOUND)
        except PermissionError:
            raise ImageError("%s: Permission denied" % argv[0], EXIT_NOT_EXECUTABLE)
        except subprocess.SubprocessError as e:
            raise ImageError("Error: cannot start %s: %s" % (name, e))
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _stop(proc, group.pgid, grace)
            raise ImageError("Error: %s timed out after %ds" % (name, timeout))
        except BaseException:
            _stop(proc, group.pgid, grace)
            raise
        return proc.returncode, out
    finally:
        group.close()


def check(argv, timeout, **kw):
    rc, out = run(argv, timeout, **kw)
    if rc != 0:
        raise ImageError("Error: %s failed with exit %d" % (os.path.basename(argv[0]), rc), _exit_code(rc))
    return out


def bash_fn(root, name, *args, timeout, capture=False):
    """Call a function of firmae.config (as pipeline._bash_fn / makeNetwork do)."""
    return run(["bash", "-c", 'source ./firmae.config && "$@"', "_", name] + [str(a) for a in args],
               timeout, cwd=root, capture=capture)


def sync():
    check(["sync"], T_SYNC)


def binaries(root, arch):
    """[(name, host path)] of BINARIES for arch, from firmae.config's get_binary
    (which also rejects an invalid architecture)."""
    script = ('source ./firmae.config && for b in "${BINARIES[@]}"; do '
              'p=$(get_binary "$b" "$1") || { printf "%s\\n" "$p"; exit 1; }; '
              'printf "%s\\0%s\\0" "$b" "$p"; done')
    rc, out = run(["bash", "-c", script, "_", arch], T_SHORT, cwd=root, capture=True)
    text = out.decode(errors="replace")
    if rc != 0:
        raise ImageError(text.strip() or "Error: get_binary failed (exit %d)" % rc, EXIT_FAILURE)
    items = text.split("\0")[:-1]
    if not items or len(items) % 2:
        raise ImageError("Error: cannot read BINARIES from firmae.config")
    return list(zip(items[0::2], items[1::2]))


# ---------------------------------------------------------------- loop device / mount

LOOP_PARTITION_RE = re.compile(r"/dev/loop[0-9]+p1\Z")


def is_mounted(path):
    return os.path.ismount(path)


class Held:
    """Mount and loop devices this run holds; release() frees what is left, in
    reverse order (unmount first, then the loop devices, newest first)."""

    def __init__(self, root):
        self.root = root
        self.loops = []
        self.mountpoint = None

    def add_partition(self, image):
        rc, out = bash_fn(self.root, "add_partition", image, timeout=T_PARTITION, capture=True)
        device = out.decode(errors="replace").strip()
        if rc != 0:
            raise ImageError("Error: add_partition failed (exit %d)" % rc, _exit_code(rc))
        if not LOOP_PARTITION_RE.match(device):
            raise ImageError("Error: add_partition printed %r, not a loop partition" % device[:200])
        self.loops.append(device[:-2])          # ${DEVICE:0:$((${#DEVICE}-2))}
        return device

    def del_partition(self, loop, timeout=T_CLEANUP, grace=None):
        run(["bash", "-c", 'source ./firmae.config && "$@"', "_", "del_partition", loop],
            timeout, cwd=self.root, grace=grace)                     # always returns 0
        if loop in self.loops:
            self.loops.remove(loop)

    def mount(self, device, mountpoint):
        # registered before the attempt: an interrupted mount_partition may
        # still have mounted it
        self.mountpoint = mountpoint
        rc, _ = bash_fn(self.root, "mount_partition", device, mountpoint, timeout=T_MOUNT)
        if rc != 0:
            raise ImageError("Error: mount_partition failed (exit %d)" % rc, _exit_code(rc))

    def umount(self):
        """The normal-path unmount: a failure is an error, as with `set -e`."""
        check(["umount", self.mountpoint], T_SHORT)
        self.mountpoint = None

    def release(self):
        """Best effort, never raises an error of its own, and takes at most
        CLEANUP_BUDGET seconds (see there). Signals that arrive meanwhile are
        held back until the end so that they cannot cut the cleanup short (the
        commands run in guarded groups of their own and are not hit by the
        caller's group signal anyway)."""
        pending = []
        deadline = _clock() + CLEANUP_BUDGET

        def defer(signum, frame):
            pending.append(signum)

        def cleanup(what, cap, call):
            """call(timeout) with what is left of the budget; False if skipped."""
            timeout = min(cap, int(deadline - _clock()) - run_overhead(CLEANUP_STOP_GRACE))
            if timeout < 1:
                say("Error: no time left to %s (cleanup budget %ds)" % (what, CLEANUP_BUDGET))
                return False
            call(timeout)
            return True
        old = {}
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old[s] = signal.signal(s, defer)
        try:
            if self.mountpoint is not None:
                if is_mounted(self.mountpoint):
                    say("----Cleaning up: unmounting %s----" % self.mountpoint)
                    mnt, result = self.mountpoint, []
                    for argv, cap in ((["umount", mnt], T_CLEANUP_UMOUNT),
                                      (["umount", "-l", mnt], T_CLEANUP_LAZY)):
                        try:
                            if not cleanup("unmount %s" % mnt, cap,
                                           lambda t: result.append(run(argv, t, grace=CLEANUP_STOP_GRACE)[0])):
                                break
                        except ImageError as e:
                            say(str(e))
                        if result and result[-1] == 0:
                            break
                self.mountpoint = None
            for loop in reversed(list(self.loops)):
                say("----Cleaning up: releasing %s----" % loop)
                try:
                    if not cleanup("release %s" % loop, T_CLEANUP,
                                   lambda t: self.del_partition(loop, t, CLEANUP_STOP_GRACE)):
                        self.loops.remove(loop)
                except ImageError as e:
                    say(str(e))
                    self.loops.remove(loop)
        finally:
            for s, h in old.items():
                signal.signal(s, h)
        if pending and sys.exc_info()[0] is None:
            # nothing else is propagating: act on the signal now
            if pending[0] == signal.SIGINT:
                raise KeyboardInterrupt
            raise SystemExit(128 + pending[0])


# ---------------------------------------------------------------- writing into the image

def open_dir(root, path):
    """Descriptor of directory `path` of the image mounted at `root`, resolved
    the way chroot would (absolute symlinks re-rooted, `..` clamped), each
    component then opened with O_NOFOLLOW. Raises ImageError if it is not a
    directory (or a symlink loop)."""
    root = os.path.realpath(root)
    try:
        target = imagepath.resolve_in_root(root, path)
    except imagepath.SymlinkLoop as e:
        raise ImageError("Error: %s" % e)
    rel = os.path.relpath(target, root)
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):    # cannot happen; belt and braces
        raise ImageError("Error: %s escapes the image" % path)
    fd = os.open(root, _DIR_FLAGS)
    try:
        if rel != os.curdir:
            for comp in rel.split(os.sep):
                nfd = os.open(comp, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = nfd
    except OSError as e:
        os.close(fd)
        if e.errno in (errno.ENOTDIR, errno.ELOOP, errno.ENOENT):
            raise ImageError("Error: %s of the image is not a directory" % path)
        raise
    return fd


@contextlib.contextmanager
def image_dir(root, path):
    fd = open_dir(root, path)
    try:
        yield fd
    finally:
        os.close(fd)           # no descriptor may stay open: umount would fail (EBUSY)


def remove_entry(dir_fd, name, shown):
    """Remove whatever has this name (file, symlink, FIFO, device); a
    directory is an error (as `rm -f` of it was)."""
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    except IsADirectoryError:
        raise ImageError("Error: %s in the image is a directory; refusing to replace it" % shown)
    except PermissionError as e:
        if e.errno == errno.EISDIR:
            raise ImageError("Error: %s in the image is a directory; refusing to replace it" % shown)
        raise


def create_file(dir_fd, name, shown, src=None, data=b"", mode=0o644):
    """A fresh regular file `name` in dir_fd with the contents of host file
    `src` (or `data`) and exactly `mode`. Whatever had that name is removed
    first; nothing is ever written through a symlink."""
    remove_entry(dir_fd, name, shown)
    fd = os.open(name, _NEW_FILE, 0o600, dir_fd=dir_fd)
    with os.fdopen(fd, "wb") as out:
        if src is not None:
            with open(src, "rb") as inp:
                shutil.copyfileobj(inp, out)
        else:
            out.write(data)
        out.flush()
        os.fchmod(out.fileno(), mode)


def cp_mode(src, umask):
    """Mode `cp` gives a new copy: the source's permission bits minus umask
    (no set-id bits without -p)."""
    return stat.S_IMODE(os.stat(src).st_mode) & 0o777 & ~umask


def install(dir_fd, name, src, umask, shown, executable=False):
    """cp src <dir>/name [&& chmod a+x <dir>/name]"""
    mode = cp_mode(src, umask) | (0o111 if executable else 0)
    create_file(dir_fd, name, shown, src=src, mode=mode)


def make_char_device(dir_fd, name, mode, major, minor):
    """mknod -m <mode> <dir>/name c major minor (mode exact, as -m sets it).
    mknod(2) never follows a symlink in the last component; the old entry is
    removed first."""
    remove_entry(dir_fd, name, name)
    old = os.umask(0)
    try:
        os.mknod(name, stat.S_IFCHR | mode, os.makedev(major, minor), dir_fd=dir_fd)
    finally:
        os.umask(old)


def edit_file(dir_fd, name, edits, shown):
    """sed -i 's/<a>/<b>/g' for each (a, b) in order, on a descriptor opened
    without following symlinks. The patterns are plain text without newlines,
    so a global bytes replace equals sed's per-line one."""
    try:
        fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError as e:
        raise ImageError("Error: cannot open %s: %s" % (shown, e.strerror))
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ImageError("Error: %s is not a regular file" % shown)
    with os.fdopen(fd, "r+b") as f:
        data = f.read(MAX_SCRIPT_BYTES + 1)
        if len(data) > MAX_SCRIPT_BYTES:
            raise ImageError("Error: %s is larger than %d bytes" % (shown, MAX_SCRIPT_BYTES))
        new = data
        for a, b in edits:
            new = new.replace(a, b)
        if new != data:
            f.seek(0)
            f.write(new)
            f.truncate()


def put_top(root, src, name):
    """put_top of the old script: <image>/name replaces whatever the image has
    under that name (removed again after use)."""
    if not src:
        raise ImageError("Error: %s not found" % name)
    with image_dir(root, "/") as fd:
        install(fd, name, src, current_umask(), "/" + name)


def remove_top(root, name, missing_ok=False):
    with image_dir(root, "/") as fd:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            if not missing_ok:
                raise ImageError("rm: cannot remove '/%s': No such file or directory" % name)


def make_firmadyne_dirs(root):
    """mkdir (not -p): fails if the firmware already has /firmadyne (or one of
    its subdirectories), as before -- even when it is a symlink."""
    fd = os.open(os.path.realpath(root), _DIR_FLAGS)
    try:
        for rel in ("firmadyne", "firmadyne/libnvram", "firmadyne/libnvram.override"):
            parent, _, name = rel.rpartition("/")
            pfd = os.open(parent, _DIR_FLAGS, dir_fd=fd) if parent else fd
            try:
                os.mkdir(name, 0o777, dir_fd=pfd)
            except FileExistsError:
                raise ImageError("mkdir: cannot create directory '%s/%s/': File exists"
                                 % (root.rstrip("/"), rel))
            finally:
                if pfd != fd:
                    os.close(pfd)
    finally:
        os.close(fd)


def _write_result(work_dir, name, data):
    """scratch/<IID>/<name>, replaced atomically (never written through a link)."""
    fd, tmp = tempfile.mkstemp(dir=work_dir, prefix=".%s." % name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), 0o644)
        os.replace(tmp, os.path.join(work_dir, name))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def take_result(root, name, work_dir, move):
    """Copy /firmadyne/<name> out of the image to work_dir if it is a regular
    file of at most MAX_RESULT_BYTES; move=True also removes it from the image
    (the old `mv`) and makes anything else an error, move=False (the old
    `[ -f ] && [ ! -L ] && cp`) skips it. Returns True if copied."""
    shown = "/firmadyne/" + name

    def refuse(why):
        if move:
            raise ImageError("Error: %s of the image %s; refusing to copy it" % (shown, why))
        say("%s of the image %s; not copied" % (shown, why))
        return False

    with image_dir(root, "/firmadyne") as dfd:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
        except FileNotFoundError:
            if move:
                raise ImageError("mv: cannot stat '%s': No such file or directory" % shown)
            return False
        except OSError as e:
            return refuse("is a symlink" if e.errno == errno.ELOOP else "cannot be opened (%s)" % e.strerror)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return refuse("is not a regular file")
        with os.fdopen(fd, "rb") as f:
            data = f.read(MAX_RESULT_BYTES + 1)
        if len(data) > MAX_RESULT_BYTES:
            raise ImageError("Error: %s of the image is larger than %d bytes" % (shown, MAX_RESULT_BYTES))
        _write_result(work_dir, name, data)
        if move:
            os.unlink(name, dir_fd=dfd)
    return True


def install_injection_checker(root, src):
    """/bin/a (resolved with chroot semantics; the firmware may have planted a
    FIFO, device or symlink there): a fresh executable copy of src."""
    umask = current_umask()
    with image_dir(root, "/bin") as fd:
        install(fd, "a", src, umask, "/bin/a", executable=True)


def setup_firmadyne(root, binaries_list, script_dir, firmae_etc):
    """The "Setting up FIRMADYNE" block of the old script, step by step."""
    umask = current_umask()
    with image_dir(root, "/firmadyne") as fd:
        for name, path in binaries_list:
            install(fd, name, path, umask, "/firmadyne/" + name, executable=True)
        make_char_device(fd, "ttyS1", 0o666, 4, 65)
        for name in GUEST_SCRIPTS:
            install(fd, name, os.path.join(script_dir, name), umask, "/firmadyne/" + name, executable=True)
    install_injection_checker(root, os.path.join(script_dir, "injectionChecker.sh"))
    with image_dir(root, "/firmadyne") as fd:
        # touch + chmod a+x
        create_file(fd, "debug.sh", "/firmadyne/debug.sh", mode=(0o666 & ~umask) | 0o111)
        if not firmae_etc:
            for name, edits in ETC_OFF_EDITS:
                edit_file(fd, name, edits, "/firmadyne/" + name)


# ---------------------------------------------------------------- the flow

def as_bool(name, value):
    """firmae.config switches are run as commands: `(${FIRMAE_ETC})`."""
    if value not in ("true", "false"):
        raise ImageError("Error: %s must be 'true' or 'false', not %r" % (name, value))
    return value == "true"


def chroot_env(cfg):
    env = dict(os.environ)
    env.update(FIRMAE_BOOT=cfg.FIRMAE_BOOT, FIRMAE_ETC=cfg.FIRMAE_ETC)
    return env


def build(cfg, iid, arch, root):
    """Everything makeImage.sh did after its argument and root checks."""
    firmae_etc = as_bool("FIRMAE_ETC", cfg.FIRMAE_ETC)
    as_bool("FIRMAE_BOOT", cfg.FIRMAE_BOOT)
    say("----Running----")
    work_dir = "%s/%s" % (cfg.SCRATCH_DIR, iid)             # get_scratch
    image = work_dir + "/image.raw"                         # get_fs
    mountpoint = work_dir + "/image/"                       # get_fs_mount
    script_dir = cfg.SCRIPT_DIR
    # get_binary ran only at "Setting up FIRMADYNE"; an invalid architecture
    # now fails before anything is built (same exit 1, same message)
    bins = binaries(root, arch)

    say("----Copying Filesystem Tarball----")
    os.makedirs(work_dir, exist_ok=True)
    rc, _ = bash_fn(root, "secure_workdir", work_dir, timeout=T_SHORT)
    if rc != 0:
        raise ImageError("Error: secure_workdir failed (exit %d)" % rc, _exit_code(rc))
    tarball = "%s/%s.tar.gz" % (work_dir, iid)
    if not os.path.exists(tarball):
        src = "%s/%s.tar.gz" % (cfg.TARBALL_DIR, iid)
        if not os.path.exists(src):
            raise ImageError("Error: Cannot find tarball of root filesystem for %s!" % iid)
        shutil.copyfile(src, tarball)

    say("----Creating QEMU Image----")
    check(["qemu-img", "create", "-f", "raw", image, IMAGE_SIZE], T_SHORT)
    os.chmod(image, 0o644)

    say("----Creating Partition Table----")
    with tempfile.TemporaryFile() as script:
        script.write(FDISK_INPUT)
        script.seek(0)
        check([FDISK, image], T_SHORT, stdin=script)

    held = Held(root)
    try:
        say("----Mounting QEMU Image----")
        say("Image: %s" % image)
        device = held.add_partition(image)
        loop = device[:-2]
        say("Device: %s" % loop)

        say("----Creating Filesystem----")
        sync()
        check(["mkfs.ext2", device], T_MKFS)

        say("----Making QEMU Image Mountpoint----")
        if not os.path.exists(mountpoint):
            os.mkdir(mountpoint)
            user = os.environ.get("USER")
            if user is None:
                raise ImageError("makeImage.sh: USER: unbound variable")
            check(["chown", user, mountpoint], T_SHORT)

        say("----Mounting QEMU Image Partition----")
        sync()
        held.mount(device, mountpoint)

        say("----Extracting Filesystem Tarball----")
        check(["tar", "-xf", tarball, "-C", mountpoint], T_TAR)
        os.remove(tarball)

        say("----Creating FIRMADYNE Directories----")
        make_firmadyne_dirs(mountpoint)

        put_top(mountpoint, shutil.which("busybox"), "busybox")
        put_top(mountpoint, shutil.which("bash-static"), "bash-static")
        say("----Finding Init (chroot)----")
        if os.path.exists(work_dir + "/kernelInit"):
            put_top(mountpoint, work_dir + "/kernelInit", "kernelInit")
        put_top(mountpoint, os.path.join(script_dir, "inferFile.sh"), "inferFile.sh")
        check(["chroot", mountpoint, "/bash-static", "/inferFile.sh"], T_CHROOT, env=chroot_env(cfg))
        remove_top(mountpoint, "bash-static")
        remove_top(mountpoint, "inferFile.sh")
        remove_top(mountpoint, "kernelInit", missing_ok=True)

        take_result(mountpoint, "init", work_dir, move=True)
        take_result(mountpoint, "service", work_dir, move=False)

        say("----Patching Filesystem (chroot)----")
        put_top(mountpoint, os.path.join(script_dir, "fixImage.sh"), "fixImage.sh")
        check(["chroot", mountpoint, "/busybox", "ash", "/fixImage.sh"], T_CHROOT, env=chroot_env(cfg))
        remove_top(mountpoint, "fixImage.sh")
        remove_top(mountpoint, "busybox")

        say("----Setting up FIRMADYNE----")
        setup_firmadyne(mountpoint, bins, script_dir, firmae_etc)

        say("----Unmounting QEMU Image----")
        sync()
        held.umount()
        held.del_partition(loop)

        device = held.add_partition(image)
        rc, _ = run(["e2fsck", "-y", device], T_FSCK)
        if rc != 0:
            # 1 = errors were corrected; still a failure, as with `set -e` before
            say("e2fsck -y %s exited with %d" % (device, rc))
            raise ImageError("Error: e2fsck failed with exit %d" % rc, _exit_code(rc))
        sync()
        time.sleep(1)
        held.del_partition(device[:-2])
    finally:
        held.release()


def package_root():
    """The installation: parent of the firmae/ package that is running."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


USAGE = "Usage: makeImage.sh <image ID> [<architecture>]"


def main(argv=None, root=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or re.fullmatch(r"[0-9]+", argv[0]) is None:
        say(USAGE)
        return EXIT_FAILURE
    if os.geteuid() != 0:
        say("Error: This script requires root privileges!")
        return EXIT_FAILURE
    if len(argv) < 2:
        say("Error: missing <architecture>")
        say(USAGE)
        return EXIT_FAILURE
    iid, arch = argv[0], argv[1]          # argv[2] (file name) was never used
    raise_on_sigterm()                    # SIGTERM/SIGHUP -> SystemExit: cleanup runs
    root = root or package_root()
    try:
        try:
            cfg = config.load(root)
        except FirmAEError as e:
            raise ImageError("Error: %s" % e.message)
        build(cfg, iid, arch, root)
    except ImageError as e:
        say(str(e))
        return e.code
    except OSError as e:
        # e.g. a directory where a helper file is to be removed; already cleaned up
        say("Error: %s" % e)
        return EXIT_FAILURE
    except KeyboardInterrupt:
        say("Interrupted")
        return 128 + signal.SIGINT
    return 0


if __name__ == "__main__":
    sys.exit(main())
