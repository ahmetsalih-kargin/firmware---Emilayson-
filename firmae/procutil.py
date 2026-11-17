"""Finding and stopping the processes of one image (REFACTORING_PLAN 4.5).

Python copies of qemu_pids / stop_qemu / wait_for_exit of firmae.config and of
pid_running of scripts/hostfwd_check.sh. The Bash functions stay (run_mode.sh
and the generated run.sh use them); tests/unit/test_check_py.py runs both
copies on the same processes so they cannot drift apart.

Only /proc is read and only signals are sent; nothing here starts a process.
"""

import os
import re
import signal
import time

# keep in sync with QEMU_STOP_GRACE in firmae.config (the tests compare them)
QEMU_STOP_GRACE = 10       # seconds between SIGTERM and SIGKILL
_POLL = 0.5                # both Bash loops poll every half second

PROC = "/proc"


def _is_pid_name(name):
    """What the glob /proc/[0-9]* matches: the name starts with a digit."""
    return name[:1] in tuple("0123456789")


def read_cmdline(pid, proc=PROC):
    """argv of a process as `mapfile -d '' ARGV < /proc/<pid>/cmdline` reads it:
    split on NUL, a final NUL does not add an empty element. None when the
    file cannot be read (process gone, no permission)."""
    try:
        with open("%s/%s/cmdline" % (proc, pid), "rb") as f:
            data = f.read()
    except OSError:
        return None
    if not data:
        return []
    parts = data.split(b"\0")
    if data.endswith(b"\0"):
        parts.pop()
    return [os.fsdecode(p) for p in parts]


def _same_file(a, b):
    """`[ a -ef b ]`: both exist and are the same file (symlinks followed)."""
    try:
        sa, sb = os.stat(a), os.stat(b)
    except (OSError, ValueError):
        return False
    return (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)


def argv_is_qemu_of(argv, image, iid):
    """The matching rule of qemu_pids (firmae.config), for one argv:
    argv[0]'s basename is qemu-system-*, and one argument (its first line, as
    `IFS=, read -r -a` reads it) has a comma-separated field file=<image>
    -- the exact string, or an absolute path ending in /<IID>/image.raw that
    names the same file."""
    if argv is None or len(argv) <= 1:
        return False
    if not argv[0].rsplit("/", 1)[-1].startswith("qemu-system-"):
        return False
    suffix = "/%s/image.raw" % iid
    for arg in argv[1:]:
        if "file=" not in arg:
            continue
        for field in arg.split("\n", 1)[0].split(","):
            if not field.startswith("file="):
                continue
            path = field[len("file="):]
            if path == image:
                return True
            # Bash: [[ "$FILE" == /*"/<IID>/image.raw" ]] && [ "$FILE" -ef "$IMG" ]
            if (path.startswith("/") and len(path) >= 1 + len(suffix) and path.endswith(suffix)
                    and _same_file(path, image)):
                return True
    return False


def qemu_pids(scratch_dir, iid, proc=PROC):
    """PIDs (strings, /proc order) of the QEMU processes emulating image <iid>
    of the installation whose SCRATCH_DIR is `scratch_dir`."""
    image = "%s/%s/image.raw" % (scratch_dir, iid)
    try:
        names = sorted(n for n in os.listdir(proc) if _is_pid_name(n))
    except OSError:
        return []
    return [n for n in names if argv_is_qemu_of(read_cmdline(n, proc), image, iid)]


def pid_running(pid, proc=PROC):
    """pid_running of hostfwd_check.sh: the process exists and is not a zombie
    (state after the last ') ' of /proc/<pid>/stat is not Z or X)."""
    pid = str(pid)
    if re.fullmatch(r"[0-9]+", pid) is None:
        return False
    try:
        with open("%s/%s/stat" % (proc, pid), "rb") as f:
            stat = f.read()
    except OSError:
        return False
    stat = stat.rstrip(b"\n")
    idx = stat.rfind(b") ")
    rest = stat[idx + 2:] if idx >= 0 else stat
    return bool(rest) and rest[:1] not in (b"Z", b"X")


def _signal_all(pids, sig, kill=os.kill):
    for pid in pids:
        try:
            kill(int(pid), sig)
        except (OSError, ValueError):
            pass


def stop_qemu(scratch_dir, iid, sleep=time.sleep, grace=QEMU_STOP_GRACE, proc=PROC, kill=os.kill):
    """SIGTERM this image's QEMU, SIGKILL whatever is left after `grace` s."""
    pids = qemu_pids(scratch_dir, iid, proc)
    if not pids:
        return
    _signal_all(pids, signal.SIGTERM, kill)
    for _ in range(int(grace / _POLL)):
        if not qemu_pids(scratch_dir, iid, proc):
            return
        sleep(_POLL)
    _signal_all(qemu_pids(scratch_dir, iid, proc), signal.SIGKILL, kill)


def wait_for_exit(child, seconds, sleep=time.sleep):
    """wait_for_exit of firmae.config for a child we started (subprocess.Popen):
    wait up to `seconds`, SIGKILL it at the deadline and reap it. Polling the
    Popen (not the PID) cannot hit a reused PID. Returns its exit status."""
    if child is None:
        return None
    for _ in range(int(seconds / _POLL)):
        if child.poll() is not None:
            return child.returncode
        sleep(_POLL)
    if child.poll() is None:
        try:
            child.kill()
        except OSError:
            pass
    return child.wait()
