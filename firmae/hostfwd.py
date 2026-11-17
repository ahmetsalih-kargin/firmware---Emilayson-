"""Web check of a user-network (DHCP mode) emulation: Python copy of the parts
of scripts/hostfwd_check.sh that check_emulation needs (REFACTORING_PLAN 4.5).
hostfwd_check.sh stays for scripts/run_mode.sh; tests/unit/test_check_py.py
feeds both copies the same files so their acceptance rules cannot drift.

QEMU forwards guest ports to loopback ports that makeNetwork.py chose and
recorded in scratch/<IID>/hostfwd ("<tcp|udp> <guest port> <host port>" per
line). Those ports are not reserved: another program can hold one, so an
answer counts only while this image's QEMU runs and owns the listening socket.
"""

import os
import re
import shutil
import stat
import subprocess
import sys

from firmae import procutil

# same values as scripts/hostfwd_check.sh (and HOSTFWD_PORT_MIN/MAX of makeNetwork.py)
HOSTFWD_PORT_MIN = 10000
HOSTFWD_PORT_MAX = 19999
HOSTFWD_MAX_BYTES = 4096
HOSTFWD_MAX_LINES = 64

SS_TIMEOUT = 10            # seconds; `ss` of one port answers at once
SS_MAX_OUTPUT = 1 << 20    # bytes of `ss` output that are looked at

_LINE = re.compile(rb"(tcp|udp) ([0-9]{1,5}) ([0-9]{1,5})")
_OWNER = re.compile(r"pid=([0-9]*)")

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def read_regular_file(name, limit, dir_fd=None):
    """Up to `limit` bytes of a regular file that is not a symlink (O_NOFOLLOW,
    then fstat S_ISREG; O_NONBLOCK so that a FIFO cannot block the open).
    None if it is missing, a symlink, not a regular file or unreadable."""
    try:
        fd = os.open(name, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, left = [], limit
        while left > 0:
            data = os.read(fd, min(left, 65536))
            if not data:
                break
            chunks.append(data)
            left -= len(data)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def parse_hostfwd(content):
    """read_hostfwd of hostfwd_check.sh on the first HOSTFWD_MAX_BYTES + 1 bytes
    of the file: (http host port | None, https host port | None), or None when
    the whole file is rejected (malformed, out-of-range or duplicate line, too
    many lines, too large)."""
    # `head -c N | tr -d '\000'` inside backticks: NULs dropped, trailing newlines stripped
    content = content.replace(b"\0", b"").rstrip(b"\n")
    if len(content) > HOSTFWD_MAX_BYTES:
        return None
    http = https = None
    # `while read -r LINE ... <<< "$CONTENT"`: the here-string adds one newline,
    # so an empty file is one empty (invalid) line
    for n, line in enumerate(content.split(b"\n"), 1):
        m = _LINE.fullmatch(line)
        if n > HOSTFWD_MAX_LINES or m is None:
            return None
        proto, guest, host = m.group(1), int(m.group(2), 10), int(m.group(3), 10)
        if not 1 <= guest <= 65535 or not HOSTFWD_PORT_MIN <= host <= HOSTFWD_PORT_MAX:
            return None
        if proto != b"tcp":
            continue
        if guest == 80:
            if http is not None:
                return None
            http = host
        elif guest == 443:
            if https is not None:
                return None
            https = host
    return http, https


def read_hostfwd(name, dir_fd=None):
    """scratch/<IID>/hostfwd -> (http, https) host ports (None: not mapped), or
    None if the file is missing, a symlink, not regular or invalid."""
    content = read_regular_file(name, HOSTFWD_MAX_BYTES + 1, dir_fd=dir_fd)
    if content is None:
        return None
    return parse_hostfwd(content)


def emulation_state(scratch_dir, iid, run_alive=None):
    """hostfwd_emulation_state: "running" (this image's QEMU runs), "starting"
    (not yet, but run.sh is still there; without `run_alive` we cannot tell,
    so also "starting") or "dead" (run.sh gone and no QEMU of this image)."""
    if procutil.qemu_pids(scratch_dir, iid):
        return "running"
    if run_alive is None or run_alive():
        return "starting"
    return "dead"


def _warn(msg, err=None):
    (err or sys.stderr).write(msg + "\n")
    (err or sys.stderr).flush()


def _listeners(port, run=subprocess.run):
    """Output of `ss -Htlnp "sport = :<port>"` as text, "" when ss fails."""
    try:
        res = run(["ss", "-Htlnp", "sport = :%d" % port], stdin=subprocess.DEVNULL,
                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=SS_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return ""
    if res.returncode != 0:
        return ""
    # bash: NULs dropped, trailing newlines stripped by the command substitution
    return res.stdout[:SS_MAX_OUTPUT].replace(b"\0", b"").decode("utf-8", "replace").rstrip("\n")


def owned_by_qemu(scratch_dir, iid, port, err=None, run=subprocess.run, which=shutil.which):
    """hostfwd_owned_by_qemu: every TCP listener on <port> belongs to a QEMU of
    this image. No ss, no listener, or an owner we cannot see is "not ours"."""
    if which("ss") is None:
        _warn("[!] hostfwd: 'ss' not found; cannot tell who listens on 127.0.0.1:%d (web=false)" % port, err)
        return False
    out = _listeners(port, run)
    if not out:
        _warn("[!] hostfwd: no listener found on port %d (web=false)" % port, err)
        return False
    qemu = set(procutil.qemu_pids(scratch_dir, iid))
    for line in out.split("\n"):
        pids = [p for p in _OWNER.findall(line) if p]
        if not pids:
            _warn("[!] hostfwd: owner of port %d unknown (web=false)" % port, err)
            return False
        for pid in pids:
            if pid not in qemu:
                _warn("[!] hostfwd: port %d belongs to PID %s, not to the QEMU of image %s (web=false)"
                      % (port, pid, iid), err)
                return False
    return True
