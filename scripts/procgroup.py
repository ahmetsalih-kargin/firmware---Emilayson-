"""Run a command in its own process group and make sure the whole group is
gone when we return -- on normal exit, timeout, Ctrl-C or SIGTERM.

makeNetwork.py used to run the initial emulation as
    os.system("timeout --preserve-status --signal SIGINT T run.<arch>.sh ...")
os.system() ignores SIGINT while it waits, and `timeout` moves itself and QEMU
into a separate process group, so Ctrl-C on FirmAE never reached QEMU and a
killed FirmAE left QEMU running (measured in Phase 0, scenarios C and D).
There was also no SIGKILL fallback if the group ignored SIGINT.
"""

import os
import signal
import subprocess


def _signal_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
        return True
    except ProcessLookupError:
        return False


def stop_group(proc, first=signal.SIGINT, grace=15):
    """Send `first` to proc's process group, SIGKILL it after `grace` seconds,
    and reap proc. Every process of the group gets the signals, so QEMU dies
    together with the shell script that started it."""
    pgid = proc.pid           # start_new_session=True: pgid == pid
    _signal_group(pgid, first)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    _signal_group(pgid, signal.SIGKILL)   # also catches stragglers after proc exited
    proc.wait()


def run_with_timeout(argv, timeout, grace=15, timeout_signal=signal.SIGINT, **popen_kwargs):
    """Run argv in a new session/process group. Returns (returncode, timed_out).

    timeout: seconds; then the group gets `timeout_signal` (SIGINT, like the
    old `timeout --signal SIGINT`) and SIGKILL `grace` seconds later.
    Any exception while waiting (KeyboardInterrupt, SystemExit raised by a
    SIGTERM handler, ...) stops the group with SIGTERM before propagating.
    """
    proc = subprocess.Popen(argv, start_new_session=True, **popen_kwargs)
    try:
        try:
            return proc.wait(timeout=timeout), False
        except subprocess.TimeoutExpired:
            stop_group(proc, timeout_signal, grace)
            return proc.returncode, True
    except BaseException:
        stop_group(proc, signal.SIGTERM, grace)
        raise


def raise_on_sigterm():
    """Turn SIGTERM into SystemExit(143) so `finally`/except blocks run."""
    def _handler(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGHUP, _handler)
