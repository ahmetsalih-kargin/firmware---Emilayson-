"""scripts/procgroup.py: the initial emulation runs in its own process group
that is always gone when run_with_timeout() returns (REFACTORING_PLAN 3.x)."""

import os
import signal
import sys
import time

import pytest

from scripts.procgroup import run_with_timeout

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")


def alive(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
        return False   # gone, or reaped while /proc/<pid>/stat was read (empty/truncated)


def test_normal_exit_returns_status():
    assert run_with_timeout(["sh", "-c", "exit 3"], 10) == (3, False)


def test_timeout_sends_sigint_to_the_group(tmp_path):
    out = tmp_path / "got"
    t0 = time.time()
    rc, timed_out = run_with_timeout(
        ["bash", "-c", "trap 'echo INT > %s; exit 0' INT; while true; do sleep 0.1; done" % out],
        timeout=1, grace=5)
    assert timed_out and rc == 0
    assert out.read_text().strip() == "INT"
    assert time.time() - t0 < 5


def test_sigint_ignored_escalates_to_sigkill():
    t0 = time.time()
    rc, timed_out = run_with_timeout(["bash", "-c", "trap '' INT; sleep 600"], timeout=1, grace=1)
    assert timed_out and rc == -signal.SIGKILL
    assert time.time() - t0 < 10


def test_grandchildren_die_with_the_group(tmp_path):
    """QEMU is a grandchild (run.<arch>.sh -> qemu); it must not survive."""
    pidfile = tmp_path / "gc"
    run_with_timeout(["bash", "-c", "trap '' INT; sleep 600 & echo $! > %s; wait" % pidfile],
                     timeout=1, grace=1)
    gc = int(pidfile.read_text())
    for _ in range(50):
        if not alive(gc):
            break
        time.sleep(0.1)
    assert not alive(gc)


def test_interruption_stops_the_group(tmp_path):
    """Ctrl-C (KeyboardInterrupt) or SIGTERM (SystemExit via raise_on_sigterm)
    while waiting: the group is stopped before the exception propagates."""
    pidfile = tmp_path / "child"

    def interrupt(signum, frame):
        raise KeyboardInterrupt
    old = signal.signal(signal.SIGALRM, interrupt)
    signal.alarm(1)
    try:
        with pytest.raises(KeyboardInterrupt):
            run_with_timeout(["bash", "-c", "echo $$ > %s; exec sleep 600" % pidfile],
                             timeout=60, grace=2)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    assert not alive(int(pidfile.read_text()))
