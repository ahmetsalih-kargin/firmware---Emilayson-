"""Execute the run.sh that makeNetwork.py generates, with every system command
stubbed, and check that it cleans up on every exit path (REFACTORING_PLAN 3.2):
normal end, SIGTERM, Ctrl-C (SIGINT to the process group), START_NET failure,
image preparation failure. No root, no real QEMU, mount or TAP.
"""

import os
import shutil
import signal
import subprocess
import time

import pytest

from scripts import makeNetwork as mn

pytestmark = pytest.mark.linux

FAKE_QEMU = """#!/bin/bash
echo "qemu start $$" >> "$LOG"
trap 'echo "qemu got TERM" >> "$LOG"; exit 0' TERM
if [ -n "${QEMU_EXIT_AFTER:-}" ]; then sleep "$QEMU_EXIT_AFTER"; echo "qemu exit" >> "$LOG"; exit 0; fi
while true; do sleep 0.1; done
"""


@pytest.fixture
def world(repo_root, tmp_path, firmae_env):
    root = tmp_path / "FirmAE"
    (root / "scratch" / "1" / "image" / "firmadyne").mkdir(parents=True)
    log = tmp_path / "log"
    # firmae.config as shipped, plus stand-ins for the two helpers that need root
    text = (repo_root / "firmae.config").read_text()
    text += ('\nadd_partition () { [ -n "${FAIL_PARTITION:-}" ] && return 1; echo /dev/fakeloop0p1; }\n'
             'del_partition () { echo "del_partition $1" >> "$LOG"; }\n')
    (root / "firmae.config").write_text(text)

    bindir = tmp_path / "bin"
    bindir.mkdir()

    def stub(name, body):
        (bindir / name).write_text("#!/bin/bash\n" + body + "\n")
        (bindir / name).chmod(0o755)
    rec = 'echo "$(basename $0) $*" >> "$LOG"'
    stub("sudo", 'exec "$@"')
    stub("mount", rec + '; [ -z "${FAIL_MOUNT:-}" ]')
    stub("umount", rec)
    stub("mountpoint", "exit 1")
    stub("tunctl", rec + '; ! { [ -n "${FAIL_TUNCTL:-}" ] && [ "$1" = -t ]; }')
    stub("ip", rec)
    stub("qemu-system-mipsel", FAKE_QEMU)

    script = mn.qemuCmd(1, [("192.168.0.1", "eth0", None, None, "br0")], [], "normal",
                        "mips", "el", "rdinit=/firmadyne/preInit.sh", False)
    run_sh = root / "scratch" / "1" / "run.sh"
    run_sh.write_text(script)
    run_sh.chmod(0o755)

    env = dict(os.environ, LOG=str(log), PATH="%s:%s" % (bindir, os.environ["PATH"]),
               USER=os.environ.get("USER", "root"))
    env.pop("FIRMAE_DOCKER", None)

    def start(**extra):
        return subprocess.Popen([str(run_sh)], cwd=root, env=dict(env, **extra),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, start_new_session=True)

    def calls():
        return log.read_text().splitlines() if log.exists() else []
    return start, calls


def wait_for(calls, text, timeout=15):
    for _ in range(int(timeout / 0.1)):
        if any(text in c for c in calls()):
            return
        time.sleep(0.1)
    raise AssertionError("never saw %r in %r" % (text, calls()))


def qemu_pid(calls):
    return int(next(c for c in calls() if c.startswith("qemu start")).split()[-1])


def gone(pid):
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        return True


def test_normal_end_tears_the_network_down_once(world):
    start, calls = world
    p = start(QEMU_EXIT_AFTER="1")
    out, _ = p.communicate(timeout=60)
    assert p.returncode == 0, out
    c = calls()
    assert "tunctl -t tap1_0 -u %s" % os.environ.get("USER", "root") in c
    assert c[-2:] == ["ip link set tap1_0 down", "tunctl -d tap1_0"]
    assert c.count("tunctl -d tap1_0") == 1
    assert c.count("del_partition /dev/fakeloop0") == 1
    assert "qemu exit" in c
    assert out.rstrip().endswith("Done!")


@pytest.mark.parametrize("how,expected_rc", [("sigterm", 143), ("ctrl-c", 130)])
def test_interrupt_stops_qemu_and_cleans_up(world, how, expected_rc):
    start, calls = world
    p = start()
    wait_for(calls, "qemu start")
    q = qemu_pid(calls)
    if how == "sigterm":
        p.send_signal(signal.SIGTERM)            # only the script, like `kill <pid>`
    else:
        os.killpg(p.pid, signal.SIGINT)          # the whole foreground group, like Ctrl-C
    out, _ = p.communicate(timeout=30)
    assert p.returncode == expected_rc, out
    c = calls()
    assert "qemu got TERM" in c
    assert c[-2:] == ["ip link set tap1_0 down", "tunctl -d tap1_0"]
    for _ in range(50):
        if gone(q):
            break
        time.sleep(0.1)
    assert gone(q)


def test_start_net_failure_still_removes_what_was_created(world):
    start, calls = world
    p = start(FAIL_TUNCTL="1")
    out, _ = p.communicate(timeout=60)
    assert p.returncode != 0
    c = calls()
    assert not any(x.startswith("qemu start") for x in c)
    assert "tunctl -d tap1_0" in c               # was skipped before: set -e exited first


def test_image_preparation_failure_releases_the_loop_device(world):
    start, calls = world
    p = start(FAIL_MOUNT="1")
    out, _ = p.communicate(timeout=60)
    assert p.returncode != 0
    c = calls()
    assert "del_partition /dev/fakeloop0" in c   # loop device was leaked before
    assert not any(x.startswith("tunctl") for x in c)
