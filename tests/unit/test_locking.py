"""Locks of a FirmAE run: two runs for the same firmware must not share
scratch/<IID> and images/<IID>.*. The image id is only known after
`extractor.py -nk`, which already writes images/<IID>.tar.gz, so the run first
locks scratch/.locks/<md5 of the firmware>.lock (md5: the key the database maps
to the image id) and only then runs any stage; it then also locks
scratch/<IID>/.firmae.lock. A run that cannot get a lock is skipped with
ExitCode.BUSY, runs no stage (not even the extractor) and must not release
(tear down) the other run's emulation. The locks are flocks: they disappear
with their process.

Same stub project as test_pipeline.py; no real emulation."""

import fcntl
import hashlib
import io
import os
import subprocess
import sys
import threading
import time

import pytest

from firmae import config
from firmae.errors import ExitCode
from firmae.log import Reporter
from firmae.pipeline import FIRMWARE_LOCK_DIR, LOCK_NAME, Pipeline

from test_pipeline import IID, fw, project, run  # noqa: F401  (project is a fixture)

pytestmark = pytest.mark.linux


def recording_pipeline(project, option="check"):
    """A Pipeline whose firmae.config calls (release_emulation, ...) are recorded."""
    out = io.StringIO()
    pipe = Pipeline(config.load(str(project)), option, "dlink", Reporter(out=out, color=False))
    calls = []
    real = pipe._bash_fn

    def bash_fn(name, *args):
        calls.append(name)
        return real(name, *args)
    pipe._bash_fn = bash_fn
    return pipe, out, calls


def firmware_lock(project, firmware):
    with open(firmware, "rb") as f:
        digest = hashlib.md5(f.read()).hexdigest()
    return project / "scratch" / FIRMWARE_LOCK_DIR / ("%s.lock" % digest)


def hold_locks(*paths):
    """Another process holding these locks (like a running FirmAE)."""
    for p in paths:
        p.parent.mkdir(parents=True, exist_ok=True)
    code = ("import fcntl, os, sys, time\n"
            "for path in sys.argv[1:]:\n"
            "    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)\n"
            "    fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "    os.ftruncate(fd, 0); os.write(fd, b'%d\\n' % os.getpid())\n"
            "print('locked', flush=True)\n"
            "time.sleep(600)\n")
    p = subprocess.Popen([sys.executable, "-c", code] + [str(x) for x in paths], stdout=subprocess.PIPE)
    try:
        assert p.stdout.readline().strip() == b"locked"
    finally:
        p.stdout.close()        # the handshake is over; do not leak the pipe
    return p


def extractor_calls(project):
    f = project / "extractor_calls"
    return f.read_text().splitlines() if f.exists() else []


def test_a_running_firmware_is_skipped_before_any_stage(project):
    """The other run holds what a real FirmAE run holds: both locks."""
    firmware = fw(project)
    holder = hold_locks(firmware_lock(project, firmware), project / "scratch" / IID / LOCK_NAME)
    try:
        pipe, out, calls = recording_pipeline(project)
        code = pipe.run_firmware(firmware)
        assert code == ExitCode.BUSY == 75
        text = out.getvalue()
        assert "firmware %s is being processed by another FirmAE run (pid %d)" % (firmware, holder.pid) in text
        assert "skipping this firmware" in text
        assert extractor_calls(project) == []              # not even -nk (rewrites images/<IID>.tar.gz)
        assert calls == []                                 # no secure_workdir, no release_emulation
        assert not (project / "scratch" / IID / "result").exists()
        assert not (project / "image_done").exists()
        assert pipe._fw_lock_fd is None and pipe._lock_fd is None
    finally:
        holder.kill()
        holder.wait()
    # the locks died with their holder: no stale lock, the next run proceeds
    code, _, _ = run(project)
    assert code == ExitCode.OK


def test_two_runs_racing_for_the_same_new_firmware(project):
    """Both runs start on a firmware never seen before (no image id yet). The
    first is inside `extractor.py -nk`; the second must not run the extractor."""
    firmware = fw(project)
    started, go = project / "nk_started", project / "go"
    (project / "sources/extractor/extractor.py").write_text(
        '#!/bin/bash\necho "$@" >> "$PROJECT/extractor_calls"\nmkdir -p images\n'
        'if [[ " $* " == *" -nk "* ]]; then\n'
        '  touch "%s"\n'
        '  for i in $(seq 200); do [ -e "%s" ] && break; sleep 0.05; done\n'
        '  : > images/%s.tar.gz\n'
        'fi\n' % (started, go, IID))
    first, _, calls1 = recording_pipeline(project)
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("code", first.run_firmware(firmware)))
    t.start()
    try:
        for _ in range(200):
            if started.exists():
                break
            time.sleep(0.05)
        assert started.exists()
        second, out2, calls2 = recording_pipeline(project)
        assert second.run_firmware(firmware) == ExitCode.BUSY
        assert "is being processed by another FirmAE run (pid %d)" % os.getpid() in out2.getvalue()
        assert len(extractor_calls(project)) == 1          # only the first run's -nk
        assert calls2 == []                                # nothing released, nothing secured
    finally:
        go.write_text("")
        t.join(timeout=60)
    assert result["code"] == ExitCode.OK
    assert [c.split()[5] for c in extractor_calls(project)] == ["-nk", "-nf"]
    assert calls1.count("release_emulation") == 2          # stale leftovers at start + the end


def test_two_pipelines_racing_for_the_same_image(project):
    """A slow makeImage.sh keeps the first run busy while the second starts."""
    firmware = fw(project)
    started = project / "image_started"
    (project / "scripts/makeImage.sh").write_text(
        '#!/bin/bash\ntouch "%s"\nfor i in $(seq 100); do [ -e "%s" ] && break; sleep 0.1; done\n'
        'touch "$PROJECT/image_done"\n' % (started, project / "go"))
    first, out1, calls1 = recording_pipeline(project)
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("code", first.run_firmware(firmware)))
    t.start()
    try:
        for _ in range(200):
            if started.exists():
                break
            time.sleep(0.05)
        assert started.exists()
        n = len(extractor_calls(project))
        second, out2, calls2 = recording_pipeline(project)
        assert second.run_firmware(firmware) == ExitCode.BUSY
        assert calls2 == []
        assert len(extractor_calls(project)) == n
    finally:
        (project / "go").write_text("")
        t.join(timeout=60)
    assert result["code"] == ExitCode.OK
    assert calls1.count("release_emulation") == 2          # the owner still cleans up


def test_the_image_lock_alone_still_makes_a_run_busy(project):
    """scratch/<IID>/.firmae.lock is kept for anything else that locks the
    image. (A FirmAE run of this IID holds the firmware lock as well -- same
    md5 -- so then the run stops earlier, see above; here only the image lock
    is held and the run gets as far as the image id.)"""
    holder = hold_locks(project / "scratch" / IID / LOCK_NAME)
    try:
        pipe, out, calls = recording_pipeline(project)
        assert pipe.run_firmware(fw(project)) == ExitCode.BUSY
        assert "image %s is being processed by another FirmAE run (pid %d)" % (IID, holder.pid) in out.getvalue()
        assert "release_emulation" not in calls            # the other holder's resources stay
        assert [c.split()[5] for c in extractor_calls(project)] == ["-nk"]
    finally:
        holder.kill()
        holder.wait()


def test_the_locks_are_released_after_each_firmware(project):
    firmware = fw(project)
    pipe, _, calls = recording_pipeline(project)
    assert pipe.run_firmware(firmware) == ExitCode.OK
    # release_emulation once right after locking (a SIGKILLed run's leftovers), once at the end
    assert calls == ["secure_workdir", "release_emulation", "release_emulation"]
    assert pipe._lock_fd is None and pipe._fw_lock_fd is None
    for path in (project / "scratch" / IID / LOCK_NAME, firmware_lock(project, firmware)):
        fd = os.open(str(path), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # nobody holds it any more
        finally:
            os.close(fd)


def test_the_lock_is_released_after_a_failure(project, monkeypatch):
    monkeypatch.setenv("STUB_IMAGE_RC", "3")
    pipe, _, calls = recording_pipeline(project)
    assert pipe.run_firmware(fw(project)) == ExitCode.IMAGE
    assert "release_emulation" in calls and pipe._lock_fd is None and pipe._fw_lock_fd is None
    monkeypatch.delenv("STUB_IMAGE_RC")
    assert pipe.run_firmware(fw(project)) == ExitCode.OK


def test_the_firmware_lock_is_released_when_the_extractor_fails(project, monkeypatch):
    monkeypatch.setenv("STUB_EXTRACT_RC", "5")
    pipe, _, calls = recording_pipeline(project)
    assert pipe.run_firmware(fw(project)) == ExitCode.EXTRACTION
    assert pipe._fw_lock_fd is None and calls == []      # no image id: nothing to release
    monkeypatch.delenv("STUB_EXTRACT_RC")
    assert pipe.run_firmware(fw(project)) == ExitCode.OK


def test_the_lock_fds_are_not_inherited_by_stages(project):
    """A stage (or a QEMU it leaves behind) must not keep a lock alive."""
    (project / "scripts/makeImage.sh").write_text(
        '#!/bin/bash\nls -l /proc/$$/fd > "$PROJECT/stage_fds"\n')
    code, _, _ = run(project)
    assert code == ExitCode.OK
    fds = (project / "stage_fds").read_text()
    assert LOCK_NAME not in fds and ".lock" not in fds


def test_a_symlinked_lock_file_is_not_followed(project, tmp_path):
    work = project / "scratch" / IID
    work.mkdir(parents=True)
    target = tmp_path / "elsewhere"
    os.symlink(str(target), work / LOCK_NAME)
    pipe, out, calls = recording_pipeline(project)
    assert pipe.run_firmware(fw(project)) == ExitCode.INTERNAL
    assert "cannot open lock file" in out.getvalue()
    assert not target.exists() and "release_emulation" not in calls


def test_a_symlinked_lock_directory_is_not_followed(project, tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (project / "scratch").mkdir()
    os.symlink(str(target), project / "scratch" / FIRMWARE_LOCK_DIR)
    pipe, out, calls = recording_pipeline(project)
    assert pipe.run_firmware(fw(project)) == ExitCode.INTERNAL
    assert "cannot open lock directory" in out.getvalue()
    assert os.listdir(target) == [] and extractor_calls(project) == [] and calls == []


def test_a_symlinked_workdir_is_refused(project, tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (project / "scratch").mkdir()
    os.symlink(str(target), project / "scratch" / IID)
    pipe, out, calls = recording_pipeline(project)
    assert pipe.run_firmware(fw(project)) == ExitCode.INTERNAL
    assert "cannot secure" in out.getvalue()
    assert os.listdir(target) == [] and "release_emulation" not in calls
