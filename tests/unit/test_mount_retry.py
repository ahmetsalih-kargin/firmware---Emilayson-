"""makeNetwork.mountImage retries a failing mount briefly (the partition node of a
fresh loop device can still be settling) and no longer ignores a final failure."""

import subprocess
import types

import pytest

from scripts import makeNetwork as mn


@pytest.fixture
def fake(monkeypatch):
    calls = []
    results = []

    def run(argv, **kw):
        calls.append(argv)
        rc = results.pop(0)
        return types.SimpleNamespace(returncode=rc, args=argv, stderr=b"mount: boom")

    monkeypatch.setattr(mn.subprocess, "check_output", lambda argv, **kw: b"/dev/loop9p1\n")
    monkeypatch.setattr(mn.subprocess, "run", run)
    monkeypatch.setattr(mn.time, "sleep", lambda s: None)
    return calls, results


def test_transient_mount_failures_are_retried(fake):
    calls, results = fake
    results[:] = [32, 32, 0]
    assert mn.mountImage("/w/scratch/1") == "/dev/loop9p1"
    assert [c[0] for c in calls] == ["mount"] * 3
    assert calls[0] == ["mount", "/dev/loop9p1", "/w/scratch/1/image"]


def test_a_persistent_mount_failure_is_raised_after_five_attempts(fake, capsys):
    calls, results = fake
    results[:] = [32] * 5
    with pytest.raises(subprocess.CalledProcessError):
        mn.mountImage("/w/scratch/1")
    assert len(calls) == 5
    assert "mount: boom" in capsys.readouterr().err
