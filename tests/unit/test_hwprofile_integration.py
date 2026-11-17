"""The pipeline's hardware profile steps with the REAL `python3 -m firmae.hwprofile`.

test_pipeline_hwprofile.py replaces the CLI with a stub; here nothing is faked:
a small synthetic rootfs tarball (a fake ELF that mentions /dev/gpio and
/dev/watchdog, plus a .ko) and a recorded serial log go through
Pipeline._hwprofile_static / _hwprofile_dynamic and _hw_summary_line. Written
against the contract only: CLI --tar/--out/--serial-log/--timeout/--update, top
level keys schema/static/dynamic/peripherals/notes.
"""

import io
import json
import os
import shutil
import tarfile

import pytest

from firmae import config
from firmae.log import Reporter
from firmae.pipeline import HWPROFILE_JSON, Pipeline
from firmae.state import State

pytestmark = pytest.mark.linux

SERIAL = "hw_watchdog.log"


def _add(tar, name, data, mode=0o755):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


@pytest.fixture
def rig(repo_root, tmp_path, monkeypatch):
    for var in ("FIRMAE_HWPROFILE", "FIRMAE_TIMEOUT_HWPROFILE"):
        monkeypatch.delenv(var, raising=False)
    tarball = tmp_path / "1.tar.gz"
    with tarfile.open(tarball, "w:gz") as tar:
        _add(tar, "./bin/wdtest", b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 24 +
             b"\x00/dev/gpio\x00/dev/watchdog\x00padding\x00")
        _add(tar, "./lib/modules/2.6.36/kernel/drivers/foo.ko", b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 56,
             mode=0o644)
    workdir = tmp_path / "scratch" / "1"
    workdir.mkdir(parents=True)
    log = workdir / "qemu.initial.serial.log"
    shutil.copyfile(repo_root / "tests" / "fixtures" / "serial" / SERIAL, log)

    cfg = config.load(str(repo_root))
    pipe = Pipeline(cfg, "check", "dlink", Reporter(out=io.StringIO(), color=False))
    pipe.iid = "1"
    pipe.state = State(str(workdir))
    return pipe, str(tarball), workdir


def test_real_cli_through_the_pipeline_steps(rig):
    pipe, tarball, workdir = rig
    pipe._hwprofile_static(tarball)
    profile = workdir / HWPROFILE_JSON
    assert pipe._hw_static_ok and pipe._hw_ran and profile.is_file(), (workdir / "hwprofile.log").read_text()
    first = json.loads(profile.read_text())
    assert first["static"]                                  # filled by the tarball
    assert "peripherals" in first and "notes" in first

    pipe._hwprofile_dynamic()
    data = json.loads(profile.read_text())
    assert set(data) >= {"schema", "static", "dynamic", "peripherals", "notes"}
    assert data["static"] and data["dynamic"]
    assert data["peripherals"]["watchdog"]["status"] == "failing"
    assert data["peripherals"]["gpio"]["status"] in ("referenced", "failing", "covered", "unsupported")

    line = pipe._hw_summary_line()
    assert line.startswith("[hw] ") and "watchdog=failing" in line
    assert line.endswith("(%s)" % profile) or line.endswith("(scratch/1/%s)" % HWPROFILE_JSON)
    assert line.index("watchdog=failing") < line.index("gpio=") or "gpio=" not in line   # loud ones first
    log = (workdir / "hwprofile.log").read_text()
    assert "Traceback" not in log
    assert os.stat(profile).st_mode & 0o777 <= 0o666            # a regular, ordinary file


def test_a_second_run_replaces_the_profile_instead_of_updating_a_stale_one(rig):
    pipe, tarball, workdir = rig
    pipe._hwprofile_static(tarball)
    pipe._hwprofile_dynamic()
    assert json.loads((workdir / HWPROFILE_JSON).read_text())["dynamic"]
    # a new run whose static step fails (missing tarball): the old profile must be gone
    pipe._hw_ran = False
    pipe._hwprofile_static(str(workdir / "no-such.tar.gz"))
    assert not pipe._hw_static_ok and not (workdir / HWPROFILE_JSON).exists()
    pipe._hwprofile_dynamic()
    assert not (workdir / HWPROFILE_JSON).exists()              # nothing was updated into existence
    pipe._hw_summary()                                          # prints nothing
    assert "[hw]" not in pipe.say.out.getvalue()
