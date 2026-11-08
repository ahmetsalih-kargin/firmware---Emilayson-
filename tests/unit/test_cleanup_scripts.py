"""scripts/delete.sh and util/cleanup.sh only touch FirmAE's own resources
(REFACTORING_PLAN 2.8). System commands are stubs that record their arguments;
nothing is actually killed, unmounted or detached."""

import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.linux


def stub(bindir, name, body):
    p = bindir / name
    p.write_text("#!/bin/bash\n" + body + "\n")
    p.chmod(0o755)


@pytest.fixture
def fake_system(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls"
    rec = 'echo "$(basename "$0") $*" >> "%s"' % log
    # `exec` resolves through PATH, so builtins such as `kill` hit the stubs
    # below instead of the real shell builtin
    stub(bindir, "sudo", 'exec "$@"')
    for name in ("kill", "umount", "rm", "psql"):
        stub(bindir, name, rec)
    for fw in ("iptables", "ip6tables"):          # delete.sh also removes firewall rules
        stub(bindir, fw, "exit 1")
    return bindir, log


def calls(log):
    return log.read_text().splitlines() if log.exists() else []


def test_delete_sh_targets_only_its_own_image(repo_root, tmp_path, fake_system):
    bindir, log = fake_system
    root = tmp_path / "FirmAE"
    (root / "scripts").mkdir(parents=True)
    (root / "scratch" / "1").mkdir(parents=True)
    shutil.copy(repo_root / "firmae.config", root)
    shutil.copy(repo_root / "scripts" / "delete.sh", root / "scripts")
    # pgrep answers only for the exact pattern; 999999 cannot be a real PID
    # (> pid_max), so even a mistake here could not signal a real process
    stub(bindir, "pgrep", 'case "$3" in "/scratch/1/") echo 999999 ;; esac; %s' %
         ('echo "pgrep $*" >> "%s"' % log))
    stub(bindir, "mountpoint", "exit 1")
    stub(bindir, "losetup", 'echo "losetup $*" >> "%s"' % log)
    stub(bindir, "ip", 'printf "%%s\\n" '
         '"5: tap1_0.2@tap1_0: <UP>" "4: tap1_0: <UP>" "6: tap11_0: <UP>" "7: tap1_1: <UP>" "8: eth0: <UP>"; '
         'echo "ip $*" >> "%s"' % log)
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    env.pop("FIRMAE_DOCKER", None)
    res = subprocess.run(["bash", "./scripts/delete.sh", "1"], cwd=root, env=env,
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stdout + res.stderr
    c = calls(log)
    assert "pgrep -f -- /scratch/1/" in c
    assert c.count("kill 999999") == 1 and "kill -9 999999" in c
    deletes = [x for x in c if x.startswith("ip link delete")]
    assert deletes == ["ip link delete tap1_0.2", "ip link delete tap1_0", "ip link delete tap1_1"]
    assert "rm -f /tmp/qemu.1 /tmp/qemu.1.S1" in c
    assert any(x.startswith("psql ") and "id=1;" in x for x in c)


def test_cleanup_sh_targets_only_firmae(repo_root, tmp_path, fake_system):
    bindir, log = fake_system
    stub(bindir, "docker", 'echo "docker $*" >> "%s"; [ "$1" = ps ] && echo abc123' % log)
    stub(bindir, "xargs", 'read -r x; echo "xargs $* $x" >> "%s"' % log)
    stub(bindir, "findmnt", 'printf "%s\\n" / /home/u/FirmAE/scratch/3/image /mnt/usb /work/FirmAE/scratch/12/image')
    stub(bindir, "losetup", '[ "$1" = -l ] && printf "%%s\\n" '
         '"/dev/loop0 /var/lib/snapd/snaps/core.snap" "/dev/loop5 /home/u/FirmAE/scratch/3/image.raw" '
         '"/dev/loop6 /work/FirmAE/scratch/12/image.raw" "/dev/loop7 /home/u/vm.img"; '
         '[ "$1" = -d ] && echo "losetup $*" >> "%s"' % log)
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    res = subprocess.run(["bash", str(repo_root / "util" / "cleanup.sh")], env=env,
                         capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    c = calls(log)
    assert "docker ps -aq --filter ancestor=fcore" in c
    assert "xargs -r docker rm -f abc123" in c
    assert [x for x in c if x.startswith("umount")] == [
        "umount /work/FirmAE/scratch/12/image", "umount /home/u/FirmAE/scratch/3/image"]
    assert [x for x in c if x.startswith("losetup -d")] == ["losetup -d /dev/loop5", "losetup -d /dev/loop6"]
