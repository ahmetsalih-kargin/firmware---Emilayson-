"""Guest network isolation (REFACTORING_PLAN Phase 5 remainder, SECURITY.md S8):
firewall rules that keep the emulated firmware from opening connections to the
host or being routed anywhere. iptables/ip6tables are stubs; no real firewall
is touched."""

import os
import shutil
import subprocess

import pytest


pytestmark = pytest.mark.linux

INPUT = "-i tap{iid}_+ -m conntrack --ctstate NEW -m comment --comment firmae:{iid} -j DROP"
FORWARD = "-i tap{iid}_+ -m comment --comment firmae:{iid} -j DROP"


@pytest.fixture
def world(repo_root, tmp_path, iptables_stubs):
    root = tmp_path / "FirmAE"
    (root / "scratch" / "7").mkdir(parents=True)
    (root / "scratch" / "17").mkdir()
    shutil.copy(repo_root / "firmae.config", root)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log, state = tmp_path / "log", tmp_path / "rules"
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]),
               **iptables_stubs(bindir, log, state))
    env.pop("FIRMAE_DOCKER", None)

    def run(script, **extra):
        return subprocess.run(["bash", "-c", "source ./firmae.config && " + script], cwd=root,
                              env=dict(env, **extra), capture_output=True, text=True, timeout=60)
    return root, run, state, log


def rules(state):
    return sorted(state.read_text().splitlines())


def expected(tool, iid):
    return [tool + " INPUT " + INPUT.format(iid=iid), tool + " FORWARD " + FORWARD.format(iid=iid)]


def test_isolate_applies_two_rules_per_family_and_unisolate_removes_them(world):
    root, run, state, _ = world
    res = run("isolate_guest_network 7")
    assert res.returncode == 0, res.stderr
    assert rules(state) == sorted(expected("iptables", 7) + expected("ip6tables", 7))
    assert (root / "scratch/7/isolation").read_text().strip() == "applied: iptables ip6tables"

    assert run("unisolate_guest_network 7", IPT_DROPPED="5").returncode == 0
    assert rules(state) == []
    text = (root / "scratch/7/isolation").read_text()
    assert "dropped (iptables INPUT): 5" in text and "dropped (ip6tables INPUT): 5" in text


def test_isolate_is_idempotent(world):
    root, run, state, _ = world
    run("isolate_guest_network 7; isolate_guest_network 7; isolate_guest_network 7")
    assert len(rules(state)) == 4


def test_other_images_rules_are_untouched(world):
    root, run, state, _ = world
    run("isolate_guest_network 17; isolate_guest_network 7")
    assert len(rules(state)) == 8
    run("unisolate_guest_network 7")
    assert rules(state) == sorted(expected("iptables", 17) + expected("ip6tables", 17))


def test_unisolate_without_rules_is_a_quiet_noop(world):
    root, run, state, _ = world
    res = run("unisolate_guest_network 7; echo done")
    assert res.stdout.strip() == "done" and res.stderr == ""
    assert not (root / "scratch/7/isolation").exists()


def test_half_applied_set_is_rolled_back_and_reported(world):
    root, run, state, _ = world
    res = run("isolate_guest_network 7", IPT_FAIL_FORWARD="1")
    assert res.returncode == 0                       # the emulation still runs
    assert rules(state) == []                        # INPUT rule did not stay behind alone
    assert "NOT applied" in res.stderr
    assert (root / "scratch/7/isolation").read_text().startswith("not applied")


def test_missing_iptables_is_loud_but_not_fatal(world, tmp_path):
    root, run, state, _ = world
    strict_path = "/usr/bin:/bin"
    if subprocess.run(["bash", "-c", "command -v iptables"], env={"PATH": strict_path},
                      capture_output=True).returncode == 0:
        pytest.skip("iptables lives in /usr/bin on this system")
    res = run("isolate_guest_network 7", PATH=strict_path)
    assert res.returncode == 0
    assert "WARNING: guest network isolation NOT applied" in res.stderr
    assert (root / "scratch/7/isolation").read_text().startswith("not applied")


def test_release_emulation_removes_the_rules(world):
    root, run, state, _ = world
    run("isolate_guest_network 7")
    assert len(rules(state)) == 4
    res = run("QEMU_STOP_GRACE=1; release_emulation 7")
    assert res.returncode == 0, res.stderr
    assert rules(state) == []


def test_emulate_sh_isolates_after_the_network_and_before_qemu(repo_root):
    """Structure of scripts/emulate.sh (the former run.sh template); the
    runtime order is checked in test_generated_run_sh.py and, against the old
    script, in test_emulate_equivalence.py."""
    out = (repo_root / "scripts" / "emulate.sh").read_text()
    # "\nisolate_...": the cleanup function also contains "unisolate_guest_network ${IID}"
    assert out.index("\nstart_net\n") < out.index("\nisolate_guest_network ${IID}\n") \
        < out.index('"${QEMU}" "${QEMU_ARGS[@]}" &')
    cleanup = out[out.index("cleanup () {"):out.index("trap cleanup EXIT")]
    assert cleanup.index("        stop_net\n") < cleanup.index("unisolate_guest_network ${IID}")
