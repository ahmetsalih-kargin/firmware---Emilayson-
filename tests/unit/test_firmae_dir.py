"""firmae.config derives FIRMAE_DIR from its own location, not $(pwd)
(REFACTORING_PLAN 2.7): analyses_all.sh and nmap.sh source ../firmae.config
from analyses/, where $(pwd) used to yield analyses/scratch."""

import os
import subprocess

import pytest

pytestmark = pytest.mark.linux


@pytest.mark.parametrize("cwd,config", [(".", "./firmae.config"), ("analyses", "../firmae.config")])
def test_scratch_dir_is_independent_of_cwd(repo_root, cwd, config):
    env = dict(os.environ)
    env.pop("FIRMAE_DOCKER", None)
    res = subprocess.run(["bash", "-c", 'source %s && echo "$SCRATCH_DIR"' % config],
                         cwd=repo_root / cwd, env=env, capture_output=True, text=True, timeout=30)
    assert res.stdout.strip() == "%s/scratch" % repo_root


def test_docker_mode_keeps_fixed_path(repo_root):
    env = dict(os.environ, FIRMAE_DOCKER="true")
    res = subprocess.run(["bash", "-c", 'source ./firmae.config && echo "$SCRATCH_DIR $PSQL_IP"'],
                         cwd=repo_root, env=env, capture_output=True, text=True, timeout=30)
    assert res.stdout.strip() == "/work/FirmAE/scratch 172.17.0.1"
