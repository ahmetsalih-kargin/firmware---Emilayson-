"""Settings: firmae.config stays the single source (shell syntax, sourced by the
guest-facing scripts too). Python reads the values by sourcing it in bash, so
there is no second parser that could disagree with it."""

import dataclasses
import os
import subprocess

from .errors import ExitCode, FirmAEError

# keep in sync with check_arch() in firmae.config (tests compare them)
VALID_ARCHS = ("armel", "mipseb", "mipsel")

_VARS = ("FIRMAE_BOOT", "FIRMAE_NET", "FIRMAE_NVRAM", "FIRMAE_KERNEL", "FIRMAE_ETC",
         "TIMEOUT", "CHECK_TIMEOUT", "PSQL_IP", "FIRMAE_DIR", "SCRATCH_DIR",
         "TARBALL_DIR", "SCRIPT_DIR")


@dataclasses.dataclass(frozen=True)
class Config:
    root: str
    FIRMAE_BOOT: str
    FIRMAE_NET: str
    FIRMAE_NVRAM: str
    FIRMAE_KERNEL: str
    FIRMAE_ETC: str
    TIMEOUT: int
    CHECK_TIMEOUT: int
    PSQL_IP: str
    FIRMAE_DIR: str
    SCRATCH_DIR: str
    TARBALL_DIR: str
    SCRIPT_DIR: str

    def scratch(self, iid):
        return os.path.join(self.SCRATCH_DIR, str(iid))

    def env(self):
        """Environment for child processes (what firmae.config exported to them)."""
        e = dict(os.environ)
        e.update(TIMEOUT=str(self.TIMEOUT), FIRMAE_NET=self.FIRMAE_NET)
        return e


def find_root(start=None):
    """Directory containing firmae.config: the working directory or its parent
    (the two places run.sh looked)."""
    start = os.path.abspath(start or os.getcwd())
    for cand in (start, os.path.dirname(start)):
        if os.path.isfile(os.path.join(cand, "firmae.config")):
            return cand
    raise FirmAEError("config", ExitCode.PRIVILEGE, "Could not find 'firmae.config'!")


def load(root=None):
    root = find_root(root)
    script = 'source ./firmae.config && for v in %s; do printf "%%s\\0" "$v=${!v}"; done' % " ".join(_VARS)
    res = subprocess.run(["bash", "-c", script], cwd=root, capture_output=True, timeout=30)
    if res.returncode != 0:
        raise FirmAEError("config", ExitCode.PRIVILEGE,
                          "cannot read firmae.config: %s" % res.stderr.decode(errors="replace").strip())
    values = dict(item.split("=", 1) for item in res.stdout.decode().split("\0") if item)
    return Config(root=root,
                  TIMEOUT=int(values.pop("TIMEOUT")),
                  CHECK_TIMEOUT=int(values.pop("CHECK_TIMEOUT")),
                  **values)
