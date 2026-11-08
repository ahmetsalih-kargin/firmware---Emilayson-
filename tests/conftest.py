"""Shared pytest fixtures for the FirmAE test suite.

Layout:
    tests/unit/         no root, no QEMU; pure Python or bash with stubbed commands
    tests/integration/  (later phases) needs root and/or QEMU
    tests/fixtures/     data captured from real runs (see tests/fixtures/README.md)
"""

import os
import platform
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Make `import scripts.makeNetwork` work regardless of where pytest is started.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _has_lf_scripts():
    """Bash cannot run scripts checked out with CRLF (Windows autocrlf)."""
    with open(REPO_ROOT / "firmae.config", "rb") as f:
        return b"\r\n" not in f.read()


def pytest_collection_modifyitems(config, items):
    is_linux = platform.system() == "Linux"
    lf_ok = is_linux and _has_lf_scripts()
    is_root = is_linux and os.geteuid() == 0
    skip_linux = pytest.mark.skip(
        reason="needs Linux + LF checkout (bash scripts); run from WSL/Linux clone")
    skip_root = pytest.mark.skip(reason="needs root")
    for item in items:
        if "linux" in item.keywords and not lf_ok:
            item.add_marker(skip_linux)
        if "root" in item.keywords and not is_root:
            item.add_marker(skip_root)


@pytest.fixture
def repo_root():
    return REPO_ROOT


@pytest.fixture
def read_fixture():
    """Read a fixture as bytes with normalised (LF) line endings.

    Fixture files may be checked out with CRLF on Windows; the parsers under
    test split on b"\\n", so a stray b"\\r" would change results.
    """
    def _read(relpath):
        with open(FIXTURES / relpath, "r", encoding="utf-8", newline=None) as f:
            return f.read().encode("utf-8")
    return _read


@pytest.fixture
def firmae_env(monkeypatch):
    """Set the FIRMAE_* switches the way firmae.config does by default."""
    def _set(net="true", timeout="360"):
        monkeypatch.setenv("FIRMAE_NET", net)
        monkeypatch.setenv("TIMEOUT", timeout)
    _set()
    return _set


IPTABLES_STUB = r'''#!/bin/bash
# Fake iptables/ip6tables: keeps the rules in $IPT_STATE (one line per rule,
# "<tool> <chain> <spec>"), logs every call to $LOG, never touches a real firewall.
tool=$(basename "$0")
echo "$tool $*" >> "$LOG"
op=$1; shift
case "$op" in
  -I) chain=$1; shift
      if [ -n "${IPT_FAIL_FORWARD:-}" ] && [ "$chain" = FORWARD ]; then exit 4; fi
      echo "$tool $chain $*" >> "$IPT_STATE"; exit 0;;
  -D) chain=$1; shift
      line="$tool $chain $*"
      grep -qxF -- "$line" "$IPT_STATE" 2>/dev/null || exit 1
      grep -vxF -- "$line" "$IPT_STATE" > "$IPT_STATE.new"; mv "$IPT_STATE.new" "$IPT_STATE"; exit 0;;
  -L) chain=$1
      grep "^$tool $chain " "$IPT_STATE" 2>/dev/null | while read -r _ _ rest; do
        tag=$(echo "$rest" | sed -n 's/.*--comment \(firmae:[0-9]*\).*/\1/p')
        echo "   ${IPT_DROPPED:-7}      420 DROP       0    --  tap+ *       0.0.0.0/0  0.0.0.0/0  ctstate NEW /* $tag */"
      done; exit 0;;
esac
exit 0
'''


@pytest.fixture
def iptables_stubs():
    """write_stubs(bindir, log, state) -> puts fake iptables and ip6tables in bindir."""
    def write(bindir, log, state):
        for name in ("iptables", "ip6tables"):
            p = bindir / name
            p.write_text(IPTABLES_STUB)
            p.chmod(0o755)
        state.write_text("")
        return {"LOG": str(log), "IPT_STATE": str(state)}
    return write
