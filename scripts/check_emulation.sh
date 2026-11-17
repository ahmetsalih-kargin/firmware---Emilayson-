#!/bin/bash
# Check of the inferred emulation: the work is done by firmae/check.py
# (REFACTORING_PLAN 4.5); this wrapper keeps the old call
#   ./scripts/check_emulation.sh <image ID> <arch>
# (scripts/makeNetwork.py, from the FirmAE directory; it reads scratch/<IID>/web).
# This tool runs as root, so the interpreter must not import anything but the
# installed code: python3 -I ignores PYTHON* variables and puts neither the
# working directory nor the script directory on sys.path; check.py adds the
# installation directory after the standard library itself. The installation
# is found from this file, never from the working directory. exec: python3
# replaces this shell, so signals reach it directly (same process group).
# CDPATH= and >/dev/null: with CDPATH exported, cd would print the directory
# it found and that output would become part of FIRMAE_HOME.
FIRMAE_HOME="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null && pwd)"
exec python3 -I "${FIRMAE_HOME}/firmae/check.py" "$0" "$@"
