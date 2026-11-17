#!/bin/bash
# Builds scratch/<IID>/image.raw from the extracted root file system. The flow
# lives in firmae/image.py (REFACTORING_PLAN 4.3); this wrapper keeps the old call
#   makeImage.sh <image ID> <architecture> [<file name>]
# (exit 0 on success, non-zero on failure). The tool runs as root, so the
# interpreter must not import anything but the installed code: python3 -I
# ignores PYTHON* variables and puts neither the working directory nor the
# script directory on sys.path; the installation is found from this file.
# CDPATH= and >/dev/null: with CDPATH exported, cd would print the directory
# it found and that output would become part of FIRMAE_HOME.
FIRMAE_HOME="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null && pwd)"
exec python3 -I "${FIRMAE_HOME}/firmae/image.py" "$@"
