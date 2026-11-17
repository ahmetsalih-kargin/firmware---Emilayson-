#!/bin/bash
# Initial emulation (armel): the QEMU command line is built by firmae/qemu.py
# (REFACTORING_PLAN 4.2); this wrapper keeps the old call
#   run.armel.sh <image ID> <QEMU_INIT>
# This tool runs as root, so the interpreter must not import anything but the
# installed code: python3 -I ignores PYTHON* variables (PYTHONPATH, ...) and
# puts neither the working directory nor the script directory on sys.path;
# qemu.py adds the installation directory after the standard library itself.
# The installation is found from this file, never from the working directory.
# python3 replaces this shell (exec) and then QEMU replaces python3; -I only
# affects the interpreter, QEMU gets the caller's environment unchanged.
# CDPATH= and >/dev/null: with CDPATH exported, cd would print the directory
# it found and that output would become part of FIRMAE_HOME.
FIRMAE_HOME="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null && pwd)"
exec python3 -I "${FIRMAE_HOME}/firmae/qemu.py" initial armel "$@"
