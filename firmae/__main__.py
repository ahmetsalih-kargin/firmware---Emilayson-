"""Command line: python3 -m firmae <mode> <brand> <firmware|directory>

Same arguments as the old run.sh (which is now a thin wrapper around this)."""

import os
import sys

from scripts.procgroup import raise_on_sigterm

from . import config
from .errors import ExitCode, FirmAEError
from .log import Reporter
from .pipeline import Pipeline

MODES = {"-c": "check", "--check": "check", "-a": "analyze", "--analyze": "analyze",
         "-r": "run", "--run": "run", "-d": "debug", "--debug": "debug",
         "-b": "boot", "--boot": "boot"}

USAGE = """Usage: {prog} [mode]... [brand] [firmware|firmware_directory]
mode: use one option at once
      -r, --run     : run mode         - run emulation (no quit)
      -c, --check   : check mode       - check network reachable and web access (quit)
      -a, --analyze : analyze mode     - analyze vulnerability (quit)
      -d, --debug   : debug mode       - debugging emulation (no quit)
      -b, --boot    : boot debug mode  - kernel boot debugging using QEMU (no quit)
"""


def firmware_list(path):
    """A file, or every file below a directory (sorted: find's order was arbitrary)."""
    if not os.path.isdir(path):
        return [path]
    return [os.path.join(d, f) for d, _, files in sorted(os.walk(path)) for f in sorted(files)]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    prog = os.environ.get("FIRMAE_PROG", "./run.sh")
    if len(argv) != 3 or argv[0] not in MODES:
        sys.stdout.write(USAGE.format(prog=prog))
        return int(ExitCode.USAGE)
    option, brand, firmware = MODES[argv[0]], argv[1], argv[2]
    say = Reporter()

    try:
        cfg = config.load()
    except FirmAEError as e:
        say.error("Error: %s" % e.message)
        return int(e.code)
    os.chdir(cfg.root)           # the stage scripts use paths relative to the project root

    if os.geteuid() != 0:
        say.error("This script must run with 'root' privilege")
        return int(ExitCode.PRIVILEGE)
    if option == "debug" and os.path.isdir(firmware):
        say.error("select firmware file on debug mode!")
        return int(ExitCode.USAGE)

    raise_on_sigterm()           # SIGTERM/SIGHUP -> SystemExit so cleanup runs
    pipeline = Pipeline(cfg, option, brand, say)
    failures = []
    try:
        for path in firmware_list(firmware):
            code = pipeline.run_firmware(path)
            if code != ExitCode.OK:
                failures.append(code)
    except KeyboardInterrupt:
        say.error("interrupted")
        return int(ExitCode.SIGINT)
    except SystemExit as e:
        say.error("terminated")
        return int(e.code) if isinstance(e.code, int) else int(ExitCode.SIGTERM)
    # one firmware: its own code; a directory: the first failure (all were processed)
    return int(failures[0]) if failures else int(ExitCode.OK)


if __name__ == "__main__":
    sys.exit(main())
