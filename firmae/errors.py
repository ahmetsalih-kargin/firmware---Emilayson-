"""Exit codes and the error type of the host-side pipeline.

Before, run.sh exited 0 whatever happened (the step that failed was visible only
in scratch/<IID>/result). Every failure now has its own exit code and names the
stage it happened in. The text written to scratch/<IID>/result is unchanged.
"""

import enum


class ExitCode(enum.IntEnum):
    OK = 0
    INTERNAL = 1            # unexpected error (traceback in the log)
    USAGE = 2
    PRIVILEGE = 3           # not root / firmae.config not found
    EXTRACTION = 10         # rootfs could not be extracted
    IMAGE_ID = 11           # database returned no image id
    DATABASE = 12           # database not reachable (Docker mode)
    ARCH = 20               # architecture not found / not supported
    IMAGE = 30              # building the QEMU image failed
    NETWORK = 40            # network inference failed
    UNREACHABLE = 50        # emulation ran, but no web service
    ANALYSIS = 60
    TIMEOUT = 124
    SIGHUP = 129
    SIGINT = 130
    SIGTERM = 143


class FirmAEError(Exception):
    """A failure of one stage for one firmware.

    result_text is what the old scripts wrote to scratch/<IID>/result (None:
    write nothing, as before).
    """

    def __init__(self, stage, code, message, result_text=None):
        super().__init__(message)
        self.stage = stage
        self.code = ExitCode(code)
        self.message = message
        self.result_text = result_text

    def __str__(self):
        return "[%s] %s (exit %d)" % (self.stage, self.message, self.code)
