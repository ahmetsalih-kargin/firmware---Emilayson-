"""One place for what the pipeline tells the user and what it records.

Console: the familiar "[*] ..", "[+] ..", "[-] .." lines (docker-helper.py and
users read them), unchanged.
Log file scratch/<IID>/firmae.log: every line with a timestamp, level, image id
and stage, e.g.
    2026-11-04T12:00:01 INFO  [iid=42][image] building QEMU image
Lines said before the image id is known are buffered and written once it is.
Nothing secret is logged (no passwords, no connection strings).
"""

import datetime
import sys

_COLORS = {"-": "\033[31m", "+": "\033[32m", "*": ""}
_LEVEL = {"-": "ERROR", "+": "INFO", "*": "INFO"}


class Reporter:
    def __init__(self, out=None, color=None):
        self.out = out or sys.stdout
        self.color = self.out.isatty() if color is None else color
        self.iid = None
        self.stage = "-"
        self._file = None
        self._pending = []

    def bind(self, iid, logfile):
        self.iid = iid
        self._file = open(logfile, "a", buffering=1)
        for line in self._pending:
            self._file.write(line)
        self._pending = []

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def say(self, kind, message, stage=None):
        if stage:
            self.stage = stage
        mark = "[%s%s%s]" % (_COLORS[kind], kind, "\033[0m" if _COLORS[kind] else "") if self.color else "[%s]" % kind
        self.out.write("%s %s\n" % (mark, message))
        self.out.flush()
        self._record(_LEVEL[kind], message)

    def info(self, message, stage=None):
        self.say("*", message, stage)

    def ok(self, message, stage=None):
        self.say("+", message, stage)

    def error(self, message, stage=None):
        self.say("-", message, stage)

    def plain(self, message):
        """Console-only text (separators, blank lines)."""
        self.out.write(message + "\n")
        self.out.flush()

    def debug(self, message):
        self._record("DEBUG", message)

    def _record(self, level, message):
        line = "%s %-5s [iid=%s][%s] %s\n" % (
            datetime.datetime.now().isoformat(timespec="seconds"), level,
            self.iid if self.iid is not None else "-", self.stage, message)
        if self._file:
            self._file.write(line)
        else:
            self._pending.append(line)
