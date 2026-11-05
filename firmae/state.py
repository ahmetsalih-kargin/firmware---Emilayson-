"""Typed access to the small files in scratch/<IID>/ that the stages use to
hand results to each other and to the other tools (docker-helper.py,
util/collect_result.py, debug.py). File names and formats are unchanged."""

import os


class State:
    def __init__(self, workdir):
        self.dir = workdir

    def path(self, name):
        return os.path.join(self.dir, name)

    def write(self, name, value):
        with open(self.path(name), "w") as f:
            f.write("%s\n" % value)

    def read(self, name, default=None):
        try:
            with open(self.path(name)) as f:
                return f.read().strip()
        except FileNotFoundError:
            return default

    def exists(self, name):
        return os.path.exists(self.path(name))

    def remove(self, name):
        try:
            os.unlink(self.path(name))
        except FileNotFoundError:
            pass

    def flag(self, name):
        """True when the file contains 'true' (egrep -sqi true)."""
        return "true" in (self.read(name, "") or "").lower()

    def write_time(self, name, seconds):
        self.write("time_" + name, "%.9f" % seconds)
