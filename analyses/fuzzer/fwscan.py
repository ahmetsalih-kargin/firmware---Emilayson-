"""Shell-free helpers for scanning an extracted firmware tree.

The fuzzer used to build shell pipelines such as
    strings <path> | grep -P '...' | sort | uniq
with file paths taken from the firmware image. A file named e.g.
`a;<command>;cgi` therefore executed <command> on the host as root
(SECURITY.md S1). These helpers do the same work in Python, without a shell.

Semantics follow the GNU tools they replace:
  * strings_of()   -> `strings`   : runs of >= 4 printable ASCII chars (incl. TAB)
  * find_entries() -> `find -iname/-name [-executable]` (files AND directories;
                      symlinks are listed but never descended into)
  * grep_files()   -> `grep -r -l`: regular files only; symlinks, devices and
                      FIFOs are skipped (grep -r skips them too, and opening a
                      FIFO would block forever)
Results are sorted, so scans are deterministic (find/grep returned
directory order).
"""

import fnmatch
import os
import re
import stat

_PRINTABLE = re.compile(rb"[\t\x20-\x7e]{4,}")


def _walk(root):
    """Yield (path, lstat) for every entry below root, never following symlinks."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            try:
                yield path, os.lstat(path)
            except OSError:
                continue


def _is_regular(st):
    return stat.S_ISREG(st.st_mode)


def read_regular(path, st=None):
    """Return the file's bytes, or None if it is not a regular file (or unreadable)."""
    try:
        st = st or os.lstat(path)
        if not _is_regular(st):
            return None
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def strings_of(path, min_len=4):
    """Printable strings of a regular file, like GNU `strings` (decoded as ASCII)."""
    data = read_regular(path)
    if data is None:
        return []
    pattern = _PRINTABLE if min_len == 4 else re.compile(rb"[\t\x20-\x7e]{%d,}" % min_len)
    return [m.decode("ascii") for m in pattern.findall(data)]


def strings_matching(path, regex):
    """`strings path | grep -P regex | sort | uniq`."""
    rx = re.compile(regex)
    return sorted({s for s in strings_of(path) if rx.search(s)})


def find_entries(root, pattern, ignore_case=True, executable=False):
    """`find root [-executable] -iname/-name pattern`, sorted."""
    out = []
    pat = pattern.lower() if ignore_case else pattern
    for path, st in _walk(root):
        name = os.path.basename(path)
        if not fnmatch.fnmatchcase(name.lower() if ignore_case else name, pat):
            continue
        if executable and not os.access(path, os.X_OK):
            continue
        out.append(path)
    return sorted(out)


def grep_files(root, regex, ignore_case=False):
    """`grep -r -l regex root` over regular files, sorted. `regex` is bytes."""
    rx = re.compile(regex, re.IGNORECASE if ignore_case else 0)
    out = []
    for path, st in _walk(root):
        if not _is_regular(st):
            continue
        data = read_regular(path, st)
        if data is not None and rx.search(data):
            out.append(path)
    return sorted(out)


def grep_lines(root, regex):
    """`grep -r regex root` -> list of (path, line) for matching lines (bytes regex)."""
    rx = re.compile(regex)
    out = []
    for path, st in _walk(root):
        if not _is_regular(st):
            continue
        data = read_regular(path, st)
        if data is None or not rx.search(data):
            continue
        for line in data.split(b"\n"):
            if rx.search(line):
                out.append((path, line.decode("utf-8", "replace")))
    return sorted(out)
