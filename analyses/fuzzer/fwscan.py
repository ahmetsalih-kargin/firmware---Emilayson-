"""Shell-free helpers for scanning an extracted firmware tree.

The fuzzer used to build shell pipelines such as
    strings <path> | grep -P '...' | sort | uniq
with file paths taken from the firmware image. A file named e.g.
`a;<command>;cgi` therefore executed <command> on the host as root
(SECURITY.md S1). These helpers do the same work in Python, without a shell.

Semantics follow the GNU tools they replace:
  * iter_strings()  -> `strings`   : runs of >= 4 printable ASCII chars (incl. TAB)
  * find_entries()  -> `find -iname/-name [-executable]` (files AND directories;
                       symlinks are listed but never descended into)
  * grep_files()    -> `grep -r -l`: regular files only; symlinks, devices and
                       FIFOs are skipped (grep -r skips them too, and opening a
                       FIFO would block forever)
Results are sorted, so scans are deterministic (find/grep returned
directory order).

Memory: files are read in 1 MiB blocks, never as a whole -- firmware images
contain files of hundreds of MB, and the tools above streamed too. Limits of
the streaming: a grep_files() match must be shorter than OVERLAP bytes to be
found across a block boundary (the patterns used are 7-15 bytes), and a single
printable run longer than MAX_RUN bytes is reported in pieces.
"""

import fnmatch
import os
import re
import stat

CHUNK = 1 << 20
OVERLAP = 4096
MAX_RUN = 16 << 20

_PRINTABLE = re.compile(rb"[\t\x20-\x7e]{4,}")
_PRINTABLE_BYTES = b"\t" + bytes(range(0x20, 0x7F))


def _printable_tail(buf):
    """Trailing run of printable bytes of buf, in linear time. (A regex such as
    `[...]*\\Z` used with search() is quadratic on a long run that is followed
    by a non-printable byte.)"""
    return buf[len(buf.rstrip(_PRINTABLE_BYTES)):]


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


def _chunks(path, st=None):
    """Yield the content of a regular file in CHUNK-sized blocks. Anything else
    (symlink, FIFO, device, unreadable file) yields nothing."""
    try:
        st = st or os.lstat(path)
        if not _is_regular(st):
            return
        f = open(path, "rb")
    except OSError:
        return
    with f:
        while True:
            try:
                block = f.read(CHUNK)
            except OSError:
                return
            if not block:
                return
            yield block


def _contains(path, rx, st=None):
    tail = b""
    for block in _chunks(path, st):
        buf = tail + block
        if rx.search(buf):
            return True
        tail = buf[-OVERLAP:]
    return False


def iter_strings(path, min_len=4):
    """Printable strings of a regular file, like GNU `strings` (decoded as ASCII),
    one at a time."""
    rx = _PRINTABLE if min_len == 4 else re.compile(rb"[\t\x20-\x7e]{%d,}" % min_len)
    carry = b""                       # printable run that may continue in the next block
    for block in _chunks(path):
        buf = carry + block
        carry = _printable_tail(buf)
        if len(carry) > MAX_RUN:      # pathological: flush instead of growing without bound
            carry = b""
            body = buf
        else:
            body = buf[:len(buf) - len(carry)]
        for m in rx.findall(body):
            yield m.decode("ascii")
    if len(carry) >= min_len:
        yield carry.decode("ascii")


def strings_of(path, min_len=4):
    """All printable strings of a regular file as a list (small files / tests)."""
    return list(iter_strings(path, min_len))


def strings_matching(path, regex):
    """`strings path | grep -P regex | sort | uniq`."""
    rx = re.compile(regex)
    return sorted({s for s in iter_strings(path) if rx.search(s)})


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
        if _is_regular(st) and _contains(path, rx, st):
            out.append(path)
    return sorted(out)


def grep_lines(root, regex):
    """`grep -r regex root` -> list of (path, line) for matching lines (bytes regex)."""
    rx = re.compile(regex)
    out = []
    for path, st in _walk(root):
        if not _is_regular(st) or not _contains(path, rx, st):
            continue
        try:
            with open(path, "rb") as f:
                for line in f:                      # lazily, one line at a time
                    line = line.rstrip(b"\n")
                    if rx.search(line):
                        out.append((path, line.decode("utf-8", "replace")))
        except OSError:
            continue
    return sorted(out)
