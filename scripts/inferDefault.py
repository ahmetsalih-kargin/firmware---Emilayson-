#!/usr/bin/env python3
"""Find the firmware files that hold default NVRAM values.

The image is untrusted: it may contain symlinks to host paths (/proc/kcore,
/dev/zero, ...), FIFOs and device nodes, and the guest has written to it
during the initial emulation. Only regular files are read (never through a
symlink), each up to MAX_FILE_BYTES, and results are written so that a
symlink planted in the image cannot redirect them to the host.
"""

import os
import re
import stat
import subprocess
import sys

MAX_LOG_BYTES = 64 * 1024 * 1024     # serial log: the guest controls its size
MAX_FILE_BYTES = 64 * 1024 * 1024    # per image file; NVRAM default files are small
CHUNK = 1024 * 1024
FILE_TIMEOUT = 60                    # seconds for one `file` call
MAX_KEYS = 10000                     # distinct NVRAM keys taken from the log
MAX_KEY_BYTES = 256                  # longest key taken from the log


def _open_regular(path):
    """Open path read-only if it is a regular file and not a symlink, else None.
    O_NOFOLLOW/O_NONBLOCK and the fstat check also cover a file swapped after
    lstat (a FIFO must not block us)."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
    except OSError:
        os.close(fd)
        return None
    return os.fdopen(fd, "rb")


def GetKeyList(IID, scratch="./scratch"):
    keys = {}                      # insertion-ordered set: O(1) membership
    tooLong = dropped = 0
    f = _open_regular("{}/{}/qemu.initial.serial.log".format(scratch, IID))
    if f is None:
        return []
    with f:
        data = f.read(MAX_LOG_BYTES)
    for i in data.split(b"\n"):
        if i.startswith(b"[NVRAM]"):
            l = i.split(b" ")
            if len(l) < 3:
                continue
            # isascii: int() rejects some isnumeric() strings (e.g. "²")
            if not (l[1].isascii() and l[1].isdigit()):
                continue
            # length check first: int() refuses very long decimal strings
            keyLen = int(l[1].decode()) if len(l[1]) <= 9 else MAX_LOG_BYTES
            key = l[2][:keyLen]
            # TODO: if you can parse null seperated key/value data in the binary, then remove equal character
            # key = (i.split(b':')[1].strip())
            try:
                key.decode()
            except UnicodeDecodeError:
                # invalid key info
                continue
            if len(key) > MAX_KEY_BYTES:
                tooLong += 1
                continue
            if key in keys:
                continue
            if len(keys) >= MAX_KEYS:
                dropped += 1
                continue
            keys[key] = True
    if tooLong:
        print("inferDefault.py: ignored %d NVRAM keys longer than %d bytes"
              % (tooLong, MAX_KEY_BYTES), file=sys.stderr)
    if dropped:
        print("inferDefault.py: more than %d distinct NVRAM keys; ignored %d"
              % (MAX_KEYS, dropped), file=sys.stderr)
    return list(keys)


def _trie_regex(keys, d=0):
    """Regex source (bytes) matching the longest key, among the sorted, distinct
    `keys` that share their first d bytes, from offset d on. Common prefixes are
    merged, so at a given position only keys that really share the data are
    tried (a flat alternation would try every key at every byte)."""
    terminal = len(keys[0]) == d
    rest = keys[1:] if terminal else keys
    if not rest:
        return b""
    alts = []
    i = 0
    while i < len(rest):
        j = i + 1
        while j < len(rest) and rest[j][d] == rest[i][d]:
            j += 1
        group = rest[i:j]
        plen = len(os.path.commonprefix([group[0], group[-1]]))
        alts.append(re.escape(group[0][d:plen]) + _trie_regex(group, plen))
        i = j
    body = alts[0] if len(alts) == 1 else b"(?:" + b"|".join(alts) + b")"
    # greedy "?": the longer key is tried first
    return b"(?:" + body + b")?" if terminal else body


class KeyMatcher:
    """Which of `keys` occur in a byte stream, in one pass over the data.

    Same result as `key in data` for every key (b"" occurs everywhere), but the
    cost no longer grows with the number of keys: one compiled trie regex finds,
    at each offset, the longest key starting there; every shorter key starting
    there is a prefix of it and is added from `prefixes` (so overlapping and
    nested keys are all found).
    """

    def __init__(self, keys):
        self.keys = set(keys)
        self.total = len(self.keys)
        self.empty = b"" in self.keys
        real = sorted(k for k in self.keys if k)
        self.overlap = max((len(k) for k in real), default=1) - 1
        self.pattern = None
        if real:
            first = b"".join(re.escape(bytes([b])) for b in sorted({k[0] for k in real}))
            src = b"(?=[" + first + b"])(?=(" + _trie_regex(real) + b"))"
            old = sys.getrecursionlimit()
            sys.setrecursionlimit(max(old, 20000))     # nesting depth <= MAX_KEY_BYTES
            try:
                self.pattern = re.compile(src)
            finally:
                sys.setrecursionlimit(old)
        self._expanded = {}

    def _with_prefixes(self, m):
        r = self._expanded.get(m)
        if r is None:
            r = self._expanded[m] = [m] + [m[:n] for n in range(1, len(m)) if m[:n] in self.keys]
        return r

    def new_matches(self, buf, found):
        """Add the keys occurring in buf to the set `found`."""
        if self.pattern is None:
            return
        for m in set(self.pattern.findall(buf)):
            found.update(self._with_prefixes(m))


def count_keys(f, keyList, limit=MAX_FILE_BYTES):
    """Number of keys occurring in the first `limit` bytes of f, read in chunks
    (with an overlap so a key spanning two chunks is still found). keyList is a
    list of distinct keys or a KeyMatcher built from them."""
    matcher = keyList if isinstance(keyList, KeyMatcher) else KeyMatcher(keyList)
    found = set([b""]) if matcher.empty else set()
    tail = b""
    left = limit
    while left > 0 and len(found) < matcher.total:
        chunk = f.read(min(CHUNK, left))
        if not chunk:
            break
        left -= len(chunk)
        buf = tail + chunk
        matcher.new_matches(buf, found)
        tail = buf[-matcher.overlap:] if matcher.overlap > 0 else b""
    return len(found)


def GetDefaultFiles(keyList, root):
    default_list = []
    matcher = KeyMatcher(keyList)
    for dir_name, dir_list, file_list in os.walk(root, followlinks=False):
        rel = os.path.relpath(dir_name, root)
        if ("/" + rel).find("/firmadyne") != -1:
            dir_list[:] = []
            continue

        for file_name in file_list:
            path = os.path.join(dir_name, file_name)
            f = _open_regular(path)
            if f is None:
                continue
            with f:
                count = count_keys(f, matcher)
            # TODO: adjust approximate value
            # TODO: need to save the start index of the nvram data to parsing from the binary
            if count > len(keyList) // 2:
                default_list.append((path, count))
    return default_list


def file_type(path):
    """`file` output for path without following a symlink, or None."""
    try:
        out = subprocess.run(["file", "-b", "-h", "--", path], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=FILE_TIMEOUT, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    # the type comes from file contents: no whitespace may survive into the line
    return re.sub(r"\s", "_", out.decode(errors="replace").rstrip("\n"))


def write_into_image(dirpath, name, data):
    """Write data to dirpath/name; refuse a symlinked directory and replace (not
    follow) whatever the guest left under that name."""
    dfd = os.open(dirpath, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.unlink(name, dir_fd=dfd)
        except FileNotFoundError:
            pass
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    finally:
        os.close(dfd)


def Log(IID, keyList, default_list, root, scratch="./scratch"):
    # logging found nvram keys
    with open("{}/{}/nvram_keys".format(scratch, IID), "w") as out:
        out.write(str(len(keyList)) + "\n")
        for i in keyList:
            out.write(i.decode() + "\n")

    # logging default nvram files
    if default_list:
        lines = []
        for i, j in default_list:
            # path inside the image (the old i.split("image")[1] cut at any "image" in the path)
            path = "/" + os.path.relpath(i, root)
            # the line format is "<path> <count> <type>": a name with a blank or
            # control character would inject fields or lines
            if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in path):
                print("inferDefault.py: skipping file with an unsafe name: %r" % path,
                      file=sys.stderr)
                continue
            fileType = file_type(i)
            if fileType is None:
                continue
            if fileType.find("symbolic") == -1:
                lines.append("{} {} {}\n".format(path, j, fileType))
        # surrogateescape: image file names are arbitrary bytes
        data = "".join(lines).encode(errors="surrogateescape")
        with open("{}/{}/nvram_files".format(scratch, IID), "wb") as f:
            f.write(data)
        write_into_image(os.path.join(root, "firmadyne"), "nvram_files", data)


def main(argv, scratch="./scratch"):
    IID = argv[1]
    if not (IID.isascii() and IID.isdigit()):
        print("usage: %s <image id>" % argv[0], file=sys.stderr)
        return 2
    keyList = GetKeyList(IID, scratch)
    if len(keyList) < 10:
        return 0
    root = "{}/{}/image".format(scratch, IID)
    defaultList = GetDefaultFiles(keyList, root)
    try:
        Log(IID, keyList, defaultList, root, scratch)
    except OSError as e:     # e.g. image/firmadyne replaced by a symlink (ELOOP)
        print("inferDefault.py: cannot write results: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    # execute only if run as a script
    sys.exit(main(sys.argv))
