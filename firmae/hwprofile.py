"""Hardware dependency profiler: which peripherals does a firmware rootfs use,
and which of them can FirmAE's generic emulation not provide?

    python3 -m firmae.hwprofile --tar images/<IID>.tar.gz --out scratch/<IID>/hw_profile.json
                                [--serial-log <log> ...] [--timeout <seconds>]
                                [--mem-limit-mb <MiB>]
    python3 -m firmae.hwprofile --update --out scratch/<IID>/hw_profile.json
                                --serial-log <log> [--serial-log <log> ...]

Static part (this module, `scan_tarball`): the rootfs tarball is read as a
stream, member by member, and the content of every regular file is searched
for "/dev/...", "/sys/...", "/proc/..." strings and for ioctl request names.
Kernel module names (*.ko) and device nodes (tar CHRTYPE/BLKTYPE members) are
listed from the member headers. The dynamic part (serial-log events) comes from
`firmae.hwserial.scan_serial_logs` (a separate module); `build_profile`
combines both into one status per peripheral class.

Security (the tarball is attacker-controlled; this may run as root):
  * members are never extracted: content is streamed with `extractfile`, and a
    member name is only ever a label in the output, never a host path;
  * symlinks and hard links are never followed or read (hard links would make
    tarfile seek back to an earlier member; they are listed by name only);
  * the work this module does itself is bounded by the MAX_* constants below;
    when a bound is hit the scan stops (or skips) and reports
    `truncated: true` and the name of the bound in `limits_hit`;
  * tarfile's own header parsing is bounded from the outside: all bytes
    tarfile reads while parsing one member's headers (GNU long names, pax
    records, the GNU 'S' sparse extension blocks, the pax "GNU.sparse 1.0"
    map) count against MAX_HEADER_BYTES, and the global pax headers tarfile
    keeps across members against MAX_PAX_GLOBAL_KEYS / MAX_HEADER_BYTES.
    tarfile turns those bytes into Python objects (the sparse map into a list
    of ints), so memory per member is a small multiple of MAX_HEADER_BYTES,
    not of it exactly. Nested headers (pax/long-name chains) recurse inside
    tarfile; a RecursionError ends the scan with "header_nesting". Sparse
    members are listed but their content is not scanned ("sparse_member");
  * the decompressed stream is counted (compression bombs) and the time
    budget is checked on every read, including while skipping a member's
    data; xz is decoded with a decoder memory limit (MAX_XZ_MEMORY: a hostile
    header can ask for a 4 GiB dictionary); gzip (32 KiB window) and bzip2
    (at most 900 kB blocks) need little memory by format;
  * a malformed tarball gives a partial result with "read_error" (or
    TarballError when not even the first member could be read);
  * the CLI entry point (python3 -m firmae.hwprofile; the library functions
    never change the caller's limits) adds a second layer for whatever the
    bounds above do not foresee: it caps its own address space (RLIMIT_AS,
    --mem-limit-mb, default DEFAULT_MEM_LIMIT_MB, 0 = off; POSIX only) and,
    on Linux, stops the scan with "memory" (partial result) once the
    address space (/proc/self/statm, checked in the stream reader) passes
    75% of that limit -- before the hard limit, because a MemoryError at the
    hard limit can leave CPython spinning in C. A MemoryError that happens
    anyway still gives a partial result when it can. Last resort: a
    faulthandler watchdog thread ends the process with exit 1 (no output)
    HARD_GRACE seconds after --timeout, whatever the main thread is doing;
  * the CLI never prints a traceback: an unexpected error is one
    "hwprofile: error:" line, exit 1;
  * the written JSON is at most MAX_PROFILE_BYTES: sample lists and keys of
    the static/dynamic sections are trimmed ("profile_size" in limits_hit),
    the peripherals section is computed before trimming and kept whole;
  * the scanning regex is linear: one literal prefix followed by one bounded
    character class, no nested quantifiers;
  * every firmware-derived string that reaches the JSON is printable ASCII
    (0x20-0x7e, anything else becomes '?') and at most MAX_STR characters;
  * the output file is written to a temporary file in the target directory
    (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600, then 0640 & ~umask) and renamed
    over the target with os.replace; a target that is a symlink is refused.

Classification rules (all in tables below, first matching row wins):
  PATH_RULES    path prefix  -> peripheral class, or IGNORE for generic paths
                ("/dev/null", "/dev/tty*", ...: counted in device_paths but
                never evidence for a peripheral). Unmatched /dev paths are
                class "other"; unmatched /sys and /proc paths are not evidence.
  MODULE_RULES  *.ko name    -> module class (watchdog, i2c, ..., other)
  IOCTL_RULES   ioctl name   -> peripheral class. ioctl_hints are HINTS: the
                names are found as text (debug strings, scripts, headers); a
                stripped binary uses the numeric request only, so absence
                means nothing and presence is not an observed call.
  PERIPHERAL_SUPPORT  class -> status when referenced, FirmAE mechanism.

Status of a peripheral class, in this order of precedence:
  "failing"         the dynamic section shows a runtime error for the class
                    (wins over everything, also over "covered"): an error
                    count in dynamic["devices"] (by PATH_RULES) or
                    dynamic["modules"] (by MODULE_RULES), or a class event
                    (EVENT_CLASSES). Without dynamic["modules"] (older
                    hwserial / older profile) the event samples are searched
                    for /dev paths and *.ko names instead;
  "not-referenced"  no static and no dynamic trace;
  "covered"         referenced, and FirmAE has a known mechanism
                    (nvram -> libnvram, mtd -> nandsim, uart -> QEMU serial);
  "unsupported"     referenced, and FirmAE has no counterpart (i2c, spi);
                    never presented as working;
  "referenced"      referenced, no runtime error seen (or no log at all).
"""

import argparse
import gzip
import itertools
import json
import math
import os
import re
import secrets
import stat
import sys
import tarfile
import time

try:
    import bz2
except ImportError:          # minimal Python builds
    bz2 = None
try:
    import lzma
except ImportError:
    lzma = None
try:
    import resource
except ImportError:          # Windows
    resource = None

SCHEMA = 1

# ---------------------------------------------------------------- limits
# Module globals, read at call time (tests make them small with monkeypatch).
DEFAULT_TIMEOUT = 240.0           # seconds, whole static scan
MAX_MEMBERS = 200000              # tar members looked at
MAX_FILE_BYTES = 16 << 20         # content bytes scanned per member
MAX_TOTAL_BYTES = 2 << 30         # content bytes scanned in total
MAX_STREAM_BYTES = 4 << 30        # decompressed tar stream bytes (incl. skipped data)
MAX_HEADER_READ = 8 << 20         # one read by tarfile (GNU long name, pax header)
MAX_HEADER_BYTES = 1 << 20        # all bytes tarfile reads for one member's headers
MAX_PAX_GLOBAL_KEYS = 1000        # keys of the global pax headers kept by tarfile
MAX_XZ_MEMORY = 128 << 20         # xz decoder memory limit (xz -9 needs ~65 MiB)
MAX_PROFILE_BYTES = 2 << 20       # size of the written JSON
DEFAULT_MEM_LIMIT_MB = 1536       # CLI: RLIMIT_AS of the process (0 = not set)
MEM_RESERVE = 8 << 20             # CLI under RLIMIT_AS: freed on MemoryError, headroom to finish
HARD_GRACE = 30.0                 # CLI: seconds after --timeout before the process is ended
# Holds the reserve (one bytearray) while the CLI runs under RLIMIT_AS; a list
# so that a MemoryError handler can drop it with clear(), allocating nothing.
_RESERVE = []
# CLI only: [address-space bytes at which the scan stops, fd of /proc/self/statm]
_MEM_GUARD = [0, None]
_HARD_DEADLINE_FILE = []
MAX_KEYS = 2000                   # distinct keys per dict / entries per list
MAX_SAMPLE_FILES = 5              # member names kept per key
MAX_STR = 256                     # length of every firmware-derived string
MAX_EVIDENCE = 10                 # evidence strings per peripheral
MAX_EXISTING_PROFILE = 64 << 20   # --update: size of the profile read back
CHUNK = 1 << 20                   # read size
KEEP = 512                        # bytes carried between blocks (> longest match)
HIST = 4096                       # backward-seek window of the stream reader
MAX_PATH_TAIL = 240               # characters after "/dev/" etc.

IGNORE = "ignore"
PERIPHERALS = ("i2c", "spi", "gpio", "watchdog", "led", "mtd", "nvram", "uart", "wlan", "other")
MODULE_CLASSES = ("watchdog", "i2c", "spi", "gpio", "led", "wlan", "ethernet", "mtd", "usb",
                  "netfilter", "other")

# (pattern, class); "x*" is a prefix, anything else an exact path. First match wins.
PATH_RULES = (
    ("/dev/ttyS*", "uart"),           # before the generic /dev/tty*
    ("/dev/ttyUSB*", "uart"),
    ("/dev/ttyAMA*", "uart"),
    ("/dev/i2c*", "i2c"),
    ("/sys/class/i2c*", "i2c"),
    ("/sys/bus/i2c*", "i2c"),
    ("/dev/spidev*", "spi"),
    ("/dev/spi*", "spi"),
    ("/sys/bus/spi*", "spi"),
    ("/sys/class/spi*", "spi"),
    ("/dev/gpio*", "gpio"),
    ("/sys/class/gpio*", "gpio"),
    ("/dev/watchdog*", "watchdog"),
    ("/dev/wdt*", "watchdog"),
    ("/sys/class/watchdog*", "watchdog"),
    ("/dev/led*", "led"),
    ("/sys/class/leds*", "led"),
    ("/dev/mtd*", "mtd"),
    ("/proc/mtd", "mtd"),
    ("/sys/class/mtd*", "mtd"),
    ("/dev/nvram*", "nvram"),
    # generic: counted, never evidence for a peripheral
    ("/dev/null", IGNORE),
    ("/dev/console", IGNORE),
    ("/dev/urandom", IGNORE),
    ("/dev/random", IGNORE),
    ("/dev/zero", IGNORE),
    ("/dev/full", IGNORE),
    ("/dev/log", IGNORE),
    ("/dev/kmsg", IGNORE),
    ("/dev/ptmx", IGNORE),
    ("/dev/root", IGNORE),
    ("/dev/ppp", IGNORE),
    ("/dev/net*", IGNORE),            # /dev/net/tun
    ("/dev/fuse", IGNORE),
    ("/dev/misc/fuse", IGNORE),
    ("/dev/misc", IGNORE),
    ("/dev/egd-pool", IGNORE),
    ("/dev/sd*", IGNORE),             # USB storage / disks (QEMU disk)
    ("/dev/hd*", IGNORE),
    ("/dev/sr*", IGNORE),
    ("/dev/mmcblk*", IGNORE),
    ("/dev/mapper*", IGNORE),
    ("/dev/tty*", IGNORE),
    ("/dev/pty*", IGNORE),
    ("/dev/pts*", IGNORE),
    ("/dev/shm*", IGNORE),
    ("/dev/fd*", IGNORE),
    ("/dev/std*", IGNORE),
    ("/dev/ram*", IGNORE),
    ("/dev/loop*", IGNORE),
    ("/dev/*", "other"),              # vendor nodes (/dev/brcmboard, ...)
)

# /proc paths that say nothing about hardware: not recorded at all (they would
# only use up MAX_KEYS). Matched per path component.
PROC_IGNORE = (
    "/proc/self", "/proc/net", "/proc/sys", "/proc/meminfo", "/proc/cpuinfo", "/proc/mounts",
    "/proc/stat", "/proc/uptime", "/proc/loadavg", "/proc/version", "/proc/cmdline",
    "/proc/filesystems", "/proc/partitions", "/proc/kmsg", "/proc/kallsyms", "/proc/swaps",
    "/proc/diskstats", "/proc/vmstat", "/proc/slabinfo", "/proc/locks", "/proc/kcore", "/proc/fs",
)

# (module class, regex on the lower-case name without .ko). First match wins.
MODULE_RULES = (
    ("netfilter", r"^(?:nf_|nft_|xt_|ipt_|ip6t_|ebt_|arpt_|iptable_|ip6table_|ebtable|arptable|"
                  r"nfnetlink|x_tables|ip_tables|ip6_tables|ip_conntrack|ip_nat|ip_set|nf$)"),
    ("watchdog", r"wdt|watchdog|wdog"),
    ("i2c", r"i2c"),
    ("mtd", r"mtd|nand|^ubi|cfi_|jedec|m25p80|spi[_-]nor"),
    ("spi", r"spi"),
    ("led", r"(?:^|[_-])leds?(?:[_-]|$)|^ledtrig"),
    ("gpio", r"gpio"),
    ("usb", r"usb|[eoux]hci"),
    ("wlan", r"^wl(?:$|_|\d)|wlan|wifi|80211|^ath|^rt[235]|^rtl8|^mt7|^dhd|^qca|^umac|^mwl|"
             r"^bcm43|^brcmf"),
    ("ethernet", r"^et$|eth|^robo|bcm57|gmac|^ag71|switch|rtl83|^phy|mii|^r8169|^e100|enet|^ctf$"),
)
_MODULE_RX = tuple((cls, re.compile(rx)) for cls, rx in MODULE_RULES)
MODULE_TO_PERIPHERAL = {"watchdog": "watchdog", "i2c": "i2c", "spi": "spi", "gpio": "gpio",
                        "led": "led", "wlan": "wlan", "mtd": "mtd"}   # ethernet/usb/netfilter/other: none

IOCTL_RULES = (("I2C_", "i2c"), ("SPI_IOC_", "spi"), ("WDIOC_", "watchdog"), ("GPIO", "gpio"),
               ("MEM", "mtd"))
IOCTL_NAMES = frozenset((
    "I2C_RDWR", "I2C_SLAVE", "I2C_SLAVE_FORCE", "I2C_SMBUS", "I2C_FUNCS", "I2C_TENBIT",
    "I2C_RETRIES", "I2C_TIMEOUT", "I2C_PEC",
    "SPI_IOC_MESSAGE", "SPI_IOC_RD_MODE", "SPI_IOC_WR_MODE", "SPI_IOC_RD_MODE32",
    "SPI_IOC_WR_MODE32", "SPI_IOC_RD_LSB_FIRST", "SPI_IOC_WR_LSB_FIRST",
    "SPI_IOC_RD_BITS_PER_WORD", "SPI_IOC_WR_BITS_PER_WORD", "SPI_IOC_RD_MAX_SPEED_HZ",
    "SPI_IOC_WR_MAX_SPEED_HZ",
    "WDIOC_KEEPALIVE", "WDIOC_SETTIMEOUT", "WDIOC_GETTIMEOUT", "WDIOC_SETOPTIONS",
    "WDIOC_GETSUPPORT", "WDIOC_GETSTATUS", "WDIOC_GETBOOTSTATUS", "WDIOC_SETPRETIMEOUT",
    "GPIO_GET_CHIPINFO_IOCTL", "GPIO_GET_LINEINFO_IOCTL", "GPIO_GET_LINEHANDLE_IOCTL",
    "GPIO_GET_LINEEVENT_IOCTL", "GPIOHANDLE_GET_LINE_VALUES_IOCTL",
    "GPIOHANDLE_SET_LINE_VALUES_IOCTL", "GPIO_V2_GET_LINE_IOCTL",
    "MEMGETINFO", "MEMERASE", "MEMERASE64", "MEMWRITEOOB", "MEMREADOOB", "MEMLOCK", "MEMUNLOCK",
    "MEMGETBADBLOCK", "MEMSETBADBLOCK", "MEMGETREGIONCOUNT", "MEMGETREGIONINFO",
))

# class -> (status when referenced, FirmAE mechanism that provides it)
PERIPHERAL_SUPPORT = {
    "i2c": ("unsupported", None),
    "spi": ("unsupported", None),
    "gpio": ("referenced", None),
    "watchdog": ("referenced", None),
    "led": ("referenced", None),
    "mtd": ("covered", "nandsim (empty NAND MTD)"),
    "nvram": ("covered", "libnvram (LD_PRELOAD)"),
    "uart": ("covered", "QEMU serial port"),
    "wlan": ("referenced", None),
    "other": ("referenced", None),
}

# dynamic["events"] kinds -> class; kinds whose samples are searched for
# /dev paths and *.ko names; kinds that belong to no class (notes only)
EVENT_CLASSES = {"gpio_error": "gpio", "watchdog_error": "watchdog", "mtd_error": "mtd"}
EVENTS_WITH_PATHS = ("device_open_failed", "no_such_device", "module_load_failed")
GENERAL_EVENTS = ("hook_register_failed", "segfault", "kernel_panic")

NOTE_IOCTL = ("ioctl_hints are string-level hints (request names found as text), "
              "not observed ioctl calls")

# One pass finds both kinds. Linear: literal prefix + one bounded class each.
_SCAN_RX = re.compile(
    rb"(?<![A-Za-z0-9_.\-])(/(?:dev|sys|proc)/[A-Za-z0-9_./\-]{1,%d})"
    rb"|(?<![A-Za-z0-9_])((?:I2C_|SPI_IOC_|WDIOC_|GPIO|MEM)[A-Z0-9_]{2,40})" % MAX_PATH_TAIL)
_KO_RX = re.compile(r"[A-Za-z0-9_.\-]{1,64}\.ko\b")
_SAN_TABLE = bytes(c if 0x20 <= c < 0x7F else 0x3F for c in range(256))


class HwProfileError(Exception):
    """Static scan or output failed (CLI exit 1)."""


class TarballError(HwProfileError):
    """The tarball cannot be read at all (not a file, not a tar, corrupt)."""


class _Stop(Exception):
    """A bound was hit; `reason` goes to limits_hit."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------- helpers

def sanitize(value, limit=None):
    """Printable ASCII only (others -> '?'), at most `limit` (MAX_STR) characters."""
    limit = MAX_STR if limit is None else limit
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value[:limit + 1])
    else:
        text = str(value)[:limit + 1]
        try:
            raw = text.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            raw = text.encode("utf-8", "replace")
    out = raw.translate(_SAN_TABLE).decode("ascii")
    if len(out) > limit:
        out = out[:max(0, limit - 3)] + "..."
    return out


def classify_path(path):
    """Class of a /dev, /sys or /proc path from PATH_RULES; IGNORE; or None."""
    for pattern, cls in PATH_RULES:
        if pattern.endswith("*"):
            if path.startswith(pattern[:-1]):
                return cls
        elif path == pattern:
            return cls
    return None


def classify_module(name):
    """Module class of a kernel module file name (e.g. 'sys-watchdog.ko')."""
    stem = name.lower()
    for ext in (".ko.gz", ".ko.xz", ".ko"):
        if stem.endswith(ext):
            stem = stem[:-len(ext)]
            break
    for cls, rx in _MODULE_RX:
        if rx.search(stem):
            return cls
    return "other"


def classify_ioctl(name):
    for prefix, cls in IOCTL_RULES:
        if name.startswith(prefix):
            return cls
    return None


def _proc_ignored(path):
    return any(path == p or path.startswith(p + "/") for p in PROC_IGNORE)


def _is_module_name(base):
    return base.endswith((".ko", ".ko.gz", ".ko.xz")) and len(base) > 3


def _int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def iter_matches(blocks):
    """Yield ("path"|"ioctl", bytes) for every match in the concatenation of
    `blocks`, exactly as one finditer over the whole content would, while
    holding only one block plus KEEP bytes. A match that starts before
    `limit` (len(buf) - KEEP) is complete within buf (matches are shorter than
    KEEP); later ones are found again in the next round."""
    keep = KEEP
    buf = b""
    base = 0          # absolute offset of buf[0]
    resume = 0        # absolute offset where the next search starts
    for block in blocks:
        if not block:
            continue
        buf = buf + block if buf else block
        limit = len(buf) - keep
        if limit <= 0:
            continue
        for m in _SCAN_RX.finditer(buf, resume - base):
            if m.start() >= limit:
                break
            yield _kind(m)
            resume = base + m.end()
        resume = max(resume, base + limit)
        cut = limit - 1                # one byte before `limit` for the lookbehind
        buf = buf[cut:]
        base += cut
    for m in _SCAN_RX.finditer(buf, max(0, resume - base)):
        yield _kind(m)


def _kind(m):
    if m.group(1) is not None:
        return "path", m.group(1)
    return "ioctl", m.group(2)


def _member_path(name):
    """'./dev/mtd0' -> '/dev/mtd0' (a label, never used as a host path)."""
    while name.startswith("./"):
        name = name[2:]
    return "/" + name.lstrip("/")


# ---------------------------------------------------------------- stream

def _check_memory():
    """Soft memory guard of the CLI: stop the scan (a clean _Stop, raised by
    our own reader) while the address space is still below RLIMIT_AS.
    Reaching the hard limit is not a reliable way out: CPython can spin in C
    re-raising the MemoryError (seen in tarfile's `raise e` with VmSize pinned
    at the limit) where no Python-level deadline check runs."""
    try:
        pages = int(os.pread(_MEM_GUARD[1], 64, 0).split(None, 1)[0])
    except (OSError, ValueError, IndexError):
        return
    if pages * _PAGE > _MEM_GUARD[0]:
        raise _Stop("memory")


_PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def _arm_mem_guard(limit_bytes):
    """Stop scanning at 75% of limit_bytes (or limit - 64 MiB, the lower one),
    measured from /proc/self/statm; silently off where that does not exist."""
    if not hasattr(os, "pread"):
        return
    try:
        fd = os.open("/proc/self/statm", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return
    _MEM_GUARD[:] = [min(limit_bytes * 3 // 4, limit_bytes - (64 << 20)), fd]


def _arm_hard_deadline(seconds):
    """CLI only: end the process (exit 1) `seconds` from now whatever it is
    doing, from faulthandler's C watchdog thread: --timeout then also holds
    when the main thread is stuck in C code. The thread dump goes to
    /dev/null (no traceback on the terminal)."""
    try:
        import faulthandler
        f = open(os.devnull, "w")
        faulthandler.dump_traceback_later(seconds, exit=True, file=f)
    except Exception:
        return
    _HARD_DEADLINE_FILE[:] = [f]


class _Budget:
    def __init__(self, deadline):
        self.deadline = deadline
        self.stream = 0

    def check_time(self):
        if time.monotonic() > self.deadline:
            raise _Stop("time")

    def add_stream(self, n):
        self.stream += n
        if self.stream > MAX_STREAM_BYTES:
            raise _Stop("stream_bytes")


class _BoundedReader:
    """Forward-only file object for tarfile over the decompressed stream.
    Every byte is counted against MAX_STREAM_BYTES, every read checks the
    deadline, a single read is at most MAX_HEADER_READ bytes, a forward seek
    reads (and counts) the skipped bytes, and a backward seek is served from
    the last HIST bytes only (tarfile seeks back one byte after a member
    whose size is a multiple of 512).
    Between begin_header() and end_header() (one tarfile.next()) every byte
    requested by read() is also counted against MAX_HEADER_BYTES, before it
    is read: tarfile reads the sparse map and the GNU 'S' extension blocks
    512 bytes at a time into unbounded lists, so a per-read cap alone does
    not bound them. Seeks (skipping member data) are not header bytes."""

    def __init__(self, raw, budget):
        self._raw = raw
        self._budget = budget
        self._pos = 0              # logical position
        self._end = 0              # bytes pulled from raw
        self._hist = bytearray()   # raw bytes [end - len(hist), end)
        self._header = None        # header bytes of the current next(), or None
        self._reads = 0

    def begin_header(self):
        self._header = 0

    def end_header(self):
        self._header = None

    def tell(self):
        return self._pos

    def _pull(self, n):
        self._budget.check_time()
        data = self._raw.read(n)
        self._budget.add_stream(len(data))
        self._end += len(data)
        self._hist += data
        if len(self._hist) > 2 * HIST:
            del self._hist[:-HIST]
        return data

    def read(self, n=-1):
        if n is None or n < 0 or n > MAX_HEADER_READ:
            raise _Stop("header_size")
        if self._header is not None:
            self._header += n
            if self._header > MAX_HEADER_BYTES:
                raise _Stop("header_size")
        self._reads += 1
        if _MEM_GUARD[0] and (n >= 65536 or not self._reads & 63):
            _check_memory()
        parts = []
        if self._pos < self._end and n > 0:
            start = len(self._hist) - (self._end - self._pos)
            chunk = bytes(self._hist[start:start + n])
            self._pos += len(chunk)
            n -= len(chunk)
            parts.append(chunk)
        while n > 0:
            data = self._pull(n)
            if not data:
                break
            self._pos += len(data)
            n -= len(data)
            parts.append(data)
        return b"".join(parts)

    def seek(self, offset, whence=0):
        if whence == 1:
            offset += self._pos
        elif whence != 0:
            raise _Stop("seek")
        if offset < self._end - len(self._hist) or offset < 0:
            raise _Stop("backward_seek")
        if offset <= self._end:
            self._pos = offset
            return offset
        self._pos = self._end
        while self._end < offset:
            if not self._pull(min(CHUNK, offset - self._end)):
                break
            self._pos = self._end
        return self._pos

    def seekable(self):
        return True

    def readable(self):
        return True


class _XZReader:
    """Minimal read(n) over one or more concatenated .xz streams, decoded with
    memlimit=MAX_XZ_MEMORY (lzma.LZMAFile has no memory limit; the dictionary
    size comes from the attacker's block header). Exceeding the limit stops
    the scan with "xz_memory". Like LZMAFile, data after the last stream that
    is not a valid stream (e.g. stream padding) ends the input."""

    def __init__(self, raw):
        self._raw = raw
        self._dec = self._new()
        self._eof = False

    @staticmethod
    def _new():
        return lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_XZ_MEMORY)

    def _decompress(self, data, n, trailing=False):
        try:
            return self._dec.decompress(data, n)
        except lzma.LZMAError as e:
            if "memory usage limit" in str(e).lower():     # LZMA_MEMLIMIT_ERROR
                raise _Stop("xz_memory")
            if trailing:
                self._eof = True
                return b""
            raise

    def read(self, n=CHUNK):
        n = CHUNK if n is None or n < 0 else n
        while not self._eof and n > 0:
            if self._dec.eof:
                rest = self._dec.unused_data or self._raw.read(CHUNK)
                if not rest:
                    self._eof = True
                    break
                self._dec = self._new()
                data = self._decompress(rest, n, trailing=True)
            elif self._dec.needs_input:
                chunk = self._raw.read(CHUNK)
                if not chunk:
                    raise EOFError("xz stream ended before the end-of-stream marker")
                data = self._decompress(chunk, n)
            else:
                data = self._decompress(b"", n)
            if data:
                return data
        return b""

    def close(self):
        pass                       # the raw file is closed by the caller


def _open_decompressed(path):
    """(raw file, decompressing reader) for a regular file; never blocks on a FIFO."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_BINARY", 0))
    except OSError as e:
        raise TarballError("cannot open %s: %s" % (path, e.strerror or e))
    raw = os.fdopen(fd, "rb")
    try:
        if not stat.S_ISREG(os.fstat(raw.fileno()).st_mode):
            raise TarballError("%s is not a regular file" % path)
        magic = raw.read(6)
        raw.seek(0)
        if magic[:2] == b"\x1f\x8b":
            dec = gzip.GzipFile(fileobj=raw, mode="rb")
        elif magic[:3] == b"BZh" and bz2 is not None:
            dec = bz2.BZ2File(raw)
        elif magic == b"\xfd7zXZ\x00" and lzma is not None:
            dec = _XZReader(raw)
        else:
            dec = raw
    except BaseException:
        raw.close()
        raise
    return raw, dec


# ---------------------------------------------------------------- static scan

class _Static:
    def __init__(self):
        self.scanned_members = 0
        self.scanned_files = 0
        self.elf_files = 0
        self.bytes_scanned = 0
        self.limits = set()
        self.device_paths = {}
        self.sys_proc_paths = {}
        self.ioctl_hints = {}
        self.modules = {}
        self.nodes = set()

    def limit(self, name):
        self.limits.add(name)

    def record(self, table, tname, key, label, seen):
        if key in seen:
            return
        entry = table.get(key)
        if entry is None:
            if len(table) >= MAX_KEYS:
                self.limit("keys:" + tname)
                return
            entry = table[key] = {"count": 0, "files": []}
        seen.add(key)
        entry["count"] += 1
        if len(entry["files"]) < MAX_SAMPLE_FILES:
            entry["files"].append(label)

    def result(self):
        limits = sorted(self.limits)
        return {
            "scanned_members": self.scanned_members,
            "scanned_files": self.scanned_files,
            "elf_files": self.elf_files,
            "bytes_scanned": self.bytes_scanned,
            "truncated": bool(limits),
            "limits_hit": limits,
            "device_paths": self.device_paths,
            "sys_proc_paths": self.sys_proc_paths,
            "ioctl_hints": self.ioctl_hints,
            "kernel_modules": [{"name": n, "class": c} for n, c in sorted(self.modules.items())],
            "device_nodes": [{"path": p, "type": t, "major": a, "minor": b}
                             for p, t, a, b in sorted(self.nodes)],
        }


def _scan_content(tar, member, label, st, budget):
    remaining = MAX_TOTAL_BYTES - st.bytes_scanned
    if remaining <= 0:
        st.limit("total_bytes")
        return
    f = tar.extractfile(member)
    if f is None:
        return
    cap = min(MAX_FILE_BYTES, remaining)
    if member.size > MAX_FILE_BYTES:
        st.limit("file_bytes")
    if member.size > remaining:
        st.limit("total_bytes")
    st.scanned_files += 1
    state = {"read": 0}

    def blocks():
        while state["read"] < cap:
            budget.check_time()
            block = f.read(min(CHUNK, cap - state["read"]))
            if not block:
                return
            state["read"] += len(block)
            st.bytes_scanned += len(block)
            yield block

    gen = blocks()
    first = next(gen, b"")
    if first[:4] == b"\x7fELF":
        st.elf_files += 1
    seen_paths, seen_sys, seen_ioctl = set(), set(), set()
    for kind, raw in iter_matches(itertools.chain((first,), gen)):
        text = raw.decode("ascii")
        if kind == "ioctl":
            if text in IOCTL_NAMES:
                st.record(st.ioctl_hints, "ioctl_hints", text, label, seen_ioctl)
            continue
        path = text.rstrip("./")
        if path.count("/") < 2:            # "/dev", "/sys/" ...
            continue
        if path.startswith("/dev/"):
            st.record(st.device_paths, "device_paths", path, label, seen_paths)
        elif path.startswith("/proc/") and _proc_ignored(path):
            continue
        else:
            st.record(st.sys_proc_paths, "sys_proc_paths", path, label, seen_sys)


def _note_member(member, st):
    """Header-only information: kernel modules and device nodes."""
    if member.ischr() or member.isblk():
        if len(st.nodes) >= MAX_KEYS:
            st.limit("keys:device_nodes")
        else:
            st.nodes.add((sanitize(_member_path(member.name)), "c" if member.ischr() else "b",
                          _int(member.devmajor), _int(member.devminor)))
        return
    if not (member.isreg() or member.islnk()):
        return
    base = member.name.rsplit("/", 1)[-1]
    if _is_module_name(base):
        name = sanitize(base)
        if name not in st.modules:
            if len(st.modules) >= MAX_KEYS:
                st.limit("keys:kernel_modules")
            else:
                st.modules[name] = classify_module(name)


def scan_tarball(path, *, deadline=None):
    """Static section of the profile for the rootfs tarball `path` (gzip,
    bzip2, xz or plain tar). `deadline` is a time.monotonic() value (default:
    now + DEFAULT_TIMEOUT); when it passes the result so far is returned with
    truncated=True and "time" in limits_hit. Raises TarballError when the
    tarball cannot be read at all; a read error after the first member gives a
    partial result with "read_error". A bound, a RecursionError
    ("header_nesting") or a MemoryError ("memory") give the partial result."""
    if deadline is None:
        deadline = time.monotonic() + DEFAULT_TIMEOUT
    budget = _Budget(deadline)
    st = _Static()
    raw, dec = _open_decompressed(path)
    hit = None
    try:
        reader = _BoundedReader(dec, budget)
        reader.begin_header()              # TarFile() already reads the first member
        tar = tarfile.TarFile(fileobj=reader, mode="r", encoding="utf-8", errors="surrogateescape")
        while True:
            budget.check_time()
            reader.begin_header()
            member = tar.next()
            reader.end_header()
            if member is None:
                break
            tar.members = []               # stream: do not keep 200 000 TarInfo objects
            _check_pax_globals(tar)
            if st.scanned_members >= MAX_MEMBERS:
                st.limit("members")
                break
            st.scanned_members += 1
            _note_member(member, st)
            if member.issparse():
                st.limit("sparse_member")  # listed, content not scanned
            elif member.isreg() and member.size > 0:   # never symlinks, hard links, devices
                _scan_content(tar, member, sanitize(member.name), st, budget)
    # The handlers only bind a constant: after a MemoryError the traceback
    # (and the objects it keeps) is released when the handler ends.
    except _Stop as e:
        hit = e.reason
    except RecursionError:                 # pax / long-name chains recurse in tarfile
        hit = "header_nesting"
    except MemoryError:
        _RESERVE.clear()                   # headroom for the partial result and the write
        hit = "memory"
    except Exception as e:                 # TarError, OSError, EOFError, zlib/lzma errors, and
        if st.scanned_members == 0:        # whatever else tarfile raises on a malformed header
            raise TarballError("cannot read tarball %s: %s: %s"
                               % (path, type(e).__name__, sanitize(e))) from None
        hit = "read_error"
    finally:
        try:
            dec.close()
        finally:
            raw.close()
    if hit is not None:
        st.limit(hit)
    return st.result()


def _check_pax_globals(tar):
    """tarfile keeps global pax ('g') headers for the rest of the archive and
    copies them for every member with an extended header: bound them."""
    glob = tar.pax_headers
    if glob and (len(glob) > MAX_PAX_GLOBAL_KEYS or
                 sum(len(k) + len(v) for k, v in glob.items()) > MAX_HEADER_BYTES):
        raise _Stop("pax_headers")


# ---------------------------------------------------------------- profile

def _clean(obj, depth=0):
    """Deep copy with every string sanitized and every container bounded."""
    if depth > 8:
        return None
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, (str, bytes)):
        return sanitize(obj)
    if isinstance(obj, dict):
        return {sanitize(k): _clean(v, depth + 1)
                for k, v in itertools.islice(obj.items(), 10 * MAX_KEYS)}
    if isinstance(obj, (list, tuple)):
        return [_clean(v, depth + 1) for v in itertools.islice(obj, 10 * MAX_KEYS)]
    return None


def _dict(obj, key):
    value = obj.get(key) if isinstance(obj, dict) else None
    return value if isinstance(value, dict) else {}


def _list(obj, key):
    value = obj.get(key) if isinstance(obj, dict) else None
    return value if isinstance(value, list) else []


def _paths_in(text):
    for kind, raw in iter_matches((text.encode("ascii", "replace"),)):
        if kind == "path":
            yield raw.decode("ascii").rstrip("./")


def build_profile(static, dynamic=None):
    """The full profile: schema, static, dynamic, peripherals, notes."""
    static = _clean(static) if isinstance(static, dict) else {}
    dynamic = _clean(dynamic) if isinstance(dynamic, dict) else None
    refs = {c: [] for c in PERIPHERALS}      # (sort key, text)
    fails = {c: [] for c in PERIPHERALS}
    notes = [NOTE_IOCTL]

    for section in ("device_paths", "sys_proc_paths"):
        for path, entry in _dict(static, section).items():
            cls = classify_path(path)
            if cls in refs:
                n = _int(entry.get("count")) if isinstance(entry, dict) else 0
                refs[cls].append(((0, -n, path), "static %s (%d files)" % (path, n)))
    for name, entry in _dict(static, "ioctl_hints").items():
        cls = classify_ioctl(name)
        if cls in refs:
            n = _int(entry.get("count")) if isinstance(entry, dict) else 0
            refs[cls].append(((1, -n, name), "ioctl-hint %s (%d files)" % (name, n)))
    for mod in _list(static, "kernel_modules"):
        if isinstance(mod, dict) and isinstance(mod.get("name"), str):
            cls = MODULE_TO_PERIPHERAL.get(mod.get("class"))
            if cls:
                refs[cls].append(((2, 0, mod["name"]), "module %s" % mod["name"]))
    for node in _list(static, "device_nodes"):
        if isinstance(node, dict) and isinstance(node.get("path"), str):
            cls = classify_path(node["path"])
            if cls in refs:
                refs[cls].append(((3, 0, node["path"]), "node %s %s %d:%d" % (
                    node["path"], node.get("type") if node.get("type") in ("c", "b") else "?",
                    _int(node.get("major")), _int(node.get("minor")))))

    if dynamic is not None:
        device_fail = module_fail = False
        for path, info in sorted(_dict(dynamic, "devices").items()):
            cls = classify_path(path)
            if cls not in refs:
                continue
            errors = _int(info.get("errors")) if isinstance(info, dict) else 0
            if errors:
                fails[cls].append(((0, -errors, path), "runtime %s errors=%d" % (path, errors)))
                device_fail = True
            else:
                refs[cls].append(((4, 0, path), "runtime %s (no errors)" % path))
        # dynamic["modules"]: exact per-module error counts (newer hwserial).
        # Without it, fall back to the event samples below.
        counted = isinstance(dynamic.get("modules"), dict)
        for name, info in sorted(_dict(dynamic, "modules").items()):
            cls = MODULE_TO_PERIPHERAL.get(classify_module(name))
            if not cls:
                continue
            errors = _int(info.get("errors")) if isinstance(info, dict) else 0
            if errors:
                fails[cls].append(((0, -errors, name), "runtime module %s errors=%d" % (name, errors)))
                module_fail = True
            else:
                refs[cls].append(((4, 0, name), "runtime module %s (no errors)" % name))
        events = _dict(dynamic, "events")
        for kind in sorted(events):
            ev = events[kind]
            count = _int(ev.get("count")) if isinstance(ev, dict) else 0
            if not count:
                continue
            samples = [s for s in _list(ev, "samples") if isinstance(s, str)][:20]
            first = (": " + sanitize(samples[0], 100)) if samples else ""
            if kind in EVENT_CLASSES:
                fails[EVENT_CLASSES[kind]].append(((1, -count, kind), "event %s x%d%s" % (kind, count, first)))
                continue
            classified = False
            if kind in EVENTS_WITH_PATHS and counted:
                # the counters above already classified every module / device
                classified = module_fail if kind == "module_load_failed" else device_fail
            elif kind in EVENTS_WITH_PATHS:
                for sample in samples:
                    found = set()
                    for path in _paths_in(sample):
                        cls = classify_path(path)
                        if cls in fails:
                            found.add((cls, path))
                    for ko in _KO_RX.findall(sample):
                        cls = MODULE_TO_PERIPHERAL.get(classify_module(ko))
                        if cls:
                            found.add((cls, ko))
                    for cls, what in sorted(found):
                        fails[cls].append(((2, 0, what), "event %s %s" % (kind, what)))
                        classified = True
            if not classified:
                notes.append("dynamic: %s x%d%s" % (kind, count, first))

    peripherals = {}
    for cls in PERIPHERALS:
        status_if_ref, mechanism = PERIPHERAL_SUPPORT[cls]
        if fails[cls]:
            status = "failing"
        elif refs[cls]:
            status = status_if_ref
        else:
            status = "not-referenced"
        items = [t for _, t in sorted(set(fails[cls]))] + [t for _, t in sorted(set(refs[cls]))]
        evidence = items[:MAX_EVIDENCE]
        if len(items) > MAX_EVIDENCE:
            evidence.append("... and %d more" % (len(items) - MAX_EVIDENCE))
        if mechanism and status != "not-referenced":
            evidence.append("firmae: %s" % mechanism)
        peripherals[cls] = {"status": status, "evidence": [sanitize(e) for e in evidence]}

    if static.get("truncated"):
        notes.append("static scan incomplete (truncated); limits hit: %s" %
                     (", ".join(s for s in _list(static, "limits_hit") if isinstance(s, str)) or "?"))
    if dynamic is None:
        notes.append("no dynamic data (no serial log scanned): statuses rest on the rootfs only")
    for status, text in (("unsupported", "UNSUPPORTED (referenced, FirmAE has no emulation for it): %s"),
                         ("failing", "FAILING at runtime: %s")):
        hit = [c for c in PERIPHERALS if peripherals[c]["status"] == status]
        if hit:
            notes.append(text % ", ".join(hit))
    if any(peripherals[c]["status"] == "referenced" for c in ("gpio", "watchdog")):
        notes.append("gpio/watchdog: the FirmAE kernel's devfs stubs accept open/ioctl on /dev/gpio, "
                     "/dev/watchdog and /dev/wdt without real data; 'referenced' is not 'working'")
    return {"schema": SCHEMA, "static": static, "dynamic": dynamic,
            "peripherals": peripherals, "notes": [sanitize(n) for n in notes]}


# ---------------------------------------------------------------- output

def _dumps(profile):
    return json.dumps(profile, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def _weight(value):
    if isinstance(value, dict):
        return -max(_int(value.get("count")), _int(value.get("errors")))
    return 0


def _is_table(value):
    return isinstance(value, dict) and bool(value) and all(isinstance(v, dict) for v in value.values())


def _biggest(obj):
    """Largest table/list length below obj."""
    if isinstance(obj, dict):
        own = len(obj) if _is_table(obj) else 0
        return max([own] + [_biggest(v) for v in obj.values()])
    if isinstance(obj, list):
        return max([len(obj)] + [_biggest(v) for v in obj])
    return 0


def _shrink(obj, k):
    """Keep at most k entries in every table (dict of dicts: the k with the
    highest count/errors) and list below obj; record dicts keep all their
    fields, limits_hit lists are kept whole."""
    if isinstance(obj, dict):
        for key in list(obj):
            value = obj[key]
            if key == "limits_hit":
                continue
            if _is_table(value) and len(value) > k:
                keep = sorted(value, key=lambda x: (_weight(value[x]), str(x)))[:k]
                obj[key] = value = {x: value[x] for x in keep}
            elif isinstance(value, list) and len(value) > k:
                obj[key] = value = value[:k]
            _shrink(value, k)
    elif isinstance(obj, list):
        for value in obj:
            _shrink(value, k)


def fit_profile(profile, max_bytes=None):
    """Trim `profile` in place until its JSON is at most max_bytes
    (MAX_PROFILE_BYTES): first the sample file lists, then the number of
    entries per dict/list of the static and dynamic sections. The peripherals
    section is never touched. Marks "profile_size" in static.limits_hit."""
    limit = MAX_PROFILE_BYTES if max_bytes is None else max_bytes
    size = len(_dumps(profile))
    if size <= limit:
        return profile
    static = profile.get("static")
    if not isinstance(static, dict):
        static = profile["static"] = {}
    hits = [h for h in _list(static, "limits_hit") if isinstance(h, str)]
    static["limits_hit"] = sorted(set(hits) | {"profile_size"})
    static["truncated"] = True
    notes = profile.setdefault("notes", [])
    notes.append("profile trimmed from %d bytes to fit %d bytes (fewer keys / sample files "
                 "in static and dynamic; peripherals complete)" % (size, limit))
    sections = [s for s in (static, profile.get("dynamic")) if isinstance(s, dict)]
    k = MAX_SAMPLE_FILES
    while len(_dumps(profile)) > limit and k > 1:      # sample lists first
        k -= 1
        for s in sections:
            for table in ("device_paths", "sys_proc_paths", "ioctl_hints"):
                for entry in _dict(s, table).values():
                    if isinstance(entry, dict) and isinstance(entry.get("files"), list):
                        entry["files"] = entry["files"][:k]
    k = max([_biggest(s) for s in sections] + [0])
    while len(_dumps(profile)) > limit and k > 0:
        k //= 2
        for s in sections:
            _shrink(s, k)
    if len(_dumps(profile)) > limit:
        profile["notes"] = notes[:100]
    return profile


def write_profile(out_path, profile):
    """Write `profile` as JSON to out_path atomically (temporary file in the
    same directory + os.replace). Refuses a target that is a symlink or not a
    regular file. Raises HwProfileError."""
    data = _dumps(profile).encode("ascii")
    directory = os.path.dirname(os.path.abspath(out_path))
    base = os.path.basename(out_path)
    if not base or base in (".", ".."):
        raise HwProfileError("invalid output path %r" % out_path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    use_dirfd = os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY")
    dfd = None
    tmp = ".%s.tmp-%s" % (base, secrets.token_hex(8))
    try:
        if use_dirfd:
            dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
            target, tmp_path = base, tmp
        else:
            target, tmp_path = os.path.join(directory, base), os.path.join(directory, tmp)
        try:
            st = os.lstat(target, dir_fd=dfd) if use_dirfd else os.lstat(target)
        except FileNotFoundError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            raise HwProfileError("refusing to write %s: it is a symlink" % out_path)
        if st is not None and not stat.S_ISREG(st.st_mode):
            raise HwProfileError("refusing to write %s: not a regular file" % out_path)
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_BINARY", 0))
        fd = os.open(tmp_path, flags, 0o600, dir_fd=dfd) if use_dirfd else os.open(tmp_path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
                if hasattr(os, "fchmod"):
                    mask = os.umask(0)
                    os.umask(mask)
                    os.fchmod(f.fileno(), 0o640 & ~mask)
            if use_dirfd:
                os.replace(tmp_path, target, src_dir_fd=dfd, dst_dir_fd=dfd)
            else:
                os.replace(tmp_path, target)
        except BaseException:
            try:
                if use_dirfd:
                    os.unlink(tmp_path, dir_fd=dfd)
                else:
                    os.unlink(tmp_path)
            except OSError:
                pass
            raise
        if dfd is not None:
            try:
                os.fsync(dfd)
            except OSError:
                pass
    except OSError as e:
        raise HwProfileError("cannot write %s: %s" % (out_path, e.strerror or e))
    finally:
        if dfd is not None:
            os.close(dfd)


def _read_profile(path):
    """An existing profile (for --update); never through a symlink, bounded."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise HwProfileError("cannot read existing profile %s: %s" % (path, e.strerror or e))
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise HwProfileError("existing profile %s is not a regular file" % path)
        raw = f.read(MAX_EXISTING_PROFILE + 1)
    if len(raw) > MAX_EXISTING_PROFILE:
        raise HwProfileError("existing profile %s is too large" % path)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as e:
        raise HwProfileError("existing profile %s is not valid JSON: %s" % (path, e))
    if not isinstance(data, dict) or not isinstance(data.get("static"), dict):
        raise HwProfileError("existing profile %s has no static section" % path)
    return data


def _scan_serial(paths, deadline=None):
    """(dynamic or None, notes). firmae.hwserial is optional; `deadline`
    (time.monotonic() value) is passed on when hwserial accepts it."""
    try:
        from firmae.hwserial import scan_serial_logs
    except Exception as e:      # ImportError, or a broken module
        return None, ["hwserial unavailable (%s: %s); dynamic section empty" % (type(e).__name__, e)]
    try:
        if deadline is None:
            dynamic = scan_serial_logs(list(paths))
        else:
            try:
                dynamic = scan_serial_logs(list(paths), deadline=deadline)
            except TypeError:   # older hwserial without the keyword
                dynamic = scan_serial_logs(list(paths))
    except Exception as e:
        return None, ["serial log scan failed (%s: %s); dynamic section empty" % (type(e).__name__, e)]
    if not isinstance(dynamic, dict):
        return None, ["serial log scan returned %s, not a dict; dynamic section empty"
                      % type(dynamic).__name__]
    return dynamic, []


def _summary(profile, out, elapsed):
    st = profile.get("static") or {}
    per = " ".join("%s=%s" % (c, profile["peripherals"][c]["status"]) for c in PERIPHERALS)
    return ("hwprofile: %s members=%s files=%s elf=%s bytes=%s truncated=%s dynamic=%s %s (%.1fs)" % (
        sanitize(out), _int(st.get("scanned_members")), _int(st.get("scanned_files")),
        _int(st.get("elf_files")), _int(st.get("bytes_scanned")),
        "yes" if st.get("truncated") else "no", "no" if profile.get("dynamic") is None else "yes",
        per, elapsed))


def _parser():
    p = argparse.ArgumentParser(prog="python3 -m firmae.hwprofile",
                                description="Hardware dependency profile of a firmware rootfs.")
    p.add_argument("--tar", help="rootfs tarball (images/<IID>.tar.gz)")
    p.add_argument("--out", required=True, help="profile JSON to write")
    p.add_argument("--serial-log", action="append", default=[], metavar="LOG",
                   help="serial log of an emulation run (repeatable)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help="time budget in seconds of the static scan; the serial log scan "
                        "gets what is left of it (default %(default)s)")
    p.add_argument("--update", action="store_true",
                   help="keep the static section of --out, rescan the serial logs")
    p.add_argument("--mem-limit-mb", type=int, default=DEFAULT_MEM_LIMIT_MB, metavar="MiB",
                   help="address space limit of this process (RLIMIT_AS) in MiB, 0 = none "
                        "(default %(default)s)")
    return p


def _set_mem_limit(mb):
    """Lower this process's RLIMIT_AS soft limit to `mb` MiB (never above the
    hard limit). Returns a note when it could not be applied, else None."""
    if not mb:
        return None
    if resource is None or not hasattr(resource, "RLIMIT_AS"):
        return "memory limit not applied (no RLIMIT_AS on this platform)"
    want = mb << 20
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        if hard != resource.RLIM_INFINITY:
            want = min(want, hard)
        if soft == resource.RLIM_INFINITY or want < soft:
            resource.setrlimit(resource.RLIMIT_AS, (want, hard))
    except (ValueError, OSError) as e:
        return "memory limit not applied (%s: %s)" % (type(e).__name__, e)
    return None


def _current_as_limit():
    try:
        soft = resource.getrlimit(resource.RLIMIT_AS)[0]
    except Exception:
        return 0
    return 0 if soft == resource.RLIM_INFINITY else soft


def main(argv=None, set_rlimit=False):
    """CLI entry point; returns the exit code. Never prints a traceback:
    an unexpected error becomes one error line and exit 1 (KeyboardInterrupt
    and SystemExit are not caught). RLIMIT_AS (--mem-limit-mb) is set only
    with set_rlimit=True, which the `python3 -m firmae.hwprofile` entry point
    passes: calling main() in-process (tests) does not limit the caller."""
    try:
        return _main(argv, set_rlimit)
    except MemoryError:
        _RESERVE.clear()
        hit = "out of memory"
    except RecursionError:
        hit = "recursion limit reached"
    except Exception as e:
        hit = "unexpected %s: %s" % (type(e).__name__, sanitize(e))
    try:
        print("hwprofile: error: %s" % hit, file=sys.stderr)
    except Exception:
        pass
    return 1


def _main(argv, set_rlimit):
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2
    err = None
    if args.update and args.tar:
        err = "--update and --tar are mutually exclusive"
    elif not args.update and not args.tar:
        err = "--tar is required (or --update with --serial-log)"
    elif args.update and not args.serial_log:
        err = "--update needs at least one --serial-log"
    elif not (math.isfinite(args.timeout) and args.timeout > 0):
        err = "--timeout must be a positive number"
    elif args.mem_limit_mb < 0:
        err = "--mem-limit-mb must be >= 0"
    if err:
        parser.print_usage(sys.stderr)
        print("hwprofile: error: %s" % err, file=sys.stderr)
        return 2

    t0 = time.monotonic()
    notes = []
    if set_rlimit:
        _arm_hard_deadline(args.timeout + HARD_GRACE)
    more = _set_mem_limit(args.mem_limit_mb) if set_rlimit else None
    if more:
        notes.append(more)
    elif set_rlimit and args.mem_limit_mb:
        _arm_mem_guard(_current_as_limit() or (args.mem_limit_mb << 20))
        # Should a MemoryError still happen (outside the guarded reads), freeing
        # this gives room to build and write the partial profile. Untouched
        # pages: no RSS.
        _RESERVE[:] = [bytearray(MEM_RESERVE)]
    try:
        if args.update:
            static = _read_profile(args.out)["static"]
            notes.append("static section kept from the existing profile (--update)")
        else:
            static = scan_tarball(args.tar, deadline=t0 + args.timeout)
    except HwProfileError as e:
        print("hwprofile: error: %s" % e, file=sys.stderr)
        return 1
    dynamic = None
    if args.serial_log:
        dynamic, more = _scan_serial(args.serial_log, deadline=t0 + args.timeout)
        notes += more
    profile = build_profile(static, dynamic)
    profile["notes"] += [sanitize(n) for n in notes]
    fit_profile(profile)
    try:
        write_profile(args.out, profile)
    except HwProfileError as e:
        print("hwprofile: error: %s" % e, file=sys.stderr)
        return 1
    print(_summary(profile, args.out, time.monotonic() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main(set_rlimit=True))
