"""Count hardware-related failure traces in emulation serial logs.

The guest's serial console output (scratch/<IID>/qemu.*.serial.log) is
ATTACKER CONTROLLED: any line, any length, NUL/ANSI/invalid UTF-8, gigabytes.
This module therefore

  * opens a log only with O_NOFOLLOW and only if it is a regular file,
  * reads at most MAX_LOG_BYTES per file, in blocks of _BLOCK bytes; only the
    first MAX_LINE_BYTES of every line are examined, the rest of an over-long
    line is dropped (the log is then marked truncated), so memory stays
    bounded whatever the line length,
  * stops reading when the caller's `deadline` (absolute time.monotonic()
    value) passes; the log and the result are then marked truncated,
  * sanitises every line (ANSI escapes, control bytes and non-ASCII dropped)
    before matching, skips most lines with a few cheap substring tests, and
    uses only anchored, linear-time regexes (no nested quantifiers),
  * bounds every dictionary (devices, modules, samples, process names),
  * never uses log content as a command or a path.

Result layout (all keys always present):

  logs      [{name, lines, bytes, truncated, error}]  one entry per input path
  events    {kind: {"count": int, "samples": [str]}}
  devices   {"/dev/...": {"errors": int}}   at most MAX_DEVICES paths
  modules   {"<module file>": {"errors": int}}   at most MAX_MODULES names
  respawn   {"<process name>": int}
  truncated bool   any log cut short (byte limit, over-long line, deadline)
                   or the module table overflowed

What each counter counts exactly
--------------------------------
events[kind]["count"]  number of INCIDENTS, not of lines. One line yields at
  most one kind (first match wins, in the order below). Two rules merge lines
  of one incident into a single count (the merged lines are still scanned for
  device paths and module names, and a merged kernel_panic line still adds a
  sample):

  * kernel_panic: a panic/oops line that follows another panic/oops line of
    the same log by at most PANIC_WINDOW (50) lines belongs to the same
    incident (the window slides: it restarts at every such line). An
    "Internal error: Oops" followed by its backtrace and "Kernel panic" is
    one incident.
  * segfault: a kernel line ("sending SIGSEGV to X", "segfault at ...") is one
    incident. A shell line ("Segmentation fault") that follows an unmatched
    kernel line by at most SEGV_WINDOW (40) lines is the same crash and is not
    counted; each kernel line absorbs at most one shell line.

  Both windows are per log file. A guest can only ever INFLATE a count by
  printing extra lines (harmless); the windows give it one way to SUPPRESS:
  printing a fake panic/oops line within 50 lines before a real panic, or a
  fake kernel SIGSEGV line within 40 lines before a real "Segmentation fault"
  shell line, hides that one real incident. This is accepted and documented;
  the guest can equally well just not print the error.

devices[path]["errors"]  number of event lines (any kind, merged or not)
  whose FIRST /dev/... path is `path`.
modules[name]["errors"]  number of module_load_failed lines that name `name`
  (file name only; "bcm_wdt.ko", or a bare module name for kernel messages
  such as "bcm_wdt: Unknown symbol ..."). Lines naming no module are counted
  in events only. These are full counters; unlike the samples they are not
  limited to the first MAX_SAMPLES lines.

Event kinds (one kind per line, first match wins, in this order):

  kernel_panic          "Kernel panic", "Internal error: Oops", "Oops:",
                        "Unable to handle kernel"
  segfault              "SIGSEGV", "segmentation fault", "segfault"
  hook_register_failed  "firmadyne: Cannot register ..." / "firmadyne: Cannot create ..."
                        (the kernel hooks for /dev/watchdog, wdt, gpio, device class)
  module_load_failed    "insmod:", "modprobe:", "can't insert", "unknown symbol in module",
                        "disagrees about version"  (NOT "do you need to insmod?" hints)
  mtd_error             line mentions "mtd" together with an error word
  watchdog_error        "Error in opening the device", or "watchdog" with an error word
  gpio_error            line mentions "gpio" together with an error word
  device_open_failed    "can't/cannot/unable to/failed to open" or "error opening" + "/dev/"
  no_such_device        "No such device" (ENODEV: ifconfig/wlanconfig ioctls, /dev/nvram, ...)

An "error word" is matched as a whole word: fail/failed/failure/failing,
error(s), cannot, can't, unable, no such, not found, timeout, timed out,
invalid ("failsafe" or "errorless" do not match; "gpio_error" does). Plain
negations and zero counts are removed first: "no error(s)", "0 errors",
"zero errors", "error_count=0", "errors: 0", "failures=0", "without error".

Firmadyne trace lines ("[ts] firmadyne: sys_socket[PID: 77 (udevd)]: ...",
matched strictly: the line must start with "firmadyne: <func>[PID: n (name)]: ")
are not events for the generic kinds (device_open_failed, no_such_device, mtd,
watchdog, gpio): real traces describe syscalls, and a "No such device" in
their argument text is not a hardware failure. They ARE still checked for
kernel_panic, segfault and module_load_failed, so a guest cannot hide those by
dressing them up as a trace. Their process names feed `respawn`: how many
distinct PIDs carried the same name (plus `do_execve: <path>` executions of
the same basename). A name is reported when seen >= RESPAWN_MIN times; at most
RESPAWN_TOP names are returned. The figure is approximate (a legitimately busy
command such as ifconfig also shows up).

Limitations: a guest can still hide a generic error (open failed, no such
device, mtd/watchdog/gpio) by printing it inside a perfectly formed trace
prefix, or simply by not printing it; the counts describe what the guest
chose to log.
"""

import os
import re
import stat
from time import monotonic as _now

MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 4096
MAX_DEVICES = 500
MAX_MODULES = 500
MAX_SAMPLES = 5
SAMPLE_LEN = 200
RESPAWN_MIN = 10
RESPAWN_TOP = 20
PANIC_WINDOW = 50
SEGV_WINDOW = 40
_BLOCK = 256 * 1024
_MAX_NAMES = 200          # distinct process names tracked per log
_MAX_PIDS = 256           # distinct pids remembered per name
_NAME_LEN = 100

EVENT_KINDS = (
    "device_open_failed", "no_such_device", "hook_register_failed",
    "module_load_failed", "segfault", "kernel_panic", "mtd_error",
    "watchdog_error", "gpio_error",
)
_GENERIC_KINDS = frozenset(("device_open_failed", "no_such_device",
                            "mtd_error", "watchdog_error", "gpio_error"))

# Anchored / simple patterns only; every quantifier is over a character class
# that cannot overlap with what follows it, so matching is linear.
_ANSI_RE = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
_DROP = bytes(b for b in range(256) if not 0x20 <= b <= 0x7e)
_TS_RE = re.compile(r"\[\s{0,8}\d{1,10}\.\d{1,10}\]\s{0,4}")
_DEV_RE = re.compile(r"/dev/[A-Za-z0-9_.+-]{1,40}(?:/[A-Za-z0-9_.+-]{1,40}){0,4}")
_TRACE_RE = re.compile(r"firmadyne: [a-z0-9_]{1,40}\[PID: (\d{1,10}) \(([A-Za-z0-9_.+:-]{1,32})\)\]: ")
_EXECVE_RE = re.compile(r"firmadyne: do_execve: ([A-Za-z0-9_./+-]{1,200})")
_ERR_RE = re.compile(
    r"(?<![a-z0-9])(?:fail(?:ed|ure|ures|ing|s)?|errors?|cannot|can't|unable"
    r"|no such|not found|timeout|timed out|invalid)(?![a-z0-9])")
_NEG_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"no (?:more )?(?:errors?|failures?)"
    r"|(?:0|zero) (?:errors?|failures?)"
    r"|(?:errors?|failures?)(?:[_ ]?count)? ?[:=] ?0"
    r"|without (?:any )?(?:errors?|failures?)"
    r")(?![a-z0-9])")
_MODNAME_OK = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.+-")
_MODNAME_FULL = re.compile(r"[A-Za-z0-9_.+-]{1,64}\Z")
_MOD_SKIP = frozenset(("can't", "cannot", "load", "insert", "module", "fatal", "error",
                       "failed", "unknown", "symbol", "in", "not", "found", "the"))

_OPEN_WORDS = ("can't open", "cannot open", "unable to open", "failed to open",
               "error opening", "open failed", "failed opening")

# A line without any of these substrings cannot be an event or a trace.
_GATE = ("firmadyne", "kernel panic", "oops", "unable to handle", "sigsegv",
         "segmentation fault", "segfault", "insmod:", "modprobe:", "can't insert",
         "unknown symbol", "disagrees", "mtd", "watchdog", "gpio",
         "error in opening", "/dev/", "no such device")


def _sanitize(raw):
    """bytes -> printable-ASCII str (ANSI escapes and control/non-ASCII removed)."""
    raw = _ANSI_RE.sub(b"", raw)
    return raw.translate(None, _DROP).decode("ascii")


def _has_err(low):
    return _ERR_RE.search(low) is not None


def _classify(low):
    """Event kind for a sanitised, lower-cased line, or None."""
    if ("kernel panic" in low or "internal error: oops" in low or "oops:" in low
            or "unable to handle kernel" in low):
        return "kernel_panic"
    if "sigsegv" in low or "segmentation fault" in low or "segfault" in low:
        return "segfault"
    if "firmadyne: cannot " in low and ("register" in low or "create" in low):
        return "hook_register_failed"
    if ("insmod:" in low or "modprobe:" in low or "can't insert" in low
            or "unknown symbol in module" in low or "disagrees about version" in low):
        return "module_load_failed"
    if "mtd" in low or "watchdog" in low or "gpio" in low or "error in opening" in low:
        neg = _NEG_RE.sub(" ", low)
        if "mtd" in neg and _has_err(neg):
            return "mtd_error"
        if "error in opening the device" in neg or ("watchdog" in neg and _has_err(neg)):
            return "watchdog_error"
        if "gpio" in neg and _has_err(neg):
            return "gpio_error"
    if "/dev/" in low:
        neg = _NEG_RE.sub(" ", low)
        for w in _OPEN_WORDS:
            if w in neg:
                return "device_open_failed"
    if "no such device" in low:
        return "no_such_device"
    return None


def _module_name(text):
    """File name of the kernel module a failure line talks about, or None."""
    low = text.lower()
    i = low.find(".ko")
    tries = 0
    while i > 0 and tries < 8:
        tries += 1
        end = i + 3
        nxt = text[end:end + 1]
        if not nxt or not (nxt.isalnum() or nxt == "_"):
            j = i
            while j > 0 and i - j < 61 and text[j - 1] in _MODNAME_OK:
                j -= 1
            if j < i:
                return text[j:end]
        i = low.find(".ko", i + 3)
    # kernel style "<module>: Unknown symbol ..." / "<module>: disagrees ..."
    body = _TS_RE.sub("", text, count=1)
    head, sep, _rest = body.partition(": ")
    if sep and _MODNAME_FULL.match(head) and head.lower() not in _MOD_SKIP \
            and ("unknown symbol" in low or "disagrees" in low):
        return head
    # "modprobe: can't load module foo", "FATAL: Module foo not found"
    k = low.find("module ")
    if k >= 0:
        for tok in body[k + 7:k + 7 + 120].split(None, 3)[:2]:
            tok = tok.strip("'\"`,:;()")
            tok = tok.rsplit("/", 1)[-1]
            if tok and tok.lower() not in _MOD_SKIP and _MODNAME_FULL.match(tok):
                return tok
    return None


def _empty_events():
    return {k: {"count": 0, "samples": []} for k in EVENT_KINDS}


class _Acc(object):
    """Accumulator shared by all logs of one scan."""

    def __init__(self):
        self.events = _empty_events()
        self.devices = {}
        self.modules = {}
        self.modules_overflow = False

    def add_event(self, kind, text, count=True, sample=True):
        ev = self.events[kind]
        if count:
            ev["count"] += 1
        if sample:
            s = _TS_RE.sub("", text, count=1).strip()[:SAMPLE_LEN]
            if len(ev["samples"]) < MAX_SAMPLES and s not in ev["samples"]:
                ev["samples"].append(s)
        m = _DEV_RE.search(text)
        if m:
            dev = m.group(0).rstrip(".")
            if dev in self.devices:
                self.devices[dev]["errors"] += 1
            elif len(self.devices) < MAX_DEVICES:
                self.devices[dev] = {"errors": 1}
        if kind == "module_load_failed":
            name = _module_name(text)
            if name:
                if name in self.modules:
                    self.modules[name]["errors"] += 1
                elif len(self.modules) < MAX_MODULES:
                    self.modules[name] = {"errors": 1}
                else:
                    self.modules_overflow = True


class _LineScanner(object):
    """Per-log state: respawn tables and the incident-merging windows."""

    def __init__(self, acc):
        self.acc = acc
        self.pids = {}        # name -> set of pids (bounded)
        self.execs = {}       # basename -> count (bounded)
        self.over = False     # an over-long line was clipped
        self.last_panic = None
        self.seg_pending = 0
        self.seg_line = 0

    def feed(self, no, raw, over):
        """Process line number `no` (raw bytes, already clipped)."""
        if over:
            self.over = True
        if len(raw) < 6:
            return
        if b"\x1b" in raw:
            raw = _ANSI_RE.sub(b"", raw)
        text = raw.translate(None, _DROP).decode("ascii")
        if len(text) < 6:
            return
        low = text.lower()
        for key in _GATE:
            if key in low:
                break
        else:
            return
        trace = False
        if "firmadyne" in low:
            m = _TS_RE.match(text)
            body = text[m.end():] if m else text
            t = _TRACE_RE.match(body)
            if t:
                trace = True
                name = t.group(2)
                s = self.pids.get(name)
                if s is None and len(self.pids) < _MAX_NAMES:
                    s = self.pids[name] = set()
                if s is not None and len(s) < _MAX_PIDS:
                    s.add(t.group(1))
            else:
                e = _EXECVE_RE.match(body)
                if e:
                    base = e.group(1).rsplit("/", 1)[-1][:32]
                    if base in self.execs:
                        self.execs[base] += 1
                    elif base and len(self.execs) < _MAX_NAMES:
                        self.execs[base] = 1
                    return
        kind = _classify(low)
        if kind is None or (trace and kind in _GENERIC_KINDS):
            return
        count = True
        sample = True
        if kind == "kernel_panic":
            if self.last_panic is not None and no - self.last_panic <= PANIC_WINDOW:
                count = False
            self.last_panic = no
        elif kind == "segfault":
            if "segmentation fault" in low and "sigsegv" not in low:
                if self.seg_pending > 0 and no - self.seg_line <= SEGV_WINDOW:
                    self.seg_pending -= 1
                    count = sample = False
            else:
                if no - self.seg_line > SEGV_WINDOW:
                    self.seg_pending = 0
                self.seg_pending += 1
                self.seg_line = no
        self.acc.add_event(kind, text, count, sample)


def _open_regular(path):
    """(file, None) for a regular, non-symlink file, else (None, reason)."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None, "not a regular file"
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, "file not found"
    except OSError as e:
        return None, _sanitize(("cannot open: %s" % (e.strerror or "error")).encode("ascii", "replace"))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None, "not a regular file"
        return os.fdopen(fd, "rb"), None
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        return None, "cannot open: fstat failed"


def _scan_one(path, acc, deadline=None):
    entry = {"name": "", "lines": 0, "bytes": 0, "truncated": False, "error": None}
    try:
        path = os.fspath(path)
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        entry["name"] = _sanitize(os.path.basename(path).encode("utf-8", "replace"))[:_NAME_LEN]
    except (TypeError, ValueError):
        entry["error"] = "invalid path"
        return entry, {}
    if deadline is not None and _now() > deadline:
        entry["truncated"] = True
        return entry, {}
    f, err = _open_regular(path)
    if f is None:
        entry["error"] = err
        return entry, {}
    st = _LineScanner(acc)
    total = lines = 0
    truncated = False
    part_head = b""      # first bytes of the unterminated line at the block end
    part_len = 0         # its real length so far
    try:
        with f:
            while total < MAX_LOG_BYTES:
                if deadline is not None and _now() > deadline:
                    truncated = True
                    break
                block = f.read(min(_BLOCK, MAX_LOG_BYTES - total))
                if not block:
                    break
                total += len(block)
                if b"\n" not in block:
                    part_len += len(block)
                    if len(part_head) < MAX_LINE_BYTES:
                        part_head = (part_head + block)[:MAX_LINE_BYTES]
                    continue
                if not block.strip(b"\n"):          # only newlines: fast path
                    if part_len:
                        st.feed(lines + 1, part_head, part_len >= MAX_LINE_BYTES)
                    lines += len(block)
                    part_head, part_len = b"", 0
                    continue
                parts = block.split(b"\n")
                n_term = len(parts) - 1
                first = parts[0]
                st.feed(lines + 1, (part_head + first[:MAX_LINE_BYTES])[:MAX_LINE_BYTES],
                        part_len + len(first) >= MAX_LINE_BYTES)
                no = lines + 1
                for k in range(1, n_term):
                    line = parts[k]
                    if len(line) >= 6:
                        st.feed(no + k, line[:MAX_LINE_BYTES], len(line) >= MAX_LINE_BYTES)
                lines += n_term
                last = parts[-1]
                part_head, part_len = last[:MAX_LINE_BYTES], len(last)
            else:
                if f.read(1):
                    truncated = True
            if part_len:
                lines += 1
                st.feed(lines, part_head, part_len >= MAX_LINE_BYTES)
    except OSError as e:
        entry["error"] = _sanitize(("read error: %s" % (e.strerror or "error")).encode("ascii", "replace"))
    entry["lines"] = lines
    entry["bytes"] = total
    entry["truncated"] = truncated or st.over
    spawn = {}
    for name, s in st.pids.items():
        spawn[name] = len(s)
    for name, n in st.execs.items():
        if n > spawn.get(name, 0):
            spawn[name] = n
    return entry, spawn


def scan_serial_logs(paths, *, deadline=None):
    """Scan several serial logs and return one merged result (see module doc).

    `deadline` is an absolute time.monotonic() value; when it passes, reading
    stops, the affected log and the result are marked truncated.
    """
    acc = _Acc()
    logs = []
    spawn_total = {}
    try:
        plist = list(paths)
    except TypeError:
        plist = []
    for p in plist:
        entry, spawn = _scan_one(p, acc, deadline)
        logs.append(entry)
        for name, n in spawn.items():
            spawn_total[name] = spawn_total.get(name, 0) + n
    hot = [(n, name) for name, n in spawn_total.items() if n >= RESPAWN_MIN]
    hot.sort(key=lambda t: (-t[0], t[1]))
    return {
        "logs": logs,
        "events": acc.events,
        "devices": acc.devices,
        "modules": acc.modules,
        "respawn": {name: n for n, name in hot[:RESPAWN_TOP]},
        "truncated": any(l["truncated"] for l in logs) or acc.modules_overflow,
    }


def scan_serial_log(path, *, deadline=None):
    """Scan a single serial log; same result shape as scan_serial_logs."""
    return scan_serial_logs([path], deadline=deadline)
