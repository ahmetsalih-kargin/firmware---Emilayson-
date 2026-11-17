"""Aggregate hardware report over scratch/<IID>/ (REFACTORING_PLAN 6.3, minimal scope).

    python3 -m firmae.hwreport [--scratch DIR] [--format md|csv|json] [--out FILE]

Reads, after the fact, what earlier runs left under scratch/<IID>/ (brand, name,
architecture, ping, web, result and hw_profile.json from firmae/hwprofile.py) and
reports, per firmware and in total, which peripherals are not-referenced /
referenced / failing / covered / unsupported, and how that relates to the
emulation outcome (web reachable or not). `unsupported` (the firmware references
the peripheral, FirmAE has no emulation for it) and `failing` are listed by name
and never counted as success; `referenced` means "seen", not "works". Nothing is
run or changed: it is a read-only scan, exit status 0 even when some profiles are
missing or broken (2 only for usage errors or an unreadable scratch root).

Every file below scratch/<IID>/ can carry attacker-controlled text (derived from
firmware and guest logs), so nothing in it is trusted: only directories named by a
canonical positive integer are visited (never through a symlink), files are opened
with O_NOFOLLOW relative to the directory descriptor, must be regular files and are
read with a hard size cap; booleans must be exactly "true"; architecture and every
peripheral status come from fixed whitelists; the only free text (brand, name) is
cut to printable ASCII, length-capped and escaped for the target format (CSV formula
prefixes, Markdown metacharacters, no line breaks). The output file is created with
O_EXCL|O_NOFOLLOW: an existing path is refused (exit 2) unless --force is given,
which replaces an existing single-link regular file; a symlink, FIFO, device,
directory or hard-linked file is never written, with or without --force.
"""

import argparse
import csv
import errno
import io
import json
import os
import re
import stat
import sys

from firmae.hwprofile import MAX_PROFILE_BYTES, PERIPHERALS, sanitize

MAX_IIDS = 100000                 # rows kept (the smallest IIDs); the rest is only counted
MAX_ENTRIES = 1000000             # directory entries looked at in the scratch root
MAX_LINE_BYTES = 4096             # single-line files (brand, name, architecture, ...)
MAX_BRAND = 64
MAX_NAME = 128

STATUSES = ("not-referenced", "referenced", "failing", "covered", "unsupported")
EXTRA_STATUSES = ("missing", "invalid")      # no profile / unusable profile or entry
ALL_STATUSES = STATUSES + EXTRA_STATUSES
LOUD = ("unsupported", "failing")
ARCHS = ("armel", "mipseb", "mipsel")        # firmae.config.VALID_ARCHS
ARCH_VALUES = ARCHS + ("other", "missing")
BOOL_FILES = ("result", "ping", "web")
PROFILE_STATES = ("ok", "missing", "invalid")

_IID_RX = re.compile(r"[1-9][0-9]{0,17}\Z")
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)     # a FIFO must not block open()
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_HAVE_DIR_FD = os.open in getattr(os, "supports_dir_fd", ())

_MD_ESCAPE = re.compile(r"([\\`*_{}\[\]()#+\-.!~|])")
_CSV_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


# ------------------------------------------------------------------- reading

def _read_file(dir_fd, path, name, cap):
    """(state, bytes): state "ok", "missing" (no such file) or "invalid" (anything else
    wrong: symlink, not a regular file, too large, unreadable)."""
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC
    try:
        if dir_fd is not None:
            fd = os.open(name, flags, dir_fd=dir_fd)
        else:
            fd = os.open(os.path.join(path, name), flags)
    except FileNotFoundError:
        return "missing", b""
    except OSError:                    # ELOOP (symlink), EACCES, ENXIO, ...
        return "invalid", b""
    try:
        with os.fdopen(fd, "rb", closefd=False) as f:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return "invalid", b""
            raw = f.read(cap + 1)
    except OSError:
        return "invalid", b""
    finally:
        os.close(fd)
    if len(raw) > cap:
        return "invalid", b""
    return "ok", raw


def _text(state, raw, limit):
    """Sanitized first line, or "" (missing/invalid/empty)."""
    if state != "ok":
        return ""
    line = raw.split(b"\n", 1)[0].strip()
    return sanitize(line, limit).lstrip(" ")


def _bool(state, raw):
    return state == "ok" and raw.strip() == b"true"


def _arch(state, raw):
    if state == "missing":
        return "missing"
    if state != "ok":
        return "other"
    value = raw.strip().decode("ascii", "replace")
    return value if value in ARCHS else "other"


def _peripherals(state, raw):
    """(profile state, has dynamic section, {kind: status})."""
    if state == "missing":
        return "missing", False, dict.fromkeys(PERIPHERALS, "missing")
    broken = ("invalid", False, dict.fromkeys(PERIPHERALS, "invalid"))
    if state != "ok":
        return broken
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):       # UnicodeDecodeError is a ValueError
        return broken
    periph = data.get("peripherals") if isinstance(data, dict) else None
    if not isinstance(periph, dict):
        return broken
    out = {}
    for kind in PERIPHERALS:
        entry = periph.get(kind)
        if entry is None:
            out[kind] = "missing"
            continue
        status = entry.get("status") if isinstance(entry, dict) else None
        out[kind] = status if isinstance(status, str) and status in STATUSES else "invalid"
    return "ok", isinstance(data.get("dynamic"), dict), out


def read_firmware(scratch_fd, scratch_path, iid):
    """The row of one IID directory, or None when it is not a plain directory."""
    name = str(iid)
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_DIRECTORY | _O_NONBLOCK | _O_CLOEXEC
    try:
        if scratch_fd is not None:
            dfd = os.open(name, flags, dir_fd=scratch_fd)
        else:
            dpath = os.path.join(scratch_path, name)
            if os.path.islink(dpath):
                return None
            dfd = os.open(dpath, flags)
    except OSError:
        return None
    path = os.path.join(scratch_path, name)
    use_fd = dfd if _HAVE_DIR_FD else None
    try:
        if not stat.S_ISDIR(os.fstat(dfd).st_mode):
            return None

        def get(fname, cap=MAX_LINE_BYTES):
            return _read_file(use_fd, path, fname, cap)

        brand = _text(*get("brand"), MAX_BRAND)
        fname = _text(*get("name"), MAX_NAME)
        arch = _arch(*get("architecture"))
        flags_ = {b: _bool(*get(b)) for b in BOOL_FILES}
        pstate, dynamic, periph = _peripherals(*get("hw_profile.json", MAX_PROFILE_BYTES))
    finally:
        os.close(dfd)
    row = {"iid": iid, "brand": brand, "name": fname, "arch": arch}
    row.update(flags_)
    row["profile"] = pstate
    row["dynamic"] = dynamic
    row["peripherals"] = periph
    return row


def scan(scratch):
    """(rows sorted by IID, info). Raises OSError when the root cannot be listed."""
    names = []
    seen = skipped = 0
    root_fd = None
    if _HAVE_DIR_FD:
        root_fd = os.open(scratch, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    try:
        with os.scandir(root_fd if root_fd is not None else scratch) as it:
            for entry in it:
                seen += 1
                if seen > MAX_ENTRIES:
                    break
                if _IID_RX.match(entry.name):
                    names.append(int(entry.name))
                else:
                    skipped += 1
        names.sort()
        kept = names[:MAX_IIDS]
        rows = []
        symlinked = 0
        for iid in kept:
            row = read_firmware(root_fd, scratch, iid)
            if row is None:
                symlinked += 1               # symlink, regular file, vanished: not a firmware dir
            else:
                rows.append(row)
    finally:
        if root_fd is not None:
            os.close(root_fd)
    info = {"entries_scanned": min(seen, MAX_ENTRIES),
            "entries_truncated": seen > MAX_ENTRIES,
            "skipped_non_iid": skipped,
            "skipped_not_directory": symlinked,
            "iids_dropped_over_cap": max(0, len(names) - MAX_IIDS)}
    return rows, info


# ---------------------------------------------------------------- aggregation

def aggregate(rows, info=None):
    """Counts and lists, in a fixed key order (the JSON output is byte-for-byte stable)."""
    status = {k: dict.fromkeys(ALL_STATUSES, 0) for k in PERIPHERALS}
    cross = {k: {s: {"web_true": 0, "web_false": 0} for s in LOUD} for k in PERIPHERALS}
    by_arch = dict.fromkeys(ARCH_VALUES, 0)
    by_profile = dict.fromkeys(PROFILE_STATES, 0)
    flag_true = dict.fromkeys(BOOL_FILES, 0)
    lists = {s: [] for s in LOUD}
    for row in rows:
        by_arch[row["arch"]] += 1
        by_profile[row["profile"]] += 1
        for b in BOOL_FILES:
            flag_true[b] += 1 if row[b] else 0
        hit = {s: [] for s in LOUD}
        for kind in PERIPHERALS:
            st = row["peripherals"][kind]
            status[kind][st] += 1
            if st in LOUD:
                cross[kind][st]["web_true" if row["web"] else "web_false"] += 1
                hit[st].append(kind)
        for s in LOUD:
            if hit[s]:
                lists[s].append({"iid": row["iid"], "brand": row["brand"], "name": row["name"],
                                 "web": row["web"], "peripherals": hit[s]})
    out = {"total": len(rows),
           "profile": by_profile,
           "without_profile": by_profile["missing"],
           "flag_true": flag_true,
           "arch": by_arch,
           "peripheral_status": status,
           "web_crosstab": cross,
           "unsupported_firmware": lists["unsupported"],
           "failing_firmware": lists["failing"]}
    out["scan"] = dict(info or {})
    return out


def build_report(scratch):
    rows, info = scan(scratch)
    return {"firmware": rows, "aggregate": aggregate(rows, info)}


# ------------------------------------------------------------------ rendering

def csv_cell(value):
    """A text cell safe against spreadsheet formula injection (CSV injection)."""
    text = "%s" % (value,)
    if text.lstrip(" ").startswith(_CSV_DANGEROUS):     # spreadsheets skip leading blanks
        return "'" + text
    return text


def md_cell(value):
    """Text for a Markdown table cell / list item: no HTML, no markup, no pipes."""
    text = sanitize(value, 4 * max(MAX_NAME, MAX_BRAND)).replace("&", "&amp;")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = _MD_ESCAPE.sub(r"\\\1", text)
    return text or "-"


def _yn(flag):
    return "true" if flag else "false"


def render_json(report):
    return json.dumps(report, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def render_csv(report):
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    w.writerow(["iid", "brand", "name", "arch", "result", "ping", "web", "profile", "dynamic"]
               + list(PERIPHERALS))
    for r in report["firmware"]:
        w.writerow([r["iid"], csv_cell(r["brand"]), csv_cell(r["name"]), r["arch"],
                    _yn(r["result"]), _yn(r["ping"]), _yn(r["web"]), r["profile"],
                    _yn(r["dynamic"])] + [r["peripherals"][k] for k in PERIPHERALS])
    return out.getvalue()


def _table(header, body):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in body]
    return lines


def _fw_list(items, empty):
    if not items:
        return [empty, ""]
    out = []
    for it in items:
        out.append("- %d %s / %s (web=%s): %s" % (
            it["iid"], md_cell(it["brand"]), md_cell(it["name"]), _yn(it["web"]),
            ", ".join(it["peripherals"])))
    out.append("")
    return out


def render_md(report):
    agg = report["aggregate"]
    scan_info = agg["scan"]
    L = ["# FirmAE hardware report", ""]
    L += ["Read-only summary of scratch/IID/hw_profile.json and the result files. "
          "`referenced` means the firmware mentions the peripheral, not that it works; "
          "`unsupported` and `failing` are problems, never successes.", ""]
    L += ["## Summary", ""]
    L += ["- firmware: %d" % agg["total"],
          "- with a usable profile: %d" % agg["profile"]["ok"],
          "- without profile: %d" % agg["without_profile"],
          "- with an invalid profile: %d" % agg["profile"]["invalid"],
          "- result=true: %d, ping=true: %d, web=true: %d" % (
              agg["flag_true"]["result"], agg["flag_true"]["ping"], agg["flag_true"]["web"]),
          "- architectures: " + ", ".join("%s=%d" % (k, v) for k, v in agg["arch"].items()),
          "- skipped entries (not an IID): %d, not a plain directory: %d" % (
              scan_info.get("skipped_non_iid", 0), scan_info.get("skipped_not_directory", 0))]
    if scan_info.get("iids_dropped_over_cap") or scan_info.get("entries_truncated"):
        L.append("- WARNING: incomplete scan: %d IIDs over the cap of %d were left out%s" % (
            scan_info.get("iids_dropped_over_cap", 0), MAX_IIDS,
            ", directory listing cut off" if scan_info.get("entries_truncated") else ""))
    L.append("")
    L += ["## Firmware with an UNSUPPORTED peripheral", "",
          "Referenced by the firmware, no FirmAE emulation exists. Not a success even when "
          "web=true.", ""]
    L += _fw_list(agg["unsupported_firmware"], "None.")
    L += ["## Firmware with a FAILING peripheral", ""]
    L += _fw_list(agg["failing_firmware"], "None.")
    L += ["## Peripheral by status", ""]
    L += _table(["peripheral"] + list(ALL_STATUSES),
                [[k] + [agg["peripheral_status"][k][s] for s in ALL_STATUSES] for k in PERIPHERALS])
    L += ["", "## Emulation outcome (web) of firmware with a loud status", ""]
    body = []
    for k in PERIPHERALS:
        c = agg["web_crosstab"][k]
        body.append([k, c["failing"]["web_true"], c["failing"]["web_false"],
                     c["unsupported"]["web_true"], c["unsupported"]["web_false"]])
    L += _table(["peripheral", "failing, web=true", "failing, web=false",
                 "unsupported, web=true", "unsupported, web=false"], body)
    L += ["", "## Per firmware", ""]
    L += _table(["iid", "brand", "name", "arch", "result", "ping", "web", "profile"] + list(PERIPHERALS),
                [[r["iid"], md_cell(r["brand"]), md_cell(r["name"]), r["arch"], _yn(r["result"]),
                  _yn(r["ping"]), _yn(r["web"]), r["profile"]] + [r["peripherals"][k] for k in PERIPHERALS]
                 for r in report["firmware"]])
    return "\n".join(L) + "\n"


RENDERERS = {"md": render_md, "csv": render_csv, "json": render_json}


# --------------------------------------------------------------------- output

class OutputError(Exception):
    pass


def write_output(path, text, force=False):
    """Create `path` exclusively; an existing path is refused. With force=True an existing
    regular file (single link) is truncated and rewritten; a symlink, FIFO, device,
    directory or hard-linked file is refused either way."""
    data = text.encode("ascii", "replace")
    base = os.O_WRONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC
    try:
        fd = os.open(path, base | os.O_CREAT | os.O_EXCL, 0o644)
        created = True
    except FileExistsError:
        created = False
        if not force:
            raise OutputError("refusing to write %s: already exists (use --force to "
                              "overwrite a regular file)" % path)
        try:
            fd = os.open(path, base)
        except OSError as e:
            raise OutputError("cannot overwrite %s: %s" % (path, e.strerror or e))
    except OSError as e:
        raise OutputError("cannot create %s: %s" % (path, e.strerror or e))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (not created and st.st_nlink != 1):
            raise OutputError("refusing to write %s: not a plain regular file" % path)
        if not created:
            os.ftruncate(fd, 0)
        view = memoryview(data)
        while view:
            try:
                n = os.write(fd, view)
            except BlockingIOError:
                continue
            view = view[n:]
    except OSError as e:
        raise OutputError("cannot write %s: %s" % (path, e.strerror or e))
    finally:
        os.close(fd)


# ------------------------------------------------------------------------ CLI

def default_scratch():
    """SCRATCH_DIR of firmae.config when the project root can be found, else ./scratch."""
    try:
        from firmae import config
        return config.load().SCRATCH_DIR
    except Exception:
        return "scratch"


def _parser():
    p = argparse.ArgumentParser(
        prog="python3 -m firmae.hwreport", description=__doc__.split("\n\n", 1)[0] + "\n\n"
        "Aggregates hw_profile.json of every scratch/<IID>/: per-peripheral status counts, "
        "web outcome next to failing/unsupported peripherals, and the firmware with "
        "unsupported or failing peripherals (never counted as success). Read-only; "
        "exit 0 even when profiles are missing, 2 on usage errors or an unreadable scratch "
        "root. All file contents are treated as untrusted.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scratch", metavar="DIR", help="scratch root (default: SCRATCH_DIR of "
                   "firmae.config, else ./scratch)")
    p.add_argument("--format", choices=sorted(RENDERERS), default="md")
    p.add_argument("--out", metavar="FILE", help="write here (created exclusively: an existing "
                   "path is refused unless --force; never through a symlink) instead of stdout")
    p.add_argument("--force", action="store_true", help="with --out: overwrite an existing "
                   "single-link regular file (symlinks, FIFOs, devices, directories and "
                   "hard-linked files are still refused)")
    return p


def main(argv=None):
    args = _parser().parse_args(argv)
    scratch = args.scratch or default_scratch()
    try:
        report = build_report(scratch)
    except OSError as e:
        print("hwreport: cannot read scratch root %s: %s" % (sanitize(scratch), e.strerror or e),
              file=sys.stderr)
        return 2
    text = RENDERERS[args.format](report)
    if args.out:
        try:
            write_output(args.out, text, force=args.force)
        except OutputError as e:
            print("hwreport: %s" % sanitize(str(e), 400), file=sys.stderr)
            return 2
    else:
        sys.stdout.write(text)
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
