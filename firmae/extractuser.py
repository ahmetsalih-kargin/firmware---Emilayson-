"""Running the firmware extractor as a dedicated unprivileged user (SECURITY.md S9).

Opt-in: FIRMAE_EXTRACT_USER=<name> (default empty: extractor.py runs as root,
exactly as before). It is not the default because the tarball is not the same:
an unprivileged extraction cannot restore the firmware's owners (every file is
owned by the extract user; the tarball says uid/gid 0), unsquashfs drops
setuid/setgid bits when it is not root, and device nodes in the firmware cannot
be created (fixImage.sh recreates the standard ones). Measured with DIR-868L and
WNAP320 (WP-B2 phase 2; same member names, order, data, link targets, kernel and
database rows otherwise): device nodes missing (74 / 47), setgid lost on 3
directories (DIR-868L), symlink mtimes = extraction time (197, WNAP320); both
firmwares are all-root, so the owner difference did not show. extractor.py
clears its umask when not root, which would otherwise mask the image's modes.

When set, for each extractor call the pipeline

  1. checks the user (exists, is not uid 0; else ExitCode.EXTRACTION, never a
     silent fallback to root) and that we are root (setpriv needs it);
  2. creates a per-run workspace W = <base>/run-<random> (base:
     FIRMAE_EXTRACT_TMP, default /var/tmp/firmae-extract; owned by root, not
     group/other writable, never a symlink):
        W        root:<gid> 0750   (the user can neither rename nor add entries)
        W/in     root:<gid> 0750   copy of the firmware (same basename, same
                                   content: same md5 / image row) + done.list
        W/bin    root:<gid> 0750   copy of extractor.py (the project directory
                                   need not be readable by the user)
        W/out    user:<gid> 0700   extractor output (<IID>.tar.gz / .kernel)
        W/tmp    user:<gid> 0700   TMPDIR (binwalk's working directories)
        W/home   user:<gid> 0700   HOME (binwalk's ~/.config)
     All runs share the user's uid, so before that: lock_runs() flocks the
     base directory (one extraction as the user at a time; BUSY after
     LOCK_WAIT) and kill_user() SIGKILLs whatever of the user still runs;
  3. runs `[unshare --pid --fork --kill-child --] setpriv --reuid --regid
     --init-groups --no-new-privs -- python3 W/bin/extractor.py ...` with an
     explicit environment (child_env: PATH, LANG/LC_*, PG*, FIRMAE_DB_*, HOME,
     TMPDIR, USER, LOGNAME). In its own PID namespace (when unshare supports
     it, probed once) everything the extractor started dies with it, also
     processes that called setsid(). setpriv's --reset-env is not used: it
     would drop FIRMAE_DB_PASSWORD, and putting the password on an `env`
     command line would show it in ps;
  4. kill_user() again (nothing may write into W/out while root reads it), then
     collect(): only the names root expects (expected_names: <IID>.tar.gz for
     -nk, <IID>.kernel for -nf, IID = what the database gives for the
     firmware's md5, or extractor.py's "<basename>_<md5>" fallback); each must
     be a regular file owned by the user with one link (no hard link to a file
     of someone else); the kernel is copied, the tarball re-packed by
     normalise_tarball() into images/ (temporary file + link(): an existing
     images/<name> is never replaced; mode 0644, root-owned);
  5. kills the user's processes and removes W (also on failure, timeout, Ctrl-C).

What the extract user can still do: everything a compromised extractor can do
as that user -- it has the database credentials it needs for its own writes
(the `firmadyne` role, SECURITY.md S4; it could e.g. change which image row a
md5 maps to, which only makes root accept another *not yet published* image
id), and it can fill W/out and W/tmp. It can no longer write as root anywhere,
replace a published image, outlive its run, or reach another run's workspace.
The user must be dedicated to FirmAE: all its processes are killed.
"""

import collections
import fcntl
import gzip
import os
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tarfile
import time

from . import hwprofile

ENV_USER = "FIRMAE_EXTRACT_USER"
ENV_BASE = "FIRMAE_EXTRACT_TMP"
DEFAULT_BASE = "/var/tmp/firmae-extract"

# setpriv is searched only here, never in root's PATH
SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# libpq reads PGPORT/PGHOST/...: without them the extractor would reach another
# server than root's tools do (e.g. the test setup with PGPORT=5433). PGPASSFILE
# and PGSERVICEFILE are not passed (paths to root's files).
PASS_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "PGCONNECT_TIMEOUT", "PGPORT", "PGHOST",
            "PGHOSTADDR", "PGSSLMODE", "PGPASSWORD", "PGDATABASE", "PGUSER")
PASS_PREFIXES = ("FIRMAE_DB_",)

# Names the extractor writes (ExtractionItem.get_rootfs_path/get_kernel_path):
# the database id, or "<basename>_<md5>" without a database.
OUTPUT_NAME = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z._+-]{0,250}\.(?:tar\.gz|kernel)\Z")
MAX_OUT_ENTRIES = 64                 # entries of W/out looked at
MAX_KERNEL_BYTES = 1 << 30           # the extractor copies the whole kernel item
MAX_TARBALL_BYTES = hwprofile.MAX_STREAM_BYTES    # compressed size of the rootfs tarball
NORMALISE_TIMEOUT = 900              # seconds for re-packing one tarball

# tarball bounds (consistent with firmae/hwprofile.py, which reads the same tarball later)
MAX_MEMBERS = hwprofile.MAX_MEMBERS
MAX_NAME = 4096                      # characters of a member or link name
MAX_DEPTH = 256                      # path components of a member name
MAX_TRACKED_CHARS = 64 << 20         # characters of all paths remembered for the checks
COPY_CHUNK = 1 << 20

Ident = collections.namedtuple("Ident", "name uid gid")


class ExtractUserError(Exception):
    """Configuration or workspace error; the pipeline turns it into ExitCode.EXTRACTION."""


class TarballError(ExtractUserError):
    """The tarball handed back by the unprivileged extractor was refused."""


# ------------------------------------------------------------- configuration

def requested_user(environ=None):
    return (os.environ if environ is None else environ).get(ENV_USER, "").strip()


def base_dir(environ=None):
    return (os.environ if environ is None else environ).get(ENV_BASE, "").strip() or DEFAULT_BASE


def lookup(name):
    """Ident of `name`; refuses unknown users and uid 0."""
    try:
        pw = pwd.getpwnam(name)
    except (KeyError, TypeError, ValueError):
        raise ExtractUserError("%s=%s: no such user (create it, e.g. FIRMAE_CREATE_USERS=1 "
                               "./install.sh, or unset %s); not extracting as root instead"
                               % (ENV_USER, name, ENV_USER))
    if pw.pw_uid == 0:
        raise ExtractUserError("%s=%s is uid 0 (root); use an unprivileged user or unset %s"
                               % (ENV_USER, name, ENV_USER))
    return Ident(name, pw.pw_uid, pw.pw_gid)


def require_root():
    if os.geteuid() != 0:
        raise ExtractUserError("%s needs root (setpriv changes the user)" % ENV_USER)


def find_setpriv():
    path = shutil.which("setpriv", path=SAFE_PATH)
    if not path:
        raise ExtractUserError("%s is set but setpriv (util-linux) was not found in %s"
                               % (ENV_USER, SAFE_PATH))
    return path


def command(setpriv, ident, argv, pidns=()):
    """[unshare --pid --fork --kill-child --] setpriv ... -- argv. In its own PID
    namespace the extractor is pid 1: when it exits (or is killed on a timeout,
    via --kill-child) the kernel kills every process it left, also those that
    left the process group with setsid()."""
    return list(pidns) + [setpriv, "--reuid=%d" % ident.uid, "--regid=%d" % ident.gid,
                          "--init-groups", "--no-new-privs", "--"] + list(argv)


# ------------------------------------------------------ one run at a time

LOCK_WAIT = 3 * 3600         # seconds a run waits for another one's extraction
KILL_WAIT = 10               # seconds for the extract user's processes to go
_PIDNS = []                  # cached probe result: [] not probed, [prefix] probed


def pid_namespace_prefix():
    """The unshare prefix when `unshare --pid --fork --kill-child` works here
    (util-linux >= 2.32, CAP_SYS_ADMIN: root, also --privileged Docker); else []
    (the uid-wide kill below still runs before and after every extraction)."""
    if not _PIDNS:
        prefix = []
        unshare = shutil.which("unshare", path=SAFE_PATH)
        if unshare:
            argv = [unshare, "--pid", "--fork", "--kill-child", "--"]
            try:
                ok = subprocess.run(argv + ["true"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=20).returncode == 0
            except Exception:              # OSError, TimeoutExpired
                ok = False
            prefix = argv if ok else []
        _PIDNS.append(prefix)
    return list(_PIDNS[0])


def lock_runs(base, wait=None, clock=time.monotonic, sleep=time.sleep):
    """flock the base directory: one extraction as the extract user at a time
    (all runs share its uid: a second run's workspace would be reachable by the
    first run's processes, and the kill below would hit the other run). Returns
    the fd (closing it releases the lock); raises ExtractUserError after `wait`."""
    wait = LOCK_WAIT if wait is None else wait
    fd = _open_base(base)
    deadline = clock() + wait
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if clock() >= deadline:
                os.close(fd)
                raise ExtractUserError("another extraction as %s holds %s for more than %ds"
                                       % (ENV_USER, base, wait))
            sleep(1)
        except OSError as e:
            os.close(fd)
            raise ExtractUserError("cannot lock %s: %s" % (base, e))


def user_pids(uid, proc="/proc"):
    """Live (not zombie) processes whose real, effective or saved uid is `uid`."""
    pids = []
    try:
        names = os.listdir(proc)
    except OSError:
        return pids
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc, name, "status")) as f:
                status = f.read()
        except OSError:
            continue                        # gone meanwhile
        uids, state = None, ""
        for line in status.splitlines():
            if line.startswith("Uid:"):
                uids = line.split()[1:4]
            elif line.startswith("State:"):
                state = line.split()[1] if len(line.split()) > 1 else ""
        if uids and str(uid) in uids and state not in ("Z", "X"):
            pids.append(int(name))
    return pids


def kill_user(uid, wait=None, proc="/proc", kill=os.kill, sleep=time.sleep, clock=time.monotonic):
    """SIGKILL every process of the (dedicated) extract user and wait until they
    are gone. Returns the pids still there after `wait` seconds (normally []).
    Refuses uid 0 and our own uids: never kill ourselves or root."""
    if uid == 0 or uid in (os.getuid(), os.geteuid()):
        raise ExtractUserError("refusing to kill the processes of uid %d" % uid)
    wait = KILL_WAIT if wait is None else wait
    deadline = clock() + wait
    while True:
        pids = user_pids(uid, proc)
        if not pids:
            return []
        for pid in pids:
            try:
                kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        if clock() >= deadline:
            return user_pids(uid, proc)
        sleep(0.1)


def child_env(base_env, ws, ident):
    """Only what the extractor needs; nothing else of root's environment."""
    env = {k: base_env[k] for k in PASS_ENV if k in base_env}
    env.update((k, v) for k, v in base_env.items() if k.startswith(PASS_PREFIXES))
    env.setdefault("PATH", DEFAULT_PATH)
    env.update(HOME=ws.home, TMPDIR=ws.tmp, USER=ident.name, LOGNAME=ident.name)
    return env


def path_brand(path, root):
    """The brand extractor.py derives when it gets no -b: the first component
    of the firmware path relative to the project root (its working directory)."""
    return os.path.relpath(os.path.abspath(path), root).split(os.sep)[0]


# ------------------------------------------------------------------ workspace

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_base(base):
    """The base directory, created if missing; must be ours (root), a real
    directory and not writable by group/others (it may live in /var/tmp)."""
    try:
        os.mkdir(base, 0o711)
    except FileExistsError:
        pass
    except OSError as e:
        raise ExtractUserError("cannot create %s: %s" % (base, e))
    try:
        fd = os.open(base, _DIR_FLAGS)
    except OSError as e:
        raise ExtractUserError("cannot open %s (a symlink?): %s" % (base, e))
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        os.close(fd)
        raise ExtractUserError("%s is not owned by uid %d or is group/other writable; refusing "
                               "to use it (remove it or set %s)" % (base, os.geteuid(), ENV_BASE))
    os.fchmod(fd, 0o711)            # the extract user must be able to traverse it
    return fd


class Workspace:
    SUBDIRS = (("in", False, 0o750), ("bin", False, 0o750),
               ("out", True, 0o700), ("tmp", True, 0o700), ("home", True, 0o700))

    def __init__(self, path, ident):
        self.path = path
        self.ident = ident
        for name, _, _ in self.SUBDIRS:
            setattr(self, name if name != "in" else "indir", os.path.join(path, name))

    @classmethod
    def create(cls, base, ident):
        bfd = _open_base(base)
        try:
            name = "run-" + secrets.token_hex(8)
            os.mkdir(name, 0o700, dir_fd=bfd)
            rfd = os.open(name, _DIR_FLAGS, dir_fd=bfd)
        finally:
            os.close(bfd)
        ws = cls(os.path.join(base, name), ident)
        try:
            os.fchown(rfd, os.geteuid(), ident.gid)
            os.fchmod(rfd, 0o750)
            for sub, user_owned, mode in cls.SUBDIRS:
                os.mkdir(sub, 0o700, dir_fd=rfd)
                sfd = os.open(sub, _DIR_FLAGS, dir_fd=rfd)
                try:
                    os.fchown(sfd, ident.uid if user_owned else os.geteuid(), ident.gid)
                    os.fchmod(sfd, mode)
                finally:
                    os.close(sfd)
        except BaseException:
            os.close(rfd)
            ws.cleanup()
            raise
        os.close(rfd)
        return ws

    def _root_file(self, dirpath, name, writer):
        """A new root:<gid> 0640 file dirpath/name (never through a symlink)."""
        dfd = os.open(dirpath, _DIR_FLAGS)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=dfd)
        finally:
            os.close(dfd)
        with os.fdopen(fd, "wb") as f:
            os.fchown(f.fileno(), os.geteuid(), self.ident.gid)
            os.fchmod(f.fileno(), 0o640)
            writer(f)
        return os.path.join(dirpath, name)

    def stage_firmware(self, src):
        """Copy of the firmware under its own basename (the database stores the
        basename and the md5 of the content; both stay the same)."""
        name = os.path.basename(src)
        if name in ("", ".", ".."):
            raise ExtractUserError("invalid firmware file name %r" % src)
        with open(src, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise ExtractUserError("%s is not a regular file" % src)
            return self._root_file(self.indir, name, lambda dst: shutil.copyfileobj(f, dst, COPY_CHUNK))

    def stage_script(self, src):
        with open(src, "rb") as f:
            return self._root_file(self.bin, os.path.basename(src),
                                   lambda dst: shutil.copyfileobj(f, dst, COPY_CHUNK))

    def write_done_list(self, images_dir):
        """Output names that already exist in images/: the extractor skips them
        (as it did when it wrote to images/ directly) and still marks them as
        extracted in the database."""
        try:
            names = sorted(n for n in os.listdir(images_dir)
                           if OUTPUT_NAME.match(n) and os.path.isfile(os.path.join(images_dir, n)))
        except FileNotFoundError:
            names = []
        data = "".join(n + "\n" for n in names).encode()
        return self._root_file(self.indir, "done.list", lambda dst: dst.write(data))

    def cleanup(self):
        """Remove the workspace (root ignores the modes the extractor left;
        rmtree does not follow symlinks). Returns a list of error strings."""
        errors = []
        shutil.rmtree(self.path, onerror=lambda fn, p, exc: errors.append("%s: %s" % (p, exc[1])))
        return errors


# ------------------------------------------------------------------ collect

def expected_names(tags, flag):
    """The only output names root accepts from this extractor call: <tag>.tar.gz
    for -nk (rootfs only), <tag>.kernel for -nf (kernel only), for the tags root
    computed itself (the image id of the firmware's md5, the "<basename>_<md5>"
    fallback of extractor.py's generate_tag). A name of another firmware written
    by a compromised extractor is never published."""
    suffix = {"-nk": ".tar.gz", "-nf": ".kernel"}[flag]
    return sorted({t + suffix for t in tags if t and OUTPUT_NAME.match(t + suffix)})


def collect(out_dir, images_dir, uid, allowed, deadline=None):
    """Move the extractor's output from W/out to images/: only the names in
    `allowed` (expected_names); an existing images/<name> is never replaced (the
    extractor skips outputs that exist: done.list). Returns the published names."""
    try:
        ofd = os.open(out_dir, _DIR_FLAGS)
    except OSError as e:
        raise ExtractUserError("cannot open %s: %s" % (out_dir, e))
    try:
        names = os.listdir(ofd)
        if len(names) > MAX_OUT_ENTRIES:
            raise ExtractUserError("%s has %d entries (more than %d)" % (out_dir, len(names), MAX_OUT_ENTRIES))
        wanted = sorted(n for n in names if n in set(allowed))
        if not wanted:
            return []
        os.makedirs(images_dir, exist_ok=True)
        ifd = os.open(images_dir, _DIR_FLAGS)
        try:
            for name in wanted:
                _collect_one(ofd, ifd, name, uid, deadline)
        finally:
            os.close(ifd)
        return wanted
    finally:
        os.close(ofd)


def _collect_one(ofd, ifd, name, uid, deadline):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=ofd)
    except OSError as e:
        raise ExtractUserError("cannot open output %s: %s" % (name, e))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise ExtractUserError("output %s is not a regular file" % name)
    with os.fdopen(fd, "rb") as src:
        if st.st_uid != uid or st.st_nlink != 1:
            raise ExtractUserError("output %s is not a file of the extract user with one link "
                                   "(uid %d, %d links)" % (name, st.st_uid, st.st_nlink))
        if name.endswith(".kernel"):
            if st.st_size > MAX_KERNEL_BYTES:
                raise ExtractUserError("kernel %s is larger than %d bytes" % (name, MAX_KERNEL_BYTES))
            _publish(ifd, name, lambda dst: _copy_bounded(src, dst, MAX_KERNEL_BYTES))
        else:
            if st.st_size > MAX_TARBALL_BYTES:
                raise ExtractUserError("tarball %s is larger than %d bytes" % (name, MAX_TARBALL_BYTES))
            _publish(ifd, name, lambda dst: normalise_tarball(src, dst, deadline))


def _copy_bounded(src, dst, limit):
    total = 0
    while True:
        block = src.read(COPY_CHUNK)
        if not block:
            return total
        total += len(block)
        if total > limit:
            raise ExtractUserError("output grew beyond %d bytes while copying" % limit)
        dst.write(block)


def _publish(ifd, name, writer):
    """images/<name> via a temporary file and link(): never half-written, never
    written through a symlink, never replacing an existing entry (link fails
    with EEXIST, also for a symlink); root-owned, 0644 (as make_archive wrote it)."""
    try:
        os.lstat(name, dir_fd=ifd)
        raise ExtractUserError("images/%s exists already; not replaced" % name)
    except FileNotFoundError:
        pass
    tmp = ".%s.tmp-%s" % (name, secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=ifd)
    try:
        with os.fdopen(fd, "wb") as dst:
            writer(dst)
            dst.flush()
            os.fchmod(dst.fileno(), 0o644)
        try:
            os.link(tmp, name, src_dir_fd=ifd, dst_dir_fd=ifd, follow_symlinks=False)
        except FileExistsError:
            raise ExtractUserError("images/%s appeared meanwhile; not replaced" % name)
    finally:
        try:
            os.unlink(tmp, dir_fd=ifd)
        except OSError:
            pass


# --------------------------------------------------------- tarball normaliser

def _key(name, what="member name"):
    """Canonical path of a member name; refuses absolute names and '..'."""
    if not isinstance(name, str) or not name or len(name) > MAX_NAME or "\0" in name:
        raise TarballError("invalid %s %r" % (what, name[:80] if isinstance(name, str) else name))
    if name.startswith("/"):
        raise TarballError("absolute %s %r" % (what, name[:80]))
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise TarballError("%s with '..': %r" % (what, name[:80]))
    if len(parts) > MAX_DEPTH:
        raise TarballError("%s deeper than %d components" % (what, MAX_DEPTH))
    return "/".join(parts)


class _Paths:
    """What the archive created so far, to refuse members that would be
    extracted through a symlink (or replace a directory) -- impossible in a
    tarball made from a real directory tree, possible in a forged one."""

    def __init__(self):
        self.kind = {}          # key -> "d" | "r" (regular) | "o" (other)
        self.implicit = set()   # keys used as an ancestor of a member
        self.chars = 0

    def _track(self, key):
        self.chars += len(key) + 1
        if self.chars > MAX_TRACKED_CHARS:
            raise TarballError("too many / too long member names")

    def add(self, key, kind):
        if key in self.kind:
            raise TarballError("duplicate member %r" % key[:80])
        if kind != "d" and (key == "" or key in self.implicit):
            raise TarballError("non-directory member %r replaces a directory" % key[:80])
        parts = key.split("/") if key else []
        for i in range(len(parts) - 1, 0, -1):          # deepest ancestor first
            anc = "/".join(parts[:i])
            known = self.kind.get(anc)
            if known is not None and known != "d":
                raise TarballError("member %r below the non-directory %r" % (key[:80], anc[:80]))
            if anc in self.implicit or known == "d":
                break                                   # its ancestors were checked already
            self.implicit.add(anc)
            self._track(anc)
        self.kind[key] = kind
        self._track(key)


def _member_kind(m):
    if m.issparse():
        raise TarballError("sparse member %r" % m.name[:80])
    if m.isdir():
        return "d"
    if m.isreg():
        return "r"
    if m.issym() or m.islnk() or m.isfifo():
        return "o"
    if m.ischr() or m.isblk():
        raise TarballError("device member %r from the unprivileged extractor" % m.name[:80])
    raise TarballError("member %r of unsupported type %r" % (m.name[:80], m.type))


def _normalised(m, kind, paths):
    t = tarfile.TarInfo(m.name)
    t.mode = m.mode & 0o7777
    t.mtime = m.mtime
    t.uid = t.gid = 0
    t.uname = t.gname = "root"
    if kind == "d":
        t.type = tarfile.DIRTYPE
    elif kind == "r":
        t.type = tarfile.REGTYPE
        t.size = m.size
    elif m.issym():
        if not m.linkname or len(m.linkname) > MAX_NAME or "\0" in m.linkname:
            raise TarballError("invalid symlink target of %r" % m.name[:80])
        t.type = tarfile.SYMTYPE
        t.linkname = m.linkname
    elif m.islnk():
        target = _key(m.linkname, "hard link target")
        if paths.kind.get(target) != "r":
            raise TarballError("hard link %r to %r, which is not an earlier regular file"
                               % (m.name[:80], m.linkname[:80]))
        t.type = tarfile.LNKTYPE
        t.linkname = m.linkname
    else:
        t.type = tarfile.FIFOTYPE
    return t


def normalise_tarball(src, dst, deadline=None, max_members=None):
    """Re-pack the gzip tarball `src` (binary file object, written by the
    unprivileged extractor, so hostile) into `dst` as a gzip tarball that

      * keeps member names, order, modes (incl. setuid/setgid/sticky and
        mode 000), mtimes, symlink targets (absolute ones too), hard links,
        FIFOs and the data;
      * says uid/gid 0, uname/gname root for every member (the files were
        owned by the extract user; as root the owners came from the firmware);
      * carries none of the input's pax headers (rebuilt from the fields);
      * refuses (TarballError): absolute names, '..', duplicates, members below
        a non-directory, a non-directory replacing a directory, hard links to
        anything but an earlier regular member, devices, sparse and unknown
        types, more than MAX_MEMBERS members, more than MAX_STREAM_BYTES of
        decompressed stream, oversized headers (firmae.hwprofile's bounded
        reader) and the deadline.

    Returns the number of members."""
    limit = MAX_MEMBERS if max_members is None else max_members
    if deadline is None:
        deadline = time.monotonic() + NORMALISE_TIMEOUT
    budget = hwprofile._Budget(deadline)
    gz = gzip.GzipFile(fileobj=src, mode="rb")
    count = 0
    out = None
    try:
        reader = hwprofile._BoundedReader(gz, budget)
        reader.begin_header()
        tar = tarfile.TarFile(fileobj=reader, mode="r", encoding="utf-8", errors="surrogateescape")
        reader.end_header()
        out = tarfile.open(fileobj=dst, mode="w|gz", format=tarfile.PAX_FORMAT,
                           encoding="utf-8", errors="surrogateescape")
        paths = _Paths()
        while True:
            budget.check_time()
            reader.begin_header()
            m = tar.next()
            reader.end_header()
            if m is None:
                break
            tar.members = []
            hwprofile._check_pax_globals(tar)
            count += 1
            if count > limit:
                raise TarballError("more than %d members" % limit)
            kind = _member_kind(m)
            key = _key(m.name)
            t = _normalised(m, kind, paths)
            paths.add(key, kind)
            if kind == "r":
                out.addfile(t, tar.extractfile(m))
            else:
                out.addfile(t)
        out.close()
        out = None
    except hwprofile._Stop as e:
        raise TarballError("tarball limit hit: %s" % e.reason)
    except TarballError:
        raise
    except RecursionError:
        raise TarballError("tarball headers nest too deeply")
    except Exception as e:      # TarError, OSError, EOFError, zlib errors, malformed headers
        raise TarballError("cannot read the extracted tarball: %s: %s" % (type(e).__name__, e))
    finally:
        if out is not None:         # failed: end the output stream now (the caller discards it),
            try:                    # not later in __del__ when dst may be closed
                out.close()
            except Exception:
                pass
        gz.close()
    return count
