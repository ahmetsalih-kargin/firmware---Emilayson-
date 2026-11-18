"""firmae/extractuser.py (SECURITY.md S9): workspace, environment, setpriv
command, collecting the unprivileged extractor's output and re-packing its
tarball. No root: the "extract user" is the current user."""

import gzip
import io
import os
import stat
import tarfile
import time
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.linux
pytest.importorskip("pwd")

from firmae import extractuser as eu            # noqa: E402  (needs pwd: Linux)
from firmae import hwprofile                    # noqa: E402

ME = eu.Ident("me", os.getuid(), os.getgid())


# ------------------------------------------------------------------ helpers

def member(name, kind="file", data=b"", mode=0o644, uid=1234, gid=1234, uname="bob",
           gname="bob", linkname="", mtime=1500000000):
    t = tarfile.TarInfo(name)
    t.mode, t.uid, t.gid, t.uname, t.gname, t.mtime = mode, uid, gid, uname, gname, mtime
    t.type = {"file": tarfile.REGTYPE, "dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE,
              "hard": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE, "chr": tarfile.CHRTYPE,
              "blk": tarfile.BLKTYPE}[kind]
    t.linkname = linkname
    if kind == "file":
        t.size = len(data)
    return t, (data if kind == "file" else None)


def make_tgz(members, pax=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w|gz", format=tarfile.PAX_FORMAT, pax_headers=pax) as tar:
        for t, data in members:
            tar.addfile(t, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def normalise(raw, **kw):
    out = io.BytesIO()
    n = eu.normalise_tarball(io.BytesIO(raw), out, **kw)
    return n, out.getvalue()


def read_members(raw):
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        res = []
        for m in tar.getmembers():
            data = tar.extractfile(m).read() if m.isreg() else None
            res.append((m, data))
        return res


def sample_tree():
    return [
        member(".", "dir", mode=0o755),
        member("./bin", "dir", mode=0o755),
        member("./bin/busybox", data=b"\x7fELF busybox", mode=0o4755),       # setuid
        member("./bin/sh", "sym", linkname="busybox", mode=0o777),
        member("./bin/ash", "hard", linkname="./bin/busybox", mode=0o4755),
        member("./etc", "dir", mode=0o555),
        member("./etc/shadow", data=b"root::0:0:", mode=0o000),               # mode 000
        member("./etc/abs", "sym", linkname="/tmp/var/run", mode=0o777),     # absolute target stays
        member("./var", "dir", mode=0o1777),                                   # sticky
        member("./var/fifo", "fifo", mode=0o600),
        member("./usr/sbin/httpd", data=b"x" * 5000, mode=0o2755),             # setgid, implicit dirs
    ]


# --------------------------------------------------------------- normaliser

def test_normalise_keeps_everything_but_the_owners():
    src = sample_tree()
    n, raw = normalise(make_tgz(src))
    assert n == len(src)
    got = read_members(raw)
    assert [m.name for m, _ in got] == [t.name for t, _ in src]
    for (m, data), (t, tdata) in zip(got, src):
        assert (m.type, m.mode, m.linkname, int(m.mtime)) == (t.type, t.mode, t.linkname, t.mtime)
        assert (m.uid, m.gid, m.uname, m.gname) == (0, 0, "root", "root")
        assert data == tdata
    modes = {m.name: m.mode for m, _ in got}
    assert modes["./bin/busybox"] == 0o4755 and modes["./etc/shadow"] == 0 and modes["./var"] == 0o1777
    assert modes["./usr/sbin/httpd"] == 0o2755


def test_normalised_tarball_extracts_with_gnu_tar(tmp_path):
    _, raw = normalise(make_tgz(sample_tree()))
    (tmp_path / "t.tar.gz").write_bytes(raw)
    out = tmp_path / "x"
    out.mkdir()
    import subprocess
    subprocess.run(["tar", "-xzf", str(tmp_path / "t.tar.gz"), "-C", str(out)], check=True)
    assert os.readlink(out / "bin" / "sh") == "busybox"
    assert os.stat(out / "bin" / "ash").st_ino == os.stat(out / "bin" / "busybox").st_ino
    assert stat.S_ISFIFO(os.lstat(out / "var" / "fifo").st_mode)
    os.chmod(out / "etc", 0o755)          # so pytest can clean up


def test_input_pax_headers_do_not_survive():
    raw = make_tgz([member("./a", data=b"1")], pax={"comment": "evil", "uname": "bob"})
    _, out = normalise(raw)
    with tarfile.open(fileobj=io.BytesIO(out), mode="r:gz") as tar:
        m = tar.getmembers()[0]
        assert "comment" not in tar.pax_headers and "comment" not in m.pax_headers
        assert m.uname == "root"


@pytest.mark.parametrize("members, what", [
    ([member("/etc/passwd", data=b"x")], "absolute"),
    ([member("../x", data=b"x")], "'..'"),
    ([member("./a/../../x", data=b"x")], "'..'"),
    ([member("./dev/sda", "chr")], "device"),
    ([member("./dev/mtd0", "blk")], "device"),
    ([member("./a", data=b"1"), member("a", data=b"2")], "duplicate"),
    ([member("./l", "sym", linkname="/etc"), member("./l/passwd", data=b"x")], "below the non-directory"),
    ([member("./d/f", data=b"x"), member("./d", "sym", linkname="/etc")], "replaces a directory"),
    ([member(".", "sym", linkname="/")], "replaces a directory"),
    ([member("./h", "hard", linkname="/etc/shadow")], "absolute hard link target"),
    ([member("./h", "hard", linkname="../../etc/shadow")], "hard link target with '..'"),
    ([member("./h", "hard", linkname="./missing")], "not an earlier regular file"),
    ([member("./s", "sym", linkname="x"), member("./h", "hard", linkname="./s")], "not an earlier regular file"),
])
def test_hostile_members_are_refused(members, what):
    with pytest.raises(eu.TarballError, match=what.replace("(", r"\(")):
        normalise(make_tgz(members))


def test_member_cap():
    members = [member("./f%d" % i, data=b"") for i in range(5)]
    assert normalise(make_tgz(members), max_members=5)[0] == 5
    with pytest.raises(eu.TarballError, match="more than 4 members"):
        normalise(make_tgz(members), max_members=4)


def test_stream_cap(monkeypatch):
    raw = make_tgz([member("./big", data=b"\0" * 200000)])
    monkeypatch.setattr(hwprofile, "MAX_STREAM_BYTES", 100000)
    with pytest.raises(eu.TarballError, match="stream_bytes"):
        normalise(raw)


def test_deadline():
    with pytest.raises(eu.TarballError, match="time"):
        normalise(make_tgz(sample_tree()), deadline=time.monotonic() - 1)


def test_tracked_name_cap(monkeypatch):
    monkeypatch.setattr(eu, "MAX_TRACKED_CHARS", 50)
    with pytest.raises(eu.TarballError, match="too many"):
        normalise(make_tgz([member("./%s/f" % ("d" * 30), data=b""), member("./%s" % ("e" * 30), data=b"")]))


def test_depth_cap():
    with pytest.raises(eu.TarballError, match="deeper"):
        normalise(make_tgz([member("/".join(["a"] * (eu.MAX_DEPTH + 1)), data=b"")]))


@pytest.mark.parametrize("raw", [b"", b"not gzip at all", gzip.compress(b"\x01" * 1024)])
def test_garbage_is_refused(raw):
    with pytest.raises(eu.TarballError):
        normalise(raw)


def test_truncated_data_is_refused():
    raw = make_tgz([member("./a", data=b"y" * 100000)])
    plain = gzip.decompress(raw)[:20000]
    with pytest.raises(eu.TarballError):
        normalise(gzip.compress(plain))


# ---------------------------------------------------------------- workspace

def test_workspace_layout_and_cleanup(tmp_path):
    base = str(tmp_path / "base")
    ws = eu.Workspace.create(base, ME)
    assert stat.S_IMODE(os.stat(base).st_mode) == 0o711
    assert stat.S_IMODE(os.stat(ws.path).st_mode) == 0o750
    for d, mode in ((ws.indir, 0o750), (ws.bin, 0o750), (ws.out, 0o700), (ws.tmp, 0o700), (ws.home, 0o700)):
        assert stat.S_IMODE(os.stat(d).st_mode) == mode
    fw = tmp_path / "DIR-868L.zip"
    fw.write_bytes(b"firmware")
    p = ws.stage_firmware(str(fw))
    assert p == os.path.join(ws.indir, "DIR-868L.zip") and open(p, "rb").read() == b"firmware"
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o640
    os.makedirs(os.path.join(ws.out, "x", "y"))
    os.symlink("/", os.path.join(ws.out, "root"))            # never followed by the cleanup
    assert ws.cleanup() == []
    assert os.listdir(base) == []


@pytest.mark.parametrize("prepare", ["symlink", "writable"])
def test_unsafe_base_is_refused(tmp_path, prepare):
    base = tmp_path / "base"
    if prepare == "symlink":
        (tmp_path / "elsewhere").mkdir()
        base.symlink_to(tmp_path / "elsewhere")
    else:
        base.mkdir()
        base.chmod(0o777)
    with pytest.raises(eu.ExtractUserError, match="symlink|writable"):
        eu.Workspace.create(str(base), ME)
    assert not os.listdir(str(tmp_path / "elsewhere")) if prepare == "symlink" else True


def test_done_list_mirrors_images(tmp_path):
    images = tmp_path / "images"
    images.mkdir()
    for n in ("12.tar.gz", "12.kernel", "13.tar.gz", "notes.txt", ".x.tar.gz"):
        (images / n).write_text("")
    (images / "14.tar.gz").mkdir()               # not a file
    ws = eu.Workspace.create(str(tmp_path / "base"), ME)
    path = ws.write_done_list(str(images))
    assert open(path).read().split() == ["12.kernel", "12.tar.gz", "13.tar.gz"]
    ws2 = eu.Workspace.create(str(tmp_path / "base"), ME)
    assert open(ws2.write_done_list(str(tmp_path / "none"))).read() == ""


# ----------------------------------------------------- environment / command

def test_child_env_is_a_whitelist(tmp_path):
    ws = SimpleNamespace(home="/w/home", tmp="/w/tmp")
    base = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "FIRMAE_DB_PASSWORD": "pw", "FIRMAE_DB_PORT": "5433",
            "PGCONNECT_TIMEOUT": "30", "SECRET": "x", "LD_PRELOAD": "/evil.so", "PYTHONPATH": "/evil",
            "HOME": "/root", "TMPDIR": "/tmp", "SUDO_USER": "ahmet", "PGPORT": "5433",
            "PGPASSFILE": "/root/.pgpass"}
    env = eu.child_env(base, ws, eu.Ident("firmae-extract", 999, 999))
    assert env == {"PATH": "/usr/bin", "LANG": "C.UTF-8", "FIRMAE_DB_PASSWORD": "pw", "PGPORT": "5433",
                   "FIRMAE_DB_PORT": "5433", "PGCONNECT_TIMEOUT": "30", "HOME": "/w/home",
                   "TMPDIR": "/w/tmp", "USER": "firmae-extract", "LOGNAME": "firmae-extract"}
    assert eu.child_env({}, ws, ME)["PATH"] == eu.DEFAULT_PATH


def test_setpriv_command():
    argv = eu.command("/usr/bin/setpriv", eu.Ident("u", 999, 998), ["python3", "x.py", "-nk"])
    assert argv == ["/usr/bin/setpriv", "--reuid=999", "--regid=998", "--init-groups",
                    "--no-new-privs", "--", "python3", "x.py", "-nk"]


def test_lookup():
    with pytest.raises(eu.ExtractUserError, match="no such user"):
        eu.lookup("no-such-user-firmae-xyz")
    with pytest.raises(eu.ExtractUserError, match="uid 0"):
        eu.lookup("root")
    import pwd
    me = pwd.getpwuid(os.getuid())
    if me.pw_uid != 0:
        assert eu.lookup(me.pw_name) == (me.pw_name, me.pw_uid, me.pw_gid)


def test_setpriv_is_not_taken_from_path(monkeypatch, tmp_path):
    fake = tmp_path / "setpriv"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(eu, "SAFE_PATH", str(tmp_path / "nothing"))
    with pytest.raises(eu.ExtractUserError, match="setpriv"):
        eu.find_setpriv()
    monkeypatch.setattr(eu, "SAFE_PATH", "/usr/bin:/bin")
    if os.path.exists("/usr/bin/setpriv") or os.path.exists("/bin/setpriv"):
        assert os.path.dirname(eu.find_setpriv()) in ("/usr/bin", "/bin")


def test_path_brand():
    assert eu.path_brand("/p/FirmAE/firmwares/x.zip", "/p/FirmAE") == "firmwares"
    assert eu.path_brand("/p/FirmAE/./a/../dlink/x.zip", "/p/FirmAE") == "dlink"


# ------------------------------------------------------------------ collect

def fresh_out(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    images = tmp_path / "images"
    return out, images


BOTH = ["12.kernel", "12.tar.gz"]


def test_collect_publishes_kernel_and_normalised_tarball(tmp_path):
    out, images = fresh_out(tmp_path)
    (out / "12.tar.gz").write_bytes(make_tgz(sample_tree()))
    (out / "12.kernel").write_bytes(b"KERNEL")
    (out / "junk.bin").write_bytes(b"ignored")
    os.symlink("/etc/passwd", str(out / "nameless"))
    assert eu.collect(str(out), str(images), os.getuid(), BOTH) == BOTH
    assert (images / "12.kernel").read_bytes() == b"KERNEL"
    assert all(m.uid == 0 for m, _ in read_members((images / "12.tar.gz").read_bytes()))
    assert sorted(os.listdir(str(images))) == BOTH                     # no temp files
    for n in BOTH:
        assert stat.S_IMODE(os.stat(images / n).st_mode) == 0o644


def test_collect_ignores_names_root_did_not_expect(tmp_path):
    """A compromised extractor of firmware 12 writes the output of image 99."""
    out, images = fresh_out(tmp_path)
    (out / "12.tar.gz").write_bytes(make_tgz(sample_tree()))
    (out / "99.tar.gz").write_bytes(make_tgz([member("./evil", data=b"x")]))
    (out / "99.kernel").write_bytes(b"EVIL")
    assert eu.collect(str(out), str(images), os.getuid(), ["12.tar.gz"]) == ["12.tar.gz"]
    assert os.listdir(str(images)) == ["12.tar.gz"]


def test_collect_never_replaces_an_existing_file(tmp_path):
    out, images = fresh_out(tmp_path)
    images.mkdir()
    (images / "12.tar.gz").write_bytes(b"published earlier")
    (out / "12.tar.gz").write_bytes(make_tgz(sample_tree()))
    with pytest.raises(eu.ExtractUserError, match="exists already"):
        eu.collect(str(out), str(images), os.getuid(), ["12.tar.gz"])
    assert (images / "12.tar.gz").read_bytes() == b"published earlier"
    assert os.listdir(str(images)) == ["12.tar.gz"]                    # no temp file left


def test_publish_race_with_an_appearing_file_does_not_replace_it(tmp_path):
    images = tmp_path / "images"
    images.mkdir()
    ifd = os.open(str(images), os.O_RDONLY | os.O_DIRECTORY)
    try:
        def writer(dst):            # the file appears after the existence check
            dst.write(b"new")
            (images / "12.kernel").write_bytes(b"other")
        with pytest.raises(eu.ExtractUserError, match="appeared meanwhile"):
            eu._publish(ifd, "12.kernel", writer)
    finally:
        os.close(ifd)
    assert (images / "12.kernel").read_bytes() == b"other"
    assert os.listdir(str(images)) == ["12.kernel"]


def test_collect_refuses_an_existing_symlink_and_leaves_it(tmp_path):
    out, images = fresh_out(tmp_path)
    images.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("keep")
    os.symlink(str(victim), str(images / "12.kernel"))
    (out / "12.kernel").write_bytes(b"K")
    with pytest.raises(eu.ExtractUserError, match="exists already"):
        eu.collect(str(out), str(images), os.getuid(), ["12.kernel"])
    assert victim.read_text() == "keep" and os.path.islink(str(images / "12.kernel"))


def test_expected_names():
    assert eu.expected_names(["12", "fw.bin_abc"], "-nk") == ["12.tar.gz", "fw.bin_abc.tar.gz"]
    assert eu.expected_names(["12"], "-nf") == ["12.kernel"]
    assert eu.expected_names(["", "../x", "a b"], "-nk") == []          # never a path or odd name


@pytest.mark.parametrize("make", ["symlink", "hardlink", "fifo", "dir", "owner"])
def test_collect_refuses_suspicious_outputs(tmp_path, make):
    out, images = fresh_out(tmp_path)
    secret = tmp_path / "secret"
    secret.write_bytes(b"root only")
    uid = os.getuid()
    if make == "symlink":
        os.symlink(str(secret), str(out / "12.kernel"))
    elif make == "hardlink":
        os.link(str(secret), str(out / "12.kernel"))
    elif make == "fifo":
        os.mkfifo(str(out / "12.kernel"))
    elif make == "dir":
        (out / "12.kernel").mkdir()
    else:
        (out / "12.kernel").write_bytes(b"K")
        uid += 1
    with pytest.raises(eu.ExtractUserError):
        eu.collect(str(out), str(images), uid, ["12.kernel"])
    assert not (images / "12.kernel").exists()


def test_collect_refuses_a_bad_tarball_and_leaves_no_partial_file(tmp_path):
    out, images = fresh_out(tmp_path)
    (out / "12.tar.gz").write_bytes(make_tgz([member("./ok", data=b"1"), member("../evil", data=b"2")]))
    with pytest.raises(eu.TarballError):
        eu.collect(str(out), str(images), os.getuid(), ["12.tar.gz"])
    assert os.listdir(str(images)) == []


def test_collect_size_and_entry_caps(tmp_path, monkeypatch):
    out, images = fresh_out(tmp_path)
    (out / "12.kernel").write_bytes(b"K" * 100)
    monkeypatch.setattr(eu, "MAX_KERNEL_BYTES", 99)
    with pytest.raises(eu.ExtractUserError, match="larger"):
        eu.collect(str(out), str(images), os.getuid(), ["12.kernel"])
    monkeypatch.setattr(eu, "MAX_OUT_ENTRIES", 2)
    for i in range(3):
        (out / ("f%d" % i)).write_text("")
    with pytest.raises(eu.ExtractUserError, match="entries"):
        eu.collect(str(out), str(images), os.getuid(), ["12.kernel"])


def test_collect_nothing_to_publish(tmp_path):
    out, images = fresh_out(tmp_path)
    assert eu.collect(str(out), str(images), os.getuid(), BOTH) == []
    assert not images.exists()


# ------------------------------------------------- one run at a time, kill

def test_lock_runs_serialises(tmp_path):
    base = str(tmp_path / "base")
    fd = eu.lock_runs(base, wait=0)
    try:
        t = [0.0]
        with pytest.raises(eu.ExtractUserError, match="holds"):
            eu.lock_runs(base, wait=3, clock=lambda: t[0], sleep=lambda s: t.__setitem__(0, t[0] + s))
        assert t[0] >= 3                                  # it waited, bounded
    finally:
        os.close(fd)
    os.close(eu.lock_runs(base, wait=0))                  # free again


def fake_proc(tmp_path, procs):
    """procs: {pid: (uid line values, state)}"""
    proc = tmp_path / "proc"
    proc.mkdir(exist_ok=True)
    for pid, (uids, state) in procs.items():
        d = proc / str(pid)
        d.mkdir()
        (d / "status").write_text("Name:\tx\nState:\t%s (x)\nUid:\t%s\n" % (state, "\t".join(map(str, uids))))
    (proc / "self").mkdir(exist_ok=True)
    return proc


def test_user_pids(tmp_path):
    proc = fake_proc(tmp_path, {10: ((999, 999, 999, 999), "S"), 11: ((0, 999, 999, 999), "R"),
                                12: ((1000, 1000, 1000, 1000), "S"), 13: ((999, 999, 999, 999), "Z"),
                                14: ((0, 0, 999, 0), "S")})
    assert sorted(eu.user_pids(999, str(proc))) == [10, 11, 14]       # real, effective or saved uid


def test_kill_user_kills_until_gone(tmp_path):
    import shutil as sh
    import signal as sg
    proc = fake_proc(tmp_path, {20: ((999,) * 4, "S"), 21: ((999,) * 4, "S"), 22: ((1000,) * 4, "S")})
    killed = []

    def kill(pid, sig):
        killed.append((pid, sig))
        sh.rmtree(str(proc / str(pid)))
    assert eu.kill_user(999, wait=5, proc=str(proc), kill=kill, sleep=lambda s: None) == []
    assert sorted(killed) == [(20, sg.SIGKILL), (21, sg.SIGKILL)]
    assert (proc / "22").exists()


def test_kill_user_reports_survivors_after_the_wait(tmp_path):
    proc = fake_proc(tmp_path, {30: ((999,) * 4, "D")})
    t = [0.0]
    left = eu.kill_user(999, wait=2, proc=str(proc), kill=lambda p, s: None,
                        sleep=lambda s: t.__setitem__(0, t[0] + s), clock=lambda: t[0])
    assert left == [30] and t[0] >= 2


def test_kill_user_refuses_root_and_ourselves():
    for uid in (0, os.getuid(), os.geteuid()):
        with pytest.raises(eu.ExtractUserError, match="refusing"):
            eu.kill_user(uid, kill=lambda p, s: pytest.fail("must not kill"))


def test_pid_namespace_probe(monkeypatch):
    import subprocess as sp
    calls = []
    monkeypatch.setattr(eu, "_PIDNS", [])
    monkeypatch.setattr(eu.shutil, "which", lambda name, path=None: "/usr/bin/" + name)
    monkeypatch.setattr(eu.subprocess, "run",
                        lambda argv, **kw: calls.append(argv) or sp.CompletedProcess(argv, 0))
    want = ["/usr/bin/unshare", "--pid", "--fork", "--kill-child", "--"]
    assert eu.pid_namespace_prefix() == want and eu.pid_namespace_prefix() == want
    assert calls == [want + ["true"]]                     # probed once, cached
    argv = eu.command("/usr/bin/setpriv", eu.Ident("u", 9, 9), ["python3"], pidns=want)
    assert argv[:6] == want + ["/usr/bin/setpriv"] and argv[-2:] == ["--", "python3"]


@pytest.mark.parametrize("outcome", ["fails", "raises", "missing"])
def test_pid_namespace_falls_back(monkeypatch, outcome):
    import subprocess as sp
    monkeypatch.setattr(eu, "_PIDNS", [])
    monkeypatch.setattr(eu.shutil, "which",
                        lambda name, path=None: None if outcome == "missing" else "/usr/bin/" + name)

    def run(argv, **kw):
        if outcome == "raises":
            raise sp.TimeoutExpired(argv, 20)
        return sp.CompletedProcess(argv, 1)
    monkeypatch.setattr(eu.subprocess, "run", run)
    assert eu.pid_namespace_prefix() == []
