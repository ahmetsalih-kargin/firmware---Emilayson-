"""Static checks of install.sh, requirements.txt, core/Dockerfile and binaries.sha256,
and behaviour tests of download.sh with a fake wget (no network) -- Phase 7."""

import hashlib
import os
import re
import shutil
import subprocess

import pytest


def code_lines(path):
    """Non-comment, non-empty lines."""
    return [l for l in path.read_text().splitlines() if l.strip() and not l.lstrip().startswith("#")]


def index_of(lines, needle, start=0):
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i
    raise AssertionError("%r not found" % needle)


# ---------------------------------------------------------------- install.sh

@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_install_sh_parses(repo_root):
    res = subprocess.run(["bash", "-n", str(repo_root / "install.sh")], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


def test_install_sh_changes_to_its_own_directory_first(repo_root):
    lines = code_lines(repo_root / "install.sh")
    assert lines[0].startswith('cd -- "$(CDPATH= cd -- "$(dirname -- "$0")"')


def test_install_sh_restarts_postgres_after_the_config_edits(repo_root):
    lines = code_lines(repo_root / "install.sh")
    restart = index_of(lines, "/etc/init.d/postgresql restart")
    assert index_of(lines, "listen_addresses") < restart
    assert index_of(lines, "host firmware firmadyne 172.17.0.0/24 md5") < restart
    # docker0 (172.17.0.1) must exist: docker is installed and started first
    assert index_of(lines, "apt install -y docker.io") < restart
    assert index_of(lines, "systemctl start docker") < restart
    assert len([l for l in lines if "/etc/init.d/postgresql restart" in l]) == 1


def test_install_sh_has_no_trust_and_no_apt_key(repo_root):
    text = "\n".join(code_lines(repo_root / "install.sh"))
    assert "trust" not in text
    assert "apt-key" not in text


def test_install_sh_groupadd_is_guarded_and_user_quoted(repo_root):
    lines = code_lines(repo_root / "install.sh")
    seen = 0
    for l in lines:
        if "groupadd" in l:
            seen += 1
            assert l.startswith("getent group docker >/dev/null || ")
        if "usermod" in l:
            assert '"$USER"' in l
    assert seen == 1


def test_install_sh_appends_are_idempotent(repo_root):
    lines = code_lines(repo_root / "install.sh")
    assert len([l for l in lines if "tee --append" in l]) == 1     # only inside append_once
    assert any("grep -qxF" in l and "tee --append" in l for l in lines)


def test_install_sh_detects_pep668_before_the_first_pip(repo_root):
    lines = code_lines(repo_root / "install.sh")
    guard = index_of(lines, "EXTERNALLY-MANAGED")
    first = index_of(lines, "pip_root install --upgrade pip")
    assert guard < first
    assert "exit 1" in "\n".join(lines[guard:first])
    # every pip call outside the guard block goes through the pip_user / pip_root helpers
    outside = (repo_root / "install.sh").read_text().replace(pep668_block(repo_root), "")
    assert "-m pip" not in outside
    assert len(re.findall(r"^(pip_user|pip_root) install", outside, re.M)) == 6
    assert "sys.prefix==sys.base_prefix" in "\n".join(lines)          # not blocked inside a venv


def test_install_sh_postgres_is_started_before_the_psql_steps(repo_root):
    lines = code_lines(repo_root / "install.sh")
    pkg = index_of(lines, "apt install -y postgresql")
    start = index_of(lines, "service postgresql start")
    assert "/etc/init.d/postgresql start" in lines[start] and lines[start].rstrip().endswith("|| true")
    assert pkg < start < index_of(lines, "CREATE USER") < index_of(lines, "createdb")
    assert start < index_of(lines, "psql -d firmware")
    assert start < index_of(lines, "/etc/init.d/postgresql restart")       # the final restart stays
    text = (repo_root / "install.sh").read_text()
    assert "does not listen on 172.17.0.1" in text


def test_install_sh_binwalk_cleanup_uses_sudo(repo_root):
    lines = code_lines(repo_root / "install.sh")
    clean = [l for l in lines if "BINWALK_CLEANUP}\" = 1" in l]
    assert len(clean) == 1 and "sudo rm -rf -- v2.3.4.tar.gz binwalk-2.3.4" in clean[0]
    assert not [l for l in lines if re.search(r"(^|[^o] )rm -rf v2\.3\.4", l)]


def test_requirements_dev_comment_is_not_stale(repo_root):
    text = (repo_root / "requirements-dev.txt").read_text()
    assert "6.2.4 (pinned in requirements.txt" not in text
    assert "pytest>=7.4" in text


def pep668_block(repo_root):
    text = (repo_root / "install.sh").read_text()
    m = re.search(r"^# BEGIN pep668$.*?^# END pep668$", text, re.M | re.S)
    assert m
    return m.group(0)


@pytest.fixture
def pep668(repo_root, tmp_path):
    """Runs the guard block of install.sh with a fake python3 (-c prints $FAKE_MANAGED, other
    calls are logged with their args and PIP_BREAK_SYSTEM_PACKAGES) and a fake sudo that, like
    the real one, drops PIP_BREAK_SYSTEM_PACKAGES unless it is given through `env`."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    (bindir / "python3").write_text(
        '#!/bin/sh\n'
        'case "$*" in *" -c "*|"-c "*) echo "$FAKE_MANAGED"; exit 0;; esac\n'
        'echo "python3 $* | break=${PIP_BREAK_SYSTEM_PACKAGES-unset}" >> "$FAKE_LOG"\n')
    (bindir / "sudo").write_text('#!/bin/sh\nexec env -u PIP_BREAK_SYSTEM_PACKAGES "$@"\n')
    for n in ("python3", "sudo"):
        (bindir / n).chmod(0o755)
    (tmp_path / "guard.sh").write_text(pep668_block(repo_root) + "\npip_user install u1\npip_root install r1\necho GUARD-PASSED\n")
    log = tmp_path / "pip.log"

    def run(managed, **env):
        e = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]), FAKE_MANAGED=managed, FAKE_LOG=str(log))
        for k in ("PIP_BREAK_SYSTEM_PACKAGES", "FIRMAE_PIP_ARGS"):
            e.pop(k, None)
        e.update(env)
        res = subprocess.run(["bash", str(tmp_path / "guard.sh")], env=e, capture_output=True, text=True, timeout=60)
        return res, (log.read_text().splitlines() if log.exists() else [])
    return run


@pytest.mark.linux
def test_pep668_guard_blocks_with_an_accurate_message(pep668):
    res, log = pep668("True")
    assert res.returncode == 1 and "GUARD-PASSED" not in res.stdout
    assert log == []                                                   # no pip call was made
    assert "PIP_BREAK_SYSTEM_PACKAGES=1 ./install.sh" in res.stderr
    assert "FIRMAE_PIP_ARGS=--break-system-packages ./install.sh" in res.stderr
    assert "may break" in res.stderr


@pytest.mark.linux
def test_pep668_guard_passes_when_python_is_not_externally_managed(pep668):
    res, log = pep668("False")
    assert res.returncode == 0 and "GUARD-PASSED" in res.stdout, res.stderr
    assert log == ["python3 -m pip install u1 | break=unset", "python3 -m pip install r1 | break=unset"]


@pytest.mark.linux
def test_pep668_guard_skipped_with_break_system_packages_env_and_passed_through_sudo(pep668):
    res, log = pep668("True", PIP_BREAK_SYSTEM_PACKAGES="1")
    assert res.returncode == 0 and "GUARD-PASSED" in res.stdout, res.stderr
    assert log == ["python3 -m pip install u1 | break=1", "python3 -m pip install r1 | break=1"]
    # (the fake sudo drops the variable, so r1 sees it only because pip_root passes it via `env`)
    res, _ = pep668("True", PIP_BREAK_SYSTEM_PACKAGES="0")             # only 1 is an opt-in
    assert res.returncode == 1


@pytest.mark.linux
def test_pep668_guard_skipped_with_firmae_pip_args_which_reach_every_pip_call(pep668):
    res, log = pep668("True", FIRMAE_PIP_ARGS="--break-system-packages --quiet")
    assert res.returncode == 0 and "GUARD-PASSED" in res.stdout, res.stderr
    assert log == ["python3 -m pip install u1 --break-system-packages --quiet | break=unset",
                   "python3 -m pip install r1 --break-system-packages --quiet | break=unset"]
    res, _ = pep668("True", FIRMAE_PIP_ARGS="--quiet")                 # other args are no opt-in
    assert res.returncode == 1


def test_install_sh_binwalk_build_runs_in_a_subshell(repo_root):
    lines = code_lines(repo_root / "install.sh")
    assert not [l for l in lines if re.search(r"\bcd -\s*(#.*)?$", l)]
    text = "\n".join(lines)
    assert "( cd binwalk-2.3.4" in text
    assert "( cd ./analyses/routersploit" in text


# ---------------------------------------------------------------- requirements / Dockerfile

def test_requirements_are_pinned_unique_and_without_pytest(repo_root):
    names = []
    for l in code_lines(repo_root / "requirements.txt"):
        m = re.fullmatch(r"([A-Za-z0-9_.\-]+)==([0-9][A-Za-z0-9_.\-]*)", l.strip())
        assert m, l
        names.append(m.group(1).lower().replace("_", "-"))
    assert len(names) == len(set(names))
    assert "pytest" not in names
    assert "pytest" not in (repo_root / "requirements.txt").read_text().lower()


def test_dockerfile_uses_a_keyring_and_no_chmod_777(repo_root):
    text = (repo_root / "core/Dockerfile").read_text()
    assert "apt-key" not in text
    assert "chmod 777" not in text
    assert "chmod 755 /usr/bin/sudo" in text
    assert "signed-by=/usr/share/keyrings/google-chrome.gpg" in text
    assert "gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg" in text
    assert "apt-get install -y gnupg" in text
    assert text.index("apt-get install -y gnupg") < text.index("gpg --dearmor")
    assert "COPY requirements.txt /tmp/requirements.txt" in text
    assert text.splitlines()[0] == "FROM ubuntu:20.04"


# ---------------------------------------------------------------- binaries.sha256 / download.sh

def download_urls(repo_root):
    return re.findall(r"^download (https://\S+)$", (repo_root / "download.sh").read_text(), re.M)


def listed(path):
    out = {}
    for l in path.read_text().splitlines():
        if l.strip() and not l.lstrip().startswith("#"):
            h, name = l.split(None, 1)
            assert re.fullmatch(r"UNKNOWN|[0-9a-f]{64}", h), l
            assert name.strip() not in out, "duplicate " + name
            out[name.strip()] = h
    return out


def test_every_download_has_a_checksum_line_and_vice_versa(repo_root):
    names = [u.rsplit("/", 1)[1] for u in download_urls(repo_root)]
    assert len(names) >= 25 and len(names) == len(set(names))
    assert sorted(listed(repo_root / "binaries.sha256")) == sorted(names)


@pytest.fixture
def dl(repo_root, tmp_path):
    """A copy of download.sh in a scratch dir with a fake wget: the 'downloaded'
    content of a file is 'content-of-<name>'."""
    root = tmp_path / "fm"
    root.mkdir()
    shutil.copy(repo_root / "download.sh", root)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    wget = bindir / "wget"
    wget.write_text('#!/bin/sh\n'
                    'out=; url=\n'
                    'while [ $# -gt 0 ]; do case "$1" in -O) out=$2; shift 2;; *) url=$1; shift;; esac; done\n'
                    'name=${url##*/}\n'
                    'echo "$url" >> "$WGET_LOG"\n'
                    'if [ -n "$WGET_FAIL" ]; then printf partial > "$out"; exit 1; fi\n'
                    'if [ -n "$WGET_KILL" ]; then printf partial > "$out"; kill -TERM $PPID; sleep 1; exit 0; fi\n'
                    'printf "content-of-%s" "$name" > "$out"\n')
    wget.chmod(0o755)
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]), WGET_LOG=str(tmp_path / "wget.log"))
    env.pop("FIRMAE_VERIFY_DOWNLOADS", None)

    class DL:
        pass
    d = DL()
    d.root, d.env, d.urls = root, env, download_urls(repo_root)
    d.log = tmp_path / "wget.log"
    d.names = [u.rsplit("/", 1)[1] for u in d.urls]

    def sums(mapping):
        """mapping: name -> hash/'UNKNOWN'; names left out are not listed."""
        (root / "binaries.sha256").write_text(
            "# test\n" + "".join("%s  %s\n" % (h, n) for n, h in mapping.items()))
    d.sums = sums

    def raw(text):
        """exact bytes of binaries.sha256 (CRLF, malformed lines ...)"""
        (root / "binaries.sha256").write_bytes(text.encode())
    d.raw = raw

    def good(name):
        return hashlib.sha256(("content-of-%s" % name).encode()).hexdigest()
    d.good = good

    def run(mode=None, **extra):
        e = dict(d.env, **extra)
        if mode:
            e["FIRMAE_VERIFY_DOWNLOADS"] = mode
        return subprocess.run(["sh", "./download.sh"], cwd=str(root), env=e, capture_output=True,
                              text=True, timeout=60)
    d.run = run
    return d


def files_in(d):
    p = d.root / "binaries"
    return sorted(x.name for x in p.iterdir()) if p.exists() else []


@pytest.mark.linux
def test_download_all_known_hashes_pass(dl):
    dl.sums({n: dl.good(n) for n in dl.names})
    for mode in (None, "strict", "warn"):
        res = dl.run(mode)
        assert res.returncode == 0, res.stdout + res.stderr
        assert "WARNING" not in res.stderr
        assert files_in(dl) == sorted(dl.names)           # no temp files left
        assert (dl.root / "binaries" / dl.names[0]).read_text() == "content-of-" + dl.names[0]


@pytest.mark.linux
def test_download_unknown_hash_warns_and_keeps_the_file_by_default(dl):
    dl.sums({n: "UNKNOWN" for n in dl.names})
    res = dl.run()                                        # default mode = warn
    assert res.returncode == 0, res.stdout + res.stderr
    assert "WARNING: unverified download: %s (no SHA-256 in binaries.sha256)" % dl.names[0] in res.stderr
    assert files_in(dl) == sorted(dl.names)
    assert dl.run("warn").returncode == 0


@pytest.mark.linux
def test_download_file_missing_from_the_list_is_treated_as_unknown(dl):
    dl.sums({n: dl.good(n) for n in dl.names[1:]})
    res = dl.run("warn")
    assert res.returncode == 0 and "unverified download: %s" % dl.names[0] in res.stderr
    assert (dl.root / "binaries" / dl.names[0]).exists()
    shutil.rmtree(str(dl.root / "binaries"))
    res = dl.run("strict")
    assert res.returncode == 1 and "unverified download: %s" % dl.names[0] in res.stderr
    assert not (dl.root / "binaries" / dl.names[0]).exists()


@pytest.mark.linux
def test_download_unknown_hash_in_strict_mode_fails_and_removes(dl):
    dl.sums({n: "UNKNOWN" for n in dl.names})
    res = dl.run("strict")
    assert res.returncode == 1, res.stdout + res.stderr
    assert "unverified download: %s" % dl.names[0] in res.stderr
    assert files_in(dl) == []                              # temp file deleted, nothing moved into place


@pytest.mark.linux
@pytest.mark.parametrize("mode", [None, "warn", "strict"])
def test_download_hash_mismatch_always_fails_and_removes(dl, mode):
    m = {n: dl.good(n) for n in dl.names}
    m[dl.names[1]] = "0" * 64
    dl.sums(m)
    res = dl.run(mode)
    assert res.returncode == 1, res.stdout + res.stderr
    assert "mismatch for %s" % dl.names[1] in res.stderr
    assert dl.names[1] not in files_in(dl)
    assert not [f for f in files_in(dl) if f.endswith(".part")]


@pytest.mark.linux
def test_download_verifies_files_that_are_already_present(dl):
    dl.sums({n: dl.good(n) for n in dl.names})
    assert dl.run().returncode == 0
    first = len(dl.log.read_text().splitlines())
    assert dl.run().returncode == 0
    assert len(dl.log.read_text().splitlines()) == first   # verified files are not fetched again
    # a corrupted file is replaced by a fresh, verified download
    bad = dl.root / "binaries" / dl.names[2]
    bad.write_text("tampered")
    assert dl.run().returncode == 0
    assert bad.read_text() == "content-of-" + dl.names[2]
    assert len(dl.log.read_text().splitlines()) == first + 1


@pytest.mark.linux
def test_download_present_unverifiable_file_is_rejected_in_strict_mode(dl):
    dl.sums({n: "UNKNOWN" for n in dl.names})
    (dl.root / "binaries").mkdir()
    keep = dl.root / "binaries" / dl.names[0]
    keep.write_text("mine")
    res = dl.run("strict")
    assert res.returncode == 1 and keep.read_text() == "mine"          # the user's file is not deleted
    res = dl.run("warn")
    assert res.returncode == 0 and keep.read_text() == "mine"          # and not replaced


@pytest.mark.linux
def test_download_rejects_an_unknown_mode_and_a_wget_failure(dl):
    dl.sums({n: "UNKNOWN" for n in dl.names})
    assert dl.run("yes").returncode == 1
    res = dl.run("warn", WGET_FAIL="1")
    assert res.returncode == 1 and "download failed" in res.stderr
    assert files_in(dl) == []


# ---------------------------------------------------------------- download.sh: checksum list parsing

def listed_lines(dl, hashes, eol="\n", marker=""):
    return "# test" + eol + "".join("%s  %s%s%s" % (h, marker, n, eol) for n, h in hashes.items())


@pytest.mark.linux
@pytest.mark.parametrize("mode", [None, "warn", "strict"])
def test_download_crlf_checksum_list_still_detects_a_mismatch(dl, mode):
    m = {n: dl.good(n) for n in dl.names}
    m[dl.names[1]] = "0" * 64
    dl.raw(listed_lines(dl, m, eol="\r\n"))
    res = dl.run(mode)
    assert res.returncode == 1, res.stdout + res.stderr
    assert "mismatch for %s" % dl.names[1] in res.stderr
    assert dl.names[1] not in files_in(dl)


@pytest.mark.linux
def test_download_crlf_checksum_list_verifies_and_replaces_a_tampered_file(dl):
    dl.raw(listed_lines(dl, {n: dl.good(n) for n in dl.names}, eol="\r\n"))
    (dl.root / "binaries").mkdir()
    bad = dl.root / "binaries" / dl.names[0]
    bad.write_text("tampered")
    res = dl.run("warn")
    assert res.returncode == 0 and "unverified" not in res.stderr, res.stderr
    assert "does not match binaries.sha256; downloading it again" in res.stderr
    assert bad.read_text() == "content-of-" + dl.names[0]


@pytest.mark.linux
def test_download_accepts_uppercase_hashes_a_binary_marker_and_a_missing_last_newline(dl):
    m = {n: dl.good(n).upper() for n in dl.names}
    dl.raw(listed_lines(dl, m, marker="*").rstrip("\n"))
    res = dl.run("strict")
    assert res.returncode == 0 and "WARNING" not in res.stderr, res.stderr
    m[dl.names[1]] = ("0" * 63 + "A")
    dl.raw(listed_lines(dl, m))
    shutil.rmtree(str(dl.root / "binaries"))
    res = dl.run("warn")
    assert res.returncode == 1 and "mismatch for %s" % dl.names[1] in res.stderr


def bad_lists(dl):
    h = dl.good(dl.names[0])
    return {
        "short hash": "%s  %s\n" % (h[:63], dl.names[0]),
        "long hash": "%s0  %s\n" % (h, dl.names[0]),
        "non-hex hash": "%sg  %s\n" % (h[:63], dl.names[0]),
        "path prefix": "%s  binaries/%s\n" % (h, dl.names[0]),
        "dot-slash prefix": "%s  ./%s\n" % (h, dl.names[0]),
        "name with spaces": "%s  my file\n" % h,
        "extra field": "%s  %s extra\n" % (h, dl.names[0]),
        "only a hash": "%s\n" % h,
        "dot-dot name": "%s  ..\n" % h,
        "duplicate": "%s  %s\nUNKNOWN  %s\n" % (h, dl.names[0], dl.names[0]),
        "duplicate with marker": "%s  %s\n%s  *%s\n" % (h, dl.names[0], h, dl.names[0]),
    }


@pytest.mark.linux
@pytest.mark.parametrize("case", sorted([
    "short hash", "long hash", "non-hex hash", "path prefix", "dot-slash prefix", "name with spaces",
    "extra field", "only a hash", "dot-dot name", "duplicate", "duplicate with marker"]))
@pytest.mark.parametrize("mode", [None, "warn", "strict"])
def test_download_malformed_checksum_list_is_fatal_before_anything_is_downloaded(dl, case, mode):
    good = "".join("%s  %s\n" % (dl.good(n), n) for n in dl.names[1:])
    dl.raw("# test\r\n" + bad_lists(dl)[case] + good)
    res = dl.run(mode)
    assert res.returncode == 1, res.stdout + res.stderr
    assert "ERROR: binaries.sha256:" in res.stderr
    assert not dl.log.exists()                                          # wget never ran
    assert files_in(dl) == []


# ---------------------------------------------------------------- download.sh: destination, messages, cleanup

@pytest.mark.linux
@pytest.mark.parametrize("kind", ["dir-symlink", "file-symlink", "dangling-symlink", "directory"])
def test_download_refuses_a_destination_that_is_not_a_regular_file(dl, kind):
    dl.sums({n: "UNKNOWN" for n in dl.names})
    binaries = dl.root / "binaries"
    binaries.mkdir()
    target = dl.root / "elsewhere"
    dest = binaries / dl.names[0]
    if kind == "dir-symlink":
        target.mkdir()
        dest.symlink_to(target)
    elif kind == "file-symlink":
        target.write_text("precious")
        dest.symlink_to(target)
    elif kind == "dangling-symlink":
        dest.symlink_to(target)
    else:
        dest.mkdir()
    for mode in ("warn", "strict"):
        res = dl.run(mode)
        assert res.returncode == 1, res.stdout + res.stderr
        assert "not a regular file" in res.stderr and dl.names[0] in res.stderr
    assert not dl.log.exists()
    if kind == "dir-symlink":
        assert dest.is_symlink() and list(target.iterdir()) == []       # nothing moved into the linked directory
    elif kind == "file-symlink":
        assert dest.is_symlink() and target.read_text() == "precious"
    elif kind == "dangling-symlink":
        assert dest.is_symlink() and not target.exists()
    else:
        assert dest.is_dir() and list(dest.iterdir()) == []


@pytest.mark.linux
def test_download_existing_unverifiable_file_message_says_existing(dl):
    dl.sums({n: "UNKNOWN" for n in dl.names})
    (dl.root / "binaries").mkdir()
    (dl.root / "binaries" / dl.names[0]).write_text("mine")
    res = dl.run("warn")
    assert res.returncode == 0
    assert "WARNING: unverified existing file: %s" % dl.names[0] in res.stderr
    assert "unverified download: %s" % dl.names[0] not in res.stderr      # fetched ones keep the old wording
    assert "unverified download: %s" % dl.names[1] in res.stderr


@pytest.mark.linux
def test_download_wget_failure_removes_the_partial_file(dl):
    dl.sums({n: "UNKNOWN" for n in dl.names})
    res = dl.run("warn", WGET_FAIL="1")                                # the fake wget leaves a partial file behind
    assert res.returncode == 1 and "download failed" in res.stderr
    assert not (dl.root / "binaries" / (".%s.part" % dl.names[0])).exists()
    assert files_in(dl) == []


@pytest.mark.linux
def test_download_removes_the_part_file_when_terminated(dl):
    dl.sums({n: "UNKNOWN" for n in dl.names})
    res = dl.run("warn", WGET_KILL="1")                                # fake wget writes a partial file, then SIGTERMs the script
    assert res.returncode == 143, res.stdout + res.stderr
    assert files_in(dl) == []
    assert len(dl.log.read_text().splitlines()) == 1
