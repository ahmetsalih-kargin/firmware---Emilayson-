# Changelog

All changes are relative to upstream `master` `653565b`. Step numbers refer to
`REFACTORING_PLAN.md`, finding IDs (S1…) to `SECURITY.md`.
**Behaviour change** marks anything a user or script could notice.

## [Unreleased] — refactor/hardening

### Phase 2 — security and functional fixes

#### Security
- **2.1 / S1** `analyses/fuzzer/fuzzer.py`: scanning the extracted image no longer
  goes through a shell. File names from the firmware were pasted into
  `strings … | grep …` commands run with `shell=True`, so a file named
  `a;<command>;cgi` executed `<command>` on the host as root. New module
  `analyses/fuzzer/fwscan.py` does the same work in Python.
  - Behaviour change: scan results are sorted (previously directory order), so the
    fuzzer visits URIs/parameters in a deterministic order. Symlinks, FIFOs and device
    files are not read (as with `grep -r`).
- **2.2 / S3** `scripts/getArch.py`: rootfs tarball members are no longer extracted to
  the predictable `/tmp/<IID>`; `../` members could write anywhere as root. Candidate
  files are copied one at a time into a private temporary directory that is always
  removed. The image id must be numeric; the SQL update is parameterised.
  - Behaviour change: `scratch/<IID>/fileType` now names the temporary file instead of
    `/tmp/<IID>/<member>` (no component reads this file). A member path containing
    `ARM`/`MSB`/… can no longer influence the detected architecture.
- **2.3 / S5** `scripts/makeImage.sh`, `scripts/makeNetwork.py`, new
  `scripts/imagepath.py`: writes into the mounted image no longer follow symlinks
  planted by the firmware to host paths. Paths are resolved with chroot semantics
  (`bin -> /usr/bin` lands in the image's `/usr/bin`); top-level helper files replace
  whatever the image has under that name, as before.
- **2.4 / S2** `run.sh`, `scripts/makeImage.sh`, `firmae.config` (`secure_workdir`):
  `scratch/<IID>` is no longer world-writable (`chmod -R a+rwx`) although root later
  executes `scratch/<IID>/run.sh`. It belongs to the owner of `scratch/` (the invoking
  user in Docker mode, so `docker-helper.py` still works), mode 0755;
  world-writable bits from earlier runs are removed; `image.raw` is 0644.
  - Behaviour change: other local users can no longer modify files in `scratch/`.
- **2.5 / S4** `install.sh`: PostgreSQL access from Docker is `md5` for the `firmware`
  database and the `firmadyne` user only, instead of `trust` for all databases and
  users (password-less superuser for every container on docker0).
  - Behaviour change: existing installations keep their old line in `pg_hba.conf`;
    replace `host all all 172.17.0.1/24 trust` by
    `host firmware firmadyne 172.17.0.0/24 md5` and reload PostgreSQL.
- **2.6 / S6** `docker-helper.py`: every `docker` call uses an argument list; firmware
  names and brands reach the in-container `bash -c` as positional parameters.
  - Behaviour change: background runs use `docker exec -d` instead of a host-side `&`;
    `-c`/`-s` no longer request a TTY (`-it` failed without one); `-s` runs the script
    by its base name.

#### Fixed
- **2.7** `analyses/nmap.sh`: the target IP was looked up from a `GUESTIP=` line that
  the generated `run.sh` never contains, so nmap never ran. It now takes the target
  from `analyses_all.sh` (fallback `scratch/<IID>/ip`) and copies the XML report to
  `analysis_log/nmap_log.txt`, where `fuzzer.py` reads it. The missing `/` in the
  output path is fixed.
  - Behaviour change: nmap and the fuzzer's port discovery actually run; analysis
    takes longer.
- **2.7** `firmae.config`: `FIRMAE_DIR` comes from the location of `firmae.config`, not
  `$(pwd)`. `analyses_all.sh` and `nmap.sh` run from `analyses/` and used the
  non-existent `analyses/scratch/<IID>` in host (non-Docker) mode.
  - Behaviour change: host-mode analysis logs are written to `scratch/<IID>/analysis_log`
    (where Docker mode and `docker-helper.py` already expected them).
- **2.8** `scripts/delete.sh`: processes are matched by `/scratch/<IID>/` (IID 1 no
  longer matches 10, 11, 21, …) and get SIGTERM before SIGKILL; the mount and exactly
  the loop devices backed by the image are released (instead of "newest
  `/dev/mapper` entry"); all `tap<IID>_*` interfaces are removed (the loop
  `for i in 0 .. 4` iterated over `0`, `..`, `4`); `/tmp/qemu.<IID>*` sockets are
  removed (the quoted glob never matched).
- **2.8** `util/cleanup.sh`: removes only containers of the `fcore` image and only
  mounts/loop devices of `scratch/<IID>/image(.raw)`.
  - Behaviour change: unrelated containers and loop devices are no longer removed.
- **2.9** `run.sh`, `scripts/check_emulation.sh`: `2>&1 > log` sent stderr to the
  terminal and kept it out of `tar2db.log`, `makeImage.log`, `makeNetwork.log`,
  `emulation.log`. Both streams now go to the log; when a step fails, `run.sh` prints
  the last 20 lines of its log and stops with the step's exit code (as `set -e` did).
  - Behaviour change: step output that used to appear on the terminal is in the logs.
- **2.11** `scripts/makeNetwork.py`, `analyses/fuzzer/fuzzer.py`,
  `util/collect_result.py`: regular expressions are raw strings; Python 3.12
  `SyntaxWarning: invalid escape sequence` is gone (an error in future Python).
- **2.12** new `.gitattributes`: scripts and sources are checked out with LF on every OS.
  Windows checkouts (`core.autocrlf=true`) produced CRLF scripts that fail on Linux
  and in Docker.

### Phase 1 — tests (no FirmAE behaviour change)
- `pytest.ini`, `requirements-dev.txt`, `tests/`: characterization tests for the network
  inference and QEMU command generation, built from two real Phase 0 runs.

### Documentation
- `ARCHITECTURE.md`, `SECURITY.md`, `REFACTORING_PLAN.md`, `TEST_REPORT.md`, this file.
