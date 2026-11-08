# Changelog

All changes are relative to upstream `master` `653565b`. Step numbers refer to
`REFACTORING_PLAN.md`, finding IDs (S1…) to `SECURITY.md`.
**Behaviour change** marks anything a user or script could notice.

## [Unreleased] — refactor/hardening

### Review of Phases 0-5 (2026-11-08): bugs, security, memory, performance

Found by static analysis, a ResourceWarning-strict test run, probes and real emulation;
each item has a regression test (`tests/unit/test_audit_fixes.py` and others).

- **Memory (regression I introduced in 2.1):** `analyses/fuzzer/fwscan.py` read whole files
  into memory (+300 MB for a 300 MB file, +413 MB for `strings`); the shell tools it replaced
  streamed. It now reads 1 MiB blocks; peak memory is bounded (test: < 16 MB for a 48 MB file).
- **Disk/time:** `scripts/getArch.py` copied whole tar members (200 MB) to a temporary file
  for `file`; it now copies the first 1 MiB (identical result, `file` reads the header).
- **Bug (race, found in a real run):** `add_partition` (Phase 3 rewrite) returned as soon as
  `/dev/loopNp1` existed; once, `mount` failed with ENOENT (`run.sh` exit 40). It now waits until
  the kernel reports a size and udev has settled, and confirms the node is still there;
  `mount_partition` retries the mount (makeImage.sh, generated run.sh, makeNetwork.py). The race
  could NOT be reproduced in a 150-cycle stress test (0 failures before and after), so the fix
  rests on the error message and reasoning, not on a reproduction; B, A, B then ran clean.
- **Bug:** the log lines of a firmware written before its image id was known carried the id of
  the previous firmware (`firmae/log.py`).
- **Orphans:** `run_with_timeout` now also kills the process group after a NORMAL exit of a stage.
- **Hangs:** helper scripts (database lookups, architecture detection) and the cleanup call have
  timeouts (600 s / 180 s); `PGCONNECT_TIMEOUT=30` for psycopg2; the image id must be ASCII digits
  (`str.isdigit()` also accepts e.g. "²").
- **Security S14 (raised to P1):** `update_database("kernel_version", desc)` pasted binwalk's
  description of the image (firmware content) into SQL: SQL injection from the firmware. Now
  parameterised, column names checked against a list; `cur` could also be undefined (NameError).
- **Security S13:** the database password comes from `FIRMAE_DB_PASSWORD` (default unchanged);
  `install.sh` creates the role with it, `docker-helper.py` forwards it.
- **Security S17:** `debug.py` tcpdump / file transfer no longer build shell commands.
- **S18:** `console.c` checks the result of `open()` (precedence). The prebuilt `console.*`
  downloaded by `download.sh` are not rebuilt.
- `scripts/inferKernel.py` and `inferDefault.py` no longer use a shell.
- ShellCheck: the `error` (SC2145) in `check_emulation.sh` and the SC2155/SC2174 warnings in
  files I added are fixed; the remaining warnings are in code I did not write.
- Tests: closed two files my own tests left open; the suite passes with ResourceWarning as error.
- **Open, new:** S19 `util/compare.py` (see SECURITY.md).

### Phase 5 — network isolation (TAP mode: firewall rules instead of namespaces)

- **S8** `firmae.config` (`isolate_guest_network`, `unisolate_guest_network`), generated
  `run.sh`, `release_emulation`, `delete.sh`: in TAP mode the guest ran on the other end of
  a host interface and could open connections to every host service listening on that
  address, and -- where the host forwards packets (Docker Desktop's WSL distribution has
  `ip_forward=1`) -- reach the LAN through the host. Per address family (iptables and
  ip6tables) two rules tagged `firmae:<IID>` match `tap<IID>_+` (TAP and its VLANs): new
  connections from the guest to the host are dropped, nothing from the guest is forwarded.
  Connections the host opens to the guest (web check, nmap, fuzzer, debug shell) are not
  affected. The rules are applied after the network is up and before QEMU starts, and
  removed on every exit path; the number of dropped connection attempts is recorded in
  `scratch/<IID>/isolation`.
  - Behaviour change: firmware cannot open connections to the host or beyond it.
  - Behaviour change: if iptables is missing the emulation still runs, but a warning is
    printed and `scratch/<IID>/isolation` says "not applied". `install.sh` installs iptables.
  - Decision: per-analysis network namespaces (plan 5.4) were not used. Every host-side tool
    (check_network, nmap, fuzzer, debug.py) would have to run inside the namespace; the
    firewall rules reach the same goal for guest-to-host traffic without touching them.
    The guest can still reach other guests on the same host only if the host forwards
    between TAP interfaces; the FORWARD rule blocks that too.

- **S8** `scripts/run.<arch>.sh`: the initial emulation, where untrusted firmware runs for
  the first time, used `-netdev user` without restrictions, so it could reach the host,
  the LAN and the internet. `restrict=on` isolates the guest (DHCP still works).
  The DHCP-mode final emulation (`makeNetwork.py`) gets `restrict=on` as well; explicit
  `hostfwd` rules are not affected by it.
  - Behaviour change: firmware cannot reach the outside world during the initial
    emulation (e.g. ntp/dns/cloud calls fail instead of succeeding).
- **S8** `scripts/makeNetwork.py`: `hostfwd` rules listen on `127.0.0.1` (were all
  interfaces), so the emulated web UI is no longer exposed to the LAN. Placeholder NICs
  (`-netdev socket`) listen on `127.0.0.1`, in a per-image range
  `20000 + 4*(IID % 10000) + n` instead of the fixed `:2000-2003` on all interfaces, so
  parallel emulations no longer collide.
  - Behaviour change: the DHCP-mode web UI is reachable from the host itself only.
- **S12** QEMU monitor and serial sockets moved from `/tmp/qemu.<IID>[.S1]` to
  `scratch/<IID>/run/{monitor,serial1}.sock` (directory mode 0700). The monitor allows
  code execution with QEMU's privileges. `debug.py`, `release_emulation` and `delete.sh`
  follow; the old `/tmp` names are still removed.
  - Behaviour change: scripts that connected to `/tmp/qemu.<IID>.S1` must use the new path.
    Unix sockets cannot be created on Windows drives mounted in WSL (`/mnt/c`); keep the
    project on the Linux file system.
- Not done: dynamic host ports for `hostfwd` and the port-discovery fix (2.10): with the
  discovery fixed, DHCP-mode firmware would try to forward tens of ports (22, 53, 161, ...)
  and QEMU does not start when one is busy on the host; per-analysis network namespaces (5.4,
  needs a separate decision). TAP-mode final emulation is not isolated from the host.

### Phase 4 — Python orchestration (partial: stage orchestration only)

- New package `firmae/` (`errors`, `config`, `state`, `log`, `pipeline`, `__main__`).
  `run.sh` is now a three-line wrapper (`python3 -m firmae`); the command line is
  unchanged. The pipeline runs the same stages with the same messages, log file
  names and `scratch/<IID>/` files; stage scripts are called with argument lists.
  The terminal-bound modes (analyze, debug, run, boot) moved unchanged into
  `scripts/run_mode.sh`.
  - Behaviour change: **exit codes.** run.sh used to exit 0 whatever happened. Now:
    0 ok, 2 usage, 3 not root / no config, 10 extraction failed, 11 no image id,
    12 database unreachable (Docker), 20 architecture, 30 image, 40 network,
    50 web unreachable (check mode), 124 timeout, 129/130/143 SIGHUP/SIGINT/SIGTERM.
    The text in `scratch/<IID>/result` is unchanged.
  - Behaviour change: a failing firmware no longer stops a directory run; all files
    are processed and the exit code is the first failure's. Files of a directory are
    processed in sorted order (was `find` order).
  - Behaviour change: `-b auto` is resolved for every firmware (the old script
    overwrote `BRAND` after the first file, so later files reused its brand).
  - Behaviour change: usage errors exit 2 (was 1); in check mode "web unreachable" exits
    50 (was 0).
  - New: `scratch/<IID>/firmae.log`, every line with timestamp, level, image id and stage.
  - Whatever the exit path, the image's QEMU, mount, loop devices, TAP/VLAN and
    sockets are released after each firmware (previously only at the end of the script).
- Not done (planned 4.2-4.5, 4.7): porting `makeImage.sh`, `makeNetwork.py`, `run.<arch>.sh`
  and `check_emulation.sh` to Python, concurrency locks, resource limits, metrics.

### Phase 3 — process and resource lifecycle

- `firmae.config`: `qemu_pids`/`stop_qemu` find and stop exactly one image's QEMU
  (command line contains `/scratch/<IID>/image.raw`; SIGTERM, SIGKILL after 10 s).
  `release_emulation` frees an image's QEMU, mount, loop devices, TAP/VLAN interfaces
  and `/tmp/qemu.<IID>*` sockets; idempotent. `add_partition` uses
  `losetup --find --show` and gives up after 30 s instead of waiting forever.
  - Behaviour change: the old `ps aux | grep qemu-system-<arch> | kill` killed every
    emulation of that architecture (mipseb also killed mipsel); only the image's own
    QEMU is stopped now.
- `scripts/procgroup.py`, `scripts/makeNetwork.py`: the initial emulation runs in its own
  process group; after `TIMEOUT` it gets SIGINT, SIGKILL 15 s later; Ctrl-C/SIGTERM stop
  the group before exit. Replaced `os.system` (it ignored SIGINT while waiting). A failed
  `mount` is no longer ignored.
- Generated `scratch/<IID>/run.sh`: QEMU runs in the background under a `cleanup` trap
  (EXIT/INT/TERM/HUP) that stops QEMU, unmounts, detaches the loop device and removes
  the TAP/VLAN interfaces, also when `START_NET` fails half-way or `set -e` exits
  early. Exit codes 130/143/129 for signals.
  - Behaviour change: QEMU's exit status is still ignored (as with `| true`).
- `run.sh`, `scripts/check_emulation.sh`: cleanup traps; long steps run in the background
  and are awaited, so Ctrl-C/SIGTERM act at once; extractor `timeout` gets `-k 30`.
  - Behaviour change: an interrupted run now releases everything of its image and the
    next run of the same firmware works (before: leaked QEMU held `image.raw` locked).

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
