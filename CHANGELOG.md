# Changelog

All changes are relative to upstream `master` `653565b`. Step numbers refer to
`REFACTORING_PLAN.md`, finding IDs (S1…) to `SECURITY.md`.
**Behaviour change** marks anything a user or script could notice.

## [Unreleased] — refactor/hardening

### Phase 4.3 / 4.4 / 4.5 — `firmae/image.py`, `emulation.conf`, `firmae/check.py` (2026-11-17, "group 2")

Measured on real emulation (WSL2, DIR-868L armel and WNAP320 mipseb, TAP mode; see `TEST_REPORT.md` "Grup 2"). The DHCP
mode with a real firmware, analyze/debug/run/boot, Docker mode and a Python 3.8 runtime are **not** verified.
Scope is deliberately minimal (user decision): no full Python launcher, no native loop/mount/`tarfile`.

- **4.5 `check_emulation` in Python.** `scripts/check_emulation.sh` is a thin wrapper; `firmae/check.py` (with
  `firmae/procutil.py` and `firmae/hostfwd.py`) is the process. The Bash `check_network`, `qemu_pids` and
  `scripts/hostfwd_check.sh` stay for `run_mode.sh`; equivalence is pinned by `tests/unit/test_check_py.py`.
  Fixes: the signal race (audit B4); state files are written with `O_NOFOLLOW`/`O_EXCL`.
- **4.4 data instead of generated Bash.** `makeNetwork.py` writes a validated `scratch/<IID>/emulation.conf`;
  `scratch/<IID>/run.sh` is a fixed wrapper that `exec`s the static `scripts/emulate.sh` (the QEMU parent is
  `emulate.sh`, no extra process). The file is never sourced or eval'd; the grammar is strict in Python and Bash.
  The `scratch/<IID>/run.sh` and `emulation.conf` write refuses symlink targets. `util/compare.py` knows `emulation.conf`.
- **4.3 `makeImage` in Python.** `scripts/makeImage.sh` is a thin wrapper; `firmae/image.py` calls the same external
  tools. Host-side writes no longer follow symlinks planted by the guest (`SECURITY.md` S27). Orphaned chroot/tar
  children on SIGKILL are fixed (guard process group + `PR_SET_PDEATHSIG`, cleanup budget 47 s < `STAGE_GRACE` 60 s).
- **Guest IPv4 class filtering (audit B1, existed before).** Loopback, 0/8, multicast, link-local, reserved and
  255.255.255.255 are rejected in `makeNetwork.py`, `emulate.sh` and `check.py`; a guest IP equal to the host TAP IP is
  dropped; `check.py` skips addresses assigned locally on the host (bind test; disabled with a warning when
  `net.ipv4.ip_nonlocal_bind=1`).
- **Behaviour changes.**
  - `check_emulation`: stale `ping`/`time_ping`/`ip`/`web`/`time_web` are removed at the start; `ip.N` must be a valid,
    usable IPv4 address; `isDhcp` counts only when it is exactly `true`; a firmware whose only addresses are in the
    rejected classes gets no TAP probe.
  - `makeNetwork.py`: colliding multi-network layouts drop the colliding entry.
  - `makeImage`: an invalid architecture fails at the start; an existing directory at a copy target is an error; an
    existing `ttyS1` is replaced; `init`/`service` are copied with mode 0644, a 1 MiB limit and without following
    symlinks; per-step timeouts (tar/chroot 1800 s); cleanup runs `umount` for 10 s, then `umount -l`; children get
    stdin `/dev/null`; every command has one extra `/bin/sh` guard process.
  - `emulate.sh` quotes all paths and validates its input (invalid input: exit 1, no side effects).
  - The dead `get_kernel … true|false` branch was removed; the wrappers (`run.<arch>.sh`) are CDPATH-safe.
- **Still open.** Root `run.sh` and `firmae.config:24` use the `cd "$(dirname…)"` pattern that an exported `CDPATH`
  affects; chroot steps (`fixImage.sh` may run firmware binaries through `PATH`) remain a chroot-escape risk; the
  `add_partition` window is covered only by `release_emulation` (`losetup -j`, no `dmsetup remove`).

### Phase 2.10 / 5.1 / 4.2 — port discovery, DHCP host ports, `firmae.qemu` (2026-11-17)

Uncommitted working-tree changes ("group 1"). Verified by unit tests only; the DHCP mode and the
new `firmae.qemu` start path have **not** been run with a real firmware / real QEMU (no real run had been made when this was written (the first attempt produced no measurement because WSL crashed)).

- **`findPorts` (2.10), behaviour change.** It now parses the kernel's real 4.1 log format
  (`inet_bind[PID: n (name)]: proto:SOCK_X, port:N`; no address is logged, `0.0.0.0` is assumed) as well as the
  old format. Port 0 and ports >= 32768 (ephemeral) are dropped, repeats of the same (proto, port) collapse
  (first bind wins), at most `MAX_PORTS = 256` entries. Real fixtures: DIR-868L udp 19541, 5353, 67, 5355, 137, 53,
  1900 and tcp 4433, 443, 53, 8181, 80, 8182; WNAP320 tcp 80, 443, 22 and udp 161, 137, 138. The generated TAP-mode
  `run.sh` is unchanged (both `tests/fixtures/generated/*.expected` files are byte-identical to HEAD).
- **`qemuCmd(..., hostfwd=)` signature (5.1).** `qemuCmd`, `qemuNetworkConfig` and `qemuArchNetworkConfig` take
  `hostfwd=[(proto, guest port, host port), ...]` (plus `iid`); `None` means "choose with `chooseHostPorts`", `[]`
  means `restrict=on` with no forward rule. The forwards go to one NIC only: the first with a DHCP address (a host port
  cannot be forwarded twice). Existing callers keep working.
- **Audit follow-ups (same day, verified in code; not run with a real DHCP firmware).** New `scripts/hostfwd_check.sh` (sourced by `check_emulation.sh` and `run_mode.sh`): before each probe it checks that the emulation is alive (`qemu_pids`, run.sh pid, zombie check) and after a successful answer that the port's owner is this IID's QEMU (`ss -Htlnp`); no `ss` / unreadable pid gives `web=false` + a warning (before: a foreign process holding the chosen port, while QEMU refused to start, was counted as `web=true`). That a slirp listener shows up under QEMU's pid in `ss -p` is NOT verified. `run_mode.sh`: for a DHCP image (`isDhcp`) analyze is refused without running any tool (exit 60, `ExitCode.ANALYSIS`), debug is refused (exit 50), run mode probes only the mapped ports; TAP branches unchanged. `makeNetwork.py`: the rules go to a user NIC that was really placed (`qemuNetworkConfigAndHostfwd`) and `scratch/<IID>/hostfwd` is read back from the generated run.sh's `-netdev` lines (`hostfwdRulesIn`), so a file means the rules are in QEMU's arguments; `hostfwdBlock` uses the whole IID. Still open: `debug.py`, `analyses/*`, `util/collect_result.py` without DHCP support, and the "Network reachable on 127.0.0.1" message in `firmae/pipeline.py`.
- **DHCP / user-network host ports (5.1).** Host ports come from 127.0.0.1 ports 10000-19999, starting at a
  per-image block of 40 (`hostfwdBlock`), each one checked free by binding it. The mapping is written to
  `scratch/<IID>/hostfwd` (`<tcp|udp> <guest> <host>` per line, symlinks not followed); `run.sh` re-checks the TCP
  host ports before QEMU starts (the check-to-bind race is accepted). `scripts/check_emulation.sh` (DHCP branch)
  validates that file strictly and probes only `http://127.0.0.1:<host port of 80>` / `https://127.0.0.1:<host port of 443>`,
  never the host's own port 80 (fixes the false-positive `web=true`). In DHCP mode `ping` means "web answered"
  and on success `ip` is `127.0.0.1` (the host: analysis tools that take that address as the target are
  still wrong in this mode, see `REFACTORING_PLAN.md` "Takip gerekir").
- **`firmae/qemu.py` (4.2).** `build_initial_argv` / `main`: `python3 -I <kurulum>/firmae/qemu.py initial <arch> <IID> <QEMU_INIT>` (cwd and `PYTHON*` stay off the module path);
  `scripts/run.{armel,mipseb,mipsel}.sh` are thin wrappers. The process ends in `os.execvpe` (no shell or Python
  process stays in between; the old Bash left one). Behaviour differences from the old scripts: `FIRMAE_NET` /
  `FIRMAE_KERNEL` accept only `true` / `false` (they were run as commands); `firmae.config` is found from the
  script's tree, not the working directory; IIDs such as `+5` or ` 5` are rejected; a `FIRMAE_DIR` containing spaces
  works; SIGPIPE / SIGXFSZ are reset to default before exec. The wrapper runs `python3 -I` on the file (cwd and `PYTHON*`
  variables stay off the module path; `qemu.py` appends the install root to the END of `sys.path`), so a fake `firmae/` package in the
  current directory no longer replaces the real code (an audit finding against the earlier `python3 -m firmae.qemu` call); users can no longer
  redirect `firmae` with `PYTHONPATH`. The deliberate differences are tested separately (`tests/unit/golden_old_quirks.json`): a leading-zero IID
  (`08`, `09`) and a `FIRMAE_NET` other than `true`/`false` are rejected (the old scripts still started QEMU; `FIRMAE_NET=yes` ran `/usr/bin/yes` and hung).
- **Tests.** `tests/unit/test_qemu_cmd.py`: the user-network test passes explicit `hostfwd=` ports (`127.0.0.1:10000-:80`
  ...) and keeps its claim (`restrict=on`, every forward on 127.0.0.1, none on 0.0.0.0 or with an empty address); a new test
  covers `hostfwd=None` and `hostfwd=[]`. The `/proc/<pid>/stat` read race (the one fixed in `test_audit_fixes.py`) is
  closed the same way in `test_procgroup.py`, `test_lifecycle_functions.py`, `test_pipeline.py` and
  `test_pipeline_hwprofile.py`: a vanished process or an empty / truncated `stat` counts as "process gone"; no assertion
  was weakened.

### Test and docs fixes (2026-11-17)

- `tests/unit/test_audit_fixes.py`: `test_normal_exit_leaves_no_background_process_behind` was flaky (12/100 and 6/150 runs failed with `ProcessLookupError` from reading `/proc/<pid>/stat` of a process being reaped); the race is closed, the assertion is unchanged (0/200 failures afterwards, TEST_REPORT.md section G). `REFACTORING_PLAN.md` now has a step-by-step status table; stale "not committed" / "428 tests" / "Phase 6 not started" statements in the plan, SECURITY.md, TEST_REPORT.md and ARCHITECTURE.md were corrected (no code change).

### Phase 6.1 — hardware profile (2026-11-16)

A new, purely informational pipeline step that records which peripherals a firmware
references and which of them failed in the serial log. Unit-tested (stub CLI, synthetic
input, real CLI on a synthetic tarball) and exercised in real emulation runs of two
firmwares (DIR-868L ARM, WNAP320 MIPS).

- **Real-run validation:** TEST_REPORT.md ("Faz 6.1 — donanım profili"). Not covered there:
  Python 3.8, a second independent audit, analyze/debug/run/boot modes, Docker mode.

- **New step `hwprofile`** (`firmae/pipeline.py`, `_hwprofile_static`): after architecture
  detection and before `tar2db`/`makeImage`, runs
  `python3 -m firmae.hwprofile --tar images/<IID>.tar.gz --out scratch/<IID>/hw_profile.json`.
- **New step `hwprofile-dynamic`** (`_hwprofile_dynamic`): after `makeNetwork.py`, runs
  `... --update --out ... --serial-log qemu.initial.serial.log --serial-log qemu.final.serial.log`
  (only the logs that exist; skipped when there is none or no static profile).
- **Never fatal:** a failing CLI, a timeout or a missing `firmae.hwprofile` module only
  produces a `[*]` line and `scratch/<IID>/hwprofile.log`; the exit code, `result` and the
  `time_*` files of the run are unchanged. Only `Exception` is caught, so Ctrl-C and SIGTERM
  still propagate (the CLI runs through `scripts.procgroup.run_with_timeout`, which stops its
  process group first). Check mode that skips emulation (earlier success) leaves an existing
  profile untouched.
- **Behaviour change:** one extra summary line at the end of a run that wrote a profile, e.g.
  `[hw] gpio=failing watchdog=failing nvram=covered i2c=not-referenced spi=not-referenced (scratch/1/hw_profile.json)`.
  The file is untrusted: it is opened with `O_NOFOLLOW`, read up to 8 MiB, a broken one gives a
  fixed warning line, and only known peripheral names and known status values are printed
  (`unsupported` and `failing` first).
- **New environment variables:** `FIRMAE_HWPROFILE=0` switches both steps off;
  `FIRMAE_TIMEOUT_HWPROFILE` (default 300 s, 0 = no limit, validated like the other
  `FIRMAE_TIMEOUT_*`); the CLI gets `--timeout` = 80% of the value (see the audit entry below).
- **After the independent audit (2026-11-17), pipeline side:**
  - **Behaviour change:** the dynamic step also runs when the network step failed or timed out
    (the initial serial log is then the most useful evidence). It runs in `run_firmware`'s
    `finally`, after `release_emulation` (QEMU gone, logs final; the release does not delete
    them) and before the image lock is dropped. The original exit code and message are kept;
    on Ctrl-C/SIGTERM it does not run.
  - **Behaviour change:** an old `hw_profile.json` (file or symlink itself, never its target)
    is removed before the static step; if that step does not exit 0, the dynamic step and the
    summary are skipped, so a stale profile is neither updated nor summarised.
  - **Behaviour change:** the CLI's `--timeout` is 80% of the outer limit (at least 1 s; was
    limit-30, at least 30, which exceeded the outer limit below 60 s); with no outer limit
    (`FIRMAE_TIMEOUT_HWPROFILE=0`) `--timeout 240` is passed (was: none).
  - `stage_timeout`: a very long `FIRMAE_TIMEOUT_*` value (thousands of digits) no longer raises
    an unhandled `ValueError` (treated as not set); upper bound 7 days for all stages.
  - The summary reads up to 8 MiB (was 4) and prints the fixed line
    `[hw] profil okunamadı (scratch/<IID>/hw_profile.json)` for an oversized or corrupt profile
    instead of nothing.
  - Contract of the profiler CLI (documented, no pipeline code change): new option
    `--mem-limit-mb` (default inside the CLI; the pipeline does not pass it), new field
    `dynamic.modules`.
  - Tests: new `tests/unit/test_hwprofile_integration.py` (real `python3 -m firmae.hwprofile`
    on a synthetic tarball and a recorded serial log); `test_pipeline_hwprofile.py` extended.
- **After the commit (2026-11-17), profiler CLI only:** a process that reached `RLIMIT_AS` could spin
  at 100% CPU inside `tarfile` and ignore `--timeout` (flaky `test_cli_rlimit_catches_what_the_bounds_miss`).
  The CLI now stops the scan with `limits_hit: memory` at 75% of `--mem-limit-mb` (Linux, `/proc/self/statm`),
  ends the process with exit 1 `--timeout` + 30 s after start as a last resort, and keeps an 8 MiB reserve for
  a `MemoryError`. Library functions, pipeline arguments and the profile schema are unchanged. Test count
  769 -> 772 (TEST_REPORT.md, "Faz 6.1", F).
- **SECURITY.md:** S26 (attack surface of the profiler), updated with the audit findings.
- **Documentation:** `ARCHITECTURE.md` section 9 corrected: libnvram replaces the firmware's own
  nvram API symbols and does not intercept libc `open`/`ioctl`; the instrumented, downloaded
  kernel (not this repository) does the `LD_PRELOAD`, so a second preload library needs a kernel
  change or another loading path; stale line references fixed; `/firmadyne/strace` is copied
  into the image but never called. Exploration findings (two firmwares: DIR-868L ARM, WNAP320
  MIPS) recorded with their limits.
- **Tests:** `tests/unit/test_pipeline_hwprofile.py` (new). `tests/unit/test_pipeline.py` sets
  `FIRMAE_HWPROFILE=0` in its fixture so its stub tree does not start the profiler.
- **Not done:** `strace`-based dynamic tracing (6.2), a report over the Phase 0 set (6.3), `libhwmock`
  (6.4), the kernel hook registration errors (`Cannot register character device`).

### Second hardening pass (2026-11-16)

Two rounds of parallel fixes plus an independent review (see `TEST_REPORT.md`, last section).
Test count 181 -> 428 (WSL Ubuntu 24.04, Python 3.12, not root); new findings S20-S25 and
the closing of S19 are in `SECURITY.md`. Not committed at the time of writing.

#### Security

- **S20 (P0) command injection from the serial log:** `scripts/makeNetwork.py` took interface
  and bridge names from the guest's serial log and pasted them into the generated root
  script without validation. Parsing now uses strict patterns anchored with `\Z` (a trailing
  newline is rejected; `$` accepts it), `checkQemuCmdInputs` validates everything a second
  time before the script is written, and values are passed through `re.escape`. Numbers that
  are absurdly long skip the line instead of reaching `int()`.
- **S21 (P1) write to the host through a symlink in the image:** every write into the mounted
  image (`openImageFile`, `firmadyneFile`) refuses a symlink or a non-regular file; the
  generated `run.sh` template carries a 16-line check block for the files it writes itself
  (`/firmadyne` directory, `network_type`, `net_bridge`, `net_interface`, `debug.sh`);
  `mount_partition` and `makeNetwork.py` mount with `nodev,nosuid`.
- **S22 (P1) `scripts/inferDefault.py`:** does not read a symlink or a non-regular file of the
  image (it could read `/proc/kcore` or host files); the copy of `nvram_files` does not
  follow symlinks.
- **S23 (P2) guest-controlled resource use:** serial log read at most 64 MB; at most 4
  networks, 64 interface records and 32 extra `hostfwd` ports (port 0 is rejected);
  `inferDefault.py` is bounded to 600 s by `makeNetwork.py`, reads at most 64 MiB per file,
  keeps at most 10 000 NVRAM keys of at most 256 bytes and no longer takes quadratic time
  (1 MB file with 40k keys: 7.62 s -> 0.59 s); `fwscan.py` printable-run scan is linear
  (an 80 KB printable block took 16.8 s); file names containing blanks/control characters
  are skipped.
- **S24 (P1) another installation's QEMU was stopped:** `qemu_pids` (`firmae.config`) matches
  `/proc/<pid>/cmdline` against this installation's full `scratch/<IID>/image.raw` path
  instead of a name pattern, so a QEMU of another checkout is left alone (verified in the
  real run: an unrelated `qemu-system-arm` / `qemu-system-mipsel` survived).
- **S25 (P2) no locking between concurrent runs:** see "Fixed" (firmware and image locks).
- **S19 (P1) `util/compare.py`:** rewritten without a shell; resolves and detaches only its
  own loop device; mounts `ro,nodev,nosuid,noexec`.
- `secure_workdir` refuses `scratch/<IID>` when it is a symlink; `fuzzer.py` extracts with
  `tar --no-same-owner --no-same-permissions`.

#### Fixed

- **Locks (S25):** `firmae/pipeline.py` takes `scratch/.locks/<md5 of the firmware>.lock`
  BEFORE the first extraction (the image id is not known yet) and
  `scratch/<IID>/.firmae.lock` once it is. A run that cannot get a lock exits with the new
  code 75 and touches nothing. After the locks are held, leftovers of an earlier killed run of
  that IID (QEMU, mount, loop, TAP) are released once. The lock file descriptors are not
  inherited by stages. `.locks/*.lock` files are not deleted (they accumulate).
- **Stage timeouts:** `tar2db` and image 3600 s; network `900 + candidates x (TIMEOUT +
  CHECK_TIMEOUT + 300)`; `FIRMAE_TIMEOUT_TAR2DB`, `_IMAGE`, `_NETWORK` override (0 = no limit).
  Return codes of the helper scripts are checked instead of ignored.
- **check mode:** an image whose `result` is already `true` gets that file rewritten
  unchanged, so `docker-helper.py` (which ignores results older than the run) accepts it.
- `check_network`: returns at once when there is no IP (it used to spin); at most 8 IPs;
  the deadline is checked after every IP.
- `fuzzer.py` / `fwscan.py`: a malformed log line, several commas or a non-UTF-8 file no
  longer crash; the extracted tree is removed on failure too; sockets are closed.
- `analyses_all.sh`: warns and continues when `routersploit/rsf.py` is missing (empty
  submodule); the exit code of each step goes to `analysis_log/steps`; `result` is still an
  unconditional `true`.
- `initializer.py`: `driver.quit()` in `try/finally`, also when a step raises. `debug.py`:
  correct TAP name (`tap<IID>_<n>`), socket timeout, files read with `with`.
- `tar2db.py`: digests computed in chunks, `ON CONFLICT DO NOTHING`, errors are no longer
  swallowed, parameterised queries; files with identical content now get a row for every name.
- `extractor.py`: the temporary directory is removed on every path (also SIGTERM).
- `makeImage.sh`: when `/bin/a` is a FIFO, device or symlink it is removed and re-created.
- `docker-helper.py`: waits up to 300 s for the image id, ignores a `result` older than the
  run, reports failures, skips a malformed `.list` line.

#### Changed behaviour

- **Behaviour change:** new exit code **75** (`ExitCode.BUSY`): another FirmAE run holds this
  firmware or image; the firmware is skipped.
- **Behaviour change:** limits above (serial log 64 MB, 4 networks, 64 interface records, 32
  extra ports, 10 000 NVRAM keys, 64 MiB files, 600 s for `inferDefault.py`); firmware beyond
  them is processed with the excess ignored (usually with a warning).
- **Behaviour change:** `tar2db.py` writes one row per file name, so `object_to_image` has more
  rows than before for firmware with duplicate content; it exits 1 on a database error (it
  used to exit 0 and import nothing) and 2 on wrong usage.
- **Behaviour change:** `util.py get_iid|get_brand` exit 1 with an empty stdout on a database
  error; "no record" stays exit 0. `extractor.py` exits 1 when the database is unreachable.
  The pipeline reports a failed image-id or architecture lookup as exit 12 (database) instead of 11 or 20.
- **Behaviour change:** `docker-helper.py` exits 1 if any firmware failed (it always exited 0);
  empty list: exit 1.
- **Behaviour change:** `makeImage.sh` exits 1 with an error when `/bin` of the image is not a
  directory.
- **Behaviour change:** `util/compare.py` mounts read-only and no longer touches loop devices
  it did not create.
- Generated `run.sh` differs from the previous commit only by the 16-line check block.
- Not changed: `result` of `analyses_all.sh` is always `true`; TAP names and the iptables
  comment `firmae:<IID>` are one namespace per host (two installations with the same IID
  collide); `findPorts` does not recognise the real 4.1 kernel log format.

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
- **Found then, fixed in the second pass (2026-11-16):** S19 `util/compare.py` (see SECURITY.md).

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
