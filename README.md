# FirmAE

> **This is a modified fork of [pr0v3rbs/FirmAE](https://github.com/pr0v3rbs/FirmAE)** (MIT License, see
> `LICENSE.txt`; copyright of the original authors is retained). The changes (security fixes, process and
> resource handling, network isolation, a Python pipeline, tests) are described in `CHANGELOG.md`,
> `SECURITY.md`, `ARCHITECTURE.md`, `REFACTORING_PLAN.md` and `TEST_REPORT.md`.


FirmAE is a fully-automated framework that performs emulation and vulnerability
analysis. FirmAE significantly increases the emulation success rate (From
[Firmadyne](https://github.com/firmadyne/firmadyne)'s 16.28% to 79.36%) with
five arbitration techniques. We tested FirmAE on 1,124 wireless-router and
IP-camera firmware images from top eight vendors.

We also developed a dynamic analysis tool for 0-day discovery, which infers web
service information based on the filesystem and kernel logs of target firmware.
By running our tool on the succesfully emulation firmware images, we discovered
12 new 0-days which affect 23 devices.

# Installation

Note that we tested FirmAE on Ubuntu 20.04 (upstream) and, in this fork, on WSL2 Ubuntu 24.04. **Python 3.10 or newer is required** (`requirements.txt`; Python 3.8 is no longer supported; measured only with 3.12.3). On Ubuntu 24.04 there are known issues for the host install:
the system Python is externally managed (PEP 668), so `install.sh` stops unless you opt in to
pip's `--break-system-packages` (`PIP_BREAK_SYSTEM_PACKAGES=1 ./install.sh` or
`FIRMAE_PIP_ARGS=--break-system-packages ./install.sh`; this may break distribution-managed
Python packages; a virtual environment does not work, because the pipeline runs as root with the system Python); and `sasquatch` (built by
binwalk's `deps.sh`) does not build with GCC 13 without changes (the Docker image builds it from a pinned commit with fixes, see below). See `TEST_REPORT.md`.

1. Clone `FirmAE`
```console
$ git clone --recursive https://github.com/pr0v3rbs/FirmAE
```

2. Run `download.sh` script. The 27 downloaded files are checked against `binaries.sha256` (SHA-256) and a mismatch deletes the file and exits 1. **Default mode is `strict`**; `FIRMAE_VERIFY_DOWNLOADS=warn` only warns for unlisted/unknown hashes. The hashes pin the current upstream release assets; they do not prove where those files came from.
```console
$ ./download.sh
```

3. Run `install.sh` script.
```console
$ ./install.sh
```

# Usage

1. Execute `init.sh` script.
```console
$ ./init.sh
```

2. Prepare a firmware.
```console
$ wget https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip
```

3. Check emulation
```console
$ sudo ./run.sh -c <brand> <firmware>
```

4. Analyze the target firmware

* Analysis mode uses the FirmAE analyzer

```console
$ sudo ./run.sh -a <brand> <firmware>
```

* Run mode helps to test web service or execute custom analyzer

```console
$ sudo ./run.sh -r <brand> <firmware>
```

## Exit codes, timeouts and environment variables (fork)

`run.sh` no longer exits 0 on every failure: the codes are listed in `firmae/errors.py` (for
example 10 extraction, 30 image, 40 network, 50 web unreachable, 75 another FirmAE run holds
the same firmware or image and this one was skipped). Stage time limits can be changed with
`FIRMAE_TIMEOUT_TAR2DB`, `FIRMAE_TIMEOUT_IMAGE` and `FIRMAE_TIMEOUT_NETWORK` (seconds, 0 = no
limit); the database password is read from `FIRMAE_DB_PASSWORD` (default unchanged). Details
and behaviour changes: `CHANGELOG.md`.

Hardware profile (informational, never changes the result or the exit code): before the
image is built and after the network inference, `firmae.hwprofile` records which peripherals
(GPIO, watchdog, NVRAM, I2C, SPI, ...) the firmware references and which ones failed in the
serial log, in `scratch/<IID>/hw_profile.json` (log: `hwprofile.log`), and the run prints one
`[hw] gpio=failing ... (path)` line. `FIRMAE_HWPROFILE=0` switches it off;
`FIRMAE_TIMEOUT_HWPROFILE` sets its time limit in seconds (default 300, 0 = no limit; the
profiler itself always gets a budget of 80% of it, or 240 s without a limit; all
`FIRMAE_TIMEOUT_*` are capped at 7 days). The serial-log step also runs when network
inference failed. A profile from an earlier run is deleted first, and a corrupt profile gives
`[hw] profil okunamadı (...)` instead of a summary. Not yet verified in a real emulation run; no peripheral is emulated by it. See
`ARCHITECTURE.md` section 9.

DHCP firmware (QEMU user-mode network, fork): the emulated web UI is reachable only on the
host's loopback, at `http://127.0.0.1:<host port>` / `https://127.0.0.1:<host port>`. The host
ports are chosen from 10000-19999 and recorded in `scratch/<IID>/hostfwd` (`<tcp|udp> <guest port>
<host port>` per line, e.g. `tcp 80 10000`). `run.sh -c` then reports `ip=127.0.0.1`, which is
the host itself; analysis (`-a`) and debug tools that use that address are not usable in this mode yet (see
`REFACTORING_PLAN.md`). This mode has not been verified in a real emulation run.

## Debug

After `run.sh -c` finished.

### 1. User-level basic debugging utility.

Useful when an emulated firmware is network reachable or not
* It supports `socat` connection, `nc` reverse shell (31337) and `telnet` connection (31338)
* And the setup will be done automatically

```console
$ sudo ./run.sh -d <brand> <firmware>
```

### 2. Kernel-level boot debugging.

```console
$ sudo ./run.sh -b <brand> <firmware>
```

## Turn on/off arbitration

Check the five arbitrations environment variable in the `firmae.config`
```sh
$ head firmae.config
#!/bin/sh

FIRMAE_BOOT=true
FIRMAE_NETWORK=true
FIRMAE_NVRAM=true
FIRMAE_KERNEL=true
FIRMAE_ETC=true

if (${FIRMAE_ETC}); then
  TIMEOUT=240
```

## Docker

The image (`fcore:24.04`, about 5 GB) is built on **Ubuntu 24.04**. On Windows, enable Docker Desktop's WSL
integration for the distribution you run FirmAE in. By default the container is started **without
`--privileged`**, with `--cap-add SYS_ADMIN --cap-add NET_ADMIN --device /dev/loop-control --device /dev/net/tun
--device-cgroup-rule 'b 7:* rmw'` (this is still close to root, see `SECURITY.md` S7). Measured with `-ec` on two
firmware images (about 7 minutes each); `-ea`, `-ed`, `-er` and parallel containers are not verified.

Environment variables (fork), also described in `SECURITY.md` / `ARCHITECTURE.md` section 12:

| Variable | Effect |
|---|---|
| `FIRMAE_DB_PORT` | PostgreSQL port for all database clients (default: libpq default / `PGPORT`) |
| `FIRMAE_DOCKER_PRIVILEGED=1` | use the old `--privileged -v /dev:/dev` flags |
| `FIRMAE_DOCKER_APPARMOR=unconfined` | required on AppArmor-enabled daemons for the narrowed mode |
| `FIRMAE_EXTRACT_USER`, `FIRMAE_EXTRACT_TMP` | opt-in: run firmware extraction as an unprivileged user (default off: device nodes, setgid bits and symlink mtimes are lost; host mode only) |
| `FIRMAE_BROWSER_USER`, `FIRMAE_BROWSER_TMP` | opt-in: run the headless-browser step as an unprivileged user (Chrome itself not verified) |
| `FIRMAE_CREATE_USERS=1` | `install.sh` creates those users |
| `FIRMAE_VERIFY_DOWNLOADS=warn` | `download.sh` only warns on unlisted/unknown hashes (default `strict`) |

First, prepare a docker image.
```console
$ ./docker-init.sh
```

### Parallel mode

Then, run one of the below commands. ```-ec``` checks only the emulation, and
```-ea``` checks the emulation and analyzes vulnerabilities.

```console
$ ./docker-helper.py -ec <brand> <firmware>
$ ./docker-helper.py -ea <brand> <firmware>
```

Here, `<firmware>` can be a text file that lists the paths of firmware image.
Check the sample file at [./examples/test.list](./examples/test.list).

### Debug mode

After a firmware image successfully emulated.
```console
$ ./docker-helper.py -ed <firmware>
```

# Evaluation

## Emulation result

Google spreadsheet -
[view](https://docs.google.com/spreadsheets/d/1dbKxr_WOZ7UmneOogug1Zykj1erpfk-GzRNni8DjroI/edit?usp=sharing)

## Dataset

Google drive -
[download](https://drive.google.com/file/d/1hdm75NVKBvs-eVH9rKb5xfgryNSnsg_8/view?usp=sharing)

# CVEs

### ASUS
- [CVE-2019-20082](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2019-20082)

### Belkin
- [Belkin01](https://github.com/pr0v3rbs/CVE/tree/master/Belkin01)

### D-Link
- [CVE-2018-20114](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-20114)
- [CVE-2018-19986](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990#cve-2018-19986---hnap1setroutersettings)
- [CVE-2018-19987](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990#cve-2018-19987---hnap1setaccesspointmode)
- [CVE-2018-19988](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990#cve-2018-19988---hnap1setclientinfodemo)
- [CVE-2018-19989](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990#cve-2018-19989---hnap1setqossettings)
- [CVE-2018-19990](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990#cve-2018-19990---hnap1setwifiverifyalpha)
- [CVE-2019-6258](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2019-6258)
- [CVE-2019-20084](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2019-20084)

### TRENDNet
- [CVE-2019-11399](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2019-11399)
- [CVE-2019-11400](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2019-11400)

# Authors
This research project has been conducted by [SysSec Lab](https://syssec.kr) at KAIST.
* [Mingeun Kim](https://pr0v3rbs.blogspot.kr/)
* [Dongkwan Kim](https://0xdkay.me/)
* [Eunsoo Kim](https://hahah.kim)
* [Suryeon Kim](#)
* [Yeongjin Jang](https://www.unexploitable.systems/)
* [Yongdae Kim](https://syssec.kaist.ac.kr/~yongdaek/)

# Citation
We would appreciate if you consider citing [our
paper](https://syssec.kaist.ac.kr/pub/2020/kim_acsac2020.pdf) when using FirmAE.

```bibtex
@inproceedings{kim:2020:firmae,
  author = {Mingeun Kim and Dongkwan Kim and Eunsoo Kim and Suryeon Kim and Yeongjin Jang and Yongdae Kim},
  title = {{FirmAE}: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis},
  booktitle = {Annual Computer Security Applications Conference (ACSAC)},
  year = 2020,
  month = dec,
  address = {Online}
}
```
