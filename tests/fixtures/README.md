# Test fixtures

Captured on 2026-11-04 during the Phase 0 baseline (`TEST_REPORT.md`), with
FirmAE `653565b`, QEMU 8.2.2 and the kernels from `download.sh`.

| File | Source |
|---|---|
| `serial/serial_armel_dir868l.log` | `scratch/1/qemu.initial.serial.log` of `DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip` (sha256 `43fa0196…2675263`), **only** the lines the network parser reads (`inet_bind`, `__inet_insert_ifa`, `ioctl_SIOCSIFHWADDR`, `br_dev_ioctl`, `br_add_if`, `register_vlan_dev`) |
| `serial/serial_mipseb_wnap320.log` | same, for `WNAP320_V2.0.3.zip` (sha256 `4c169735…2b9e06a`) |
| `generated/run_sh_armel_dir868l.expected` | `scratch/1/run.sh` that `makeNetwork.py` generated in the same run |
| `generated/run_sh_mipseb_wnap320.expected` | same, for WNAP320 |

The serial excerpts are the complete set of parser-relevant lines, so the
parsers see exactly what they saw during the real run. To refresh them,
re-run the baseline and extract with:

```bash
grep -aE 'firmadyne: (inet_bind|__inet_insert_ifa|ioctl_SIOCSIFHWADDR|br_dev_ioctl|br_add_if|register_vlan_dev)' \
  scratch/<IID>/qemu.initial.serial.log
```
