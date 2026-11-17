# Test fixtures

Captured on 2026-11-04 during the Phase 0 baseline (`TEST_REPORT.md`), with
FirmAE `653565b`, QEMU 8.2.2 and the kernels from `download.sh`.

| File | Source |
|---|---|
| `serial/serial_armel_dir868l.log` | `scratch/1/qemu.initial.serial.log` of `DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip` (sha256 `43fa0196…2675263`), **only** the lines the network parser reads (`inet_bind`, `__inet_insert_ifa`, `ioctl_SIOCSIFHWADDR`, `br_dev_ioctl`, `br_add_if`, `register_vlan_dev`) |
| `serial/serial_mipseb_wnap320.log` | same, for `WNAP320_V2.0.3.zip` (sha256 `4c169735…2b9e06a`) |
| `generated/run_sh_armel_dir868l.expected` | `scratch/1/run.sh` that `makeNetwork.py` generated in the same run |
| `generated/run_sh_mipseb_wnap320.expected` | same, for WNAP320 |
| `generated/emulation_armel_dir868l.expected` | `scratch/<IID>/emulation.conf` that the current `makeNetwork.py` writes for the DIR-868L fixture (Phase 4.4) |
| `generated/emulation_mipseb_wnap320.expected` | same, for WNAP320 |
| `generated/run_sh_wrapper.expected` | the fixed `run.sh` wrapper (it only execs `scripts/emulate.sh`) that `makeNetwork.py` now writes |
| `legacy/makeNetwork_38d1bb0.py` | frozen copy of `makeNetwork.py` at commit `38d1bb0`; used only to render the old self-contained `run.sh` in the equivalence tests |

The old `generated/run_sh_*.expected` files are kept as the reference output of
the pre-4.4 `makeNetwork.py`; `tests/unit/test_emulate_equivalence.py` compares
what `scripts/emulate.sh` + `emulation.conf` do against them.

The serial excerpts are the complete set of parser-relevant lines, so the
parsers see exactly what they saw during the real run. To refresh them,
re-run the baseline and extract with:

```bash
grep -aE 'firmadyne: (inet_bind|__inet_insert_ifa|ioctl_SIOCSIFHWADDR|br_dev_ioctl|br_add_if|register_vlan_dev)' \
  scratch/<IID>/qemu.initial.serial.log
```
