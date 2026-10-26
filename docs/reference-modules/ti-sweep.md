# ti-sweep

## Why this exists

Five things were not possible before in Ablation:

1. **No sweep path for TI COFF2/AR archives.** All prior sweeps assumed ELF input to `BinaryContext`. C28x `.lib` and `.a` files cl2000/tiarmclang output are COFF2 or AR-of-COFF2; `lief.parse()` returns `None` and `capstone` has no C28x support. The sweep routes these through `TiCoffLoader` + `EcuC28xDecoder` directly, bypassing the ELF path entirely.

2. **No batch extraction from TI TIREX package zips.** TI distributes SDKs as zip archives with nested directories and sometimes double-nested inner zips. Walking 138 packages (23 GB) with `unzip -l` + per-binary type dispatch was not scriptable without a dedicated sweep entry point.

3. **No TI-specific vuln profiles for semantic search.** Base and Fortinet sweep profiles are tuned for x86-64 Linux daemons. TI MCU firmware uses UART HAL, TI-RTOS/FreeRTOS task APIs, OTA BIM, and BLE/15.4/Wi-SUN stack parser idioms that have no semantic overlap with `recv()`/`system()`/`popen()` profiles.

4. **No NNC artifact sweep across a package corpus.** `TiNNCScanner` existed as a single-binary tool. The sweep runs it as a fast symbol-table-only pass across every `.a` / ELF file in a package before the slower taint analysis starts, so TINCC findings are always collected even when taint is skipped.

5. **No ARM32 Thumb triage path for embedded MCU ELFs.** Prior ARM32 sweeps targeted Linux userspace function prologues at PUSH {r4, lr} or PUSH {r4-r11, and lr}. Cortex-M Thumb firmware compiled with tiarmclang uses different prologue patterns and has no dynamic linker; `batch_plt_intersect` only works for binaries with a PLT section, which many bare-metal ELFs lack.

---

## What it does

Batch vulnerability sweep over a TI TIREX SDK package directory or a single zip or extracted directory. Handles four binary classes:

| Class | Format | Scanner path |
|---|---|---|
| TI COFF2/AR | `.a`, `.lib` with COFF2 magic | `TiCoffLoader` → `TiNNCScanner` → `EcuC28xDecoder` func-start harvest |
| ARM Thumb ELF | `.out` Cortex-M0+/M33/M4/R5 | `ARM32TaintTracker(thumb=True)` |
| ARM64 ELF | `.out` Cortex-A53 | `ARM64TaintTracker` |
| Flat binary | `.bin` prebuilt images | `FlatBinaryFuncStartScanner` + `EcuArchDetector` |

`.hex` Intel HEX files are skipped (conversion to flat binary is out of scope; use `objcopy -I ihex -O binary` upstream).

Phase order per package:

1. Phase 0 (Triage): extract zip, classify binaries by magic/extension, filter ELFs with no PLT exec-class sinks (via `batch_plt_intersect`).
2. Phase 1 NNC scan: run `TiNNCScanner` on every COFF/AR and ELF binary. Fast symbol table only.
3. Phase 2 ELF taint: arch-routed `ARM32TaintTracker` / `ARM64TaintTracker` on PLT-passing ELFs.
4. Phase 3 C28x disasm: `EcuC28xDecoder.function_starts()` on COFF archives, then `EcuSecurityAccessScanner` on flat ROM `.bin` images.
5. Phase 4 (Crypto): `HashAlgoDiscriminator` on ARM32 ELFs first 1 MB.

Results are written to `reports/sweep_ti_<package>_<ts>.md` and a master summary to `reports/sweep_ti_master_<ts>.md`.

---

## Usage

```bash
# Sweep all 138 packages in the TIREX directory
python3 sweeps/ti_sweep.py /media/cowboy/research/TI-RE/tirex/

# Single package
python3 sweeps/ti_sweep.py /media/cowboy/research/TI-RE/tirex/MSPM0-SDK__2.11.00.07.zip

# Already-extracted directory
python3 sweeps/ti_sweep.py /tmp/mspm0_sdk/ --product MSPM0-SDK --version 2.11.00.07

# Skip taint analysis (NNC + crypto only: much faster)
python3 sweeps/ti_sweep.py /media/cowboy/research/TI-RE/tirex/ --no-taint

# Limit to specific package name patterns
python3 sweeps/ti_sweep.py /media/cowboy/research/TI-RE/tirex/ --filter simplelink
```

## Output

- `reports/sweep_ti_<slug>_<ts>.md`: per-package report with findings table
- `reports/sweep_ti_master_<ts>.md`: cross-package summary, all findings ranked by severity

---

## Vuln profiles

TI-specific semantic profiles in addition to base_sweep.VULN_PROFILES:

| Profile | Target | CWE class |
|---|---|---|
| `ti_ota_no_auth` | OTA/BIM without ECDSA/RSA | CWE-347 |
| `ti_uart_overflow` | UART HAL recv → fixed buffer | CWE-121 |
| `ti_ble_packet_overflow` | BLE/BLE5 peer length → memcpy | CWE-122 |
| `ti_uds_sa_weak_seed` | UDS SecurityAccess static seed | CWE-798 |
| `ti_flash_write_unchecked` | Flash write without addr/size check | CWE-787 |
| `ti_coap_parse_overflow` | CoAP/MQTT length → memcpy | CWE-122 |
| `ti_wifi_ssid_overflow` | SimpleLink WiFi SSID/passphrase | CWE-121 |
| `ti_dmm_race` | DMM multi-protocol shared buffer race | CWE-362 |

---

## How it works

Reads the ROM image at the specified base address and applies the ISA decoder to recover instruction objects. Function boundaries are identified from preamble/epilogue patterns specific to the target compiler and ABI. Security-relevant patterns UDS handler tables, seed/key routines, calibration write paths are identified by combining structural matching with known compiler output signatures. Decoded results are stored in a `BinaryContext`-compatible format for downstream analysis.

---

## Example output

```
[CRITICAL] WEAK_SEED   UDS 0x27 0x01 at ROM:0x8004A0
  detail: seed is timestamp-derived (LSB of timer register)
  algorithm: linear congruential; key derivable in < 2^16 guesses

[HIGH] UNPROTECTED_WRITE   calibration region at ROM:0x810000
  detail: no write-protect fuse check before accepting 0x34 WriteDataByIdentifier
```

---

## False positives

Calibration data regions contain byte sequences that decode as valid instructions in some ISAs. Confirm candidate function VAs against the ROM layout from `ECURomLayoutAnalyzer` before treating them as code. Security Access sequences in boot ROM are expected and not findings unless the seed/key algorithm is cryptographically weak.

---

## Pipeline position

**Before this module:** `ECUArchDetector` to identify the processor family and confirm this decoder applies to the target ROM.

**After this module:** Feed decoded instructions to the appropriate taint tracker RH850, TriCore, SH-2A, and or C28x for vulnerability analysis.

---

## Reading output

`sweep_packageinput_path` returns a `Tuple[str, List[dict], str]`: `package_name, findings_list, report_markdown`. Each dict in `findings_list` represents one finding:

| Key | Content |
|:---|:---|
| `binary` | Basename of the analyzed file |
| `binary_path` | Absolute path to the analyzed file |
| `finding_id` | Phase-specific ID: `TAINT-ARM32`, `TAINT-ARM64`, `TAINT-RV32`, or NNC scanner ID |
| `severity` | `HIGH` or scanner-reported severity string |
| `title` | Finding description string |
| `phase` | Phase that produced it: `nnc`, `taint`, or `c28x` |
| `va` | Virtual address of the finding NNC findings only |
| `symbol` | Symbol name NNC findings only |
| `arch` | Architecture string: `arm32_thumb`, `arm64`, `riscv32` taint findings only |

`sweep_directorytirex_dir` calls `sweep_package` for each `.zip` package in the directory and writes per-package and master Markdown reports to `reports/`.

---

## See also

- [ECUArchDetector](ecu-arch-detector.md): identify processor family before choosing a decoder
- [ECURomLayoutAnalyzer](ecu-rom-layout-analyzer.md): map ROM sections before decoding
- [ECUSecurityAccessScanner](ecu-security-access-scanner.md): find UDS 0x27 bypass vectors in decoded code
