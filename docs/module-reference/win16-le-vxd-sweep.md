# win16-le-vxd-sweep

`sweeps/win16_le_vxd_sweep.py`

## Why this exists

3 things that were not possible before in Ablation:

1. **No LE binary could be loaded.** The LE (Linear Executable) format — used by every Windows 3.x VxD — was invisible to Ablation. LIEF rejects it (wrong magic). `pe_sweep.py` reads MZ then checks for `PE\x00\x00`; LE files have `LE` instead and are silently skipped. All ring-0 network stack components (`VIP.386`, `VTCP.386`, `VNBT.386`, `VUDP.386`, `VDHCP.386`, `VTDI.386`, `WSOCK.386`, `WSTCP.386`) were zero-coverage targets.

2. **VMM INT-20h service calls were unresolvable.** VxDs have no IAT. All kernel service calls go through `INT 20h` followed by a 4-byte service ID DWORD. Without knowing this convention, every call site in a VxD looked like a non-calling function to the semantic encoder — no call targets, no import names, systematically low scores on every network-sink profile. This module decodes INT-20h + DWORD sequences into named VMM services (`VMM!HeapAllocate`, `VMM!PageLock`, etc.) that the semantic profiles can match.

3. **VxD ring-0 vulnerability profiles did not exist.** The generic `heap_overflow` and `recv_overflow` profiles expect libc-style sinks (`malloc`, `recv`). VxD code uses `VMM!HeapAllocate` + `rep movsd` for the same operations. Without VxD-specific profiles, a kernel-heap overflow in `VTCP.386` would score lower than a false-positive wrapper in a Win32 GUI app.

---

## What this module does

Parses Windows 3.x LE binaries, assembles code object pages into a flat 32-bit buffer, locates function starts via prologue scan + call-target recovery, decodes VMM INT-20h service calls into named symbols, and runs a semantic sweep with the standard MiniLM-L6-v2 model augmented with VxD-specific vulnerability profiles.

---

## LE format internals

### Header layout (Windows VxD variant)

The LE header differs from the IBM OS/2 LX spec by a 4-byte shift in the page/fixup/loader size field group. Verified against VIP.386, VTCP.386, VNBT.386 from WfW 3.11 TCP/IP-32 3.11a:

| Offset | Field | VIP.386 value |
|--------|-------|--------------|
| LE+0x28 | page_size | 0x1000 |
| LE+0x2c | bytes_on_last_page | 0xa56 |
| LE+0x30 | fixup_section_size | 0xf3e |
| LE+0x38 | loader_section_size | 0x75 |
| LE+0x40 | obj_table_off (= fixed header size) | 0xc4 |
| LE+0x44 | num_objects | 2 |
| LE+0x48 | obj_page_table_off | 0xf4 |

### Data pages location

```
data_base = le_off + obj_table_off + loader_size + fixup_size
          = 0x80  + 0xc4          + 0x75        + 0xf3e
          = 0x10f7  (for VIP.386)
```

`obj_table_off` is both the offset to the object table from the LE header start AND the size of the fixed LE header (the object table is always the first structure after the fixed header).

### Object page table entries

4 bytes per entry:
- bytes `[0..2]` big-endian 24-bit: 1-indexed page number
- byte `[3]`: flags (0=normal, 1=iterated/compressed, 2=invalid, 3=zeroed)

Page N's data is at: `data_base + (N - 1) * page_size`

This big-endian-in-little-endian-file encoding is the primary reason standard binary loaders fail on LE VxDs.

### VMM service calls

VxDs call VMM services via:
```asm
int   20h
dd    SERVICE_ID   ; e.g. 0x00010063 = VMM!HeapAllocate
```

The `int 20h` + 4-byte DWORD at `insn_offset + 2` is the complete call sequence. The module decodes ~80 commonly encountered service IDs into named strings for the semantic sweep.

---

## Usage

```bash
# Single VxD file
python3 sweeps/win16_le_vxd_sweep.py VIP.386 \
  --vendor microsoft --product tcpip32 --version 3.11a

# Full directory (scans .386, .vxd, .drv, .sys for LE magic)
python3 sweeps/win16_le_vxd_sweep.py /tmp/ms-tcpip-extract/ \
  --vendor microsoft --product tcpip32 --version 3.11a
```

Output goes to `reports/sweep_le_<vendor>_<product>_<version>_<ts>.md`.

---

## What to look for in results

**DDB entry points** (`ctrl_proc`, `v86_api_proc`, `pm_api_proc`): these are the VxD's public API surface. Functions appearing in results that ARE a DDB entry point handle calls from user-mode Win16 apps or DOS VMs — direct network attack surface.

**`VMM!HeapAllocate` + `rep movsd/movsb`** in the same function: potential heap overflow if the `HeapAllocate` size and the `rep` count are both derived from a network packet field.

**`VMM!lstrcpy` / `VMM!lstrcat`**: ring-0 string copies without bounds — same class as Win16 `lstrcpy` but in kernel address space.

**Score threshold**: 0.30 (same as other sweeps). Ring-0 code tends to be tighter and more uniform than user-mode code, so false-positive rates are lower but true-positive scores are also lower.

---

## Profiles added

5 VxD-specific profiles beyond the standard base + Win16 NE profiles:

- `vxd_ring0_recv_overflow` — heap alloc then rep movsd from network buffer
- `vxd_netbios_name_overflow` — NetBIOS/DHCP hostname into fixed ring-0 buffer
- `vxd_heap_alloc_intovf` — 32-bit overflow before VMM!HeapAllocate
- `vxd_v86_param_nocopy` — V86 pointer dereference without private-buffer copy
- `vxd_format_string_ring0` — wsprintf with network-derived format string in ring-0
