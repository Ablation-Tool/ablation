#!/usr/bin/env python3
"""
skydio_flyby_findings.py — Manual verification of semantic sweep candidates

Source: skydio_flyby_re.py sweep on libflyby_jni.so (ARM64, 60MB, stripped)
BuildID: b867c6540e28e1f2edc3ec0d6ecfc08f6ecbe4b2

Priority candidates from sweep (multi-query overlap = highest priority):
  F1: 0x01747278 — memcpy + protobuf overlap (Q6 0.3038, Q10 0.3908)
  F2: 0x02cffed8 — MAVLink parser top hit (Q4 0.4230)
  F3: 0x026dbf10 — protobuf + serial validation overlap (Q9+Q10)
  F4: 0x02cbcfbc — repeated memcpy callee 0x1675db0 x4 (Q6 0.3075)
  F5: 0x02efd8d0 — OTA firmware update handler (Q8 0.3444)
  F6: 0x02ce7be4 — firmware signing verification (Q3 0.2179)
  F7: 0x026988ac — serial validation / shared utility (Q1+Q5+Q9)

Usage:
  python3 modules/skydio_flyby_findings.py
  python3 modules/skydio_flyby_findings.py --addr 0x01747278
  python3 modules/skydio_flyby_findings.py --all
"""
import sys
import struct
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import capstone

BINARY = "/media/cowboy/research/Skydio/intel-vdt/re-material/libflyby_jni.so"

# Candidates from semantic sweep
CANDIDATES = {
    'F1_memcpy_protobuf': {
        'addr': 0x01747278,
        'queries': ['Q6_memcpy_length(0.3038)', 'Q10_protobuf_parse(0.3908)'],
        'note': 'Multi-query overlap: protobuf decoder with repeated memcpy callee. '
                'Potential heap overflow if decoded length not bounds-checked.',
        'callee': '0x168dbe0 x2',
        'priority': 'CRITICAL',
    },
    'F2_mavlink_parser': {
        'addr': 0x02cffed8,
        'queries': ['Q4_mavlink_parser(0.4230)'],
        'note': 'Top MAVLink parser hit. Check packet.len used as memcpy length. '
                'MAVLink2 max payload 253 bytes — verify buffer allocation matches.',
        'callee': '0x1666510, 0x16d3680',
        'priority': 'HIGH',
    },
    'F3_protobuf_serial': {
        'addr': 0x026dbf10,
        'queries': ['Q9_serial_validation(0.3387)', 'Q10_protobuf_parse(0.3952)'],
        'note': 'Serial number validation inside protobuf decoder. '
                'Check if SkydioX10- prefix checked then numeric suffix unbounded.',
        'callee': '0x166dc00, 0x16a1640, 0x168ea50',
        'priority': 'HIGH',
    },
    'F4_memcpy_loop': {
        'addr': 0x02cbcfbc,
        'queries': ['Q6_memcpy_length(0.3075)'],
        'note': 'Calls 0x1675db0 four times (loop copy pattern). '
                'If 0x1675db0 is memcpy/memmove, this is a block-copy with external length.',
        'callee': '0x1675db0 x4',
        'priority': 'HIGH',
    },
    'F5_ota_handler': {
        'addr': 0x02efd8d0,
        'queries': ['Q8_firmware_update(0.3444)'],
        'note': 'OTA firmware update handler. Check: path traversal in filename field, '
                'hash verification order (verify-then-write vs write-then-verify).',
        'callee': '0x16ad860, 0x165d2a0, 0x167eb20',
        'priority': 'HIGH',
    },
    'F6_release_signing': {
        'addr': 0x02ce7be4,
        'queries': ['Q3_find_release_signing(0.2179)'],
        'note': 'Firmware release signature verification. '
                'Check if EVP_DigestVerify return value checked, offline path skip.',
        'callee': '0x165e450, 0x168cf20, 0x167bce0',
        'priority': 'MEDIUM',
    },
    'F7_serial_utility': {
        'addr': 0x026988ac,
        'queries': ['Q1_iot_exchange(0.1483)', 'Q5_http_client(0.0340)', 'Q9_serial_validation(0.3474)'],
        'note': 'Appears across IoT exchange, HTTP client, and serial validation queries. '
                'Likely a shared identity/credential utility function.',
        'callee': '0x1691400',
        'priority': 'MEDIUM',
    },
}


def load_binary(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def get_text_section(data: bytes) -> tuple:
    """Return (text_data, text_addr, text_offset)."""
    if data[:4] != b'\x7fELF':
        raise ValueError("Not ELF")
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

    strshdr_off = e_shoff + e_shstrndx * e_shentsize
    strtab_off = struct.unpack_from('<Q', data, strshdr_off + 24)[0]

    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name_off = struct.unpack_from('<I', data, off)[0]
        nstart = strtab_off + name_off
        nend = data.index(b'\x00', nstart)
        name = data[nstart:nend].decode(errors='replace')
        if name == '.text':
            sh_addr = struct.unpack_from('<Q', data, off + 16)[0]
            sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
            sh_size = struct.unpack_from('<Q', data, off + 32)[0]
            return data[sh_offset:sh_offset + sh_size], sh_addr, sh_offset
    return data, 0, 0


def disasm_at(data: bytes, text_data: bytes, text_addr: int, text_offset: int,
              va: int, n_insns: int = 80) -> list:
    """Disassemble n_insns instructions at virtual address va."""
    foff = (va - text_addr)
    if foff < 0 or foff >= len(text_data):
        return [f"  [!] VA 0x{va:x} out of .text range"]
    code = text_data[foff:foff + n_insns * 4]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    insns = []
    for insn in md.disasm(code, va):
        insns.append(f"  0x{insn.address:08x}:  {insn.mnemonic:<8} {insn.op_str}")
        if len(insns) >= n_insns:
            break
    return insns


def analyze_candidate(name: str, cand: dict, data: bytes,
                      text_data: bytes, text_addr: int, text_offset: int):
    print(f"\n{'='*70}")
    print(f"[{name}] addr=0x{cand['addr']:08x}  priority={cand['priority']}")
    print(f"  Queries: {', '.join(cand['queries'])}")
    print(f"  Callees: {cand['callee']}")
    print(f"  Note: {cand['note']}")
    print(f"{'='*70}")

    insns = disasm_at(data, text_data, text_addr, text_offset, cand['addr'], 80)

    # Analysis hints
    calls = [l for l in insns if 'bl ' in l or 'blr ' in l]
    ldr_str = [l for l in insns if 'ldr' in l or 'str' in l]
    cmp_cbz = [l for l in insns if 'cmp' in l or 'cbz' in l or 'cbnz' in l or 'b.eq' in l or 'b.ne' in l]

    print(f"\n  Disassembly ({len(insns)} insns):")
    for l in insns:
        print(l)

    print(f"\n  Call sites ({len(calls)}):")
    for c in calls:
        print(f"    {c.strip()}")

    print(f"\n  Memory ops: {len(ldr_str)} ldr/str  |  {len(cmp_cbz)} branches/compares")

    # Flag suspicious patterns
    flags = []
    asm_str = '\n'.join(insns)
    if len(calls) >= 3 and 'calls: 0x1675db0' in cand.get('callee', ''):
        flags.append("REPEATED_CALLEE: 0x1675db0 called multiple times — loop copy pattern")
    if any('x2' in l and ('bl ' in l or 'ldr' in l) for l in insns):
        flags.append("POSSIBLE_LENGTH_IN_X2: x2 register used near call — verify length arg")

    if flags:
        print(f"\n  [!!!] FLAGS:")
        for f in flags:
            print(f"    - {f}")

    return insns


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=BINARY)
    parser.add_argument('--addr', type=lambda x: int(x, 16), default=None)
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--priority', choices=['CRITICAL', 'HIGH', 'MEDIUM'], default=None)
    args = parser.parse_args()

    print(f"[*] Skydio libflyby_jni.so — Candidate Analysis")
    print(f"[*] Binary: {args.binary}\n")

    data = load_binary(args.binary)
    text_data, text_addr, text_offset = get_text_section(data)
    print(f"[*] .text: VA=0x{text_addr:x}, {len(text_data)//1024}KB\n")

    if args.addr:
        name = f"manual_0x{args.addr:08x}"
        cand = {'addr': args.addr, 'queries': ['manual'], 'note': 'Manual analysis',
                'callee': 'unknown', 'priority': 'MANUAL'}
        analyze_candidate(name, cand, data, text_data, text_addr, text_offset)
        return

    to_analyze = {}
    if args.all:
        to_analyze = CANDIDATES
    else:
        # Default: CRITICAL and HIGH only
        to_analyze = {k: v for k, v in CANDIDATES.items()
                     if v['priority'] in ('CRITICAL', 'HIGH')}
        if args.priority:
            to_analyze = {k: v for k, v in CANDIDATES.items()
                         if v['priority'] == args.priority}

    print(f"[*] Analyzing {len(to_analyze)} candidates\n")
    results = {}
    for name, cand in to_analyze.items():
        insns = analyze_candidate(name, cand, data, text_data, text_addr, text_offset)
        results[name] = {'addr': cand['addr'], 'insns': insns, **cand}

    print(f"\n\n{'='*70}")
    print("SUMMARY — PRIORITY FINDINGS")
    print('='*70)
    for name, r in results.items():
        print(f"\n  [{r['priority']}] {name}")
        print(f"    addr=0x{r['addr']:08x}")
        print(f"    {r['note']}")
        print(f"    Queries: {', '.join(r['queries'])}")


if __name__ == '__main__':
    main()
