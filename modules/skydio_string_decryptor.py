#!/usr/bin/env python3
"""
skydio_string_decryptor.py — Bulk decryption of XOR-obfuscated strings in libflyby_jni.so

Decryption formula (reversed from 0x02615bb0):
  decrypted[i] = encrypted[i] ^ key_table[i % 412] ^ 0xF1

Key table: 412 bytes at VA 0x3183803 (file offset = VA, flat-mapped R-X segment)
Key: '2NRRVkwEN6bsmhs1xI4hJNfVPv9oSYTSqDFa...' (printable ASCII, embedded in R-X segment)

Pattern: scan for the ubfx+umull+lsr+msub+ldrb+eor+eor+strb decryption loop signature,
then walk back to find the MOVZ/STURB byte-assembly block preceding it.

Confirmed decryption: 0x02615bb0 -> 'experimental/webrtc_c_impl/peer.cc'
  - XOR key at x19 = 0x3183803
  - 34-byte string assembled at [x29, -0x4f] to [x29, -0x2e]
  - x1 = (stack_ptr) | 1 (C++ SSO tagged pointer -- shifts buffer start by +1)

Usage:
  python3 modules/skydio_string_decryptor.py
  python3 modules/skydio_string_decryptor.py --all
  python3 modules/skydio_string_decryptor.py --va 0x02615aa4
"""
import sys
import struct
import argparse
import capstone
from pathlib import Path

BINARY = "/media/cowboy/research/Skydio/intel-vdt/re-material/libflyby_jni.so"

KEY_VA       = 0x3183803   # VA of XOR key table
KEY_PERIOD   = 412         # key table period (modular repeat length)
XOR_CONST    = 0xF1        # second XOR constant in decryption loop

# Decryption loop signature: 8-instruction sequence
# ubfx w13, w8, #2, #0xe
# umull x13, w13, w9
# and w12, w8, #0xffff
# lsr x13, x13, #0x23
# msub w12, w13, w10, w12
# ldrb w11, [x1, x8]
# ldrb w12, [x19, w12, uxtw]
# eor w11, w11, w12
LOOP_MNEMS = ['ubfx', 'umull', 'and', 'lsr', 'msub', 'ldrb', 'ldrb', 'eor']


def load_binary(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def get_load_segments(data: bytes) -> list:
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type  = struct.unpack_from('<I', data, off)[0]
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr  = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        if p_type == 1 and (p_flags & 1):
            segs.append((p_vaddr, p_vaddr + p_filesz, p_offset))
    return segs


def va_to_foff(segs: list, va: int) -> int:
    for va_start, va_end, foff_base in segs:
        if va_start <= va < va_end:
            return foff_base + (va - va_start)
    raise ValueError(f"VA 0x{va:x} not mapped")


def decrypt(enc_bytes: bytes, key_table: bytes, key_offset: int = 0) -> bytes:
    out = bytearray()
    for i, b in enumerate(enc_bytes):
        key = key_table[(i + key_offset) % KEY_PERIOD]
        out.append(b ^ key ^ XOR_CONST)
    return bytes(out)


def find_decrypt_loops(data: bytes, segs: list) -> list:
    """Scan R-X segment for the XOR decryption loop pattern."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    hits = []

    for va_start, va_end, foff_base in segs:
        seg_size = va_end - va_start
        seg_data = data[foff_base:foff_base + seg_size]

        insns = []
        for insn in md.disasm(seg_data, va_start):
            insns.append(insn)

        # Slide window: look for 8-mnem sequence matching LOOP_MNEMS
        for idx in range(len(insns) - len(LOOP_MNEMS)):
            window = insns[idx:idx + len(LOOP_MNEMS)]
            if all(w.mnemonic == m for w, m in zip(window, LOOP_MNEMS)):
                loop_va = insns[idx].address
                # Confirm: the two eor instructions use #0xfffffff1
                eor1 = insns[idx + 7]
                eor2_va = insns[idx + 8].address if idx + 8 < len(insns) else None
                if '#0xfffffff1' in (insns[idx + 8].op_str if idx + 8 < len(insns) else ''):
                    hits.append(loop_va)

    return hits


def extract_and_decrypt_at(data: bytes, segs: list, func_start_va: int,
                            key_table: bytes, max_insns: int = 200) -> list:
    """
    Disassemble func_start_va, find all MOVZ/STURB byte-assembly blocks,
    extract encrypted bytes, and decrypt them.
    Returns list of (stack_offset_base, enc_bytes, dec_bytes) tuples.
    """
    foff = va_to_foff(segs, func_start_va)
    code = data[foff:foff + max_insns * 4]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    insns = list(md.disasm(code, func_start_va))

    reg_vals = {}
    stack_bytes = {}  # offset -> byte value (signed stack offset)
    results = []

    for insn in insns:
        mnem = insn.mnemonic.lower()
        op = insn.op_str

        # Track MOV/MOVZ to registers
        if mnem in ('mov', 'movz') and ',' in op:
            parts = [p.strip() for p in op.split(',')]
            dst = parts[0].lower()
            if parts[1].startswith('#'):
                try:
                    val = int(parts[1].lstrip('#'), 0) & 0xFF
                    reg_vals[dst] = val
                except ValueError:
                    pass
        elif mnem == 'movk' and ',' in op:
            # movk wN, #imm, lsl #shift -- only track if shift=0 and this is first movk
            parts = [p.strip() for p in op.split(',')]
            dst = parts[0].lower()
            if len(parts) >= 2 and parts[1].startswith('#') and 'lsl' not in op:
                try:
                    val = int(parts[1].lstrip('#'), 0) & 0xFF
                    reg_vals[dst] = val
                except ValueError:
                    pass

        # Track STURB writes to stack
        elif mnem == 'sturb' and 'x29' in op:
            parts = [p.strip() for p in op.split(',')]
            src_reg = parts[0].lower()
            # Parse offset from [x29, #-N]
            try:
                off_str = op.split('#')[1].rstrip(']')
                stack_off = int(off_str, 0)  # signed
                val = reg_vals.get(src_reg, reg_vals.get('w' + src_reg[1:] if src_reg.startswith('x') else src_reg))
                if val is None and src_reg == 'wzr':
                    val = 0
                if val is not None:
                    stack_bytes[stack_off] = val & 0xFF
            except (IndexError, ValueError):
                pass

        # At the decryption loop header (ubfx), extract the buffer
        elif mnem == 'ubfx' and stack_bytes:
            # Find lowest stack offset with data -- that's the buffer start
            if not stack_bytes:
                continue
            min_off = min(stack_bytes.keys())
            max_off = max(stack_bytes.keys())
            # x1 = (x29 + min_off) | 1 -> actual start is min_off+1 if min_off is even
            # The SSO tag: sub x12, x29, #0x50; orr x1, x12, #1 shifts start by 1
            # Determine actual start from 'orr x1, x12, #1' -- shifts +1 from min_off
            enc_start = min_off + 1
            enc_bytes = bytes(stack_bytes.get(enc_start + i, 0)
                              for i in range(max_off - enc_start + 1)
                              if stack_bytes.get(enc_start + i) is not None)
            # Stop at null terminator if present
            null_pos = None
            for i in range(len(enc_bytes)):
                if stack_bytes.get(enc_start + i) == 0:
                    null_pos = i
                    break
            if null_pos:
                enc_bytes = enc_bytes[:null_pos]

            dec_bytes = decrypt(enc_bytes, key_table)
            results.append((enc_start, enc_bytes, dec_bytes))
            stack_bytes = {}
            reg_vals = {}

    return results


def find_all_loops_by_pattern(data: bytes, seg_end: int = 0x39904a0) -> list:
    """
    Fast byte-pattern scan for all XOR decrypt loop instances.

    Two loop families:
    (A) Standard: uses eor #0xfffffff1 as ARM64 bitmask immediate
        Signature: eor w11,w11,w12 (0x4a0c016b) + eor w11,w11,#0xfffffff1 (0x521c716b)
        XOR constant = 0xF1 (low byte of 0xfffffff1)

    (B) Register: uses eor w12,w12,w9 where w9 is set via mov wN,#const earlier
        Signature: eor w12,w12,w13 (0x4a0d818c) + strb w12,[x1,x8] (0x38286c2c)
        XOR constant varies per function (e.g., 0x69 in platform_state.cc SetCloudAuth)
        Detection: scan for the umull+msub+ldrb triple that precedes the eor pair

    Returns list of (va, xor_const) tuples.
    """
    # Family A: exact 8-byte eor+eor_immediate signature
    PATTERN_A = b'\x6b\x01\x0c\x4a\x6b\x71\x1c\x52'
    # Family B: eor w12,w12,w13 (0x4a0d818c) -- register-based second XOR
    PATTERN_B = b'\x8c\x81\x0d\x4a'
    hits = []
    pos = 0
    while pos < seg_end:
        idx = data.find(PATTERN_A, pos, seg_end)
        if idx < 0:
            break
        if idx % 4 == 0:
            hits.append((idx, XOR_CONST))  # Family A: fixed 0xF1
        pos = idx + 4

    # Family B: scan for eor w12,w12,w13 -- resolve xor_const via preceding mov
    pos = 0
    md = None
    while pos < seg_end:
        idx = data.find(PATTERN_B, pos, seg_end)
        if idx < 0:
            break
        if idx % 4 == 0:
            # Check if followed by strb (confirming this is inside a decrypt loop)
            next_insn = struct.unpack_from('<I', data, idx + 4)[0] if idx + 4 < seg_end else 0
            # strb w12, [x1, x8] = 0x3828_6c2c
            if (next_insn & 0xFFFFFFFF) == 0x3828682c or (next_insn & 0xFFFFFFFF) == 0x38286c2c:
                # Scan backward up to 256 instructions for the xor_const register assignment
                xor_const = None
                for back_off in range(idx - 4, max(idx - 256*4, 0), -4):
                    word = struct.unpack_from('<I', data, back_off)[0]
                    # mov w9, #imm8: 0x52800009 + imm5<<5 -- movz w9, #imm
                    # movz wN, #imm: encoding = 0x52800000 | (imm16 << 5) | Rd
                    if (word & 0xFFE0001F) == 0x52800009:  # movz w9, #imm
                        imm16 = (word >> 5) & 0xFFFF
                        if imm16 <= 0xFF:
                            xor_const = imm16
                            break
                    # Also check for generic family: eor wX,wX,wY + eor wX,wX,#0xfffffff1
                    # If we find standard pattern nearby, skip (avoid double-counting)
                    if data[back_off:back_off+8] == PATTERN_A:
                        xor_const = None
                        break
                if xor_const is not None and xor_const != XOR_CONST:
                    hits.append((idx, xor_const))  # Family B: variable constant
        pos = idx + 4

    # Sort by VA
    hits.sort(key=lambda x: x[0])
    return hits


def scan_all_decrypt_loops(data: bytes, segs: list, key_table: bytes) -> list:
    """
    Scan full binary for XOR decrypt loops using byte-pattern matching,
    then extract and decrypt all encrypted strings.
    """
    results = []
    seg_end = segs[0][1] if segs else 0x39904a0

    print(f"  Pattern scan: VA=0x0-0x{seg_end:x} ({seg_end//1024//1024}MB)...")
    hits = find_all_loops_by_pattern(data, seg_end)
    print(f"  Found {len(hits)} XOR decrypt loops ({sum(1 for _, c in hits if c == XOR_CONST)} family-A, "
          f"{sum(1 for _, c in hits if c != XOR_CONST)} family-B)")

    for loop_va, loop_xor in hits:
        func_start = max(loop_va - 0x200, 0)
        res = extract_and_decrypt_at(data, segs, func_start, key_table, max_insns=200)
        results.append({
            'loop_va': loop_va,
            'loop_xor': loop_xor,
            'func_start': func_start,
            'strings': res,
        })
        for enc_start, enc, dec in res:
            try:
                s = dec.decode('ascii', errors='replace')
                printable = all(0x20 <= b <= 0x7e for b in dec)
                print(f"    [0x{loop_va:08x}] {'[+]' if printable else '[?]'} "
                      f"len={len(dec):3d} xor=0x{loop_xor:02x} {s!r}")
            except Exception as e:
                print(f"    [0x{loop_va:08x}] decode error: {e}")

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=BINARY)
    parser.add_argument('--va', type=lambda x: int(x, 16), default=None,
                        help='Function VA to decrypt (default: scan all)')
    parser.add_argument('--all', action='store_true',
                        help='Scan entire binary for decrypt loops (slow)')
    args = parser.parse_args()

    print(f"[*] Skydio libflyby_jni.so — String Decryptor")
    print(f"[*] Key table VA: 0x{KEY_VA:x}  Period: {KEY_PERIOD}  XOR const: 0x{XOR_CONST:02x}\n")

    data = load_binary(args.binary)
    segs = get_load_segments(data)
    for va_s, va_e, foff in segs:
        print(f"[*] R-X segment: VA=0x{va_s:x}-0x{va_e:x}  ({(va_e-va_s)//1024//1024}MB)")

    key_table = data[KEY_VA:KEY_VA + KEY_PERIOD]
    print(f"[*] Key table: {key_table[:20]}...")

    if args.va:
        print(f"\n[*] Decrypting strings in function at 0x{args.va:x}")
        results = extract_and_decrypt_at(data, segs, args.va, key_table)
        for enc_start, enc, dec in results:
            print(f"  enc_start offset: {enc_start:#x}  len: {len(enc)}")
            print(f"  encrypted: {enc.hex()}")
            print(f"  decrypted: {dec.decode('ascii', errors='replace')!r}")
        return

    # Default: decrypt the confirmed instance at 0x02615aa4
    print(f"\n[*] Confirmed instance: 0x02615aa4 (after ucon::Puller::FetchAvailableFiles)")
    func_va = 0x02615a48
    results = extract_and_decrypt_at(data, segs, func_va, key_table)
    for enc_start, enc, dec in results:
        try:
            s = dec.decode('ascii', errors='replace')
            printable = all(0x20 <= b <= 0x7e for b in dec)
            print(f"  [{'+' if printable else '?'}] {s!r}  (len={len(dec)}, enc_start={enc_start:#x})")
        except Exception as e:
            print(f"  [!] decode error: {e}  raw={dec.hex()}")

    if args.all:
        print(f"\n[*] Full binary scan for XOR decrypt loops...")
        all_results = scan_all_decrypt_loops(data, segs, key_table)
        print(f"\n[*] Total: {len(all_results)} loops, "
              f"{sum(len(r['strings']) for r in all_results)} strings decrypted")


if __name__ == '__main__':
    main()
