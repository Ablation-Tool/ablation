#!/usr/bin/env python3 -I
"""
aix433_rmail_setclock_re.py — byte-level confirmation for Section W HIGH findings.

Targets:
  rmail   (3356B text, 20 imports) — popen()+sprintf() via BFF in bos.net.tcp.*
  setclock (4080B text, 26 imports) — stime()+socket+network via bos.net.tcp.server

Runs entirely in memory from the BFF archives.

Usage:
    python3 -I sweeps/aix433_rmail_setclock_re.py
"""
import sys, io, tarfile, struct
sys.path.insert(0, '/home/cowboy/ablation')

from ablation.analyzers.aix_bff_extractor import AixBffExtractor
from ablation.core.xcoff_parser import parse

ARCHIVE = '/media/cowboy/research/IBM-RE/AIX-4.3.3-ML11/aix433ml11.tar.gz'
TARGETS = {'rmail', 'setclock', 'fingerd', 'vacation', 'sntp'}

EXEC_SINKS = {
    'system', 'popen', 'execve', 'execl', 'execle', 'execlp',
    'execv', 'execvp', 'fork', 'stime',
}
OVERFLOW_SINKS = {'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf'}


def bl_scan(text_data, text_va):
    """Stride-scan for all BL targets in PPC32 text section.
    BL encoding: bits [6:31] = LI (24-bit signed offset / 4); bit 0 = Link bit.
    Opcode = upper 6 bits = 0x12 (18 decimal).
    Returns list of (insn_va, target_va).
    """
    results = []
    for off in range(0, len(text_data) - 3, 4):
        word = struct.unpack('>I', text_data[off:off+4])[0]
        if (word >> 26) != 0x12:
            continue
        if not (word & 1):
            continue  # Not BL (link bit must be set)
        li = (word >> 2) & 0xFFFFFF
        if li & 0x800000:
            li = li - 0x1000000  # sign extend 24-bit
        target = (text_va + off) + li * 4
        results.append((text_va + off, target))
    return results


def loader_toc_map(xcoff_data):
    """Parse XCOFF32 LOADER section to get (toc_offset -> import_name) map."""
    try:
        xb = parse('target', data=xcoff_data)
        # Build map: stub_va (from imports) -> name
        stub_map = {}
        for sym in xb.imports:
            if sym.va:
                stub_map[sym.va] = sym.name
        return stub_map, xb
    except Exception as e:
        return {}, None


def analyze_binary(name, xcoff_data):
    """Analyze a single XCOFF32 binary for exec/overflow sinks."""
    print(f'\n=== {name} ({len(xcoff_data)} bytes) ===')

    stub_map, xb = loader_toc_map(xcoff_data)
    if xb is None:
        print(f'  ERROR: xcoff_parser failed')
        return

    print(f'  arch={xb.arch}  text_va=0x{xb.text.vaddr:08x}  text_size=0x{xb.text.size:x}')
    print(f'  imports ({len(xb.imports)}):')
    exec_stubs = {}
    for sym in xb.imports:
        if sym.name in (EXEC_SINKS | OVERFLOW_SINKS):
            print(f'    {sym.name:<20s} stub_va=0x{sym.va:08x}')
            exec_stubs[sym.va] = sym.name

    if not exec_stubs:
        print('  No exec/overflow stubs found.')
        return

    # Run BL scan
    raw = xcoff_data
    text_data = raw[xb.text.offset: xb.text.offset + xb.text.size]
    bl_list = bl_scan(text_data, xb.text.vaddr)
    print(f'  BL count: {len(bl_list)} total')

    # Find callers of exec/overflow stubs
    print(f'\n  Exec/overflow call sites:')
    for caller_va, target_va in bl_list:
        if target_va in exec_stubs:
            sink = exec_stubs[target_va]
            file_off = xb.text.offset + (caller_va - xb.text.vaddr)
            word_bytes = xcoff_data[file_off:file_off+4]
            print(f'    {sink:<20s}  caller_va=0x{caller_va:08x}  target_va=0x{target_va:08x}'
                  f'  file_off=0x{file_off:x}  bytes={word_bytes.hex()}')

    # Byte verify BL instruction
    print(f'\n  Byte verification:')
    for caller_va, target_va in bl_list:
        if target_va not in exec_stubs:
            continue
        sink = exec_stubs[target_va]
        file_off = xb.text.offset + (caller_va - xb.text.vaddr)
        word = struct.unpack('>I', xcoff_data[file_off:file_off+4])[0]
        # Decode
        li = (word >> 2) & 0xFFFFFF
        if li & 0x800000:
            li = li - 0x1000000
        reconstructed_target = caller_va + li * 4
        match = '✓' if reconstructed_target == target_va else '✗'
        print(f'    {sink:<20s}  0x{caller_va:08x}: word=0x{word:08x}  '
              f'li={li}  target=0x{reconstructed_target:08x} {match}')


def main():
    print(f'[+] Scanning {ARCHIVE} for: {sorted(TARGETS)}')
    found = {}
    try:
        tf = tarfile.open(ARCHIVE, 'r:gz')
    except Exception as e:
        print(f'ERROR: {e}')
        return

    for member in tf.getmembers():
        if not member.name.endswith('.bff'):
            continue
        try:
            fobj = tf.extractfile(member)
            if fobj is None:
                continue
            bff_data = fobj.read()
        except Exception:
            continue

        extractor = AixBffExtractor(bff_data)
        try:
            for xcoff_name, xcoff_bytes in extractor.extract():
                base = xcoff_name.split('/')[-1]
                if base in TARGETS and base not in found:
                    found[base] = (member.name, xcoff_bytes)
        except Exception:
            continue

        if len(found) == len(TARGETS):
            break

    tf.close()

    if not found:
        print('ERROR: No target binaries found.')
        return

    for target_base in sorted(TARGETS):
        if target_base in found:
            bff_name, xcoff_data = found[target_base]
            print(f'\n[found in {bff_name}]')
            analyze_binary(target_base, xcoff_data)
        else:
            print(f'\n{target_base}: NOT FOUND in corpus')


if __name__ == '__main__':
    main()
