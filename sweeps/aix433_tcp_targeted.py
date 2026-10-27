#!/usr/bin/env python3 -I
"""
aix433_tcp_targeted.py — targeted byte-level RE for AIX 4.3.3 TCP utility findings.

Directly loads specific BFF members by name (no full archive scan).
Analyzes rmail, setclock, fingerd, vacation, sntp for byte-level sink confirmation.
"""
import sys, tarfile, struct
sys.path.insert(0, '/home/cowboy/ablation')

from ablation.analyzers.aix_bff_extractor import AixBffExtractor
from ablation.core.xcoff_parser import parse

ARCHIVE = '/media/cowboy/research/IBM-RE/AIX-4.3.3-ML11/aix433ml11.tar.gz'

# BFFs known to contain the targets (from session file)
TARGET_BFFS = [
    'bos.net.tcp.client.4.3.3.86.bff',   # rmail, sntp, rwhod
    'bos.net.tcp.server.4.3.3.84.bff',   # setclock, timedc, fingerd?
    'bos.net.tcp.server.4.3.3.0.bff',    # older server package
    'bos.net.tcp.client.4.3.3.0.bff',    # vacation, fingerd?
    'bos.net.tcp.client.4.3.1.0.bff',    # oldest version
]
TARGETS = {'rmail', 'setclock', 'fingerd', 'vacation', 'sntp'}

EXEC_SINKS = {
    'system', 'popen', 'execve', 'execl', 'execle', 'execlp',
    'execv', 'execvp', 'fork', 'stime', 'adjtime',
}
OVERFLOW_SINKS = {'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf'}
ALL_SINKS = EXEC_SINKS | OVERFLOW_SINKS


def bl_scan(text_data, text_va):
    results = []
    for off in range(0, len(text_data) - 3, 4):
        word = struct.unpack('>I', text_data[off:off+4])[0]
        if (word >> 26) != 0x12:
            continue
        if not (word & 1):
            continue
        li = (word >> 2) & 0xFFFFFF
        if li & 0x800000:
            li = li - 0x1000000
        target = (text_va + off) + li * 4
        results.append((text_va + off, target))
    return results


def analyze(name, xcoff_data, bff_src):
    print(f'\n=== {name} (from {bff_src}, {len(xcoff_data)} bytes) ===')
    try:
        xb = parse(name, data=xcoff_data)
    except Exception as e:
        print(f'  parse error: {e}')
        return None

    print(f'  arch={xb.arch}  text_va=0x{xb.text.vaddr:08x}  text_size=0x{xb.text.size:x}'
          f'  data_va=0x{xb.data.vaddr:08x}  toc_va=0x{xb.toc_va:08x}')

    # Find exec/overflow stubs
    exec_stubs = {}
    print(f'  Imports ({len(xb.imports)} total):')
    for sym in xb.imports:
        if sym.name in ALL_SINKS:
            print(f'    *** {sym.name:<20s} stub_va=0x{sym.va:08x}')
            exec_stubs[sym.va] = sym.name

    if not exec_stubs:
        print('  No exec/overflow stubs — SAFE at import level.')
        return {'name': name, 'verdict': 'SAFE', 'sinks': []}

    # BL scan
    raw = xcoff_data
    text_data = raw[xb.text.offset: xb.text.offset + xb.text.size]
    bl_list = bl_scan(text_data, xb.text.vaddr)

    # Find callers
    findings = []
    print(f'\n  Call sites (from {len(bl_list)} total BL instructions):')
    for caller_va, target_va in bl_list:
        if target_va not in exec_stubs:
            continue
        sink = exec_stubs[target_va]
        file_off = xb.text.offset + (caller_va - xb.text.vaddr)
        word = struct.unpack('>I', xcoff_data[file_off:file_off+4])[0]
        # Verify
        li = (word >> 2) & 0xFFFFFF
        if li & 0x800000:
            li = li - 0x1000000
        reconstructed = caller_va + li * 4
        ok = '✓' if reconstructed == target_va else '✗'
        word_hex = xcoff_data[file_off:file_off+4].hex()
        print(f'    {sink:<20s}  caller=0x{caller_va:08x}  stub=0x{target_va:08x}'
              f'  file_off=0x{file_off:x}  bytes={word_hex} {ok}')
        findings.append({
            'sink': sink, 'caller_va': caller_va, 'stub_va': target_va,
            'file_off': file_off, 'bytes': word_hex, 'verified': reconstructed == target_va,
        })

    # Context: look for arg set-up before each interesting call
    print(f'\n  Arg context (instruction before each call):')
    for f in findings:
        off = xb.text.offset + (f['caller_va'] - xb.text.vaddr)
        prev_off = off - 4
        if prev_off >= xb.text.offset:
            prev_word = struct.unpack('>I', xcoff_data[prev_off:prev_off+4])[0]
            prev_va = f['caller_va'] - 4
            print(f'    {f["sink"]:<20s}  prev@0x{prev_va:08x}: 0x{prev_word:08x}', end='')
            # Decode common patterns
            opcode = prev_word >> 26
            if opcode == 14:  # addi
                rt = (prev_word >> 21) & 0x1f
                ra = (prev_word >> 16) & 0x1f
                si = prev_word & 0xffff
                if si & 0x8000: si -= 0x10000
                print(f'  addi r{rt}, r{ra}, 0x{si:x}')
            elif opcode == 32:  # lwz
                rt = (prev_word >> 21) & 0x1f
                ra = (prev_word >> 16) & 0x1f
                d = prev_word & 0xffff
                if d & 0x8000: d -= 0x10000
                print(f'  lwz r{rt}, 0x{d:x}(r{ra})')
            elif opcode == 38:  # stb
                rs = (prev_word >> 21) & 0x1f
                ra = (prev_word >> 16) & 0x1f
                d = prev_word & 0xffff
                if d & 0x8000: d -= 0x10000
                print(f'  stb r{rs}, 0x{d:x}(r{ra})')
            else:
                print()
        # Also print the instruction before that
        if prev_off - 4 >= xb.text.offset:
            pp_word = struct.unpack('>I', xcoff_data[prev_off-4:prev_off][0:4])[0]
            pp_va = f['caller_va'] - 8
            opcode = pp_word >> 26
            if opcode == 14:  # addi
                rt = (pp_word >> 21) & 0x1f
                ra = (pp_word >> 16) & 0x1f
                si = pp_word & 0xffff
                if si & 0x8000: si -= 0x10000
                print(f'    {"":<20s}  prev@0x{pp_va:08x}: 0x{pp_word:08x}  addi r{rt}, r{ra}, 0x{si:x}')
            elif opcode == 32:  # lwz
                rt = (pp_word >> 21) & 0x1f
                ra = (pp_word >> 16) & 0x1f
                d = pp_word & 0xffff
                if d & 0x8000: d -= 0x10000
                print(f'    {"":<20s}  prev@0x{pp_va:08x}: 0x{pp_word:08x}  lwz r{rt}, 0x{d:x}(r{ra})')

    return {'name': name, 'findings': findings, 'xb': xb}


def main():
    found = {}  # name -> (bff_name, bytes)

    print(f'[+] Loading targeted BFFs from archive...')
    tf = tarfile.open(ARCHIVE, 'r:gz')
    for member in tf.getmembers():
        bname = member.name.split('/')[-1]
        if bname not in TARGET_BFFS:
            continue
        print(f'  Loading {bname} ({member.size} bytes)...')
        fobj = tf.extractfile(member)
        if fobj is None:
            continue
        bff_data = fobj.read()
        extractor = AixBffExtractor(bff_data)
        try:
            for xcoff_name, xcoff_bytes in extractor.extract():
                base = xcoff_name.split('/')[-1]
                if base in TARGETS and base not in found:
                    found[base] = (bname, xcoff_bytes)
                    print(f'    -> found {base} ({len(xcoff_bytes)} bytes)')
        except Exception as e:
            print(f'    extractor error: {e}')

    tf.close()

    print(f'\n[+] Found {len(found)}/{len(TARGETS)} targets: {sorted(found.keys())}')
    not_found = TARGETS - set(found.keys())
    if not_found:
        print(f'    NOT FOUND: {sorted(not_found)}')

    for target in sorted(TARGETS):
        if target in found:
            bff_src, xcoff_data = found[target]
            analyze(target, xcoff_data, bff_src)

    print('\n[DONE]')


if __name__ == '__main__':
    main()
