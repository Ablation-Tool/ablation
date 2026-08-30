"""
Full ASA/FTD lina version timeline for attr_list_add_impl patch attribution.

Scans all available lina versions with the 9.14 seed to determine:
  - Which versions contain the function (introduction version)
  - Which versions show is_patched=True (patch version)
  - Whether the patch was forward-ported to FTD

Adjust VERSIONS paths to match your extracted firmware locations.
"""

import sys, os, time
import capstone
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.version_delta import FuncFeatures, FuncMatcher
from modules.semantic_search import SemanticSearcher

LINA_914  = '/home/cowboy/VDT/intel/cisco-downloads/asa9-14-extracted/lina'
SEED_VA   = 0xc563d0   # attr_list_add_impl
SEED_NAME = 'attr_list_add_impl'
DB        = '~/.ablation/func_id.db'

# Ordered from oldest to newest. Set path to None to skip a version.
# Note: 9.2.4 (i386), 9.1.7.23 (x86-64), and FTD 1200/10.0.0 ARM64 are in test_cross_arch.py
VERSIONS = [
    # ASA 9.0.4.42 is i386 — cross-arch result (jac=0.1471, MEDIUM, Era 1); in test_cross_arch.py
    ('ASA 9.1.7.23',   '/media/cowboy/research/cisco-lina-re/asa91723-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.5.2.204',  '/media/cowboy/research/cisco-lina-re/asa952-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.6.4.18',   '/media/cowboy/research/cisco-lina-re/asa964-extract/cpio-root/asa/bin/lina'),
    # FTD 6.2.0-362 (Jan 2017, ~ASA 9.6.x era): jac=0.1307 Era 1
    ('FTD 6.2.0-362',  '/media/cowboy/research/cisco-lina-re/ftd620-extract/lina'),
    # ASA 9.7.1 (Jan 2017): jac=0.1301 Era 1 — boundary pin: Era 1→2 transition is between 9.7.1 and 9.9.2.85
    ('ASA 9.7.1',      '/media/cowboy/research/cisco-lina-re/asa971-extract/lina'),
    ('ASA 9.9.2.85',   '/media/cowboy/research/cisco-lina-re/asa992-85-extract/cpio-root/asa/bin/lina'),
    # FTD 6.3.0-83 (Nov 2018, ~ASA 9.8-9.9 era): jac=0.9593 Era 2 UNPATCHED
    ('FTD 6.3.0-83',   '/media/cowboy/research/cisco-lina-re/ftd630-extract/lina'),
    ('ASA 9.10.1.37',  '/media/cowboy/research/cisco-lina-re/asa9101037-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.10.1.40',  '/media/cowboy/research/cisco-lina-re/asa9101040-mnt/asa/bin/lina'),
    ('ASA 9.10.1.42',  '/media/cowboy/research/cisco-lina-re/asa9101042-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.12.4.13',  '/media/cowboy/research/cisco-lina-re/asa9124-13-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.12.4.67',  '/media/cowboy/research/cisco-lina-re/asa9124-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.13.1.12',  '/media/cowboy/research/cisco-lina-re/asa9131112-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.14 (seed source)', None),   # seed — skip self-match
    ('ASA 9.14.1.15',  '/media/cowboy/research/cisco-lina-re/asa9141-15-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.14.1.30',  '/media/cowboy/research/cisco-lina-re/asa9141-30-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.14.2.4',   '/media/cowboy/research/cisco-lina-re/asa9142-4-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.14.2.14',  '/media/cowboy/research/cisco-lina-re/asa91424-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.14.4.24',  '/media/cowboy/research/cisco-lina-re/asa9144-extract/cpio-root/asa/bin/lina'),
    # FTD 6.6.0 (Apr 2020, ASA 9.14.x base): jac=0.9593 Era 2 UNPATCHED
    ('FTD 6.6.0',      '/media/cowboy/research/cisco-lina-re/ftd660-extract/lina'),
    # ASA 9.15.1.1: jac=0.2143 Era 3 PATCHED — direct ASA-side patch boundary confirmation
    ('ASA 9.15.1.1',   '/media/cowboy/research/cisco-lina-re/asa915-11-extract/lina'),
    # FTD 6.7.0-65 (Nov 2020, ASA 9.15.x base): jac=0.2143 Era 3 PATCHED — matches 9.15.1.1 exactly
    ('FTD 6.7.0-65',   '/media/cowboy/research/cisco-lina-re/ftd670-extract/lina'),
    ('ASA 9.16.1',     '/home/cowboy/VDT/intel/cisco-downloads/asa9-16-1-binwalk-out/'
                       '_asa9-16-1-smp-k8.bin.extracted/asa9-16-1-cpio/asa/bin/lina'),
    # FTD 7.0.0-94 (May 2021, ASA 9.16.x base): jac=0.2051 Era 3 PATCHED
    ('FTD 7.0.0-94',   '/media/cowboy/research/cisco-lina-re/ftd700-extract/lina'),
    ('ASA 9.16.2.14',  '/media/cowboy/research/cisco-lina-re/asa9162-14-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.16.4.42',  '/media/cowboy/research/cisco-lina-re/asa916442-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.16.4.92',  '/media/cowboy/research/cisco-lina-re/asa91692-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.16.4.76',  '/media/cowboy/research/cisco-lina-re/asa9164-76-extract/cpio-root/asa/bin/lina'),
    ('ASA 9.16.4.84',  '/media/cowboy/research/cisco-lina-re/asa9164-84-extract/cpio-root/asa/bin/lina'),
    # ASA 9.20.3: jac=0.1690 Era 3 drift — patched impl accumulating structural changes
    ('ASA 9.20.3',     '/media/cowboy/research/cisco-lina-re/asa9203-extract/lina'),
    ('ASA 9.22',       '/home/cowboy/VDT/intel/cisco-downloads/asa9-22-lina/asa/bin/lina'),
    ('ASA 9.22.1.1',   '/media/cowboy/research/cisco-lina-re/asa92211-extract/lina'),
    ('ASA 9.22.2',     '/media/cowboy/research/cisco-lina-re/asa9222-extract/'
                       '_asa9-22-2-32-smp-k8.bin.extracted/_rootfs.img.extracted/cpio-root/asa/bin/lina'),
    ('FTD 7.6.2',      '/media/cowboy/research/cisco-lina-re/ftd-762-extract/'
                       'rootfs/root/ngfw/usr/local/asa/bin/lina'),
    ('ASA 10.1.2.1.7', '/media/cowboy/research/cisco-lina-re/asa10121-extract/cpio-root/asa/bin/lina'),
]

_PROLOGUES  = [b'\x55\x48\x89\xe5', b'\xf3\x0f\x1e\xfa\x55', b'\x55\x41']
_MIN_INSTRS = 8
_MAX_BYTES  = 4096


def extract_func(data: bytes, offset: int) -> tuple[list[str], list[str]]:
    raw = data[offset: offset + _MAX_BYTES]
    md  = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines, calls = [], []
    for insn in md.disasm(raw, offset):
        op = f'{insn.mnemonic} {insn.op_str}'.strip()
        lines.append(op)
        if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
            calls.append(insn.op_str)
        if insn.mnemonic in ('ret', 'retq', 'retn'):
            break
        if insn.mnemonic in ('jmp', 'jmpq'):
            try:
                if abs(int(insn.op_str, 16) - offset) > 0x20000:
                    break
            except ValueError:
                break
    return lines, calls


def prologue_scan(data: bytes) -> list[FuncFeatures]:
    seen: set[int] = set()
    for pat in _PROLOGUES:
        pos = 0
        while True:
            idx = data.find(pat, pos)
            if idx == -1:
                break
            seen.add(idx)
            pos = idx + 1
    feats = []
    for offset in sorted(seen):
        asm, calls = extract_func(data, offset)
        if len(asm) >= _MIN_INSTRS:
            feats.append(FuncFeatures.from_disasm_lines(offset, hex(offset), asm, calls))
    return feats


def main():
    ss      = SemanticSearcher(DB)
    ss.build_corpus()
    matcher = FuncMatcher(semantic_searcher=ss)

    with open(LINA_914, 'rb') as f:
        data914 = f.read()
    asm_seed, callee_vas = extract_func(data914, SEED_VA)
    seed = FuncFeatures.from_disasm_lines(SEED_VA, SEED_NAME, asm_seed, callee_vas)
    print(f'Seed: {SEED_NAME}  instrs={seed.n_instrs}\n')
    print(f'{"Version":<25} {"Functions":>10} {"Time":>6}  {"VA":>12}  {"Jac":>6}  {"Sem":>6}  {"Conf":<8}  Patched  Delta')
    print('-' * 105)

    results = []
    for label, path in VERSIONS:
        if path is None or not os.path.exists(path):
            print(f'{label:<25}  {"(skipped)":>10}')
            continue
        size_mb = os.path.getsize(path) / 1024 / 1024
        with open(path, 'rb') as f:
            data = f.read()
        t0 = time.time()
        feats = prologue_scan(data)
        scan_s = time.time() - t0
        t0 = time.time()
        match = matcher.find_homolog(seed, feats)
        match_s = time.time() - t0
        total_s = scan_s + match_s

        if match is None:
            print(f'{label:<25} {len(feats):>10} {total_s:>5.0f}s  {"NOT FOUND":>12}')
            results.append((label, None))
        else:
            delta = ''
            if match.delta.added:   delta += f'+{len(match.delta.added)}'
            if match.delta.removed: delta += f'-{len(match.delta.removed)}'
            print(f'{label:<25} {len(feats):>10} {total_s:>5.0f}s  '
                  f'{hex(match.va):>12}  {match.jaccard:.4f}  {match.semantic_score:.4f}  '
                  f'{match.confidence:<8}  '
                  f'{"YES" if match.delta.is_patched else "NO":>7}  {delta}')
            results.append((label, match))

    print('\n--- Attribution Summary ---')
    for label, m in results:
        if m is None:
            print(f'  {label}: NOT PRESENT (function not introduced yet, or too diverged)')
        elif m.delta.is_patched:
            print(f'  {label}: PATCHED (delta: +{len(m.delta.added)}-{len(m.delta.removed)})')
        else:
            print(f'  {label}: UNPATCHED (jac={m.jaccard:.4f}, sem={m.semantic_score:.4f}, conf={m.confidence})')


if __name__ == '__main__':
    main()
