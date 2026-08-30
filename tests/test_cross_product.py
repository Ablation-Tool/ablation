"""
Cross-product homolog search: CUCM 15.0.1 capf -> ISE 3.5 + CUCM peers.

Seed: capfBldAuthString from CUCM's Certificate Authority Proxy Function daemon.
Tests whether the same Cisco auth-string utility code appears in:
  - ISE security manager (libciscossm.so)
  - ISE EST server (estserver)
  - ISE nginx proxy
  - CUCM Trust Verification Service (tvs)
  - CUCM database layer (libdbl.so)

HIGH match = shared code across products (vulnerability in one affects the other).
LOW/no-match = correct discrimination (different protocol stacks).
"""

import sys
import capstone
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.version_delta import FuncFeatures, FuncMatcher
from modules.semantic_search import SemanticSearcher

CAPF_PATH  = '/media/cowboy/research/cisco-lina-re/cucm-15.0.1-extract/cm-capf/usr/local/cm/bin/capf'
SEED_VA    = 0x37630   # capfBldAuthString (PIE: VA == file offset for this binary)
SEED_NAME  = 'capfBldAuthString'
DB         = '~/.ablation/func_id.db'

ISE_BASE   = '/media/cowboy/research/ise-re/ise-35/ise35-cisco-ra-extracted/opt/CSCOcpm/appsrv/cisco-ra'
CUCM_BASE  = '/media/cowboy/research/cisco-lina-re/cucm-15.0.1-extract'

TARGETS = {
    'ISE libciscossm':   f'{ISE_BASE}/deps/ciscossm/lib/libciscossm.so',
    'ISE estserver':     f'{ISE_BASE}/est/bin/estserver',
    'ISE nginx':         f'{ISE_BASE}/nginx/sbin/nginx',
    'CUCM tvs':          f'{CUCM_BASE}/cm-tvs/usr/local/cm/bin/tvs',
    'CUCM libdbl':       f'{CUCM_BASE}/cm-dbl/usr/local/cm/lib64/libdbl.so',
}

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


def prologue_scan(path: str) -> list[FuncFeatures]:
    with open(path, 'rb') as f:
        data = f.read()
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
        if len(asm) < _MIN_INSTRS:
            continue
        feats.append(FuncFeatures.from_disasm_lines(offset, hex(offset), asm, calls))
    return feats


def main():
    ss      = SemanticSearcher(DB)
    ss.build_corpus()
    matcher = FuncMatcher(semantic_searcher=ss)

    with open(CAPF_PATH, 'rb') as f:
        capf_data = f.read()

    asm_seed, callee_vas = extract_func(capf_data, SEED_VA)
    seed = FuncFeatures.from_disasm_lines(SEED_VA, SEED_NAME, asm_seed, callee_vas)
    print(f'Seed: {SEED_NAME}  instrs={seed.n_instrs}')

    results = {}
    for label, path in TARGETS.items():
        print(f'\nScanning {label}...')
        feats = prologue_scan(path)
        print(f'  {len(feats)} functions')
        match = matcher.find_homolog(seed, feats)
        if match is None:
            print(f'  no match')
            results[label] = None
        else:
            print(f'  top: VA={hex(match.va)}  jac={match.jaccard:.4f}  '
                  f'sem={match.semantic_score:.4f}  [{match.confidence}]')
            results[label] = match

    print('\n--- Summary ---')
    for label, m in results.items():
        if m is None:
            print(f'  {label:22s}: no match')
        else:
            print(f'  {label:22s}: sem={m.semantic_score:.4f}  '
                  f'jac={m.jaccard:.4f}  [{m.confidence}]')


if __name__ == '__main__':
    main()
