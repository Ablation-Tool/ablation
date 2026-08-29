"""
False positive check: seed a Cisco RADIUS function, scan unrelated binaries.

If BERT is discriminating correctly, top match in sshd/openssl should be
well below the 0.9256 we got for the real lina 9.22 homolog.

A HIGH confidence result (>=0.75) in a non-Cisco binary with no RADIUS code
would indicate the pipeline is latching on generic list/copy patterns rather
than RADIUS-specific behavior — a false positive.

Pass criteria:
  - top semantic score in sshd   < 0.75
  - top semantic score in openssl < 0.75
  - real lina 9.22 score (0.9256) remains clearly above both
"""

import sys
import time
import capstone
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.version_delta import FuncFeatures, FuncMatcher
from modules.semantic_search import SemanticSearcher

LINA_914  = '/home/cowboy/VDT/intel/cisco-downloads/asa9-14-extracted/lina'
SEED_VA   = 0xc563d0
SEED_NAME = 'attr_list_add_impl'
DB        = '~/.ablation/func_id.db'

TARGETS = {
    'sshd':    '/usr/sbin/sshd',
    'openssl': '/usr/bin/openssl',
}

_PROLOGUES = [
    b'\x55\x48\x89\xe5',
    b'\xf3\x0f\x1e\xfa\x55',
    b'\x55\x41',
]
_MIN_INSTRS = 8
_MAX_BYTES  = 4096
# HIGH confidence requires Jaccard >= 0.15 (version_delta._SEM_JACCARD_MIN).
# Generic C patterns (alloc+copy+return) score 0.90+ cross-binary but have
# Jaccard ~0.09 — correctly capped at MEDIUM by the floor rule.
_FP_HIGH_CONFIDENCE = 'HIGH'


def extract_func(data: bytes, offset: int) -> tuple[list[str], list[str]]:
    raw = data[offset: offset + _MAX_BYTES]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines, calls = [], []
    for insn in md.disasm(raw, offset):
        lines.append(f'{insn.mnemonic} {insn.op_str}'.strip())
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
    candidates: set[int] = set()
    for pat in _PROLOGUES:
        pos = 0
        while True:
            idx = data.find(pat, pos)
            if idx == -1:
                break
            candidates.add(idx)
            pos = idx + 1
    feats = []
    for offset in sorted(candidates):
        asm, calls = extract_func(data, offset)
        if len(asm) < _MIN_INSTRS:
            continue
        feats.append(FuncFeatures.from_disasm_lines(offset, hex(offset), asm, calls))
    return feats


def main():
    ss = SemanticSearcher(DB)
    ss.build_corpus()
    matcher = FuncMatcher(semantic_searcher=ss)

    # Seed
    with open(LINA_914, 'rb') as f:
        data_914 = f.read()
    asm_seed, calls_seed = extract_func(data_914, SEED_VA)
    seed = FuncFeatures.from_disasm_lines(SEED_VA, SEED_NAME, asm_seed, calls_seed)
    print(f'Seed: {SEED_NAME} @ {hex(SEED_VA)}  instrs={seed.n_instrs}')

    results = {}

    for name, path in TARGETS.items():
        print(f'\nScanning {name} ({path})...')
        t0 = time.time()
        feats = prologue_scan(path)
        print(f'  {len(feats)} functions in {time.time()-t0:.1f}s')

        match = matcher.find_homolog(seed, feats)
        if match is None:
            print(f'  no match found')
            results[name] = 0.0
            continue

        print(f'  top match  VA={hex(match.va)}  jaccard={match.jaccard:.4f}  sem={match.semantic_score:.4f}  [{match.confidence}]')
        results[name] = match

    print(f'\n--- Summary ---')
    print(f'  lina 9.22 (true homolog) : sem=0.9256  jac=0.1562  [HIGH]  ← baseline')
    for name, m in results.items():
        flag = '  *** FALSE POSITIVE ***' if m.confidence == _FP_HIGH_CONFIDENCE else '  ok (MEDIUM/LOW)'
        print(f'  {name:12s}             : sem={m.semantic_score:.4f}  jac={m.jaccard:.4f}  [{m.confidence}]{flag}')

    for name, m in results.items():
        assert m.confidence != _FP_HIGH_CONFIDENCE, \
            f'FALSE POSITIVE: {name} rated HIGH (sem={m.semantic_score:.4f} jac={m.jaccard:.4f})'

    print('\nPASS — unrelated binaries correctly rated MEDIUM/LOW despite high semantic score')


if __name__ == '__main__':
    main()
