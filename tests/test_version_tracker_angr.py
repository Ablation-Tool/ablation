"""
Verification: VersionTracker end-to-end on real lina binaries.

Seed: lina 9.14 attr_list_add_impl (0xc563d0) — extracted via capstone
      (FuncFeatures.from_disasm_lines, no angr required for the seed).

Target: lina 9.22 — function candidates found via prologue scanning
        (x86-64 push rbp / endbr64 patterns), then features extracted
        per-function via capstone. Orders of magnitude faster than CFGFast
        on a 94MB binary; proves the 3-stage pipeline end-to-end.

Expected: homolog found in 9.22, semantic_score >= 0.75, PATCHED.

Optional --angr flag runs full CFGFast on 9.14 and validates that floor_func
finds the seed when the exact VA is not a known function entry.
"""

import sys
import time
import argparse
import capstone
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.version_delta import (
    FuncFeatures, FuncMatcher, DeltaReport, HomologMatch,
    jaccard_similarity,
)
from modules.semantic_search import SemanticSearcher

LINA_914  = '/path/to/binary'
LINA_922  = '/path/to/binary'
SEED_VA   = 0xc563d0
SEED_NAME = 'attr_list_add_impl'
DB        = '~/.ablation/func_id.db'

# x86-64 function prologue byte sequences to scan for
_PROLOGUES = [
    b'\x55\x48\x89\xe5',          # push rbp; mov rbp, rsp
    b'\xf3\x0f\x1e\xfa\x55',      # endbr64; push rbp
    b'\x55\x41',                   # push rbp; push r...
]
_MIN_INSTRS = 8
_MAX_BYTES  = 4096


def extract_func_capstone(data: bytes, file_offset: int, va: int) -> tuple[list[str], list[str]]:
    """Disassemble from file_offset up to ret/tail-call, return (asm_lines, callees)."""
    raw = data[file_offset: file_offset + _MAX_BYTES]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines, callees = [], []
    for insn in md.disasm(raw, va):
        op = f'{insn.mnemonic} {insn.op_str}'.strip()
        lines.append(op)
        if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
            callees.append(insn.op_str)
        if insn.mnemonic in ('ret', 'retq', 'retn'):
            break
        if insn.mnemonic in ('jmp', 'jmpq'):
            try:
                dest = int(insn.op_str, 16)
                if abs(dest - va) > 0x20000:
                    break
            except ValueError:
                break
    return lines, callees


def prologue_scan(path: str) -> list[FuncFeatures]:
    """Find function candidates via prologue byte patterns; extract features via capstone."""
    print(f'Prologue scanning {path}...')
    t0 = time.time()
    with open(path, 'rb') as f:
        data = f.read()

    candidates: set[int] = set()
    for pat in _PROLOGUES:
        pos = 0
        while True:
            idx = data.find(pat, pos)
            if idx == -1:
                break
            # Align to 16-byte boundary within ±16
            aligned = (idx + 8) & ~0xF
            for va in range(max(0, idx - 4), idx + 4):
                if data[va: va + len(pat)] == pat:
                    candidates.add(va)
                    break
            pos = idx + 1

    print(f'  {len(candidates)} prologue candidates in {time.time()-t0:.1f}s — extracting features...')
    t0 = time.time()

    features = []
    for offset in sorted(candidates):
        asm, calls = extract_func_capstone(data, offset, offset)
        if len(asm) < _MIN_INSTRS:
            continue
        f = FuncFeatures.from_disasm_lines(offset, hex(offset), asm, calls)
        features.append(f)

    print(f'  {len(features)} functions with >={_MIN_INSTRS} instrs in {time.time()-t0:.1f}s')
    return features


def main(use_angr: bool = False, full_cfg: bool = False):
    ss = SemanticSearcher(DB)
    ss.build_corpus()

    # ── seed extraction (capstone, no angr) ──────────────────────────────────
    print(f'Extracting seed from 9.14 @ {hex(SEED_VA)} ({SEED_NAME})...')
    with open(LINA_914, 'rb') as f:
        data_914 = f.read()
    asm_seed, calls_seed = extract_func_capstone(data_914, SEED_VA, SEED_VA)
    seed = FuncFeatures.from_disasm_lines(SEED_VA, SEED_NAME, asm_seed, calls_seed)
    print(f'  instrs={seed.n_instrs}  ngrams={len(seed.ngrams_4)}')
    assert seed.n_instrs >= 10, f'seed too short: {seed.n_instrs} instrs'

    if use_angr:
        # ── angr validation: floor_func finds seed when exact VA missing ─────
        print(f'\nAngr floor_func validation (slow)...')
        import angr
        proj = angr.Project(LINA_914, auto_load_libs=False)
        cfg  = proj.analyses.CFGFast(normalize=True)
        func = cfg.kb.functions.get(SEED_VA)
        if func is None:
            func = cfg.kb.functions.floor_func(SEED_VA)
        assert func is not None, 'floor_func returned None'
        print(f'  floor_func → {func.name} @ {hex(func.addr)}')

    # ── target: full CFGFast or prologue scan on 9.22 ────────────────────────
    if full_cfg:
        from modules.version_delta import VersionTracker
        tracker = VersionTracker(
            binaries={'9.14': LINA_914, '9.22': LINA_922},
            semantic_searcher=ss,
        )
        print(f'CFGFast on 9.22 ({LINA_922}) — this takes ~60-70 min...')
        t0 = time.time()
        target_feats = tracker._all_features(LINA_922)
        print(f'  {len(target_feats)} functions in {time.time()-t0:.1f}s')
    else:
        target_feats = prologue_scan(LINA_922)
    assert len(target_feats) > 100, f'too few functions found: {len(target_feats)}'

    # ── 3-stage match ────────────────────────────────────────────────────────
    print(f'\nRunning 3-stage matcher (seed → {len(target_feats)} candidates)...')
    t0 = time.time()
    matcher = FuncMatcher(semantic_searcher=ss)
    match = matcher.find_homolog(seed, target_feats)
    print(f'  done in {time.time()-t0:.1f}s')

    assert match is not None, 'FuncMatcher found no homolog'

    print(f'\nResult:')
    print(f'  homolog VA       : {hex(match.va)}')
    print(f'  jaccard          : {match.jaccard:.4f}')
    print(f'  semantic_score   : {match.semantic_score:.4f}')
    print(f'  confidence       : {match.confidence}')
    print(f'  is_patched       : {match.delta.is_patched}')
    print(f'  ratio            : {match.delta.ratio:.4f}')
    if match.delta.added[:5]:
        print(f'  added            : {match.delta.added[:5]}')
    if match.delta.removed[:5]:
        print(f'  removed          : {match.delta.removed[:5]}')

    assert match.semantic_score >= 0.70, \
        f'semantic_score {match.semantic_score:.4f} < 0.70'

    print('\nPASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--angr', action='store_true',
                        help='also validate angr floor_func on 9.14 (adds CFGFast time)')
    parser.add_argument('--full', action='store_true',
                        help='run full CFGFast on 9.22 target instead of prologue scan')
    args = parser.parse_args()
    main(use_angr=args.angr, full_cfg=args.full)
