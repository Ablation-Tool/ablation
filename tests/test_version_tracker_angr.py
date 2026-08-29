"""
Verification: VersionTracker.track() with real angr CFGFast against lina binaries.

Tracks lina 9.14 attr_list_add_impl (0xc563d0) into lina 9.22.
Uses the three-stage pipeline:
  Stage 1  Structural pre-filter (basic block count ±2, edge ratio ±35%)
  Stage 2  Mnemonic 4-gram Jaccard (top-10 candidates)
  Stage 3  BERT semantic tiebreaker / primary for low-Jaccard cases

Expected outcome: homolog found in 9.22, semantic_score >= 0.75, PATCHED.

NOTE: CFGFast on ~94MB ELFs takes 5-20 min per binary. Use --fast to skip
      the 9.22 run and only validate seed extraction.
"""

import sys
import time
import argparse
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.version_delta import VersionTracker
from modules.semantic_search import SemanticSearcher

LINA_914  = '/home/cowboy/VDT/intel/cisco-downloads/asa9-14-extracted/lina'
LINA_922  = '/home/cowboy/VDT/intel/cisco-downloads/asa9-22-lina/asa/bin/lina'
SEED_VA   = 0xc563d0   # attr_list_add_impl
SEED_NAME = 'attr_list_add_impl'
DB        = '~/.ablation/func_id.db'

def main(fast=False):
    ss = SemanticSearcher(DB)
    ss.build_corpus()

    binaries = {'9.14': LINA_914}
    if not fast:
        binaries['9.22'] = LINA_922

    tracker = VersionTracker(binaries=binaries, semantic_searcher=ss)

    print(f'Loading 9.14 ({LINA_914})...')
    t0 = time.time()
    proj, cfg = tracker._load_cfg(LINA_914)
    print(f'  CFGFast done in {time.time()-t0:.1f}s')
    print(f'  functions: {len(cfg.kb.functions)}')

    seed = tracker._seed_features(LINA_914, SEED_VA, SEED_NAME)
    assert seed is not None, f'seed function {hex(SEED_VA)} not found'
    print(f'  seed: {seed.name}  blocks={seed.n_blocks}  instrs={seed.n_instrs}')

    if fast:
        print('\n--fast: skipping 9.22 CFGFast. Seed extraction PASS.')
        return

    print(f'\nLoading 9.22 ({LINA_922})...')
    t0 = time.time()
    reports = tracker.track(seed_binary='9.14', seed_va=SEED_VA, seed_name=SEED_NAME)
    print(f'  track() done in {time.time()-t0:.1f}s')

    for r in reports:
        print(f'\n{r.summary()}')
        if r.match:
            m = r.match
            print(f'  homolog VA       : {hex(m.va)}')
            print(f'  homolog name     : {m.name}')
            print(f'  jaccard          : {m.jaccard:.4f}')
            print(f'  semantic_score   : {m.semantic_score:.4f}')
            print(f'  confidence       : {m.confidence}')
            print(f'  is_patched       : {m.delta.is_patched}')
            print(f'  ratio            : {m.delta.ratio:.4f}')
            if m.delta.added[:5]:
                print(f'  added            : {m.delta.added[:5]}')
            if m.delta.removed[:5]:
                print(f'  removed          : {m.delta.removed[:5]}')
            if m.new_callees:
                print(f'  new callees      : {m.new_callees}')
            if m.removed_callees:
                print(f'  removed callees  : {m.removed_callees}')

    found = [r for r in reports if r.match is not None]
    assert found, 'VersionTracker found no homolog in 9.22'
    m = found[0].match
    assert m.semantic_score >= 0.70, f'semantic_score {m.semantic_score:.4f} < 0.70'
    print('\nPASS')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--fast', action='store_true', help='seed extraction only, skip 9.22')
    args = parser.parse_args()
    main(fast=args.fast)
