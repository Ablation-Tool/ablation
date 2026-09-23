"""
Verification: SemanticSearcher against real seeded func_id_db.

Tests that BERT-backed corpus lookup returns correct top-1 for two distinct
query roles against the 26 confirmed lina functions seeded in the live db.
"""

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.semantic_search import SemanticSearcher

DB = '~/.ablation/func_id.db'

def main():
    ss = SemanticSearcher(DB)
    n = ss.build_corpus()
    print(f'corpus: {n} functions')
    assert n >= 20, f'expected >=20 seeded functions, got {n}'

    # RADIUS attr-list handler
    r = ss.query('RADIUS attribute class linked-list append overflow strcpy', top_k=3)
    print(f'\nRADIUS query  top-1: {r[0].name!r}  score={r[0].score:.4f}')
    for x in r:
        print(f'  {x.score:.4f}  {x.name}  ({x.role})')
    # Top-1 must be RADIUS role AND lead second place by a clear margin
    assert 'RADIUS' in r[0].role.upper(), f'top-1 not RADIUS: {r[0].role}'
    assert r[0].score >= r[1].score * 1.15, \
        f'top-1 margin too narrow: {r[0].score:.4f} vs {r[1].score:.4f}'

    # Crypto / obfuscation
    r2 = ss.query('RSA private key decrypt EVP_PKEY PEM obfuscation cipher', top_k=3)
    print(f'\nCRYPTO query  top-1: {r2[0].name!r}  score={r2[0].score:.4f}')
    for x in r2:
        print(f'  {x.score:.4f}  {x.name}  ({x.role})')
    # Top-1 must be the crypto function AND clearly ahead of second place
    assert 'Decrypt' in r2[0].name or 'CRYPTO' in r2[0].role.upper(), \
        f'top-1 not crypto: {r2[0].name}'
    assert r2[0].score >= r2[1].score * 2.0, \
        f'top-1 margin too narrow: {r2[0].score:.4f} vs {r2[1].score:.4f}'

    print('\nPASS')

if __name__ == '__main__':
    main()
