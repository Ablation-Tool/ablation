# AixInstallpStep4Multilevel

Multi-level escape decoder for IBM AIX installp BFF step 4: handling rare bytes whose sorted-rank index exceeds the K-1 limit of the single-level decoder in `AixInstallpDecompressor`.

---

## Why this exists

1. **The single-level step4 decoder silently drops rare bytes with sorted-rank j ≥ K-1.** For K=56, this means any rare byte with j ≥ 55 is lost. These bytes produce no output: they are either dropped or emitted as raw escape pairs rather than the intended byte.

2. **Empirical RE on VIOS `automountd` (U828079.bff, K=56) proves a j=185 case exists.** `sym_table[241]=0xdf` carries j=185, which far exceeds the single-level limit of 54. The byte 0xdf is part of the XCOFF32 magic `0x01df`: without decoding it, XCOFF32 magic verification fails.

3. **IBM `liblpp.a` uses a level-k E-run scheme for large j.** The level-k hypothesis encodes rare byte R with rank j using k escape bytes followed by a term byte, where `k = floorj / (K - 1) + 1`.

---

## Level-k encoding

For rare byte R with sorted-rank j among `sym_table[K..255]`:

```
level k     = floor(j / (K - 1)) + 1
term_idx    = j mod (K - 1)
encoded     = [E^k, sorted_K_nonescape[term_idx]]

Decoded:
  [E^k, term]  →  sym_table[K + (k-1)*(K-1) + term_idx]  for k=1..MAX_LEVEL
```

**Self-escape rule:** `[E, E]` → emit E literal. `[E^{2m}, ...]` → m self-escaped E literals.

**For K=56 example: decoding 0xdf**
```
j = 241 - 56 = 185
k = floor(185/55) + 1 = 4
term_idx = 185 mod 55 = 20
sorted_K_nonescape[20] = 0x38
Encoded: [0x01, 0x01, 0x01, 0x01, 0x38]  (4 E's + 0x38)
```

---

## Usage

```python
from ablation.core.aix_installp_step4_multilevel import AixInstallpStep4Multilevel

# After step 3 BWT inverse produces bwt_buf (K-byte alphabet, escape-encoded):
decoder = AixInstallpStep4Multilevel(sym_table, bwt_buf, K=56)
decoded_bytes = decoder.decode()
```

---

## Limitations

**Level-k hypothesis is empirically unconfirmed.** The E-run distribution in the `automountd` main-cycle segment shows E^1 (713×), E^2 (25×), E^3 (12×), E^4 (3×), E^5 (1×). E^4 sequences decode as two self-escape pairs 2 × E literals in the observed data, not as level-4 terms. No j ≥ 55 rare bytes have been observed in any decoded segment so far. This module encodes the hypothesis; it has not yet been validated against a confirmed level-k case.

**Only for K < 256 entries.** When K=256 all 256 bytes are common, there are no rare bytes and the single-level decoder is sufficient.

---

## Pipeline position

**When to use:** Check `K` from `AixInstallpDecompressor`. If any `sym_table[K:]` byte is expected in the output and K < 200, use this module for step 4 instead of the single-level decoder.

**After:** Pass decoded bytes to XCOFF32 magic verification (`xcoff_bytes[:2] == b'\x01\xdf'`).

---

## See also

- [AIX Installp Decompressor](aix-installp-decompressor.md): full pipeline; single-level step 4
- [BWT Eulerian Reconstructor](bwt-eulerian-reconstructor.md): multi-cycle BWT recovery when K < 256
