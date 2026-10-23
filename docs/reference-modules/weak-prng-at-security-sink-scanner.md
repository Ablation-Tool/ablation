# WeakPRNGAtSecuritySinkScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Detect weak PRNG use in security-sensitive call paths.** `TaintTracker` follows user input to exec sinks. No prior module checked whether random number output from a weak PRNG feeds session ID generation, token creation, or cryptographic nonce derivation. `WeakPRNGAtSecuritySinkScanner` checks PLT imports for weak generators (15 functions), checks for strong alternatives (12 functions), and flags security-named functions that call a weak PRNG without calling a strong one first. When no strong PRNG is present in the binary at all, it emits a global HIGH finding.

## Usage

```python
from modules.weak_prng_at_security_sink_scanner import WeakPRNGAtSecuritySinkScanner

scanner = WeakPRNGAtSecuritySinkScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = WeakPRNGAtSecuritySinkScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: WeakPRNGFinding

| Field | Type | Description |
|-------|------|-------------|
| `scope` | str | `global` or the security function name |
| `scope_va` | int | 0 for global; function VA otherwise |
| `weak_prngs` | list[str] | Weak PRNG functions found |
| `time_seeded` | bool | True when `srand(time(...))` pattern detected |
| `no_strong` | bool | True when no strong PRNG is imported at all |
| `severity` | str | `HIGH` for global or time-seeded; `MEDIUM` for path-level |

## Weak PRNG set

15 functions: `rand`, `srand`, `random`, `srandom`, `rand_r`, `lrand48`, `mrand48`, `nrand48`, `drand48`, `jrand48`, `erand48`, `srand48`, `lcong48`, `seed48`, `random_r`.

## Strong PRNG set

12 functions: `getrandom`, `getentropy`, `RAND_bytes`, `RAND_priv_bytes`, `randombytes`, `randombytes_buf`, `arc4random`, `arc4random_buf`, `BCryptGenRandom`, `CryptGenRandom`, `SecRandomCopyBytes`, `wc_RNG_GenerateBlock`.

## Security function heuristic

Functions scanned for security context: names matching `session`, `token`, `nonce`, `csrf`, `keygen`, `derive_key`, `otp`, `secret`, `passw`, `auth`, `challenge`, `random_id`, `gen_rand`, `rand_gen`, `uuid`.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## See also

- [DeprecatedCryptoScanner](deprecated-crypto-scanner.md): MD5/SHA-1/DES/RC4 detection
- [HardcodedCredentialScanner](hardcoded-credential-scanner.md): static secrets that bypass PRNG entirely
- [TaintTracker](taint-analysis.md): trace PRNG output to session/token sinks
