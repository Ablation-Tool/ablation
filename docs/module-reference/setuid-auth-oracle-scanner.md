# SetuidAuthOracleScanner

## Why this exists

Four things were not possible before in Ablation:

1. **Detect CWE-307 (no rate limiting) in setuid validators without taint analysis.** A setuid binary that calls `getspnam`/`crypt`/`strcmp` and returns the result via exit code is a brute-force oracle. This module flags the pattern from PLT imports alone — no taint run required. Before this module, the pattern had to be found by manual PLT inspection on each new binary.

2. **Distinguish PAM-mediated auth from raw shadow validators.** PAM enforces rate limiting via `pam_tally2`, `faillock`, and audit hooks. A binary that calls `getspnam` directly (no `pam_start` in PLT) bypasses all of that. The module uses `pam_start` absence as a strong signal for missing controls, and checks rate-limiting indicators *per oracle function body only* — not binary-wide — so a `usleep` on a different path does not mask a real oracle.

3. **Locate the validation function and its callers.** The module walks every function body to find which function(s) call both a shadow accessor and a crypt function, then walks one level up the call graph to show reachability from entry points — replacing the manual call trace needed to confirm exploitability.

4. **Flag weak PRNG seeding alongside the oracle in one pass.** OTP generation seeded with `gettimeofday().tv_usec` (~20 bits of entropy) is a CWE-338 pattern that commonly co-occurs with the oracle pattern in the same binary. The module reports both findings together so neither is missed during triage.

## Patterns detected

| Pattern | CWE | Trigger |
|---------|-----|---------|
| Shadow password oracle | CWE-307 | `getspnam`/`getspnam_r` + `crypt`/`crypt_r` in same function; no rate-limit call in that function |
| Microsecond-seeded PRNG | CWE-338 | `srandom`/`srand` + `gettimeofday`/`time` + `random`/`rand` all in PLT |

## Usage

```python
from modules.setuid_auth_oracle_scanner import SetuidAuthOracleScanner

# From path (builds BinaryContext internally)
scanner = SetuidAuthOracleScanner.from_path('/opt/hsc/bin/LoginMOMIssue')
hits = scanner.scan()
print(scanner.report(hits))

# From existing context
scanner = SetuidAuthOracleScanner.from_context(ctx)
hits = scanner.scan()
for h in hits:
    print(h.fmt())

# Non-setuid daemon running as root
scanner = SetuidAuthOracleScanner.from_path('/usr/sbin/authlite', is_privileged=True)
```

## Key API

| Symbol | Description |
|--------|-------------|
| `SetuidAuthOracleScanner.from_context(ctx, is_privileged=False)` | Constructor from existing `BinaryContext` |
| `SetuidAuthOracleScanner.from_path(path, is_privileged=False)` | Constructor from binary path. Raises `ValueError` for files > 256 MB. |
| `scan()` | Returns `list[OracleHit]`, one per oracle function found |
| `report(hits)` | Returns formatted string report |
| `OracleHit.binary_path` | Path of the binary |
| `OracleHit.is_setuid` | True if `st_mode & 0o4000` |
| `OracleHit.shadow_func` | e.g. `"getspnam"` |
| `OracleHit.crypt_func` | e.g. `"crypt"` |
| `OracleHit.cmp_func` | e.g. `"strcmp"` |
| `OracleHit.has_rate_limit` | True if PAM/sleep/tally found *in the oracle function body* |
| `OracleHit.oracle_func_va` | VA of the function doing all three calls |
| `OracleHit.callers` | Names of functions that call the oracle function |
| `OracleHit.weak_prng` | True if CWE-338 co-pattern also detected |
| `OracleHit.prng_func` | e.g. `"srandom"` |
| `OracleHit.time_func` | e.g. `"gettimeofday"` |
| `OracleHit.rand_func` | e.g. `"random"` |

## Architecture support

x86-64 ELF only. The constructor raises `ValueError` for any other architecture. ARM/MIPS binaries would require a different calling convention for PLT call site detection.

## Limitations

- **x86-64 only.** Capstone is initialized with `CS_ARCH_X86 / CS_MODE_64`. Passing any other architecture raises `ValueError` at construction time.
- **One-level caller walk.** `callers` shows direct callers only — not the full reachability chain.
- **CWE-338 is binary-wide, not per-function.** The weak PRNG check looks for `srandom`/`time`/`random` in PLT, which confirms the pattern exists in the binary but does not pinpoint which function seeds with time. Use `WindowAnalyzer.dump_text()` to trace the exact OTP generation site.
- **Rate-limit check is per-oracle-function only.** A `usleep()` present in PLT but only on an unrelated code path does not suppress the finding. This is intentional — see the design note below.

## Design note: per-function rate-limit check

The rate-limit check (`_RATE_LIMIT_FUNCS` intersection) is applied only to instructions within the oracle function body, not to the binary's PLT as a whole. This is critical for correctness: `LoginMOMIssue` imports `usleep@plt` for a different path (session expiry logic) but the `isValid()` oracle function has no `usleep` call. A binary-wide check would suppress a real CWE-307 finding.

## FORGE audit

Gate: **PASSED** (0 CRITICAL, 0 HIGH).

- 1 MEDIUM (false_positive_risk): `SHA512_Update`/`SHA256_Update` removed from `_CRYPT_FUNCS`; these are OpenSSL primitives imported by any TLS binary and would produce false positives against binaries that happen to import both an OpenSSL hash and `getspnam`.
- 1 MEDIUM (false_positive_risk): `lckpwdf`/`ulckpwdf` removed from `_SHADOW_FUNCS`; these lock the shadow file but do not read it. Replaced with `getspent`/`getspent_r`/`shadow_ent`.
- 1 MEDIUM (portability): arch guard added to `__init__`; raises `ValueError` for non-x86-64 `BinaryContext` to prevent silent misclassification.

Confirmed on: `LoginMOMIssue` (setuid, 1 oracle hit, CWE-307 + CWE-338 co-finding, callers: `main`).
