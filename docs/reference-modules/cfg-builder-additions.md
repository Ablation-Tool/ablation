# CFGBuilder: Access Control Analysis Functions

## Why these additions exist

Three gaps motivated this addition:

1. No Ablation function identified reachable blocks that bypass all access-control check points. Complete mediation failure is one of the most impactful auth findings, and dominator-tree analysis is the correct tool.
2. Error paths that skip security-state writes such as token zeroing and auth flag reset are a common class of auth bug. No analysis existed to detect them structurally.
3. Functions that return zero on an error path without passing through any auth check are a distinct auth-bypass class not covered by the existing dead-security-check or constant-time scanners.

## find_complete_mediation_gaps

Returns a list of block VAs reachable from entry that have no auth-check block as a dominator ancestor.

`auth_block_vas`: a set of block VAs identified as access-control check points. Identify these by looking for blocks containing comparisons against a known auth return value, or by name-matching using `ctx.name()`.

```python
from ablation.analyzers.cfg_builder import CFGBuilder, find_complete_mediation_gaps

builder = CFGBuilder(ctx.path)
cfg = builder.build_function(func_va)

auth_va = 0x1234  # VA of the block containing the auth check
gaps = find_complete_mediation_gaps(cfg, auth_block_vas={auth_va})
for block_va in gaps:
    print(f"Block 0x{block_va:x} reachable without auth check")
```

## find_error_path_security_gaps(cfg)

Returns a list of `(secure_block_va, skipped_block_va)` pairs. Each pair identifies a branch where one successor contains a security-critical write and the other does not.

Identifies patterns where the success path zeros a session token or clears an auth flag, but the error path jumps past that write, leaving the prior state in place.

```python
from ablation.analyzers.cfg_builder import find_error_path_security_gaps

gaps = find_error_path_security_gaps(cfg)
for secure_va, skipped_va in gaps:
    print(f"Security write at 0x{secure_va:x} skipped on error path 0x{skipped_va:x}")
```

**Security write patterns detected:** writes to operands matching session, token, key, auth, role, secret, passwd, or cred.

## find_auth_bypass_via_error_path(cfg)

Returns a list of block VAs for RET blocks that return zero on paths that never pass through a block with auth-keyword operands.

A zero return on an error path that bypassed the auth check is interpreted by callers as success.

```python
from ablation.analyzers.cfg_builder import find_auth_bypass_via_error_path

bypass_vas = find_auth_bypass_via_error_path(cfg)
for va in bypass_vas:
    print(f"Zero return at 0x{va:x} reachable without auth operand in dominator chain")
```

**Zero return patterns detected:** `XOR eax,eax`, `MOV eax,0`, `MOVZ w0,0` and similar patterns in the final block before RET.

## Severity and triage

All three functions return VA lists. They do not produce `Finding` objects. Create findings with `FindingRegistry.register()` at HIGH severity for confirmed gaps. Use `PathSolver.solve_path()` to verify that the identified paths are feasible before reporting.

These functions operate on a single-function CFG from `CFGBuilder.build_function()`. They do not analyze cross-function paths. Combine with `TaintTracker` for interprocedural coverage.
