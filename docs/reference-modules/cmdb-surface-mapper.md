# CMDB Surface Mapper

**File:** `ablation/analyzers/cmdb_surface_mapper.py`

Forward-direction CMDB attack surface mapper for x86-64 FortiWeb and FortiOS binaries.
Phase 0.5 of the Fortinet RE methodology.

---

## What it does

Enumerates every `cmf_query_create()` call site in a binary, extracts the CMDB table ID
from the `rdi` argument, then checks whether any caller of that table also calls an
exec-class sink (`system`, `popen`, `execvp`, etc.) in the same function body.

Output: a map of `table_id → CMDBTableEntry` with exec-reach flag, caller VAs, and
field-read counts.

---

## Analysis direction

The CMDB abstraction layer blocks backward taint tracing; `cmf_query_get_string()`
returns a char pointer, but the handle chain (`cmf_query_create → cmf_query_update →
cmf_query_get_string`) is opaque to TaintTracker. Tracing **forward** from `cmf_query_create`
call sites bypasses this: the table ID is concrete, the caller function is identified,
and exec-sink co-location flags the function for targeted SinkArgClassifier + TaintTracker
analysis.

---

## Known limitations

| Limitation | What it means in practice |
|---|---|
| **Co-location only** | `reaches_exec = True` means the caller body contains both a CMDB access and an exec-sink call. It does NOT mean the CMDB field value flows to the sink argument. Use SinkArgClassifier + TaintTracker to confirm. |
| **One level deep** | No interprocedural reach. If the CMDB field is passed to a helper that calls `system()`, this tool will not flag it. |
| **Immediate table IDs only** | `_extract_rdi` resolves `mov edi, <imm>` and `xor edi, edi`. Register-propagated or memory-loaded table IDs are excluded from the map. |
| **x86-64 ET_DYN/ET_EXEC only** | Validated by ELF `e_machine` check at startup. |
| **PIE VA == file offset** | The byte-indexing approach requires `text.virtual_address == text.file_offset` (true for FortiWeb/FortiOS KVM PIE binaries). Validated via lief section table at runtime. |

---

## Usage

```python
from ablation.analyzers.cmdb_surface_mapper import CMDBSurfaceMapper

# Basic
mapper = CMDBSurfaceMapper.from_path('/tmp/fwb743/rootfs_mount/lib/libcmdb_plugin.so')
surface = mapper.map()
print(CMDBSurfaceMapper.report(surface))

# With vendor-specific sinks
mapper = CMDBSurfaceMapper.from_path(
    '/tmp/fwb743/rootfs_mount/bin/cmdbsvr',
    extra_sinks={'fadcsystem', 'fadcpopen', 'sys_vdom_exec'},
    extra_tables={0x3a00: 'system_admin'},
    verbose=True,
)
surface = mapper.map()

# Exec-reach tables only: these are the triage targets for SinkArgClassifier
for tid, entry in surface.items():
    if entry.reaches_exec:
        print(f"Table {hex(tid)} ({entry.name}): {entry.exec_sink_name}() "
              f"in func {hex(entry.exec_func_va)}")

# From an existing BinaryContext (reuses built XRefGraph, no re-parse)
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
mapper = CMDBSurfaceMapper.from_context(ctx, verbose=True)
surface = mapper.map()
```

---

## Workflow position

```
Phase 0.5 (this tool)
  cmf_query_create call sites → table_id map → exec-reach flag

Phase 1 (for exec-reach tables only)
  SinkArgClassifier.from_path(binary).classify_all()
  → RODATA_CONST: eliminate
  → ARG_PROPAGATED / SNPRINTF_RODATA: advance to Phase 2

Phase 2
  TaintTracker to verify field read → sink argument data flow
  → CONFIRMED or ELIMINATED
```

---

## Output fields

`CMDBTableEntry` attributes:

| Field | Type | Description |
|---|---|---|
| `name` | str | Table name from `_CONFIRMED_TABLES` or `table_0x<hex>` |
| `callers` | List[int] | Function VAs that call `cmf_query_create(table_id)` |
| `field_read_count` | int | Count of CMDB accessor calls co-located in caller functions |
| `reaches_exec` | bool | Any caller co-locates an exec-sink call (co-location, not data flow) |
| `exec_func_va` | Optional[int] | VA of the function with the co-located exec call |
| `exec_call_va` | Optional[int] | VA of the exec sink call instruction |
| `exec_sink_name` | Optional[str] | Name of the exec sink (`system`, `popen`, etc.) |

---

## Known table IDs

Confirmed entries in `_CONFIRMED_TABLES` (update from binary analysis, not guesswork):

| ID | Name | Source |
|---|---|---|
| `0x427c` | `automation_action_DefaultScript` | cmdbsvr FortiWeb 7.4.3 |
| `0x4290` | `automation_action_Script` | cmdbsvr FortiWeb 7.4.3 |
| `0x6000` | `auth_saml` | libcmdb_plugin.so FortiWeb 7.4.3 |
| `0x226` | `automation_action_exec` | cmdbsvr FortiWeb 7.4.3 |

To add a new confirmed entry, verify the table ID via `cmf_query_create(0xXXXX)` in
disassembly, then add to `_CONFIRMED_TABLES` with a source annotation.

---

## CLI

```
python3 -m ablation.analyzers.cmdb_surface_mapper /path/to/binary [--json] [--verbose]
```

`--json` emits the full surface as a machine-readable JSON object (keys are hex table IDs).

---

## FortiWeb RE history

First used in the FortiWeb 7.4.3 engagement (2026-10-04, session 3) to discover
**FWB-KRB-1** (CVSS 7.2 HIGH): libcmdb_plugin.so Kerberos realm name injected into
`system()` without sanitization. The backward-trace methodology (TaintTracker from
`system()`) missed this because the CMDB abstraction layer blocked the trace. Forward
mapping from `cmf_query_create` in libcmdb_plugin.so identified the exec-reach table
immediately, and manual disassembly of the caller confirmed the unsanitized field.

---

## Why this exists

Prior to this module, cmdb surface mapper required manual work outside the Ablation pipeline. This module integrates the capability directly so findings feed the shared `PatternLibrary` and `FindingRegistry` without a separate toolchain.

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Example output

```
[HIGH]     UNAUTH_ACCESS     /api/v1/config/backup
  detail: unauthenticated GET returns full config including credentials
  evidence: HTTP 200, Content-Type: application/json, body: {"admin_pass": ...}

[MEDIUM]   INFO_DISCLOSURE   /status
  detail: version string exposed without authentication
  evidence: X-Version: FortiOS 7.2.1 build 1254
```

---

## False positives

Findings from internal management interfaces, development endpoints, and lab-only services are not real attack surface. Filter by comparing discovered endpoints against the product's documented management plane. Authentication-required findings are lower severity unless a pre-auth bypass is confirmed separately.

---

## Pipeline position

**Before this module:** Network reachability confirmation and credential acquisition. `BinaryContext` is not required; this module works from a live target or captured traffic.

**After this module:** Feed findings to `FindingRegistry.register()` and review with `LLMAnalyst` for chaining opportunities.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `finding_type` | Category (e.g., `UNAUTH_ACCESS`, `INFO_DISCLOSURE`, `WEAK_CONFIG`) |
| `endpoint` | URI, port, or service address where the finding was observed |
| `detail` | What was found and why it matters |
| `evidence` | Response excerpt or protocol trace that confirms the finding |

---

## See also

- [FindingRegistry](registry.md) — record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md) — chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md) — port and service fingerprinting
