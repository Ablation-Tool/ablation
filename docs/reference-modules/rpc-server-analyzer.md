# RPC Server Analyzer

**File:** `ablation/analyzers/rpc_server_analyzer.py`

Enumerates Windows RPC server interfaces and flags those registered with `RPC_C_AUTHN_LEVEL_NONE` so any network caller reaches the interface without credentials. Pairs with Windows PE Security Analysis for complete RPC attack surface coverage.

Works on x86 and x64 PE binaries without a running server, no Ghidra required.

---

## Why this exists

Three things were not possible before this module:

1. **RPC interface UUID extraction required Ghidra.** Windows RPC servers register interfaces by passing an `RPC_SERVER_INTERFACE*` to `RpcServerRegisterIf*`. The struct contains the interface UUID and transfer syntax UUID. Ablation had no automated path from the call site to those values without Ghidra's RPC parser or manual struct reading.

2. **Authentication level analysis was a manual trace.** `RpcServerRegisterIfEx` takes an auth level argument. `RPC_C_AUTHN_LEVEL_NONE` (value 1) means any network caller can invoke the interface with no credentials, a direct lateral movement path. Confirming whether a binary registered an unauthenticated interface required tracing the argument at each call site by hand.

3. **Endpoint strings had no systematic extraction.** `RpcServerUseProtseqEp*` binds the server to a named pipe, TCP port, or ALPC port. That string is the network address of the attack surface. Before this module, enumerating those strings required manual cross-referencing of string search results to verify they reached an endpoint registration function.

---

## Detection algorithm

For each PE binary:

1. Builds an IAT map for: `RpcServerRegisterIf`, `RpcServerRegisterIfEx`, `RpcServerRegisterIfEx2`, `RpcServerRegisterIf2`, `RpcServerRegisterIf3`, `RpcServerUseProtseqEpA`, `RpcServerUseProtseqEpW`.
2. Scans all code sections with Capstone for call sites targeting those IAT entries.
3. At each `RpcServerRegisterIf*` call site, extracts the first argument (`RPC_SERVER_INTERFACE*`) and reads the interface UUID and transfer syntax UUID from the struct at that address.
4. At each `RpcServerRegisterIfEx` call site, extracts the second argument (auth level).
5. At each `RpcServerUseProtseqEp*` call site, extracts the endpoint string as UTF-16LE or ASCII.
6. Reports any interface registered with auth level `RPC_C_AUTHN_LEVEL_NONE` as HIGH (CWE-306).

---

## Usage

```python
from ablation.analyzers.rpc_server_analyzer import RPCServerAnalyzer

ana = RPCServerAnalyzer.from_path('rpcss.dll')
findings = ana.scan()
print(RPCServerAnalyzer.report(findings))

# Per-interface detail
for iface in ana.interfaces():
    print(f"{iface.uuid}  auth={iface.auth_level_name}  unauthenticated={iface.unauthenticated}")

# Endpoint strings (attack surface binding)
print("Endpoints:", ana.endpoint_strings())

# High-severity findings only
highs = [f for f in findings if f.severity == 'HIGH']
for f in highs:
    print(f"[HIGH] {f.uuid}  endpoint={f.endpoint}")
```

---

## Findings

| Severity | Category | Trigger |
|---|---|---|
| `HIGH` | `unauthenticated_rpc` | Interface registered with `RPC_C_AUTHN_LEVEL_NONE` (CWE-306) |
| `INFO` | `rpc_interface` | Interface registered with a non-zero auth level |
| `INFO` | `endpoint_inventory` | Endpoint string extracted from `RpcServerUseProtseqEp*` |
| `INFO` | `no_rpc` | Binary imports no RPC server registration functions |

---

## Authentication level reference

| Level | Value | Meaning |
|---|---|---|
| `RPC_C_AUTHN_LEVEL_NONE` | 1 | No authentication: any network caller accepted |
| `RPC_C_AUTHN_LEVEL_CONNECT` | 2 | Authentication on connect only |
| `RPC_C_AUTHN_LEVEL_CALL` | 3 | Authentication on each call |
| `RPC_C_AUTHN_LEVEL_PKT` | 4 | Authentication with packet integrity |
| `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` | 5 | Authentication with integrity check per packet |
| `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` | 6 | Authentication with per-packet encryption |

When `RpcServerRegisterIf` (not `IfEx`) is called, no auth level argument is passed. The server's process-wide default applies. The module reports this case as `auth_level = -1`.

---

## Interface fields (`RpcInterface`)

| Field | Description |
|---|---|
| `uuid` | Interface UUID string (e.g. `6bffd098-a112-3610-9833-46c3f87e345a`) |
| `version_major` | Interface version major |
| `version_minor` | Interface version minor |
| `transfer_syntax` | Transfer syntax UUID |
| `auth_level` | Integer auth level (1–6), or -1 if `RpcServerRegisterIf` was used |
| `auth_level_name` | Human-readable auth level name |
| `unauthenticated` | `True` if `auth_level == RPC_C_AUTHN_LEVEL_NONE` |
| `endpoint` | Endpoint string if extracted from a `RpcServerUseProtseqEp*` call near this registration |

---

## Dependencies

- `lief >= 0.14.0`: PE parsing, IAT map, section headers
- `capstone >= 5.0`: call site scanning and argument extraction
