# RPCServerAnalyzer

## Why this exists

3 things that weren't possible before in Ablation:

1. **No RPC interface UUID extraction.** Windows RPC servers register interfaces with `RpcServerRegisterIf*`. The first argument is a pointer to `RPC_SERVER_INTERFACE`, which contains the interface UUID and transfer syntax. Before this module, finding out what RPC interfaces a binary exposes required Ghidra's RPC parser or manual struct reading. Ablation had no automated path from `RpcServerRegisterIf` call site to interface UUID.

2. **No authentication level analysis.** `RpcServerRegisterIfEx` takes an auth level argument. `RPC_C_AUTHN_LEVEL_NONE` (1) means any network caller can invoke methods with no credentials. This is a direct lateral movement path. Before this module, confirming whether a given binary registered unauthenticated RPC required manual trace through the `RpcServerRegisterIfEx` argument list.

3. **No endpoint string extraction.** `RpcServerUseProtseqEp*` binds the server to a specific named pipe, TCP port, or ALPC port. That string is the network address of the attack surface. Before this module, enumerating those strings required string search plus manual cross-referencing to verify they were actually passed to an endpoint registration function.

---

## What it does

`RPCServerAnalyzer` works on x86 and x64 PE binaries. It:

1. Builds an IAT map for `RpcServerRegisterIf`, `RpcServerRegisterIfEx`, `RpcServerRegisterIfEx2`, `RpcServerRegisterIf2`, `RpcServerRegisterIf3`, `RpcServerUseProtseqEpA/W`.
2. Scans code sections for register call sites with Capstone.
3. For each `RpcServerRegisterIf*` call site, extracts the first argument (the `RPC_SERVER_INTERFACE*`), reads the struct at that address to get the interface UUID and transfer syntax UUID.
4. For `RpcServerRegisterIfEx` calls, extracts the second argument (auth level).
5. For `RpcServerUseProtseqEp*` calls, extracts the second argument (endpoint string), reads it as UTF-16LE or ASCII.
6. Reports any interface registered with auth level NONE as HIGH.

---

## Usage

```python
from ablation.analyzers.rpc_server_analyzer import RPCServerAnalyzer

ana = RPCServerAnalyzer.from_path('rpcss.dll')
findings = ana.scan()
print(RPCServerAnalyzer.report(findings))

for iface in ana.interfaces():
    print(f"{iface.uuid}  auth={iface.auth_level_name}  unauthenticated={iface.unauthenticated}")

print("Endpoints:", ana.endpoint_strings())
```

---

## Findings

| Severity | Category | Trigger |
|---|---|---|
| HIGH | `unauthenticated_rpc` | Interface registered with `RPC_C_AUTHN_LEVEL_NONE` (CWE-306) |
| INFO | `rpc_interface` | Interface registered with non-zero auth level |
| INFO | `endpoint_inventory` | Endpoint strings extracted from `RpcServerUseProtseqEp*` |
| INFO | `no_rpc` | No RPC server imports |

---

## Authentication level reference

| Level | Value | Meaning |
|---|---|---|
| `RPC_C_AUTHN_LEVEL_NONE` | 1 | No authentication: any caller accepted |
| `RPC_C_AUTHN_LEVEL_CONNECT` | 2 | Auth on connect only |
| `RPC_C_AUTHN_LEVEL_CALL` | 3 | Auth on each call |
| `RPC_C_AUTHN_LEVEL_PKT` | 4 | Auth + packet integrity |
| `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` | 5 | Auth + integrity check |
| `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` | 6 | Auth + encryption |

When `RpcServerRegisterIf` (not `IfEx`) is used, no auth level is passed. The server's default applies. The module reports this case as `auth_level = -1` with a descriptive message.

---

## Dependencies

- `lief >= 0.14.0` (PE parsing, IAT, section headers)
- `capstone >= 5.0` (call site scanning, argument extraction)
