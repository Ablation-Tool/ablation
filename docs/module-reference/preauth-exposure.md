# Pre-Authentication Exposure

Traverses the control flow graph from the network entry point and identifies every code path that reaches a security-sensitive operation before an authentication gate. Produces a reachability map so manual review starts at the authentication boundary, not before it.

---

## Why this exists

One thing blocked pre-auth surface mapping before `PreAuthRouteAuditor`:

**Manual route table reading was the only option.**
Web framework route tables in compiled firmware binaries are initialized at runtime through registration calls such as `route_url_register(path, handler_class)`. Finding which routes skip authentication required reading the route init function manually, identifying the registration call pattern, extracting handler class names, and then tracing those handlers to see whether they gate on session validation. For a binary with 400 routes that takes days. `PreAuthRouteAuditor` does it in a single function call.

---

## How it works

The auditor targets flatui-style web frameworks (FortiManager, FortiAnalyzer web management backends) but the control flow graph traversal approach applies to any route-registration framework where the authentication check is expressed as a middleware parameter at registration time.

### Full pipeline

```mermaid
flowchart TD
    A[/"firmware binary (e.g., libservice.so)"/] --> B["Step 1 · Route init function scan\nCapstone disassembly from route_init_va to route_init_end_va\nFor each call instruction in range:\n  Extract registration args:\n    arg[0] = HTTP path string\n    arg[1] = HTTP method (GET/POST/PUT/DELETE)\n    arg[2] = handler class name\n    arg[3] = middleware list"]

    B --> C{"arg[3] includes\nWorkflowLockWithoutSessionPermit?"}
    C -->|Yes| D["Route is authenticated\nSkip — not attack surface"]
    C -->|No| E["Route is pre-auth candidate"]

    E --> F["Step 2 · Handler factory resolution\nfactory_va points to vtable dispatch table\nGET_REGISTER and POST_REGISTER calls\nassign handler VAs per HTTP method\nExtract GET handler VA and POST handler VA"]

    F --> G["Step 3 · FuncProfiler on each handler\nCapstone disassembly of handler body\nCollect all PLT call targets reachable\nCheck each against sink table:\n  exec sinks: system / popen / execve\n  memory sinks: strcpy / sprintf / memcpy\n  I/O sinks: write / send / sendto"]

    G --> H[/"PreAuthResult\nroute_path · method · handler_va\nsink_calls · pre_auth=True"/]

    style A fill:#1e293b,stroke:#475569,color:#e2e8f0
    style H fill:#7f1d1d,stroke:#991b1b,color:#fecaca
```

### What "pre-auth" means in this framework

```mermaid
flowchart TD
    A["HTTP request arrives at port 443"] --> B["TLS termination (nginx / stunnel)"]
    B --> C["Route match: path = 'api/v2/monitor/system/status'"]
    C --> D{"Middleware list\nevaluation"}

    D -->|"WorkflowLockWithoutSessionPermit\nNOT in list"| E[/"Request handler runs directly\nPre-auth route — attack surface"/]
    D -->|"Session validation middleware\nin list"| F{"Session cookie\nvalid?"}

    F -->|Yes| G["Handler runs"]
    F -->|No| H["401 response"]

    style E fill:#7f1d1d,stroke:#991b1b,color:#fecaca
```

Flatui-style frameworks encode the middleware list as a bitfield or a set of string constants passed to the registration call. The auditor reads that argument at the call site and checks whether the session validation constant is present. A missing constant means the handler is reachable without authentication.

---

## Usage

VA constants must be updated per firmware version. Read the route init function VA from the binary before calling:

```python
from ablation.analyzers.preauth_route_auditor import PreAuthRouteAuditor

auditor = PreAuthRouteAuditor.from_path('/path/to/libservice.so')
results = auditor.run(
    route_init_va=0x27b324,
    route_init_end_va=0x288d50,
    factory_va=0x2a5000,
    factory_end_va=0x2b0000,
)
print(results.fmt())
```

Each result in `results.routes` has:

| Field | Content |
|---|---|
| `path` | HTTP path string (e.g., `api/v2/monitor/system/status`) |
| `method` | `GET` / `POST` / `PUT` / `DELETE` |
| `handler_va` | VA of the handler function |
| `sink_calls` | List of dangerous PLT calls reachable from the handler |
| `pre_auth` | `True` if no session validation middleware is present |

---

## PocGenerator

Once pre-auth routes are confirmed, `PocGenerator` produces minimal curl commands that reproduce each finding at the protocol level.

```python
from ablation.analyzers.poc_generator import PocGenerator

poc = PocGenerator.generate_all(results.pre_auth_routes())
for item in poc:
    print(item.curl_command)
    print(f"  Expected response delta: {item.expected_delta}")
    print(f"  CWE: {item.cwe}")
```

Each PoC includes:

- Minimal curl command with the auth bypass path
- Expected response difference between authenticated and unauthenticated calls (confirms the bypass without guessing)
- CWE classification for the PSIRT submission
- Severity scoring based on the sinks reachable from the handler

The PoC output is paste-ready for a disclosure report. The curl command reproduces the bypass and the expected delta documents why the response confirms pre-auth access rather than just a 401 with a different body.
