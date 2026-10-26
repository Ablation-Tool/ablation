# Go Subprocess Surface

Enumerate `os/exec.Command` and `exec.Cmd.Start/Run` call sites in stripped Go binaries: classifying each site by command path type `relative`, `path`, `absolute`, `dynamic` to identify PATH injection and CWD injection attack surfaces.

---

## Why this exists

1. **Go appliance agents FortiClient, cloud agents, IoT gateways frequently invoke system commands via `os/exec.Command()`: without path type classification, the full subprocess attack surface is invisible in a stripped binary.** `GoSubprocessScanner` uses the pclntab function table to enumerate all exec-family call sites, resolves command path strings using `GoStringResolver`, and classifies each site. PATH-type sites `ping`, `route`, `curl` are exploitable via `$PATH` injection without any additional code-execution primitives.

2. **The `path` type is the highest-risk finding: a bare command name like `ping` is resolved via `$PATH` at runtime.** If the attacker controls `$PATH` through a prior privilege escalation, environment injection, or a web interface that sets process environment, they can replace `ping` with an arbitrary executable. `GoSubprocessScanner` surfaces every `path`-type site with the command name, providing the exact strings needed to verify PATH hijackability in a target deployment.

3. ARM64 Go binaries are partially supported: `BL imm` call detection works, but `GoStringResolver`'s `lea rax/mov ebx` pattern is x86-64 specific. ARM64 ADRP+ADD string loading is a known gap; all ARM64 subprocess sites are classified as `DYNAMIC/MEDIUM` until the resolver is extended.

---

## How it works

See [Go String Recovery](go-string-recovery.md) for the full implementation. `GoSubprocessScanner` is the high-level workflow that combines pclntab function enumeration, PLT resolution for exec symbols, `GoStringResolver` string recovery, and path type classification into a single `scan()` call.

### Path type classification

| Type | Pattern | Severity | Risk |
|:---|:---|:---|:---|
| `relative` | `./cmd` or `../cmd` | HIGH | CWD injection if attacker controls CWD |
| `path` | bare `cmd` no slash | HIGH | PATH injection via `$PATH` manipulation |
| `absolute` | `/usr/bin/cmd` | LOW | Not directly injectable via environment |
| `dynamic` | not statically resolvable | MEDIUM | Requires dynamic analysis to classify |

---

## Usage

```python
from ablation.analyzers.go_subprocess_scanner import GoSubprocessScanner

# Load pclntab (from LIEF or ELF section parsing)
import lief
binary = lief.parse('/path/to/go_binary')
pclntab_section = binary.get_section('gopclntab')
pclntab = bytes(pclntab_section.content)

scanner = GoSubprocessScanner('/path/to/go_binary', pclntab=pclntab)
sites = scanner.scan()

# Print all PATH-injection candidates
for site in sites:
    if site.path_type == 'path':
        print(f"  {site.call_va:#x}  cmd='{site.cmd_str}'  [PATH injection]")

# Full results
for site in sites:
    print(f"  {site.call_va:#x}  {site.path_type.upper():10s}  {site.cmd_str!r}")
    print(site.as_dict())
```

---

## Example output

The following illustrates the output format. Actual commands and addresses are binary-specific.

```
GoSubprocessScanner: <N> subprocess sites found

PATH injection candidates (<M> sites):
  <call-va>  PATH     cmd='ping'
  <call-va>  PATH     cmd='iptables'
  <call-va>  PATH     cmd='curl'

Other sites:
  <call-va>  ABSOLUTE  cmd='/usr/bin/sh'
  <call-va>  DYNAMIC   cmd=<unresolved>  [arm64: string resolution gap]
```

---

## False positives

**All ARM64 sites are reported as `DYNAMIC/MEDIUM`, not because they are safe, but because the ARM64 string resolver is not implemented.** On ARM64 Go binaries, manually inspect `DYNAMIC` sites with `BinaryLifter` (`arch='arm64'`) or disassembly to determine the actual command string and path type.

---

## Pipeline position

Run after stripping and mounting the firmware filesystem. `GoSubprocessScanner` takes seconds on most Go appliance agents and produces an immediately actionable list of PATH injection candidates. For `path`-type findings, verify whether the agent's process environment can be influenced by an attacker: check web UI environment injection, SSRF-to-RCE chains, or configuration file injections.

---

## Reading findings

`GoSubprocessScanner.scan()` returns a list of finding dicts:

| Field | Content |
|:---|:---|
| `severity` | `HIGH` PATH injection / `MEDIUM` DYNAMIC unresolved / `INFO` ABSOLUTE path |
| `call_va` | VA of the `exec.Command()` or `os.Exec()` call site |
| `cmd_type` | `PATH` no slash: PATH injection, `ABSOLUTE` hardcoded path, or `DYNAMIC` unresolved at analysis time |
| `cmd` | Resolved command string for example `ping`, `/usr/bin/sh` or `<unresolved>` |
| `detail` | Exploitation context for PATH findings |

---

## See also

- [Go String Recovery](go-string-recovery.md): full `GoStringResolver` API reference
- [Injection and Persistence Indicators](injection-and-persistence-indicators.md): broader injection surface including non-Go binaries
- [Fork/Exec Classification](fork-exec-classification.md): similar classification for `fork()`+`exec()` patterns in C binaries
