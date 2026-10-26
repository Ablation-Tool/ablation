# CGISurfaceMapper

Walk CGI directories in a firmware rootfs, classify every handler as shell or ELF, run ShellSinkClassifier on all shell scripts in one batch, and return a prioritized attack-surface table sorted by worst-case exec-sink verdict.

---

## Why this exists

1. **CGI enumeration was manual.** IoT firmware ships 50–200 CGI handlers as the primary HTTP attack surface. Manually listing, classifying, and triaging each took hours. This module does the full sweep in one call: `CGISurfaceMapper.from_rootfs(path).map()`.

2. **ShellSinkClassifier needed a caller that scopes it to the right files.** Running ShellSinkClassifier across `/usr/bin` on a full rootfs would include every shell utility, not just CGI handlers. This module narrows the input to known CGI directory paths, then batches all shell scripts into a single ShellSinkClassifier call.

3. **ELF handlers need queueing for binary RE.** CGI handlers that are ELF binaries such as `camctrl.cgi` are not analyzable by ShellSinkClassifier. This module surfaces them separately so the caller can immediately run `BinaryContext.load_or_build()` + `SinkArgClassifier` on them.

---

## How it works

```
from_rootfs(path, cgi_dirs=None)
  Instantiate with rootfs Path.
  cgi_dirs: override the default search paths (see _CGI_PATHS).

map() → CGISurface
  1. _find_cgi_dirs(): walk _CGI_PATHS list under rootfs, collect dirs that exist
  2. For each file in each dir:
       _classify_handler(): read first 16 bytes
         ELF magic \x7fELF → handler_type='elf', max_verdict='elf'
         Shebang #!/bin/sh|#!/bin/ba|#!/usr/bin or .sh/.cgi suffix → 'shell'
         Symlink → 'symlink'
         Other → None (skipped)
       _infer_auth(): check if any path part matches _AUTH_DIRS → 'admin' | 'user' | 'unknown'
  3. Collect shell handler paths, construct ShellSinkClassifier(paths), call classify()
  4. Index sinks by script path, attach to handlers, compute max_verdict via _worst_verdict()
  5. Sort all handlers by priority (ARG_PROPAGATED=0 ... empty=5)
  6. Return CGISurface(rootfs, cgi_dirs, handlers)

report(surface) → str
  Header summary (counts), then one line per handler with verdict/auth/size/path.
  For ARG_PROPAGATED and EVAL_SINK handlers: show up to 3 sink detail lines.
```

Default `_CGI_PATHS` searched: `usr/share/www/cgi-bin`, `var/www/cgi-bin`, `www/cgi-bin`, `opt/www/cgi-bin`, `web/cgi-bin`, `htdocs/cgi-bin`, `srv/www/cgi-bin`, `home/www/cgi-bin`, `usr/local/www/cgi-bin`, `usr/bin`.

---

## CGISurfaceMapper

```python
from ablation.analyzers.cgi_surface_mapper import CGISurfaceMapper

mapper = CGISurfaceMapper.from_rootfs('/media/cowboy/research/VIVOTEK/FD8369A/rootfs_mount')
surface = mapper.map()
print(CGISurfaceMapper.report(surface))

# Filter to only risky handlers (ARG_PROPAGATED / EVAL_SINK / UNKNOWN)
for h in surface.risky:
    print(f"{h.max_verdict:<18} {h.rel_path}")

# Queue ELF handlers for binary RE
elf_paths = [h.abs_path for h in surface.elf_handlers]
```

---

## CGIHandler fields

| Field | Content |
|:---|:---|
| `rel_path` | Path relative to rootfs root |
| `abs_path` | Absolute path |
| `handler_type` | `shell` / `elf` / `symlink` / `unknown` |
| `size` | File size in bytes |
| `auth_hint` | `admin` / `user` / `unknown` (from directory name) |
| `max_verdict` | Worst ShellSinkClassifier verdict across all sinks |
| `sink_count` | Number of exec sinks found (shell only) |
| `sinks` | Full `List[ShellSinkResult]` |

### Verdict priority order

| Verdict | Priority | Meaning |
|:---|:---|:---|
| `ARG_PROPAGATED` | 0 | Attacker-controlled value in command position |
| `EVAL_SINK` | 1 | eval with any argument. Always requires manual review. |
| `UNKNOWN` | 2 | Unresolved provenance. Conservative. Treat as risky. |
| `RODATA_CONST` | 3 | Only internal literal values reach the sink |
| `[elf]` | 4 | ELF handler. Needs BinaryContext + SinkArgClassifier. |
| `RODATA_CONST` (no sinks) | 3 | No exec sinks found |

---

## Usage

```python
# Full surface map
mapper = CGISurfaceMapper.from_rootfs('/media/fw/rootfs_mount')
surface = mapper.map()
print(CGISurfaceMapper.report(surface))

# Just the risky handlers
for h in surface.risky:
    for s in h.sinks:
        if s.verdict == 'ARG_PROPAGATED':
            print(f"  L{s.line_num}: {s.line.strip()}")

# Custom CGI dirs (e.g. vendor uses /opt/webserver/cgi/)
mapper = CGISurfaceMapper.from_rootfs(
    '/media/fw/rootfs_mount',
    cgi_dirs=['/media/fw/rootfs_mount/opt/webserver/cgi'],
)
surface = mapper.map()
```

---

## Example output

```
CGISurfaceMapper: /media/fw/rootfs_mount
  CGI dirs found  : 2
  Total handlers  : 74
  Shell handlers  : 61
  ELF handlers    : 8
  Risky (AP/EVAL/UNK): 6

VERDICT            AUTH        SIZE  PATH
--------------------------------------------------------------------------------
ARG_PROPAGATED     unknown   63,234B  usr/bin/upload_vadp
    L554    VAR_CMD    [NEW_PACK=EXTERNAL, NEW_INIT_SCR=EXTERNAL]
      /tmp/pkg/${NEW_INIT_SCR} chkver /tmp/pkg
ARG_PROPAGATED     unknown   12,891B  usr/bin/upload_ttf
    L88     VAR_CMD    [$1=EXTERNAL]
      decode.sh "$1" /tmp/ttf_tmp
EVAL_SINK          admin      9,881B  usr/share/www/cgi-bin/admin/audioclip.cgi
    L88     EVAL       [i=UNKNOWN, $@/$*/$N=EXTERNAL]
      eval "$2=\"$i\""
[elf]              unknown   137,000B  usr/share/www/cgi-bin/admin/httpd
RODATA_CONST       unknown      211B  usr/share/www/cgi-bin/identify.cgi
```

---

## False positives

**`auth_hint='admin'` on non-auth paths:** The auth inference checks whether any directory component matches `{'admin', 'auth', 'secure', 'protected', 'private'}`. A path like `/usr/admin_tools/handler.sh` would match `admin` even if it isn't an auth-protected CGI handler. Treat `auth_hint` as a hint, not a guarantee.

**Shell handlers with UNKNOWN verdict:** These are handlers where a variable in command position has no assignment anywhere in the script. The variable was set by an external caller or config. UNKNOWN is conservative. Most are RODATA_CONST in practice. Read the script to confirm.

---

## Pipeline position

**Before this module:** `IoTFirmwareUnpacker.unpack()` to get a rootfs path, then pass `result.rootfs_path` here.

**After this module:** `BinaryContext.load_or_build()` on ELF handlers from `surface.elf_handlers`. Manual review of ARG_PROPAGATED sinks. PathSolver on UNKNOWN sinks.

---

## FORGE findings

| ID | Severity | Finding |
|:---|:---|:---|
| CSM-F1 | LOW | No ceiling on file count scanned per rootfs walk |
| CSM-F2 | LOW | `_infer_auth` matches any ancestor path component, not just immediate parent |

---

## See also

- [ShellSinkClassifier](shell-sink-classifier.md): the underlying engine for shell handler analysis
- [IoTFirmwareUnpacker](iot-firmware-unpacker.md): extracts the rootfs that this module consumes
