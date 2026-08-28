# Apple / macOS Module Reference

Swift binary RE, Mach-O format analysis, malware persistence, sysadmin attack surface, and Orka cluster enumeration.

---

## `swift_re` — Swift binary RE

Reads `__swift5_types`, `__swift5_proto`, `__swift5_reflstr` Mach-O sections directly — no `swift-demangle` in PATH required.

- **gRPC** — extracts service names, methods, request/response types, streaming flags from the protobuf descriptor pool in `__DATA`
- **SwiftNIO / Vapor** — finds TCP/HTTP server setup call sites, maps full URL → handler table
- **async/await** — detects `swift_async_let_start`, `swift_task_create`, actor hops (`_swift_task_switch`), continuation resume points; maps functions that cross trust boundaries
- **LicenseSpring** — locates license validation call sites in commercial macOS binaries

---

## `macos_malware_re` — macOS malware and persistence

- **Persistence** — LaunchAgents, LaunchDaemons, Login Items, cron, periodic scripts, shell profile injection, DYLD_INSERT_LIBRARIES, kernel extensions / System Extensions
- **TCC** — reads `TCC.db` directly; maps FDA, camera, mic, screen-recording grants; flags UTType handler / AppleScript / Accessibility bypass indicators
- **EvilQuest / ThiefQuest** — known PList names, ransomware extension list, C2 beacon patterns, `sysctl hw.model` VM-detection bypass
- **dyld hijack** — finds writable `@rpath` entries in LC_RPATH load commands (writable rpath = dylib injection without SIP bypass)
- **Keychain** — enumerates items by service/account label, flags `kSecAttrAccessibleAlways`; scans `/Users/admin/orka/`, `/opt/orka/`, `/etc/orka/` for credential files

---

## `macos_sysadmin` — macOS administrative attack surface

- **Keychain** — generic passwords, internet passwords, certificates, keys; maps any-app ACLs vs per-app ACLs
- **FileVault** — FDE status, recovery key exposure, Institutional Recovery Key presence
- **Open Directory** — local user enumeration via LDAP to `127.0.0.1`, admin group members, shadow hash presence in `/var/db/dslocal/`
- **MDM / DEP** — enrolled MDM server URL, DEP indicator; enrolled devices accept arbitrary MDM commands from the enrolled server
- **ARD / VNC** — service status, VNC password plist location, screen-sharing enabled users
- **Sudoers / PAM** — NOPASSWD rules, PAM module stack, auth bypass indicators
- **Orka** — launchd services, agent socket paths, control plane tokens stored in macOS Keychain

---

## Orka Cluster RE

### `orka_enum` — Live cluster enumeration

Validates tokens, lists VMs, extracts VM configuration (CPU, RAM, image, node), maps image registry contents, tests default credentials. Feeds `orka_oidc_re` and `orka_jwt_dynamic_re` with token material.

### `orka_oidc_re` — Orka OIDC / PKCE flow RE + CVE-2020-26160

Reconstructs the OIDC auth flow from Go binary symbols: `fetchClusterInfo`, PKCE code challenge, token exchange, JWT extraction. Maps internal host range (`10.221.188.x`) from cluster-info.

- **CVE-2020-26160** — `dgrijalva/jwt-go` v3.2.0 accepted an empty HMAC key; Orka's HS256 validation was affected
- **`aud` bypass** — tokens without a required audience claim accepted when the parser's expected audience list was empty

```python
from modules.orka_oidc_re import OrkaOIDCAnalyzer
flow = OrkaOIDCAnalyzer('https://orka-api:443').extract_auth_flow()
```

### `orka_jwt_dynamic_re` — Orka HS256 empty-key forge

Replicates Go's `SigningMethodHMAC.Verify` with `b''` as the key. Forges a token with any `sub` and `role` claim.

```python
from modules.orka_jwt_dynamic_re import OrkaJWTForger
forged = OrkaJWTForger().forge(
    captured_token='eyJ...',
    target_sub='admin',
    target_role='orka-admin'
)
```

### `orka_api_surface_re` — Orka REST API reconstruction from binary

Scans Go binary components for URL path strings and HTTP method references. Outputs 60+ sorted routes across VM, image, ISO, service account, registry credential, node, and image cache operations — with observed authentication requirements per endpoint.

### `orka_vm_exec_re` — Orka VM exec path

VM name == pod name (confirmed from `getExecRequestURL` disassembly — no transformation). Traces the exec path to `/api/v1/namespaces/orka-default/pods/<vm>/exec?container=orka-vm` via SPDY executor. With `pods/exec` permission and a forged SA token: arbitrary command execution in any running Orka VM.

---

## Binary Parsers (macOS)

### `core/macho_analyzer` — Mach-O binary parser

Universal fat binaries, single-arch 32/64. Extracts: all LC_ load commands, section/segment layout, import table, export trie, code signature (entitlements, team ID), ObjC runtime metadata. Flags hardened-runtime bypass entitlements: `com.apple.security.cs.allow-unsigned-executable-memory`, `com.apple.private.security.clear-library-validation`.

### `core/bv41_decoder` — Apple BV41 / Compression.framework LZ4 decoder

Pure Python, no native dependencies. Decodes Apple's BV41 chunked LZ4 format from `dyld_shared_cache` slices, APFS snapshots, and Orka VM image layers in Harbor.

### `core/swift_demangle` — Swift ABI name demangler

Handles `$s` prefix (Swift 5+ mangling): module qualifiers, generic specializations, protocol conformances, operator names, property accessors. Falls back to the `swift-demangle` binary if present.
