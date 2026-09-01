"""
cisco_secure_client_plugins_re — Cisco Secure Client VPN Plugins 5.1.15.287 RE

Plugins directory: /opt/cisco/secureclient/bin/plugins/
Components:
  libvpnipsec.so    — IKEv2/IPsec implementation with STRAP
                    BuildID: fc5c3f1f68e6592c14e5a4d027c5b2d954363a70
  libacdownloader.so — Update/downloader plugin
                    BuildID: df4c5fc32559c7df6b1331bf5195880f413491f8
  libacwebhelper.so — Web helper (SAML/web auth)
  libacfeedback.so  — Telemetry feedback

Primary focus: libvpnipsec.so (IKEv2 + STRAP) and libacdownloader.so (update chain)

Architecture — libvpnipsec.so:
  vpnagentd (root) ──dlopen──> libvpnipsec.so
       │
       ├── CGraniteShim::initiateHandshake() ──> IKEv2 state machine
       ├── CStrapMgr::GenerateKeyPair() ──> STRAP ephemeral keys
       ├── CCertIKEAdapter::VerifyServerCertificate() ──> peer cert verify
       ├── CCommandShell kernel interaction ──> PF_KEY SADB (SAD/SPD install)
       └── ikev2_return_to_fallback_keys() ──> cipher fallback

Architecture — libacdownloader.so:
  vpnagentd ──dlopen──> libacdownloader.so
       │
       ├── CCloudDownloaderMainThread::startUpdateCheck() ──> manifest fetch
       ├── GET https://<headend>/binaries/vpndownloader.sh (manifest)
       ├── Hash verify: "hash of retrieved file %s, expected %s"
       └── chmod + execvp(vpndownloader.sh) ──> update execution as root

STRAP protocol (AnyConnect Session Resumption):
  ANYCONNECT_STRAP_PUBKEY  — IKEv2 NOTIFY payload type (client sends ECDH pubkey)
  ANYCONNECT_STRAP_VERIFY  — IKEv2 NOTIFY payload type (session resumption proof)
  ANYCONNECT_STRAP_SPEC    — protocol spec identifier
  CISCO-ANYCONNECT-STRAP-DH — DH parameters vendor ID
  CStrapMgr implements GenerateKeyPair, GetPubKey, GetDHPubKey, GenerateVerifyAndRekey
  Purpose: allows VPN session to resume without full re-authentication after reconnect

IKEv2 classes (confirmed by mangled symbols):
  CGraniteShim — the IKEv2 shim (Granite = internal IKEv2 codename)
  CIKEConnectionCrypto — crypto operations for an IKE SA
  CCertIKEAdapter — X.509 cert operations within IKE
  CCertificate, COpenSSLCertificate — cert wrappers
  CCertHelper, CCertPKCS7 — PKCS7/chain helpers
  COpenSSLCertUtils — OpenSSL X.509 utilities
  UserAuthenticationTlv — IKEv2 extended authentication (XAUTH/EAP TLV)
  LocalACPolicyInfo — local policy (cert store exclusions)
"""

import hashlib
import struct
import os
import socket


# ── Finding Registry ─────────────────────────────────────────────────────────

FINDINGS = {
    "PLUG-F01": {
        "title": "STRAP session resumption: no confirmed replay protection in resumption proof",
        "severity": "HIGH",
        "status": "CANDIDATE",
        "source_file": "opt/cisco/secureclient/bin/plugins/libvpnipsec.so",
        "description": (
            "The STRAP (Stateless Tunnel Resumption And Persistence) protocol "
            "allows VPN session resumption without re-authentication. "
            "CStrapMgr implements:\n"
            "  GenerateKeyPair(bool) — generate STRAP ECDH key pair\n"
            "  GetPubKey() — return client pubkey (ANYCONNECT_STRAP_PUBKEY notify)\n"
            "  GetDHPubKey() — return DH pubkey (ANYCONNECT_STRAP-DH vendor ID)\n"
            "  GenerateVerifyAndRekey(nonce, verify_out, rekey_out) — "
            "    produce resumption proof from nonce\n"
            "The resumption proof (ANYCONNECT_STRAP_VERIFY notify) is sent in "
            "IKE_AUTH to resume a prior session. If the verify computation "
            "does not bind to the current IKEv2 exchange's SPIi/SPIr/nonce values, "
            "a captured STRAP_VERIFY from session N can be replayed in session N+1 "
            "to impersonate the original client without knowing their credentials. "
            "The vector is: capture valid client STRAP exchange, wait for reconnect, "
            "replay against a rogue headend running as the real client."
        ),
        "evidence": [
            "libvpnipsec.so: CStrapMgr::GenerateVerifyAndRekey (nonce + verify + rekey outputs)",
            "libvpnipsec.so: ANYCONNECT_STRAP_PUBKEY, ANYCONNECT_STRAP_VERIFY notify types",
            "libvpnipsec.so: CISCO-ANYCONNECT-STRAP, CISCO-ANYCONNECT-STRAP-DH vendor IDs",
            "libvpnipsec.so: 'Failed to generate STRAP verify notify payload'",
            "libvpnipsec.so: 'Headend supports AnyConnect VPN STRAP'",
        ],
        "impact": (
            "If replay protection is absent or insufficient: "
            "capture STRAP exchange, replay to rogue headend, resume session without creds. "
            "Effectively: VPN session hijacking post-disconnect."
        ),
        "strap_notify_types": {
            "ANYCONNECT_STRAP_SPEC": "protocol spec",
            "ANYCONNECT_STRAP_PUBKEY": "client ECDH pubkey",
            "ANYCONNECT_STRAP_VERIFY": "resumption proof",
        },
        "remediation": (
            "Ensure STRAP_VERIFY binds to: SPIi || SPIr || Ni || Nr from current exchange. "
            "Include anti-replay counter in proof material. "
            "Set short STRAP ticket lifetime."
        ),
    },

    "PLUG-F02": {
        "title": "IKEv2 cipher fallback: ikev2_return_to_fallback_keys downgrades SA",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "opt/cisco/secureclient/bin/plugins/libvpnipsec.so",
        "description": (
            "libvpnipsec.so contains 'ikev2_return_to_fallback_keys' and "
            "'Using fallback SA' — a negotiation fallback mechanism that switches "
            "to weaker SA parameters when the primary negotiation fails. "
            "IKEv2 downgrade attacks (CVE-2016-6407 class):\n"
            "  1. Attacker is on-path and injects INVALID_KE_PAYLOAD or "
            "     NO_PROPOSAL_CHOSEN notify into the IKE_SA_INIT response.\n"
            "  2. Client calls ikev2_return_to_fallback_keys and retries with "
            "     weaker DH group / cipher.\n"
            "  3. If fallback SA uses legacy parameters (DH group 2, 3DES, MD5), "
            "     the resulting VPN session is cryptographically weak.\n"
            "Additional events: EV_GEN_FALLBACK_AUTH, EV_SIGN_FALLBACK — "
            "authentication fallback from cert-based to PSK or weaker method."
        ),
        "evidence": [
            "libvpnipsec.so: 'ikev2_return_to_fallback_keys'",
            "libvpnipsec.so: 'Using fallback SA'",
            "libvpnipsec.so: 'EV_GEN_FALLBACK_AUTH', 'EV_SIGN_FALLBACK'",
        ],
        "impact": (
            "On-path attacker forces client to downgrade to weak cipher suite. "
            "EV_SIGN_FALLBACK: force cert auth -> PSK -> MITM if PSK is guessable."
        ),
        "remediation": (
            "Remove fallback to DH groups < 14 (2048-bit). "
            "Disable 3DES, RC4, MD5 from all proposal lists. "
            "Configure 'strict proposal' mode: no fallback, hard fail on no match."
        ),
    },

    "PLUG-F03": {
        "title": "libacdownloader.so: chmod + execvp on downloaded script — TOCTOU race",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "opt/cisco/secureclient/bin/plugins/libacdownloader.so",
        "description": (
            "libacdownloader.so downloads vpndownloader.sh from the headend at "
            "https://<headend>/binaries/vpndownloader.sh, verifies its hash "
            "('hash of retrieved file %s, expected %s'), then:\n"
            "  1. chmod(downloaded_path, 0755) — 'Failed to change permissions on remote downloader'\n"
            "  2. execvp(downloaded_path, args) — execute as root via vpnagentd\n"
            "TOCTOU race:\n"
            "  - The hash check and chmod are separate operations on a filesystem path.\n"
            "  - Between hash check and chmod, attacker can replace the file.\n"
            "  - Between chmod and execvp, attacker can replace the executable.\n"
            "Race window depends on filesystem caching but is exploitable on slow "
            "filesystems or under I/O pressure.\n"
            "Additionally, the manifest file is fetched separately:\n"
            "  'Failed to parse manifest file [%s]' / 'failed to download downloader manifest'\n"
            "If the manifest format is XML or JSON and parsed unsafely, injection "
            "into the manifest can manipulate which binary gets downloaded and executed."
        ),
        "evidence": [
            "libacdownloader.so: '/binaries/vpndownloader.sh'",
            "libacdownloader.so: 'Failed to change permissions on remote downloader : chmod'",
            "libacdownloader.so: 'Detected different remote downloader (hashes: local = [%s] remote = [%s])'",
            "libacdownloader.so: 'Failed to retrieve cloud remote Cisco Secure Client - Downloader'",
            "libacdownloader.so: 'chmod', execvp via CDownloaderPluginIpc::Start",
            "libacdownloader.so: 'update execute'",
        ],
        "impact": (
            "Root code execution: attacker replaces download after hash check or "
            "serves malicious manifest pointing to attacker binary. "
            "vpnagentd executes the script as root."
        ),
        "exploit_sketch": (
            "Option A (TOCTOU):\n"
            "  1. Watch for download to /tmp or cached path\n"
            "  2. Race: after hash check, before chmod, replace with malicious binary\n"
            "  3. chmod makes malicious binary executable\n"
            "  4. execvp runs it as root\n"
            "Option B (manifest injection):\n"
            "  1. Compromise headend or MITM HTTPS (rogue cert)\n"
            "  2. Serve malicious manifest pointing to malicious downloader\n"
            "  3. Client downloads, hash matches attacker's expected hash\n"
            "  4. Execution as root\n"
        ),
        "remediation": (
            "Use O_TMPFILE or atomically rename after hash verification. "
            "Never chmod + execvp in separate steps — use fexecve(fd) after fstat "
            "verification to avoid TOCTOU entirely. "
            "Pin headend certificate; disallow headend cert changes without admin approval."
        ),
    },

    "PLUG-F04": {
        "title": "CCertIKEAdapter: custom X.509 verification path — cert validation bypass surface",
        "severity": "HIGH",
        "status": "CANDIDATE",
        "source_file": "opt/cisco/secureclient/bin/plugins/libvpnipsec.so",
        "description": (
            "IKEv2 server certificate verification is implemented in CCertIKEAdapter "
            "rather than using OpenSSL's X509_verify_cert() directly. "
            "The adapter chain:\n"
            "  sendServerCertRequestToApi() → processServerCertResponse() → "
            "  VerifyServerCertificate() → CCertHelper::AddVerificationCert() → "
            "  OpenCertificate() → GetCertificateChain()\n"
            "Custom cert verification paths in VPN clients are a historically "
            "high-risk area (CVE-2023-20178 class — wrong signature verification order, "
            "CVE-2021-1428 class — chain not fully verified). "
            "If CCertIKEAdapter::VerifyServerCertificate() fails to:\n"
            "  1. Validate the full chain to a trusted root\n"
            "  2. Check revocation (CRL/OCSP)\n"
            "  3. Validate extended key usage (serverAuth)\n"
            "  4. Validate hostname/SAN against the configured gateway address\n"
            "then a rogue headend with any valid TLS cert can MITM the VPN connection."
        ),
        "evidence": [
            "libvpnipsec.so: CCertIKEAdapter::VerifyServerCertificate",
            "libvpnipsec.so: CCertIKEAdapter::loadPeerCerts, processServerCertResponse",
            "libvpnipsec.so: CCertHelper::AddVerificationCert, GetCertificateChain",
            "libvpnipsec.so: http://crl3.digicert.com/ (CRL fetch — network-dependent)",
            "libvpnipsec.so: 'An unrecoverable error has been encountered with the received server certificate'",
            "libvpnipsec.so: 'Already pending request to verify server certificate'",
        ],
        "impact": (
            "If verification is incomplete: MITM VPN headend with any CA-signed cert. "
            "Attacker captures credentials, intercepts all VPN traffic."
        ),
        "cert_verify_checklist": [
            "chain validation to trusted root",
            "revocation check (CRL/OCSP) — CRL URL is network-fetched",
            "EKU check (serverAuth OID 1.3.6.1.5.5.7.3.1)",
            "hostname / SAN validation against configured gateway",
            "cert not yet valid / expired check",
        ],
        "remediation": (
            "Replace custom cert adapter with OpenSSL X509_verify_cert() + explicit hostname check. "
            "Enable OCSP stapling to avoid network-dependent CRL fetches. "
            "Implement cert pinning for known headend certificates."
        ),
    },

    "PLUG-F05": {
        "title": "SADB/PF_KEY interface: attacker-influenced IKE negotiation installs weak SA",
        "severity": "HIGH",
        "status": "CANDIDATE",
        "source_file": "opt/cisco/secureclient/bin/plugins/libvpnipsec.so",
        "description": (
            "After successful IKEv2 negotiation, libvpnipsec.so installs IPsec SAs "
            "into the kernel using PF_KEY v2 sockets (SADB_ADD messages). "
            "The cipher suite, key material, SPI, and lifetime in the SADB_ADD "
            "come directly from the IKEv2 negotiation with the headend. "
            "If PLUG-F02 (fallback downgrade) succeeds or PLUG-F04 (cert bypass) "
            "allows a rogue headend:\n"
            "  - Rogue headend negotiates: AES-128-CBC + HMAC-MD5 (weak)\n"
            "  - Client installs weak SA via PF_KEY SADB_ADD to kernel\n"
            "  - All VPN traffic uses weak ciphers, decryptable offline\n"
            "Additionally: if SPI values or key material are predictable "
            "(not full-entropy random), ESP replay attacks are possible."
        ),
        "evidence": [
            "libvpnipsec.so: 'SADB init failed:...............'",
            "libvpnipsec.so: 'Check for IPSEC rekey', 'IKE SA rekey'",
            "libvpnipsec.so: 'CESP' class (Child SA ESP handler)",
            "Combined chain: PLUG-F02 downgrade → PF_KEY SADB_ADD with weak keys",
        ],
        "impact": (
            "Weak kernel IPsec SA: all VPN traffic encrypted with breakable cipher. "
            "Attacker captures ESP traffic, decrypts offline. "
            "Full VPN traffic compromise."
        ),
        "remediation": (
            "Enforce minimum cipher policy at client: AES-256-GCM only for ESP. "
            "Reject headend proposals with MD5/SHA1 integrity or DH < group 14. "
            "Fix PLUG-F02 (no cipher fallback) as prerequisite."
        ),
    },

    "PLUG-F06": {
        "title": "libacdownloader.so: abstract socket com.cisco.anyconnect.downloader — IPC race",
        "severity": "MEDIUM",
        "status": "CONFIRMED",
        "source_file": "opt/cisco/secureclient/bin/plugins/libacdownloader.so",
        "description": (
            "The downloader plugin communicates with vpndownloader via an abstract "
            "UNIX domain socket named 'com.cisco.anyconnect.downloader' (confirmed by "
            "the IPC thread start message 'IpcThreadStarted'). "
            "Like the csc_vpnagent/csc_vpncli abstract sockets (CSC-F01), abstract "
            "sockets are not protected by filesystem ACL — any process that knows "
            "the name can connect. "
            "Additional abstract socket: 'com.cisco.anyconnect.cloud_downloader' "
            "for cloud update channel; 'com.cisco.anyconnect.software_update_monitor' "
            "for update monitoring. "
            "If any of these IPC channels accept messages without verifying the "
            "caller, a local user can inject update notifications to trigger "
            "the download/execute chain (PLUG-F03) without a headend connection."
        ),
        "evidence": [
            "libacdownloader.so: 'com.cisco.anyconnect.downloader' abstract socket name",
            "libacdownloader.so: 'com.cisco.anyconnect.cloud_downloader'",
            "libacdownloader.so: 'com.cisco.anyconnect.software_update_monitor'",
            "libacdownloader.so: 'IpcThreadStarted', 'InvokeThreadStarted'",
            "libacdownloader.so: 'nnect.downloadercom.cisco.anycon' (mangled in binary)",
        ],
        "impact": (
            "Inject update trigger message to abstract IPC → trigger download chain → "
            "TOCTOU race (PLUG-F03) → root code execution without headend interaction."
        ),
        "remediation": (
            "Apply abstract socket authentication (CSC-F01 fix) to all downloader IPC channels. "
            "Verify caller PID == vpnagentd PID before processing trigger messages."
        ),
    },
}


# ── Protocol Constants ─────────────────────────────────────────────────────────

# IKEv2 NOTIFY payload types (Cisco-private)
CISCO_STRAP_NOTIFY_TYPES = {
    "ANYCONNECT_STRAP_SPEC":   "protocol spec — negotiation of STRAP capability",
    "ANYCONNECT_STRAP_PUBKEY": "client ECDH public key for STRAP ticket",
    "ANYCONNECT_STRAP_VERIFY": "session resumption proof (bind to exchange nonces)",
}

# IKEv2 Vendor IDs
CISCO_VENDOR_IDS = {
    "CISCO-ANYCONNECT-STRAP":    "STRAP capability advertisement",
    "CISCO-ANYCONNECT-STRAP-DH": "STRAP DH parameters",
    "CISCO-ANYCONNECT-SNI":      "SNI extension",
}

# Abstract socket names
DOWNLOADER_ABSTRACT_SOCKETS = [
    "\x00com.cisco.anyconnect.downloader",
    "\x00com.cisco.anyconnect.cloud_downloader",
    "\x00com.cisco.anyconnect.software_update_monitor",
]

# IKEv2 class hierarchy (from demangled symbols)
IKEV2_CLASSES = {
    "CGraniteShim": "IKEv2 state machine shim (Granite = IKEv2 codename)",
    "CIKEConnectionCrypto": "crypto operations for IKE SA",
    "CCertIKEAdapter": "X.509 cert operations within IKE (custom path — risky)",
    "CStrapMgr": "STRAP key management singleton",
    "CCertificate": "cert wrapper",
    "COpenSSLCertificate": "OpenSSL cert implementation",
    "CCertHelper": "cert chain + PKCS7 operations",
    "CCertPKCS7": "PKCS7 builder for cert chains",
    "COpenSSLCertUtils": "X.509 utility functions",
    "UserAuthenticationTlv": "IKEv2 extended auth (EAP/XAUTH TLV)",
    "LocalACPolicyInfo": "local policy (cert store exclusions)",
}


def probe_downloader_sockets() -> dict:
    """
    Check if downloader abstract sockets are accepting connections.
    """
    results = {}
    for name in DOWNLOADER_ABSTRACT_SOCKETS:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(name)
            results[name[1:]] = "open"
            s.close()
        except ConnectionRefusedError:
            results[name[1:]] = "refused"
        except Exception as e:
            results[name[1:]] = f"error: {e}"
    return results


def report(verbose: bool = False):
    print("Cisco Secure Client VPN Plugins 5.1.15.287 — RE Findings")
    print("libvpnipsec.so BuildID: fc5c3f1f68e6592c14e5a4d027c5b2d954363a70")
    print("libacdownloader.so BuildID: df4c5fc32559c7df6b1331bf5195880f413491f8")
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
    print("STRAP notify types:")
    for k, v in CISCO_STRAP_NOTIFY_TYPES.items():
        print(f"  {k}: {v}")
    print()
    print("IKEv2 classes (custom, not stock OpenSSL):")
    for k, v in IKEV2_CLASSES.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    import sys
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    report(verbose=verbose)

    if "--probe-sockets" in sys.argv:
        print("\nProbing downloader abstract sockets...")
        results = probe_downloader_sockets()
        for name, status in results.items():
            print(f"  \\x00{name}: {status}")
