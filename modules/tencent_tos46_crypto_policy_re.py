"""
TencentOS 4.6 — crypto-policies DEFAULT configuration reverse engineering.

Source: /usr/share/crypto-policies/ (Python policy generator + pre-compiled policy files)
Current policy: /etc/crypto-policies/state/CURRENT.pol

TOS 4.6 ships a MODIFIED crypto-policies framework that adds SM2/SM2DHE (TLCP)
as preferred cipher key exchange algorithms in the DEFAULT policy. This is absent
in upstream RHEL/CentOS crypto-policies.

The policy framework uses Python generators in:
  /usr/share/crypto-policies/python/policygenerators/openssl.py
  /usr/share/crypto-policies/python/cryptopolicies/alg_lists.py
"""

METADATA = {
    "source": "/usr/share/crypto-policies/",
    "policy_file": "/etc/crypto-policies/state/CURRENT.pol",
    "base_policy": "DEFAULT",
    "tos_modification": "SM2/SM2DHE added as preferred key exchange before ECDH/RSA",
    "upstream_comparison": "RHEL/CentOS DEFAULT crypto-policy does NOT include SM2",
}

POLICY_MATRIX = {
    "DEFAULT": {
        "openssl_cipher": "@SECLEVEL=2:kSM2:kSM2DHE:kEECDH:kRSA:kEDH:kPSK:kDHEPSK:kECDHEPSK:kRSAPSK:-aDSS:-3DES:!DES:!RC4:!RC2:!IDEA:-SEED:!eNULL:!aNULL:!MD5:-SHA384:-CAMELLIA:-ARIA:-AESCCM8",
        "sm2_position": "FIRST — kSM2:kSM2DHE before kEECDH:kRSA",
        "nss": "allows SM3 hash algorithm",
        "ssh": "standard (AES-GCM, ChaCha20) — no SM ciphers in SSH",
    },
    "FUTURE": {
        "openssl_cipher": "@SECLEVEL=3:kSM2:kSM2DHE:kEECDH:kEDH:kPSK:kDHEPSK:kECDHEPSK:-kRSAPSK:-kRSA:...",
        "sm2_position": "FIRST — RSA REMOVED (stronger than DEFAULT)",
        "note": "Future-hardened mode: SM2 first, RSA/RSA-PSK completely removed",
    },
    "FIPS": {
        "openssl_cipher": "@SECLEVEL=2:kEECDH:kEDH:...-kSM2:-SM2DHE:...",
        "sm2_position": "DISABLED — -kSM2:-SM2DHE explicitly excluded",
        "note": "FIPS 140-2/140-3 compliance requires SM2 exclusion (not NIST-approved)",
        "conflict": "FIPS and SM2 are MUTUALLY EXCLUSIVE on TOS 4.6",
    },
    "LEGACY": {
        "openssl_cipher": "@SECLEVEL=2:kEECDH:kRSA:...-kSM2:-SM2DHE:...",
        "sm2_position": "DISABLED",
        "note": "Legacy compatibility mode without SM2",
    },
}

POLICY_GENERATOR_ANALYSIS = {
    "alg_lists.py": {
        "kex_algorithms": "['DH', 'ECDH', 'SM2', 'SM2DHE']",
        "note": (
            "SM2 and SM2DHE are integrated into the policy framework's "
            "key exchange algorithm list alongside DH and ECDH. "
            "This is a TOS-specific addition to the upstream Python policy generator."
        ),
    },
    "openssl.py": {
        "sm2_enable": "{'SM2': 'kSM2', 'SM2DHE': 'kSM2DHE'} — maps SM2 → OpenSSL kSM2 cipher group",
        "sm2_disable": "{'SM2': '-kSM2', 'SM2DHE': '-SM2DHE'} — maps to disable string",
        "note": (
            "The policy generator knows SM2 by name and can enable or disable it "
            "per-policy. DEFAULT enables it first; FIPS/LEGACY disable it."
        ),
    },
}

OPENSSL_SM2_CIPHER_GROUPS = {
    "kSM2": (
        "OpenSSL cipher group: key exchange using SM2 elliptic curve key agreement. "
        "In TLS context, this selects TLCP-compatible cipher suites using SM2 for key exchange. "
        "Cipher suites: TLS_SM4_GCM_SM3 (RFC 8998), TLS_SM4_CCM_SM3 (RFC 8998) — "
        "SM4 for bulk encryption, SM3 for MAC/HMAC."
    ),
    "kSM2DHE": (
        "SM2 DHE (Diffie-Hellman Ephemeral) using SM2 curve. "
        "Forward-secret SM2 key exchange. Used in TLCP (GM/T 0024) "
        "as the ephemeral variant of SM2 ECDHE."
    ),
}

SSH_EXCLUSION = {
    "openssh_policy": (
        "Ciphers: aes256-gcm, chacha20-poly1305, aes256-ctr, aes128-gcm, aes128-ctr. "
        "No SM4 cipher in SSH. "
        "MACs: hmac-sha2-256-etm, hmac-sha1-etm, umac-128-etm, hmac-sha2-512-etm. "
        "No SM3 MAC in SSH."
    ),
    "explanation": (
        "SM4/SM3 are NOT included in the SSH crypto policy — only in TLS. "
        "SSH connections on TOS 4.6 use standard international algorithms. "
        "Only OpenSSL-based TLS connections use SM2/TLCP."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "DEFAULT crypto policy places kSM2:kSM2DHE FIRST — all OpenSSL apps prefer TLCP over TLS",
        "detail": (
            "TOS 4.6 DEFAULT OpenSSL cipher string starts with kSM2:kSM2DHE before kEECDH:kRSA. "
            "Any application using OpenSSL with the default config will advertise SM2 cipher suites "
            "as the first preference. If the peer also supports SM2/TLCP, the connection uses "
            "TLCP (SM4 encryption, SM3 MAC) instead of TLS 1.3 with ECDHE/AES. "
            "This affects: nginx, httpd, curl, wget, Python requests (OpenSSL backend), "
            "PostgreSQL, MySQL, and any application using system OpenSSL without explicit cipher config. "
            "Standard TLS inspection tools and IDS/IPS that do not understand TLCP/SM ciphers "
            "will fail to decrypt or inspect these connections."
        ),
        "cipher_preference_order": ["kSM2", "kSM2DHE", "kEECDH", "kRSA"],
        "policy": "DEFAULT",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "FUTURE policy removes RSA entirely while keeping SM2 first — strongest China-centric hardening",
        "detail": (
            "The FUTURE policy (`update-crypto-policies --set FUTURE`) is stricter: "
            "kSM2:kSM2DHE first, kRSA and kRSAPSK REMOVED. "
            "A TOS 4.6 server configured with FUTURE cannot negotiate RSA key exchange at all — "
            "only SM2 and ECDHE are available. "
            "This is stricter than RHEL's FUTURE policy (which keeps RSA but raises min key size). "
            "A TOS 4.6 server in FUTURE mode using SM2 is effectively incompatible with "
            "any TLS client that doesn't support SM2/TLCP and doesn't support ECDHE — "
            "which includes legacy corporate MITM proxies and some enterprise tools."
        ),
        "policy": "FUTURE",
        "rsa_removed": True,
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "FIPS and SM2 are mutually exclusive on TOS 4.6 — compliance modes conflict",
        "detail": (
            "FIPS policy explicitly disables SM2 (-kSM2:-SM2DHE). "
            "SM2 is not approved under FIPS 140-2 or 140-3 (US NIST standards). "
            "A TOS 4.6 deployment in FIPS mode cannot use TLCP — only international algorithms. "
            "DEFAULT and FUTURE use SM2 first. FIPS disables SM2. "
            "This creates a binary choice: Chinese regulatory compliance (SM2) vs. "
            "US regulatory compliance (FIPS). No policy satisfies both simultaneously. "
            "TOS 4.6 used by organizations needing both MLPS (China) and FIPS (US export) "
            "compliance has no compatible crypto policy."
        ),
        "policy_conflict": {
            "FIPS": "SM2 disabled",
            "DEFAULT": "SM2 first preference",
        },
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "SM2-first DEFAULT makes TLCP invisible to standard TLS inspection infrastructure",
        "detail": (
            "Network inspection tools (NGFWs, IDS/IPS, CASB, DLP) that perform "
            "TLS inspection typically support TLS 1.2/1.3 with RSA/ECDHE. "
            "TLCP (SM2 key exchange, SM4 bulk cipher) is not supported by Palo Alto, "
            "Fortinet, Cisco, Zscaler, or any major Western NGFW as of 2026. "
            "Traffic between two TOS 4.6 servers using DEFAULT policy will negotiate "
            "TLCP instead of TLS, making the content opaque to any inline TLS inspection device. "
            "This applies to east-west traffic within a Tencent Cloud CVM cluster."
        ),
        "inspection_bypass": "TLCP not supported by major Western TLS inspection vendors",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "NSS (Firefox/Thunderbird) allows SM3 hash but SSH excludes SM3/SM4",
        "detail": (
            "NSS config in DEFAULT allows SM3 hash: 'HMAC-SHA256:HMAC-SHA1:...:SM3:SHA256:...'. "
            "SM3 is permitted in NSS-based applications (Firefox, Thunderbird). "
            "SSH DEFAULT policy has NO SM ciphers or MACs: "
            "'Ciphers aes256-gcm,chacha20-poly1305,...' / 'MACs hmac-sha2-256-etm,...'. "
            "Asymmetric: TLS via OpenSSL/NSS prefers Chinese crypto; SSH stays international. "
            "This means SSH sessions to TOS 4.6 are standard and inspectable; "
            "TLS sessions may not be."
        ),
        "nss_sm3_allowed": True,
        "ssh_sm_excluded": True,
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "Policy generator Python code in /usr/share — modifiable by root without recompilation",
        "detail": (
            "The crypto policy generator is Python source at "
            "/usr/share/crypto-policies/python/policygenerators/openssl.py. "
            "An attacker with root access can modify the Python policy generator to "
            "silently add cipher suites (e.g., NULL encryption, weak ciphers) to all policies. "
            "The compiled policy files in /usr/share/crypto-policies/*/openssl.txt are "
            "pre-generated from this Python code. If an attacker modifies both the Python "
            "source and the pre-compiled policy files, then runs 'update-crypto-policies', "
            "all OpenSSL-using applications pick up the modified policy on next restart. "
            "There is no signed integrity check on the policy Python source."
        ),
        "policy_generator_path": "/usr/share/crypto-policies/python/policygenerators/",
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "SM2DHE (ephemeral SM2) in DEFAULT provides forward secrecy via SM2 curve",
        "detail": (
            "kSM2DHE is ephemeral SM2 Diffie-Hellman — each session generates a fresh SM2 key pair. "
            "This provides forward secrecy (future key compromise doesn't decrypt past sessions). "
            "kSM2 (non-ephemeral) does NOT provide forward secrecy — the server's static SM2 key "
            "is used for key derivation, so key compromise exposes all past sessions. "
            "Both are in the DEFAULT policy; SM2DHE should be negotiated when possible. "
            "Whether SM2 or SM2DHE is negotiated depends on server/client preference ordering."
        ),
        "forward_secrecy": {"kSM2DHE": True, "kSM2": False},
    },
]

if __name__ == '__main__':
    print("TOS 4.6 crypto-policies analysis")
    print()
    print("Policy matrix (SM2 position):")
    for name, policy in POLICY_MATRIX.items():
        sm2_pos = policy.get('sm2_position', 'unknown')
        print(f"  {name:8s}: {sm2_pos}")
    print()
    print("Key finding: DEFAULT prefers SM2 → TLCP over TLS for all OpenSSL applications")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
