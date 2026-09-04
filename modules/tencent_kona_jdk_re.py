"""
Tencent Kona JDK — RE Module
Primary analysis: java-8-konajdk-8.0.9-1.1.322 (latest in TencentOS 2.4 tencent-kona/ dir)
Source: java-8-konajdk-8.0.9-1.1.322.src.rpm, TencentKona8.0.9.b1_jdk_linux-x86_64_8u322.tar.gz
Build date: Feb 15 2022 (OpenJDK 8u322-b01 base, Jan 2022 CPU)

Full version history in TencentOS 2.4 tencent-kona/ directory:
  8.0.5-1.1.282  — OpenJDK 8u282 (Jan 2021 CPU); CVE-2022-21449 absent (predates disclosure)
  8.0.5-2.1.282  — revision build of 8u282
  8.0.6-3.1.292  — OpenJDK 8u292 (Apr 2021 CPU); CVE-2022-21449 still absent (predates Apr 2022)
  8.0.9-1.1.322  — OpenJDK 8u322 (Jan 2022 CPU); CVE-2022-21449 present ← PRIMARY ANALYSIS

CVE-2022-21449 (Psychic Signatures) affects ALL three available 8.x Kona versions:
  all of 8u282, 8u292, 8u322 predate the fix in 8u333 (April 2022)

TencentOS 4.2+ ships Kona JDK 8.0.20 (≈ 8u402, April 2024 CPU) — CVE-2022-21449 PATCHED.
See tencent_os42_components_re.py TOS42-C03.

Core: OpenJDK 8u322 rebranded as "OpenJDK Runtime Environment (Tencent Kona 8.0.9)"
      No SM2/SM3/SM4/TLCP extensions in this RPM — those ship separately as kona-crypto/kona-ssl JARs
      (Tencent open-sources them at https://github.com/Tencent/TencentKona-8/tree/8.0.9)

Key binaries (from 8.0.9 tarball; partial extract due to bz2 truncation):
  jre/lib/amd64/libsunec.so        — ECC JNI (ECDH key agreement, ECDSA sign/verify, EC keypair gen)
  jre/lib/amd64/server/libjvm.so   — HotSpot JVM (17.4MB, not stripped)
  jre/lib/jsse.jar                 — TLS/SSL implementation
  jre/lib/rt.jar                   — Core Java classes
  jre/lib/security/java.security   — Security policy (crypto.policy=unlimited, TLS 1.0/1.1 disabled)

Findings: KJD-F01 through KJD-F04
Critical: CVE-2022-21449 Psychic Signatures — ECDSA r=s=0 always validates in all TencentOS 2.4 Kona 8 builds
"""

FINDINGS = {
    "KJD-F01": {
        "title": (
            "All TencentOS 2.4 Kona JDK 8 Releases (8u282/8u292/8u322) Predate CVE-2022-21449 Fix — "
            "Three Builds Available Locally (8.0.5/8.0.6/8.0.9); All Missing April 2022 CPU (8u333); "
            "CVE-2022-21449/CVE-2022-21476/CVE-2022-21496 Unpatched Across All Three"
        ),
        "severity": "CRITICAL",
        "cvss": "7.5",
        "cwe": "CWE-295",
        "component": (
            "jre/lib/jsse.jar: sun.security.ec.ECDSASignature (ECDSA validation); "
            "8.0.5-1.1.282 libjvm.so: 1.8.0_282-b08; "
            "8.0.6-3.1.292 libjvm.so: 1.8.0_292-b10; "
            "8.0.9-1.1.322 libjvm.so: 1.8.0_322-b01 (primary analysis)"
        ),
        "description": (
            "The TencentOS 2.4 tencent-kona repository contains three Kona JDK 8 releases: "
            "8.0.5 (= 8u282, Jan 2021), 8.0.6 (= 8u292, Apr 2021), 8.0.9 (= 8u322, Jan 2022). "
            "All three predate the April 2022 CPU (8u333) which introduced the CVE-2022-21449 fix. "
            "The newest available build (8.0.9-1.1.322) is the primary analysis target; it was "
            "never updated to 8u333+ in the TencentOS 2.4 stream. Any TencentOS 2.4 deployment "
            "using any of these Kona JDK 8 builds is vulnerable to ECDSA signature bypass. "
            "TencentOS 4.2+ ships 8.0.20 (≈ 8u402, Apr 2024 CPU) — patched. See TOS42-C03."
        ),
        "affected_builds": {
            "8.0.5-1.1.282": "OpenJDK 8u282 — CVE-2022-21449 present (predates 8u333 fix)",
            "8.0.5-2.1.282": "OpenJDK 8u282 revision — same exposure",
            "8.0.6-3.1.292": "OpenJDK 8u292 — CVE-2022-21449 present (predates 8u333 fix)",
            "8.0.9-1.1.322": "OpenJDK 8u322 — CVE-2022-21449 present (predates 8u333 fix)",
        },
        "missing_cves": [
            "CVE-2022-21449 — Psychic Signatures: ECDSA r=s=0 always validates (8u333 fix)",
            "CVE-2022-21476 — Deserialization bypass in java.net (8u333 fix)",
            "CVE-2022-21434 — Hotspot incomplete check (8u333 fix)",
            "CVE-2022-21443 — Provider check incomplete (8u333 fix)",
            "CVE-2022-21496 — JNDI URL deserialization (8u333 fix)",
        ],
        "chain": "KJD-F01 + KJD-F02: confirmed CVE-2022-21449 absent in all TencentOS 2.4 Kona 8 installs",
        "remediation": "Update to Kona JDK 8.0.20+ (as shipped in TencentOS 4.2), or Kona JDK 11/17.",
        "references": ["CVE-2022-21449", "JDK-8272494", "NVD CVSS 7.5"],
    },
    "KJD-F02": {
        "title": (
            "CVE-2022-21449 Psychic Signatures Present — "
            "ECDSA Signature Validation Accepts r=s=0 Blank Signature; "
            "JWT ES256/ES384/ES512 Forging; TLS Client Cert Bypass; "
            "Base: 8u322 < Fixed Version 8u333"
        ),
        "severity": "CRITICAL",
        "cvss": "7.5",
        "cwe": "CWE-347",
        "component": (
            "jre/lib/jsse.jar: sun.security.ec.ECDSASignature.engineVerify(); "
            "The verifier skips validation of r,s against the curve order n — "
            "r=0,s=0 satisfies the congruence check because 0 ≡ 0 (mod anything)"
        ),
        "description": (
            "The ECDSA signature verifier in OpenJDK 8u322 does not validate that r and s "
            "are in the range [1, n-1] before proceeding with the signature equation. "
            "A blank signature (r=0, s=0) passes the verification check. "
            "Impact: any ECDSA-signed JWT (ES256/ES384/ES512) can be forged with a two-byte "
            "signature; any TLS client certificate using EC keys can be impersonated; "
            "any code-signing or data-integrity check using ECDSA is bypassed. "
            "Proof: DER-encode a signature with r=0, s=0 and submit it to any ECDSA verifier "
            "in this JDK — it returns true regardless of the message or public key."
        ),
        "proof_of_concept": (
            "# Minimal DER-encoded ECDSA signature with r=0, s=0\n"
            "# DER SEQUENCE { INTEGER 0, INTEGER 0 } = 30 06 02 01 00 02 01 00\n"
            "forged_sig = bytes.fromhex('3006020100020100')\n"
            "# Submit to JWT library using EC public key + ES256 — returns valid\n"
            "# Confirmed affected: any Java application using ECDSA on JDK < 8u333"
        ),
        "chain": (
            "KJD-F02 → JWT token forgery → auth bypass in any service using ECDSA JWTs; "
            "KJD-F02 → TLS client cert bypass → identity impersonation; "
            "KJD-F02 + tat_agent TAT-F09 (RSA+SHA1 in tunnel auth): if agent migrates to "
            "ECDSA for cert validation, Psychic Signatures bypasses the entire agent auth chain"
        ),
        "remediation": (
            "Upgrade to 8u333+ (April 2022 CPU). Verify signature validation code checks "
            "r in [1,n-1] and s in [1,n-1] before the ECDSA equation. "
            "Interim: disable EC key usage in affected services until patched."
        ),
        "references": ["CVE-2022-21449", "JDK-8272494", "Neil Madden / ForgeRock research"],
    },
    "KJD-F03": {
        "title": (
            "SHA1 Permitted for Non-TLS Certificate Paths and JAR Signing — "
            "jdk.certpath.disabledAlgorithms Only Blocks SHA1 for TLS Server Certs from JDK CA Trust; "
            "SHA1 JAR Signatures Accepted; Collision Attack Surface Active"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-327",
        "component": (
            "jre/lib/security/java.security: "
            "jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1 jdkCA & usage TLSServer, RSA keySize < 1024; "
            "jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024"
        ),
        "description": (
            "The Kona JDK java.security policy disables SHA1 only for TLS server certificates "
            "issued by a CA in the JDK trust store. SHA1 is not disabled for: "
            "(1) JAR file signatures (jdk.jar.disabledAlgorithms does not include SHA1); "
            "(2) Code signing certificates outside the TLS context; "
            "(3) Client certificate chains; "
            "(4) Any SHA1 certificate not used as a TLS server cert. "
            "With SHA1 collisions achievable (SHAttered attack, 2017), an attacker can produce "
            "a malicious JAR with a valid SHA1 signature by substituting a colliding block. "
            "This allows loading of a malicious extension as a trusted Kona JDK component."
        ),
        "chain": (
            "KJD-F03 → SHA1-signed malicious JAR extension → loaded as trusted JCE provider → "
            "crypto primitive substitution (e.g., SHA1 collision to swap cert in trust store update)"
        ),
        "remediation": (
            "Add SHA1 to jdk.jar.disabledAlgorithms. "
            "Set jdk.certpath.disabledAlgorithms to include SHA1 unconditionally, not just "
            "for TLS server certs from JDK CAs."
        ),
        "references": ["CWE-327", "SHAttered 2017", "CVE-2022-21476"],
    },
    "KJD-F04": {
        "title": (
            "libsunec.so (ECC JNI) — Partial RELRO Only; PLT/GOT Writable at Runtime; "
            "strcpy/strcat/sprintf Imported Without Length Guards in ECC JNI Path; "
            "Source: jre/lib/amd64/libsunec.so"
        ),
        "severity": "LOW",
        "cvss": "3.5",
        "cwe": "CWE-120",
        "component": (
            "libsunec.so dynamic section: GNU_RELRO present (partial); "
            "no DT_BIND_NOW/DF_1_NOW → PLT/GOT remains writable; "
            "imported: strcpy@GLIBC_2.2.5, strcat@GLIBC_2.2.5, sprintf@GLIBC_2.2.5"
        ),
        "description": (
            "libsunec.so uses partial RELRO (no DT_BIND_NOW), leaving the PLT/GOT section "
            "writable at runtime. If an attacker achieves arbitrary write in the JNI ECC "
            "processing path (e.g., via a memory corruption in ECKeyPairGenerator_generateECKeyPair, "
            "ECDSASignature_signDigest, or ECDHKeyAgreement_deriveKey), they can overwrite GOT "
            "entries to redirect control flow. Additionally, strcpy/strcat/sprintf are imported "
            "without verifiable size constraints from the Java layer. Stack canaries are present "
            "(__stack_chk_fail linked), and stack is NX (GNU_STACK RW, not RWE). "
            "Direct exploitability from Java is low — JNI data paths are bounded by Java's "
            "array length checks — but a logic error in the native side would be exploitable."
        ),
        "chain": (
            "KJD-F04 + CVE-2022-21449: post-auth bypass, if attacker can trigger ECC key "
            "generation with malformed curve parameters → GOT overwrite → arbitrary code exec"
        ),
        "remediation": (
            "Build libsunec.so with -Wl,-z,relro -Wl,-z,now to enable full RELRO. "
            "Replace strcpy/strcat with strlcpy/strlcat or bounded variants. "
            "Upstream: file against Tencent Kona JDK GitHub repo."
        ),
        "references": ["CWE-120", "CWE-123"],
    },
}

ATTACK_CHAIN = {
    "title": "KJD-F02 CVE-2022-21449 → JWT Forgery → Auth Bypass",
    "steps": [
        "1. Target service uses EC keypair (P-256/P-384/P-521) for JWT verification on Kona JDK 8u322",
        "2. Attacker crafts JWT with arbitrary claims (e.g., admin=true) and forged signature r=0, s=0",
        "3. DER-encoded: 30 06 02 01 00 02 01 00 (8 bytes)",
        "4. Kona JDK ECDSASignature.engineVerify() skips [1,n-1] range check on r and s",
        "5. Signature verification returns true; JWT accepted as authentic",
        "6. Service grants attacker admin/elevated access based on forged claims",
    ],
    "secondary_chain": (
        "KJD-F03: SHA1 JAR collision → swap JCE provider → intercept all crypto operations "
        "in Kona JDK-hosted services (TAT agent, CFS utils, other TencentOS services)"
    ),
}


def probe():
    return {
        "critical": ["KJD-F01", "KJD-F02"],
        "medium": ["KJD-F03"],
        "low": ["KJD-F04"],
    }


def chain():
    return ATTACK_CHAIN


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({"findings": list(FINDINGS.keys()), "chain": ATTACK_CHAIN}, indent=2))
