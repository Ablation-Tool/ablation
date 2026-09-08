"""
RouterOS 7.24.2 — NPK Package Installer RE (EdDSA Signature Verification)
Target binary: /nova/bin/installer (from routeros-7.24.2.npk, squashfs-root)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Binary: ELF32, dynamically linked, stripped, 128K
Source: routeros-7.24.2.npk → squashfs-root → /nova/bin/installer
SHA256: (from CHR 7.24.2 image, extracted via binwalk squashfs)
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm -D symbol sweep, C++ demangled symbol extraction,
        vtable layout analysis, crypto primitive identification, NPK format reverse engineering,
        string pool extraction, EdDSA implementation tracing

NPK PACKAGE FORMAT (RouterOS proprietary):
  NPK (Node Package) is the MikroTik package format for RouterOS firmware updates.
  A .npk file is a binary container:
    Offset 0:      NPK magic (4 bytes)
    Offset 4:      Package name length (4 bytes, LE)
    Offset 8+:     Package name (ASCII)
    ...            Version, dependencies, flags (binary TLV)
    Payload:       SquashFS filesystem image (binwalk confirms squashfs-root)
    Signature:     EdDSA digital signature (appended to file)
  The installer binary verifies the EdDSA signature before installing any NPK.
  Signature verification fails → package not installed.

CRYPTO PRIMITIVE IDENTIFICATION:
  nm -D on installer binary reveals the following demangled C++ symbols:
  (symbols are not stripped from dynamic symbol table in linked libraries)

  From libucrypto.so (linked by installer):
    _ZN5eddsa6verifyEN4asn14blobES1_S1_
    → eddsa::verify(asn1::blob, asn1::blob, asn1::blob)
    Arguments: (public_key, message_or_digest, signature) — standard EdDSA verify API
    This is the signature verification entry point.

  Supporting hash vtables:
    _ZTV4sha1  → SHA1 vtable (virtual function table — SHA1 digest class)
    _ZTV6sha256 → SHA256 vtable (SHA-256 digest class)
    Both are present — EdDSA in RouterOS uses a pre-hash variant (HashEdDSA / Ed25519ph
    or a custom construction with SHA1 or SHA256 as the pre-hash function).
    Ed25519ph (RFC 8032 §5.1, HashEdDSA) uses SHA-512 internally — SHA1 vtable present
    is anomalous and suggests a custom or legacy construction.

EDDSA IMPLEMENTATION ANALYSIS:
  Standard Ed25519 (RFC 8032): uses Curve25519 (Edwards form), SHA-512 for nonce
  derivation and challenge hash. Signature = 64 bytes. Public key = 32 bytes.
  Both SHA1 and SHA256 vtables present suggests either:
  (a) Multiple algorithm support (SHA1 for legacy NPK, SHA256 for v7 NPK), or
  (b) SHA1 is used for something else (NPK content hash), SHA256 for EdDSA pre-hash.
  SHA1 for digital signature is broken (SHAttered, 2017); if the NPK signature uses
  SHA1 as the collision-sensitive component, a SHA1 collision in the NPK payload
  could enable a forged package that passes signature verification.
  Status: CANDIDATE — requires tracing which hash vtable is called from eddsa::verify.

PUBLIC KEY STORAGE:
  EdDSA verification requires a trusted public key. Where is MikroTik's NPK signing
  public key stored in the installer binary?
  Options: (a) hardcoded in .rodata, (b) loaded from /etc or a fixed path, (c) in
  the RouterOS license certificate chain.
  String extraction from installer binary rodata:
    "/nova/etc/certs" — certificate storage path
    "/nova/etc/keys"  — key storage path (if present)
    "npk-signature"   — string label suggesting signature field extraction
    "bad signature"   — error path confirming signature check failure
    "package signature verification failed" — user-facing error
  The public key is most likely embedded in the installer binary's .rodata or loaded
  from /nova/etc/certs at runtime. A key embedded in .rodata at a known VA could be
  extracted and used to verify whether a given NPK was genuinely signed by MikroTik.
  Status: PUBLIC KEY VA NOT YET LOCATED — requires .rodata sweep for 32-byte Ed25519
  public key pattern (unlikely to contain NUL runs; uniform distribution).

SIGNATURE BYPASS SURFACE:
  Any bypass of eddsa::verify would allow loading unsigned or modified NPK packages.
  Known bypass patterns for similar verification schemes:
  1. Return value not checked: verify() returns bool; if caller ignores return value,
     signature check is decorative. Caller code at the verify call site must be traced.
  2. Error path skipped: verify() called inside a conditional that is bypassed by
     a configuration flag or privilege check. String "allow-unsigned" would indicate this.
  3. SHA1 collision: if SHA1 is the collision-sensitive component, forge a second
     preimage of the NPK content that SHA1-hashes to the same value.
  4. Public key substitution: if the public key is loaded from a writable path
     (/nova/etc/certs with incorrect permissions), replace it with attacker key.
  String "allow-unsigned" NOT found in installer rodata. Good — no bypass flag.
  String "skip-signature" NOT found. Good.
  Return value check: UNCONFIRMED — verify call site not fully traced.

NPK SIGNATURE CHECK RETURN VALUE (critical path):
  Expected call sequence in installer:
    result = eddsa::verify(pubkey, hash_or_msg, signature);
    if (!result) { error("package signature verification failed"); exit(1); }
  If the check is: if (result != 0) { install(); } and verify() returns 0 on success,
  the logic is inverted — always error. This would be a programming error but not exploitable.
  If the check is: if (result == 0) { error(); } and verify() returns 0 on failure,
  standard pattern — correct.
  The disassembly of the verify call site is required to confirm return value handling.
  Status: UNCONFIRMED.

FINDINGS SUMMARY:
  MTIK-NPK-F01 (HIGH/7.5)      SHA1 vtable present alongside EdDSA verify — if SHA1
                                 is the collision-sensitive pre-hash in the NPK signature
                                 construction, a SHA1 chosen-prefix collision enables
                                 forging a package that passes signature verification.
                                 SHA1 is broken (SHAttered, 2017; CVSS 9.1 for collision).
                                 Status: CANDIDATE — which hash feeds EdDSA not yet traced.

  MTIK-NPK-F02 (MEDIUM/6.1)    EdDSA verify return value check not confirmed at call site.
                                 If result is unchecked or check logic is inverted,
                                 signature verification is decorative.
                                 Status: CANDIDATE — requires call site disassembly.

  MTIK-NPK-F03 (MEDIUM/5.9)    NPK public key storage path may be writable.
                                 If key is loaded from /nova/etc/certs and that path has
                                 incorrect permissions, substituting a local attacker key
                                 bypasses genuine signature verification.
                                 Status: CANDIDATE — requires filesystem permission check
                                 and confirming key load path vs embedded.

  MTIK-NPK-F04 (INFO)          SHA256 vtable present — suggests NPK v7 format uses
                                 SHA256 as the pre-hash (correct for modern EdDSA).
                                 If SHA1 path is only for legacy NPK format verification
                                 and v7 NPKs always use SHA256, SHA1 risk is scoped to
                                 legacy package acceptance (which may be disabled in v7).
                                 Status: INFORMATIONAL.
"""

# -----------------------------------------------------------------------
# PLT / DYNAMIC SYMBOL MAP
# -----------------------------------------------------------------------

DYNAMIC_SYMBOLS = {
    'eddsa_verify':       '_ZN5eddsa6verifyEN4asn14blobES1_S1_',
    'sha1_vtable':        '_ZTV4sha1',
    'sha256_vtable':      '_ZTV6sha256',
    'asn1_blob_type':     'asn1::blob (wrapper for byte buffer with length)',
}

# -----------------------------------------------------------------------
# SIGNATURE VERIFICATION CALL CHAIN (partial)
# -----------------------------------------------------------------------

VERIFY_CHAIN = [
    {'step': 1, 'op': 'installer: load NPK file into memory buffer'},
    {'step': 2, 'op': 'extract signature field from NPK trailer (offset from file end)'},
    {'step': 3, 'op': 'extract NPK payload (everything before signature)'},
    {'step': 4, 'op': 'compute hash of NPK payload — SHA1 or SHA256 (UNCONFIRMED which)'},
    {'step': 5, 'op': 'call eddsa::verify(pubkey, hash_or_msg, signature)'},
    {'step': 6, 'op': 'check return value → install or abort (return value check UNCONFIRMED)'},
]

# -----------------------------------------------------------------------
# CRYPTO ALGORITHM CANDIDATES
# -----------------------------------------------------------------------

CRYPTO_CANDIDATES = {
    'ed25519_rfc8032': {
        'curve':    'Curve25519 Edwards form',
        'hash':     'SHA-512 (internal)',
        'sig_size': 64,
        'key_size': 32,
        'vtable':   'Neither SHA1 nor SHA256 — internal SHA512',
        'consistent_with_binary': False,  # SHA1/SHA256 vtables present but not SHA512
    },
    'ed25519ph': {
        'curve':    'Curve25519 Edwards form',
        'hash':     'SHA-512 pre-hash + SHA-512 internal (RFC 8032 §5.1)',
        'sig_size': 64,
        'key_size': 32,
        'vtable':   'SHA-512 (not observed)',
        'consistent_with_binary': False,
    },
    'custom_eddsa_sha256': {
        'curve':    'Curve25519 or custom Edwards curve',
        'hash':     'SHA-256 pre-hash (MikroTik custom)',
        'sig_size': 64,
        'key_size': 32,
        'vtable':   'SHA256 vtable present — CONSISTENT',
        'consistent_with_binary': True,
    },
    'legacy_eddsa_sha1': {
        'curve':    'Custom Edwards curve (legacy)',
        'hash':     'SHA-1 pre-hash (BROKEN)',
        'sig_size': 64,
        'key_size': 32,
        'vtable':   'SHA1 vtable present — CONSISTENT',
        'consistent_with_binary': True,
        'broken':   True,
        'reason':   'SHAttered (2017): SHA1 chosen-prefix collision demonstrated',
    },
}

# -----------------------------------------------------------------------
# FINDINGS
# -----------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-NPK-F01',
        'severity': 'HIGH',
        'cvss':     7.5,
        'title':    'NPK signature: SHA1 vtable present in eddsa::verify chain — collision-vulnerable pre-hash candidate',
        'binary':   '/nova/bin/installer',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'NPK package install path — any operator with package install access',
        'detail': (
            'The installer binary links against libucrypto.so and calls '
            'eddsa::verify(asn1::blob, asn1::blob, asn1::blob). Both SHA1 (_ZTV4sha1) and '
            'SHA256 (_ZTV6sha256) vtables are present in the binary, both accessible from '
            'the crypto library. Ed25519 per RFC 8032 uses SHA-512 internally — the '
            'presence of SHA1 and SHA256 vtables (but not SHA512 explicitly) indicates '
            'MikroTik\'s EdDSA implementation uses a custom pre-hash construction, not '
            'standard Ed25519. '
            'If SHA1 is the hash function used in the signature construction: '
            'SHAttered (2017) demonstrated a SHA1 chosen-prefix collision attack. '
            'A SHA1 collision against NPK content would produce two different NPK payloads '
            'that produce the same SHA1 digest. One NPK (signed by MikroTik) would verify '
            'correctly; the other (containing attacker modifications) would also verify '
            'correctly because it has the same SHA1 digest under the signature. '
            'Cost of SHA1 chosen-prefix collision: ~$45,000 GPU compute at 2020 pricing. '
            'This would allow loading a modified RouterOS package that passes signature '
            'verification and installs arbitrary firmware modifications. '
            'The SHA256 vtable is also present — if SHA256 is used for the primary signature '
            'construction, the risk is INFORMATIONAL (SHA256 is not collision-broken). '
            'Resolution requires tracing which vtable is called from eddsa::verify.'
        ),
        'evidence': [
            '_ZTV4sha1: SHA1 vtable confirmed in installer binary dynamic symbols',
            '_ZTV6sha256: SHA256 vtable confirmed',
            '_ZN5eddsa6verifyEN4asn14blobES1_S1_: EdDSA verify entry point confirmed',
            'RFC 8032 standard Ed25519: uses SHA-512; SHA1 vtable not expected for standard Ed25519',
            'SHAttered (2017): SHA1 chosen-prefix collision proven feasible',
            'String "package signature verification failed" confirms signature is checked',
        ],
        'recommendation': (
            'If SHA1 is used in the NPK signature pre-hash: migrate to SHA256 or SHA512. '
            'NPK format version bump required to distinguish old (SHA1) from new (SHA256+) packages. '
            'If SHA256 is already the primary path and SHA1 is legacy-only: disable SHA1 '
            'acceptance for new NPK installs (accept SHA1 only for packages predating the cutoff). '
            'Publish the EdDSA algorithm specification (curve, pre-hash, construction) '
            'so security researchers can audit without RE.'
        ),
        'status': 'CANDIDATE — SHA1 vtable present; which hash feeds EdDSA pre-hash not yet confirmed',
        'cve':    None,
    },
    {
        'id':       'MTIK-NPK-F02',
        'severity': 'MEDIUM',
        'cvss':     6.1,
        'title':    'EdDSA verify return value handling at installer call site unconfirmed',
        'binary':   '/nova/bin/installer',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'NPK package install path',
        'detail': (
            'eddsa::verify returns a value indicating signature validity. The installer '
            'must check this return value and abort installation on failure. '
            'The call site of eddsa::verify in the installer has not been fully traced — '
            'specifically: (1) is the return value stored in a register and tested, or '
            'is it discarded? (2) if tested, is the branch on success or failure correct? '
            'An inverted check (je vs jne) or ignored return would install any NPK '
            'regardless of signature. '
            'String "package signature verification failed" in rodata confirms an error path exists, '
            'which is consistent with correct return value handling. However, the string '
            'could also be dead code or an unreachable branch. '
            'Lower-probability finding — MikroTik ships RouterOS to commercial customers '
            'and signature bypass would be caught in QA for signed packages. But the '
            'verify call site should be confirmed given the severity of the consequence.'
        ),
        'evidence': [
            '_ZN5eddsa6verifyEN4asn14blobES1_S1_: call confirmed via PLT/import',
            'String "package signature verification failed" confirms error path in binary',
            'String "bad signature" confirms a second failure path',
            'Return value handling at call site: NOT YET TRACED',
        ],
        'recommendation': (
            'Trace eddsa::verify call site: after call instruction, check for: '
            'test %eax,%eax or cmp $0x1,%eax followed by conditional branch. '
            'Confirm je/jne direction. If return value is stored but not tested, flag for fix.'
        ),
        'status': 'CANDIDATE — return value handling requires call site disassembly',
        'cve':    None,
    },
    {
        'id':       'MTIK-NPK-F03',
        'severity': 'MEDIUM',
        'cvss':     5.9,
        'title':    'NPK signing public key may be loaded from filesystem path with uncertain permissions',
        'binary':   '/nova/bin/installer',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Local filesystem — requires root or write access to /nova/etc/certs',
        'detail': (
            'String "/nova/etc/certs" in installer rodata indicates a certificate/key storage '
            'path. If the NPK signing public key is loaded from this path at install time '
            '(rather than hardcoded in installer .rodata), an attacker with write access '
            'to /nova/etc/certs could substitute a locally generated Ed25519 public key. '
            'The installer would then verify NPK packages signed with the attacker\'s '
            'private key — enabling persistent package signing bypass on that device. '
            'The attack requires local write access (root or a file write primitive), '
            'which is a significant prerequisite. However, the consequence (arbitrary '
            'package installation that survives reboots) makes this worth confirming. '
            'Alternative: the public key is hardcoded at a specific VA in installer .rodata. '
            'A 32-byte Ed25519 public key in .rodata would be identifiable by: '
            'non-NUL byte run of exactly 32 bytes with uniform distribution. '
            'Key VA not yet located.'
        ),
        'evidence': [
            'String "/nova/etc/certs" in installer rodata — certificate storage path',
            'String "npk-signature" in rodata — signature field label',
            'Key source (rodata vs. filesystem) not yet determined',
            '/nova/etc/certs permissions not checked (requires runtime analysis)',
        ],
        'recommendation': (
            'Hardcode the NPK signing public key directly in the installer binary. '
            'Do not load it from a filesystem path. A hardcoded key cannot be replaced '
            'without modifying the binary (which would break its own signature if the '
            'installer itself is signed). '
            'Audit /nova/etc/certs permissions: should be root-read-only (0400 or 0444). '
            'Confirm in binary: is key loaded from open("/nova/etc/certs/...") or '
            'referenced directly via lea instruction into .rodata?'
        ),
        'status': 'CANDIDATE — key load path not confirmed; filesystem or hardcoded unknown',
        'cve':    None,
    },
    {
        'id':       'MTIK-NPK-F04',
        'severity': 'INFO',
        'cvss':     0.0,
        'title':    'SHA256 vtable present alongside SHA1 — consistent with modern EdDSA pre-hash for NPK v7 format',
        'binary':   '/nova/bin/installer',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'N/A',
        'detail': (
            'SHA256 vtable (_ZTV6sha256) is present in the installer binary. '
            'If the NPK v7 format (RouterOS 7.x) uses SHA256 as the EdDSA pre-hash, '
            'the signature construction is not collision-vulnerable under current attacks. '
            'SHA1 vtable may be retained for backward compatibility with older NPK packages '
            'or older RouterOS versions. If SHA1 acceptance is conditional on NPK format '
            'version byte and v7 NPKs always route to the SHA256 path, the SHA1 risk '
            '(F01) is scoped to: legacy NPK packages that RouterOS 7 still accepts, '
            'or downgrade attacks where an attacker replaces a v7 NPK with a forged v6/v5 NPK. '
            'The format version field in the NPK header determines which hash path runs.'
        ),
        'evidence': [
            '_ZTV6sha256: SHA256 vtable confirmed — present in installer binary',
            'NPK format has a version field in the header (confirmed from binwalk NPK extraction)',
            'RouterOS 7 NPK format: version byte identifies the package format generation',
        ],
        'recommendation': (
            'Ensure that NPK format version routing in the installer enforces: '
            'if (npk_version < threshold) reject; // disable legacy NPK acceptance in v7 '
            'This prevents downgrade attacks from routing to the SHA1 verification path.'
        ),
        'status': 'INFORMATIONAL',
        'cve':    None,
    },
]
