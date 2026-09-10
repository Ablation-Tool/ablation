"""
Cisco UCS HUU Cross-Model RE Module — C220 M8, C245 M8, C480 M5
Sources (all /media/cowboy/research/Cisco-UCS/):
  ucs-c220m8-huu-6.0.2.260143.iso  (1.3GB) — C220 M8 HUU 6.0.2.260143
  ucs-c245m8-huu-6.0.2.260180.iso  (1.3GB) — C245 M8 HUU 6.0.2.260180
  ucs-c480m5-huu-4.2.3r.iso        (741MB) — C480 M5 HUU 4.2.3r

Analysis method:
  - Mount ISO, extract squashfs container
  - C220/C245: base.tar.gz contains full Linux rootfs + /root/hsu.tgz.enc
  - C480: squashfs IS the full Linux rootfs + /root/hsu.tgz.enc
  - All: decrypt-file at /usr/sbin/decrypt-file — PBKDF2 AES-256-CBC key extracted via `strings`
  - hsu.tgz.enc decrypted → Flask/gunicorn HUU app (hsu_wsgi:app)

Combined with prior analysis of ucs-xe130cm8-huu-6.0.2.260143.iso (module: cisco_ucs_huu_xe130cm8_602_re.py).
Total confirmed: 4 HUU ISOs across 3 server generations and 2 firmware version lines.
"""

FIRMWARE = {
    "targets": [
        {"model": "UCS C220 M8", "version": "6.0.2.260143", "source": "ucs-c220m8-huu-6.0.2.260143.iso"},
        {"model": "UCS C245 M8", "version": "6.0.2.260180", "source": "ucs-c245m8-huu-6.0.2.260180.iso"},
        {"model": "UCS C480 M5", "version": "4.2.3r",       "source": "ucs-c480m5-huu-4.2.3r.iso"},
    ],
    "also_confirmed_in": "ucs-xe130cm8-huu-6.0.2.260143.iso (cisco_ucs_huu_xe130cm8_602_re.py)",
    "decrypt_file_hashes": {
        "C245 M8 6.0.2": "93a0ae39fafe748bc1abecfcf7332a4c",
        "C480 M5 4.2.3r": "9fbe7c32cda03774343631036ac671a5",
    },
    "findings": ["HUU-CROSS-F1", "HUU-C480-F1", "HUU-C480-F2"],
}

# ─────────────────────────────────────────────────────────
# HUU-CROSS-F1: PBKDF2 key "zfguijkophju@*%1]" confirmed in ALL four HUU ISOs
#               — spans 3 server generations (C220/C245/C480/XE130C), 2 version lines (4.2.3r, 6.0.2)
#               — decrypt-file binary differs per ISO but key string is identical
# ─────────────────────────────────────────────────────────
HUU_CROSS_F1 = {
    "id":       "HUU-CROSS-F1",
    "title":    "Hardcoded PBKDF2 AES-256 key 'zfguijkophju@*%1]' in decrypt-file binary confirmed in "
                "all 4 tested UCS HUU ISOs spanning 3 server generations and firmware versions 4.2.3r–6.0.2",
    "status":   "CONFIRMED — strings /usr/sbin/decrypt-file in C220 M8 6.0.2, C245 M8 6.0.2, "
                "C480 M5 4.2.3r, XE130C M8 6.0.2 (4 independent ISOs)",
    "severity": "CRITICAL",

    "key":  "zfguijkophju@*%1]",

    "decrypt_command": (
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in /root/hsu.tgz.enc "
        "-out hsu.tgz -k 'zfguijkophju@*%1]' -nosalt"
    ),

    "confirmed_in": {
        "ucs-xe130cm8-huu-6.0.2.260143":  "XE130C M8 — prior module cisco_ucs_huu_xe130cm8_602_re.py",
        "ucs-c220m8-huu-6.0.2.260143":    "C220 M8 6.0.2 — CONFIRMED, decrypt succeeds",
        "ucs-c245m8-huu-6.0.2.260180":    "C245 M8 6.0.2 — CONFIRMED, decrypt succeeds, hsu.tgz 46MB",
        "ucs-c480m5-huu-4.2.3r":          "C480 M5 4.2.3r — CONFIRMED, decrypt succeeds, hsu.tgz 7.3MB",
    },

    "decrypt_file_binary_versions": (
        "The decrypt-file binaries have different MD5 hashes across ISOs "
        "(C245: 93a0ae39..., C480: 9fbe7c32...) — the binary was rebuilt per model/version — "
        "but the embedded key string is identical in all four. "
        "The key is not a model-specific default; it is a shared codebase constant "
        "present for at least the span of firmware versions 4.2.3r (2021-era) through 6.0.2 (2026). "
        "This is a minimum 3-year deployment window for the same static key."
    ),

    "impact": (
        "Any party who has extracted this key from any UCS HUU ISO — including the prior finding "
        "in XE130C M8 — can decrypt the hsu.tgz.enc Flask application package from ANY UCS HUU ISO. "
        "The decrypted app contains the full HUU web application source (Python, Flask blueprints, "
        "Redfish API handler, firmware update logic, inventory enumeration, diagnostics). "
        "This allows: (1) offline audit of all HUU API endpoints for vulnerabilities, "
        "(2) re-encryption of a modified HUU app with the same key to produce a trojanized ISO, "
        "(3) cross-model applicability — an attacker who obtains the key from any publicly available "
        "HUU ISO gains decryption capability against all other UCS server models."
    ),

    "huu_app_structure": {
        "C245_M8_6.0.2": "hsu_wsgi.py → app.py (Flask) → HuuApp, RedfishApp, InventoryApp, SduApp, ConfigApp blueprints",
        "C480_M5_4.2.3r": "hsu_wsgi.py → hsu_wsgi (gunicorn WSGI) → Redfish.py, RedfishUtils.py",
        "auth_state": "No HTTP authentication on gunicorn (127.0.0.1:8000). nginx proxy on :80 has no auth_basic. "
                      "HUU is designed to run air-gapped on-server but the no-auth posture confirmed across all models.",
    },
}

# ─────────────────────────────────────────────────────────
# HUU-C480-F1: tsa_ucs ELF binary in C480 M5 has full debug symbols + tsa_execute_command export
#              + uses deprecated SSLv23_client_method (allows SSLv3 downgrade)
# ─────────────────────────────────────────────────────────
HUU_C480_F1 = {
    "id":       "HUU-C480-F1",
    "title":    "C480 M5 HUU tsa_ucs binary ships with full debug symbols and exports tsa_execute_command — "
                "TSA RPC agent on CIMC management plane with SSLv23_client_method (permits SSLv3 handshake)",
    "status":   "CONFIRMED — /opt/cisco/tsa_ucs in ucs-c480m5-huu-4.2.3r.squashfs",
    "severity": "MEDIUM",

    "binary_metadata": {
        "path":      "/opt/cisco/tsa_ucs",
        "type":      "ELF 64-bit LSB executable, x86-64, dynamically linked",
        "symbols":   "NOT stripped — full symbol table present (debug_info=yes)",
        "linked_to": "libssl.so.10 (OpenSSL 1.0.x)",
        "build_id":  "00e311700820e85d828a8c93398b7b3e6726f12e",
    },

    "exported_functions": {
        "tsa_execute_command": "0x0040453b — execute arbitrary command via TSA RPC channel",
        "tsa_rpc_execute":     "0x0040a74a — generic RPC execution",
        "tsa_request_send":    "0x004092cc — send TSA request to management plane",
        "tsa_lib_open":        "0x00409e46 — open TSA library session",
        "tsa_keep_alive":      "0x0040a931 — session keepalive",
        "huu_write_file":      "0x004083d7 — write arbitrary file via HUU TSA channel",
        "huu_read_file":       "0x00407da0 — read arbitrary file via HUU TSA channel",
        "huu_get_nvmeslot":    "0x004078a0 — enumerate NVMe slots",
        "huu_get_m2driveslot": "0x00407b20 — enumerate M.2 slots",
    },

    "ssl_issue": (
        "tsa_ucs calls SSLv23_client_method() (deprecated in OpenSSL 1.0, removed in 1.1). "
        "The cipher string in the binary: 'AES128:HIGH:!3DES:!SSLv2:!eNULL:!aNULL:!PSK:!SRP' "
        "excludes SSLv2 but does NOT exclude SSLv3. With SSLv23_client_method and SSLv3 not "
        "explicitly disabled, a POODLE-capable MITM on the management network can downgrade "
        "the TSA connection to SSLv3 and decrypt traffic. "
        "This is the CIMC management plane connection — TSA manages firmware/file operations on the BMC."
    ),

    "debug_symbol_impact": (
        "The full symbol table provides a complete API map for the TSA RPC protocol: "
        "all function names, addresses, and argument patterns are visible via nm. "
        "tsa_execute_command at 0x40453b is a direct RPC execution primitive. "
        "An attacker with access to the HUU environment (on-server or via network if "
        "HUU is accessible remotely) can reverse the full TSA protocol from symbols alone "
        "without needing a firmware debugger or source code."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU-C480-F2: biosup and fwup in tools/cisco/utils/ encrypted with OpenSSL + SALT (distinct key)
#              — separate encryption key not present in any extracted binary
# ─────────────────────────="C480 M5 HUU 4.2.3r — salted encrypted tool binaries"
# ─────────────────────────────────────────────────────────
HUU_C480_F2 = {
    "id":       "HUU-C480-F2",
    "title":    "C480 M5 HUU tools/cisco/utils/biosup and fwup are OpenSSL-encrypted with salted password "
                "(distinct key from hsu.tgz.enc PBKDF2 key) — key not found in any extracted binary",
    "status":   "CONFIRMED — file command returns 'openssl enc\\'d data with salted password' for both; "
                "PBKDF2 key 'zfguijkophju@*%1]' does NOT decrypt them",
    "severity": "LOW",

    "encrypted_files": {
        "/tools/cisco/utils/biosup": "openssl enc'd data with salted password — BIOS update utility",
        "/tools/cisco/utils/fwup":   "openssl enc'd data with salted password — firmware update utility",
    },

    "analysis": (
        "The tools/cisco/utils/ directory contains two encrypted binaries (biosup, fwup) used by the "
        "HUU firmware update pipeline. These use the OpenSSL legacy salted encryption format "
        "(-salt, default EVP_BytesToKey KDF) rather than PBKDF2. "
        "The decrypt-file binary's embedded key ('zfguijkophju@*%1]') does not decrypt these files. "
        "A separate key is used, likely embedded in tsa_ucs or distributed via an encrypted config. "
        "The `huu_write_file` export in tsa_ucs suggests these tools may be decrypted on-demand "
        "by the TSA layer rather than by the HUU app directly. "
        "Key has not been recovered; the asymmetry in key schemes between hsu.tgz.enc (PBKDF2) "
        "and these tools (salted) suggests they were encrypted by different build pipelines."
    ),

    "note": (
        "This pattern of layered encryption (PBKDF2 for the app, salted for the tools) "
        "exists ONLY in the C480 M5 4.2.3r HUU. "
        "The 6.0.2 HUUs (C220/C245/XE130C M8) do not have encrypted binaries in the tools/ directory — "
        "they store catalog-referenced firmware binaries unencrypted."
    ),
}

C480_NOTES = {
    "python_version": "Python 2.7 + Python 3.5 (C480 M5 4.2.3r vs Python 3.13 in 6.0.2 HUUs)",
    "nginx_config": (
        "Nginx port 80, root /var/www/localhost/html — "
        "HUU app served via gunicorn (init-huu.sh: hsu_wsgi:app, 127.0.0.1:8000)"
    ),
    "shadow_accounts": "All accounts locked (*) or nologin (!); no crackable hashes in shadow",
}

FINDINGS = [HUU_CROSS_F1, HUU_C480_F1, HUU_C480_F2]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
