"""
Cisco UCS XE130C M8 HUU 6.0.2.260143 — Reverse Engineering Module
Source: ucs-xe130cm8-huu-6.0.2.260143.iso (/media/cowboy/research/Cisco-UCS/)
ISO: 498MB, kernel + rootfs.img (squashfs lz4, 140MB) + container squashfs (267MB)
Container structure: squashfs → base.tar.gz (plain gzip) → hsu.tgz.enc (AES inner payload)
"""

FIRMWARE = {
    "target":      "Cisco UCS XE130C M8 HUU 6.0.2.260143",
    "source":      "ucs-xe130cm8-huu-6.0.2.260143.iso",
    "rootfs":      "rootfs.img — squashfs lz4, 140MB, 4741 inodes",
    "container":   "ucs-xe130cm8-huu-container-6.0.2.260143.squashfs — 267MB lz4",
    "inner_enc":   "base.tar.gz → hsu.tgz.enc — AES-256-CBC PBKDF2-SHA256 -nosalt",
    "cimc_version": "6.0(2.260081)",
    "bios_version": "XE1X0M8.6.0.2c.0.0526261754",
    "findings":    ["HUU-XE-F1", "HUU-XE-F2", "HUU-XE-F3"],
}

# ─────────────────────────────────────────────────────────
# HUU-XE-F1: Same AES-256-CBC key 'zfguijkophju@*%1]' — adds -nosalt flag
#             vs C480 M5 and M8 families; cross-generational key scope extends
# ─────────────────────────────────────────────────────────
HUU_XE_F1 = {
    "id":       "HUU-XE-F1",
    "title":    "decrypt-file hardcodes AES-256-CBC key 'zfguijkophju@*%1]' with PBKDF2-SHA256 "
                "and -nosalt — same base password as all M8 and M5 families; -nosalt makes "
                "key derivation deterministic (no per-file salt)",
    "status":   "CONFIRMED — strings /usr/sbin/decrypt-file in rootfs.img; decryption of hsu.tgz.enc verified",
    "severity": "CRITICAL",

    "binary":        "usr/sbin/decrypt-file (ELF 64-bit, stripped)",
    "sha256_binary": "586e3267add8932c6dfb85472df30780572809fb8802ee43b7bd7405524ae666",

    "hardcoded_invocation": (
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s.gz "
        "-k zfguijkophju@*%1] -nosalt 2>&1\n"
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s "
        "-k zfguijkophju@*%1] -nosalt 2>&1"
    ),
    "hardcoded_key":  "zfguijkophju@*%1]",
    "kdf":            "PBKDF2-SHA256 (-md sha256 -pbkdf2 -nosalt)",

    "nosalt_significance": (
        "The -nosalt flag removes the 8-byte random salt that openssl enc normally prepends "
        "to the ciphertext. Without a salt, PBKDF2 runs with an empty salt, meaning the same "
        "password always produces the same derived AES key. "
        "Two encrypted files with identical plaintexts will have identical ciphertexts. "
        "Offline dictionary attacks against the key require no per-file salt extraction step. "
        "C480 M5 (4.2.3r) uses PBKDF2 WITHOUT -nosalt; XE130C M8 adds -nosalt — a regression."
    ),

    "layer_structure": (
        "hsu.tgz.enc is not in the container squashfs directly but embedded 2 layers deep:\n"
        "  container squashfs (267MB)\n"
        "    └─ base.tar.gz (115MB, plain gzip, verified by imgverify before extraction)\n"
        "         └─ hsu.tgz.enc (AES-256-CBC PBKDF2 -nosalt, decrypts to 1.7GB HUU Flask app)"
    ),

    "decryption_verified": (
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -nosalt "
        "-in hsu.tgz.enc -k 'zfguijkophju@*%1]' → 1.7GB gzip tarball containing HUU Flask application. "
        "Successfully decrypted and extracted. Key confirmed identical to other HUU families."
    ),

    "cross_generational_scope": [
        "C480 M5 (4.2.3r)         — HUU-M5-F1 (PBKDF2 without -nosalt)",
        "C220 M8 (6.0.2.260143)   — confirmed in prior analysis (EVP_BytesToKey legacy)",
        "C245 M8 (6.0.2.260180)   — confirmed in prior analysis",
        "XE130C M8 (6.0.2.260143) — HUU-XE-F1 (PBKDF2 with -nosalt, this finding)",
        "UCS Diagnostics 7.1.4.260010 — confirmed in prior analysis",
        "UCS SCU 7.1.7.260200       — confirmed in prior analysis",
    ],
}

# ─────────────────────────────────────────────────────────
# HUU-XE-F2: HUU application nginx.conf (bundled in hsu.tgz.enc) uses 'user root;'
#             — nginx worker processes run as root despite system nginx using 'user www;'
# ─────────────────────────────────────────────────────────
HUU_XE_F2 = {
    "id":       "HUU-XE-F2",
    "title":    "HUU Flask application nginx.conf uses 'user root;' — nginx worker processes run as root "
                "while system-level nginx config at /etc/nginx/nginx.conf uses 'user www;'",
    "status":   "CONFIRMED — hsu/nginx.conf extracted from hsu.tgz.enc in XE130C M8 6.0.2.260143",
    "severity": "HIGH",

    "app_nginx_conf":    "hsu/nginx.conf: user root; (bundled in hsu.tgz.enc)",
    "system_nginx_conf": "/etc/nginx/nginx.conf: user www; (container base.tar.gz)",

    "analysis": (
        "The XE130C M8 HUU uses a layered approach: the system nginx config specifies 'user www;' "
        "but the HUU Flask application overrides this by launching its own nginx instance from "
        "hsu/nginx.conf which specifies 'user root;'. "
        "The application-level nginx runs the HUU Redfish API server as root. "
        "Same pattern as C480 M5 (HUU-M5-F3) but the dual-config obscures the root-user nginx "
        "behind a 'safer-looking' system-level configuration."
    ),

    "same_as": "HUU-M5-F3 (C480 M5) — identical nginx root user finding, same HUU codebase",
}

# ─────────────────────────────────────────────────────────
# HUU-XE-F3: HUU Redfish/REST API endpoints have no authentication in XE130C M8
#             (confirms persistence across XE130C M8 generation)
# ─────────────────────────────────────────────────────────
HUU_XE_F3 = {
    "id":       "HUU-XE-F3",
    "title":    "HUU Redfish REST API Flask app has no authentication middleware in XE130C M8 — "
                "unauthenticated endpoint access persistent across C480 M5 and M8 product families",
    "status":   "CONFIRMED — json_api.py, FirmwareInventory.py, InventoryApi.py in hsu.tgz.enc payload",
    "severity": "CRITICAL",

    "flask_auth": "None — no before_request hook, no BasicAuth, no session check across all API modules",

    "api_modules": [
        "json_api.py",
        "FirmwareInventory.py",
        "InventoryApi.py",
        "LaunchModeService.py",
        "python_api.py",
        "storage_api.py",
    ],

    "verification_improvement": (
        "Unlike C480 M5 (HUU-M5-F2) where imgverify was fully COMMENTED OUT, "
        "XE130C M8 hsu-init actually calls: "
        "'if ! imgverify /tmp/*-container-*-base.tar.gz >> /tmp/imgverify.log 2>&1 "
        "then fatal \"Base container signature verification failed!\"' — "
        "the outer container layer is signature-verified before extraction in XE130C M8. "
        "However the inner hsu.tgz.enc is still AES-encrypted with the hardcoded key, "
        "not signature-verified. Once the outer imgverify passes, the inner payload is "
        "decrypted with the known static key — same attack surface."
    ),

    "same_as": "HUU-M5-F3 (C480 M5) — no auth, nginx root; confirmed persistent across generations",
}

FINDINGS = [HUU_XE_F1, HUU_XE_F2, HUU_XE_F3]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
