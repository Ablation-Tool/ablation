"""
AXIS Queue Monitor 3.0.20 (tvqu Rust rewrite) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Queue Monitor 3.0.20 (tvqu Rust), appId 211492
Version: 3.0.20  Arch: aarch64 (ARTPEC-8/7, CV25, S5L)
APPUSR=sdk APPGRP=sdk (ROOT DROPPED from 2.x)

3.x is a Rust rewrite sharing architecture with People Counter 5.x (same crate base).
libsodium NaCl for secrets. Bundled: curl, libcjson.so.1, libmd5.so, libsodium.so.23.
popen still used in gen_allparams_page().
Adds histogram binary files (hval.buf, hvalmin.buf, hvalpeople.buf) for queue analytics.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-QM3"
LABEL = "tvqu 3.x Rust: WebReportUpload SSRF, popen inject, tarslip+histogram, libsodium key"

FINDINGS = [
    {
        "id": "AXIS-QM3-01",
        "severity": "HIGH",
        "title": "SSRF via WebReportUpload0Url + AllowInsecure (operator)",
        "detail": (
            "WebReportUpload0Url is operator-writable. "
            "curl command: CURL_CA_BUNDLE=... curl -L -f --anyauth %s %s -s -m 20 "
            "'%s://%s%s/api/?method=camera.ping&encrypted=true'. "
            "Protocol and host slots from axparam -> SSRF to attacker-controlled server. "
            "WebReportUpload0AllowInsecure=1 + Httppost.AllowInsecure disable TLS check. "
            "WebReportUpload0ProxyEnabled + Proxy param adds proxy hop to SSRF chain."
        ),
        "params": {
            "WebReportUpload0Url": "(operator-writable)",
            "WebReportUpload0AllowInsecure": "0 (set to 1 for TLS bypass)",
            "Httppost.AllowInsecure": "0 (second insecure path)",
        },
        "curl_template": "CURL_CA_BUNDLE=... curl -L -f --anyauth %s %s -s -m 20 '%s://%s%s/api/?method=camera.ping&encrypted=true'",
        "prerequisite": "Operator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-QM3-02",
        "severity": "HIGH",
        "title": "popen shell injection via allparams/parambackup generation (operator)",
        "detail": (
            "gen_allparams_page(): popen — same class as PC5-01. "
            "cd /tmp/; tar czf tvqu-parambackup.tar.gz parambackup.txt params.meta — shell tar. "
            "Operator-writable axparams interpolated into format strings passed to popen() "
            "-> shell injection -> sdk process RCE."
        ),
        "prerequisite": "Operator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-QM3-03",
        "severity": "MEDIUM",
        "title": "Tarslip via .restore_backup — license + histogram binary override",
        "detail": (
            "tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup — tarslip class. "
            "cp /tmp/backup/licbackup.xml /usr/local/packages/tvqu/lic.xml — license override. "
            "cp /tmp/hval.buf /usr/local/packages/tvqu/localdata/hval.buf — histogram override. "
            "Histogram binary files (hval.buf, hvalmin.buf, hvalpeople.buf) control queue analytics output. "
            "Overwriting histograms corrupts queue-length metrics without exploiting any crypto."
        ),
        "cgi": "/.restore_backup (administrator)",
        "histogram_files": ["hval.buf", "hvalmin.buf", "hvalpeople.buf"],
        "prerequisite": "Administrator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-QM3-04",
        "severity": "LOW",
        "title": "folder_password credential in libsodium secrets — key derivation attack",
        "detail": (
            "folder_password axparam migrated to libsodium crypto_secretbox storage "
            "('Migrating parameter %s to secrets'). "
            "If libsodium key is device-derived from known material (serial/MAC): "
            "offline key recovery -> decrypt folder_password -> "
            "gain access to cloud upload target (folder storage, SFTP, cloud storage)."
        ),
        "param": "folder_password",
        "crypto": "libsodium crypto_secretbox",
        "prerequisite": "Physical device access for serial number + libsodium key derivation reverse",
        "status": "UNPATCHED",
        "cve": None,
    },
]
