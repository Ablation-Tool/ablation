"""
AXIS People Counter 5.0.5 (tvpcrs Rust rewrite) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS People Counter 5.0.5 (tvpc Rust), appId 211490
Version: 5.0.5  Arch: aarch64 (ARTPEC-8/CV25/S5L/ARTPEC-7)
APPUSR=sdk APPGRP=sdk (ROOT DROPPED from 4.x — reduced blast radius)

5.x is a Rust rewrite of tvpc daemon (crate: tvpcrs).
Runtime: Rust async-executor, zbus D-Bus (DBUS_COOKIE_SHA1 auth), libsodium NaCl.
TCP 23456 and TCP 4066 still present in 5.x despite Rust rewrite.
popen still used in gen_allparams_page().
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-PC5"
LABEL = "tvpc 5.x Rust: popen inject, tarslip, TCP 23456/4066, VAPIX creds D-Bus"

FINDINGS = [
    {
        "id": "AXIS-PC5-01",
        "severity": "HIGH",
        "title": "popen shell injection via allparams generation (operator)",
        "detail": (
            "gen_allparams_page() calls popen() in Rust tvpcrs. "
            "Shell command: cd /tmp/; tar czf tvpc-parambackup.tar.gz parambackup.txt params.meta. "
            "Operator-writable axparameter values may be interpolated into format strings "
            "passed to popen() -> shell injection -> sdk process RCE. "
            "Same class as PC-01 in 4.x; blast radius reduced: sdk sandbox vs root."
        ),
        "cgi": "/.apioperator (operator)",
        "prerequisite": "Operator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC5-02",
        "severity": "MEDIUM",
        "title": "Tarslip via .restore_backup (administrator) — license + sdk sandbox write",
        "detail": (
            "tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup — tarslip class. "
            "cp /tmp/backup/licbackup.xml /usr/local/packages/tvpc/lic.xml — license override. "
            "Writes attacker-controlled files to /tmp/backup and copies lic.xml to ACAP package dir. "
            "Runs as sdk (APPUSR): impact is ACAP package dir control, not full camera takeover. "
            "Same vector as 4.x but blast radius reduced."
        ),
        "cgi": "/.restore_backup (administrator)",
        "prerequisite": "Administrator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC5-03",
        "severity": "MEDIUM",
        "title": "TCP 23456 unauthenticated event listener — still present in 5.0.5",
        "detail": (
            "Counter0EventListenerPort=23456 confirmed in param.conf. "
            "Counter.SlavePort/MasterPort strings in binary. "
            "TCP 23456 passage event injection still accepted from any LAN host without auth. "
            "Rust rewrite preserved this legacy attack surface intact. "
            "Sends false people-count data -> corrupts occupancy analytics."
        ),
        "port": 23456,
        "prerequisite": "Network access to camera TCP 23456",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC5-04",
        "severity": "LOW",
        "title": "TCP 4066 master/slave sync — still present; SlavePass now libsodium-encrypted",
        "detail": (
            "Counter.SlavePort=4066 in binary; Counter0SlavePort in param.conf. "
            "SlavePass migrated to libsodium crypto_secretbox storage "
            "('Migrating parameter %s to secrets'). "
            "If libsodium key is derivable from device-specific material (serial/MAC): "
            "slave auth bypass still possible. "
            "Counter0SlaveAddress SSRF still applicable: attacker-controlled SlaveAddress "
            "redirects sync to rogue master."
        ),
        "port": 4066,
        "prerequisite": "Network access to TCP 4066 + libsodium key derivation",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC5-05",
        "severity": "MEDIUM",
        "title": "VAPIX credentials via D-Bus sniffable by co-resident ACAP",
        "detail": (
            "tvpcrs::local_vapix fetches LocalVapixCredentials via D-Bus. "
            "Credential used for internal VAPIX calls: 'Authorization: Bearer %s'. "
            "D-Bus session accessible to co-resident ACAPs on same camera. "
            "Co-resident ACAP sniffs D-Bus -> captures VAPIX bearer token -> "
            "uses token for direct VAPIX API calls at tvpc's privilege level."
        ),
        "dbus_call": "tvpcrs::local_vapix / LocalVapixCredentials",
        "prerequisite": "Co-resident ACAP on same camera with D-Bus session access",
        "status": "UNPATCHED",
        "cve": None,
    },
]
