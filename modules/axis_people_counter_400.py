"""
AXIS People Counter 4.0.0 / S5L variant (tvpc) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS People Counter 4.0.0 (tvpc), appId 211490
Version: 4.0.0  Arch: aarch64 stripped (S5L / ARTPEC-5 variant)

Key difference from 4.6.110: TrueviewVAPIX VAPIX account NOT removed in postinst.
4.6.110 explicitly removes TrueviewVAPIX account at install; 4.0.0 does not.
Any 4.0.0 deployment may retain TrueviewVAPIX account with default/weak VAPIX password.

Bundled: curl (armhf binary), apache.conf, install_stream_profile.sh.
NTP manipulation: postinst.sh installs custom NTP (NTPD_ARGS=-r -t 60).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-PC40"
LABEL = "tvpc 4.0.0: TrueviewVAPIX default account, TCP 23456, tarslip"

FINDINGS = [
    {
        "id": "AXIS-PC40-01",
        "severity": "CRITICAL",
        "title": "TrueviewVAPIX default VAPIX account persists on 4.0.0 cameras",
        "detail": (
            "TrueviewVAPIX VAPIX service account NOT removed in 4.0.0 postinst.sh. "
            "4.6.110 explicitly removes this account; 4.0.0 leaves it active. "
            "Any 4.0.0 People Counter installation may retain TrueviewVAPIX account "
            "with default or guessable VAPIX password. "
            "Chain: enumerate TrueviewVAPIX user -> try default password -> "
            "VAPIX admin-level access -> full camera control. "
            "Attack: find camera with People Counter 4.0.0 installed -> VAPIX admin."
        ),
        "account": "TrueviewVAPIX",
        "affected": "4.0.0 (not patched until postinst in 4.6.110)",
        "prerequisite": "Camera network access; People Counter 4.0.0 installed",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC40-02",
        "severity": "HIGH",
        "title": "TCP 23456 unauthenticated event injection (inherited from 4.6.110)",
        "detail": (
            "Counter0EventListenerPort=23456 confirmed in 4.0.0 param.conf. "
            "Same raw TCP event inject surface as 4.6.110 (PC-03). "
            "Any LAN host can inject synthetic passage events without authentication. "
            "False people-count data corrupts occupancy/flow analytics."
        ),
        "port": 23456,
        "prerequisite": "Network access to camera TCP 23456",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC40-03",
        "severity": "HIGH",
        "title": "Backup tarslip via restore path (inherited from 4.6.110)",
        "detail": (
            "cd /tmp/; tar czf tvpc-parambackup.tar.gz ... — same tarslip class as 4.6.110. "
            "Backup restore CGI performs tar extraction without path traversal mitigation. "
            "Operator-level access: upload malicious tar.gz -> arbitrary file write."
        ),
        "prerequisite": "Operator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
]
