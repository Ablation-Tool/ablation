"""
AXIS p-ptz remote connection (remote_ptz_conn_setup) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS p-ptz remote connection (remote_ptz_conn_setup), appId 413658
Version: 1.5.0 (aarch64 ELF PIE unstripped)
Arch: aarch64 (unstripped)
STARTMODE=never (setup tool only, not a persistent daemon)

Provides /axis-cgi/remotecameracontrol/* CGI endpoints for remote PTZ pairing.
setvapixparams.cgi proxies VAPIX param writes to paired remote camera.
If remote camera URL or auth token can be controlled: authenticated SSRF.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-PTZR"
LABEL = "remote_ptz_conn_setup: setvapixparams SSRF, remote camera config leak"

CGI_ENDPOINTS = [
    "/axis-cgi/remotecameracontrol/getvapixparams.cgi",
    "/axis-cgi/remotecameracontrol/getvapixstatus.cgi",
    "/axis-cgi/remotecameracontrol/setvapixparams.cgi",
    "/axis-cgi/ptz/ptzsetactivedrivermode.cgi",
    "/axis-cgi/viewarea/configure.cgi",
]

FINDINGS = [
    {
        "id": "AXIS-PTZR-01",
        "severity": "MEDIUM",
        "title": "setvapixparams.cgi — authenticated SSRF via remote camera parameter write",
        "detail": (
            "setvapixparams.cgi proxies VAPIX configuration parameter writes "
            "to a paired remote camera. Remote camera URL and auth credentials "
            "come from the pairing configuration. "
            "If an attacker can control the remote camera URL or auth token "
            "(via pairing config manipulation at admin level), this CGI becomes "
            "an authenticated SSRF: the local camera makes authenticated VAPIX "
            "write requests to an attacker-controlled or internal remote target."
        ),
        "cgi": "/axis-cgi/remotecameracontrol/setvapixparams.cgi",
        "prerequisite": "Admin-level camera auth; control of pairing config",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PTZR-02",
        "severity": "MEDIUM",
        "title": "getvapixparams.cgi — remote camera config and credential read",
        "detail": (
            "getvapixparams.cgi reads VAPIX parameters from the paired remote camera. "
            "May expose credentials stored in axparameter on the remote camera "
            "(cloud integration passwords, proxy credentials, etc.) "
            "if the remote camera has such params and the read scope is not restricted. "
            "getvapixstatus.cgi additionally exposes remote camera operational state."
        ),
        "cgi": "/axis-cgi/remotecameracontrol/getvapixparams.cgi",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
]
