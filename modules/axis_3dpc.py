"""
AXIS 3D People Counter (a3dpc) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS 3D People Counter (a3dpc), appId 211491
Version: 1.8.3 (MIPS32 mipsisa32r2el, not stripped, debug info)
Arch: MIPS32 little-endian (mipsisa32r2el) + Python 2.7 via pyrun

Architecture: a3dpc is a C stub; core logic in Python 2.7 (EOL) via pyrun (4.5MB self-contained).
Apache reverse proxies /stereo/* to Python app at localhost:50000.
libwrapper.so (5.5MB) wraps stereo depth-sensing algorithm.

Critical: admin-level /cmd/install endpoint may accept EAP URL -> install malicious ACAP.
Flask routes in Python code include /../ path traversal constant.
Hardcoded credential: admin:1password23 in pyc string constants.
Developer home path leaked: /home/gustafo/3dcounter/package/
curl --fail --connect-timeout 10 --insecure used for ACAP download (TLS not verified).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-A3DPC"
LABEL = "a3dpc: admin EAP install RCE, hardcoded cred, Python 2.7 EOL, path traversal"

FLASK_ROUTES = [
    "/anonymize/anonymize", "/anonymize/anonymized.json", "/anonymize/reset",
    "/awb/<key>.csv", "/awb/clear/<key>",
    "/axis-cgi/mjpg/video.cgi",
    "/calibrate/start", "/calibrate/stop", "/calibrate/clear",
    "/config.json", "/config/video.json", "/configure.html",
    "/counts.json", "/data/clear",
    "/debug_download", "/debug_download_prepare", "/debug/log/<level>",
    "/export_meta.json", "/export_raw.%s",
    "/fake/down", "/fake/up",
    "/full_zone_params_recalculation.json",
    "/params.json",
    "/temporary_api/snr", "/temporary_api/zone",
]

FINDINGS = [
    {
        "id": "AXIS-A3DPC-01",
        "severity": "HIGH",
        "title": "Admin CGI package install/download — RCE via malicious EAP URL",
        "detail": (
            "Admin-level endpoints at localhost:50000 (proxied via Apache): "
            "/cmd/install, /cmd/download, /cmd/upgrade, /cmd/purge. "
            "Binary: g_spawn_async_with_pipes used for subprocess execution "
            "('Executing \\'%s\\'' log message). "
            "curl --fail --connect-timeout 10 --insecure used for download (TLS not verified). "
            "DOWNLOAD_URL param controls download source (default https://www.axis.com/r/ redirector). "
            "If /cmd/install accepts attacker-controlled URL (via DOWNLOAD_URL axparam), "
            "install malicious EAP -> persistent code execution as ACAP user."
        ),
        "cgi": "/cmd/install, /cmd/download (admin)",
        "curl_flags": "curl --fail --connect-timeout 10 --insecure",
        "download_url_default": "https://www.axis.com/r/",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-A3DPC-02",
        "severity": "MEDIUM",
        "title": "Proxy password plaintext logging: 'GOT proxy_password: %s'",
        "detail": (
            "'GOT proxy_url: %s' and 'GOT proxy_password: %s' format strings in a3dpc binary. "
            "Proxy credentials logged at debug level to stdout/syslog. "
            "If logging enabled: proxy credential in syslog or /tmp log file. "
            "Readable by co-resident ACAP or via backup/tarslip chain."
        ),
        "log_strings": ["GOT proxy_url: %s", "GOT proxy_password: %s"],
        "prerequisite": "Read access to syslog or debug log output",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-A3DPC-03",
        "severity": "MEDIUM",
        "title": "X-Forwarded-User spoofing from co-resident ACAP",
        "detail": (
            "Apache config: RequestHeader unset Authorization (strips auth). "
            "RewriteRule injects X-Forwarded-User from REMOTE_USER env var. "
            "Python app at localhost:50000 trusts X-Forwarded-User as user identity. "
            "If another ACAP on the camera can make loopback requests to 50000 with "
            "a custom X-Forwarded-User header, Python app processes it as arbitrary user."
        ),
        "prerequisite": "Co-resident ACAP with loopback HTTP access to localhost:50000",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-A3DPC-04",
        "severity": "MEDIUM",
        "title": "Depth frame exfiltration via /stereo viewer endpoint",
        "detail": (
            "Apache proxies /stereo/* to http://127.0.0.1:50000 after unsetting Authorization. "
            "Python app may serve raw stereo depth map frames at viewer access level. "
            "3D scene reconstruction from depth maps: privacy violation beyond standard 2D video. "
            "libwrapper.so processes stereo depth frames — if /stereo endpoint exposes raw output, "
            "attacker with viewer auth reconstructs 3D scenes."
        ),
        "prerequisite": "Viewer-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
]

HARDCODED_ARTIFACTS = {
    "credential": "admin:1password23 (from pyc string constants in Python app)",
    "dev_path": "/home/gustafo/3dcounter/package/ (developer home in binary strings)",
    "path_traversal_constant": "/../ present as string constant in app_api.pyc",
    "python_version": "2.7 (EOL 2020-01-01)",
    "subprocess_import": "subprocess.Popen imported in app_api.pyc",
    "postinst_injection": "parhandclient --nocgi set root.Network.Bonjour.FriendlyName with camera serial/product name interpolated without quoting",
}
