"""
AXIS Radar Data Visualizer (radardatavisualizer) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Radar Data Visualizer (radardatavisualizer), appId 414283
Version: 3.3.2  Arch: aarch64 stripped
CGI: administrator /control.cgi, viewer /consume.cgi

Renders radar detection zones on video stream using cairo + libresvg.so.0 (Rust SVG renderer).
Bundles: libresvg.so.0.35.0, libcairo.so.2, libcurl.so.4.8.0, libpango-1.0.so.0, libgstreamer-1.0.so.0
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-RDV"
LABEL = "radardatavisualizer: viewer radar exposure, SVG path injection, libcurl SSRF"

FINDINGS = [
    {
        "id": "AXIS-RDV-01",
        "severity": "MEDIUM",
        "title": "Viewer-level radar target data exposure via /consume.cgi",
        "detail": (
            "/consume.cgi is viewer-accessible (lowest camera privilege). "
            "Provides radar visualization data: detected objects, zones, speed estimates. "
            "axo_match_stream_id + vdo_stream_get stream video with radar overlay to viewer. "
            "All radar targets on camera accessible to any viewer-level user without operator/admin auth. "
            "Radar data includes: object positions, velocities, zone assignments, speed readings."
        ),
        "cgi": "/consume.cgi (viewer-accessible)",
        "prerequisite": "Viewer-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-RDV-02",
        "severity": "MEDIUM",
        "title": "SVG file path injection via axparam — resvg file read / crash",
        "detail": (
            "'Failed to parse SVG file %s: %d' — %s is SVG file path from config. "
            "If SVG file path comes from admin-writable axparam: "
            "set to /etc/passwd or other sensitive file -> libresvg.so.0 (Rust) "
            "attempts to parse file as SVG -> error message may include file content "
            "or trigger resvg crash via unexpected content. "
            "Adversarial SVG files: even Rust-based renderer subject to SVG complexity attacks "
            "(deep nesting, recursive patterns, path length extremes)."
        ),
        "prerequisite": "Admin-level axparam write to SVG path config",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-RDV-03",
        "severity": "MEDIUM",
        "title": "libcurl SSRF via radar sensor connection URL",
        "detail": (
            "radardatavisualizer connects to radar sensor for data feed. "
            "If sensor connection URL is operator/admin-configurable via axparam "
            "and fed to bundled libcurl.so.4.8.0: "
            "SSRF to attacker-controlled RTSP or HTTP endpoint. "
            "Connection metadata (camera IP, User-Agent, request path) leaks to attacker server."
        ),
        "lib": "libcurl.so.4.8.0 (bundled)",
        "prerequisite": "Operator or admin axparam write to radar sensor URL",
        "status": "UNPATCHED",
        "cve": None,
    },
]
