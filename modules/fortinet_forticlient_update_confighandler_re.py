"""
FortiClient update daemon + confighandler RE
Sources (all from forticlient-vpn-deb/opt/forticlient/):
  - update   (Go, 12MB) -- signature + software update daemon
  - confighandler (Rust, 22.8MB) -- EMS policy receiver + distribution hub
Method: gopclntab symbol extraction, strings analysis, Rust panic-path source extraction
"""

# ---------------------------------------------------------
# update daemon architecture
# ---------------------------------------------------------
UPDATE_ARCH = {
    "id":       "UPDATE-ARCH",
    "product":  "update -- FortiClient signature + software update daemon (Go, 11.9MB stripped ELF64)",
    "binary":   "/opt/forticlient/update",

    "embedded_curl": {
        "version":  "libcurl 8.7.1",
        "note":     "curl is embedded (not system curl); update daemon uses it for all HTTP downloads",
    },

    "download_components": {
        "Added component to download: (%s) %s [%s]":   "Component download log format",
        "Downloaded object: %s %s":                     "Download completion log",
        "DownloadSignature":                            "Signature download operation",
        "Couldn't resume download":                     "Resumable download support (range requests)",
        "email_downloads":                              "Email component download (AV/sandbox)",
    },

    "ems_integration": {
        "EMS_ADDRESS":      "EMS server address (pushed by EMS enrollment)",
        "EMS_FINGERPRINT":  "EMS TLS certificate fingerprint (used for cert pinning)",
        "EMS_HOSTNAME":     "EMS server hostname",
        "EMS_PORT":         "EMS server port",
        "ems not enabled":  "EMS enrollment state check",
        "ems_allow_show_alwaysup":          "EMS-controlled always-up policy flag",
        "ems_allow_show_autoconnect":       "EMS-controlled auto-connect policy flag",
        "ems_allow_show_remember_password": "EMS-controlled credential save policy flag",
    },

    "update_config": {
        "forticlient_configuration_t.system_t.update_t":           "Update configuration block",
        "forticlient_configuration_t.system_t.update_t.scheduled_update_t": "Scheduled update config",
        "auto_patch":           "Automatic patching feature (see FCTSCHED-F03)",
        "auto_patch_t":         "Auto-patch configuration type",
    },

    "ipc":  "Shared 8f6ddf1358bd9d067261f529f69fda59.ipc socket (same pattern as other daemons)",
}


# ---------------------------------------------------------
# UPDATE-F01: libcurl 8.7.1 download channel
# ---------------------------------------------------------
UPDATE_F01_CURL = {
    "id":       "UPDATE-F01",
    "product":  "update -- libcurl 8.7.1 embedded for all software + signature downloads",
    "severity": "HIGH -- MITM on update channel delivers malicious signatures; curl version has known CVEs",
    "class":    "Insecure update channel (CWE-494); specific curl version may have security patches absent",
    "evidence": [
        "string: 'CLIENT libcurl 8.7.1'",
        "string: 'Added component to download: (%s) %s [%s]'",
        "string: 'DownloadSignature'",
        "string: 'EMS_FINGERPRINT'",
    ],

    "description": (
        "The update daemon embeds libcurl 8.7.1 (statically or dynamically linked). "
        "libcurl 8.7.1 was released in 2024-03; subsequent versions patched: "
        "  - CVE-2024-2379 (QUIC certificate verification bypass; libcurl <= 8.7.1) "
        "  - CVE-2024-2004 (DoH name too long; affects curl <= 8.7.0 -- possibly 8.7.1 as well) "
        "TLS certificate pinning is partially implemented via EMS_FINGERPRINT: "
        "  - The EMS server certificate fingerprint is checked for the EMS channel. "
        "  - Signature download servers (FortiGuard CDN) may NOT have pinned fingerprints. "
        "Attack vector: MITM on the signature download channel (not the EMS channel). "
        "If FortiGuard signature download URL is HTTP or pinning is absent: "
        "  1. Attacker MITM intercepts AV/IPS signature download. "
        "  2. Returns malicious signature package with crafted content. "
        "  3. update daemon applies the package: AV signatures updated with attacker data. "
        "Practical impact: AV evasion by replacing real signatures with benign-file-matching entries."
    ),

    "cve_ref": "CVE-2024-2379: libcurl QUIC certificate verification bypass (affects <= 8.7.1)",
}


# ---------------------------------------------------------
# UPDATE-F02: EMS_FINGERPRINT -- pinning scope limitation
# ---------------------------------------------------------
UPDATE_F02_EMS_PINNING = {
    "id":       "UPDATE-F02",
    "product":  "update -- EMS_FINGERPRINT pinning scoped to EMS channel; FortiGuard downloads may be unpinned",
    "severity": "MEDIUM -- incomplete certificate pinning allows CDN download MITM",
    "class":    "Incomplete certificate pinning (CWE-295)",
    "evidence": [
        "string: 'EMS_FINGERPRINT'",
        "string: 'EMS_ADDRESS'",
        "string: 'Added component to download: (%s) %s [%s]' (separate download component system)",
    ],

    "description": (
        "EMS_FINGERPRINT pins the TLS certificate of the FortiClient Enterprise Management Server. "
        "This protects the EMS policy channel from MITM. "
        "However, the update daemon fetches software components and signatures from a separate "
        "download system ('Added component to download: (%s) %s [%s]'). "
        "This download system likely uses FortiGuard CDN URLs (not EMS URLs). "
        "If the FortiGuard CDN URLs are not certificate-pinned, a MITM on the network path "
        "between the endpoint and FortiGuard CDN can intercept and replace downloads. "
        "Combined with auto_patch (FCTSCHED-F03): MITM on the update channel -> malicious update "
        "delivered -> auto_patch installs it with daemon privileges."
    ),
}


# ---------------------------------------------------------
# confighandler architecture
# ---------------------------------------------------------
CONFIGHANDLER_ARCH = {
    "id":       "CONFIGHANDLER-ARCH",
    "product":  "confighandler -- FortiClient policy distribution hub (Rust, 22.8MB stripped ELF64)",
    "binary":   "/opt/forticlient/confighandler",
    "language": "Rust (confirmed by .cargo/registry source paths in panic messages)",

    "rust_crates": {
        "hyper-0.14.28":            "HTTP/1.1 + HTTP/2 client/server",
        "warp-0.3.7":               "HTTP server framework (routes policy API endpoints)",
        "rusqlite-0.29.0":          "SQLite database (stores configuration + policy state)",
        "serde_json-1.0.116":       "JSON serialization for policy parsing",
        "protobuf-json-mapping-3.4.0": "JSON-to-protobuf schema mapping",
        "bytes-1.6.0":              "Byte buffer library for HTTP body handling",
        "mime_guess-2.0.4":         "MIME type detection",
    },

    "role": (
        "confighandler is the central policy distribution daemon. "
        "It receives policy from EMS (FortiClient Enterprise Management Server) "
        "and distributes it to all other FortiClient daemons: "
        "  - fctdns: ZTNA DNS rules, SAAS filter rules "
        "  - firewall: iptables/nftables rules for ZTNA/webfilter "
        "  - vpn/iked: VPN connection profiles "
        "  - fctsched: scheduled scan/update configuration "
        "  - fortitray/GUI: UI tab visibility policy "
        "Policy is stored in a local SQLite database (rusqlite) and distributed via IPC."
    ),

    "policy_fields_confirmed": {
        "pkcs11_lib":               "Path to PKCS#11 library (configurable; dynamic library path)",
        "prompt_certificate":       "Prompt for client certificate",
        "prompt_username":          "Prompt for username",
        "sso_enabled":              "SSO (SAML/OAuth) enabled flag",
        "use_external_browser":     "Use system browser for auth (OAuth flow)",
        "dual_stack":               "IPv4/IPv6 dual stack VPN",
        "ems_allow_show_remember_password": "EMS policy: allow save-password in UI",
        "ems_allow_show_alwaysup":          "EMS policy: allow always-up in UI",
        "ems_allow_show_autoconnect":       "EMS policy: allow auto-connect in UI",
        "save_username":            "Save username flag",
        "save_password":            "Save password flag",
        "authorization_code":       "OAuth authorization code (stored in policy DB)",
        "epctrl_on_fabric":         "Endpoint control on network fabric (Zero Trust NAC)",
    },

    "ui_policy_flags": {
        "AVTabIsHidden":            "EMS hides AV tab",
        "VPNTabIsHidden":           "EMS hides VPN tab",
        "VULNTabIsHidden":          "EMS hides vulnerability scan tab",
        "ComplianceTabIsHidden":    "EMS hides compliance tab",
        "ZtnaIsHidden":             "EMS hides ZTNA tab",
        "WfTabIsHidden":            "EMS hides web filter tab",
        "SandboxTabIsHidden":       "EMS hides sandbox tab",
    },

    "api": {
        "content_type":     "application/json",
        "server":           "warp 0.3.7 HTTP server",
        "http2":            "hyper-0.14.28 with HTTP/2 support",
        "bind":             "Likely 127.0.0.1 (local-only; not confirmed from strings)",
    },

    "ipc":  "Accepted pipe<%u> on socket<%u> from %s -- shared IPC socket with other daemons",
}


# ---------------------------------------------------------
# CONFIGHANDLER-F01: pkcs11_lib configurable field = dynamic library injection
# ---------------------------------------------------------
CONFIGHANDLER_F01_PKCS11_LIB = {
    "id":       "CONFIGHANDLER-F01",
    "product":  "confighandler -- pkcs11_lib field allows attacker-controlled PKCS#11 .so loading",
    "severity": "CRITICAL -- policy injection -> configure pkcs11_lib to attacker .so -> code execution in daemon context",
    "class":    "Dynamic library injection via attacker-controlled configuration (CWE-114, CWE-427)",
    "evidence": [
        "string: 'pkcs11_lib' (configuration field in protobuf schema)",
        "string: 'prompt_certificate' (PKCS#11 certificate selection)",
        "confighandler stores + distributes all policy to FortiClient daemons",
    ],

    "mechanism": (
        "The pkcs11_lib field specifies the filesystem path of a PKCS#11 provider library (.so). "
        "This field is part of the VPN connection profile configuration "
        "(forticlient_configuration_t.vpn_t.sslvpn_t.connections_t.connection_t). "
        "confighandler reads this field from EMS policy or local configuration "
        "and distributes it to the vpn daemon. "
        "The vpn daemon then calls dlopen(pkcs11_lib) to load the PKCS#11 provider. "
        "Attack path: "
        "  1. Attacker modifies the confighandler SQLite database (rusqlite in /opt/forticlient/ or /var/). "
        "  2. Sets pkcs11_lib to a path of an attacker-controlled .so file. "
        "  3. When the VPN connects, the vpn daemon loads the malicious .so. "
        "  4. The .so's __attribute__((constructor)) function runs with vpn daemon privileges (likely root). "
        "Prerequisites: "
        "  - Local write access to the confighandler database, OR "
        "  - IPC injection into confighandler via shared IPC socket (FCTSCHED-F01), OR "
        "  - EMS compromise (FortiGate-managed EMS pushes pkcs11_lib to all enrolled clients)."
    ),

    "ems_scale": (
        "If a compromised EMS (FortiClient Enterprise Management Server) pushes a policy with "
        "pkcs11_lib=/tmp/evil.so to all enrolled FortiClient endpoints, "
        "every endpoint that connects its VPN will execute the malicious .so with daemon privileges. "
        "This is a fleet-wide code execution vector via EMS policy push."
    ),
}


# ---------------------------------------------------------
# CONFIGHANDLER-F02: authorization_code in SQLite database
# ---------------------------------------------------------
CONFIGHANDLER_F02_OAUTH_CODE = {
    "id":       "CONFIGHANDLER-F02",
    "product":  "confighandler -- OAuth authorization_code stored in rusqlite SQLite database",
    "severity": "HIGH -- OAuth code extraction allows impersonating the endpoint to the EMS OAuth server",
    "class":    "Sensitive token stored in local database (CWE-312)",
    "evidence": [
        "string: '0authorization_code'",
        "rust crate: rusqlite-0.29.0",
        "string: 'sso_enabled'",
        "string: 'use_external_browser'",
    ],

    "description": (
        "confighandler implements an OAuth 2.0 authorization code flow for EMS authentication "
        "(use_external_browser + sso_enabled flags). "
        "The authorization_code is stored in the rusqlite SQLite database. "
        "SQLite databases in Rust applications (rusqlite) are typically stored as plaintext .db files. "
        "A local attacker with read access to the database file extracts the authorization_code. "
        "If the code has not yet been exchanged for an access token, the attacker can: "
        "  1. Exchange the code for an access_token + refresh_token at the EMS OAuth endpoint. "
        "  2. Use the tokens to authenticate to EMS as the enrolled FortiClient endpoint. "
        "  3. Access EMS APIs (push policy modifications, retrieve endpoint telemetry). "
        "Refresh token stored alongside the code (common OAuth pattern) enables persistent access."
    ),
}


# ---------------------------------------------------------
# CONFIGHANDLER-F03: single point of policy distribution
# ---------------------------------------------------------
CONFIGHANDLER_F03_POLICY_HUB = {
    "id":       "CONFIGHANDLER-F03",
    "product":  "confighandler -- single policy distribution hub; compromise = all daemon configs under attacker control",
    "severity": "CRITICAL -- confighandler compromise cascades to all FortiClient daemons simultaneously",
    "class":    "Single point of failure in security architecture (CWE-1075)",
    "evidence": [
        "confighandler distributes to: fctdns (ZTNA rules), firewall (iptables rules), vpn (profiles), "
        "fctsched (scan/update config), fortitray (UI policy)",
        "All daemons share the same IPC socket for policy reception",
    ],

    "description": (
        "confighandler is the sole policy distribution hub for all FortiClient daemons. "
        "An attacker who controls confighandler can: "
        "  1. Push ZTNA rules to fctdns -> intercept DNS for arbitrary domains. "
        "  2. Push TPROXY rules to firewall -> redirect arbitrary TCP traffic. "
        "  3. Push a malicious pkcs11_lib path to vpn -> code execution (CONFIGHANDLER-F01). "
        "  4. Disable auto_patch in fctsched -> prevent security updates. "
        "  5. Enable save_password -> force credential storage in GNOME keyring (extraction target). "
        "  6. Push malicious on_connect script via VPN profile -> RCE (VPN-F01). "
        "Control of confighandler = control of the entire FortiClient security stack. "
        "Attack paths to confighandler compromise: "
        "  a. IPC socket injection (FCTSCHED-F01): if the shared socket is world-writable, "
        "     any local process can send malformed configuration updates. "
        "  b. warp HTTP API: if the warp server binds to 0.0.0.0 (not just 127.0.0.1), "
        "     network-accessible policy injection. "
        "  c. SQLite database write: direct database modification bypasses IPC. "
        "  d. EMS compromise: compromised EMS pushes malicious policy to all enrolled clients."
    ),
}


# ---------------------------------------------------------
# CONFIGHANDLER-F04: warp 0.3.7 + hyper 0.14.28 HTTP server versions
# ---------------------------------------------------------
CONFIGHANDLER_F04_HTTP_SERVER = {
    "id":       "CONFIGHANDLER-F04",
    "product":  "confighandler -- warp 0.3.7 + hyper 0.14.28 HTTP server, specific versions",
    "severity": "MEDIUM -- specific library versions may have patched vulnerabilities absent in embedded copies",
    "class":    "Use of component with known vulnerabilities (CWE-1035)",
    "evidence": [
        "rust crate: hyper-0.14.28",
        "rust crate: warp-0.3.7",
        "confighandler exposes HTTP API (application/json content type confirmed)",
    ],

    "description": (
        "confighandler uses warp 0.3.7 and hyper 0.14.28 as its HTTP server stack. "
        "hyper 0.14.28 is the last patch release in the 0.14.x series (EOL; hyper 1.x is current). "
        "Known issues in hyper 0.x: "
        "  - GHSA-2m57-hf25-phgg (hyper 0.14.x HTTP/2 request smuggling via CONTINUATION frames; "
        "    CVE-2024-32021 or similar -- check specific hyper version advisories). "
        "  - HTTP/2 CONTINUATION frames ('HTTP/2 CONTINUATION Flood'): CVE-2024-27983, "
        "    affects hyper 0.x before specific patches. "
        "warp 0.3.7 is built on hyper 0.14.x; warp vulnerabilities are typically hyper vulnerabilities. "
        "If the confighandler HTTP API is reachable from any local process (not just other daemons), "
        "an HTTP/2 CONTINUATION flood against the local port could DoS the confighandler, "
        "disrupting policy distribution to all FortiClient daemons simultaneously."
    ),
}
