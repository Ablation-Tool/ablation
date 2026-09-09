"""
AXIS Body Worn Live Self-hosted Server (BodyWornLiveSelfHosted) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Body Worn Live Self-hosted Server, appId 414710 (package.conf: APPID="")
Versions: 1.0.0 (D3110 armv7hf), 1.5.1 (W401 aarch64), 2.0.0 (Oct 2025), 2.0.1 (Feb 2026)
Arch: Go static binary (1.5.1=11.8MB, 2.0.1=13.1MB) + rsignal 1.15.0 (Rust/actix-http 3.11.0) + coturn

WebRTC/coturn relay + JWT signaling on body-worn camera docks.
coturn bundles libgssapi_krb5.so.2, libkrb5.so.3 (Kerberos) + libmicrohttpd.so.12.
Prometheus metrics ports :9446 and :9641 proxied at viewer level with no auth check.

VAPIXServiceAccounts1.GetCredentials present from 1.0.0 (all versions), not just 2.0.x.
LD_LIBRARY_PATH hardcoded to coturn/lib before exec()ing turnserver — lib substitution path.
pre-uninstall.sh deletes cert set on BOTH uninstall AND upgrade -> TLS gap during upgrade.

rsignal 1.15.0 (2026-01-19 build, aarch64-unknown-linux-gnu, release):
  DontCareVerifier in src/tls_agent.rs — TLS bypass mode present in binary symbol table.
  ValidationScheme enum: Bearer | ImplicitBearer | NoAuth | InvalidAuth.
  Endpoints: /client, /target, /licenses (::auto_assigned/licenses), /onboarding (stub).
  Anonymous targets blocked; client endpoint security violations logged with source.
  DPoP (RFC 9449) + Bearer token auth supported.

Go binary (bws-webrtc-acap):
  github.com/axteams-one/bws-webrtc-acap/internal/httputil.NewInsecureClient present.
  github.com/axteams-one/bws-webrtc-acap/internal/rsignal.(*Authorizer) — authorization component.
  ENV_AXIS_SIGNAL_SERVER_TARGET_CA_PATH (2.0.1) / ENV_AXIS_SIGNAL_SERVER_CA_PATH (2.0.0) control CA bundle.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-LSS"
LABEL = "BodyWornLiveSelfHosted WebRTC/TURN attack surface"

FINDINGS = [
    {
        "id": "AXIS-LSS-01",
        "severity": "HIGH",
        "title": "TURN shared secret via getStunTurnTestCredentials — operator-accessible",
        "detail": (
            "auth CGI method getStunTurnTestCredentials returns time-based TURN credentials "
            "per RFC 8489 sec 9.2 (HMAC-SHA1 model). "
            "If CGI is accessible at operator auth level, attacker reads TURN shared secret "
            "-> forges credentials -> relays media through camera TURN server "
            "-> media interception or DoS of body-worn video streams. "
            "coturn HMAC-SHA1: credential = HMAC-SHA1(secret, username). "
            "username = <timestamp>:<user>."
        ),
        "cgi": "auth.getStunTurnTestCredentials",
        "prerequisite": "Operator-level camera auth",
        "version": "All",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-02",
        "severity": "HIGH",
        "title": "configure CGI destructive ops: deleteSystem / setServerConfig",
        "detail": (
            "configure CGI exposes: configureSystem, deleteSystem, setServerConfig, "
            "setPrivacyConfig, getPrivacyConfig, getSystemConfig, getSystems. "
            "deleteSystem at admin level wipes body-worn system configuration. "
            "setServerConfig with attacker TURN endpoint = SSRF to attacker relay server. "
            "setPrivacyConfig toggles video privacy masking state."
        ),
        "cgi": "configure.deleteSystem / configure.setServerConfig / configure.setPrivacyConfig",
        "prerequisite": "Admin-level camera auth",
        "version": "All",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-03",
        "severity": "MEDIUM",
        "title": "JWT signing secret in Go process memory",
        "detail": (
            "getSignalingClientToken issues JWTs (golang-jwt/jwt v5.2.2). "
            "JWT signing secret stored in BodyWornLiveSelfHosted process memory. "
            "Extractable via /proc/PID/mem if process user matches attacker context. "
            "Known signing secret -> forge client JWT -> unauthorized signaling channel access "
            "-> impersonate body-worn camera client."
        ),
        "cgi": "auth.getSignalingClientToken",
        "prerequisite": "Admin shell or /proc access on W401/D3110 device",
        "version": "All",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-04",
        "severity": "MEDIUM",
        "title": "Prometheus metrics ports :9446/:9641 proxied at viewer level — no auth",
        "detail": (
            "manifest.json reverseProxy config exposes: "
            "metrics/core (http, viewer) -> http://127.0.0.1:9446, "
            "metrics/coturn (http, viewer) -> http://127.0.0.1:9641. "
            "IDD plugins (bwlcore, bws_webrtc_coturn_metrics) curl these ports with no auth check. "
            "Any viewer-level auth user gets full Prometheus metrics: "
            "peer counts, stream states, coturn session counts, restart totals. "
            "If device has any SSRF primitive, attacker fetches metrics without even viewer auth."
        ),
        "prerequisite": "Viewer-level camera auth (or SSRF to localhost)",
        "version": "All",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-05",
        "severity": "MEDIUM",
        "title": "Kerberos in bundled coturn — auth-any fallback",
        "detail": (
            "coturn/turnserver bundles libgssapi_krb5.so.2 and libkrb5.so.3 (Kerberos). "
            "turnserver strings confirm auth-any / AuthANY option. "
            "In default AXIS BWS deployments, coturn is not connected to a Kerberos KDC. "
            "If auth-any is accidentally active, unauthenticated clients relay media through "
            "the TURN server -> free relay abuse."
        ),
        "prerequisite": "Network access to TURN port 3478/5349",
        "version": "All",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-06",
        "severity": "LOW",
        "title": "D-Bus cert set deleted on upgrade (pre-uninstall.sh TLS gap)",
        "detail": (
            "pre-uninstall.sh calls PolicyKitCert.CertSetDeleteUnpriv BodyWornLiveSelfHosted1 "
            "on both uninstall AND upgrade. Certificate set deleted between old package removal "
            "and new package install. During upgrade window, TLS connections using that cert set "
            "may fail or fall back to weaker profile."
        ),
        "prerequisite": "ACAP package upgrade event",
        "version": "1.5.1+",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-07",
        "severity": "HIGH",
        "title": "2.0.x: GraphQL standalone config mutations at operator level",
        "detail": (
            "2.0.0+ adds GraphQL mutations: addBWLStandaloneConfiguration, "
            "createBWLStandaloneConfigurationRequest, deleteBWLStandaloneConfiguration. "
            "Confirmed in 2.0.x binary strings. "
            "Operator-level access = reconfigure or delete BWS standalone config without admin rights. "
            "deleteBWLStandaloneConfiguration -> drops active body-worn system configuration "
            "-> body-worn cameras lose video relay capability (operational DoS)."
        ),
        "prerequisite": "Operator-level camera auth",
        "version": "2.0.0+",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-08",
        "severity": "HIGH",
        "title": "2.0.1: ENV_AXIS_SIGNAL_SERVER_TARGET_CA_PATH — CA path injection",
        "detail": (
            "ENV_AXIS_SIGNAL_SERVER_TARGET_CA_PATH env var (2.0.1) or SIGNAL_SERVER_CA_PATH (2.0.0) "
            "sets the CA bundle path for signal server TLS verification. "
            "If user-controllable via axparameter or ACAP config interface: "
            "attacker substitutes attacker-controlled CA cert "
            "-> MitM of BodyWornLiveSelfHosted <-> signal server TLS "
            "-> intercept JWT tokens, peer connection metadata, stream routing."
        ),
        "prerequisite": "Operator-level axparameter write or ACAP restart with injected env",
        "version": "2.0.0+",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-09",
        "severity": "MEDIUM",
        "title": "2.0.x: VAPIXServiceAccounts1.GetCredentials in LSS context",
        "detail": (
            "com.axis.HTTPConf1.VAPIXServiceAccounts1.GetCredentials called from "
            "BodyWornLiveSelfHosted 2.0.x context. If service account creds returned via "
            "unprotected IDD plugin or Prometheus metrics endpoint, attacker reads plaintext "
            "VAPIX service credentials -> full VAPIX API access as service account."
        ),
        "prerequisite": "SSRF to localhost IDD plugin or metrics.sock",
        "version": "2.0.0+",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-10",
        "severity": "MEDIUM",
        "title": "2.0.x: metrics.sock Unix socket — access control check",
        "detail": (
            "/usr/local/packages/BodyWornLiveSelfHosted/metrics.sock is a Unix domain socket "
            "for Prometheus metrics in 2.0.x. ACAP sandbox does not guarantee correct socket "
            "permissions. If permissions are 0666 or group-writable and another ACAP shares the "
            "socket group, any co-resident ACAP reads full Prometheus metrics: "
            "peer counts, session states, TURN credential material, stream IDs."
        ),
        "prerequisite": "Co-resident ACAP on same device with access to ACAP package dir",
        "version": "2.0.0+",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-11",
        "severity": "HIGH",
        "title": "LD_LIBRARY_PATH injection — coturn/lib writable = code exec in coturn",
        "detail": (
            "Go binary hardcodes LD_LIBRARY_PATH=/usr/local/packages/BodyWornLiveSelfHosted/coturn/lib "
            "before exec()ing turnserver. If any lib in coturn/lib is writable by a co-resident ACAP "
            "or via tarslip from another package, attacker replaces (e.g.) libprom.so with a malicious "
            "shared object -> code exec in coturn process context on next restart. "
            "coturn runs as ACAP SDK user; code exec = full coturn/TURN session takeover."
        ),
        "prerequisite": "Write access to ACAP package dir (co-resident ACAP or tarslip chain)",
        "version": "1.0.0+",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-12",
        "severity": "MEDIUM",
        "title": "Vite dev server port 5173 hardcoded — ICE/IAM at localhost (1.5.1)",
        "detail": (
            "ENV_AXIS_SIGNAL_SERVER_ICE_ENDPOINT_PATH=http://127.0.0.1:5173/ice and "
            "ENV_AXIS_SIGNAL_SERVER_IAM_ENDPOINT_PATH=http://127.0.0.1:5173/auth hardcoded "
            "in 1.5.1 binary. Port 5173 is Vite default dev server. "
            "If production deployment accidentally runs a service on :5173 (debug mode, staging artifact), "
            "ICE endpoint and IAM auth endpoint reachable via SSRF from any local service."
        ),
        "prerequisite": "SSRF to localhost:5173 or debug build deployed to production",
        "version": "1.5.1 (check if removed in 2.x)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LSS-13",
        "severity": "MEDIUM",
        "title": "VAPIXServiceAccounts1.GetCredentials present from 1.0.0 (all versions)",
        "detail": (
            "manifest.json for 1.0.0 D3110 and 1.5.1 W401 both declare "
            "com.axis.HTTPConf1.VAPIXServiceAccounts1.GetCredentials as a required D-Bus method. "
            "Previously documented only for 2.0.x. VAPIX service account credential fetch is "
            "available to LSS from the initial 1.0.0 release. "
            "If exposed via SSRF or IDD plugin, VAPIX credentials leak applies to all versions."
        ),
        "prerequisite": "SSRF to IDD plugin or metrics endpoint",
        "version": "1.0.0+ (all versions)",
        "status": "UNPATCHED",
        "cve": None,
    },
]
