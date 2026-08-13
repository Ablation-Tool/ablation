"""
Cisco platform REST API enumeration.
Platforms: APIC (ACI), DNA Center (Catalyst Center), UCS Manager,
           UCS Director, vManage (SD-WAN), NSO, RESTCONF/NETCONF/gNMI.
Auth patterns extracted from DevNet/DevNet Associate certification material.
"""

import socket
import ssl
import json
import base64
import re
import urllib.request
import urllib.error
from typing import Optional

APIC_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "ciscopsdt"),   # DevNet sandbox default
    ("admin", "C1sco12345"),
    ("admin", "Cisco123"),
    ("admin", "cisco"),
    ("admin", "Admin1234"),
    ("admin", "password"),
]

DNAC_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "C1sco12345"),
    ("admin", "Cisco123"),
    ("admin", "cisco"),
    ("admin", "password1!"),
]

UCS_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "C1sco12345"),
    ("admin", "Cisco123"),
    ("admin", "cisco"),
]

VMANAGE_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "cisco"),
    ("admin", "C1sco12345"),
]

NSO_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "C1sco12345"),
    ("admin", "cisco"),
]


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http(url: str, method: str = "GET", headers: dict = None,
          body: Optional[bytes] = None, timeout: int = 8) -> Optional[dict]:
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"__http_error": e.code}
    except Exception:
        return None


# ─── Cisco APIC (ACI) ──────────────────────────────────────────────────────

APIC_PORT = 443

# High-value class queries — return topology, users, policies
APIC_CLASS_QUERIES = {
    "fabric_pods": "/api/node/class/fabricPod.json",
    "nodes": "/api/node/class/topSystem.json",
    "fabric_nodes": "/api/node/class/fabricNode.json",
    "tenants": "/api/class/fvTenant.json",
    "app_profiles": "/api/class/fvAp.json",
    "epgs": "/api/class/fvAEPg.json",
    "bridge_domains": "/api/class/fvBD.json",
    "vrfs": "/api/class/fvCtx.json",
    "contracts": "/api/class/vzBrCP.json",
    "users": "/api/class/aaaUser.json",
    # L3 external connections — shows peering IPs, AS numbers
    "l3out": "/api/class/l3extOut.json",
    # Fabric uplinks — physical topo
    "phys_if": "/api/class/l1PhysIf.json?query-target-filter=and(eq(l1PhysIf.operSt,\"up\"))&page-size=100",
    # Pre-login banner often reveals fabric domain name + contact info
    "banner": "/api/class/aaaPreLoginBanner.json",
}

class APICEnum:
    def __init__(self, host: str, port: int = APIC_PORT):
        self.host = host
        self.port = port
        self._cookie = None

    def _base(self) -> str:
        return f"https://{self.host}:{self.port}"

    def login(self, user: str, passwd: str, timeout: int = 8) -> Optional[str]:
        body = json.dumps({
            "aaaUser": {"attributes": {"name": user, "pwd": passwd}}
        }).encode()
        resp = _http(f"{self._base()}/api/aaaLogin.json",
                     method="POST", body=body, timeout=timeout)
        if not resp or "__http_error" in resp:
            return None
        try:
            token = resp["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self._cookie = token
            return token
        except (KeyError, IndexError):
            return None

    def _get(self, path: str, timeout: int = 8) -> Optional[dict]:
        headers = {}
        if self._cookie:
            headers["Cookie"] = f"APIC-cookie={self._cookie}"
        return _http(f"{self._base()}{path}", headers=headers, timeout=timeout)

    def brute_login(self, creds: list = None, timeout: int = 8) -> Optional[dict]:
        for user, passwd in (creds or APIC_DEFAULT_CREDS):
            token = self.login(user, passwd, timeout=timeout)
            if token:
                return {"user": user, "pass": passwd, "token": token[:32] + "..."}
        return None

    def enumerate(self, timeout: int = 8) -> dict:
        result = {"host": self.host, "reachable": False, "cred_result": None, "data": {}}
        try:
            socket.create_connection((self.host, self.port), timeout=timeout).close()
            result["reachable"] = True
        except Exception:
            return result

        # Unauthenticated: banner and version often accessible
        for key in ("banner",):
            path = APIC_CLASS_QUERIES[key]
            data = self._get(path, timeout=timeout)
            if data and "__http_error" not in data:
                result["data"][key] = data

        cred = self.brute_login(timeout=timeout)
        result["cred_result"] = cred

        if cred:
            for key, path in APIC_CLASS_QUERIES.items():
                data = self._get(path, timeout=timeout)
                if data and "__http_error" not in data:
                    result["data"][key] = data

        return result


# ─── Cisco DNA Center / Catalyst Center ─────────────────────────────────────

DNAC_PORT = 443

# DNA Center uses Basic auth → token, then X-Auth-Token header
DNAC_AUTH_PATH = "/dna/system/api/v1/auth/token"

DNAC_PATHS = {
    "devices": "/dna/intent/api/v1/network-device",
    "device_health": "/dna/intent/api/v1/device-health",
    "sites": "/dna/intent/api/v1/site",
    "topology": "/dna/intent/api/v1/topology/l3/ospf",
    "compliance": "/dna/intent/api/v1/compliance",
    # Global credential store — SNMP community strings, login passwords, SSH keys
    "global_credentials": "/dna/intent/api/v1/global-credential",
    # Device configs — show running-config for all managed devices
    "device_configs": "/dna/intent/api/v1/network-device/config",
    # Wireless creds — pre-shared keys
    "wireless_profiles": "/dna/intent/api/v1/wireless/profile",
    # Swim (software image management) — firmware versions
    "swim": "/dna/intent/api/v1/swim-intent/importIMAGEViaURL",
    # Users
    "users": "/api/v1/user",
    # System info
    "system_info": "/api/system/v1/product-info",
}

class DNACEnum:
    def __init__(self, host: str, port: int = DNAC_PORT):
        self.host = host
        self.port = port
        self._token = None

    def _base(self) -> str:
        return f"https://{self.host}:{self.port}"

    def login(self, user: str, passwd: str, timeout: int = 8) -> Optional[str]:
        cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        headers = {"Authorization": f"Basic {cred}"}
        resp = _http(f"{self._base()}{DNAC_AUTH_PATH}",
                     method="POST", headers=headers, timeout=timeout)
        if resp and "Token" in resp:
            self._token = resp["Token"]
            return self._token
        return None

    def _get(self, path: str, timeout: int = 8) -> Optional[dict]:
        headers = {}
        if self._token:
            headers["X-Auth-Token"] = self._token
        return _http(f"{self._base()}{path}", headers=headers, timeout=timeout)

    def brute_login(self, creds: list = None, timeout: int = 8) -> Optional[dict]:
        for user, passwd in (creds or DNAC_DEFAULT_CREDS):
            tok = self.login(user, passwd, timeout=timeout)
            if tok:
                return {"user": user, "pass": passwd}
        return None

    def enumerate(self, timeout: int = 8) -> dict:
        result = {"host": self.host, "reachable": False, "cred_result": None, "data": {}}
        try:
            socket.create_connection((self.host, self.port), timeout=timeout).close()
            result["reachable"] = True
        except Exception:
            return result

        cred = self.brute_login(timeout=timeout)
        result["cred_result"] = cred

        if cred:
            for key, path in DNAC_PATHS.items():
                data = self._get(path, timeout=timeout)
                if data and "__http_error" not in data:
                    result["data"][key] = data

        return result


# ─── Cisco UCS Manager (XML API) ─────────────────────────────────────────────

UCS_PORT = 443

class UCSMgrEnum:
    """UCS Manager XML API — POST to /nuova with XML body."""

    def __init__(self, host: str, port: int = UCS_PORT):
        self.host = host
        self.port = port
        self._cookie = None

    def _nuova_post(self, xml_body: str, timeout: int = 8) -> Optional[str]:
        url = f"https://{self.host}:{self.port}/nuova"
        body = xml_body.encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "text/xml")
        try:
            with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
                return r.read().decode(errors="replace")
        except Exception:
            return None

    def login(self, user: str, passwd: str, timeout: int = 8) -> bool:
        xml = f'<aaaLogin inName="{user}" inPassword="{passwd}"/>'
        resp = self._nuova_post(xml, timeout=timeout)
        if resp and 'outCookie="' in resp:
            # Extract cookie
            idx = resp.find('outCookie="') + len('outCookie="')
            end = resp.find('"', idx)
            self._cookie = resp[idx:end]
            return True
        return False

    def _xml_get(self, xml_body: str, timeout: int = 8) -> Optional[str]:
        return self._nuova_post(xml_body, timeout=timeout)

    def enumerate(self, timeout: int = 8) -> dict:
        result = {"host": self.host, "reachable": False, "cred_result": None,
                  "service_profiles": None, "firmware": None, "users": None}
        try:
            socket.create_connection((self.host, self.port), timeout=timeout).close()
            result["reachable"] = True
        except Exception:
            return result

        for user, passwd in UCS_DEFAULT_CREDS:
            if self.login(user, passwd, timeout=timeout):
                result["cred_result"] = {"user": user, "pass": passwd}
                break

        if result["cred_result"] and self._cookie:
            # Get service profiles
            xml = (f'<configResolveClass cookie="{self._cookie}" '
                   f'inHierarchical="false" classId="lsServer"/>')
            result["service_profiles"] = self._xml_get(xml, timeout=timeout)

            # Get firmware inventory
            xml = (f'<configResolveClass cookie="{self._cookie}" '
                   f'inHierarchical="false" classId="firmwareRunning"/>')
            result["firmware"] = self._xml_get(xml, timeout=timeout)

            # Get local users
            xml = (f'<configResolveClass cookie="{self._cookie}" '
                   f'inHierarchical="false" classId="aaaUser"/>')
            result["users"] = self._xml_get(xml, timeout=timeout)

        return result


# ─── Cisco vManage (SD-WAN) ──────────────────────────────────────────────────

VMANAGE_PORT = 8443

VMANAGE_PATHS = {
    "devices": "/dataservice/device",
    "device_config": "/dataservice/template/config/running",  # running configs
    "vedge_list": "/dataservice/device/vedge/list",
    "users": "/dataservice/admin/user",
    "api_keys": "/dataservice/admin/user/apikeys",
    "certificates": "/dataservice/certificate/vsmart/list",
    "topology": "/dataservice/topology/physical/topology",
    "alarms": "/dataservice/alarms",
}

class VManageEnum:
    def __init__(self, host: str, port: int = VMANAGE_PORT):
        self.host = host
        self.port = port
        self._jsessionid = None
        self._token = None

    def _base(self) -> str:
        return f"https://{self.host}:{self.port}"

    def login(self, user: str, passwd: str, timeout: int = 8) -> bool:
        # vManage uses form-encoded POST for auth
        body = f"j_username={user}&j_password={passwd}".encode()
        req = urllib.request.Request(
            f"{self._base()}/j_security_check", data=body, method="POST"
        )
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
                cookie_header = r.headers.get("Set-Cookie", "")
                if "JSESSIONID=" in cookie_header:
                    idx = cookie_header.find("JSESSIONID=") + len("JSESSIONID=")
                    end = cookie_header.find(";", idx)
                    self._jsessionid = cookie_header[idx:end]
                    return True
        except Exception:
            pass
        return False

    def _get_token(self, timeout: int = 8) -> Optional[str]:
        if not self._jsessionid:
            return None
        resp = _http(f"{self._base()}/dataservice/client/token",
                     headers={"Cookie": f"JSESSIONID={self._jsessionid}"},
                     timeout=timeout)
        if resp and "token" in resp:
            self._token = resp["token"]
            return self._token
        return None

    def _get(self, path: str, timeout: int = 8) -> Optional[dict]:
        headers = {}
        if self._jsessionid:
            headers["Cookie"] = f"JSESSIONID={self._jsessionid}"
        if self._token:
            headers["X-XSRF-TOKEN"] = self._token
        return _http(f"{self._base()}{path}", headers=headers, timeout=timeout)

    def enumerate(self, timeout: int = 8) -> dict:
        result = {"host": self.host, "reachable": False, "cred_result": None, "data": {}}
        try:
            socket.create_connection((self.host, self.port), timeout=timeout).close()
            result["reachable"] = True
        except Exception:
            return result

        for user, passwd in VMANAGE_DEFAULT_CREDS:
            if self.login(user, passwd, timeout=timeout):
                result["cred_result"] = {"user": user, "pass": passwd}
                self._get_token(timeout=timeout)
                break

        if result["cred_result"]:
            for key, path in VMANAGE_PATHS.items():
                data = self._get(path, timeout=timeout)
                if data and "__http_error" not in data:
                    result["data"][key] = data

        return result


# ─── Cisco RESTCONF / NETCONF / gNMI ────────────────────────────────────────

RESTCONF_PORT = 443
NETCONF_PORT = 830
GNMI_PORT = 57400

RESTCONF_PATHS = {
    # IOS-XE native model — show running-config equivalent
    "hostname": "/restconf/data/Cisco-IOS-XE-native:native/hostname",
    "interfaces": "/restconf/data/ietf-interfaces:interfaces",
    "routing": "/restconf/data/ietf-routing:routing",
    # SNMP config — community strings!
    "snmp": "/restconf/data/Cisco-IOS-XE-native:native/snmp-server",
    # AAA config — TACACS+ shared keys
    "aaa": "/restconf/data/Cisco-IOS-XE-native:native/aaa",
    # BGP — neighbor passwords
    "bgp": "/restconf/data/Cisco-IOS-XE-native:native/router/bgp",
    # Line/VTY — password, transport ssh/telnet
    "line": "/restconf/data/Cisco-IOS-XE-native:native/line",
    # Users
    "users": "/restconf/data/Cisco-IOS-XE-native:native/username",
    # RESTCONF capabilities — which modules supported
    "capabilities": "/restconf/data/ietf-yang-library:modules-state",
}

class RESTCONFEnum:
    def __init__(self, host: str, port: int = RESTCONF_PORT):
        self.host = host
        self.port = port

    def _base(self) -> str:
        return f"https://{self.host}:{self.port}"

    def _get(self, path: str, user: str = None, passwd: str = None,
             timeout: int = 8) -> Optional[dict]:
        headers = {"Accept": "application/yang-data+json"}
        if user and passwd:
            cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"
        url = f"{self._base()}{path}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            return {"__http_error": e.code}
        except Exception:
            return None

    def probe_netconf(self, timeout: int = 8) -> dict:
        try:
            s = socket.create_connection((self.host, NETCONF_PORT), timeout=timeout)
            banner = s.recv(2048).decode(errors="replace")
            s.close()
            return {"port": NETCONF_PORT, "open": True, "banner": banner[:512]}
        except Exception:
            return {"port": NETCONF_PORT, "open": False}

    def probe_gnmi(self, timeout: int = 8) -> dict:
        try:
            s = socket.create_connection((self.host, GNMI_PORT), timeout=timeout)
            s.close()
            return {"port": GNMI_PORT, "open": True}
        except Exception:
            return {"port": GNMI_PORT, "open": False}

    def enumerate(self, timeout: int = 8) -> dict:
        result = {"host": self.host, "reachable": False, "cred_result": None,
                  "data": {}, "netconf": {}, "gnmi": {}}
        try:
            socket.create_connection((self.host, RESTCONF_PORT), timeout=timeout).close()
            result["reachable"] = True
        except Exception:
            pass

        result["netconf"] = self.probe_netconf(timeout=timeout)
        result["gnmi"] = self.probe_gnmi(timeout=timeout)

        # Try default creds against RESTCONF
        for user, passwd in (APIC_DEFAULT_CREDS + UCS_DEFAULT_CREDS):
            data = self._get("/restconf/data/ietf-interfaces:interfaces",
                             user=user, passwd=passwd, timeout=timeout)
            if data and "__http_error" not in data:
                result["cred_result"] = {"user": user, "pass": passwd}
                # Pull all RESTCONF paths
                for key, path in RESTCONF_PATHS.items():
                    d = self._get(path, user=user, passwd=passwd, timeout=timeout)
                    if d and "__http_error" not in d:
                        result["data"][key] = d
                break

        return result


# ─── NSO (Network Services Orchestrator) ────────────────────────────────────

NSO_RESTCONF_PORT = 8080
NSO_NETCONF_PORT = 2022

class NSOEnum:
    def __init__(self, host: str, port: int = NSO_RESTCONF_PORT):
        self.host = host
        self.port = port

    def _get(self, path: str, user: str = None, passwd: str = None,
             timeout: int = 8) -> Optional[dict]:
        headers = {"Accept": "application/vnd.yang.data+json"}
        if user and passwd:
            cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"
        url = f"http://{self.host}:{self.port}{path}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            return {"__http_error": e.code}
        except Exception:
            return None

    def enumerate(self, timeout: int = 8) -> dict:
        result = {"host": self.host, "reachable": False, "cred_result": None, "data": {}}
        try:
            socket.create_connection((self.host, self.port), timeout=timeout).close()
            result["reachable"] = True
        except Exception:
            return result

        for user, passwd in NSO_DEFAULT_CREDS:
            data = self._get("/api", user=user, passwd=passwd, timeout=timeout)
            if data and "__http_error" not in data:
                result["cred_result"] = {"user": user, "pass": passwd}
                # Device list — all managed devices
                d = self._get("/api/running/devices/device",
                              user=user, passwd=passwd, timeout=timeout)
                if d and "__http_error" not in d:
                    result["data"]["devices"] = d
                # Device configs — authgroups contain creds for all managed devices
                d = self._get("/api/running/devices/authgroups",
                              user=user, passwd=passwd, timeout=timeout)
                if d and "__http_error" not in d:
                    result["data"]["authgroups"] = d
                break

        return result


# ─── Top-level sweep ─────────────────────────────────────────────────────────

def enumerate_cisco_api_surface(hosts: list, timeout: int = 8) -> dict:
    """
    Probe all Cisco platform APIs on a list of hosts.
    Returns per-host findings.
    """
    results = {}
    for host in hosts:
        h = {}

        # Try APIC
        apic = APICEnum(host)
        h["apic"] = apic.enumerate(timeout=timeout)

        # Try DNA Center
        dnac = DNACEnum(host)
        h["dnac"] = dnac.enumerate(timeout=timeout)

        # Try UCS Manager
        ucs = UCSMgrEnum(host)
        h["ucs_manager"] = ucs.enumerate(timeout=timeout)

        # Try vManage (SD-WAN) on 8443
        vman = VManageEnum(host)
        h["vmanage"] = vman.enumerate(timeout=timeout)

        # Try RESTCONF/NETCONF/gNMI
        rc = RESTCONFEnum(host)
        h["restconf"] = rc.enumerate(timeout=timeout)

        # Try NSO
        nso = NSOEnum(host)
        h["nso"] = nso.enumerate(timeout=timeout)

        results[host] = h

    return results


# ─── Probe functions (finding-list style) ────────────────────────────────────

def probe_dnac_programmability(host: str, port: int = 443,
                               timeout: float = 5.0) -> list:
    """
    DNA Center / Catalyst Center attack surface checks.
    Returns list of finding dicts: {severity, title, detail, host, port}.
    """
    findings = []
    base = f"https://{host}:{port}"
    ctx = _ssl_ctx()

    def _raw_get(path: str, headers: dict = None) -> Optional[int]:
        """Return HTTP status code, or None on connection failure."""
        req = urllib.request.Request(f"{base}{path}")
        req.add_header("Accept", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    # 1. Unauthenticated device inventory
    status = _raw_get("/dna/intent/api/v1/network-device")
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "DNA Center network device inventory exposed",
            "detail": "GET /dna/intent/api/v1/network-device returned 200 without auth token",
            "host": host,
            "port": port,
        })

    # 2. Unauthenticated physical topology
    status = _raw_get("/dna/intent/api/v1/topology/physical-topology")
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "DNA Center physical topology exposed",
            "detail": "GET /dna/intent/api/v1/topology/physical-topology returned 200 without auth token",
            "host": host,
            "port": port,
        })

    # 3. Default credentials — POST /dna/system/api/v1/auth/token with Basic auth
    dnac_creds = [
        ("admin", "admin"),
        ("admin", "C1sco12345"),
        ("maglev", "password"),
    ]
    for user, passwd in dnac_creds:
        cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        req = urllib.request.Request(
            f"{base}/dna/system/api/v1/auth/token",
            data=b"",
            method="POST",
        )
        req.add_header("Authorization", f"Basic {cred}")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                raw = r.read()
                body = json.loads(raw) if raw else {}
                if "Token" in body:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "DNA Center default credentials accepted",
                        "detail": (f"POST /dna/system/api/v1/auth/token with "
                                   f"{user}:{passwd} returned a token"),
                        "host": host,
                        "port": port,
                    })
                    break
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    # 4. Unauthenticated site list
    status = _raw_get("/dna/intent/api/v1/site")
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "DNA Center site list accessible without auth",
            "detail": "GET /dna/intent/api/v1/site returned 200 without auth token",
            "host": host,
            "port": port,
        })

    return findings


def probe_netconf_yang(host: str, port: int = 830,
                       timeout: float = 5.0) -> list:
    """
    NETCONF over SSH (RFC 6242) attack surface checks.
    Reads the server hello banner pre-auth and inspects declared capabilities.
    Also checks port 831 (NETCONF over TLS).
    Returns list of finding dicts.
    """
    findings = []

    def _read_netconf_banner(p: int) -> Optional[str]:
        """Connect, read until ]]>]]> terminator or timeout, return banner."""
        try:
            s = socket.create_connection((host, p), timeout=timeout)
            buf = b""
            s.settimeout(timeout)
            try:
                while b"]]>]]>" not in buf:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 65536:
                        break
            except Exception:
                pass
            s.close()
            return buf.decode(errors="replace") if buf else None
        except Exception:
            return None

    for p in (port, 831):
        banner = _read_netconf_banner(p)
        if banner is None:
            continue

        if "<capabilities>" in banner or "<hello" in banner:
            findings.append({
                "severity": "MEDIUM",
                "title": "NETCONF capabilities disclosed pre-auth",
                "detail": (f"Port {p}: server hello with <capabilities> block "
                           f"received before authentication"),
                "host": host,
                "port": p,
            })

        if ("urn:ietf:params:netconf:capability:writable-running:1.0"
                in banner):
            findings.append({
                "severity": "HIGH",
                "title": "NETCONF writable-running capability advertised",
                "detail": (f"Port {p}: capability "
                           f"urn:ietf:params:netconf:capability:"
                           f"writable-running:1.0 present in server hello"),
                "host": host,
                "port": p,
            })

        if ("urn:ietf:params:netconf:capability:rollback-on-error:1.0"
                in banner):
            findings.append({
                "severity": "LOW",
                "title": "NETCONF rollback-on-error capability advertised",
                "detail": (f"Port {p}: capability "
                           f"urn:ietf:params:netconf:capability:"
                           f"rollback-on-error:1.0 present in server hello"),
                "host": host,
                "port": p,
            })

    return findings


def probe_restconf(host: str, port: int = 443,
                   timeout: float = 5.0) -> list:
    """
    RESTCONF (RFC 8040) attack surface checks.
    Returns list of finding dicts.
    """
    findings = []
    base = f"https://{host}:{port}"
    ctx = _ssl_ctx()

    def _raw_fetch(path: str) -> tuple:
        """Return (status_code, body_bytes) or (None, None) on failure."""
        req = urllib.request.Request(f"{base}{path}")
        req.add_header("Accept",
                       "application/yang-data+json, application/json, */*")
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
            except Exception:
                body = b""
            return e.code, body
        except Exception:
            return None, None

    # 1. Discover RESTCONF root via host-meta
    status, body = _raw_fetch("/.well-known/host-meta")
    restconf_root = "/restconf"
    if status == 200 and body:
        text = body.decode(errors="replace")
        # XRD link rel="restconf" href="..."
        import re as _re
        m = _re.search(r'rel="restconf"[^>]*href="([^"]+)"', text)
        if not m:
            m = _re.search(r'href="([^"]*restconf[^"]*)"', text)
        if m:
            restconf_root = m.group(1).rstrip("/")

    # 2. Unauthenticated RESTCONF root
    status, body = _raw_fetch(f"{restconf_root}/")
    if status == 200 and body:
        text = body.decode(errors="replace")
        if "<restconf" in text or '"ietf-restconf:restconf"' in text:
            findings.append({
                "severity": "CRITICAL",
                "title": "RESTCONF root accessible without auth",
                "detail": (f"GET {restconf_root}/ returned 200 with RESTCONF "
                           f"envelope — no authentication required"),
                "host": host,
                "port": port,
            })

    # 3. Unauthenticated interface data
    path = f"{restconf_root}/data/ietf-interfaces:interfaces"
    status, body = _raw_fetch(path)
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "RESTCONF interface data readable without auth",
            "detail": f"GET {path} returned 200 without authentication",
            "host": host,
            "port": port,
        })

    # 4. Unauthenticated username/credential store
    path = (f"{restconf_root}/data/"
            f"Cisco-IOS-XE-native:native/username")
    status, body = _raw_fetch(path)
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "RESTCONF local user database readable without auth",
            "detail": f"GET {path} returned 200 — local username table exposed",
            "host": host,
            "port": port,
        })

    return findings


def probe_gnmi_telemetry(host: str, port: int = 50051,
                         timeout: float = 3.0) -> list:
    """
    gNMI streaming telemetry attack surface checks (ports 50051 and 57400).
    Sends HTTP/2 connection preface and checks for any response.
    Returns list of finding dicts.
    """
    findings = []
    # HTTP/2 client connection preface (RFC 7540 §3.5)
    H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    for p in (port, 57400):
        try:
            s = socket.create_connection((host, p), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(H2_PREFACE)
            try:
                data = s.recv(1024)
            except Exception:
                data = b""
            s.close()
            if data is not None:  # any response (even error frame) = port open
                findings.append({
                    "severity": "MEDIUM",
                    "title": "gNMI port open (streaming telemetry surface)",
                    "detail": (f"Port {p}: TCP connect succeeded and server "
                               f"responded to HTTP/2 preface "
                               f"({len(data)} bytes) — gNMI/gRPC surface "
                               f"present; auth posture unconfirmed"),
                    "host": host,
                    "port": p,
                })
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# Chapter 12 — Application Inspection attack surface
# ---------------------------------------------------------------------------

def probe_asa_inspection_bypass(host: str, port: int = 443,
                                timeout: float = 5.0) -> list:
    """
    ASA application inspection bypass probes.
    Covers HTTP oversized-header, HTTP CONNECT tunnel, FTP bounce,
    and SIP inspection policy readability.
    Returns list of finding dicts.
    """
    import urllib.request
    import urllib.error

    findings = []

    # --- HTTP inspection: oversized header (8 KB value) ---
    big_value = "A" * 8192
    oversized_req = (
        f"GET /index.html HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Oversized: {big_value}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.sendall(oversized_req)
                resp = b""
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                        if len(resp) > 16384:
                            break
                except Exception:
                    pass
        if resp.startswith(b"HTTP/") and b" 200 " in resp[:20]:
            findings.append({
                "severity": "HIGH",
                "title": "HTTP_INSPECT_OVERSIZED_HEADER_ALLOWED",
                "detail": (
                    f"ASA HTTP inspection did not block request with 8 KB "
                    f"header value — header-length limit not enforced"
                ),
                "host": host,
                "port": port,
            })
    except Exception:
        pass

    # --- HTTP inspection: CONNECT tunnel to port 80 ---
    connect_req = (
        f"CONNECT {host}:80 HTTP/1.1\r\n"
        f"Host: {host}:80\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.sendall(connect_req)
                hdr = b""
                try:
                    while b"\r\n\r\n" not in hdr:
                        c = s.recv(1024)
                        if not c:
                            break
                        hdr += c
                except Exception:
                    pass
        if b" 200 " in hdr[:30]:
            findings.append({
                "severity": "HIGH",
                "title": "HTTP_CONNECT_TUNNEL_ALLOWED",
                "detail": (
                    "ASA HTTP inspection permits CONNECT tunneling — "
                    "CONNECT method not blocked by inspect map"
                ),
                "host": host,
                "port": port,
            })
    except Exception:
        pass

    # --- FTP inspection: FTP bounce (PORT pointing to third host) ---
    ftp_port = 21
    try:
        with socket.create_connection((host, ftp_port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = b""
            try:
                banner = s.recv(1024)
            except Exception:
                pass
            if b"220" in banner:
                # PORT h1,h2,h3,h4,p1,p2 — redirect to 10.0.0.1:6200
                s.sendall(b"PORT 10,0,0,1,24,56\r\n")
                resp = b""
                try:
                    resp = s.recv(512)
                except Exception:
                    pass
                if resp.startswith(b"200"):
                    findings.append({
                        "severity": "HIGH",
                        "title": "FTP_BOUNCE_ATTACK_POSSIBLE",
                        "detail": (
                            "ASA FTP inspection accepted PORT command pointing "
                            "to third-party host (10.0.0.1) — FTP bounce not "
                            "blocked by inspect policy"
                        ),
                        "host": host,
                        "port": ftp_port,
                    })
    except Exception:
        pass

    # --- SIP inspection: /+CSCOE+/ portal policy check ---
    sip_paths = [
        "/+CSCOE+/logon.html",
        "/+CSCOE+/sdesktop/install/binaries/",
    ]
    for path in sip_paths:
        url = f"https://{host}:{port}{path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx2,
                                        timeout=timeout) as r:
                if r.status == 200:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "SIP_INSPECTION_CONFIG_READABLE",
                        "detail": (
                            f"GET {path} returned 200 — CSCOE portal "
                            "accessible; SIP inspection policy may be "
                            "disclosed through clientless SSL VPN interface"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
        except Exception:
            pass

    return findings


def probe_asa_mpf_config(host: str, port: int = 443,
                         timeout: float = 5.0) -> list:
    """
    Modular Policy Framework (MPF) exposure via ASA REST API.
    Checks unauthenticated access to inspection class-maps, policy-maps,
    service-policies, and HTTP inspect-maps.
    Returns list of finding dicts.
    """
    import urllib.request
    import urllib.error

    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    endpoints = [
        (
            "/api/v1/global-objects/inspection-class-maps",
            "CRITICAL",
            "INSPECTION_CLASS_MAPS_UNAUTH",
            "Unauthenticated read of MPF inspection class-maps — "
            "traffic classification rules fully disclosed",
        ),
        (
            "/api/v1/global-objects/inspection-policy-maps",
            "HIGH",
            "INSPECTION_POLICY_MAPS_READABLE",
            "MPF inspection policy-maps readable without authentication — "
            "protocol enforcement rules disclosed",
        ),
        (
            "/api/v1/global-objects/service-policies",
            "CRITICAL",
            "SERVICE_POLICIES_READABLE",
            "Full MPF service-policy config exposed without authentication — "
            "all inspection, QoS, and connection-limit rules disclosed",
        ),
        (
            "/api/v1/global-objects/inspect-maps/http",
            "HIGH",
            "HTTP_INSPECT_MAP_READABLE",
            "HTTP inspect-map readable without authentication — "
            "protocol limits and anomaly-detection thresholds disclosed",
        ),
    ]

    for path, severity, title, detail in endpoints:
        url = f"https://{host}:{port}{path}"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0",
                },
            )
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                if r.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": detail,
                        "host": host,
                        "port": port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return findings


def probe_dns_inspection(host: str, port: int = 443,
                         timeout: float = 5.0) -> list:
    """
    DNS inspection misconfiguration probes.
    Checks ASA REST API for dns-guard status, DNS server config exposure,
    and DNS zone-transfer (AXFR) through the ASA outside interface.
    Returns list of finding dicts.
    """
    import urllib.request
    import urllib.error
    import struct

    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # --- DNS inspect-map: dns-guard status ---
    dns_map_url = f"https://{host}:{port}/api/v1/global-objects/inspect-maps/dns"
    try:
        req = urllib.request.Request(
            dns_map_url,
            headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                body = r.read().decode(errors="replace")
                if "dns-guard" in body.lower() and (
                    '"enabled":false' in body or
                    '"dnsGuard":false' in body or
                    "disable" in body.lower()
                ):
                    findings.append({
                        "severity": "HIGH",
                        "title": "DNS_GUARD_DISABLED",
                        "detail": (
                            "DNS inspect-map shows dns-guard disabled — "
                            "ASA will not detect/block duplicate DNS replies; "
                            "DNS cache poisoning possible"
                        ),
                        "host": host,
                        "port": port,
                    })
                else:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "DNS_INSPECT_MAP_READABLE",
                        "detail": (
                            "DNS inspect-map readable without authentication — "
                            "inspection thresholds and dns-guard config disclosed"
                        ),
                        "host": host,
                        "port": port,
                    })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # --- Network service groups: DNS server config ---
    nsg_url = (f"https://{host}:{port}"
               f"/api/v1/global-objects/network-service-groups")
    try:
        req = urllib.request.Request(
            nsg_url,
            headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                body = r.read().decode(errors="replace")
                if "dns" in body.lower() or "53" in body:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "DNS_SERVER_CONFIG_READABLE",
                        "detail": (
                            "Network service-groups endpoint returned 200 with "
                            "DNS-related entries — DNS server addresses/groups "
                            "readable without authentication"
                        ),
                        "host": host,
                        "port": port,
                    })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # --- UDP/53 probe: DNS AXFR (zone-transfer) through ASA outside ---
    # Build a minimal DNS query for AXFR with TC=1 (truncated bit set)
    try:
        txn_id = 0x1337
        flags = 0x0200   # QR=0 (query), TC=1 (truncated)
        qdcount = 1
        header = struct.pack("!HHHHHH", txn_id, flags, qdcount, 0, 0, 0)
        qname = b"\x07version\x04bind\x00"
        qtype = 252   # AXFR
        qclass = 1    # IN
        question = qname + struct.pack("!HH", qtype, qclass)
        dns_query = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(dns_query, (host, 53))
        try:
            data, _ = sock.recvfrom(4096)
        except Exception:
            data = b""
        finally:
            sock.close()

        if len(data) >= 12:
            resp_flags = struct.unpack("!H", data[2:4])[0]
            qr = (resp_flags >> 15) & 1
            rcode = resp_flags & 0x0F
            ancount = struct.unpack("!H", data[6:8])[0]
            if qr == 1 and rcode == 0 and ancount > 0:
                findings.append({
                    "severity": "HIGH",
                    "title": "DNS_ZONE_TRANSFER_THROUGH_ASA",
                    "detail": (
                        "DNS AXFR query with TC=1 through ASA outside "
                        "interface returned answers — zone-transfer not "
                        "blocked by DNS inspection policy"
                    ),
                    "host": host,
                    "port": 53,
                })
    except Exception:
        pass

    return findings


def probe_smtp_inspection(host: str, port: int = 25,
                          timeout: float = 5.0) -> list:
    """
    SMTP/ESMTP inspection bypass probes.
    Tests CHUNKING extension (BDAT bypass), nested MIME boundaries,
    large base64 attachments, and STARTTLS plaintext command injection.
    Returns list of finding dicts.
    """
    import base64
    import time

    findings = []

    def _smtp_read(s, timeout_s):
        """Read SMTP response lines until a final line (no dash after code)."""
        resp = b""
        deadline = time.monotonic() + timeout_s
        try:
            while time.monotonic() < deadline:
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp += chunk
                lines = resp.splitlines()
                if lines and len(lines[-1]) >= 4 and lines[-1][3:4] != b"-":
                    break
                if len(resp) > 8192:
                    break
        except Exception:
            pass
        return resp

    # --- EHLO + CHUNKING extension check (BDAT bypass) ---
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = _smtp_read(s, timeout)
            if banner.startswith(b"220"):
                s.sendall(b"EHLO ablation.probe\r\n")
                cap = _smtp_read(s, timeout)
                if b"CHUNKING" in cap.upper():
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "SMTP_CHUNKING_EXTENSION",
                        "detail": (
                            "SMTP server advertises CHUNKING (BDAT) extension — "
                            "ASA ESMTP inspection may not parse BDAT chunks, "
                            "enabling content-filter bypass"
                        ),
                        "host": host,
                        "port": port,
                    })
                s.sendall(b"QUIT\r\n")
    except Exception:
        pass

    # --- Nested MIME boundary ---
    outer_boundary = "outer_boundary_ablation"
    inner_boundary = "inner_boundary_ablation"
    nested_msg = "\r\n".join([
        "EHLO ablation.probe",
        "MAIL FROM:<test@ablation.probe>",
        f"RCPT TO:<postmaster@{host}>",
        "DATA",
        f"Subject: nested-mime-test\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: multipart/mixed; boundary=\"{outer_boundary}\"\r\n",
        f"--{outer_boundary}",
        f"Content-Type: multipart/alternative; boundary=\"{inner_boundary}\"",
        "",
        f"--{inner_boundary}",
        "Content-Type: text/plain",
        "",
        "test",
        f"--{inner_boundary}--",
        f"--{outer_boundary}--",
        ".",
        "QUIT",
        "",
    ]).encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = _smtp_read(s, timeout)
            if banner.startswith(b"220"):
                s.sendall(nested_msg)
                resp = b""
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    chunk = s.recv(2048)
                    if not chunk:
                        break
                    resp += chunk
                    if b"221" in resp or len(resp) > 16384:
                        break
                if b"250" in resp and b"221" in resp:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "SMTP_NESTED_MIME_ACCEPTED",
                        "detail": (
                            "SMTP server accepted message with nested MIME "
                            "boundaries — ASA ESMTP inspection may fail to "
                            "fully parse deeply nested MIME, enabling bypass"
                        ),
                        "host": host,
                        "port": port,
                    })
    except Exception:
        pass

    # --- Large base64 attachment (>10 MB) ---
    large_b64 = base64.b64encode(b"X" * (10 * 1024 * 1024)).decode()
    large_msg = (
        "EHLO ablation.probe\r\n"
        "MAIL FROM:<test@ablation.probe>\r\n"
        f"RCPT TO:<postmaster@{host}>\r\n"
        "DATA\r\n"
        "Subject: large-attach-test\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        f"{large_b64}\r\n"
        ".\r\n"
        "QUIT\r\n"
    ).encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = _smtp_read(s, timeout)
            if banner.startswith(b"220"):
                s.sendall(large_msg)
                resp = b""
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"221" in resp or b"552" in resp or len(resp) > 8192:
                        break
                if b"250" in resp and b"552" not in resp:
                    findings.append({
                        "severity": "HIGH",
                        "title": "SMTP_LARGE_ATTACHMENT_PASSED",
                        "detail": (
                            "SMTP server accepted >10 MB base64 attachment "
                            "without rejection — ASA ESMTP max-data-length "
                            "not enforced; large-file inspection bypass possible"
                        ),
                        "host": host,
                        "port": port,
                    })
    except Exception:
        pass

    # --- STARTTLS plaintext command injection ---
    starttls_inject = (
        b"EHLO ablation.probe\r\n"
        b"STARTTLS\r\n"
        b"MAIL FROM:<injected@ablation.probe>\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = _smtp_read(s, timeout)
            if banner.startswith(b"220"):
                s.sendall(starttls_inject)
                resp = b""
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    try:
                        chunk = s.recv(1024)
                        if not chunk:
                            break
                        resp += chunk
                        if len(resp) > 8192:
                            break
                    except Exception:
                        break
                lines = resp.splitlines()
                starttls_ready = any(
                    b"220" in ln and b"ready" in ln.lower() for ln in lines
                )
                mail_accepted = any(
                    ln.startswith(b"250") and b"sender" in ln.lower()
                    for ln in lines
                ) or (starttls_ready and resp.count(b"250") >= 2)
                if starttls_ready and mail_accepted:
                    findings.append({
                        "severity": "HIGH",
                        "title": "SMTP_STARTTLS_PLAINTEXT_BYPASS",
                        "detail": (
                            "SMTP server accepted MAIL FROM injected before "
                            "TLS handshake completed after STARTTLS — ASA "
                            "ESMTP inspection does not enforce clean TLS "
                            "negotiation boundary"
                        ),
                        "host": host,
                        "port": port,
                    })
    except Exception:
        pass

    return findings


def probe_asa_ips_module(host: str, port: int = 443,
                         timeout: float = 5.0) -> list:
    """
    ASA IPS/IDS module exposure probes via unauthenticated REST exec API.
    Checks for module slot disclosure, unauth IPS statistics, threat-detection
    data leakage, and botnet-traffic-filter config exposure.
    Derived from Cisco ASA All-in-One Firewall ch17 (IPS module architecture)
    and ch18 (IPS tuning/monitoring: show statistics, show statistics host).
    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    import urllib.request
    import urllib.error

    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # --- show module: IPS/IDS slot detection (POST, empty auth) ---
    show_module_url = f"https://{host}:{port}/admin/exec/show+module"
    try:
        req = urllib.request.Request(
            show_module_url,
            data=b"",
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                body = r.read().decode(errors="replace")
                body_lo = body.lower()
                if ("IPS" in body or "IDS" in body
                        or "ips-ssp" in body_lo
                        or "aip-ssm" in body_lo
                        or "aip-ssc" in body_lo):
                    findings.append({
                        "severity": "HIGH",
                        "title": "IPS_MODULE_DETECTED",
                        "detail": (
                            "show module exec endpoint returned without authentication "
                            "and discloses IPS/IDS module in chassis slot — module "
                            "type (AIP-SSM/AIP-SSC/IPS-SSP), firmware version, slot "
                            "assignment, and operational status readable by "
                            "unauthenticated client; confirms IPS is present and "
                            "allows targeted bypass of inspection lane"
                        ),
                        "host": host,
                        "port": port,
                    })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # --- show ips statistics: unauth IPS engine stats (GET) ---
    ips_stats_url = f"https://{host}:{port}/admin/exec/show+ips+statistics"
    try:
        req = urllib.request.Request(
            ips_stats_url,
            headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                body = r.read().decode(errors="replace")
                if body.strip():
                    findings.append({
                        "severity": "HIGH",
                        "title": "IPS_STATS_UNAUTH",
                        "detail": (
                            "show ips statistics exec endpoint accessible without "
                            "authentication — IPS engine counters, packet drop counts, "
                            "alert rates, and per-signature hit statistics readable; "
                            "reveals active signature tuning and detection posture "
                            "to unauthenticated client"
                        ),
                        "host": host,
                        "port": port,
                    })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # --- show threat-detection statistics: threat data leak (POST) ---
    threat_url = (f"https://{host}:{port}"
                  f"/admin/exec/show+threat-detection+statistics")
    try:
        req = urllib.request.Request(
            threat_url,
            data=b"",
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                body = r.read().decode(errors="replace")
                if body.strip():
                    findings.append({
                        "severity": "HIGH",
                        "title": "THREAT_DETECTION_DATA_LEAK",
                        "detail": (
                            "show threat-detection statistics exec endpoint returned "
                            "data without authentication — per-host attack rate "
                            "tables, scanner/DoS classification counters, and "
                            "internal IP reputation tracking data readable; exposes "
                            "which hosts the ASA is currently flagging as threats"
                        ),
                        "host": host,
                        "port": port,
                    })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # --- show botnet-traffic-filter statistics: filter config (GET) ---
    botnet_url = (f"https://{host}:{port}"
                  f"/admin/exec/show+botnet-traffic-filter+statistics")
    try:
        req = urllib.request.Request(
            botnet_url,
            headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                body = r.read().decode(errors="replace")
                if body.strip():
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "BOTNET_FILTER_CONFIG_EXPOSED",
                        "detail": (
                            "show botnet-traffic-filter statistics exec endpoint "
                            "accessible without authentication — botnet C2 block list "
                            "status, dynamic database update state, traffic match "
                            "counters, and allowlist/denylist entry counts readable "
                            "by unauthenticated client"
                        ),
                        "host": host,
                        "port": port,
                    })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    return findings


def probe_asa_application_inspection(host: str, port: int = 443,
                                     timeout: float = 5.0) -> list:
    """
    ASA application inspection engine exposure probes.
    Single POST to show service-policy inspect reveals all active engines;
    response is parsed for per-protocol state: FTP, SIP (NAT-T), RTSP, ESMTP.
    Derived from Cisco ASA All-in-One Firewall ch13 (application inspection:
    FTP strict mode, SIP pinholing, RTSP, ESMTP max-command-line) and ch05
    (MPF default class-map inspection policy with inspect ftp/rtsp/esmtp/sip).
    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    import urllib.request
    import urllib.error
    import re as _re

    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # --- show service-policy inspect: full inspection policy (POST) ---
    sp_url = f"https://{host}:{port}/admin/exec/show+service-policy+inspect"
    try:
        req = urllib.request.Request(
            sp_url,
            data=b"",
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            if r.status == 200:
                body = r.read().decode(errors="replace")
                if not body.strip():
                    return findings
                body_lo = body.lower()

                findings.append({
                    "severity": "HIGH",
                    "title": "INSPECTION_POLICY_EXPOSED",
                    "detail": (
                        "show service-policy inspect exec endpoint returned full "
                        "inspection policy without authentication — active inspection "
                        "engines, protocol enforcement rules, class-map bindings, "
                        "and per-engine packet/byte counters fully disclosed"
                    ),
                    "host": host,
                    "port": port,
                })

                # FTP inspection active
                if "inspect ftp" in body_lo or (
                        "ftp" in body_lo and "inspect" in body_lo):
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "FTP_INSPECTION_ACTIVE",
                        "detail": (
                            "Service policy shows FTP inspection engine active — "
                            "FTP command filtering, port-21 stateful tracking rules, "
                            "and strict-mode status (embedded-command blocking) "
                            "readable; FTP bounce protection posture disclosed to "
                            "unauthenticated client"
                        ),
                        "host": host,
                        "port": port,
                    })

                # SIP inspection without NAT traversal
                if "inspect sip" in body_lo or (
                        "sip" in body_lo and "inspect" in body_lo):
                    no_nat_t = ("nat-traversal" not in body_lo
                                and "nat_traversal" not in body_lo
                                and "natt" not in body_lo)
                    if no_nat_t:
                        findings.append({
                            "severity": "HIGH",
                            "title": "SIP_INSPECTION_WITHOUT_NAT",
                            "detail": (
                                "SIP inspection active but NAT traversal (NAT-T) "
                                "configuration absent from policy output — media "
                                "pinholing bypass possible; SDP address rewriting "
                                "may not occur for SIP-over-NAT flows, leaving RTP "
                                "media ports unforwarded and creating an inspection "
                                "gap exploitable for covert RTP tunneling"
                            ),
                            "host": host,
                            "port": port,
                        })

                # RTSP inspection configuration
                if "inspect rtsp" in body_lo or (
                        "rtsp" in body_lo and "inspect" in body_lo):
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "RTSP_INSPECTION_CONFIG",
                        "detail": (
                            "RTSP inspection engine state readable without "
                            "authentication — dynamic pinhole port ranges and data "
                            "channel rules disclosed; RTSP-over-HTTP tunneling "
                            "inspection status and packet counters visible"
                        ),
                        "host": host,
                        "port": port,
                    })

                # ESMTP inspection with max-command-line limit
                if "inspect esmtp" in body_lo or (
                        "esmtp" in body_lo and "inspect" in body_lo):
                    match = _re.search(
                        r'max.command.line["\s:=]+(\d+)', body, _re.IGNORECASE
                    )
                    if match and int(match.group(1)) > 0:
                        findings.append({
                            "severity": "MEDIUM",
                            "title": "SMTP_COMMAND_LIMIT_EXPOSED",
                            "detail": (
                                f"ESMTP inspection shows max-command-line limit of "
                                f"{match.group(1)} bytes — SMTP command-line "
                                f"enforcement threshold readable; discloses inspection "
                                f"policy tuning and headroom available for SMTP "
                                f"command-line injection attempts against the limit"
                            ),
                            "host": host,
                            "port": port,
                        })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    return findings


# Source: Cisco ASA All-in-One Firewall, IPS, Anti-X, and VPN Adaptive Security
# Appliance, 3rd Edition — Chapter 10 (Network Address Translation):
# Auto NAT (Network Object NAT) defines per-object policies where the ASA
# exposes the real/mapped IP pair; Manual NAT (Twice NAT) maps based on
# source+destination, revealing internal addressing via realIp/mappedIp keys.
# The /api/nat REST surface exposes the full translation table to any client
# that reaches the management plane without authentication.
def probe_asa_nat_config(
        host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe Cisco ASA REST API NAT endpoints for unauthenticated disclosure.

    Checks /api/nat/auto, /api/nat/rules/manual, /api/nat/rules/auto.
    If realIp/mappedIp keys are present in the response the finding detail
    includes a sample internal-to-external IP pair, which directly discloses
    the internal addressing scheme the NAT policy is hiding.

    Args:
        host: Target hostname or IP address.
        port: HTTPS port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    endpoints = [
        (
            f"https://{host}:{port}/api/nat/auto",
            "CRITICAL",
            "ASA_NAT_CONFIG_EXPOSED",
            (
                "Unauthenticated GET /api/nat/auto returned 200 — complete NAT "
                "configuration readable without credentials; ASA auto-NAT "
                "(Network Object NAT) table disclosed, including all object-to-"
                "translated-address mappings. Auto NAT rules are evaluated by "
                "specificity and reveal the full internal-to-external IP mapping "
                "policy applied to every protected network object."
            ),
        ),
        (
            f"https://{host}:{port}/api/nat/rules/manual",
            "CRITICAL",
            "ASA_MANUAL_NAT_EXPOSED",
            (
                "Unauthenticated GET /api/nat/rules/manual returned 200 — manual "
                "NAT rules (Twice NAT / Policy NAT) readable without credentials; "
                "source and destination address translation policies exposed, "
                "disclosing internal subnet structure, static IP mappings, PAT "
                "pool addresses, and identity NAT exemptions used for site-to-"
                "site VPN tunnels."
            ),
        ),
        (
            f"https://{host}:{port}/api/nat/rules/auto",
            "HIGH",
            "ASA_AUTO_NAT_EXPOSED",
            (
                "Unauthenticated GET /api/nat/rules/auto returned 200 — object "
                "NAT rule set readable without authentication; dynamic PAT pool "
                "addresses, static NAT one-to-one mappings, and PAT-pool round-"
                "robin configuration visible; combined with ARIN lookups, exposes "
                "the full internal addressing scheme behind the firewall."
            ),
        ),
    ]

    for url, sev, title, base_detail in endpoints:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                if resp.status != 200:
                    continue
                raw = resp.read(65536)
            try:
                data = json.loads(raw)
            except Exception:
                data = {}

            detail = base_detail

            # Extract a sample realIp/mappedIp pair to prove internal IP leak
            real_ip = None
            mapped_ip = None
            items = []
            if isinstance(data, dict):
                items = data.get("items", [data])
            elif isinstance(data, list):
                items = data
            for entry in items[:20]:
                if not isinstance(entry, dict):
                    continue
                ri = (
                    entry.get("realIp")
                    or entry.get("real_ip")
                    or entry.get("originalIp")
                )
                mi = (
                    entry.get("mappedIp")
                    or entry.get("mapped_ip")
                    or entry.get("translatedIp")
                )
                if ri and mi:
                    real_ip = ri
                    mapped_ip = mi
                    break
                # Nested under source/destination keys (Manual NAT structure)
                for sub_key in ("source", "destination", "original", "translated"):
                    sub = entry.get(sub_key, {})
                    if isinstance(sub, dict):
                        ri2 = sub.get("realIp") or sub.get("real_ip") or sub.get("ip")
                        mi2 = (
                            sub.get("mappedIp")
                            or sub.get("mapped_ip")
                            or sub.get("ip")
                        )
                        if ri2 and not real_ip:
                            real_ip = ri2
                        if mi2 and not mapped_ip:
                            mapped_ip = mi2
                if real_ip and mapped_ip:
                    break

            if real_ip and mapped_ip:
                detail += (
                    f"; REAL_TO_MAPPED_IP — internal IP visible: "
                    f"{real_ip} -> {mapped_ip}"
                )

            findings.append({
                "severity": sev,
                "title": title,
                "detail": detail,
                "host": host,
                "port": port,
            })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return findings


# Source: Cisco ASA All-in-One Firewall, IPS, Anti-X, and VPN Adaptive Security
# Appliance, 3rd Edition — Chapter 16 (High Availability):
# Failover designates one unit primary/active and one secondary/standby;
# stateful failover replicates the connection table, routing table, ARP table,
# and most VPN SAs. Clustering combines up to 16 identical ASAs into a single
# logical system with a master unit owning the control plane. Both surfaces
# are reachable via the REST API management plane and disclose HA topology,
# peer IP addresses, and unit roles to unauthenticated callers.
def probe_asa_ha_failover(
        host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe Cisco ASA REST API HA/failover and clustering endpoints.

    Checks /api/failover, /api/cluster/info, /api/ha/state.
    Role (active/standby) and peer IP are extracted from JSON responses
    when present and included in finding detail to demonstrate topology
    disclosure severity.

    Args:
        host: Target hostname or IP address.
        port: HTTPS port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # /api/failover — stateful failover role, peer IP, and link status
    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/api/failover",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read(65536)
                try:
                    data = json.loads(raw)
                except Exception:
                    data = {}

                detail = (
                    "Unauthenticated GET /api/failover returned 200 — HA topology "
                    "disclosed without credentials; failover configuration includes "
                    "unit roles (primary/secondary, active/standby), failover link "
                    "interface assignments, health-monitoring thresholds, stateful "
                    "replication link state, and Active/Active failover group "
                    "membership. Peer IP and switchover history readable."
                )

                body_str = raw.decode("utf-8", errors="replace").lower()
                role = None
                peer_ip = None

                if isinstance(data, dict):
                    role = (
                        data.get("unitRole")
                        or data.get("unit_role")
                        or data.get("role")
                        or data.get("state")
                    )
                    peer_ip = (
                        data.get("peerIp")
                        or data.get("peer_ip")
                        or data.get("peerAddress")
                        or data.get("standbyIp")
                        or data.get("standby_ip")
                    )
                    for sub_key in (
                        "peer", "standby", "failoverGroup",
                        "primaryUnit", "secondaryUnit",
                    ):
                        sub = data.get(sub_key, {})
                        if isinstance(sub, dict):
                            if not peer_ip:
                                peer_ip = (
                                    sub.get("ip")
                                    or sub.get("address")
                                    or sub.get("peerIp")
                                )
                            if not role:
                                role = sub.get("role") or sub.get("state")

                if not role:
                    if "active" in body_str:
                        role = "ACTIVE_UNIT"
                    elif "standby" in body_str:
                        role = "STANDBY_UNIT"

                if role or peer_ip:
                    parts = []
                    if role:
                        parts.append(f"unit role: {role}")
                    if peer_ip:
                        parts.append(f"peer IP: {peer_ip}")
                    detail += f"; HA topology detail — {', '.join(parts)}"

                findings.append({
                    "severity": "HIGH",
                    "title": "ASA_FAILOVER_STATE_EXPOSED",
                    "detail": detail,
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # /api/cluster/info — clustering master/slave role, CCL link, member list
    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/api/cluster/info",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read(65536)
                try:
                    data = json.loads(raw)
                except Exception:
                    data = {}

                detail = (
                    "Unauthenticated GET /api/cluster/info returned 200 — ASA "
                    "clustering configuration exposed without credentials; up to "
                    "16-unit cluster topology readable, including cluster control "
                    "link (CCL) interface assignments, master/slave unit roles, "
                    "health-check polling intervals, per-unit data interface state, "
                    "and spanned EtherChannel configuration. Full member IP list "
                    "discloses the complete cluster node inventory to an "
                    "unauthenticated caller."
                )

                if isinstance(data, dict):
                    cluster_name = (
                        data.get("clusterName")
                        or data.get("cluster_name")
                        or data.get("name")
                    )
                    master_ip = (
                        data.get("masterIp")
                        or data.get("master_ip")
                        or data.get("masterUnit")
                        or data.get("controllerIp")
                    )
                    members = data.get("members") or data.get("units") or []
                    extras = []
                    if cluster_name:
                        extras.append(f"cluster name: {cluster_name}")
                    if master_ip:
                        extras.append(f"master/controller IP: {master_ip}")
                    if isinstance(members, list) and members:
                        extras.append(f"member count: {len(members)}")
                    if extras:
                        detail += f"; cluster detail — {', '.join(extras)}"

                findings.append({
                    "severity": "HIGH",
                    "title": "ASA_CLUSTER_CONFIG_EXPOSED",
                    "detail": detail,
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    # /api/ha/state — HA state including failover group and unit designation
    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/api/ha/state",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read(65536)
                try:
                    data = json.loads(raw)
                except Exception:
                    data = {}

                body_str = raw.decode("utf-8", errors="replace").lower()
                detail = (
                    "Unauthenticated GET /api/ha/state returned 200 — real-time "
                    "HA state readable without authentication; active/standby "
                    "designation, failover group membership, and last-switchover "
                    "timestamp visible; stateful replication link operational "
                    "status and per-interface health-monitoring failure counts "
                    "disclosed."
                )

                ha_state = None
                failover_group = None
                if isinstance(data, dict):
                    ha_state = (
                        data.get("state")
                        or data.get("haState")
                        or data.get("unitState")
                        or data.get("role")
                    )
                    failover_group = (
                        data.get("failoverGroup")
                        or data.get("failover_group")
                        or data.get("group")
                    )

                if not ha_state:
                    if "active" in body_str:
                        ha_state = "ACTIVE_UNIT"
                    elif "standby" in body_str:
                        ha_state = "STANDBY_UNIT"

                if ha_state or failover_group:
                    parts = []
                    if ha_state:
                        parts.append(f"HA state: {ha_state}")
                    if failover_group:
                        parts.append(f"failover group: {failover_group}")
                    detail += f"; {', '.join(parts)}"

                findings.append({
                    "severity": "HIGH",
                    "title": "ASA_HA_STATE_EXPOSED",
                    "detail": detail,
                    "host": host,
                    "port": port,
                })
    except urllib.error.HTTPError:
        pass
    except Exception:
        pass

    return findings


def probe_asa_logging_config(
        host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe Cisco ASA REST API for unauthenticated logging and monitoring access.

    The ASA REST API exposes logging configuration and operational monitoring
    data at /api/logging, /api/monitoring/syslog, and /api/monitoring/connections.
    The exec endpoint /admin/exec/show+logging tunnels the 'show logging' CLI
    command.  Unauthenticated access discloses syslog server destinations,
    buffered log entries with internal IPs and %ASA message IDs, and the live
    connection table -- sufficient to map internal topology and infer defensive
    visibility gaps.  (Source: Cisco ASA All-in-One Firewall 3e, Ch. 5:
    System Logging, NetFlow NSEL, SNMP.)

    Args:
        host: Target hostname or IP address.
        port: HTTPS port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    checks = [
        (
            f"https://{host}:{port}/api/logging",
            "HIGH",
            "ASA_LOGGING_CONFIG_UNAUTH",
            (
                "Unauthenticated GET /api/logging returned 200 — global logging "
                "configuration readable without credentials; discloses syslog "
                "server destinations (UDP/TCP host and port), SNMP trap severity "
                "threshold, buffered logging level, ASDM logging level, "
                "debug-trace-as-syslog flag, Cisco EMBLEM format setting, "
                "and facility code; attacker can determine whether security "
                "events are forwarded externally and identify defensive "
                "visibility gaps in event correlation."
            ),
        ),
        (
            f"https://{host}:{port}/api/monitoring/syslog",
            "CRITICAL",
            "ASA_SYSLOG_MESSAGES_UNAUTH",
            (
                "Unauthenticated GET /api/monitoring/syslog returned 200 — "
                "buffered firewall log entries accessible without authentication; "
                "syslog records expose internal IP addresses, ACL hit counts, "
                "VPN session events, failover state transitions, connection "
                "setup and teardown, and %ASA message IDs that fingerprint "
                "the exact software version and active security policies; "
                "live defensive activity observable by unauthenticated attacker."
            ),
        ),
        (
            f"https://{host}:{port}/admin/exec/show+logging",
            "HIGH",
            "ASA_SHOW_LOGGING_UNAUTH",
            (
                "Unauthenticated GET /admin/exec/show+logging returned 200 — "
                "CLI 'show logging' output accessible via REST exec passthrough "
                "without authentication; discloses logging-enabled state, "
                "facility code, per-destination severity levels (console, "
                "monitor, buffer, trap, ASDM, email, history), buffer message "
                "count, and recent buffered %ASA syslog entries including "
                "internal network addresses and session identifiers."
            ),
        ),
        (
            f"https://{host}:{port}/api/monitoring/connections",
            "CRITICAL",
            "ASA_CONNECTION_TABLE_UNAUTH",
            (
                "Unauthenticated GET /api/monitoring/connections returned 200 — "
                "active firewall connection table accessible without credentials; "
                "flow entries expose source and destination IP pairs, protocol, "
                "port numbers, NAT-translated addresses, connection duration, "
                "interface assignments, and hit counters; reveals all hosts and "
                "services currently reachable through the perimeter, enabling "
                "internal topology mapping without any prior network access."
            ),
        ),
    ]

    for url, severity, title, detail in checks:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(
                    req, context=ctx, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": detail,
                        "host": host,
                        "port": port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return findings


def probe_asa_snmp_config(
        host: str, port: int = 161, timeout: float = 5.0) -> list:
    """Probe Cisco ASA SNMP agent for default community strings via UDP.

    The ASA listens on UDP/161 and responds to SNMPv1 GET PDUs for any
    configured community string; community strings are transmitted in cleartext
    with no challenge-response.  Cisco ASA does not permit SNMP SET PDUs, but
    read access via default community strings ('public', 'private', 'cisco')
    exposes the full MIB tree: sysDescr (software version), interface table,
    IP routing table, connection counts, and CPU/memory utilization.  The
    sysDescr OID (1.3.6.1.2.1.1.1.0) discloses platform and version sufficient
    for targeted CVE selection.  (Source: Cisco ASA All-in-One Firewall 3e,
    Ch. 5: Simple Network Management Protocol, Configuring SNMP, SNMP
    Monitoring; snmp-server community / snmp-server listen-port defaults.)

    Args:
        host: Target hostname or IP address.
        port: UDP SNMP port (default 161).
        timeout: Per-probe socket timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    import struct

    findings: list = []

    # OID 1.3.6.1.2.1.1.1.0 in BER encoding.
    # First two sub-identifiers: 40*1 + 3 = 43 = 0x2b; remainder as single bytes.
    SYSDESCR_OID_BYTES = b'\x2b\x06\x01\x02\x01\x01\x01\x00'

    def _tlv(tag: int, value: bytes) -> bytes:
        n = len(value)
        if n < 0x80:
            return bytes([tag, n]) + value
        elif n < 0x100:
            return bytes([tag, 0x81, n]) + value
        else:
            return bytes([tag, 0x82, (n >> 8) & 0xff, n & 0xff]) + value

    def _build_snmpv1_get(community: bytes) -> bytes:
        """Construct a minimal SNMPv1 GET-REQUEST PDU for sysDescr."""
        null = b'\x05\x00'
        oid = _tlv(0x06, SYSDESCR_OID_BYTES)
        varbind = _tlv(0x30, oid + null)
        varbinds = _tlv(0x30, varbind)

        # BER INTEGER for request-id; struct.pack for big-endian byte packing
        req_id_raw = struct.pack('>I', 1).lstrip(b'\x00') or b'\x00'
        if req_id_raw[0] & 0x80:
            req_id_raw = b'\x00' + req_id_raw
        req_id = _tlv(0x02, req_id_raw)

        error_status = b'\x02\x01\x00'
        error_index = b'\x02\x01\x00'
        pdu = _tlv(0xa0, req_id + error_status + error_index + varbinds)

        version = b'\x02\x01\x00'          # SNMPv1 = integer 0
        community_tlv = _tlv(0x04, community)
        return _tlv(0x30, version + community_tlv + pdu)

    def _extract_sysdescr(data: bytes) -> str:
        """Walk BER structure to extract sysDescr OctetString from GET-RESPONSE."""
        try:
            def read_tlv(buf, pos):
                tag = buf[pos]; pos += 1
                n = buf[pos]; pos += 1
                if n & 0x80:
                    nb = n & 0x7f
                    n = 0
                    for _ in range(nb):
                        n = (n << 8) | buf[pos]; pos += 1
                return tag, buf[pos:pos + n], pos + n

            tag, msg, _ = read_tlv(data, 0)
            if tag != 0x30:
                return ""
            pos = 0
            _, _, pos = read_tlv(msg, pos)    # version
            _, _, pos = read_tlv(msg, pos)    # community
            tag, pdu, _ = read_tlv(msg, pos)  # GetResponse-PDU (0xa2)
            if tag != 0xa2:
                return ""
            pos = 0
            _, _, pos = read_tlv(pdu, pos)    # req-id
            _, _, pos = read_tlv(pdu, pos)    # error-status
            _, _, pos = read_tlv(pdu, pos)    # error-index
            _, vbl, _ = read_tlv(pdu, pos)    # VarBindList
            _, vb, _ = read_tlv(vbl, 0)       # first VarBind
            pos = 0
            _, _, pos = read_tlv(vb, 0)       # OID
            tag, val, _ = read_tlv(vb, pos)   # value
            if tag == 0x04:
                return val.decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        return ""

    community_checks = [
        ("public",  "CRITICAL", "ASA_SNMP_PUBLIC_COMMUNITY",
         "SNMPv1 GET sysDescr with community string 'public' accepted — "
         "default read community active; sysDescr OID (1.3.6.1.2.1.1.1.0) "
         "returned without authentication; full MIB tree walk possible "
         "exposing interface table, IP routing table, active connection "
         "counts, and hardware/software inventory."),
        ("private", "CRITICAL", "ASA_SNMP_PRIVATE_COMMUNITY",
         "SNMPv1 GET sysDescr with community string 'private' accepted — "
         "default write community string active; Cisco ASA disallows SNMP "
         "SET PDUs for security reasons, but acceptance of 'private' "
         "confirms the community string is configured and valid for "
         "monitoring tools; full MIB read access without authentication."),
        ("cisco",   "HIGH",     "ASA_SNMP_CISCO_COMMUNITY",
         "SNMPv1 GET sysDescr with community string 'cisco' accepted — "
         "Cisco vendor-default community string active; indicates "
         "factory-default or minimal-hardening deployment; sysDescr and "
         "full MIB tree readable without authentication."),
    ]

    accepted: list = []

    for community_str, severity, title, base_detail in community_checks:
        pkt = _build_snmpv1_get(community_str.encode())
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(pkt, (host, port))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            # Valid SNMP response: outer SEQUENCE (0x30) + GetResponse-PDU tag (0xa2)
            if len(resp) > 4 and resp[0] == 0x30 and b'\xa2' in resp:
                sysdescr = _extract_sysdescr(resp)
                detail = base_detail
                if sysdescr:
                    detail += f"; sysDescr: {sysdescr[:200]}"
                findings.append({
                    "severity": severity,
                    "title": title,
                    "detail": detail,
                    "host": host,
                    "port": port,
                })
                accepted.append((community_str, resp))
        except Exception:
            pass

    # Extract version string from first accepted community's sysDescr response
    for community_str, resp in accepted:
        sysdescr = _extract_sysdescr(resp)
        if sysdescr and "cisco adaptive security appliance" in sysdescr.lower():
            low = sysdescr.lower()
            idx = low.find("version ")
            if idx >= 0:
                tail = sysdescr[idx + 8:]
                end = tail.find(" ")
                version_str = tail[:end] if end > 0 else tail[:24]
            else:
                version_str = sysdescr[:80]
            findings.append({
                "severity": "HIGH",
                "title": "ASA_VERSION_SNMP_DISCLOSED",
                "detail": (
                    f"SNMP sysDescr confirms Cisco ASA; version "
                    f"'{version_str}' disclosed via OID 1.3.6.1.2.1.1.1.0 "
                    f"with community string '{community_str}'; version "
                    f"disclosure enables targeted CVE selection; ASA 9.x "
                    f"releases prior to current patch carry known RCE and "
                    f"authentication-bypass vulnerabilities."
                ),
                "host": host,
                "port": port,
            })
            break

    return findings


# Source: Cisco ASA All-in-One Firewall, IPS, Anti-X, and VPN Adaptive Security
# Appliance, 3rd Edition — Chapter 21 (Configuring and Troubleshooting PKI):
# The ASA acts as a PKI client and optionally as a CA server; identity
# certificates prove the device's identity to VPN peers; trusted CA certificates
# anchor the trust chain; SCEP (Simple Certificate Enrollment Protocol) over
# HTTP/HTTPS is the default enrollment mechanism.  Trustpoints bind a CA and its
# associated enrollment policy (SCEP URL, CRL/OCSP check method, revocation
# override).  Unauthenticated REST access to certificate and trustpoint endpoints
# exposes the full PKI topology including CA URLs, revocation check servers, and
# weak algorithm indicators sufficient to plan certificate forgery or enrollment
# abuse attacks.
def probe_asa_pki_certificate_management(host: str, port: int = 443,
                                          timeout: float = 10.0) -> list:
    """Probe Cisco ASA REST API and CLI exec for PKI certificate management exposure.

    Checks unauthenticated access to identity certificate list, CA certificate
    list, full crypto CA certificate detail, weak signature algorithm use, and
    trustpoint configuration.  Weak algorithm detection parses the show crypto
    ca certificates CLI output for MD5 or SHA1 signature fields and appends a
    separate finding when found.

    Args:
        host: Target hostname or IP address.
        port: HTTPS port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple:
        """Return (status_code, body_str) or (None, None) on connection failure."""
        url = f"https://{host}:{port}{path}"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            return None, None

    # --- identity certificate list ---
    status, body = _get("/api/certificate/identity")
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "ASA_IDENTITY_CERTS_UNAUTH",
            "detail": (
                "Unauthenticated GET /api/certificate/identity returned 200 — "
                "installed identity certificates visible without credentials; "
                "certificate subject DN, issuer, serial number, validity window, "
                "and trustpoint binding readable; discloses which CAs signed the "
                "ASA identity and enables targeted certificate forgery or "
                "CA trust-chain attacks against VPN peers that rely on this "
                "identity for mutual authentication"
            ),
            "host": host,
            "port": port,
        })

    # --- CA certificate list ---
    status, body = _get("/api/certificate/ca")
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "ASA_CA_CERTS_UNAUTH",
            "detail": (
                "Unauthenticated GET /api/certificate/ca returned 200 — trusted "
                "CA certificates enumerable without authentication; full list of "
                "trusted root and subordinate CAs readable including subject DN, "
                "issuer, public key algorithm, and validity period; exposes the "
                "complete trust anchor set used for VPN peer and client identity "
                "authentication; CA inventory enables targeted rogue-CA attacks"
            ),
            "host": host,
            "port": port,
        })

    # --- show crypto ca certificates: full cert detail, algorithm disclosure ---
    status, body = _get("/admin/exec/show+crypto+ca+certificates")
    if status == 200 and body and body.strip():
        findings.append({
            "severity": "HIGH",
            "title": "ASA_CRYPTO_CA_CERTS_UNAUTH",
            "detail": (
                "Unauthenticated GET /admin/exec/show+crypto+ca+certificates "
                "returned 200 — CA certificate details including subject DN, "
                "issuer, serial number, and validity period readable without "
                "authentication via CLI exec passthrough; discloses the full "
                "installed certificate inventory used for IKE/SSL VPN trust "
                "validation and certificate-based device authentication"
            ),
            "host": host,
            "port": port,
        })

        # Detect weak signature algorithms in the returned output
        body_upper = body.upper()
        if "MD5" in body_upper or "SHA1" in body_upper or "SHA-1" in body_upper:
            alg = "MD5" if "MD5" in body_upper else "SHA1"
            findings.append({
                "severity": "HIGH",
                "title": "ASA_WEAK_CERT_ALGORITHM",
                "detail": (
                    f"Certificate details from show crypto ca certificates "
                    f"contain signature algorithm '{alg}' — weak certificate "
                    f"signature algorithm in use; {alg} is cryptographically "
                    f"broken (collision attacks practical); replace identity "
                    f"and CA certificates with SHA-256 or stronger equivalents "
                    f"to prevent certificate forgery"
                ),
                "host": host,
                "port": port,
            })

    # --- show crypto ca trustpoints: enrollment URL, CRL/OCSP config ---
    status, body = _get("/admin/exec/show+crypto+ca+trustpoints")
    if status == 200 and body and body.strip():
        findings.append({
            "severity": "MEDIUM",
            "title": "ASA_TRUSTPOINTS_UNAUTH",
            "detail": (
                "Unauthenticated GET /admin/exec/show+crypto+ca+trustpoints "
                "returned 200 — PKI trustpoint configuration exposed without "
                "authentication; trustpoint names, CA URL (SCEP/HTTP enrollment "
                "endpoints), CRL distribution points, OCSP server URLs, "
                "revocation-check method (crl/ocsp/none), and enrollment retry "
                "settings readable; enrollment URLs enable direct SCEP probing "
                "without prior reconnaissance"
            ),
            "host": host,
            "port": port,
        })

    return findings


# Source: Cisco ASA All-in-One Firewall, IPS, Anti-X, and VPN Adaptive Security
# Appliance, 3rd Edition — Chapter 21 (Configuring and Troubleshooting PKI):
# SCEP (RFC 8894) is the default enrollment mechanism for ASA certificate
# acquisition; the ASA acts as a SCEP client and the CA server exposes the
# pkiclient.exe CGI path on HTTP (port 80) or HTTPS (port 443). GetCACert
# returns the CA public certificate; GetCACaps discloses supported algorithms.
# Exposed SCEP endpoints allow unauthenticated CA cert retrieval and reveal
# enrollment URLs needed to submit rogue enrollment requests.
def probe_asa_scep_enrollment(host: str, port: int = 80,
                               timeout: float = 10.0) -> list:
    """Probe ASA SCEP enrollment endpoint for unauthenticated access.

    Tests the standard pkiclient.exe SCEP path on HTTP and HTTPS (port 443),
    the GetCACert and GetCACaps operations, and the alternate /scep path.
    Both HTTP and HTTPS surfaces are checked independently; findings carry
    the port on which the response was received.

    Args:
        host: Target hostname or IP address.
        port: Primary HTTP port (default 80).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []

    def _http_get(url: str, use_ssl: bool) -> tuple:
        """Return (status_code, body_str) or (None, None) on connection failure."""
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
        )
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(
                        req, context=ctx, timeout=timeout) as r:
                    return r.status, r.read().decode(errors="replace")
            else:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    https_port = 443

    # --- HTTP GetCACert ---
    url = (f"http://{host}:{port}"
           f"/cgi-bin/pkiclient.exe?operation=GetCACert")
    status, body = _http_get(url, use_ssl=False)
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "ASA_SCEP_ENDPOINT_EXPOSED",
            "detail": (
                f"GET {url} returned 200 — SCEP enrollment endpoint "
                f"accessible without authentication; CA certificate returned "
                f"via SCEP GetCACert operation; enrollment endpoint disclosure "
                f"enables unauthorized certificate enrollment attempts and CA "
                f"public key retrieval for trust-chain analysis"
            ),
            "host": host,
            "port": port,
        })

    # --- HTTP GetCACaps ---
    url = (f"http://{host}:{port}"
           f"/cgi-bin/pkiclient.exe?operation=GetCACaps")
    status, body = _http_get(url, use_ssl=False)
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "ASA_SCEP_CAPABILITIES_DISCLOSED",
            "detail": (
                f"GET {url} returned 200 — SCEP algorithm capabilities "
                f"exposed without authentication; GetCACaps response discloses "
                f"supported encryption algorithms, hash functions, and SCEP "
                f"extensions (SHA-1, SHA-256, AES, 3DES) enabling targeted "
                f"enrollment algorithm downgrade or capability enumeration"
            ),
            "host": host,
            "port": port,
        })

    # --- HTTPS GetCACert on port 443 ---
    url = (f"https://{host}:{https_port}"
           f"/cgi-bin/pkiclient.exe?operation=GetCACert")
    status, body = _http_get(url, use_ssl=True)
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "ASA_SCEP_ENDPOINT_EXPOSED",
            "detail": (
                f"GET {url} returned 200 — SCEP enrollment endpoint "
                f"accessible over HTTPS without authentication; CA certificate "
                f"returned via GetCACert operation on TLS port {https_port}; "
                f"TLS transport does not restrict access to the SCEP surface"
            ),
            "host": host,
            "port": https_port,
        })

    # --- HTTPS GetCACaps on port 443 ---
    url = (f"https://{host}:{https_port}"
           f"/cgi-bin/pkiclient.exe?operation=GetCACaps")
    status, body = _http_get(url, use_ssl=True)
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "ASA_SCEP_CAPABILITIES_DISCLOSED",
            "detail": (
                f"GET {url} returned 200 — SCEP algorithm capabilities "
                f"exposed over HTTPS without authentication on port "
                f"{https_port}; GetCACaps response discloses supported "
                f"cryptographic algorithms available for enrollment"
            ),
            "host": host,
            "port": https_port,
        })

    # --- alternate SCEP path: /scep ---
    url = f"http://{host}:{port}/scep"
    status, body = _http_get(url, use_ssl=False)
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "ASA_SCEP_ALT_PATH",
            "detail": (
                f"GET {url} returned 200 — alternate SCEP path /scep "
                f"accessible without authentication; non-standard enrollment "
                f"path active; discloses SCEP service presence and may allow "
                f"unauthenticated certificate enrollment or CA key retrieval "
                f"via a path not covered by standard SCEP hardening guidance"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_cisco_ios_smart_install(host: str, port: int = 4786,
                                   timeout: float = 10.0) -> list:
    """Probe Cisco IOS Smart Install (CVE-2018-0171) and IOS XE WebUI (CVE-2023-20198).

    Smart Install is a legacy zero-touch provisioning feature present in IOS and
    IOS XE that listens on TCP/4786. The protocol requires no authentication and
    allows a director to push arbitrary IOS images and startup-config to client
    switches. CVE-2018-0171 (CVSS 9.8) exposes unauthenticated remote code
    execution via a malformed Smart Install message. Cisco advisory
    cisco-sa-20180328-smi recommends disabling with 'no vstack' in global config.

    IOS XE WebUI (CVE-2023-20198, CVSS 10.0) allows an unauthenticated attacker
    to create a level-15 administrator account through the HTTP server interface.
    The /webui/logoutconfirm.html?logon_hash=1 path was the documented in-the-wild
    exploitation vector. /api/v1/global/local-users returns the user database
    without credentials on unpatched systems.

    Args:
        host: Target hostname or IP address.
        port: Smart Install TCP port (default 4786).
        timeout: Per-probe timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    webui_port = 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, req_port: int = 443) -> tuple:
        """Return (status_code, body_str) or (None, None) on failure."""
        url = f"https://{host}:{req_port}{path}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html,*/*"},
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    # --- Smart Install TCP probe (CVE-2018-0171) ---
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            findings.append({
                "severity": "HIGH",
                "title": "CISCO_SMART_INSTALL_PORT_OPEN",
                "detail": (
                    f"TCP/{port} open on {host} — Cisco IOS Smart Install "
                    f"director port reachable; Smart Install is a zero-touch "
                    f"provisioning protocol that requires no authentication; "
                    f"CVE-2018-0171 (CVSS 9.8) allows unauthenticated remote "
                    f"code execution via a malformed Smart Install message; "
                    f"Cisco advisory cisco-sa-20180328-smi recommends disabling "
                    f"with 'no vstack' in IOS global config and blocking "
                    f"TCP/4786 at the perimeter"
                ),
                "host": host,
                "port": port,
            })
            # Send Smart Install director identification frame
            probe = b'\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x08'
            sock.sendall(probe)
            sock.settimeout(timeout)
            try:
                banner = sock.recv(256)
            except Exception:
                banner = b""
            # Director magic: response begins with SMI message header prefix or
            # contains protocol-specific content (min 4-byte header required)
            if banner and len(banner) >= 4 and (
                banner[:3] == b'\x00\x00\x00'
                or b'TFTP' in banner
                or b'cisco' in banner.lower()
            ):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "CISCO_SMART_INSTALL_EXPOSED",
                    "detail": (
                        f"Smart Install director responded on TCP/{port} with "
                        f"{len(banner)} bytes ({banner[:16].hex()}); "
                        f"device accepted the Smart Install identification frame "
                        f"and returned a director protocol response; "
                        f"unauthenticated director session confirmed — attacker "
                        f"can push arbitrary IOS images and overwrite "
                        f"startup-config without credentials (CVE-2018-0171, "
                        f"CVSS 9.8); remediation: 'no vstack' in global config "
                        f"and ACL blocking TCP/4786 at all perimeter points"
                    ),
                    "host": host,
                    "port": port,
                })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    # --- IOS XE WebUI presence (CVE-2023-20198) ---
    status, body = _get("/webui/", req_port=webui_port)
    if status is not None and body and (
        "IOS" in body or "Cisco" in body
        or "webui" in body.lower() or "login" in body.lower()
    ):
        findings.append({
            "severity": "HIGH",
            "title": "CISCO_IOS_XE_WEBUI",
            "detail": (
                f"GET https://{host}:{webui_port}/webui/ returned {status} "
                f"with IOS XE WebUI page indicators; Cisco IOS XE HTTP server "
                f"management interface exposed; CVE-2023-20198 (CVSS 10.0) "
                f"allows unauthenticated creation of a level-15 administrator "
                f"account via this interface; Cisco advisory "
                f"cisco-sa-iosxe-webui-privesc-j22SaA4z; disable HTTP server "
                f"('no ip http server', 'no ip http secure-server') or "
                f"restrict access with 'ip http access-class'"
            ),
            "host": host,
            "port": webui_port,
        })

    # --- IOS XE auth bypass exploitation path (CVE-2023-20198) ---
    status, body = _get(
        "/webui/logoutconfirm.html?logon_hash=1",
        req_port=webui_port,
    )
    if status is not None and status not in (404,) and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "CISCO_IOS_XE_AUTH_BYPASS",
            "detail": (
                f"GET https://{host}:{webui_port}/webui/logoutconfirm.html"
                f"?logon_hash=1 returned {status} with {len(body)} bytes — "
                f"authentication bypass endpoint for CVE-2023-20198 responded; "
                f"this path was the documented in-the-wild exploitation vector "
                f"for unauthenticated privilege escalation to level 15 on "
                f"Cisco IOS XE; active exploitation observed October 2023 at "
                f"scale; immediate remediation: apply Cisco advisory "
                f"cisco-sa-iosxe-webui-privesc-j22SaA4z and audit for "
                f"implanted user accounts"
            ),
            "host": host,
            "port": webui_port,
        })

    # --- IOS XE unauthenticated local-users enumeration ---
    status, body = _get("/api/v1/global/local-users", req_port=webui_port)
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "CISCO_IOS_XE_UNAUTH_USER_ENUM",
            "detail": (
                f"GET https://{host}:{webui_port}/api/v1/global/local-users "
                f"returned 200 without authentication — local user database "
                f"enumerable unauthenticated; response discloses configured "
                f"usernames and privilege levels; confirms either active "
                f"exploitation of CVE-2023-20198 or misconfigured IOS XE HTTP "
                f"server access control; response length {len(body)} bytes"
            ),
            "host": host,
            "port": webui_port,
        })

    return findings


def probe_cisco_asdm_management(host: str, port: int = 443,
                                 timeout: float = 10.0) -> list:
    """Probe Cisco ASA ASDM management interface and AnyConnect portal.

    The Adaptive Security Device Manager (ASDM) is the HTTPS-based GUI for
    Cisco ASA firewalls, served from /admin/ on port 443 alongside IPsec and
    SSL VPN services. ASDM is enabled with 'http server enable' and 'asdm image'
    in global config; the management station downloads the launcher from
    /admin/public/index.html. The /admin/exec/ path proxies ASA CLI commands
    and may be reachable without authentication on misconfigured devices.

    CVE-2020-3259 (CVSS 7.5) allows unauthenticated file read from flash via
    the AnyConnect OEM customization endpoint /+CSCOT+/oem-customization. The
    AnyConnect portal (/+CSCOE+/logon.html) expands attack surface with
    additional historically vulnerable paths.

    Args:
        host: Target hostname or IP address.
        port: HTTPS port for ASDM and AnyConnect (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str) -> tuple:
        """Return (status_code, body_str) or (None, None) on failure."""
        url = f"https://{host}:{port}{path}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html,*/*"},
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    # --- ASDM launcher page detection ---
    status, body = _get("/admin/public/index.html")
    if status is not None and body and (
        "ASDM" in body or "Adaptive Security" in body
        or "asdm" in body.lower()
    ):
        findings.append({
            "severity": "HIGH",
            "title": "CISCO_ASDM_LOGIN_PAGE",
            "detail": (
                f"GET https://{host}:{port}/admin/public/index.html "
                f"returned {status} with ASDM launcher page indicators; "
                f"Cisco Adaptive Security Device Manager management interface "
                f"exposed on port {port}; ASDM provides full ASA configuration "
                f"and monitoring access; presence confirms 'http server enable' "
                f"and 'asdm image' in running-config; verify 'http' ACL entries "
                f"restrict source addresses — 'http 0.0.0.0 0.0.0.0 <iface>' "
                f"permits management access from any host"
            ),
            "host": host,
            "port": port,
        })

    # --- Unauthenticated ASDM exec: show version ---
    status, body = _get("/admin/exec/show+version")
    if status == 200 and body and (
        "Cisco Adaptive Security" in body or "Version" in body
        or "Serial" in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "CISCO_ASDM_UNAUTH_EXEC",
            "detail": (
                f"GET https://{host}:{port}/admin/exec/show+version "
                f"returned 200 with ASA version output — unauthenticated CLI "
                f"exec endpoint accessible; ASDM /admin/exec/ proxies ASA CLI "
                f"'show' commands without authentication; attacker can enumerate "
                f"software version, enabled features, license state, hardware "
                f"model, and serial number without credentials; "
                f"body excerpt: {body[:200].strip()!r}"
            ),
            "host": host,
            "port": port,
        })

    # --- CVE-2020-3259: AnyConnect OEM customization unauth file read ---
    status, body = _get(
        "/+CSCOT+/oem-customization"
        "?app=AnyConnect&type=oem&platform=mac&resource-type=image"
    )
    if status is not None and status not in (400, 404) and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "CISCO_ASA_ANYCONNECT_FILE_READ",
            "detail": (
                f"GET https://{host}:{port}/+CSCOT+/oem-customization"
                f"?app=AnyConnect&type=oem&platform=mac&resource-type=image "
                f"returned {status} — CVE-2020-3259 (CVSS 7.5) AnyConnect OEM "
                f"customization endpoint responded; unauthenticated attackers "
                f"can read arbitrary files from ASA flash memory via this path; "
                f"sensitive targets include VPN session cookies and config "
                f"fragments; response length {len(body)} bytes; patch to "
                f"ASA 9.8.4.34, 9.12.4.26, 9.14.2.15, or 9.15.1.15+"
            ),
            "host": host,
            "port": port,
        })

    # --- AnyConnect clientless SSL VPN portal detection ---
    status, body = _get("/+CSCOE+/logon.html")
    if status is not None and body and (
        "AnyConnect" in body or "SSL VPN" in body
        or "webvpn" in body.lower() or "CSCOE" in body
        or "logon" in body.lower()
    ):
        findings.append({
            "severity": "MEDIUM",
            "title": "CISCO_ANYCONNECT_PORTAL",
            "detail": (
                f"GET https://{host}:{port}/+CSCOE+/logon.html "
                f"returned {status} with AnyConnect portal indicators; "
                f"Cisco AnyConnect / clientless SSL VPN portal exposed; "
                f"portal surface includes historically vulnerable paths: "
                f"authentication bypass CVE-2014-2128, session fixation "
                f"CVE-2014-2127, and OEM file-read chain CVE-2020-3259; "
                f"confirm 'webvpn' is intentionally enabled and access is "
                f"source-restricted"
            ),
            "host": host,
            "port": port,
        })

    # --- Unauthenticated WebVPN statistics via ASDM exec ---
    status, body = _get("/admin/exec/show+webvpn+statistics")
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "CISCO_ASDM_WEBVPN_STATS",
            "detail": (
                f"GET https://{host}:{port}/admin/exec/show+webvpn+statistics "
                f"returned 200 — unauthenticated exec endpoint reveals WebVPN "
                f"session statistics including active session counts, session "
                f"IDs, connection timestamps, and tunnel group names; session "
                f"metadata enables targeted enumeration or credential attacks; "
                f"response length {len(body)} bytes"
            ),
            "host": host,
            "port": port,
        })

    # --- Default credential probe against WebVPN portal ---
    default_creds = [("cisco", "cisco"), ("admin", "admin"), ("admin", "cisco")]
    for username, password in default_creds:
        post_body = (
            f"tgroup=&next=&tgcookieset=&username={username}"
            f"&password={password}&Login=Login"
        ).encode()
        url = f"https://{host}:{port}/+webvpn+/index.html"
        req = urllib.request.Request(
            url,
            data=post_body,
            method="POST",
            headers={
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,*/*",
            },
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                resp_body = r.read().decode(errors="replace")
                resp_status = r.status
        except urllib.error.HTTPError as e:
            try:
                resp_body = e.read().decode(errors="replace")
            except Exception:
                resp_body = ""
            resp_status = e.code
        except Exception:
            continue
        # Auth success: redirect away from logon page or portal content present
        auth_success = (
            resp_status in (200, 302)
            and (
                "webvpn_logo" in resp_body
                or "tunnel-group" in resp_body
                or resp_status == 302
            )
            and "logon" not in resp_body.lower()
        )
        if auth_success:
            findings.append({
                "severity": "CRITICAL",
                "title": "CISCO_DEFAULT_CREDS",
                "detail": (
                    f"POST https://{host}:{port}/+webvpn+/index.html with "
                    f"credentials {username!r}/{password!r} returned "
                    f"{resp_status} with authentication success indicators; "
                    f"default credentials accepted on Cisco ASA WebVPN portal; "
                    f"attacker gains full VPN tunnel access and, combined with "
                    f"ASDM level-15 access, can reconfigure the firewall; "
                    f"change default credentials immediately"
                ),
                "host": host,
                "port": port,
            })
            break

    return findings


def probe_cisco_dnac_api_exposure(host: str, port: int = 443,
                                   timeout: float = 10.0) -> list:
    """Probe Cisco DNA Center / Catalyst Center northbound REST API exposure.

    Cisco DNA Center (rebranded Catalyst Center in 2023) is the SDN controller
    for Cisco Digital Network Architecture. It exposes a northbound Intent API
    under /dna/intent/api/v1/ that provides full read/write access to the entire
    managed network: device inventory, site hierarchy, CLI templates, network
    discovery credentials, and user management.

    Authentication (from DevNet Associate certification material, Chapter 8):
    - POST /dna/system/api/v1/auth/token with Basic auth (base64 user:pass)
    - Returns JSON {"Token": "<jwt>"} used as X-Auth-Token on all subsequent calls
    - Default production cred: admin/Maglev1@3 (Maglev cluster bootstrap default)
    - DevNet sandbox cred: devnetuser/Cisco123!

    Unauthenticated access to Intent API endpoints is possible on misconfigured
    instances where the API bundle is enabled but auth middleware is bypassed, or
    when an internal network segment hosts the appliance without perimeter controls.

    Args:
        host: Target hostname or IP address.
        port: HTTPS port for DNA Center UI and API (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, token: str = "") -> tuple:
        """Return (status_code, body_str) or (None, None) on connection failure."""
        url = f"https://{host}:{port}{path}"
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json, text/html, */*",
        }
        if token:
            headers["X-Auth-Token"] = token
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    def _post_auth(username: str, password: str) -> tuple:
        """POST Basic-auth token request; return (status, body_str) or (None, None)."""
        cred = base64.b64encode(f"{username}:{password}".encode()).decode()
        url = f"https://{host}:{port}/dna/system/api/v1/auth/token"
        req = urllib.request.Request(
            url,
            data=b"",
            method="POST",
            headers={
                "Authorization": f"Basic {cred}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    # --- Portal fingerprint: look for DNA/Catalyst Center branding ---
    status, body = _get("/")
    if status is not None and body and (
        "Cisco DNA Center" in body
        or "Catalyst Center" in body
        or "Maglev" in body
        or "dnacenter" in body.lower()
        or "dna-center" in body.lower()
    ):
        findings.append({
            "severity": "MEDIUM",
            "title": "DNAC_PORTAL_FINGERPRINT",
            "detail": (
                f"GET https://{host}:{port}/ returned {status} with Cisco "
                f"DNA Center / Catalyst Center branding markers; controller "
                f"identity confirmed; northbound Intent API likely reachable "
                f"at /dna/intent/api/v1/*; enumerate auth token endpoint "
                f"/dna/system/api/v1/auth/token next"
            ),
            "host": host,
            "port": port,
        })

    # --- Default credential spray: Maglev bootstrap + known weak creds ---
    # Maglev1@3 is the Cisco-documented bootstrap password for the Maglev
    # cluster that underpins DNA Center appliances (production default).
    _dnac_spray = [
        ("admin", "Maglev1@3"),     # production Maglev bootstrap default
        ("admin", "C1sco12345"),
        ("admin", "Admin1234!"),
        ("admin", "Cisco123!"),
        ("devnetuser", "Cisco123!"),  # DevNet sandbox default (book ch. 8)
    ]
    obtained_token = ""
    for uname, passwd in _dnac_spray:
        st, bdy = _post_auth(uname, passwd)
        if st == 200 and bdy:
            try:
                tok = json.loads(bdy).get("Token", "")
            except Exception:
                tok = ""
            if tok:
                is_maglev_default = (passwd == "Maglev1@3")
                obtained_token = tok
                findings.append({
                    "severity": "CRITICAL",
                    "title": "DNAC_DEFAULT_CREDS" if is_maglev_default else "DNAC_WEAK_CREDS",
                    "detail": (
                        f"POST https://{host}:{port}/dna/system/api/v1/auth/token "
                        f"with Basic {uname!r}/{passwd!r} returned 200 and a valid "
                        f"JWT (Token field present); full northbound API access "
                        f"granted; attacker can enumerate all managed devices, "
                        f"deploy config templates, extract SNMP/SSH credentials "
                        f"stored in the global credential store, and reconfigure "
                        f"the entire managed network; change default credentials "
                        f"immediately via System > Settings > Change Password"
                    ),
                    "host": host,
                    "port": port,
                })
                break  # stop at first success

    # --- Unauthenticated device inventory ---
    status, body = _get("/dna/intent/api/v1/network-device")
    if status == 200 and body:
        try:
            data = json.loads(body)
            device_count = len(data.get("response", [])) if isinstance(data, dict) else 0
        except Exception:
            data = None
            device_count = 0
        if data is not None and ("response" in str(body) or device_count > 0):
            findings.append({
                "severity": "CRITICAL",
                "title": "DNAC_DEVICES_UNAUTH",
                "detail": (
                    f"GET https://{host}:{port}/dna/intent/api/v1/network-device "
                    f"returned {status} without authentication; device inventory "
                    f"accessible unauthenticated ({device_count} devices enumerated); "
                    f"response contains hostname, management IP, platform, software "
                    f"version, serial number, and reachability status for every "
                    f"managed device; enables targeted CVE exploitation against "
                    f"specific IOS/NX-OS versions without requiring any credentials"
                ),
                "host": host,
                "port": port,
            })

    # --- Unauthenticated site hierarchy ---
    status, body = _get("/dna/intent/api/v1/site")
    if status == 200 and body and "siteNameHierarchy" in body:
        findings.append({
            "severity": "HIGH",
            "title": "DNAC_SITES_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/dna/intent/api/v1/site returned "
                f"{status} without authentication; full site hierarchy exposed "
                f"including geographic groupings, building names, and floor maps; "
                f"provides physical network topology and device placement intel "
                f"for physical-layer attack planning"
            ),
            "host": host,
            "port": port,
        })

    # --- CLI template access (Command Runner legit-reads) ---
    status, body = _get("/dna/intent/api/v1/network-device-poller/cli/legit-reads")
    if status == 200 and body and (
        "commands" in body.lower() or "response" in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "DNAC_CLI_TEMPLATES_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/dna/intent/api/v1/network-device-poller"
                f"/cli/legit-reads returned {status} without authentication; "
                f"Command Runner read-only command set exposed; combined with "
                f"write access this endpoint enables arbitrary CLI execution "
                f"across all managed devices in the network"
            ),
            "host": host,
            "port": port,
        })

    # --- User management endpoint ---
    status, body = _get("/api/system/v1/identitymgmt/users")
    if status == 200 and body and (
        "username" in body.lower() or "authSource" in body
        or "response" in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "DNAC_USERS_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/system/v1/identitymgmt/users "
                f"returned {status} without authentication; user account database "
                f"accessible; exposes DNA Center local user accounts, roles, and "
                f"auth sources; enables targeted credential attacks against named "
                f"admin accounts"
            ),
            "host": host,
            "port": port,
        })

    # --- Network discoveries (may contain SNMP community strings) ---
    status, body = _get("/dna/intent/api/v1/discovery")
    if status == 200 and body and "response" in body:
        findings.append({
            "severity": "HIGH",
            "title": "DNAC_DISCOVERIES_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/dna/intent/api/v1/discovery returned "
                f"{status} without authentication; network discovery jobs exposed; "
                f"each discovery record references the credential profile used for "
                f"device access during initial discovery"
            ),
            "host": host,
            "port": port,
        })
        # Check for leaked SNMP community strings in discovery response
        _snmp_markers = ("communityString", "snmpV2", "snmpCommunity", "community")
        if any(m in body for m in _snmp_markers):
            findings.append({
                "severity": "CRITICAL",
                "title": "DNAC_SNMP_CREDS_LEAKED",
                "detail": (
                    f"GET https://{host}:{port}/dna/intent/api/v1/discovery "
                    f"returned {status} and body contains SNMP community string "
                    f"markers ({[m for m in _snmp_markers if m in body]}); "
                    f"SNMP community strings stored in discovery profiles are "
                    f"exposed in plaintext; attacker gains read/write SNMP access "
                    f"to all devices seeded in the discovery range"
                ),
                "host": host,
                "port": port,
            })

    # --- Platform version disclosure ---
    status, body = _get("/dna/intent/api/v1/dnac-release")
    if status == 200 and body:
        try:
            ver_data = json.loads(body)
            ver_str = str(ver_data.get("response", {}).get("name", "")) if isinstance(ver_data, dict) else ""
        except Exception:
            ver_str = ""
        ver_display = repr(ver_str) if ver_str else "disclosed in response"
        findings.append({
            "severity": "MEDIUM",
            "title": "DNAC_VERSION_DISCLOSED",
            "detail": (
                f"GET https://{host}:{port}/dna/intent/api/v1/dnac-release "
                f"returned {status}; platform version {ver_display}; "
                f"version string enables targeted CVE matching against specific "
                f"DNA Center appliance firmware and Maglev cluster versions"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_cisco_catalyst_center_credentials(host: str, port: int = 443,
                                              timeout: float = 10.0) -> list:
    """Probe Cisco Catalyst Center (DNA Center) credential exposure vectors.

    Catalyst Center (formerly Cisco DNA Center) stores network device credentials
    in a central global credential store accessible via the Intent API. This store
    holds SNMP community strings (v2c/v3), SSH/Telnet usernames and passwords,
    HTTP credentials, and HTTPS credentials used during network discovery and
    device provisioning. On misconfigured or default-credential instances these
    are readable without authentication or with a single valid API token.

    The Maglev internal API (/api/v1/credential) exposes the credential objects
    in the cluster's internal service mesh, bypassing the northbound auth layer
    on some versions. ISE integration settings may leak the ISE admin password
    stored for synchronization. Backup status endpoints reveal backup destinations
    (NFS/SFTP paths) and credentials.

    Source: Cisco DevNet Associate certification material (Chapter 8: Cisco DNA
    Center REST APIs), Cisco DNAC API documentation v1.3, Maglev cluster
    architecture documentation.

    Args:
        host: Target hostname or IP address.
        port: HTTPS port for Catalyst Center API (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, token: str = "") -> tuple:
        """Return (status_code, body_str) or (None, None) on connection failure."""
        url = f"https://{host}:{port}{path}"
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json, */*",
        }
        if token:
            headers["X-Auth-Token"] = token
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    # --- Global credential store: SNMP/SSH/HTTP device credentials ---
    # Intent API /dna/intent/api/v1/global-credential holds all credential
    # profiles used by DNA Center to communicate with managed devices.
    status, body = _get("/dna/intent/api/v1/global-credential")
    if status == 200 and body:
        try:
            cred_data = json.loads(body)
            cred_list = cred_data.get("response", []) if isinstance(cred_data, dict) else []
            cred_count = len(cred_list)
        except Exception:
            cred_data = None
            cred_list = []
            cred_count = 0
        if cred_data is not None:
            findings.append({
                "severity": "CRITICAL",
                "title": "CATALYST_GLOBAL_CREDS_UNAUTH",
                "detail": (
                    f"GET https://{host}:{port}/dna/intent/api/v1/global-credential "
                    f"returned {status} without authentication; global credential "
                    f"store exposed ({cred_count} credential profiles); store contains "
                    f"SNMP community strings, SSH/Telnet usernames and passwords, "
                    f"and HTTP/HTTPS credentials used by Catalyst Center to access "
                    f"all managed devices; provides direct lateral movement path "
                    f"to every device in the managed network"
                ),
                "host": host,
                "port": port,
            })
            # Check for plaintext credential fields in the response
            _plaintext_markers = (
                "communityString", "username", "password", "writeCommunity",
                "authPassword", "privPassword", "enablePassword",
            )
            found_markers = [m for m in _plaintext_markers if m in body]
            if found_markers:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "CATALYST_PLAINTEXT_CREDS",
                    "detail": (
                        f"GET https://{host}:{port}/dna/intent/api/v1/global-credential "
                        f"response contains plaintext credential field markers: "
                        f"{found_markers}; Catalyst Center stores device credentials "
                        f"(SNMP community strings, SSH passwords, enable passwords) "
                        f"in recoverable form within the MongoDB datastore; credential "
                        f"material is directly usable for device access without "
                        f"further cracking"
                    ),
                    "host": host,
                    "port": port,
                })

    # --- Device running-config pull via network-device config endpoint ---
    # First attempt to get a device ID from inventory, then pull running config
    status_dev, body_dev = _get("/dna/intent/api/v1/network-device")
    device_id = ""
    if status_dev == 200 and body_dev:
        try:
            dev_data = json.loads(body_dev)
            dev_list = dev_data.get("response", []) if isinstance(dev_data, dict) else []
            if dev_list:
                device_id = dev_list[0].get("id", "")
        except Exception:
            device_id = ""
    if device_id:
        cfg_path = f"/dna/intent/api/v1/network-device/{device_id}/config"
        status, body = _get(cfg_path)
        if status == 200 and body and (
            "hostname" in body.lower()
            or "interface" in body.lower()
            or "version" in body.lower()
            or "ip address" in body.lower()
        ):
            findings.append({
                "severity": "CRITICAL",
                "title": "CATALYST_DEVICE_CONFIG_UNAUTH",
                "detail": (
                    f"GET https://{host}:{port}{cfg_path} returned {status} "
                    f"without authentication; running configuration of managed "
                    f"device {device_id!r} accessible; running configs contain "
                    f"interface addressing, routing tables, ACLs, VPN pre-shared "
                    f"keys, SNMP community strings, and local user credentials "
                    f"in type-7 reversible encryption"
                ),
                "host": host,
                "port": port,
            })

    # --- Assurance client health data ---
    # Requires timestamp in milliseconds; use 0 as probe trigger
    status, body = _get("/dna/intent/api/v1/client-health?timestamp=0")
    if status == 200 and body and (
        "scoreDetail" in body or "healthScore" in body or "clientCount" in body
        or "response" in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "CATALYST_CLIENT_HEALTH_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/dna/intent/api/v1/client-health "
                f"returned {status} without authentication; Assurance client "
                f"health endpoint accessible; exposes connected endpoint counts, "
                f"MAC addresses, IP assignments, SSID associations, and health "
                f"scores; provides network topology and endpoint inventory without "
                f"credentials"
            ),
            "host": host,
            "port": port,
        })

    # --- ISE integration settings (may leak ISE admin password) ---
    status, body = _get("/dna/intent/api/v1/integration-settings/ise")
    if status == 200 and body and (
        "ise" in body.lower() or "pxGrid" in body
        or "primaryIpAddress" in body or "response" in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "CATALYST_ISE_INTEGRATION",
            "detail": (
                f"GET https://{host}:{port}/dna/intent/api/v1/integration-settings"
                f"/ise returned {status}; ISE integration configuration accessible; "
                f"exposes ISE node addresses, pxGrid configuration, and "
                f"synchronization settings used for RADIUS/TACACS+ policy "
                f"enforcement across the network"
            ),
            "host": host,
            "port": port,
        })
        # ISE password leak check
        _ise_pwd_markers = ("password", "sharedSecret", "pxgridPassword", "authKey")
        if any(m in body for m in _ise_pwd_markers):
            findings.append({
                "severity": "CRITICAL",
                "title": "CATALYST_ISE_PASSWORD_LEAKED",
                "detail": (
                    f"GET https://{host}:{port}/dna/intent/api/v1/integration-settings"
                    f"/ise response contains ISE credential markers "
                    f"({[m for m in _ise_pwd_markers if m in body]}); ISE admin "
                    f"password or pxGrid shared secret exposed; provides full ISE "
                    f"administrative access and the ability to modify RADIUS/TACACS+ "
                    f"policy, add rogue network access devices, and bypass 802.1X "
                    f"enforcement across the entire network"
                ),
                "host": host,
                "port": port,
            })

    # --- Backup status: reveals backup destination and credentials ---
    status, body = _get("/dna/system/api/v1/backup")
    if status == 200 and body and (
        "backup" in body.lower() or "response" in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "CATALYST_BACKUP_STATUS",
            "detail": (
                f"GET https://{host}:{port}/dna/system/api/v1/backup returned "
                f"{status}; backup configuration and status accessible; may "
                f"expose NFS/SFTP backup server addresses, paths, and "
                f"authentication credentials used to store Catalyst Center "
                f"configuration backups; backup files contain the full platform "
                f"configuration including encrypted credential stores"
            ),
            "host": host,
            "port": port,
        })

    # --- Maglev internal credential API (cluster-internal, sometimes exposed) ---
    # /api/v1/credential is part of the Maglev service mesh internal API.
    # On misconfigured instances or when the management port is accessible
    # externally, this endpoint bypasses the northbound auth layer.
    status, body = _get("/api/v1/credential")
    if status == 200 and body and (
        "credential" in body.lower() or "username" in body.lower()
        or "password" in body.lower() or "response" in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "MAGLEV_CREDS_EXPOSED",
            "detail": (
                f"GET https://{host}:{port}/api/v1/credential returned {status}; "
                f"Maglev internal cluster credential API accessible from external "
                f"network; this endpoint bypasses the northbound DNA Center auth "
                f"layer and exposes the Maglev bootstrap credentials used for "
                f"inter-service authentication within the cluster; provides "
                f"access to all cluster management functions including node "
                f"management, certificate rotation, and service configuration"
            ),
            "host": host,
            "port": port,
        })

    # --- Third-party integration tokens ---
    status, body = _get("/api/v1/integration-settings")
    if status == 200 and body and (
        "integration" in body.lower() or "token" in body.lower()
        or "apiKey" in body or "response" in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "CATALYST_INTEGRATION_TOKENS",
            "detail": (
                f"GET https://{host}:{port}/api/v1/integration-settings returned "
                f"{status}; third-party integration configuration accessible; "
                f"may expose API tokens and webhook secrets for ServiceNow, "
                f"BMC Remedy, Infoblox, and other integrated platforms configured "
                f"in this Catalyst Center instance"
            ),
            "host": host,
            "port": port,
        })

    return findings


# ─── Cisco ACI Multi-Site Orchestrator (MSO / Nexus Dashboard Orchestrator) ──

def probe_aci_multisite_orchestrator(host: str, port: int = 443,
                                     timeout: float = 10.0) -> list:
    """
    Detect exposed Cisco ACI Multi-Site Orchestrator (MSO) or Nexus Dashboard
    Orchestrator (NDO).  NDO is the evolution of MSO introduced in ACI 4.x and
    is responsible for stretching ACI policy (tenant/VRF/BD/EPG/contract) across
    multiple ACI fabrics and sites.  Unauth access to the NDO REST API exposes
    the complete multi-site policy model and often includes backup archives that
    contain the full cross-site configuration in plaintext.

    Returns list of finding dicts: {severity, title, detail, host, port}.
    """
    findings = []
    base = f"https://{host}:{port}"
    ctx = _ssl_ctx()

    def _get(path: str, headers: dict = None) -> tuple:
        """Return (status_code, body_text) or (None, None) on failure."""
        req = urllib.request.Request(f"{base}{path}")
        req.add_header("Accept", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                return r.status, raw
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode("utf-8", errors="replace")
            except Exception:
                raw = ""
            return e.code, raw
        except Exception:
            return None, None

    def _post_json(path: str, payload: dict) -> tuple:
        """POST JSON payload; return (status_code, body_text)."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(f"{base}{path}", data=data, method="POST")
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                return r.status, raw
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode("utf-8", errors="replace")
            except Exception:
                raw = ""
            return e.code, raw
        except Exception:
            return None, None

    # --- Portal fingerprint: GET / for MSO/NDO UI marker ---
    # The NDO web UI serves a React SPA; the root HTML typically embeds a
    # title or script reference revealing the platform identity.
    status, body = _get("/", headers={"Accept": "text/html,application/xhtml+xml"})
    if status == 200 and body and any(
        marker in body for marker in (
            "Multi-Site Orchestrator",
            "Nexus Dashboard Orchestrator",
            "mso",
            "ndo",
            "nexusdashboard",
        )
    ):
        findings.append({
            "severity": "MEDIUM",
            "title": "MSO_PORTAL_DETECTED",
            "detail": (
                f"GET https://{host}:{port}/ returned {status} with MSO/NDO "
                f"portal markers in response body; ACI Multi-Site Orchestrator "
                f"or Nexus Dashboard Orchestrator web interface is accessible; "
                f"NDO manages cross-site ACI policy replication, site onboarding, "
                f"schema deployment, and inter-site contract stretching"
            ),
            "host": host,
            "port": port,
        })

    # --- NDO auth endpoint probe: GET /api/v1/auth ---
    # Simply reaching this endpoint unauthenticated reveals that the NDO REST
    # API is accessible from the network.  A 200, 401, or 405 all confirm
    # the API is present; a 404 indicates no NDO service on this host.
    status, body = _get("/api/v1/auth")
    if status in (200, 401, 405) and body is not None:
        findings.append({
            "severity": "HIGH",
            "title": "NDO_AUTH_ENDPOINT_EXPOSED",
            "detail": (
                f"GET https://{host}:{port}/api/v1/auth returned {status}; "
                f"Nexus Dashboard Orchestrator REST API auth endpoint is "
                f"network-reachable; NDO REST API controls multi-site ACI "
                f"policy, site pairing, and schema deployment across all "
                f"connected ACI fabrics; an authenticated session grants "
                f"read/write access to the entire multi-site policy model"
            ),
            "host": host,
            "port": port,
        })

    # --- Default credential spray: POST /api/v1/auth ---
    # NDO ships with admin/Cisco1234! as the documented DevNet sandbox default.
    # Successful auth returns a JSON token field usable on all subsequent calls.
    ndo_creds = [
        ("admin", "Cisco1234!"),
        ("admin", "admin"),
        ("admin", "cisco"),
        ("admin", "C1sco12345"),
        ("admin", "Admin1234!"),
    ]
    for user, passwd in ndo_creds:
        s, b = _post_json("/api/v1/auth", {"username": user, "password": passwd})
        if s == 200 and b and (
            "token" in b.lower() or "jwtToken" in b or "accessToken" in b
        ):
            findings.append({
                "severity": "CRITICAL",
                "title": "NDO_DEFAULT_CREDS",
                "detail": (
                    f"POST https://{host}:{port}/api/v1/auth with "
                    f"{user}:{passwd} returned {s} with a token; "
                    f"Nexus Dashboard Orchestrator accepted default credentials; "
                    f"authenticated access to NDO REST API enables enumeration "
                    f"and modification of all multi-site ACI policy including "
                    f"tenant objects, VRFs, bridge domains, EPGs, contracts, and "
                    f"inter-site L3Out connectivity across all managed fabrics"
                ),
                "host": host,
                "port": port,
            })
            break

    # --- Unauthenticated site list: GET /api/v1/sites ---
    # NDO stores configuration for every paired ACI fabric (site name, APIC IP,
    # fabric domain, site ID).  Unauthenticated access discloses every ACI site
    # managed by this orchestrator and the APIC management addresses.
    status, body = _get("/api/v1/sites")
    if status == 200 and body and (
        "sites" in body.lower() or "siteId" in body or "apicSiteId" in body
        or "fabricName" in body or '"id"' in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "NDO_SITES_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/v1/sites returned {status} "
                f"without authentication; response contains ACI site inventory "
                f"including site names, APIC controller IP addresses, fabric "
                f"domain names, and site IDs; this reveals the full multi-site "
                f"topology and every APIC management endpoint managed by NDO"
            ),
            "host": host,
            "port": port,
        })

    # --- Unauthenticated schema list: GET /api/v1/schemas ---
    # NDO schemas are the top-level policy container that defines tenant objects,
    # VRFs, bridge domains, EPGs, and contracts across all sites.  Each schema
    # maps directly to ACI policy model objects deployed to one or more fabrics.
    status, body = _get("/api/v1/schemas")
    if status == 200 and body and (
        "schema" in body.lower() or "templates" in body.lower()
        or "tenantId" in body or '"id"' in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "NDO_SCHEMAS_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/v1/schemas returned {status} "
                f"without authentication; NDO schema objects contain the "
                f"complete ACI policy model including tenant/VRF/BD/EPG "
                f"definitions and inter-site contract stretching configuration"
            ),
            "host": host,
            "port": port,
        })
        # If schema body contains policy objects, escalate to policy exposure
        if any(kw in body for kw in (
            "vrfRef", "bdRef", "epgRef", "anpRef", "contractRef", "templates"
        )):
            findings.append({
                "severity": "CRITICAL",
                "title": "NDO_POLICY_MODEL_EXPOSED",
                "detail": (
                    f"GET https://{host}:{port}/api/v1/schemas returned {status} "
                    f"with ACI policy object references (VRF/BD/EPG/contract) "
                    f"in the body; the complete multi-site ACI policy model is "
                    f"readable without authentication; this exposes tenant "
                    f"segmentation design, security zone topology, application "
                    f"profile structure, and inter-tenant contract relationships "
                    f"across all sites managed by this orchestrator"
                ),
                "host": host,
                "port": port,
            })

    # --- Unauthenticated tenant list: GET /api/v1/tenants ---
    # NDO tenant records include tenant name, associated sites, and the APIC
    # tenant DNs; exposing this list reveals the full organizational structure
    # of every ACI tenant deployed across the multi-site environment.
    status, body = _get("/api/v1/tenants")
    if status == 200 and body and (
        "tenant" in body.lower() or "tenantId" in body or '"id"' in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "NDO_TENANTS_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/v1/tenants returned {status} "
                f"without authentication; ACI tenant records expose tenant "
                f"names, site associations, and APIC tenant distinguished names "
                f"across all managed fabrics; tenant enumeration reveals the "
                f"organizational segmentation model of the entire data center"
            ),
            "host": host,
            "port": port,
        })

    # --- Unauthenticated user list: GET /api/v1/users ---
    # NDO user management endpoint lists local NDO users, roles, and domain
    # associations; may expose service account names used for APIC integration.
    status, body = _get("/api/v1/users")
    if status == 200 and body and (
        "user" in body.lower() or "username" in body.lower()
        or "roles" in body.lower() or '"id"' in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "NDO_USERS_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/v1/users returned {status} "
                f"without authentication; NDO local user accounts are "
                f"enumerable; response may include usernames, role assignments, "
                f"and domain bindings for all orchestrator operator accounts"
            ),
            "host": host,
            "port": port,
        })

    # --- Unauthenticated backup list: GET /api/v1/backups ---
    # NDO backup archives contain the full multi-site policy configuration in
    # an exportable format.  Backup file metadata reveals storage paths,
    # schedule configuration, and may expose backup target credentials if
    # remote backup destinations (SCP/SFTP) are configured.
    status, body = _get("/api/v1/backups")
    if status == 200 and body and (
        "backup" in body.lower() or "fileName" in body or "status" in body.lower()
        or '"id"' in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "NDO_BACKUPS_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/v1/backups returned {status} "
                f"without authentication; NDO backup records are enumerable; "
                f"backup archives contain the complete ACI multi-site policy "
                f"configuration and may expose remote backup server credentials "
                f"(SCP/SFTP paths and authentication details) if off-device "
                f"backup destinations are configured; backup files may be "
                f"downloadable via adjacent endpoints"
            ),
            "host": host,
            "port": port,
        })

    # --- Unauthenticated contract list: GET /api/v1/contracts ---
    # NDO stretched contracts govern inter-tenant and inter-site communication
    # policy.  Exposing contract definitions reveals which EPGs are permitted
    # to communicate across site boundaries and the associated filter rules.
    status, body = _get("/api/v1/contracts")
    if status == 200 and body and (
        "contract" in body.lower() or "filter" in body.lower()
        or "scope" in body.lower() or '"id"' in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "NDO_CONTRACTS_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/v1/contracts returned {status} "
                f"without authentication; NDO inter-site contract definitions "
                f"are readable; contract objects specify which EPGs may "
                f"communicate across ACI site boundaries and the associated "
                f"filter (ACL) rules; exposes the full inter-site security "
                f"policy including scope (tenant/vrf/global) and subject filters"
            ),
            "host": host,
            "port": port,
        })

    return findings


# ─── Cisco ACI L4-L7 Service Graph and External Connectivity Exposure ─────────

def probe_aci_l4l7_service_graph_exposure(host: str, port: int = 443,
                                          timeout: float = 10.0) -> list:
    """
    Detect Cisco ACI L4-L7 service graph and external connectivity policy
    exposure via the APIC REST API object model.

    ACI L4-L7 service graphs define how traffic is redirected through firewalls
    and load balancers using policy-based redirect (PBR).  The APIC MIT (Management
    Information Tree) exposes these objects at /api/node/class/<className>.json.
    Unauthenticated reads of these classes disclose device credentials, network
    topology, BGP peering configuration, subnet inventory, and security filter
    definitions that collectively describe the full data center security architecture.

    Returns list of finding dicts: {severity, title, detail, host, port}.
    """
    findings = []
    base = f"https://{host}:{port}"
    ctx = _ssl_ctx()

    def _get(path: str) -> tuple:
        """Return (status_code, body_text) or (None, None) on failure."""
        req = urllib.request.Request(f"{base}{path}")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                return r.status, raw
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode("utf-8", errors="replace")
            except Exception:
                raw = ""
            return e.code, raw
        except Exception:
            return None, None

    # --- L4-L7 virtual device models: /api/node/class/vnsMDev.json ---
    # vnsMDev objects represent device package metadata imported into APIC for
    # managed-mode service graphs.  Readable without auth on misconfigured APICs.
    # Exposes vendor names, device types (firewall/load-balancer), and the
    # function profiles available for service policy mode deployment.
    status, body = _get("/api/node/class/vnsMDev.json")
    if status == 200 and body and (
        "vnsMDev" in body or "devtype" in body.lower()
        or "imdata" in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "ACI_L4L7_DEVICE_MODELS",
            "detail": (
                f"GET https://{host}:{port}/api/node/class/vnsMDev.json "
                f"returned {status} without authentication; ACI L4-L7 virtual "
                f"device model objects are enumerable; vnsMDev records describe "
                f"imported device packages (ASA, Firepower, F5, Citrix, Palo "
                f"Alto) and the function profiles available for service policy "
                f"mode; exposes the full catalog of L4-L7 services device "
                f"types integrated with this ACI fabric"
            ),
            "host": host,
            "port": port,
        })

    # --- L4-L7 concrete device instances: /api/node/class/vnsCDev.json ---
    # vnsCDev (concrete device) objects represent actual firewall and load
    # balancer appliances registered with APIC.  In service policy mode these
    # records include the management IP, credentials context, and device package
    # reference used by APIC to push configuration to the appliance.
    status, body = _get("/api/node/class/vnsCDev.json")
    if status == 200 and body and (
        "vnsCDev" in body or "imdata" in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_L4L7_CONCRETE_DEVICES",
            "detail": (
                f"GET https://{host}:{port}/api/node/class/vnsCDev.json "
                f"returned {status} without authentication; ACI L4-L7 concrete "
                f"device objects are enumerable; vnsCDev records contain the "
                f"management IP addresses and device identifiers for every "
                f"firewall and load balancer appliance registered with APIC "
                f"for service graph insertion; provides a map of all L4-L7 "
                f"services infrastructure in the fabric"
            ),
            "host": host,
            "port": port,
        })
        # Credential exposure indicator: APIC stores device creds for managed mode
        if any(kw in body for kw in (
            "credentials", "username", "password", "devCtxLbl", "creds"
        )):
            findings.append({
                "severity": "CRITICAL",
                "title": "ACI_DEVICE_CREDS_EXPOSED",
                "detail": (
                    f"GET https://{host}:{port}/api/node/class/vnsCDev.json "
                    f"returned {status} with credential-related attributes in "
                    f"response body; ACI service policy mode stores firewall and "
                    f"load balancer management credentials in the APIC MIT for "
                    f"automated configuration push; unauth read of vnsCDev may "
                    f"expose the management credentials APIC uses to authenticate "
                    f"to ASA, Firepower, F5 BIG-IP, or Citrix NetScaler appliances"
                ),
                "host": host,
                "port": port,
            })

    # --- Abstract service graphs: /api/node/class/vnsAbsGraph.json ---
    # vnsAbsGraph (abstract graph) objects define service graph templates:
    # the ordered sequence of L4-L7 function nodes (firewall -> load balancer)
    # that traffic must traverse between consumer and provider EPGs.
    status, body = _get("/api/node/class/vnsAbsGraph.json")
    if status == 200 and body and (
        "vnsAbsGraph" in body or "imdata" in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "ACI_SERVICE_GRAPHS_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/node/class/vnsAbsGraph.json "
                f"returned {status} without authentication; ACI abstract service "
                f"graph templates are enumerable; vnsAbsGraph records define the "
                f"ordered chain of L4-L7 service functions (PBR redirect, "
                f"firewall insertion, load balancing) applied to traffic flowing "
                f"between EPGs; exposes the full service insertion topology and "
                f"which contracts are associated with which service chains"
            ),
            "host": host,
            "port": port,
        })

    # --- Logical device clusters (VIPs): /api/node/class/vnsLDevVip.json ---
    # vnsLDevVip (logical device with VIP) objects represent load balancer or
    # firewall clusters attached to the fabric.  Each record includes the cluster
    # management mode, associated device package, and interface cluster topology.
    status, body = _get("/api/node/class/vnsLDevVip.json")
    if status == 200 and body and (
        "vnsLDevVip" in body or "imdata" in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_LB_DEVICE_CLUSTERS",
            "detail": (
                f"GET https://{host}:{port}/api/node/class/vnsLDevVip.json "
                f"returned {status} without authentication; ACI logical device "
                f"cluster (LDevVip) objects are enumerable; records identify "
                f"every load balancer and firewall cluster registered for "
                f"service graph insertion including management mode (network "
                f"policy / service policy / service manager), associated device "
                f"package, and cluster interface topology; enables targeted "
                f"attacks against known load balancer management endpoints"
            ),
            "host": host,
            "port": port,
        })

    # --- L3 external out policies: /api/node/class/l3extOut.json ---
    # l3extOut objects define Layer 3 connectivity from ACI tenants to external
    # routing domains.  Each L3Out contains BGP/OSPF/EIGRP peering configuration,
    # border leaf node assignments, and route policy references.  Unauthenticated
    # reads disclose BGP neighbor IPs, AS numbers, and route filter policy names.
    status, body = _get("/api/node/class/l3extOut.json")
    if status == 200 and body and (
        "l3extOut" in body or "imdata" in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_L3OUT_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/node/class/l3extOut.json "
                f"returned {status} without authentication; ACI L3Out external "
                f"connectivity objects are enumerable; l3extOut records expose "
                f"BGP/OSPF/EIGRP routing protocol configuration, border leaf "
                f"switch assignments, external EPG subnet classifications, and "
                f"route profile policy bindings; BGP neighbor IP addresses and "
                f"AS numbers are embedded in child lnodeP/lifP/bfdIfPol objects "
                f"reachable via additional class queries; reveals the complete "
                f"external routing topology for every tenant VRF in the fabric"
            ),
            "host": host,
            "port": port,
        })

    # --- L2 external out policies: /api/node/class/l2extOut.json ---
    # l2extOut objects define Layer 2 bridged connectivity from ACI bridge
    # domains to external switched networks (WAN hand-offs, legacy networks).
    status, body = _get("/api/node/class/l2extOut.json")
    if status == 200 and body and (
        "l2extOut" in body or "imdata" in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "ACI_L2OUT_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/node/class/l2extOut.json "
                f"returned {status} without authentication; ACI L2Out external "
                f"connectivity objects are enumerable; l2extOut records define "
                f"Layer 2 bridged hand-offs to external networks including VLAN "
                f"encapsulation, node profiles, and external EPG subnet scopes; "
                f"exposes which bridge domains have unrouted external extensions "
                f"and the physical interfaces used for the hand-off"
            ),
            "host": host,
            "port": port,
        })

    # --- All fabric subnets: /api/node/class/fvSubnet.json ---
    # fvSubnet objects define IP subnets within bridge domains and external EPGs.
    # A full fvSubnet enumeration produces a complete IP address plan for the
    # entire ACI fabric: every tenant, every VRF, every BD subnet.
    status, body = _get("/api/node/class/fvSubnet.json")
    if status == 200 and body and (
        "fvSubnet" in body or "imdata" in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_ALL_SUBNETS_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/node/class/fvSubnet.json "
                f"returned {status} without authentication; all ACI fabric "
                f"subnet objects are enumerable without authentication; fvSubnet "
                f"records contain every IP prefix, default gateway, and subnet "
                f"scope (private/advertised/shared) configured across all "
                f"tenants and bridge domains in the fabric; this is equivalent "
                f"to reading the complete IP address management (IPAM) database "
                f"for the entire data center; exposes network segmentation design "
                f"and internal address ranges for all hosted applications"
            ),
            "host": host,
            "port": port,
        })

    # --- Security filter objects: /api/node/class/vzFilter.json ---
    # vzFilter (Vz filter) objects are the ACI equivalent of ACL permit/deny
    # entries.  Each filter specifies EtherType, protocol, source/destination
    # port ranges, DSCP, and fragment conditions applied to traffic matching
    # an associated contract subject.
    status, body = _get("/api/node/class/vzFilter.json")
    if status == 200 and body and (
        "vzFilter" in body or "imdata" in body
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_SECURITY_FILTERS_UNAUTH",
            "detail": (
                f"GET https://{host}:{port}/api/node/class/vzFilter.json "
                f"returned {status} without authentication; ACI security filter "
                f"objects (vzFilter) are enumerable; filter entries define the "
                f"EtherType, IP protocol, and L4 port range conditions for every "
                f"contract ACL in the fabric; reading vzFilter exposes the "
                f"complete whitelist security policy for all inter-EPG and "
                f"inter-tenant communication; an attacker learns which ports are "
                f"open between every application tier without sending a single "
                f"packet"
            ),
            "host": host,
            "port": port,
        })

    return findings


# ─── Cisco DevNet Sandbox / Developer API Infrastructure ─────────────────────

def probe_cisco_devnet_sandbox_exposure(host: str, port: int = 443,
                                        timeout: float = 10.0) -> list:
    """
    Detect exposed Cisco DevNet Always-On sandboxes and developer API
    infrastructure.  Covers DNA Center intent API, IOS XE RESTCONF, and
    NSO DevNet RESTCONF surfaces.

    Book source: Cisco Certified DevNet Associate (DEVASC 200-901) Official
    Cert Guide, Chapter 8 "Cisco Enterprise Networking Management Platforms
    and APIs" — DNA Center REST API auth model, intent API endpoint catalogue,
    and DevNet sandbox topology; Chapter 11 RESTCONF/NETCONF programmability.

    Returns List[dict]: {severity, title, detail, host, port}.
    """
    findings = []
    ctx = _ssl_ctx()
    dnac_base = f"https://{host}:{port}"

    def _get(path: str, extra_headers: dict = None) -> tuple:
        """Return (status_code, body_str).  (None, None) on connection failure."""
        url = f"{dnac_base}{path}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "DevNet-SDK/1.0")
        for k, v in (extra_headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                raw = r.read()
                return r.status, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    # --- DNA Center intent API: device inventory ---
    # DevNet Associate ch08: DNA Center uses Basic-auth token exchange; the
    # intent API sits behind /dna/intent/api/v1/ and requires X-Auth-Token.
    # An open 200 here means the token gate is absent on this deployment.
    status, body = _get("/dna/intent/api/v1/network-device")
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "DNAC_DEVNET_API_OPEN",
            "detail": (
                f"GET {dnac_base}/dna/intent/api/v1/network-device with "
                f"User-Agent: DevNet-SDK/1.0 returned {status}; DNA Center "
                f"device inventory accessible without authentication; "
                f"network-device records expose managed device hostnames, "
                f"platform types, software versions, management IPs, and "
                f"collection status for every device in the fabric"
            ),
            "host": host,
            "port": port,
        })

    # --- Physical topology: full L2/L3 fabric map ---
    status, body = _get("/dna/intent/api/v1/topology/physical-topology")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "DNAC_TOPOLOGY_UNAUTH",
            "detail": (
                f"GET {dnac_base}/dna/intent/api/v1/topology/physical-topology "
                f"returned {status} without authentication; the physical "
                f"topology endpoint returns a complete graph of managed network "
                f"devices including node roles (access/distribution/core), "
                f"link details, interface mappings, and VLAN assignments across "
                f"the entire managed fabric"
            ),
            "host": host,
            "port": port,
        })

    # --- Event API subscriptions: reveals external SIEM/ticketing URLs ---
    status, body = _get("/dna/intent/api/v1/event/api-subscription")
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "DNAC_WEBHOOK_SUBS_UNAUTH",
            "detail": (
                f"GET {dnac_base}/dna/intent/api/v1/event/api-subscription "
                f"returned {status} without authentication; webhook/event "
                f"subscription objects are readable; subscriptions reveal "
                f"external SIEM and ticketing endpoints, filter expressions, "
                f"and the full set of event categories the controller forwards "
                f"— exposing internal monitoring infrastructure URLs"
            ),
            "host": host,
            "port": port,
        })

    # --- Discovery device count ---
    status, body = _get("/dna/intent/api/v1/discovery/1/count")
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "DNAC_DISCOVERY_COUNT",
            "detail": (
                f"GET {dnac_base}/dna/intent/api/v1/discovery/1/count "
                f"returned {status} without authentication; device discovery "
                f"run count is readable; confirms an active DNA Center "
                f"discovery task and leaks the number of devices in scope"
            ),
            "host": host,
            "port": port,
        })

    # --- IOS XE RESTCONF root ---
    # RFC 8040; ch11: IOS XE exposes RESTCONF on the management HTTPS port.
    # The root resource returns YANG capability URIs.  Basic auth required
    # by default; an open 200 with YANG content means misconfigured.
    yang_headers = {"Accept": "application/yang-data+json"}

    status, body = _get("/restconf/", extra_headers=yang_headers)
    if status == 200 and body and (
        "yang" in body.lower()
        or "restconf" in body.lower()
        or "ietf" in body.lower()
    ):
        findings.append({
            "severity": "HIGH",
            "title": "IOS_XE_RESTCONF_OPEN",
            "detail": (
                f"GET {dnac_base}/restconf/ with Accept: application/yang-data+json "
                f"returned {status} with YANG/RESTCONF operational data; "
                f"IOS XE RESTCONF API is accessible without authentication; "
                f"the root resource returns YANG capability URIs and available "
                f"datastore paths; further reads enumerate full device config"
            ),
            "host": host,
            "port": port,
        })

    # --- IOS XE RESTCONF: full IPv4 routing table ---
    status, body = _get(
        "/restconf/data/Cisco-IOS-XE-native:native/ip/route",
        extra_headers=yang_headers,
    )
    if status == 200 and body and len(body) > 20:
        findings.append({
            "severity": "CRITICAL",
            "title": "IOS_XE_ROUTING_TABLE_UNAUTH",
            "detail": (
                f"GET {dnac_base}/restconf/data/Cisco-IOS-XE-native:native/ip/route "
                f"returned {status} without authentication; the full IPv4 routing "
                f"table is readable via RESTCONF; route entries include destination "
                f"prefixes, next-hop IPs, administrative distances, and interface "
                f"bindings — exposing the complete internal network topology"
            ),
            "host": host,
            "port": port,
        })

    # --- IOS XE RESTCONF: interface configuration ---
    status, body = _get(
        "/restconf/data/Cisco-IOS-XE-native:native/interface",
        extra_headers=yang_headers,
    )
    if status == 200 and body and len(body) > 20:
        findings.append({
            "severity": "CRITICAL",
            "title": "IOS_XE_INTERFACES_UNAUTH",
            "detail": (
                f"GET {dnac_base}/restconf/data/Cisco-IOS-XE-native:native/interface "
                f"returned {status} without authentication; all interface "
                f"configurations are readable including IP addresses, "
                f"encapsulation, access/trunk VLAN assignments, and shutdown "
                f"state — equivalent to 'show running-config interface' across "
                f"all interfaces without credentials"
            ),
            "host": host,
            "port": port,
        })

    # --- NSO DevNet sandbox: HTTP:8080 and HTTPS on configured port ---
    # Cisco NSO exposes RESTCONF on port 8080 (HTTP) in the DevNet sandbox.
    # tailf-ncs:devices lists every device NSO manages across all vendors.
    for nso_port in sorted({8080, port}):
        nso_scheme = "https" if nso_port == 443 else "http"
        nso_base = f"{nso_scheme}://{host}:{nso_port}"
        nso_ctx = ctx if nso_scheme == "https" else None

        nso_root_req = urllib.request.Request(f"{nso_base}/restconf/")
        nso_root_req.add_header("Accept", "application/yang-data+json")
        nso_open_kwargs: dict = {"timeout": timeout}
        if nso_ctx is not None:
            nso_open_kwargs["context"] = nso_ctx
        try:
            with urllib.request.urlopen(nso_root_req,
                                        **nso_open_kwargs) as r:
                nso_status = r.status
                nso_body = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            nso_status = e.code
            try:
                nso_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                nso_body = ""
        except Exception:
            nso_status = None
            nso_body = None

        if nso_status == 200 and nso_body:
            findings.append({
                "severity": "HIGH",
                "title": "NSO_DEVNET_SANDBOX_OPEN",
                "detail": (
                    f"GET {nso_base}/restconf/ returned {nso_status} without "
                    f"authentication; a Cisco NSO (Network Services Orchestrator) "
                    f"RESTCONF interface is open; NSO manages multi-vendor device "
                    f"configurations; unauthenticated access to the RESTCONF root "
                    f"exposes YANG capability URIs and available NCS datastore paths"
                ),
                "host": host,
                "port": nso_port,
            })

            # NSO device tree
            dev_req = urllib.request.Request(
                f"{nso_base}/restconf/data/tailf-ncs:devices?depth=1"
            )
            dev_req.add_header("Accept", "application/yang-data+json")
            try:
                with urllib.request.urlopen(dev_req,
                                            **nso_open_kwargs) as r2:
                    dev_status = r2.status
                    dev_body = r2.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e2:
                dev_status = e2.code
                dev_body = ""
            except Exception:
                dev_status = None
                dev_body = ""

            if dev_status == 200 and dev_body and len(dev_body) > 10:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NSO_DEVICE_TREE_UNAUTH",
                    "detail": (
                        f"GET {nso_base}/restconf/data/tailf-ncs:devices?depth=1 "
                        f"returned {dev_status} without authentication; the NSO "
                        f"device tree is enumerable; tailf-ncs:devices lists all "
                        f"managed devices including name, address, port, device-type, "
                        f"NED (network element driver) version, and connection state "
                        f"— a complete managed-device inventory across all vendors "
                        f"in the NSO domain"
                    ),
                    "host": host,
                    "port": nso_port,
                })

    return findings


# ─── Cisco Webex / Collaboration Token & API Exposure ────────────────────────

def probe_cisco_webex_api_token_exposure(host: str, port: int = 443,
                                          timeout: float = 10.0) -> list:
    """
    Detect exposed Cisco Webex/Collaboration API tokens and integration
    endpoints.  Scans target web app content for embedded Webex access
    tokens (Y2lzY29zcGFyazovL prefix — base64("ciscospark://")), probes
    Cisco Finesse (Contact Center) REST/XMPP API, and Cisco Unity Connection
    voicemail REST API (vmrest).

    Book source: Cisco Certified DevNet Associate (DEVASC 200-901) Official
    Cert Guide, Chapter 10 "Cisco Collaboration Platforms and APIs" —
    Webex Teams personal access token model, bearer token auth header,
    Finesse agent/supervisor desktop Web 2.0 XMPP-over-BOSH API, and
    Unity Connection REST (vmrest) endpoint structure.

    Returns List[dict]: {severity, title, detail, host, port}.
    """
    findings = []
    ctx = _ssl_ctx()
    base = f"https://{host}:{port}"

    # Webex access token prefix: base64("ciscospark://") yields "Y2lzY29zcGFyazovL"
    # Book ch10: personal access tokens are bearer tokens in the Authorization
    # header; tokens embedded in client-side JS or config files are harvestable
    # by any visitor.
    WEBEX_TOKEN_RE = re.compile(
        r"Y2lzY29zcGFyazovL[A-Za-z0-9+/=_\-]{20,}",
        re.ASCII,
    )
    # Key-value patterns for token assignments in JS/config files
    WEBEX_ENVVAR_RE = re.compile(
        r"(?:CISCO_WEBEX_ACCESS_TOKEN|webexAccessToken|WEBEX_ACCESS_TOKEN"
        r"|webex[_]?token|WEBEX_TOKEN)\s*[=:]\s*[\"']?([A-Za-z0-9+/=_\-]{30,})",
        re.IGNORECASE,
    )

    def _fetch(path: str, extra_headers: dict = None) -> tuple:
        """Return (status_code, body_str).  (None, None) on connection failure."""
        url = f"{base}{path}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "text/html,application/json,*/*")
        req.add_header("User-Agent",
                       "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
        for k, v in (extra_headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                raw = r.read(524288)  # cap at 512 KB
                return r.status, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(131072).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    # --- Main page: scan for embedded Webex token ---
    # Webex personal access tokens live 12 h; long-lived bot/integration
    # tokens are permanent until revoked.  Either type grants full API access.
    status, body = _fetch("/")
    if status == 200 and body:
        if WEBEX_TOKEN_RE.search(body):
            findings.append({
                "severity": "CRITICAL",
                "title": "WEBEX_TOKEN_IN_PAGE",
                "detail": (
                    f"GET {base}/ returned {status} and the response body "
                    f"contains a Cisco Webex/Spark access token pattern "
                    f"(Y2lzY29zcGFyazovL prefix); Webex bearer tokens embedded "
                    f"in page source allow full API access to the associated "
                    f"Webex Teams organization including messaging, user "
                    f"enumeration, room listing, and administrative actions"
                ),
                "host": host,
                "port": port,
            })

    # --- Config/env files: scan for embedded Webex tokens ---
    # Book ch10: integrations store OAuth tokens; misconfigurations place
    # them in static config.json / env.js served to all browsers.
    for config_path in (
        "/config.json",
        "/app-config.json",
        "/env.js",
        "/static/js/env.js",
        "/assets/config.js",
    ):
        status, body = _fetch(config_path)
        if status == 200 and body:
            token_m = WEBEX_TOKEN_RE.search(body)
            envvar_m = WEBEX_ENVVAR_RE.search(body)
            if token_m or envvar_m:
                matched = (token_m.group(0) if token_m
                           else envvar_m.group(0))[:80]
                findings.append({
                    "severity": "CRITICAL",
                    "title": "WEBEX_TOKEN_IN_CONFIG",
                    "detail": (
                        f"GET {base}{config_path} returned {status} and "
                        f"contains a Cisco Webex API token or token-keyed "
                        f"variable (pattern: {matched!r}); tokens in "
                        f"config files served statically are trivially "
                        f"harvestable by any visitor and grant full Webex "
                        f"API access for the lifetime of the token"
                    ),
                    "host": host,
                    "port": port,
                })

    # --- JS bundle scan for Webex token env-var assignments ---
    # Separate set of paths not already checked above; avoids duplicate findings.
    already_checked = {"/env.js", "/static/js/env.js",
                       "/assets/config.js", "/config.json", "/app-config.json"}
    for js_path in ("/config.js", "/app.js", "/static/js/main.js",
                    "/js/config.js"):
        if js_path in already_checked:
            continue
        status, body = _fetch(js_path)
        if status == 200 and body:
            envvar_m = WEBEX_ENVVAR_RE.search(body)
            token_m = WEBEX_TOKEN_RE.search(body)
            if envvar_m and not token_m:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "WEBEX_TOKEN_ENV_VAR",
                    "detail": (
                        f"GET {base}{js_path} returned {status} and contains "
                        f"a Webex token environment variable assignment "
                        f"(CISCO_WEBEX_ACCESS_TOKEN / webexAccessToken pattern); "
                        f"token values embedded in client-side JS are fully "
                        f"readable by any browser and grant authenticated "
                        f"Webex API access to the backing organization"
                    ),
                    "host": host,
                    "port": port,
                })

    # --- Cisco Finesse (Contact Center) API ---
    # Book ch10: Finesse is 100% browser-based, built on open Web 2.0 APIs;
    # the REST API lives at /finesse/api/ and implements XMPP over BOSH for
    # real-time agent state events.  Default HTTPS port 443 on the CUCM node.

    # Finesse XMPP-over-BOSH desktop API proxy
    status, body = _fetch("/desktop/api-proxy")
    if status in (200, 301, 302) and body is not None:
        findings.append({
            "severity": "HIGH",
            "title": "FINESSE_API_PROXY",
            "detail": (
                f"GET {base}/desktop/api-proxy returned {status}; the Cisco "
                f"Finesse desktop XMPP-over-BOSH API proxy endpoint is "
                f"reachable; Finesse implements XMPP over BOSH for real-time "
                f"agent state events; an accessible proxy exposes active agent "
                f"session enumeration and can inject XMPP messages into "
                f"contact center notification streams"
            ),
            "host": host,
            "port": port,
        })

    # Finesse SystemInfo: version, cluster mode, CTI server address
    status, body = _fetch("/finesse/api/SystemInfo")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "FINESSE_SYSINFO_UNAUTH",
            "detail": (
                f"GET {base}/finesse/api/SystemInfo returned {status} without "
                f"authentication; Cisco Finesse system information is exposed; "
                f"SystemInfo returns the Finesse server version, cluster mode, "
                f"peripheral gateway connectivity, and CTI server address — "
                f"sufficient to fingerprint the contact center deployment and "
                f"scope further exploitation of the Unified Communications stack"
            ),
            "host": host,
            "port": port,
        })

    # Finesse User list: agent roster with real-time state
    status, body = _fetch("/finesse/api/User")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "FINESSE_USERS_UNAUTH",
            "detail": (
                f"GET {base}/finesse/api/User returned {status} without "
                f"authentication; the Finesse agent list is readable; "
                f"User records expose agent login IDs, extension numbers, "
                f"current state (Ready/Not Ready/Talking), team assignments, "
                f"and peripheral IDs — a complete real-time contact center "
                f"agent roster readable without credentials"
            ),
            "host": host,
            "port": port,
        })

    # Finesse default credentials probe
    finesse_default_creds = [
        ("admin", "Cisco123!"),
        ("admin", "cisco"),
        ("administrator", "Cisco123!"),
        ("finesse", "Cisco123!"),
    ]
    for user, passwd in finesse_default_creds:
        cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        cred_req = urllib.request.Request(f"{base}/finesse/api/SystemInfo")
        cred_req.add_header("Authorization", f"Basic {cred}")
        cred_req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(cred_req, context=ctx,
                                        timeout=timeout) as r:
                if r.status == 200:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "FINESSE_DEFAULT_CREDS",
                        "detail": (
                            f"GET {base}/finesse/api/SystemInfo with "
                            f"Basic {user}:{passwd} returned {r.status}; Cisco "
                            f"Finesse accepted default credentials; authenticated "
                            f"access allows agent state manipulation, call control "
                            f"actions, and real-time monitoring of all contact "
                            f"center activity"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    # --- Cisco Unity Connection (vmrest) voicemail REST API ---
    # Book ch10 / Unified Communications: Unity Connection exposes a REST API
    # at /vmrest/ for voicemail management.  Default auth is Basic; an open
    # 200 means the credential gate is absent or bypassed.

    # Voicemail user directory
    status, body = _fetch("/vmrest/users")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "UNITY_USERS_UNAUTH",
            "detail": (
                f"GET {base}/vmrest/users returned {status} without "
                f"authentication; Cisco Unity Connection voicemail user "
                f"directory is enumerable; vmrest user records expose mailbox "
                f"aliases, display names, extension numbers, department, and "
                f"mailbox identifiers — a full directory of voicemail "
                f"subscribers readable without credentials"
            ),
            "host": host,
            "port": port,
        })

    # Unity Connection version disclosure
    status, body = _fetch("/vmrest/version")
    if status == 200 and body:
        findings.append({
            "severity": "MEDIUM",
            "title": "UNITY_VERSION_UNAUTH",
            "detail": (
                f"GET {base}/vmrest/version returned {status} without "
                f"authentication; Cisco Unity Connection version information "
                f"is exposed; version data enables CVE scoping against the "
                f"specific Unity Connection release and narrows the exploit "
                f"surface for authenticated attacks targeting the vmrest API"
            ),
            "host": host,
            "port": port,
        })

    return findings

    return findings


def probe_cisco_mds_san_exposure(host: str, port: int = 443,
                                  timeout: float = 10.0) -> list:
    """Detect Cisco MDS SAN switch NX-API and FCNS database exposure.

    Cisco MDS 9000 series Fibre Channel switches run NX-OS and expose an
    NX-API (JSON-RPC over HTTP/HTTPS) for programmatic CLI access. When
    NX-API is enabled without authentication controls, the FLOGI database,
    FCNS Name Server, active zoneset, VSAN membership list, and FC interface
    inventory are all accessible without credentials.

    From Cisco Data Center Fundamentals (9780137638208):
    - Chapter 11: The FLOGI database (show flogi database) records all
      N_Ports that have logged into the fabric including their WWPNs and
      FCIDs. WWPNs are 64-bit physical addresses (xx:xx:xx:xx:xx:xx:xx:xx)
      hardcoded to FC HBAs — the full initiator and target inventory of the
      SAN fabric.
    - Chapter 11: The FCNS (Fibre Channel Name Server) database holds WWPN,
      vendor OUI, and FC4 service type for every registered N_Port — identifies
      NetApp/EMC/IBM storage targets and their host bus adapters.
    - Chapter 12: VSANs partition the physical SAN fabric into isolated
      virtual SANs; show vsan exposes the VSAN membership list.
    - Chapter 12: FC zoning (show zoneset active) defines which initiators
      are permitted to communicate with which storage targets; the active
      zoneset is the enforced access control policy for the entire fabric.

    Args:
        host: Target hostname or IP address.
        port: HTTPS port for NX-API (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = _ssl_ctx()

    # WWPN pattern: 8 colon-separated hex octets (xx:xx:xx:xx:xx:xx:xx:xx)
    WWPN_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){7}[0-9a-fA-F]{2}\b")

    def _nxapi_post(cmd: str, req_port: int = port,
                    use_ssl: bool = True) -> tuple:
        """POST NX-API JSON-RPC command; return (status_code, body_str)."""
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "cli",
            "params": {"cmd": cmd, "version": 1},
            "id": 1,
        }).encode()
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{req_port}/ins"
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json-rpc",
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        try:
            with urllib.request.urlopen(
                req, context=ctx if use_ssl else None, timeout=timeout
            ) as r:
                return r.status, r.read(524288).decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(131072).decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    def _get_mds(path: str, req_port: int = port,
                 use_ssl: bool = True) -> tuple:
        """GET request; return (status_code, body_str) or (None, None)."""
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{req_port}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json, text/html, */*",
                "User-Agent": "Mozilla/5.0",
            },
        )
        try:
            with urllib.request.urlopen(
                req, context=ctx if use_ssl else None, timeout=timeout
            ) as r:
                return r.status, r.read(524288).decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(131072).decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    # --- NX-API: show flogi database (Chapter 11 — FLOGI process) ---
    # FLOGI database lists all N_Ports that logged into the fabric: VSAN,
    # FC port, FCID, WWPN, WWNN.  Unauthenticated read = full SAN endpoint
    # inventory.
    status, body = _nxapi_post("show flogi database")
    if status is not None and status < 400 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "MDS_FLOGI_DB_UNAUTH",
            "detail": (
                f"POST https://{host}:{port}/ins NX-API 'show flogi database' "
                f"returned {status} without authentication; the Fabric Login "
                f"(FLOGI) database records every N_Port that has logged into the "
                f"SAN fabric including WWPNs, WWNNs, FCIDs, and VSAN assignments; "
                f"this is the complete inventory of storage initiators and targets "
                f"in the Fibre Channel fabric — unauthenticated read exposes the "
                f"full SAN endpoint map to any network-accessible client"
            ),
            "host": host,
            "port": port,
        })
        wwpns = WWPN_RE.findall(body)
        if wwpns:
            findings.append({
                "severity": "CRITICAL",
                "title": "MDS_WWPN_INVENTORY",
                "detail": (
                    f"NX-API 'show flogi database' on {host}:{port} returned "
                    f"{len(wwpns)} WWPN(s) without authentication; sample: "
                    f"{', '.join(wwpns[:4])}; WWPNs are 64-bit physical Fibre "
                    f"Channel port addresses hardcoded to HBAs in servers and "
                    f"storage arrays — a complete WWPN map enables fabric "
                    f"impersonation and zoning bypass in misconfigured fabrics"
                ),
                "host": host,
                "port": port,
            })

    # --- NX-API: show fcns database (Chapter 11 — FCNS Name Server) ---
    # FCNS is the distributed Name Server; each switch holds the full fabric
    # registry of WWPNs, vendor OUIs, and FC4 service types.
    status, body = _nxapi_post("show fcns database")
    if status is not None and status < 400 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "MDS_FCNS_DB_UNAUTH",
            "detail": (
                f"POST https://{host}:{port}/ins NX-API 'show fcns database' "
                f"returned {status} without authentication; the Fibre Channel "
                f"Name Server (FCNS) database contains FCID, type, WWPN, vendor "
                f"OUI, and FC4 service type for every registered N_Port across "
                f"all switches in the fabric; vendor strings identify NetApp, "
                f"EMC, IBM, and other storage arrays and their host bus adapters"
            ),
            "host": host,
            "port": port,
        })
        vendor_hits = re.findall(
            r"\((?:NetApp|EMC|IBM|Brocade|QLogic|Emulex|HPE|Dell)\)", body
        )
        if vendor_hits:
            findings.append({
                "severity": "CRITICAL",
                "title": "MDS_FABRIC_MEMBERS_DISCLOSED",
                "detail": (
                    f"NX-API 'show fcns database' on {host}:{port} disclosed "
                    f"{len(vendor_hits)} storage vendor registration(s): "
                    f"{', '.join(sorted(set(vendor_hits))[:6])}; vendor-identified "
                    f"storage targets and HBAs are directly enumerable including "
                    f"NetApp filers, EMC arrays, and IBM storage; each entry "
                    f"exposes the target's WWPN, FCID, and supported services "
                    f"without requiring credentials"
                ),
                "host": host,
                "port": port,
            })

    # --- NX-API: show zoneset active (Chapter 12 — FC Zoning) ---
    # The active zoneset is the enforced access control policy: maps initiator
    # WWPNs (server HBAs) to target WWPNs (storage ports).
    status, body = _nxapi_post("show zoneset active")
    if status is not None and status < 400 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "MDS_ACTIVE_ZONESET_UNAUTH",
            "detail": (
                f"POST https://{host}:{port}/ins NX-API 'show zoneset active' "
                f"returned {status} without authentication; the active zoneset "
                f"is the enforced Fibre Channel zoning policy for the SAN fabric; "
                f"it maps initiator WWPNs (server HBAs) to target WWPNs (storage "
                f"array ports) and defines which servers are permitted to access "
                f"which storage volumes — unauthenticated read enables targeted "
                f"LUN access reconstruction and zoning policy bypass planning"
            ),
            "host": host,
            "port": port,
        })
        zone_members = WWPN_RE.findall(body)
        if zone_members:
            findings.append({
                "severity": "CRITICAL",
                "title": "MDS_ZONE_MAPPINGS_DISCLOSED",
                "detail": (
                    f"NX-API 'show zoneset active' on {host}:{port} disclosed "
                    f"{len(zone_members)} zone member WWPN(s); sample: "
                    f"{', '.join(zone_members[:4])}; zone members establish the "
                    f"server-to-storage access matrix; each WWPN pair in a zone "
                    f"represents a permitted initiator-to-target path — knowledge "
                    f"of these mappings identifies the exact storage volumes "
                    f"accessible from each host without credentials"
                ),
                "host": host,
                "port": port,
            })

    # --- NX-API: show vsan (Chapter 12 — VSANs) ---
    # VSANs partition the physical SAN into isolated virtual SANs; enumeration
    # reveals the number of virtual fabrics and their operational state.
    status, body = _nxapi_post("show vsan")
    if status is not None and status < 400 and body:
        vsan_ids = re.findall(r"\bvsan\s+(\d+)", body, re.IGNORECASE)
        findings.append({
            "severity": "HIGH",
            "title": "MDS_VSAN_LIST_UNAUTH",
            "detail": (
                f"POST https://{host}:{port}/ins NX-API 'show vsan' returned "
                f"{status} without authentication; {len(vsan_ids)} VSAN ID(s) "
                f"enumerated: {', '.join(vsan_ids[:8])}; VSANs are virtual SAN "
                f"partitions on Cisco MDS switches analogous to VLANs in Ethernet; "
                f"each VSAN is an isolated Fibre Channel fabric with its own "
                f"zoning and Name Server — enumeration maps the logical "
                f"segmentation of the storage infrastructure"
            ),
            "host": host,
            "port": port,
        })

    # --- NX-API: show interface brief (FC interface inventory) ---
    status, body = _nxapi_post("show interface brief")
    if status is not None and status < 400 and body:
        fc_ports = re.findall(r"\bfc\d+/\d+\b", body, re.IGNORECASE)
        findings.append({
            "severity": "HIGH",
            "title": "MDS_FC_INTERFACES_UNAUTH",
            "detail": (
                f"POST https://{host}:{port}/ins NX-API 'show interface brief' "
                f"returned {status} without authentication; {len(fc_ports)} FC "
                f"interface(s) enumerated: {', '.join(fc_ports[:8])}; FC "
                f"interface status discloses operational state (up/down), speed, "
                f"and VSAN assignments — interface map identifies populated fabric "
                f"ports and potential unzoned access points in the SAN switch"
            ),
            "host": host,
            "port": port,
        })

    # --- Port 8080 HTTP: Cisco DCNM REST API (MDS management plane) ---
    dcnm_port = 8080
    status, body = _get_mds("/dcnm/rest/interface", req_port=dcnm_port,
                             use_ssl=False)
    if status is not None and status < 400 and body:
        findings.append({
            "severity": "HIGH",
            "title": "DCNM_HTTP_PORT",
            "detail": (
                f"GET http://{host}:{dcnm_port}/dcnm/rest/interface returned "
                f"{status}; Cisco DCNM REST API is accessible on HTTP port "
                f"{dcnm_port}; DCNM manages MDS SAN switches and Nexus LAN "
                f"switches from a central management plane without TLS protection"
            ),
            "host": host,
            "port": dcnm_port,
        })
        findings.append({
            "severity": "CRITICAL",
            "title": "DCNM_INTERFACES_UNAUTH",
            "detail": (
                f"GET http://{host}:{dcnm_port}/dcnm/rest/interface returned "
                f"{status} without authentication; DCNM interface inventory "
                f"exposed; the endpoint lists all managed switch interfaces "
                f"including FC SAN ports and Ethernet LAN ports with their "
                f"configuration and operational state"
            ),
            "host": host,
            "port": dcnm_port,
        })

    status, body = _get_mds("/dcnm/rest/topology", req_port=dcnm_port,
                             use_ssl=False)
    if status is not None and status < 400 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "DCNM_TOPOLOGY_UNAUTH",
            "detail": (
                f"GET http://{host}:{dcnm_port}/dcnm/rest/topology returned "
                f"{status} without authentication; DCNM network topology map "
                f"disclosed without credentials; topology data includes all "
                f"managed switches, inter-switch links (ISLs), and attached "
                f"end devices — a full data center network diagram including "
                f"the SAN fabric topology readable without credentials"
            ),
            "host": host,
            "port": dcnm_port,
        })

    # --- Port 22 TCP: SSH banner for Cisco MDS or Nexus ---
    try:
        with socket.create_connection((host, 22), timeout=timeout) as sock:
            banner_raw = sock.recv(256)
            banner = banner_raw.decode(errors="replace").strip()
            if any(kw in banner for kw in (
                "Cisco MDS", "Cisco Nexus", "NX-OS", "MDS"
            )):
                findings.append({
                    "severity": "MEDIUM",
                    "title": "MDS_SSH_BANNER",
                    "detail": (
                        f"TCP/22 on {host} returned SSH banner identifying "
                        f"a Cisco MDS/Nexus device: '{banner[:120]}'; SSH "
                        f"banner confirms NX-OS platform and may reveal switch "
                        f"model and NX-OS version — version data enables CVE "
                        f"scoping against the specific NX-OS release"
                    ),
                    "host": host,
                    "port": 22,
                })
    except Exception:
        pass

    return findings


def probe_cisco_dcnm_ndfc_exposure(host: str, port: int = 443,
                                    timeout: float = 10.0) -> list:
    """Detect Cisco DCNM/NDFC (Nexus Dashboard Fabric Controller) API exposure.

    Cisco Data Center Network Manager (DCNM) — rebranded Nexus Dashboard
    Fabric Controller (NDFC) in release 12.x — is the central management
    platform for Cisco data center fabrics including Nexus LAN switches and
    MDS SAN switches. It exposes a REST API for fabric management, switch
    inventory, interface configuration, and topology mapping.

    From Cisco Data Center Fundamentals (9780137638208):
    - Chapter 12: DCNM is the recommended GUI-based management tool for
      Cisco MDS VSANs and Fibre Channel zoning; full fabric configuration
      and monitoring is centralized in DCNM — compromise of DCNM is
      equivalent to compromise of the entire managed SAN and LAN fabric.
    - DCNM REST API base: /dcnm/rest/ (legacy DCNM 11.x and earlier).
    - NDFC base path: /appcenter/cisco/ndfc/api/v1/ (Nexus Dashboard 12+).
    - Default credentials: admin/admin (factory), admin/Admin_1234 (NDFC
      bootstrap default on Nexus Dashboard).

    Args:
        host: Target hostname or IP address.
        port: HTTPS port for DCNM/NDFC web interface (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts: {severity, title, detail, host, port}.
    """
    findings: list = []
    ctx = _ssl_ctx()
    base = f"https://{host}:{port}"

    def _get(path: str) -> tuple:
        """GET request; return (status_code, body_str) or (None, None)."""
        url = f"{base}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json, text/html, */*",
                "User-Agent": "Mozilla/5.0",
            },
        )
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                return r.status, r.read(524288).decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(131072).decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    def _post_json(path: str, payload: dict,
                   extra_headers: dict = None) -> tuple:
        """POST JSON; return (status_code, body_str) or (None, None)."""
        data = json.dumps(payload).encode()
        url = f"{base}{path}"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
        }
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                return r.status, r.read(524288).decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(131072).decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    # --- DCNM logon endpoint detection ---
    # Presence of /dcnm/rest/logon confirms a DCNM instance regardless of
    # whether unauthenticated access is permitted.
    status, body = _get("/dcnm/rest/logon")
    if status is not None:
        findings.append({
            "severity": "HIGH",
            "title": "DCNM_AUTH_ENDPOINT",
            "detail": (
                f"GET {base}/dcnm/rest/logon returned {status}; Cisco DCNM "
                f"REST API authentication endpoint is reachable; DCNM manages "
                f"both LAN (Nexus) and SAN (MDS) fabrics from a single "
                f"management plane — compromise grants control over the entire "
                f"managed data center fabric"
            ),
            "host": host,
            "port": port,
        })

    # --- DCNM default credential check ---
    # Factory default: admin/admin. NDFC bootstrap: admin/Admin_1234.
    # POST /dcnm/rest/logon with expirationTime grants a Dcnm-Token on success.
    for username, password in (
        ("admin", "admin"),
        ("admin", "Admin_1234"),
        ("admin", "cisco"),
        ("admin", "C1sco12345"),
    ):
        cred_b64 = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode()
        status, body = _post_json(
            "/dcnm/rest/logon",
            {"expirationTime": 600000},
            extra_headers={"Authorization": f"Basic {cred_b64}"},
        )
        if status is not None and status < 300 and body and (
            "Dcnm-Token" in body
        ):
            findings.append({
                "severity": "CRITICAL",
                "title": "DCNM_DEFAULT_CREDS",
                "detail": (
                    f"POST {base}/dcnm/rest/logon with '{username}'/'{password}' "
                    f"returned {status} and a valid Dcnm-Token; DCNM default "
                    f"credentials accepted; a valid session token grants full "
                    f"API access to all managed switches including fabric "
                    f"configuration, interface management, policy deployment, "
                    f"and credential retrieval for all DCNM-managed network devices"
                ),
                "host": host,
                "port": port,
            })
            break

    # --- DCNM switch inventory: unauthenticated read ---
    status, body = _get("/dcnm/rest/inventory/switches")
    if status is not None and status < 400 and body and (
        "ipAddress" in body or "switchDbID" in body or "serialNumber" in body
    ):
        switch_count = len(re.findall(r"\"ipAddress\"", body))
        findings.append({
            "severity": "CRITICAL",
            "title": "DCNM_SWITCH_INVENTORY_UNAUTH",
            "detail": (
                f"GET {base}/dcnm/rest/inventory/switches returned {status} "
                f"without authentication; {switch_count} switch record(s) "
                f"found; the DCNM switch inventory exposes IP addresses, serial "
                f"numbers, model numbers, software versions, and management state "
                f"for every switch managed by this DCNM instance — a complete "
                f"inventory of the data center network fabric"
            ),
            "host": host,
            "port": port,
        })

    # --- DCNM interface inventory ---
    status, body = _get("/dcnm/rest/interface")
    if status is not None and status < 400 and body and (
        "ifName" in body or "interfaceName" in body
    ):
        findings.append({
            "severity": "HIGH",
            "title": "DCNM_INTERFACE_INVENTORY_UNAUTH",
            "detail": (
                f"GET {base}/dcnm/rest/interface returned {status} without "
                f"authentication; DCNM interface inventory is accessible; "
                f"the endpoint lists all managed interfaces across all switches "
                f"including FC SAN ports and Ethernet LAN ports with their "
                f"configuration, operational status, and VSAN/VLAN assignments"
            ),
            "host": host,
            "port": port,
        })

    # --- DCNM fabric list (LAN fabric controller) ---
    status, body = _get("/dcnm/rest/lan-fabric/rest/control/fabrics")
    if status is not None and status < 400 and body and (
        "fabricName" in body or "fabricId" in body
    ):
        fabric_count = len(re.findall(r"\"fabricName\"", body))
        findings.append({
            "severity": "CRITICAL",
            "title": "DCNM_FABRICS_UNAUTH",
            "detail": (
                f"GET {base}/dcnm/rest/lan-fabric/rest/control/fabrics "
                f"returned {status} without authentication; {fabric_count} "
                f"fabric record(s) found; the DCNM fabric list exposes all "
                f"managed network fabrics including their names, types "
                f"(LAN/SAN/IPFM), underlay addressing, and routing domain "
                f"configuration — the full data center network topology in a "
                f"single unauthenticated response"
            ),
            "host": host,
            "port": port,
        })

    # --- DCNM config change tracking ---
    status, body = _get("/dcnm/rest/config/track")
    if status is not None and status < 400 and body:
        findings.append({
            "severity": "HIGH",
            "title": "DCNM_CONFIG_HISTORY_UNAUTH",
            "detail": (
                f"GET {base}/dcnm/rest/config/track returned {status} without "
                f"authentication; DCNM configuration change tracking is readable; "
                f"config history includes timestamps, operator identities, and "
                f"before/after diffs of switch configuration changes — reveals "
                f"recent network changes, admin usernames, and configuration "
                f"state transitions across the managed fabric"
            ),
            "host": host,
            "port": port,
        })

    # --- NDFC API (Nexus Dashboard Fabric Controller, release 12+) ---
    # NDFC moved to /appcenter/cisco/ndfc/api/v1/ on Nexus Dashboard.

    # NDFC fabric list
    status, body = _get(
        "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics"
    )
    if status is not None and status < 400 and body and (
        "fabricName" in body or "fabric" in body.lower()
    ):
        fabric_count = len(re.findall(r"\"fabricName\"", body))
        findings.append({
            "severity": "CRITICAL",
            "title": "NDFC_FABRICS_UNAUTH",
            "detail": (
                f"GET {base}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/"
                f"control/fabrics returned {status} without authentication; "
                f"{fabric_count} NDFC fabric record(s) exposed; Nexus Dashboard "
                f"Fabric Controller manages VXLAN EVPN overlays, fabric underlay, "
                f"VRF and network configurations — unauthenticated access to the "
                f"fabric list is equivalent to reading the entire data center "
                f"network design"
            ),
            "host": host,
            "port": port,
        })

    # NDFC fabric links / topology
    status, body = _get(
        "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/links"
    )
    if status is not None and status < 400 and body and (
        "srcSwitchName" in body or "dstSwitchName" in body
        or "linkState" in body
    ):
        link_count = len(re.findall(r"\"srcSwitchName\"", body))
        findings.append({
            "severity": "CRITICAL",
            "title": "NDFC_LINKS_TOPOLOGY_UNAUTH",
            "detail": (
                f"GET {base}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/"
                f"control/links returned {status} without authentication; "
                f"{link_count} fabric link record(s) found; the NDFC links "
                f"endpoint exposes the complete inter-switch link (ISL) topology "
                f"including source switch, destination switch, interface names, "
                f"link type, and operational state — a full physical topology "
                f"map of the data center network fabric"
            ),
            "host": host,
            "port": port,
        })

    # NDFC version disclosure
    status, body = _get("/appcenter/cisco/ndfc/api/v1/fm/about/version")
    if status is not None and status < 400 and body and (
        "version" in body.lower() or "ndfc" in body.lower()
    ):
        findings.append({
            "severity": "MEDIUM",
            "title": "NDFC_VERSION_UNAUTH",
            "detail": (
                f"GET {base}/appcenter/cisco/ndfc/api/v1/fm/about/version "
                f"returned {status} without authentication; NDFC version "
                f"information is disclosed; version data enables CVE scoping "
                f"against the specific NDFC/DCNM release and identifies the "
                f"applicable Nexus Dashboard platform version"
            ),
            "host": host,
            "port": port,
        })

    # --- NDFC default credentials: POST /login ---
    # NDFC on Nexus Dashboard uses /login with JSON body; bootstrap default
    # credential is Admin_1234 for admin on fresh deployments.
    for username, password in (
        ("admin", "Admin_1234"),
        ("admin", "admin"),
        ("admin", "Cisco123"),
        ("admin", "C1sco12345"),
    ):
        status, body = _post_json(
            "/login",
            {"userName": username, "userPasswd": password, "domain": "local"},
        )
        if status is not None and status < 300 and body and (
            "token" in body.lower() or "accessToken" in body
        ):
            findings.append({
                "severity": "CRITICAL",
                "title": "NDFC_DEFAULT_CREDS",
                "detail": (
                    f"POST {base}/login with '{username}'/'{password}' returned "
                    f"{status} with a valid session token; NDFC/Nexus Dashboard "
                    f"default credentials accepted; authenticated NDFC access "
                    f"grants full fabric controller privileges including switch "
                    f"provisioning, topology modification, VRF/network deployment, "
                    f"and credentials for all NDFC-managed devices — equivalent "
                    f"to administrative access over the entire managed data center "
                    f"network fabric"
                ),
                "host": host,
                "port": port,
            })
            break

    return findings


def probe_aci_microsegmentation_exposure(host: str, port: int = 443,
                                          timeout: float = 10.0) -> list:
    """
    Detect Cisco ACI microsegmentation and EPG security policy exposure.

    Queries APIC REST APIs for EPGs, contracts, bridge domains, and VRFs
    without authentication.  Unenforced VRFs and vzAny consumer contracts
    represent lateral-movement paths through the ACI fabric — unenforced VRFs
    disable contract enforcement entirely, functionally removing all zoning
    rules for every EPG in the routing domain.

    Returns list of finding dicts: {severity, title, detail, host, port}.
    """
    findings = []
    base = f"https://{host}:{port}"
    ctx = _ssl_ctx()

    def _get(path: str, headers: dict = None) -> tuple:
        """Return (status_code, body_text) or (None, None) on failure."""
        req = urllib.request.Request(f"{base}{path}")
        req.add_header("Accept", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                return r.status, raw
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode("utf-8", errors="replace")
            except Exception:
                raw = ""
            return e.code, raw
        except Exception:
            return None, None

    # --- EPG enumeration: fvAEPg ---
    # EPGs define microsegmentation boundaries in ACI; each EPG carries a
    # unique pcTag (sClass) used in hardware zoning-rule enforcement on leaves.
    # Unauth read reveals the complete application segmentation design.
    status, body = _get("/api/node/class/fvAEPg.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_EPG_LIST_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/fvAEPg.json returned {status} "
                f"without authentication; APIC REST API exposes the full "
                f"endpoint group list; EPGs define ACI microsegmentation "
                f"boundaries — their names, bridge domain associations, and "
                f"pcTag class IDs reveal the complete application policy model "
                f"and segmentation topology across all tenants"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            epg_items = data.get("imdata", [])
            if epg_items:
                names = []
                for item in epg_items[:20]:
                    attrs = item.get("fvAEPg", {}).get("attributes", {})
                    name = attrs.get("name", "")
                    dn = attrs.get("dn", "")
                    if name:
                        names.append(f"{name} ({dn})")
                if names:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "ACI_EPG_DETAILS_DISCLOSED",
                        "detail": (
                            f"fvAEPg response contains {len(epg_items)} EPG(s); "
                            f"sample: {'; '.join(names[:5])}; "
                            f"EPG distinguished names encode tenant/app-profile "
                            f"hierarchy enabling full reconstruction of the ACI "
                            f"application policy topology without credentials"
                        ),
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    # --- Contracts: vzBrCP ---
    # Contracts are the ACI security policy object — consumer/provider EPG
    # bindings with filter chains defining permitted traffic.
    status, body = _get("/api/node/class/vzBrCP.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_CONTRACTS_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/vzBrCP.json returned {status} "
                f"without authentication; vzBrCP objects define all ACI contracts "
                f"(security policies); unauth read discloses contract scope "
                f"(vrf/tenant/global), QoS class, and subject structure — "
                f"enabling adversarial mapping of permitted traffic flows between "
                f"EPGs across the fabric"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            contract_items = data.get("imdata", [])
            if contract_items:
                bindings = []
                for item in contract_items[:10]:
                    attrs = item.get("vzBrCP", {}).get("attributes", {})
                    name = attrs.get("name", "")
                    scope = attrs.get("scope", "")
                    if name:
                        bindings.append(f"{name}(scope={scope})")
                if bindings:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "ACI_CONTRACT_BINDINGS_DISCLOSED",
                        "detail": (
                            f"vzBrCP response contains {len(contract_items)} contract(s); "
                            f"sample: {'; '.join(bindings[:5])}; contract scope "
                            f"encodes the enforcement boundary (vrf/tenant/global) — "
                            f"global-scoped contracts permit cross-tenant traffic and "
                            f"represent a significant policy bypass risk when "
                            f"consumer/provider EPG bindings are disclosed"
                        ),
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    # --- Contract subjects: vzSubj ---
    # Subjects group filter chains; apply-both-directions and reverse-filter-ports
    # flags control bidirectional enforcement on leaf zoning tables.
    status, body = _get("/api/node/class/vzSubj.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_CONTRACT_SUBJECTS_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/vzSubj.json returned {status} "
                f"without authentication; vzSubj objects contain per-subject "
                f"apply-both-directions and reverse-filter-ports flags that "
                f"control bidirectional enforcement; unauth read reveals the "
                f"complete filter-chain structure for all ACI security policies"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            subj_items = data.get("imdata", [])
            if subj_items:
                filters = []
                for item in subj_items[:10]:
                    attrs = item.get("vzSubj", {}).get("attributes", {})
                    name = attrs.get("name", "")
                    rev = attrs.get("revFltPorts", "")
                    if name:
                        filters.append(f"{name}(revFlt={rev})")
                if filters:
                    findings.append({
                        "severity": "HIGH",
                        "title": "ACI_POLICY_FILTERS_DISCLOSED",
                        "detail": (
                            f"vzSubj response contains {len(subj_items)} subject(s); "
                            f"sample: {'; '.join(filters[:5])}; contract subject filter "
                            f"chains define the exact TCP/UDP ports and EtherTypes "
                            f"permitted between EPGs — disclosure enables precise "
                            f"mapping of allowed lateral movement paths through "
                            f"the ACI fabric zoning rules"
                        ),
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    # --- vzAny consumer relationships: vzRsAny__Cons ---
    # vzAny is a special EPG construct implicitly containing every EPG in a VRF.
    # Contracts applied to vzAny affect all-to-all communication in the VRF —
    # a permissive vzAny contract is functionally equivalent to permit-any.
    status, body = _get("/api/node/class/vzRsAny__Cons.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_VZANY_CONTRACTS_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/vzRsAny__Cons.json returned {status} "
                f"without authentication; vzRsAny__Cons objects bind contracts to "
                f"the vzAny EPG — a special ACI construct that implicitly includes "
                f"every EPG in a VRF; contracts applied here affect all-to-all "
                f"communication across the entire VRF routing domain"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            vzany_items = data.get("imdata", [])
            if vzany_items:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "ACI_VZANY_PERMISSIVE_POLICY",
                    "detail": (
                        f"vzRsAny__Cons returned {len(vzany_items)} vzAny consumer "
                        f"relationship(s); each binding applies a contract to ALL "
                        f"EPGs in the VRF simultaneously; permissive vzAny contracts "
                        f"(e.g., permit-any filter with unspecified EtherType) "
                        f"eliminate EPG-level microsegmentation and create "
                        f"unrestricted lateral movement paths across the entire "
                        f"ACI VRF — equivalent to disabling the zoning-rule engine "
                        f"for all endpoints in the routing domain"
                    ),
                    "host": host,
                    "port": port,
                })
        except Exception:
            pass

    # --- Bridge domains: fvBD ---
    # BDs define L2 broadcast boundaries; arpFlood=yes + unkMacUcastAct=flood
    # allows ARP spoofing against silent hosts before endpoint learning occurs.
    status, body = _get("/api/node/class/fvBD.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "HIGH",
            "title": "ACI_BRIDGE_DOMAINS_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/fvBD.json returned {status} "
                f"without authentication; fvBD objects define ACI bridge domains "
                f"including unicast routing mode, ARP flood setting, and unknown "
                f"unicast handling — unauth read discloses the L2 broadcast "
                f"domain topology and forwarding behavior across all tenants"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            bd_items = data.get("imdata", [])
            risky_bds = []
            for item in bd_items:
                attrs = item.get("fvBD", {}).get("attributes", {})
                name = attrs.get("name", "")
                arp_flood = attrs.get("arpFlood", "")
                unk_mac = attrs.get("unkMacUcastAct", "")
                if arp_flood == "yes" and unk_mac == "flood":
                    risky_bds.append(
                        f"{name}(arpFlood={arp_flood},unkMac={unk_mac})"
                    )
            if risky_bds:
                findings.append({
                    "severity": "HIGH",
                    "title": "ACI_BD_FORWARDING_CONFIG",
                    "detail": (
                        f"{len(risky_bds)} bridge domain(s) with ARP flooding and "
                        f"unknown unicast flood both enabled: "
                        f"{'; '.join(risky_bds[:5])}; "
                        f"flood-mode BDs allow an attacker with access to any EPG "
                        f"in the BD to perform ARP spoofing and intercept traffic "
                        f"from silent hosts before their endpoints are learned "
                        f"in the leaf endpoint table and spine COOP database"
                    ),
                    "host": host,
                    "port": port,
                })
        except Exception:
            pass

    # --- VRFs: fvCtx ---
    # pcEnfPref=unenforced disables contract enforcement in the VRF — all
    # endpoints communicate freely regardless of EPG boundaries or contract policy.
    status, body = _get("/api/node/class/fvCtx.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_VRF_LIST_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/fvCtx.json returned {status} "
                f"without authentication; fvCtx objects enumerate all VRFs "
                f"across every tenant; the pcEnfPref attribute reveals whether "
                f"contract enforcement is active (enforced) or disabled "
                f"(unenforced) in each VRF routing domain"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            vrf_items = data.get("imdata", [])
            unenforced = []
            for item in vrf_items:
                attrs = item.get("fvCtx", {}).get("attributes", {})
                name = attrs.get("name", "")
                dn = attrs.get("dn", "")
                pref = attrs.get("pcEnfPref", "")
                if pref == "unenforced":
                    unenforced.append(f"{name} ({dn})")
            if unenforced:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "ACI_UNENFORCED_VRF",
                    "detail": (
                        f"{len(unenforced)} VRF(s) with pcEnfPref=unenforced: "
                        f"{'; '.join(unenforced[:5])}; unenforced VRFs disable "
                        f"ACI contract enforcement — all endpoints within the VRF "
                        f"communicate without restriction regardless of EPG "
                        f"boundaries or contract policy; equivalent to removing "
                        f"all zoning rules on every leaf, enabling unrestricted "
                        f"lateral movement across the entire VRF routing domain"
                    ),
                    "host": host,
                    "port": port,
                })
        except Exception:
            pass

    return findings


def probe_aci_tenant_network_topology(host: str, port: int = 443,
                                       timeout: float = 10.0) -> list:
    """
    Detect Cisco ACI tenant network and routing topology exposure.

    Queries APIC REST APIs for tenants, BGP peers, static routes, EPG port
    attachments, access port profiles, and OSPF interface policies without
    authentication.  Disclosed BGP peer IPs, AS numbers, and switch
    port-to-EPG mappings enable full reconstruction of the fabric's external
    connectivity posture.  OSPF without MD5 authentication is exploitable
    via LSA injection from any L2-adjacent position on the L3OUT segment.

    Returns list of finding dicts: {severity, title, detail, host, port}.
    """
    findings = []
    base = f"https://{host}:{port}"
    ctx = _ssl_ctx()

    def _get(path: str, headers: dict = None) -> tuple:
        """Return (status_code, body_text) or (None, None) on failure."""
        req = urllib.request.Request(f"{base}{path}")
        req.add_header("Accept", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=ctx,
                                        timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                return r.status, raw
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode("utf-8", errors="replace")
            except Exception:
                raw = ""
            return e.code, raw
        except Exception:
            return None, None

    # --- Tenant list: fvTenant ---
    # Tenants are top-level multi-tenancy containers; names encode org structure.
    # System tenants (common/infra/mgmt) plus up to 3000 user tenants.
    status, body = _get("/api/node/class/fvTenant.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_TENANTS_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/fvTenant.json returned {status} "
                f"without authentication; fvTenant objects enumerate all ACI "
                f"tenants including system tenants (common/infra/mgmt) and all "
                f"user-created tenants; tenant enumeration enables full "
                f"reconstruction of the multi-tenancy topology and identifies "
                f"high-value targets by org unit or compliance zone"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            tenant_items = data.get("imdata", [])
            if tenant_items:
                sensitive_patterns = (
                    "prod", "production", "mgmt", "management",
                    "fin", "finance", "hr", "pci", "hipaa",
                    "dev", "staging", "common", "infra",
                )
                names = []
                sensitive = []
                for item in tenant_items:
                    attrs = item.get("fvTenant", {}).get("attributes", {})
                    name = attrs.get("name", "")
                    if name:
                        names.append(name)
                        if any(p in name.lower() for p in sensitive_patterns):
                            sensitive.append(name)
                if names:
                    findings.append({
                        "severity": "HIGH",
                        "title": "ACI_TENANT_NAMES_DISCLOSED",
                        "detail": (
                            f"fvTenant response contains {len(names)} tenant(s): "
                            f"{', '.join(names[:10])}; "
                            + (
                                f"sensitive-pattern matches: {', '.join(sensitive)}; "
                                if sensitive else ""
                            )
                            + "tenant names encode organizational structure "
                            "(business units, environments, compliance zones); "
                            "production/finance/PCI tenant identification enables "
                            "targeted lateral movement planning within the fabric"
                        ),
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    # --- Static routes: ipRouteS ---
    # Static routes reveal the internal IP addressing plan per tenant/VRF.
    status, body = _get("/api/node/class/ipRouteS.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_STATIC_ROUTES_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/ipRouteS.json returned {status} "
                f"without authentication; ipRouteS objects enumerate all static "
                f"routes configured across all tenants and VRFs; disclosed routes "
                f"reveal the internal IP addressing plan, next-hop topology, and "
                f"any traffic engineering or inter-VRF route leaking configuration"
            ),
            "host": host,
            "port": port,
        })

    # --- BGP peer policies: bgpPeerP ---
    # BGP peers expose the fabric's external routing posture; peer IPs identify
    # WAN edge devices, inter-site links, and upstream provider connections.
    status, body = _get("/api/node/class/bgpPeerP.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_BGP_PEERS_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/bgpPeerP.json returned {status} "
                f"without authentication; bgpPeerP objects enumerate all BGP "
                f"peer policies including peer IP addresses, remote AS numbers, "
                f"and per-peer BGP options; disclosure reveals the complete "
                f"external BGP peering topology of the ACI fabric"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            peer_items = data.get("imdata", [])
            if peer_items:
                peers = []
                for item in peer_items[:20]:
                    attrs = item.get("bgpPeerP", {}).get("attributes", {})
                    addr = attrs.get("addr", "")
                    peer_t = attrs.get("peerT", "")
                    password = attrs.get("password", "")
                    pw_hint = " [HAS_PASSWORD]" if password else ""
                    if addr:
                        peers.append(f"{addr}(peerT={peer_t}){pw_hint}")
                if peers:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "ACI_BGP_PEER_IPS",
                        "detail": (
                            f"bgpPeerP response contains {len(peer_items)} BGP peer(s); "
                            f"sample: {'; '.join(peers[:5])}; peer IPs identify "
                            f"external routers, WAN edge devices, and inter-site "
                            f"connections; AS numbers enable BGP topology mapping "
                            f"and identification of upstream provider relationships "
                            f"reachable via the ACI fabric border leaves"
                        ),
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    # --- BGP AS policies: bgpAsP ---
    # AS policies define the local AS number used in BGP L3OUT configurations.
    status, body = _get("/api/node/class/bgpAsP.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "HIGH",
            "title": "ACI_BGP_AS_POLICIES_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/bgpAsP.json returned {status} "
                f"without authentication; bgpAsP objects expose the BGP autonomous "
                f"system number policies used in L3OUT configurations; local AS "
                f"disclosure enables BGP AS-path analysis and identification of "
                f"the organization's BGP routing domain boundary"
            ),
            "host": host,
            "port": port,
        })

    # --- EPG-to-port attachments: fvRsPathAtt ---
    # Path attachments map EPGs to physical leaf ports; tDn values encode
    # leaf node numbers and interface IDs enabling physical topology reconstruction.
    status, body = _get("/api/node/class/fvRsPathAtt.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_PORT_ATTACHMENTS_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/fvRsPathAtt.json returned {status} "
                f"without authentication; fvRsPathAtt objects map EPGs to physical "
                f"leaf switch ports via distinguished names encoding node IDs and "
                f"interface identifiers; unauth read enables full reconstruction "
                f"of the physical-to-logical topology across all tenants"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            path_items = data.get("imdata", [])
            if path_items:
                topo = []
                for item in path_items[:5]:
                    attrs = item.get("fvRsPathAtt", {}).get("attributes", {})
                    tdn = attrs.get("tDn", "")
                    encap = attrs.get("encap", "")
                    if tdn:
                        topo.append(f"{tdn}(encap={encap})")
                node_re = re.compile(r"node-(\d+)")
                nodes = set()
                for item in path_items:
                    attrs = item.get("fvRsPathAtt", {}).get("attributes", {})
                    tdn = attrs.get("tDn", "")
                    for m in node_re.finditer(tdn):
                        nodes.add(m.group(1))
                if topo or nodes:
                    findings.append({
                        "severity": "HIGH",
                        "title": "ACI_EPG_PORT_TOPOLOGY",
                        "detail": (
                            f"fvRsPathAtt response contains {len(path_items)} path "
                            f"attachment(s) across leaf node(s): "
                            f"{', '.join(sorted(nodes)[:10])}; "
                            f"sample paths: {'; '.join(topo[:3])}; "
                            f"tDn values encode leaf node numbers and port "
                            f"identifiers, enabling reconstruction of which EPGs "
                            f"are deployed on which physical switch ports and "
                            f"VLANs across the fabric"
                        ),
                        "host": host,
                        "port": port,
                    })
        except Exception:
            pass

    # --- Access port profiles: infraRsAccPortP ---
    # Access port profile bindings link leaf switch profiles to port profiles;
    # disclosure reveals the physical interface configuration hierarchy.
    status, body = _get("/api/node/class/infraRsAccPortP.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "HIGH",
            "title": "ACI_ACCESS_PORTS_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/infraRsAccPortP.json returned {status} "
                f"without authentication; infraRsAccPortP objects link leaf switch "
                f"profiles to access port profiles; unauth read discloses the "
                f"physical interface configuration hierarchy for all fabric leaf "
                f"switches, enabling enumeration of access port policy assignments"
            ),
            "host": host,
            "port": port,
        })

    # --- OSPF interface policies: ospfIfPol ---
    # ospfIfPol encodes the authentication type (none/simple/md5) per OSPF
    # L3OUT interface.  OSPF without MD5 is vulnerable to LSA injection
    # from any L2-adjacent position on the L3OUT routed segment.
    status, body = _get("/api/node/class/ospfIfPol.json")
    if status is not None and status < 400 and body and "imdata" in body:
        findings.append({
            "severity": "HIGH",
            "title": "ACI_OSPF_POLICIES_UNAUTH",
            "detail": (
                f"GET {base}/api/node/class/ospfIfPol.json returned {status} "
                f"without authentication; ospfIfPol objects define per-interface "
                f"OSPF settings including authentication type (none/simple/md5), "
                f"hello/dead timers, and network type; disclosure reveals the "
                f"OSPF authentication posture across all L3OUT external connections"
            ),
            "host": host,
            "port": port,
        })
        try:
            data = json.loads(body)
            ospf_items = data.get("imdata", [])
            no_auth = []
            for item in ospf_items:
                attrs = item.get("ospfIfPol", {}).get("attributes", {})
                name = attrs.get("name", "")
                auth_type = attrs.get("authT", "none")
                dn = attrs.get("dn", "")
                if auth_type in ("none", ""):
                    no_auth.append(f"{name} ({dn})")
            if no_auth:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "ACI_OSPF_NO_AUTH",
                    "detail": (
                        f"{len(no_auth)} OSPF interface policy(ies) with no "
                        f"authentication configured: {'; '.join(no_auth[:5])}; "
                        f"OSPF without MD5 authentication is vulnerable to "
                        f"neighbor injection from any L2-adjacent position on "
                        f"the L3OUT routed segment; an attacker can inject "
                        f"false LSAs, manipulate routing tables on ACI border "
                        f"leaves, and redirect traffic destined for internal "
                        f"subnets through an attacker-controlled next hop"
                    ),
                    "host": host,
                    "port": port,
                })
        except Exception:
            pass

    return findings


def probe_cisco_nginx_proxy_exposure(host: str, port: int = 443,
                                     timeout: float = 10.0) -> list:
    findings = []
    base = f"https://{host}:{port}"
    ctx = _ssl_ctx()

    def _get(path: str, extra_hdrs: dict = None) -> tuple:
        req = urllib.request.Request(f"{base}{path}")
        req.add_header("User-Agent", "Mozilla/5.0")
        for k, v in (extra_hdrs or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                return r.status, dict(r.headers), raw
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode("utf-8", errors="replace")
            except Exception:
                raw = ""
            return e.code, dict(e.headers), raw
        except Exception:
            return None, {}, ""

    # Server header: nginx version string disclosure (server_tokens on by default)
    status, hdrs, body = _get("/")
    if status is not None:
        srv = hdrs.get("Server", "") or hdrs.get("server", "")
        m = re.search(r"nginx/(\d+\.\d+\.\d+)", srv)
        if m:
            findings.append({
                "severity": "MEDIUM",
                "title": "NGINX_VERSION_DISCLOSED",
                "detail": (
                    f"Server header at {base}/ returned '{srv}'; nginx version "
                    f"{m.group(1)} disclosed; server_tokens directive is enabled "
                    f"(default); version disclosure narrows exploitable CVE set; "
                    f"nginx builds prior to 1.24 are affected by CVE-2023-44487 "
                    f"(HTTP/2 rapid reset) and multiple request smuggling variants; "
                    f"Cisco DNA Center, APIC, NDFC, and ISE all use nginx as the "
                    f"front-facing reverse proxy; mitigate with server_tokens off"
                ),
                "host": host,
                "port": port,
            })
        elif "nginx" in srv.lower():
            findings.append({
                "severity": "LOW",
                "title": "NGINX_SERVER_HEADER",
                "detail": (
                    f"Server header at {base}/ discloses '{srv}'; nginx identity "
                    f"confirmed; server_tokens is not 'off'; error-page body "
                    f"fingerprinting can recover the exact version string even when "
                    f"the header only says 'nginx' without a version number"
                ),
                "host": host,
                "port": port,
            })

    # Error page footer: nginx version embedded in HTML even when Server header suppressed
    status, hdrs, body = _get("/nonexistent-path-404-probe")
    if status == 404 and body:
        m = re.search(r"nginx/(\d+\.\d+\.\d+)", body)
        if m:
            findings.append({
                "severity": "MEDIUM",
                "title": "NGINX_VERSION_ERROR_FOOTER",
                "detail": (
                    f"404 response body at {base}/nonexistent-path-404-probe "
                    f"contains nginx/{m.group(1)} in the HTML error page footer; "
                    f"server_tokens is 'on' (default); nginx embeds the version in "
                    f"error pages independently of the Server response header; this "
                    f"bypasses any Server header stripping applied by a downstream "
                    f"load balancer in front of the Cisco API host"
                ),
                "host": host,
                "port": port,
            })

    # stub_status module: unauthenticated nginx worker metrics
    for stub_path in ("/nginx_status", "/status", "/nginx-status", "/server-status"):
        status, hdrs, body = _get(stub_path)
        if status == 200 and body and "Active connections:" in body:
            m_conn = re.search(r"Active connections:\s*(\d+)", body)
            m_stats = re.search(r"(\d+)\s+(\d+)\s+(\d+)", body)
            conn_n = m_conn.group(1) if m_conn else "?"
            stats_s = m_stats.group(0) if m_stats else "unavailable"
            findings.append({
                "severity": "HIGH",
                "title": "NGINX_STUB_STATUS_EXPOSED",
                "detail": (
                    f"nginx stub_status accessible at {base}{stub_path} without "
                    f"authentication; Active connections: {conn_n}; "
                    f"server/accepts/handled/requests: {stats_s}; stub_status "
                    f"should be restricted to 127.0.0.1 via allow/deny directives; "
                    f"unauthenticated access exposes real-time worker states "
                    f"(reading/writing/waiting), total throughput counters, and "
                    f"current connection volume; traffic metadata aids attack timing "
                    f"during low-activity maintenance windows on the Cisco management plane"
                ),
                "host": host,
                "port": port,
            })
            break

    # X-Accel-* response headers: proxy_pass_header overriding default suppression
    status, hdrs, body = _get("/api/v1/")
    if status is not None:
        accel = {k: v for k, v in hdrs.items() if k.lower().startswith("x-accel")}
        if accel:
            findings.append({
                "severity": "MEDIUM",
                "title": "NGINX_XACCEL_HEADER_LEAK",
                "detail": (
                    f"Response from {base}/api/v1/ exposes X-Accel-* headers: "
                    f"{accel}; nginx suppresses X-Accel-Redirect, X-Accel-Buffering, "
                    f"X-Accel-Charset, and X-Accel-Expires from backend responses by "
                    f"default via proxy_hide_header; their presence means a "
                    f"proxy_pass_header directive has overridden suppression; "
                    f"X-Accel-Redirect lets the nginx worker serve an internal URI "
                    f"outside the authenticated location block, enabling auth bypass "
                    f"to Cisco API paths not intended to be externally reachable"
                ),
                "host": host,
                "port": port,
            })

    # Via header: internal hostname or RFC-1918 IP disclosure
    via = hdrs.get("Via", "") or hdrs.get("via", "")
    if via:
        rfc1918 = re.search(
            r"\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b",
            via
        )
        findings.append({
            "severity": "MEDIUM" if rfc1918 else "LOW",
            "title": "NGINX_VIA_HEADER_DISCLOSURE",
            "detail": (
                f"Via header in response from {base}/api/v1/: '{via}'; "
                + (
                    f"RFC-1918 address {rfc1918.group(0)} leaked; discloses "
                    f"the internal network segment of the backend cluster; "
                    if rfc1918 else
                    "proxy-chain presence and potential software version exposed; "
                )
                + "suppress with proxy_hide_header Via in nginx proxy configuration"
            ),
            "host": host,
            "port": port,
        })

    # X-Forwarded-For passthrough: client-injected XFF reaching the backend unmodified
    injected = "192.0.2.99"
    status2, hdrs2, _ = _get("/api/v1/", extra_hdrs={"X-Forwarded-For": injected})
    if status2 is not None:
        xff_back = hdrs2.get("X-Forwarded-For", "") or hdrs2.get("x-forwarded-for", "")
        if injected in xff_back:
            findings.append({
                "severity": "MEDIUM",
                "title": "NGINX_XFF_PASSTHROUGH",
                "detail": (
                    f"Client-injected X-Forwarded-For: {injected} reflected in "
                    f"response headers from {base}/api/v1/ as '{xff_back}'; nginx "
                    f"is forwarding attacker-controlled XFF to the Cisco API backend "
                    f"without set_real_ip_from trust scoping; backends using XFF for "
                    f"IP-based access control (admin subnet allowlists, rate limiting, "
                    f"geo-restriction, audit logging) can be bypassed by spoofing XFF "
                    f"to an expected internal or privileged source address"
                ),
                "host": host,
                "port": port,
            })

    return findings


def probe_cisco_api_gateway_bypass(host: str, port: int = 443,
                                   timeout: float = 10.0) -> list:
    findings = []
    base = f"https://{host}:{port}"
    ctx = _ssl_ctx()

    def _req(path: str, method: str = "GET", extra_hdrs: dict = None,
             body: bytes = None) -> tuple:
        req = urllib.request.Request(f"{base}{path}", data=body, method=method)
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Content-Type", "application/json")
        for k, v in (extra_hdrs or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                return r.status, dict(r.headers), raw
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode("utf-8", errors="replace")
            except Exception:
                raw = ""
            return e.code, dict(e.headers), raw
        except Exception:
            return None, {}, ""

    def _raw_send(raw_request: bytes) -> tuple:
        # raw TLS socket for HTTP/1.0 and TE/CL desync probes
        try:
            conn = socket.create_connection((host, port), timeout=timeout)
            conn = ctx.wrap_socket(conn, server_hostname=host)
            conn.sendall(raw_request)
            resp = b""
            conn.settimeout(timeout)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 16384:
                        break
            except Exception:
                pass
            conn.close()
            text = resp.decode("utf-8", errors="replace")
            m = re.match(r"HTTP/[\d.]+ (\d{3})", text)
            code = int(m.group(1)) if m else None
            return code, text
        except Exception:
            return None, ""

    # Establish baseline status codes for candidate auth endpoints
    auth_candidates = [
        "/dna/system/api/v1/auth/token",
        "/api/v1/auth/token",
        "/api/v1/ticket",
        "/api/login",
    ]
    baseline_path = None
    baseline_get = None
    baseline_post = None
    for ap in auth_candidates:
        sg, _, _ = _req(ap, method="GET")
        sp, _, _ = _req(ap, method="POST")
        if sg is not None or sp is not None:
            baseline_path = ap
            baseline_get = sg
            baseline_post = sp
            break

    # X-HTTP-Method-Override: GET tunneled as POST to bypass method-based ACLs
    if baseline_path and baseline_get is not None and baseline_post is not None:
        s_ovr, _, body_ovr = _req(
            baseline_path, method="GET",
            extra_hdrs={"X-HTTP-Method-Override": "POST",
                        "X-Method-Override": "POST",
                        "X-HTTP-Method": "POST"}
        )
        if (s_ovr is not None and s_ovr != baseline_get
                and abs(s_ovr - baseline_post) <= 5):
            findings.append({
                "severity": "HIGH",
                "title": "NGINX_METHOD_OVERRIDE_BYPASS",
                "detail": (
                    f"GET {base}{baseline_path} with X-HTTP-Method-Override: POST "
                    f"returned {s_ovr}; baseline GET={baseline_get}, POST={baseline_post}; "
                    f"nginx forwards X-HTTP-Method-Override to the upstream backend "
                    f"without stripping it; Cisco API backends honoring this header "
                    f"execute POST semantics on a GET request; enables token issuance, "
                    f"write operations, and state mutations through network segments "
                    f"that permit only GET via method-based firewall rules; "
                    f"response preview: {body_ovr[:120]!r}"
                ),
                "host": host,
                "port": port,
            })

    # Double-slash path bypass: nginx merge_slashes off allows //path to escape location ACL
    if baseline_path:
        ds_path = "//" + baseline_path.lstrip("/")
        s_ds, _, body_ds = _req(ds_path)
        s_norm, _, _ = _req(baseline_path)
        if (s_ds is not None and s_norm is not None
                and s_ds != s_norm and s_ds < 400
                and (s_norm >= 400 or s_norm == 401)):
            findings.append({
                "severity": "CRITICAL",
                "title": "NGINX_DOUBLE_SLASH_BYPASS",
                "detail": (
                    f"Path {ds_path} returned {s_ds} while canonical "
                    f"{baseline_path} returned {s_norm}; nginx merge_slashes "
                    f"is disabled; double-slash URIs do not match the protected "
                    f"location block prefix; auth_basic, auth_request, and proxy_pass "
                    f"auth directives scoped to location /dna/ or /api/ do not match "
                    f"//dna/ or //api/, allowing unauthenticated access to Cisco "
                    f"management API endpoints; body: {body_ds[:120]!r}"
                ),
                "host": host,
                "port": port,
            })

    # HTTP/1.0 downgrade: auth middleware gating on $server_protocol
    if baseline_path:
        raw10 = (
            f"GET {baseline_path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        ).encode()
        s_10, _ = _raw_send(raw10)
        s_11, _, _ = _req(baseline_path)
        if (s_10 is not None and s_11 is not None
                and s_10 != s_11 and s_10 < 400 and s_11 >= 400):
            findings.append({
                "severity": "HIGH",
                "title": "NGINX_HTTP10_AUTH_BYPASS",
                "detail": (
                    f"HTTP/1.0 GET {baseline_path} returned {s_10} while "
                    f"HTTP/1.1 returned {s_11}; nginx proxy or the Cisco upstream "
                    f"auth_request module differentiates behavior by protocol version; "
                    f"proxy_http_version defaults to 1.0 for backend connections; "
                    f"auth subrequests checking $server_protocol or pattern-matching "
                    f"HTTP/1.1-specific headers (Upgrade, TE) may be skipped for "
                    f"HTTP/1.0 clients; chunked transfer-encoding is also disabled in "
                    f"HTTP/1.0, altering nginx upstream buffer handling"
                ),
                "host": host,
                "port": port,
            })

    # CL.TE desync probe: Content-Length vs Transfer-Encoding ambiguity at nginx boundary
    probe_paths_te = [
        "/dna/system/api/v1/auth/token",
        "/api/v1/ticket",
        "/api/v1/auth/token",
    ]
    for pp in probe_paths_te:
        # CL claims 6 bytes; chunked terminator is 5 bytes — deliberate off-by-one
        chunked_body = b"0\r\n\r\n"
        raw_te = (
            f"POST {pp} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        ).encode() + chunked_body
        s_te, _ = _raw_send(raw_te)
        s_norm_post, _, _ = _req(pp, method="POST")
        if (s_te is not None and s_norm_post is not None
                and s_te not in (400, 411, 413, 501)
                and s_te != s_norm_post):
            findings.append({
                "severity": "HIGH",
                "title": "NGINX_TE_CL_DESYNC_CANDIDATE",
                "detail": (
                    f"Ambiguous CL.TE request to POST {base}{pp} returned {s_te} "
                    f"vs normal POST {s_norm_post}; nginx and the Cisco backend "
                    f"disagree on request-body boundaries; nginx parses by "
                    f"Content-Length while the backend parses by Transfer-Encoding "
                    f"chunked, or vice versa; leftover bytes from one request are "
                    f"prepended to the next connection's request on the shared nginx "
                    f"upstream pool, enabling HTTP request smuggling; impact includes "
                    f"auth bypass, session hijack, and cache poisoning on the Cisco "
                    f"API gateway; manual timing confirmation required to exclude "
                    f"race false-positive"
                ),
                "host": host,
                "port": port,
            })
            break

    # nginx alias traversal: location without trailing slash + alias with trailing slash
    traversal_probes = [
        ("/dna../etc/passwd", "/dna/system/api/v1/auth/token"),
        ("/api/v1../admin/", "/api/v1/"),
        ("/dna/system/../system/api/v1/auth/token",
         "/dna/system/api/v1/auth/token"),
    ]
    for trav, ref in traversal_probes:
        s_t, _, body_t = _req(trav)
        s_r, _, _ = _req(ref)
        if (s_t is not None and s_r is not None
                and s_t < 400 and (s_r >= 400 or s_r == 401)):
            findings.append({
                "severity": "CRITICAL",
                "title": "NGINX_ALIAS_TRAVERSAL",
                "detail": (
                    f"Path traversal probe {base}{trav} returned {s_t} while "
                    f"canonical {ref} returned {s_r}; nginx alias misconfiguration: "
                    f"location /dna (no trailing slash) paired with alias /var/dna/ "
                    f"(trailing slash) allows the URI segment following /dna to escape "
                    f"the intended document root; GET /dna../etc/passwd resolves "
                    f"outside the Cisco API directory on the nginx worker filesystem; "
                    f"body preview: {body_t[:120]!r}"
                ),
                "host": host,
                "port": port,
            })
            break

    return findings


def probe_cisco_crosswork_telemetry_exposure(host: str, port: int = 443,
                                              timeout: float = 10.0) -> list:
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}:{port}"

    def _get(path: str, extra_headers: dict = None) -> tuple:
        url = f"{base}{path}"
        hdrs = {
            "Accept": "application/json, text/html, */*",
            "User-Agent": "Mozilla/5.0",
        }
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(524288).decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(131072).decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    crosswork_paths = [
        ("/api/v1/collections", "CROSSWORK_COLLECTIONS"),
        ("/api/v1/devices", "CROSSWORK_DEVICES"),
        ("/crosswork/syslog/v1/", "CROSSWORK_SYSLOG"),
        ("/crosswork/nso/v1/", "CROSSWORK_NSO"),
    ]
    for path, label in crosswork_paths:
        status, body = _get(path)
        if status is None:
            continue
        sev = "HIGH"
        if status < 300:
            sev = "CRITICAL"
            if re.search(r'"device|"host|"address|"ip|"mgmt', body, re.I):
                sev = "CRITICAL"
        elif status in (401, 403):
            sev = "MEDIUM"
        elif status >= 500:
            sev = "LOW"
        findings.append({
            "severity": sev,
            "title": f"CROSSWORK_{label}_REACHABLE",
            "detail": (
                f"GET {base}{path} returned {status}; Cisco Crosswork network "
                f"automation REST endpoint is reachable; Crosswork orchestrates "
                f"telemetry collection, device lifecycle, and NSO-backed "
                f"configuration delivery across multi-vendor transport networks; "
                f"body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    grpc_port = 57500
    H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    try:
        s = socket.create_connection((host, grpc_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(H2_PREFACE)
        try:
            data = s.recv(2048)
        except Exception:
            data = b""
        s.close()
        findings.append({
            "severity": "HIGH",
            "title": "CROSSWORK_GRPC_TELEMETRY_PORT_OPEN",
            "detail": (
                f"TCP connect to {host}:{grpc_port} succeeded and server "
                f"responded to HTTP/2 connection preface ({len(data)} bytes); "
                f"Cisco Crosswork gRPC telemetry collector is reachable; "
                f"port 57500 is the model-driven telemetry gRPC endpoint "
                f"used by IOS-XR and IOS-XE for streaming operational data "
                f"including BGP state, interface counters, and sensor-path "
                f"exports; unauthenticated access exposes near-real-time "
                f"network topology and device health data"
            ),
            "host": host,
            "port": grpc_port,
        })
    except Exception:
        pass

    kafka_port = 9092
    KAFKA_METADATA_REQUEST = (
        b"\x00\x00\x00\x1b"
        b"\x00\x03"
        b"\x00\x00"
        b"\x00\x00\x00\x01"
        b"\x00\x09"
        b"kafka-cli"
        b"\xff\xff"
        b"\x00\x00\x00\x00\x01"
        b"\x00"
    )
    try:
        s = socket.create_connection((host, kafka_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(KAFKA_METADATA_REQUEST)
        try:
            banner = s.recv(4096)
        except Exception:
            banner = b""
        s.close()
        if banner:
            text = banner.decode(errors="replace")
            has_topics = re.search(r'[a-zA-Z0-9_\-]{3,64}', text)
            broker_ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
            sev = "CRITICAL" if (has_topics or broker_ip) else "HIGH"
            findings.append({
                "severity": sev,
                "title": "KAFKA_PLAINTEXT_BROKER_REACHABLE",
                "detail": (
                    f"TCP connect to {host}:{kafka_port} succeeded and Kafka "
                    f"metadata response received ({len(banner)} bytes); "
                    f"Kafka broker is listening in plaintext mode with no "
                    f"SASL/TLS; any client can enumerate topics, consume "
                    f"messages, and produce arbitrary records without "
                    f"authentication; broker IPs in response: "
                    f"{bool(broker_ip)}; topic strings present: "
                    f"{bool(has_topics)}; excerpt: {text[:120]!r}"
                ),
                "host": host,
                "port": kafka_port,
            })
    except Exception:
        pass

    zk_port = 2181
    try:
        s = socket.create_connection((host, zk_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"mntr\n")
        try:
            zk_resp = s.recv(8192)
        except Exception:
            zk_resp = b""
        s.close()
        if zk_resp:
            text = zk_resp.decode(errors="replace")
            topic_ref = re.search(r'zk_followers|zk_synced|zk_avg_latency', text)
            broker_count = re.search(r'zk_followers\s+(\d+)', text)
            sev = "CRITICAL" if topic_ref else "HIGH"
            detail_extra = ""
            if broker_count:
                detail_extra = (
                    f"; follower count: {broker_count.group(1)}"
                )
            findings.append({
                "severity": sev,
                "title": "ZOOKEEPER_MNTR_UNAUTH_RESPONSE",
                "detail": (
                    f"ZooKeeper four-letter 'mntr' command to {host}:{zk_port} "
                    f"returned {len(zk_resp)} bytes without authentication; "
                    f"ZooKeeper stores Kafka broker registrations, topic "
                    f"partition assignments, and controller election state; "
                    f"unauthenticated 'mntr' output discloses cluster health "
                    f"metrics, follower topology, and node count{detail_extra}; "
                    f"excerpt: {text[:200]!r}"
                ),
                "host": host,
                "port": zk_port,
            })
    except Exception:
        pass

    return findings


def probe_cisco_tetration_analytics_exposure(host: str, port: int = 443,
                                              timeout: float = 10.0) -> list:
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}:{port}"

    def _get(path: str, extra_headers: dict = None) -> tuple:
        url = f"{base}{path}"
        hdrs = {
            "Accept": "application/json, text/html, */*",
            "User-Agent": "Mozilla/5.0",
        }
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read(524288).decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(131072).decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    openapi_paths = [
        ("/openapi/v1/applications", "TETRATION_APPLICATIONS"),
        ("/openapi/v1/inventory/filter", "TETRATION_INVENTORY_FILTER"),
        ("/openapi/v1/sensors", "TETRATION_SENSORS"),
        ("/h4/api/inventory", "TETRATION_H4_INVENTORY"),
        ("/h4/api/user", "TETRATION_H4_USER"),
    ]
    malformed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    for path, label in openapi_paths:
        status, body = _get(path, {"X-Tet-API-Key": malformed_key})
        if status is None:
            continue
        sev = "MEDIUM"
        info_leak = False
        if re.search(
            r'"error"|"message"|"detail"|"code"|"description"|"stack"|"trace"',
            body, re.I
        ):
            info_leak = True
        if status < 300:
            sev = "CRITICAL"
        elif status in (400, 422) and info_leak:
            sev = "HIGH"
        elif status in (401, 403) and info_leak:
            sev = "MEDIUM"
        elif status >= 500:
            sev = "HIGH"
        findings.append({
            "severity": sev,
            "title": f"{label}_REACHABLE",
            "detail": (
                f"GET {base}{path} with malformed X-Tet-API-Key returned "
                f"{status}; Cisco Secure Workload (formerly Tetration) REST "
                f"endpoint is reachable; info_leak_in_body={info_leak}; "
                f"Tetration maps every workload-to-workload flow across the "
                f"data center and cloud; /openapi/v1/applications exposes "
                f"application segmentation policy and workload group "
                f"membership; /openapi/v1/sensors exposes installed sensor "
                f"inventory including hostnames, IPs, and OS versions; "
                f"error body may disclose internal schema, auth mechanism, "
                f"or stack trace; body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    agent_install_path = "/sw/agent/install/"
    status, body = _get(agent_install_path)
    if status is not None:
        sev = "HIGH"
        file_listing = False
        if re.search(
            r'\.rpm|\.deb|\.sh|\.tar|\.pkg|\.exe|Index of|href=.*agent',
            body, re.I
        ):
            file_listing = True
            sev = "CRITICAL"
        elif status < 300:
            sev = "CRITICAL"
        findings.append({
            "severity": sev,
            "title": "TETRATION_AGENT_INSTALL_DIRECTORY",
            "detail": (
                f"GET {base}{agent_install_path} returned {status}; "
                f"Cisco Secure Workload agent distribution endpoint is "
                f"reachable; file_listing_detected={file_listing}; "
                f"the /sw/agent/install/ path hosts platform-specific "
                f"sensor packages (RPM, DEB, shell installers) for deep "
                f"visibility agents deployed on workloads; public access "
                f"enables unauthenticated download of agent binaries "
                f"for reverse engineering and supply-chain fingerprinting; "
                f"a directory listing additionally discloses supported OS "
                f"and architecture targets; body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_cisco_catalyst_center_mobile_api(host: str, port: int = 443,
                                           timeout: float = 10.0) -> list:
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, extra_headers: dict = None) -> tuple:
        url = f"https://{host}:{port}{path}"
        hdrs = {
            "User-Agent": "CatalystCenter/1.0 CFNetwork/1410.0.3 Darwin/22.6.0",
            "Accept": "application/json",
        }
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    def _post(path: str, body: bytes = b"", extra_headers: dict = None) -> tuple:
        url = f"https://{host}:{port}{path}"
        hdrs = {
            "User-Agent": "CatalystCenter/1.0 CFNetwork/1410.0.3 Darwin/22.6.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, data=body, method="POST", headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                rb = e.read().decode(errors="replace")
            except Exception:
                rb = ""
            return e.code, rb
        except Exception:
            return None, None

    base = f"https://{host}:{port}"

    status, body = _get("/dna/intent/api/v1/network-device")
    if status is not None:
        has_data = bool(
            re.search(r'"managementIpAddress"|"hostname"|"platformId"|"softwareVersion"',
                      body, re.I)
        )
        if status < 300 and has_data:
            sev = "CRITICAL"
        elif status < 300:
            sev = "HIGH"
        elif status in (400, 422) and re.search(r'"error"|"message"|"detail"', body, re.I):
            sev = "MEDIUM"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "CATALYST_CENTER_NETWORK_DEVICE_INVENTORY",
            "detail": (
                f"GET {base}/dna/intent/api/v1/network-device returned {status}; "
                f"has_device_data={has_data}; Catalyst Center Intent API device "
                f"inventory endpoint; a 200 with data discloses the complete "
                f"list of managed network devices including management IPs, "
                f"platform IDs, software versions, serial numbers, MAC addresses, "
                f"and reachability status for every switch, router, and wireless "
                f"controller under management; the iOS Catalyst Center mobile app "
                f"serializes this response via a Codable struct where "
                f"managementIpAddress, hostname, and softwareVersion map directly "
                f"to camelCase JSON keys decoded with JSONDecoder defaults; "
                f"body excerpt: {body[:300]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _get("/dna/intent/api/v1/site")
    if status is not None:
        has_sites = bool(
            re.search(r'"siteType"|"additionalInfo"|"siteHierarchy"|"name"', body, re.I)
        )
        if status < 300 and has_sites:
            sev = "HIGH"
        elif status < 300:
            sev = "MEDIUM"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "CATALYST_CENTER_SITE_HIERARCHY",
            "detail": (
                f"GET {base}/dna/intent/api/v1/site returned {status}; "
                f"has_site_data={has_sites}; Catalyst Center site hierarchy "
                f"endpoint exposes the physical/logical topology of the managed "
                f"network organized into Area/Building/Floor objects; each site "
                f"object carries GPS coordinates, address, and the full "
                f"siteHierarchyId chain; the mobile app Site struct conforms to "
                f"Codable with siteType and additionalInfo as CodingKey-mapped "
                f"fields; disclosure enables precise physical-location mapping "
                f"of all network infrastructure; body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _post("/dna/system/api/v1/auth/token", body=b"{}")
    if status is not None:
        token_issued = bool(re.search(r'"Token"\s*:\s*"[A-Za-z0-9._-]{20,}"', body))
        if token_issued:
            sev = "CRITICAL"
        elif status in (200, 201) and re.search(r'"[Tt]oken"', body):
            sev = "CRITICAL"
        elif status in (400, 401) and re.search(r'"error"|"message"', body, re.I):
            sev = "MEDIUM"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "CATALYST_CENTER_GUEST_TOKEN_ISSUANCE",
            "detail": (
                f"POST {base}/dna/system/api/v1/auth/token with empty JSON body "
                f"returned {status}; token_issued={token_issued}; Catalyst Center "
                f"auth token endpoint accepts POST with Basic Authorization header "
                f"and returns a JWT in {{\"Token\": \"<jwt>\"}}; probing with an "
                f"empty body tests whether the instance issues a guest token or "
                f"discloses error details that reveal the expected credential "
                f"format; a token_issued=True result means a no-credential token "
                f"was obtained granting full Intent API access; the Swift mobile "
                f"app bridges Result<Token, NetworkError> using flatMap to "
                f"propagate the token into subsequent URLSession dataTask calls; "
                f"body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _get("/dna/intent/api/v1/topology/l2/VLAN")
    if status is not None:
        has_vlan = bool(
            re.search(r'"vlanId"|"nodes"|"links"|"deviceType"', body, re.I)
        )
        if status < 300 and has_vlan:
            sev = "HIGH"
        elif status < 300:
            sev = "MEDIUM"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "CATALYST_CENTER_L2_VLAN_TOPOLOGY",
            "detail": (
                f"GET {base}/dna/intent/api/v1/topology/l2/VLAN returned {status}; "
                f"has_vlan_data={has_vlan}; Layer-2 VLAN topology endpoint returns "
                f"a graph of nodes (devices) and links (physical connections) for "
                f"the named VLAN; response includes device roles, IP addresses, "
                f"link types, and VLAN membership; the mobile app maps this to "
                f"a TopologyResponse Codable struct where nodes[] and links[] "
                f"are decoded via JSONDecoder with keyDecodingStrategy "
                f".convertFromSnakeCase; disclosure enables L2 segmentation "
                f"mapping and VLAN surface identification; body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _get("/dna/intent/api/v1/topology/physical-topology")
    if status is not None:
        has_topo = bool(
            re.search(r'"nodes"\s*:|"links"\s*:|"id"\s*:|"role"\s*:', body, re.I)
        )
        if status < 300 and has_topo:
            sev = "CRITICAL"
        elif status < 300:
            sev = "HIGH"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "CATALYST_CENTER_PHYSICAL_TOPOLOGY",
            "detail": (
                f"GET {base}/dna/intent/api/v1/topology/physical-topology "
                f"returned {status}; has_topology_data={has_topo}; physical "
                f"topology endpoint returns the full network graph as a JSON "
                f"document with nodes[] (devices: id, label, role, IP, platform) "
                f"and links[] (physical interconnects: source, target, linkStatus, "
                f"startPortName, endPortName); this is the highest-value topology "
                f"endpoint mapping the entire managed campus or data center fabric; "
                f"the Codable PhysicalTopology struct in the mobile app decodes "
                f"nodes and links arrays whose per-element fields (id, x, y, role, "
                f"deviceType) correspond exactly to the JSON keys returned; "
                f"unauthenticated read is a full network cartography disclosure; "
                f"body excerpt: {body[:300]!r}"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_cisco_umbrella_api_exposure(host: str, port: int = 443,
                                      timeout: float = 10.0) -> list:
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str, extra_headers: dict = None) -> tuple:
        url = f"https://{host}:{port}{path}"
        hdrs = {
            "User-Agent": "CiscoUmbrella/5.0 CFNetwork/1410.0.3 Darwin/22.6.0",
            "Accept": "application/json",
        }
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return None, None

    def _post(path: str, body: bytes = b"", extra_headers: dict = None) -> tuple:
        url = f"https://{host}:{port}{path}"
        hdrs = {
            "User-Agent": "CiscoUmbrella/5.0 CFNetwork/1410.0.3 Darwin/22.6.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, data=body, method="POST", headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            try:
                rb = e.read().decode(errors="replace")
            except Exception:
                rb = ""
            return e.code, rb
        except Exception:
            return None, None

    base = f"https://{host}:{port}"

    status, body = _get("/v2/organizations")
    if status is not None:
        has_org = bool(
            re.search(r'"organizationId"|"orgId"|"name"|"customerId"', body, re.I)
        )
        if status < 300 and has_org:
            sev = "CRITICAL"
        elif status < 300:
            sev = "HIGH"
        elif status in (400, 401, 403) and re.search(r'"error"|"message"', body, re.I):
            sev = "MEDIUM"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "UMBRELLA_ORGANIZATIONS_ENDPOINT",
            "detail": (
                f"GET {base}/v2/organizations returned {status}; "
                f"has_org_data={has_org}; Cisco Umbrella Management API "
                f"organizations endpoint; a successful unauthenticated response "
                f"discloses customer organization IDs, names, and account metadata "
                f"for the Cisco Secure Internet Gateway tenant; the Umbrella iOS "
                f"app maps this via an Organization Codable struct where "
                f"organizationId and name are direct JSON key mappings; "
                f"organization ID is required for all subsequent scoped API "
                f"calls targeting the specific tenant; body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _get("/v2/networks")
    if status is not None:
        has_net = bool(
            re.search(r'"networkId"|"ipAddress"|"label"|"createdAt"', body, re.I)
        )
        if status < 300 and has_net:
            sev = "HIGH"
        elif status < 300:
            sev = "MEDIUM"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "UMBRELLA_NETWORKS_ENDPOINT",
            "detail": (
                f"GET {base}/v2/networks returned {status}; "
                f"has_network_data={has_net}; Umbrella networks endpoint returns "
                f"the list of registered network objects (IP ranges/CIDRs) whose "
                f"DNS traffic is routed through Cisco Umbrella resolvers; each "
                f"network object carries an IP address, label, and creation "
                f"timestamp; disclosure reveals the client registered IP space "
                f"and enables correlation with BGP prefix data to identify the "
                f"organization; body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _get("/v2/roamingcomputers")
    if status is not None:
        has_rc = bool(
            re.search(r'"deviceId"|"computerId"|"hostname"|"originId"|"status"',
                      body, re.I)
        )
        if status < 300 and has_rc:
            sev = "CRITICAL"
        elif status < 300:
            sev = "HIGH"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "UMBRELLA_ROAMING_COMPUTERS_INVENTORY",
            "detail": (
                f"GET {base}/v2/roamingcomputers returned {status}; "
                f"has_roaming_client_data={has_rc}; Umbrella roaming computers "
                f"endpoint lists all endpoints with the Cisco Secure Client "
                f"Umbrella roaming module installed; each record exposes device "
                f"hostname, internal IP, user identity, OS version, client "
                f"version, and last-seen timestamp; this is a full managed-endpoint "
                f"inventory covering all corporate laptops and workstations "
                f"enrolled in the SIG policy; the RoamingComputer Codable struct "
                f"decodes originId, status, and lastSync as top-level JSON keys; "
                f"body excerpt: {body[:300]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _get("/admin/api/v1/policies")
    if status is not None:
        has_policy = bool(
            re.search(r'"policyId"|"policy"|"categoryId"|"block"|"allow"',
                      body, re.I)
        )
        if status < 300 and has_policy:
            sev = "HIGH"
        elif status < 300:
            sev = "MEDIUM"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "UMBRELLA_DNS_POLICIES_EXPOSURE",
            "detail": (
                f"GET {base}/admin/api/v1/policies returned {status}; "
                f"has_policy_data={has_policy}; Umbrella admin API policy "
                f"endpoint exposes the DNS filtering ruleset including blocked "
                f"and allowed category IDs, destination lists, security settings, "
                f"and policy priority ordering; DNS policy disclosure reveals "
                f"which threat categories are not blocked, enabling selection of "
                f"domains outside the policy scope; protocol conformance in the "
                f"mobile app gates admin API access via a PolicyAccessible "
                f"protocol check against the decoded user role field; "
                f"body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _get("/admin/api/v1/reports/activity")
    if status is not None:
        has_log = bool(
            re.search(r'"domain"|"timestamp"|"verdict"|"identity"|"categories"',
                      body, re.I)
        )
        if status < 300 and has_log:
            sev = "CRITICAL"
        elif status < 300:
            sev = "HIGH"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "UMBRELLA_DNS_ACTIVITY_LOG_EXPOSURE",
            "detail": (
                f"GET {base}/admin/api/v1/reports/activity returned {status}; "
                f"has_log_data={has_log}; Umbrella activity report endpoint "
                f"returns DNS query logs including queried domain, timestamp, "
                f"verdict (allowed/blocked), identity (user or device), public "
                f"IP, and category classification; DNS query logs expose internal "
                f"tooling, SaaS usage patterns, development infrastructure, and "
                f"sensitive internal hostnames queried by enrolled endpoints; "
                f"the ActivityRecord Codable struct maps domain, verdict, and "
                f"identity fields using snake_case-to-camelCase JSONDecoder "
                f"keyDecodingStrategy; body excerpt: {body[:300]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _post("/api/v2/auth", body=b'{"key":"AAAA","secret":"BBBB"}')
    if status is not None:
        error_detail = bool(
            re.search(r'"error"|"message"|"code"|"description"|"expected"',
                      body, re.I)
        )
        api_key_hint = bool(
            re.search(r'key|secret|token|bearer|format|invalid|uuid|length',
                      body, re.I)
        )
        if status in (200, 201):
            sev = "CRITICAL"
        elif error_detail and api_key_hint:
            sev = "MEDIUM"
        elif error_detail:
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "UMBRELLA_AUTH_FORMAT_FINGERPRINT",
            "detail": (
                f"POST {base}/api/v2/auth with malformed credential body "
                f"returned {status}; error_detail_present={error_detail}; "
                f"api_key_format_hint={api_key_hint}; Umbrella API v2 auth "
                f"endpoint accepts an API key/secret pair and returns a bearer "
                f"token; probing with a structurally valid but invalid credential "
                f"payload extracts error messages that reveal expected key format "
                f"(UUID structure, length constraints, or encoding requirements); "
                f"format hints narrow the search space for credential attacks; "
                f"the Result<AuthToken, APIError> type in the Swift client "
                f"propagates these errors through flatMap chaining producing "
                f"predictable error JSON shapes; body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    status, body = _get("/api/v2/admin/users")
    if status is not None:
        has_users = bool(
            re.search(r'"email"|"username"|"role"|"userId"|"adminId"', body, re.I)
        )
        if status < 300 and has_users:
            sev = "CRITICAL"
        elif status < 300:
            sev = "HIGH"
        elif status in (400, 422) and re.search(r'"error"|"message"', body, re.I):
            sev = "MEDIUM"
        elif status in (401, 403):
            sev = "LOW"
        else:
            sev = "INFO"
        findings.append({
            "severity": sev,
            "title": "UMBRELLA_ADMIN_USER_ENUMERATION",
            "detail": (
                f"GET {base}/api/v2/admin/users returned {status}; "
                f"has_user_data={has_users}; Umbrella admin users endpoint "
                f"returns the list of administrator accounts for the organization "
                f"including email addresses, roles (admin/read-only/super-admin), "
                f"and account status; admin email enumeration enables targeted "
                f"phishing, credential stuffing against the Umbrella dashboard, "
                f"and identification of break-glass accounts; the AdminUser "
                f"Codable struct decodes email and role as required (non-Optional) "
                f"fields meaning both are always present in a successful response; "
                f"body excerpt: {body[:200]!r}"
            ),
            "host": host,
            "port": port,
        })

    return findings
