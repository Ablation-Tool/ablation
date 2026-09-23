"""HyperFlex Connect REST API, iSCSI/NFS, UCSM, APIC, stCtlVM, and cluster enumeration."""

import socket
import ssl
import struct
import subprocess
import json
import urllib.request
import urllib.error
import urllib.parse
import base64
from typing import Optional

HX_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "C1sco12345"),
    ("admin", "Cisco123"),
    ("admin", "cisco"),
    ("admin", "HXpassword1!"),
    ("hxadmin", "C1sco12345"),
    ("admin", "Password1!"),
    ("root", "password1!"),
    ("root", "Cisco123"),
]

HX_CONNECT_PORT = 443
HX_REST_BASE = "/rest/v1"

# Unauthenticated endpoints (HX Connect <4.5 exposes cluster info without token)
HX_UNAUTH_PATHS = [
    "/rest/v1/cluster",
    "/rest/v1/version",
    "/rest/v1/about",
]

# Authenticated endpoints (require hx-auth-token)
HX_AUTH_PATHS = {
    "nodes": "/rest/v1/nodes",
    "datastores": "/rest/v1/datastores",
    "alarms": "/rest/v1/alarms",
    "snapshots": "/rest/v1/clusters/local/snapshots",
    "disks": "/rest/v1/storage/disks",
    "volumes": "/rest/v1/volumes",
    # Intersight claim code — high-value: lets attacker claim device in their org
    "intersight_conn": "/rest/v1/intersight/connection",
    "network": "/rest/v1/network",
    "security": "/rest/v1/cluster/security",
}

ISCSI_PORT = 3260
NFS_PORT = 2049

# UCSM XML API credentials to try
UCSM_CREDS = [
    ("admin", "admin"),
    ("admin", "cisco"),
    ("admin", "C1sco12345"),
    ("admin", "password"),
]

# APIC REST API credentials to try
APIC_CREDS = [
    ("admin", "admin"),
    ("admin", "cisco"),
    ("admin", "Cisco123"),
    ("admin", "password"),
]


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _hx_request(host: str, path: str, method: str = "GET",
                 token: Optional[str] = None, body: Optional[dict] = None,
                 timeout: int = 8) -> Optional[dict]:
    url = f"https://{host}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("hx-auth-token", token)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"__http_error": e.code, "__reason": str(e.reason)}
    except Exception:
        return None


def _http_raw(host: str, path: str, method: str = "GET",
              port: int = 443, body: Optional[bytes] = None,
              content_type: str = "application/json",
              timeout: int = 8) -> Optional[tuple]:
    """Returns (status_code, body_bytes) or None on connection failure."""
    url = f"https://{host}:{port}{path}"
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", content_type)
    req.add_header("Accept", "*/*")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            return (r.status, r.read())
    except urllib.error.HTTPError as e:
        try:
            return (e.code, e.read())
        except Exception:
            return (e.code, b"")
    except Exception:
        return None


def probe_hx_connect(host: str, timeout: int = 8) -> dict:
    result = {"host": host, "port": HX_CONNECT_PORT, "reachable": False,
              "version": None, "unauth_data": {}, "cred_result": None,
              "auth_data": {}, "intersight_claim_code": None,
              "iscsi_targets": [], "nfs_exports": []}

    # Reachability
    try:
        s = socket.create_connection((host, HX_CONNECT_PORT), timeout=timeout)
        s.close()
        result["reachable"] = True
    except Exception:
        return result

    # Unauthenticated probe
    for path in HX_UNAUTH_PATHS:
        data = _hx_request(host, path, timeout=timeout)
        if data and "__http_error" not in data:
            result["unauth_data"][path] = data
            if "version" in data or "hxVersion" in data:
                result["version"] = data.get("version") or data.get("hxVersion")

    # Credential brute
    token = None
    for user, passwd in HX_DEFAULT_CREDS:
        body = {"username": user, "password": passwd}
        resp = _hx_request(host, "/rest/v1/tokens", method="POST",
                           body=body, timeout=timeout)
        if resp and "token" in resp:
            token = resp["token"]
            result["cred_result"] = {"user": user, "pass": passwd}
            break
        if resp and "__http_error" in resp and resp["__http_error"] == 429:
            break  # rate limited — stop

    # Authenticated enumeration
    if token:
        for key, path in HX_AUTH_PATHS.items():
            data = _hx_request(host, path, token=token, timeout=timeout)
            if data and "__http_error" not in data:
                result["auth_data"][key] = data

        # Extract Intersight claim code (high-value pivot)
        conn = result["auth_data"].get("intersight_conn", {})
        if conn and isinstance(conn, dict):
            result["intersight_claim_code"] = (
                conn.get("claimCode") or conn.get("deviceId")
            )

    # iSCSI SendTargets discovery
    result["iscsi_targets"] = _probe_iscsi(host, timeout)

    # NFS exports
    result["nfs_exports"] = _probe_nfs(host, timeout)

    return result


def _probe_iscsi(host: str, timeout: int = 8) -> list:
    """RFC 7143 iSCSI SendTargets discovery via raw socket."""
    targets = []
    try:
        s = socket.create_connection((host, ISCSI_PORT), timeout=timeout)
        # Minimal iSCSI Login PDU for discovery session
        # BHS: opcode=0x03 (LoginReq), Fbit+Cbit set, version 0x00/0x00
        # Using text params: InitiatorName + SessionType=Discovery
        text_params = (
            b"InitiatorName=iqn.2024-01.com.probe:discovery\x00"
            b"SessionType=Discovery\x00"
            b"HeaderDigest=None\x00"
            b"DataDigest=None\x00"
            b"DefaultTime2Wait=0\x00"
            b"DefaultTime2Retain=0\x00"
            b"IFMarker=No\x00"
            b"OFMarker=No\x00"
        )
        # Pad to 4-byte boundary
        pad_len = (4 - len(text_params) % 4) % 4
        text_params += b"\x00" * pad_len
        data_len = len(text_params)
        # BHS 48 bytes + text data
        bhs = struct.pack(
            ">BBHBBHIIIIIIIII",
            0x43,       # opcode=0x03 LoginReq | F=1 (0x40)
            0x87,       # flags: T=1,C=0, NSG=FullFeature(3), CSG=LoginOp(0) => 0x87
            0,          # rsvd
            0x00,       # MaxVersion
            0x00,       # MinVersion
            data_len >> 16 & 0xFF,  # AHSLength + DataSegmentLength hi
            data_len & 0xFFFF,
            0,          # TotalAHSLength
            0,          # DataSegmentLength (lo 3 bytes in next 3)
            0,          # ITT
            0,          # TSIH (0 for new session)
            0,          # CID << 16 | Reserved
            1,          # CmdSN
            1,          # ExpStatSN
            0,          # Reserved
            0,          # Reserved
        )
        # Simplified — just send something that will get a response or RST
        s.settimeout(timeout)
        s.send(bhs + text_params)
        resp = s.recv(4096)
        s.close()
        if len(resp) >= 4:
            # Any response (even error) confirms port open and iSCSI service
            targets.append({"host": host, "port": ISCSI_PORT,
                            "confirmed": True,
                            "note": "iSCSI service responding"})
    except Exception:
        # Fall back to subprocess iscsiadm if available
        try:
            out = subprocess.check_output(
                ["iscsiadm", "-m", "discovery", "-t", "sendtargets",
                 "-p", f"{host}:{ISCSI_PORT}"],
                timeout=timeout, stderr=subprocess.DEVNULL
            ).decode(errors="replace")
            for line in out.splitlines():
                if "iqn." in line or "eui." in line:
                    targets.append({"target": line.strip()})
        except Exception:
            pass
    return targets


def _probe_nfs(host: str, timeout: int = 8) -> list:
    """NFS export enumeration via showmount."""
    exports = []
    try:
        out = subprocess.check_output(
            ["showmount", "-e", "--no-headers", host],
            timeout=timeout, stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        for line in out.splitlines():
            line = line.strip()
            if line:
                exports.append(line)
    except Exception:
        # Portmapper direct probe
        try:
            s = socket.create_connection((host, 111), timeout=timeout)
            s.close()
            exports.append({"note": "portmapper open — showmount not available"})
        except Exception:
            pass
    return exports


def enumerate_hyperflex_cluster(hosts: list, timeout: int = 8) -> list:
    results = []
    for host in hosts:
        r = probe_hx_connect(host, timeout=timeout)
        results.append(r)
    return results


class HyperFlexEnumerator:
    """Full-surface HyperFlex enumerator: REST API, UCSM XML, APIC, iSCSI,
    NFS, stCtlVM SSH, and VXLAN cluster discovery.

    All probe_* methods return a list of finding dicts with keys:
        severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
        title:    short label
        detail:   evidence string
        host:     target IP/hostname
        port:     relevant port (int)
    """

    def __init__(self, host: str, timeout: int = 8):
        self.host = host
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _tcp_open(self, port: int) -> bool:
        try:
            s = socket.create_connection((self.host, port), timeout=self.timeout)
            s.close()
            return True
        except Exception:
            return False

    def _banner(self, port: int) -> Optional[str]:
        try:
            s = socket.create_connection((self.host, port), timeout=self.timeout)
            s.settimeout(self.timeout)
            data = s.recv(1024)
            s.close()
            return data.decode(errors="replace").strip()
        except Exception:
            return None

    def _finding(self, severity: str, title: str, detail: str,
                 port: int) -> dict:
        return {
            "severity": severity,
            "title": title,
            "detail": detail,
            "host": self.host,
            "port": port,
        }

    # ------------------------------------------------------------------
    # Existing probe surface (wrapped)
    # ------------------------------------------------------------------

    def probe_hx_connect_api(self) -> list:
        """HX Connect REST API: unauth endpoints + default credential brute."""
        findings = []
        r = probe_hx_connect(self.host, timeout=self.timeout)
        if not r["reachable"]:
            return findings

        if r["unauth_data"]:
            paths = list(r["unauth_data"].keys())
            findings.append(self._finding(
                "HIGH",
                "HyperFlex Connect REST API exposes data unauthenticated",
                f"Unauthenticated responses from: {', '.join(paths)}",
                443,
            ))

        if r["cred_result"]:
            u = r["cred_result"]["user"]
            p = r["cred_result"]["pass"]
            findings.append(self._finding(
                "CRITICAL",
                "HyperFlex Connect authenticated with default credentials",
                f"Credentials {u}/{p} accepted at /rest/v1/tokens",
                443,
            ))

        if r["intersight_claim_code"]:
            findings.append(self._finding(
                "CRITICAL",
                "Intersight claim code exposed — device pivot possible",
                f"claimCode/deviceId: {r['intersight_claim_code']}",
                443,
            ))

        if r["iscsi_targets"]:
            findings.append(self._finding(
                "MEDIUM",
                "iSCSI service open on HyperFlex node",
                f"{len(r['iscsi_targets'])} target(s) responding on port 3260",
                3260,
            ))

        if r["nfs_exports"]:
            findings.append(self._finding(
                "MEDIUM",
                "NFS exports visible on HyperFlex node",
                f"showmount: {r['nfs_exports']}",
                2049,
            ))

        return findings

    # ------------------------------------------------------------------
    # New probes
    # ------------------------------------------------------------------

    def probe_ucsm_api(self) -> list:
        """UCSM XML API at /nuova — default credential check.

        Tries admin/admin and admin/cisco (and admin/C1sco12345).
        200 + outCookie in body → CRITICAL.
        200 + error body (API accessible) → MEDIUM with version if present.
        """
        findings = []
        port = 443
        path = "/nuova"

        xml_tmpl = '<aaaLogin inName="{u}" inPassword="{p}"/>'
        tried_any = False

        for user, pwd in UCSM_CREDS:
            body = xml_tmpl.format(u=user, p=pwd).encode()
            resp = _http_raw(
                self.host, path, method="POST", port=port,
                body=body, content_type="application/xml",
                timeout=self.timeout,
            )
            if resp is None:
                continue

            status, raw = resp
            tried_any = True
            text = raw.decode(errors="replace")

            if status == 200:
                if "outCookie=" in text and 'errorCode="' not in text:
                    # Extract cookie snippet for evidence
                    idx = text.find("outCookie=")
                    snippet = text[idx:idx + 60].split()[0] if idx >= 0 else ""
                    findings.append(self._finding(
                        "CRITICAL",
                        "UCSM XML API authenticated with default credentials",
                        f"Credentials {user}/{pwd} accepted at {path}. {snippet}",
                        port,
                    ))
                    break  # stop on first win
                else:
                    # API reachable but auth failed or returned error
                    version = ""
                    if "outVersion=" in text:
                        idx = text.find("outVersion=")
                        version = text[idx:idx + 40].split()[0]
                    if not any(f["title"] == "UCSM XML API accessible" for f in findings):
                        findings.append(self._finding(
                            "MEDIUM",
                            "UCSM XML API accessible",
                            f"Endpoint {path} returned 200 with XML error body. {version}",
                            port,
                        ))
            elif status in (401, 403) and not tried_any:
                findings.append(self._finding(
                    "LOW",
                    "UCSM XML API accessible — authentication required",
                    f"HTTP {status} from {path}",
                    port,
                ))

        return findings

    def probe_apic_api(self, port: int = 443) -> list:
        """APIC REST API at /api/aaaLogin.json — default credential check.

        Tries admin/admin, admin/cisco, admin/password, admin/Cisco123.
        200 + token in response → CRITICAL.
        401 → MEDIUM (API accessible).
        """
        findings = []
        path = "/api/aaaLogin.json"
        found_crit = False

        for user, pwd in APIC_CREDS:
            body = json.dumps({
                "aaUser": {"attributes": {"name": user, "pwd": pwd}}
            }).encode()
            resp = _http_raw(
                self.host, path, method="POST", port=port,
                body=body, content_type="application/json",
                timeout=self.timeout,
            )
            if resp is None:
                continue

            status, raw = resp
            text = raw.decode(errors="replace")

            if status == 200:
                token = ""
                try:
                    data = json.loads(text)
                    imdata = data.get("imdata", [])
                    if imdata:
                        attrs = imdata[0].get("aaaLogin", {}).get("attributes", {})
                        token = attrs.get("token", "")
                except Exception:
                    pass

                if token:
                    findings.append(self._finding(
                        "CRITICAL",
                        "APIC authenticated with default credentials",
                        f"Credentials {user}/{pwd} accepted at {path}. "
                        f"Token prefix: {token[:16]}...",
                        port,
                    ))
                    found_crit = True
                    break
                else:
                    # Unusual: 200 but no token
                    if not any(f["severity"] in ("CRITICAL", "MEDIUM") for f in findings):
                        findings.append(self._finding(
                            "MEDIUM",
                            "APIC API accessible — unexpected 200 without token",
                            f"POST {path} returned 200 with no token for {user}/{pwd}",
                            port,
                        ))

            elif status in (400, 401, 403):
                # API is reachable; record once
                if not any(f["title"] == "APIC API accessible" for f in findings):
                    findings.append(self._finding(
                        "MEDIUM",
                        "APIC API accessible",
                        f"POST {path} returned HTTP {status} — authentication required",
                        port,
                    ))

        return findings

    def probe_iscsi_no_chap(self, port: int = 3260) -> list:
        """iSCSI login attempt with no authentication.

        Constructs a minimal iSCSI Login Request PDU (BHS + text keys).
        Parses the Login Response:
          StatusClass 0x00 (Success) → CRITICAL unauthenticated access.
          StatusClass 0x02 (Initiator error / auth required) → MEDIUM.
        """
        findings = []

        try:
            s = socket.create_connection((self.host, port), timeout=self.timeout)
        except Exception:
            return findings

        try:
            # Text parameters for an unauthenticated Normal session
            text = (
                b"InitiatorName=iqn.2024-01.com.scanner:probe\x00"
                b"SessionType=Normal\x00"
                b"HeaderDigest=None\x00"
                b"DataDigest=None\x00"
                b"MaxConnections=1\x00"
                b"InitialR2T=Yes\x00"
                b"ImmediateData=Yes\x00"
                b"MaxRecvDataSegmentLength=65536\x00"
                b"MaxBurstLength=262144\x00"
                b"FirstBurstLength=65536\x00"
                b"DefaultTime2Wait=2\x00"
                b"DefaultTime2Retain=20\x00"
                b"IFMarker=No\x00"
                b"OFMarker=No\x00"
            )
            # Pad to 4-byte boundary
            pad = (4 - len(text) % 4) % 4
            text += b"\x00" * pad
            dl = len(text)

            # Build 48-byte BHS manually (no struct ambiguity)
            bhs = bytearray(48)
            bhs[0] = 0x43           # Immediate=1 | LoginReq opcode 0x03
            bhs[1] = 0x87           # T=1, C=0, CSG=01 (OpNeg), NSG=11 (FullFeat)
            bhs[2] = 0x00           # MaxVersion
            bhs[3] = 0x00           # MinVersion
            bhs[4] = 0x00           # TotalAHSLength
            bhs[5] = (dl >> 16) & 0xFF  # DataSegmentLength[0]
            bhs[6] = (dl >> 8) & 0xFF   # DataSegmentLength[1]
            bhs[7] = dl & 0xFF          # DataSegmentLength[2]
            # ISID (bytes 8-13): OUI format, first byte 0x40
            bhs[8] = 0x40
            # TSIH (bytes 14-15): 0x0000 — new session
            # ITT (bytes 16-19): 0x00000001
            bhs[19] = 0x01
            # CID (bytes 20-21): 0x0001
            bhs[21] = 0x01
            # CmdSN (bytes 24-27): 0x00000001
            bhs[27] = 0x01
            # ExpStatSN (bytes 28-31): 0x00000000

            s.settimeout(self.timeout)
            s.sendall(bytes(bhs) + text)
            raw = s.recv(4096)

            if len(raw) >= 48:
                opcode = raw[0] & 0x3F
                if opcode == 0x23:  # Login Response
                    status_class = raw[36]
                    status_detail = raw[37]
                    if status_class == 0x00:
                        # Success — target accepted login without auth
                        findings.append(self._finding(
                            "CRITICAL",
                            "iSCSI target accepts unauthenticated connection",
                            f"Login Response StatusClass=0x00 (Success) "
                            f"StatusDetail=0x{status_detail:02x} — CHAP not enforced",
                            port,
                        ))
                    elif status_class == 0x02:
                        findings.append(self._finding(
                            "MEDIUM",
                            "iSCSI target reachable — CHAP authentication required",
                            f"Login Response StatusClass=0x02 StatusDetail=0x{status_detail:02x}",
                            port,
                        ))
                    else:
                        findings.append(self._finding(
                            "LOW",
                            "iSCSI login response received",
                            f"Opcode=0x23 StatusClass=0x{status_class:02x} "
                            f"StatusDetail=0x{status_detail:02x}",
                            port,
                        ))
                else:
                    # Got some response — port confirmed open
                    findings.append(self._finding(
                        "LOW",
                        "iSCSI port open — unexpected response opcode",
                        f"Received opcode 0x{opcode:02x} (expected 0x23 LoginResponse)",
                        port,
                    ))
            elif len(raw) > 0:
                findings.append(self._finding(
                    "LOW",
                    "iSCSI port open — short response",
                    f"Received {len(raw)} bytes, too short for BHS parse",
                    port,
                ))

        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

        return findings

    def probe_stctlvm_ssh(self) -> list:
        """stCtlVM (storage controller VM) SSH banner probe on port 22.

        HyperFlex storage controller VMs run SpringPath/stCtlVM software.
        Banner keywords: HyperFlex, SpringPath, stCtlVM.
        Any SSH banner → LOW (version disclosure at minimum).
        """
        findings = []
        port = 22

        banner = self._banner(port)
        if banner is None:
            return findings

        keywords = ("HyperFlex", "SpringPath", "stCtlVM", "hyperflex", "springpath")
        matched = [k for k in keywords if k.lower() in banner.lower()]

        if matched:
            findings.append(self._finding(
                "HIGH",
                "HyperFlex storage controller VM SSH exposed",
                f"SSH banner identifies stCtlVM: '{banner[:200]}' "
                f"(matched: {', '.join(matched)})",
                port,
            ))
        elif banner.startswith("SSH-"):
            findings.append(self._finding(
                "LOW",
                "SSH service open on HyperFlex node",
                f"Banner: '{banner[:200]}'",
                port,
            ))

        return findings

    def probe_cluster_discovery(self) -> list:
        """VXLAN overlay port (UDP/4789) and unauthenticated cluster-info endpoint.

        VXLAN: HyperFlex uses UDP/4789 for inter-node overlay traffic (HXDP
        distributed file system, IOVisor striping). An uninitiated node that
        responds to VXLAN probes may be in cluster-formation state with no
        auth enforced.

        Cluster-info: /api/v1/cluster/info without auth token. If 200 → HIGH.
        """
        findings = []

        # -- VXLAN UDP/4789 probe --
        vxlan_port = 4789
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            # Minimal VXLAN packet with VNI=0 to elicit any ICMP response
            vxlan_hdr = b"\x08\x00\x00\x00\x00\x00\x00\x00"  # flags=0x08, VNI=0
            # Inner Ethernet frame (dest/src MAC zeros, type=0x0800, no payload)
            inner_eth = b"\xff\xff\xff\xff\xff\xff" + b"\x00" * 6 + b"\x08\x00"
            probe_pkt = vxlan_hdr + inner_eth
            sock.sendto(probe_pkt, (self.host, vxlan_port))
            # Try to get ICMP port-unreachable or any UDP response
            try:
                data, _ = sock.recvfrom(512)
                # Any UDP response means VXLAN port is actively receiving
                findings.append(self._finding(
                    "MEDIUM",
                    "VXLAN port UDP/4789 responds — possible HyperFlex overlay node",
                    f"Received {len(data)} bytes in response to VXLAN probe",
                    vxlan_port,
                ))
            except socket.timeout:
                # No response — open|filtered; still worth noting if other HX signals present
                pass
            sock.close()
        except Exception:
            pass

        # -- Unauthenticated cluster info endpoint --
        for path in ("/api/v1/cluster/info", "/rest/v1/cluster", "/rest/v1/about"):
            resp = _http_raw(
                self.host, path, method="GET", port=443,
                timeout=self.timeout,
            )
            if resp is None:
                continue
            status, raw = resp
            if status == 200 and raw:
                try:
                    payload = json.loads(raw)
                    snippet = str(payload)[:200]
                except Exception:
                    snippet = raw[:200].decode(errors="replace")
                findings.append(self._finding(
                    "HIGH",
                    "HyperFlex cluster info exposed unauthenticated",
                    f"GET {path} returned 200 without auth token. Data: {snippet}",
                    443,
                ))
                break  # one finding is enough

        return findings

    # ------------------------------------------------------------------
    # Full enumeration
    # ------------------------------------------------------------------

    def enumerate_all(self) -> list:
        """Run all probes and return a deduplicated list of findings."""
        all_findings = []

        for probe_fn in (
            self.probe_hx_connect_api,
            self.probe_ucsm_api,
            self.probe_apic_api,
            self.probe_iscsi_no_chap,
            self.probe_stctlvm_ssh,
            self.probe_cluster_discovery,
        ):
            try:
                results = probe_fn()
                all_findings.extend(results)
            except Exception:
                pass

        return all_findings


# ---------------------------------------------------------------------------
# Standalone probes — HyperFlex coreapi, Intersight, UCS Manager XML API,
# HyperFlex storage (Nutanix/Prism-style endpoints)
# ---------------------------------------------------------------------------

def probe_hyperflex_api(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe HyperFlex coreapi REST endpoints for unauthenticated access and auth bypass."""
    findings: list = []

    def _finding(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    # GET /coreapi/v1/clusters — unauth cluster list = CRITICAL
    resp = _http_raw(host, "/coreapi/v1/clusters", method="GET", port=port, timeout=int(timeout))
    cluster_id = None
    if resp is not None:
        status, raw = resp
        if status == 200 and raw:
            try:
                payload = json.loads(raw)
                snippet = str(payload)[:200]
                # Extract a cluster ID for the health sub-probe
                if isinstance(payload, list) and payload:
                    first = payload[0]
                    cluster_id = (first.get("uuid") or first.get("id")
                                  or first.get("clusterUuid"))
                elif isinstance(payload, dict):
                    cluster_id = (payload.get("uuid") or payload.get("id")
                                  or payload.get("clusterUuid"))
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(
                "CRITICAL",
                "HYPERFLEX_CLUSTER_API_UNAUTH",
                f"GET /coreapi/v1/clusters returned 200 without auth. Data: {snippet}",
            ))

    # GET /coreapi/v1/clusters/{id}/health — HIGH
    health_paths = ([f"/coreapi/v1/clusters/{cluster_id}/health"] if cluster_id
                    else ["/coreapi/v1/clusters/local/health"])
    for hp in health_paths:
        hr = _http_raw(host, hp, method="GET", port=port, timeout=int(timeout))
        if hr is not None:
            hs, hraw = hr
            if hs == 200 and hraw:
                try:
                    hsnippet = str(json.loads(hraw))[:200]
                except Exception:
                    hsnippet = hraw[:200].decode(errors="replace")
                findings.append(_finding(
                    "HIGH",
                    "HYPERFLEX_HEALTH_UNAUTH",
                    f"GET {hp} returned 200 without auth. Data: {hsnippet}",
                ))
                break

    # POST /aaa/v1/auth with empty credentials — token returned = CRITICAL
    empty_body = json.dumps({"username": "", "password": ""}).encode()
    ar = _http_raw(host, "/aaa/v1/auth", method="POST", port=port,
                   body=empty_body, timeout=int(timeout))
    if ar is not None:
        as_, araw = ar
        if as_ == 200 and araw:
            try:
                apay = json.loads(araw)
                token = (apay.get("token") or apay.get("access_token")
                         or apay.get("hx-auth-token") or apay.get("sessionToken"))
                if token:
                    findings.append(_finding(
                        "CRITICAL",
                        "HYPERFLEX_AUTH_BYPASS",
                        f"POST /aaa/v1/auth with empty credentials returned a token."
                        f" Token prefix: {str(token)[:40]}",
                    ))
            except Exception:
                pass

    # GET /api/v1/dataprotectionpeer — HIGH
    rr = _http_raw(host, "/api/v1/dataprotectionpeer", method="GET", port=port,
                   timeout=int(timeout))
    if rr is not None:
        rs, rraw = rr
        if rs == 200 and rraw:
            try:
                rsnippet = str(json.loads(rraw))[:200]
            except Exception:
                rsnippet = rraw[:200].decode(errors="replace")
            findings.append(_finding(
                "HIGH",
                "HYPERFLEX_REPLICATION_UNAUTH",
                f"GET /api/v1/dataprotectionpeer returned 200 without auth."
                f" Data: {rsnippet}",
            ))

    return findings


def probe_intersight_api(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe Intersight on-prem API endpoints for unauthenticated access."""
    findings: list = []

    def _finding(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    checks = [
        ("GET",  "/api/v1/compute/PhysicalSummaries", "CRITICAL",
         "INTERSIGHT_COMPUTE_UNAUTH",
         "GET /api/v1/compute/PhysicalSummaries returned 200 without auth."),
        ("GET",  "/api/v1/server/Profiles",           "HIGH",
         "INTERSIGHT_PROFILES_UNAUTH",
         "GET /api/v1/server/Profiles returned 200 without auth."),
        ("GET",  "/api/v1/hyperflex/Clusters",        "CRITICAL",
         "INTERSIGHT_HX_CLUSTERS_UNAUTH",
         "GET /api/v1/hyperflex/Clusters returned 200 without auth."),
        ("GET",  "/api/v1/iam/Users",                 "CRITICAL",
         "INTERSIGHT_USER_LIST_UNAUTH",
         "GET /api/v1/iam/Users returned 200 without auth."),
    ]

    for method, path, severity, title, base_detail in checks:
        resp = _http_raw(host, path, method=method, port=port, timeout=int(timeout))
        if resp is None:
            continue
        status, raw = resp
        if status == 200 and raw:
            try:
                snippet = str(json.loads(raw))[:200]
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(severity, title, f"{base_detail} Data: {snippet}"))

    return findings


def probe_ucs_manager_api(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe Cisco UCS Manager XML API for null/default authentication and info leakage."""
    findings: list = []

    def _finding(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    # POST /nuova — aaaLogin with empty password
    login_xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<aaaLogin inName="admin" inPassword=""></aaaLogin>'
    )
    lr = _http_raw(host, "/nuova", method="POST", port=port, body=login_xml,
                   content_type="text/xml", timeout=int(timeout))
    cookie = None
    if lr is not None:
        ls, lraw = lr
        if ls == 200 and lraw:
            body_str = lraw.decode(errors="replace")
            # Successful login returns outCookie attribute
            if "outCookie" in body_str and 'errorCode="' not in body_str:
                # Extract cookie value for chained probe
                import re as _re
                m = _re.search(r'outCookie="([^"]+)"', body_str)
                cookie = m.group(1) if m else "present"
                findings.append(_finding(
                    "CRITICAL",
                    "UCS_MANAGER_NULL_AUTH",
                    f"POST /nuova aaaLogin with empty password succeeded."
                    f" Cookie prefix: {cookie[:40]}",
                ))

    # GET /api/json/mo/sys.json — system info without auth
    jr = _http_raw(host, "/api/json/mo/sys.json", method="GET", port=port,
                   timeout=int(timeout))
    if jr is not None:
        js, jraw = jr
        if js == 200 and jraw:
            try:
                jsnippet = str(json.loads(jraw))[:200]
            except Exception:
                jsnippet = jraw[:200].decode(errors="replace")
            findings.append(_finding(
                "HIGH",
                "UCS_SYSTEM_INFO_UNAUTH",
                f"GET /api/json/mo/sys.json returned 200 without auth."
                f" Data: {jsnippet}",
            ))

    # POST /nuova — configResolveClass lsServer (service profiles)
    cookie_val = cookie if (cookie and cookie != "present") else ""
    profiles_xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<configResolveClass cookie="' + cookie_val.encode() + b'"'
        b' classId="lsServer" inHierarchical="false"></configResolveClass>'
    )
    pr = _http_raw(host, "/nuova", method="POST", port=port, body=profiles_xml,
                   content_type="text/xml", timeout=int(timeout))
    if pr is not None:
        ps, praw = pr
        if ps == 200 and praw:
            body_str = praw.decode(errors="replace")
            if "lsServer" in body_str and "outConfigs" in body_str:
                findings.append(_finding(
                    "CRITICAL",
                    "UCS_SERVICE_PROFILES_EXPOSED",
                    f"POST /nuova configResolveClass lsServer returned service profile data."
                    f" Snippet: {body_str[:200]}",
                ))

    return findings


def probe_hyperflex_storage(host: str, port: int = 9440, timeout: float = 5.0) -> list:
    """Probe HyperFlex / Nutanix Prism-style storage API endpoints for unauthenticated access."""
    findings: list = []

    def _finding(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    checks = [
        ("GET",  "/PrismGateway/services/rest/v2.0/clusters", "CRITICAL",
         "PRISM_API_UNAUTH",
         "GET /PrismGateway/services/rest/v2.0/clusters returned 200 without auth."),
        ("GET",  "/api/nutanix/v3/clusters/list",             "HIGH",
         "NUTANIX_V3_API_UNAUTH",
         "GET /api/nutanix/v3/clusters/list returned 200 without auth."),
        ("GET",  "/PrismGateway/services/rest/v2.0/vms",      "CRITICAL",
         "VM_LIST_UNAUTH",
         "GET /PrismGateway/services/rest/v2.0/vms returned 200 without auth."),
    ]

    for method, path, severity, title, base_detail in checks:
        resp = _http_raw(host, path, method=method, port=port, timeout=int(timeout))
        if resp is None:
            continue
        status, raw = resp
        if status == 200 and raw:
            try:
                snippet = str(json.loads(raw))[:200]
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(severity, title, f"{base_detail} Data: {snippet}"))

    return findings


def probe_hyperflex_dp(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe HyperFlex data protection API endpoints for unauthenticated access.

    HyperFlex DP APIs expose snapshot schedules, replication pairs, and protection
    group membership -- revealing backup topology and recovery-point windows an attacker
    can use to plan ransomware timing or lateral movement via cloned LUNs.
    StatefulSet / PersistentVolume-backed workloads with CSI-provisioned storage are
    particularly exposed: unauth snapshot enumeration maps directly to data-at-rest scope
    (Kubernetes in Action 2e, ch.10 -- PV reclaim policies, dynamic provisioning).
    """
    findings: list = []

    def _finding(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    # HYPERFLEX_DP_API_UNAUTH -- try both known DP root paths
    for dp_root in ("/api/v1/dp/dataprotection", "/coreapi/v1/dataprotection"):
        resp = _http_raw(host, dp_root, method="GET", port=port, timeout=int(timeout))
        if resp is None:
            continue
        status, raw = resp
        if status == 200 and raw:
            try:
                snippet = str(json.loads(raw))[:200]
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(
                "CRITICAL",
                "HYPERFLEX_DP_API_UNAUTH",
                f"GET {dp_root} returned data protection API response without auth."
                f" Data: {snippet}",
            ))
            break  # one hit is sufficient; avoid duplicate findings

    # HYPERFLEX_SNAPSHOTS_UNAUTH
    resp = _http_raw(host, "/api/v1/dp/snapshots", method="GET", port=port, timeout=int(timeout))
    if resp is not None:
        status, raw = resp
        if status == 200 and raw:
            try:
                snippet = str(json.loads(raw))[:200]
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(
                "CRITICAL",
                "HYPERFLEX_SNAPSHOTS_UNAUTH",
                f"GET /api/v1/dp/snapshots returned snapshot list without auth."
                f" Data: {snippet}",
            ))

    # HYPERFLEX_REPLICATION_UNAUTH
    resp = _http_raw(host, "/api/v1/dp/replications", method="GET", port=port, timeout=int(timeout))
    if resp is not None:
        status, raw = resp
        if status == 200 and raw:
            try:
                snippet = str(json.loads(raw))[:200]
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(
                "HIGH",
                "HYPERFLEX_REPLICATION_UNAUTH",
                f"GET /api/v1/dp/replications returned replication pair data without auth."
                f" Data: {snippet}",
            ))

    # HYPERFLEX_PROTECTION_GROUPS_UNAUTH
    resp = _http_raw(host, "/api/v1/dp/protectiongroups", method="GET", port=port, timeout=int(timeout))
    if resp is not None:
        status, raw = resp
        if status == 200 and raw:
            try:
                snippet = str(json.loads(raw))[:200]
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(
                "HIGH",
                "HYPERFLEX_PROTECTION_GROUPS_UNAUTH",
                f"GET /api/v1/dp/protectiongroups returned protection group list without auth."
                f" Data: {snippet}",
            ))

    return findings


def probe_hyperflex_stfs(host: str, port: int = 8444, timeout: float = 5.0) -> list:
    """Probe HyperFlex STFS (HX native filesystem) and Prism-compatible storage endpoints.

    STFS exposes the raw HyperFlex filesystem tree over REST -- unauth access maps directly
    to all VM disk files, datastores, and their backing block layout.  The Prism-compatible
    path on port 9440 adds a cross-platform enumeration surface covering storage containers
    (equivalent to Kubernetes StorageClass + dynamic provisioner config) that reveal pool
    capacity, replication factors, and compression/dedup policy -- all inputs an attacker
    needs to scope data exfiltration or deliberate saturation of a thin-provisioned pool
    (Kubernetes in Action 2e, ch.10 -- storage classes, dynamic provisioning, PV capacity).
    """
    findings: list = []

    def _finding(severity: str, title: str, detail: str, probe_port: int = port) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": probe_port}

    # STFS endpoints on the primary STFS port
    stfs_checks = [
        ("/stfs/api/v1/tree",      "CRITICAL", "HYPERFLEX_STFS_TREE_UNAUTH",
         "GET /stfs/api/v1/tree returned filesystem tree listing without auth."),
        ("/stfs/api/v1/vm",        "CRITICAL", "HYPERFLEX_VM_FILES_UNAUTH",
         "GET /stfs/api/v1/vm returned VM file listing without auth."),
        ("/stfs/api/v1/datastore", "HIGH",     "HYPERFLEX_DATASTORE_UNAUTH",
         "GET /stfs/api/v1/datastore returned datastore enumeration without auth."),
    ]

    for path, severity, title, base_detail in stfs_checks:
        resp = _http_raw(host, path, method="GET", port=port, timeout=int(timeout))
        if resp is None:
            continue
        status, raw = resp
        if status == 200 and raw:
            try:
                snippet = str(json.loads(raw))[:200]
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(severity, title, f"{base_detail} Data: {snippet}", port))

    # Prism-compatible storage containers on port 9440
    prism_port = 9440
    resp = _http_raw(host, "/api/nutanix/v2.0/storage_containers", method="GET",
                     port=prism_port, timeout=int(timeout))
    if resp is not None:
        status, raw = resp
        if status == 200 and raw:
            try:
                data = json.loads(raw)
                snippet = str(data)[:200]
                is_json = True
            except Exception:
                snippet = raw[:200].decode(errors="replace")
                is_json = False
            if is_json:
                findings.append(_finding(
                    "CRITICAL",
                    "PRISM_STORAGE_CONTAINERS_UNAUTH",
                    f"GET /api/nutanix/v2.0/storage_containers on port {prism_port}"
                    f" returned storage container data without auth. Data: {snippet}",
                    prism_port,
                ))

    return findings


def probe_hyperflex_hx_connect(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe HX Connect REST API for unauthenticated management surface exposure.

    HX Connect is the primary web UI and REST API gateway for Cisco HyperFlex cluster
    management.  The /rest/clusters endpoint exposes full HCI topology including node
    count, storage capacity, and the dataReplFactor that determines data-protection
    posture -- an attacker who reads this knows exactly how many simultaneous node
    failures are needed to cause data loss before the RF rebuild kicks in
    (Hyperconverged Infrastructure Data Centers, Cisco Press, ch.9: Data Protection
    with Replication Factor; ch.10: HX Connect UI, cluster dashboard, System Overview
    tab exposing Data Replication Factor, Total Capacity, Available capacity).
    """
    findings: list = []

    def _finding(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    # 1. HX Connect API liveness probe
    resp = _http_raw(host, "/cgi-bin/help/doNothing.cgi", method="GET",
                     port=port, timeout=int(timeout))
    if resp is not None:
        status, _raw = resp
        if status == 200:
            findings.append(_finding(
                "INFO",
                "HYPERFLEX_HX_CONNECT_ALIVE",
                f"GET /cgi-bin/help/doNothing.cgi returned HTTP {status} --"
                f" HX Connect API surface confirmed alive on {host}:{port}.",
            ))

    # 2. Auth token endpoint reachability
    resp = _http_raw(host, "/rest/auth/tokens", method="GET",
                     port=port, timeout=int(timeout))
    if resp is not None:
        status, _raw = resp
        # 200 = no auth required; 401/405 = endpoint exists, auth enforced
        if status in (200, 401, 405):
            findings.append(_finding(
                "HIGH",
                "HYPERFLEX_AUTH_ENDPOINT",
                f"GET /rest/auth/tokens returned HTTP {status} -- token generation"
                f" surface reachable on {host}:{port}.  Credential brute-force and"
                f" token replay attacks are in scope.",
            ))

    # 3. Cluster list without auth
    resp = _http_raw(host, "/rest/clusters", method="GET",
                     port=port, timeout=int(timeout))
    if resp is not None:
        status, raw = resp
        if status == 200 and raw:
            try:
                data = json.loads(raw)
                snippet = str(data)[:200]
                is_json = True
            except Exception:
                snippet = raw[:200].decode(errors="replace")
                is_json = False
            findings.append(_finding(
                "CRITICAL",
                "HYPERFLEX_CLUSTER_LIST_UNAUTH",
                f"GET /rest/clusters returned HTTP {status} without auth -- HCI cluster"
                f" topology exposed on {host}:{port}.  Data: {snippet}",
            ))

            # 4. Cluster detail keys: capacity + replication factor
            if is_json:
                data_str = str(data)
                if "capacity" in data_str or "dataReplFactor" in data_str:
                    findings.append(_finding(
                        "CRITICAL",
                        "HYPERFLEX_CLUSTER_DETAILS",
                        f"GET /rest/clusters response contains 'capacity' or"
                        f" 'dataReplFactor' -- storage capacity and replication config"
                        f" visible without auth on {host}:{port}.  Data: {snippet}",
                    ))

    return findings


def probe_hyperflex_replication(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe HyperFlex synchronous replication and VM inventory endpoints for unauth exposure.

    HyperFlex supports synchronous replication for disaster recovery between cluster pairs;
    the peer-clusters and schedules endpoints reveal the full DR topology and RPO
    configuration with no auth required.  The /rest/vms endpoint exposes the complete VM
    inventory including powerState -- operational criticality is readable by any network
    peer, and the VM list is the prerequisite input for targeted snapshot manipulation or
    selective replication schedule disruption
    (Hyperconverged Infrastructure Data Centers, Cisco Press, ch.9: synchronous replication
    for backup and disaster recovery, stHypervisorSvc snapshot/replication coordination;
    ch.10: Virtual Machines view in HX Connect -- VM list, cloning, snapshots, and VM
    protection via replication).
    """
    findings: list = []

    def _finding(severity: str, title: str, detail: str) -> dict:
        return {"severity": severity, "title": title, "detail": detail,
                "host": host, "port": port}

    # 1. Replication peer clusters (DR topology)
    resp = _http_raw(host, "/rest/replication/peer-clusters", method="GET",
                     port=port, timeout=int(timeout))
    if resp is not None:
        status, raw = resp
        if status == 200 and raw:
            try:
                snippet = str(json.loads(raw))[:200]
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(
                "HIGH",
                "HYPERFLEX_REPLICATION_PEERS",
                f"GET /rest/replication/peer-clusters returned HTTP {status} without auth"
                f" -- DR topology exposed on {host}:{port}.  Data: {snippet}",
            ))

    # 2. Replication schedules (backup frequency / RPO)
    resp = _http_raw(host, "/rest/replication/schedules", method="GET",
                     port=port, timeout=int(timeout))
    if resp is not None:
        status, raw = resp
        if status == 200 and raw:
            try:
                snippet = str(json.loads(raw))[:200]
            except Exception:
                snippet = raw[:200].decode(errors="replace")
            findings.append(_finding(
                "HIGH",
                "HYPERFLEX_REPLICATION_SCHEDULES",
                f"GET /rest/replication/schedules returned HTTP {status} without auth"
                f" -- backup frequency and RPO configuration visible on {host}:{port}."
                f"  Data: {snippet}",
            ))

    # 3. VM inventory without auth
    resp = _http_raw(host, "/rest/vms", method="GET",
                     port=port, timeout=int(timeout))
    if resp is not None:
        status, raw = resp
        if status == 200 and raw:
            try:
                data = json.loads(raw)
                snippet = str(data)[:200]
                is_json = True
            except Exception:
                snippet = raw[:200].decode(errors="replace")
                is_json = False
            findings.append(_finding(
                "CRITICAL",
                "HYPERFLEX_VM_LIST_UNAUTH",
                f"GET /rest/vms returned HTTP {status} without auth -- virtual machine"
                f" inventory exposed on {host}:{port}.  Data: {snippet}",
            ))

            # 4. Power state enumeration
            if is_json and "powerState" in str(data):
                try:
                    vm_list = data if isinstance(data, list) else data.get("vms", [])
                    running_count = sum(
                        1 for vm in vm_list
                        if isinstance(vm, dict)
                        and vm.get("powerState", "").upper() in (
                            "POWERED_ON", "ON", "RUNNING"
                        )
                    )
                except Exception:
                    running_count = str(data).count("POWERED_ON")
                findings.append(_finding(
                    "HIGH",
                    "VM_POWER_STATE_VISIBLE",
                    f"GET /rest/vms response contains 'powerState' -- {running_count}"
                    f" running VMs enumerated without auth on {host}:{port}.",
                ))

    return findings

    return findings
