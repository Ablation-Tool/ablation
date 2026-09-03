"""
Cisco HyperFlex (HX Data Platform) — RE Module
Firmware corpus: HX-ESXi-7.0U1 through HX-ESXi-8.0U3 (install ISOs + upgrade bundles)
Architecture: Cisco-customized ESXi + stCtlVM (storage controller VM, Debian/Linux)

HyperFlex stack:
  ESXi host:   Cisco custom VIBs (hxdp-*, hx-*, springpath-*) — kernel drivers + agents
  stCtlVM:     Debian Linux VM — HX Data Platform storage stack (C++/Python/Go binaries)
               ports: 443 (HX Connect REST API), 8080 (internal), 9090 (Prometheus), 3260 (iSCSI)
  HX Connect:  HTTPS REST API — cluster management, node enrollment, Intersight claim
  UCSM:        UCS Manager XML API integration (port 443 on UCSM)
  vCenter:     Plugin integration (remote plugin OVA: HTML5-remote-plugin-Appliance-3.0.0-1173.ova)

Extraction method:
  ISO (iso9660) -> VIBs at /packages/*.vib -> .tgz -> payloads
  Upgrade bundles (.zip) -> VIBs directly
  stCtlVM: embedded as OVA or installer package inside VIBs

Default credentials (HX Connect REST API):
  POST /rest/v1/tokens {username, password} -> hx-auth-token
  Brute: admin/admin, admin/C1sco12345, admin/Cisco123, admin/HXpassword1!,
         hxadmin/C1sco12345, admin/Password1!, root/password1!, root/Cisco123

Unauthenticated endpoints (HX Connect <4.5):
  GET /rest/v1/cluster  — cluster UUID, version, node count
  GET /rest/v1/version  — HXDP version string
  GET /rest/v1/about    — platform info

High-value authenticated endpoints:
  GET /rest/v1/nodes                        — node IPs, serial numbers, roles
  GET /rest/v1/intersight/connection        — Intersight claim code (device takeover pivot)
  GET /rest/v1/clusters/local/snapshots     — snapshot inventory
  GET /rest/v1/storage/disks               — disk topology + SN
  GET /rest/v1/cluster/security            — security config

Firmware corpus:
  storfs-packages-6.0.2b-44423.tgz — HXDP core packages (848MB)
  Cisco-HX-Data-Platform-Installer-v6.0.2b-44423-esx.ova — installer appliance (Ubuntu 64-bit, 24.8GB vdisk)
  cisco-hxdc_6.0.2b-44423_amd64.deb — Intersight Device Connector + image signing verifier
  cisco-openssl_1.1.1za_amd64.deb — private EOL OpenSSL fork + CiscoSSH replacement
  hx-iscsi_6.0.2b-44423_amd64.deb — iSCSI service (16MB ELF, not stripped)
  hx-os_6.0.2b-44423_amd64.deb — OS configs (auditd, iptables, syslog-ng)
  zookeeper_3.8.1_amd64.deb — distributed coordinator
  storfs-support-workflows-6.0.2b-44423.tgz — support debs + bootstrap workflow
  hxdp-connector bundle (inner): Go binary (UPX-packed, 25MB unpacked), version 1.0.11-20250305

Key services (from syslog-ng):
  storfs, iscsisvc, scvmclient, hxmanager, cip-monitor, replsvc, smbscvmclient, stmapper, networkMonitor
  hxmanager logs sent over TCP to syslog-ng localhost:514

Port topology (iptables_node_reset.rules):
  8092 — Springpath internal cluster bus (OUTPUT restricted to springpath/www-data)
  2003 — Graphite metrics (OUTPUT restricted to www-data)
  3260 — iSCSI (inbound from ESXi initiators)

Image signing (hxdc_release_img_verify, 32-bit ELF, not stripped):
  Cisco ROMMON code-sign library (cs_rommon_* functions — shared with IOS/NX-OS boot signing)
  RSA PKCS#1 + SHA-512; custom BigNum (RsaLibBigNum*), NOT OpenSSL
  Key storage: /opt/partner/cisco-hxdc/public-key (Cisco TLV format, multi-version with revocation)
  Bundle format: [gzip tar][440-byte Cisco RSA-3072 PKCS#1 signature]
  Dev keys: cs_rommon_platform_allow_dev_keys(0) called from main() — disabled in production

Auto-upgrade NFS path:
  Primary pushes bundle to /nfs/SYSTEM/hx_device_connector/bundle_data/hxdc_active_bundle
  Secondary nodes pull from NFS at startup; no NFS write-protection enforced in code

iscsisvc architecture (16MB PIE ELF, not stripped, statically compiled OpenSSL):
  Build path: /opt/git/cypress/opensrc/istgt/src/chap_util.c  (Cisco internal project "cypress")
  IoVisor: ESXi-side kernel driver (stHypervisorSvc VIB); iscsisvc manages IoVisor registrations
  Iscsi_RegisterIoVisor / Iscsi_GetRedirectionInfo / Iscsi_Redirect — connection redirect/LB
  Binary protections:
    PIE: YES (ELF Type DYN, FLAGS_1=PIE)
    ASLR: YES (PIE binary)
    Stack canaries: YES (__stack_chk_fail called extensively in all handlers)
    NX/DEP: YES (GNU_STACK RW, not executable)
    RELRO: PARTIAL (GNU_RELRO present, no BIND_NOW -> GOT remains writable post-load)
    Note: partial RELRO = GOT overwrite remains viable exploitation primitive if heap write-primitive found
  conn_worker_ev_pdu_exec (0x282130) — iSCSI PDU execution handler
    Stack frame: 264 bytes (sub rsp,0x108); opcode read at [rsi], masked to 6-bit via 'and eax,0x3f'
    Sequence validation: bswap r13d; compare against connection struct at [rbx+0x128]+0xdc/0xe0
    Pre-filter: bt rax,0x16 gates opcodes 0x01/0x02/0x04 through CmdSN seq validation before dispatch
    Non-filtered opcodes (0x00,0x03,0x05,0x06,0x10) bypass seq validation, checked at cmp al,0x5 first
    Jump table (relative offset, 4B entries): 0xb0bc6c; valid range opcodes 0x00-0x10; >0x10 -> error
      0x00 NOP-Out       -> 0x2828b0 (conn_worker_ev_nop_send echo path via nop_send/CB/CB2)
      0x01 SCSI Command  -> 0x282da8 -> istgt_iscsi_op_scsi (0x2751e0)
      0x02 SCSI Task Mgmt-> 0x282be0
      0x03 Login Request -> 0x282b80 -> istgt_iscsi_op_login (0x27c7e0)
      0x04 Text Request  -> 0x282b20 -> istgt_iscsi_op_text (0x26d360)
      0x05 SCSI Data-Out -> 0x282e40 (also 0x2830e0 pre-seq-check path)
      0x06 Logout Request-> 0x282e10
      0x07-0x0f reserved -> 0x282610 (error handler)
      0x10 SNACK Request -> 0x2825c8
  istgt_iscsi_op_login (0x27c7e0) — RFC 3720 Login PDU handler
    Stack frame: 2248 bytes (sub rsp,0x8c8); parses T-bit, CSG/NSG, ISID, TSIH, CmdSN, ExpStatSN
  istgt_iscsi_parse_params (0x29b990) — Text/Login key=value PDU data parser
    Key buffer: xmalloc(0x41) = 65 bytes; enforces key_len <= 64 (cmp r15d,0x40; jg error)
    Value buffer: xmalloc(0x2001) = 8193 bytes; enforces val_len <= 8192 (cmp r15d,0x2000; jg error)
    Bounds checked BEFORE copy — text negotiation parser is SAFE
  istgt_iscsi_op_data (0x276d60) — SCSI Data-Out handler
    DataSegmentLength: 24-bit from PDU bytes [5:7] (max 0xFFFFFF = 16MB)
    Bounds check at 0x276f37: rcx = BufferOffset + DataSegmentLength; cmp rcx, EDTL; ja error
    memcpy at 0x276f77: dst=task_buf+offset, src=PDU_data_ptr, size=DataSegmentLength — SAFE
  chap_decrypt_init (0x28ba30) / chap_decrypt_cleanup — CHAP (MD5) authentication
  CHAP credential infrastructure:
    ZooKeeper path: /chap/<initiator-iqn>  JSON: {chapName: <base64-ciphertext>, chapSecret: <base64-ciphertext>}
    Decrypt path (decrypt_data, 0x28bcf0):
      1. get_keystore_passwd (0x28b7e0): reads <entry key="keystore_password"> from
         /etc/hyperflex/secure/hyperflex_security.properties (fgets line scan)
      2. d2i_PKCS12_fp("/etc/hyperflex/secure/hyperflex_keystore.p12"): loads PKCS#12
      3. PKCS12_parse: extracts RSA private key
      4. BIO base64-decode ciphertext, then RSA_private_decrypt(0x100, ct, pt, key, RSA_PKCS1_PADDING=1)
    Both keystore and password file in same directory: /etc/hyperflex/secure/
  _add_dm_targets — dm-device mapper target manipulation
  PEM_write_PKCS8PrivateKey / crypt_keyslot_add_by_volume_key — LUKS integration
  AkvStor DEK cache: AkvStor->kvDEKCache->kvDataEncryptionKeys[dekIndex].isSet — in-memory LUKS key cache
  Encryption library toggle: /opt/hyperflex/storfs-core/encrypt/libcrypt_disabled.so vs libcrypt_enabled.so

hxdp connector binary (Go, UPX-packed, stripped):
  Internal project names: apollo (connector codebase), starship (HXDP), diesel (build system)
  Build server: /mnt/vol1/jenkins/workspace/starship/master/diesel/code/apollo/
  Intersight cloud WebSocket endpoint: svc-static1.ucs-connect.com
  HashiCorp Vault API paths embedded: /pki/root/sign-self-issued, /sys/revoke-force/{prefix}
  SUDI certificate authentication to Intersight
  Emulator mode path: /.device_connector_emulator/intersight/catalog/Version
  Go pprof endpoint: /debug/pprof/, /debug/pprof/cmdline, /debug/pprof/profile
  Cloud domain override env vars: ENV_ANDROMEDA_DOMAIN_NAME, ENV_SERVICE_DOMAIN_NAME, ENV_WEB_ELB_DOMAIN_NAME
  Staging Intersight domains (hardcoded in binary): cntcicd.starshipcloud.com, staging.starshipcloud.com,
    cntperf.starshipcloud.com, sretest.starshipcloud.com, cntqa.starshipcloud.com
  adsecret cipher library: adsecret_cipher.CipherIntf / adsecret.CipherMsg / adsecret.DecryptReq (AES-GCM)
  JWT: ECDSA (jwt/ecdsa.go source path embedded); stSSOMgr SSO service at localhost:9334
  Cert paths: certs/cisco-root-ca.pem; config: /etc/springpath/visorhost, /etc/springpath/stMgr.cfg
  Certificate: -----END+CERTIFICATE----- non-standard PEM footer variant present

Installer appliance filesystem (Cisco-HX-Data-Platform-Installer-v6.0.2b-44423-esx.ova, 24.2GB vdisk):
  Build: BUILD_ID=44423, BUILD_DATE=20251107, BUILD_TYPE=release, BUILD_RELEASE=6.0.2b
  /etc/hyperflex/secure/ (world-traversable, drwxr-xr-x):
    hyperflex_keystore.jceks  (rw-r--r--, 2700 bytes; Java JCEKS magic 0xCECECECE)
      Entry 1: aes_encryption (SecretKeyEntry — AES key for data-at-rest)
      Entry 2: vcenter_client (PrivateKeyEntry; CN=*.cisco.com, OU=Engineering; self-signed; valid until 2055; SHA512withRSA)
    hyperflex_security.properties -> /usr/share/hyperflex/storfs-misc/hyperflex_security.properties
      Content: <entry key="keystore_password">c3ByaW5ncGF0aA==</entry>  (base64 -> "springpath")
  nginx: conf.d + ngx_cisco_fips_module.so; server.key NOT pre-provisioned in installer (generated during deploy)
  /opt/hyperflex/auth/auth — ELF 64-bit, dynamically linked, NOT stripped (symbols available)
  auth.service: WorkingDirectory=/opt/hyperflex/auth; binds localhost:9334 (stSSOMgr)
  deployNodes.py: reads credentials.installer_passwd via parseEnvVariableTunes()
  stssoclient.py: thrift client to stSSOMgr on localhost:9334

iscsisvc SCSI path analysis:
  conn_worker_ev_nop_send (0x285f10): builds fixed NOP-In response (TTT=0xFFFFFFFF, opcode=0x20, F-bit)
    via istgt_iscsi_send_response — no echo of NOP-Out DataSegment data; SAFE
  istgt_iscsi_op_scsi (0x2751e0) EDTL handling (candidate — needs exploitation confirmation):
    EDTL = bswap([r15+0x14]) -> [rsp+0x20]
    Buffer adequacy check: lea eax,[rax+rsi*1+0x11000] at 0x2755b4 where rsi=EDTL (32-bit LEA)
    Overflow: EDTL=0xFFFFFFFF causes LEA to wrap -> cmp [r14+0x2e8],0x10FF passes for most pre-allocs
    On overflow: code proceeds with undersized buffer instead of triggering jl->0x276513 error path
    0x276513 error path: Log_UserAlert + return -1 (no dynamic realloc — fixed allocation only)
    Exploitation impact: depends on whether EDTL drives subsequent memory write (vs SCSI CDB xfer len)

auth binary (hx-auth, 9.5MB ELF, not stripped, /opt/hyperflex/auth/auth):
  Uses dgrijalva/jwt-go v4.0.0-preview1 (archived 2021-01, CVE-2020-26160 audience bypass)
  Binary contains: *jwt.signingMethodNone, *jwt.unsafeNoneMagicConstant — alg:none path compiled in
  JWT key (main.TokenSigningKey) in .bss, runtime-initialized — not hardcoded
  Service: stSSOMgr on localhost:9334, Gorilla mux v1.7.1, PAM integration via CGo

installerrestapi-1.0.0.war (60MB Java WAR, installer appliance):
  web.xml comment: "Disable AAA Authentication for installer rest api"
  SPBasicAuth (SSOBasicAuthImpl) + SPAuth (SSOAuthFilterImpl) filters commented out
  No <security-constraint> elements — entire /rest/* surface unauthenticated
  Endpoints: /rest/*, /upload, /internalsupport/*, /st-support/*, /storfs-support/*
  REST resources: BootstrapResource, DeploymentResource, VirtPlatformResource
  BootstrapResource: createCluster, expandCluster, shutdownCluster, deployNodes, executeCommand,
                     runCommand, validateVcenterCredentials, getVcServerDetails, pings, getNodes
  DeploymentResource: getResponseFromHxdpRest(HxCredDetails, url), deployNodes, createCluster,
                      configInstaller, updateCatalog, checkDeployNodes
  Executor.executeCommand: prefix allowlist = {stcli, sysmtool, mkfs.storfs}; Runtime.exec(String[])
  pings(): Runtime.exec("timeout 1 ping -c 1 " + userInput) — BootstrapMethods #1 template confirmed
           Runtime.exec(String) tokenizes by whitespace; no shell invocation; argument injection only
  StorvisorFileUploader: /upload endpoint, multipart POST to /var/www/localhost/images/ (no auth)
  WebDownloader.trustAllHttpsCertificates(): TrustAllManager + always-valid HostnameVerifier installed
    globally via HttpsURLConnection.setDefaultSSLSocketFactory() — affects full installer JVM TLS stack
  SecurityConfigurationManager (singleton Enum): reads keystore_password from
    /etc/hyperflex/secure/hyperflex_security.properties -> Base64.getDecoder().decode() -> "springpath"
  HostCredentialsAccess(): connects to localhost Thrift + reads /etc/hyperflex/secure/root_file.pub
    .getUserName() / .getPassword() return EsxCredential.username / .password (ESXi host credentials)

ZooKeeper auth (zkClient.py / storfs-support/listzkdb.py):
  ZKClient.__enter__ auth token = "postEvent;" + cluster_uuid
  cluster_uuid source: /etc/hyperflex/clusteruuid
  ZK UUID auth scheme bypassed by GET /rest/v1/cluster (unauthenticated) -> cluster UUID field
  listzkdb.py uses paramiko.AutoAddPolicy() (SSH TOFU, no host key verification)
  Credentials logged in exception output: "Paramiko ssh connect exception: %s, host: %s user: %s password: %s"

vcCertificateUtilities.py:
  SpringpathVMWare.getServiceInstance_VCenter_SDK_Via_Certificate() -> uses vcenter_client RSA key from JCEKS (HX-F13)
  Confirms HX-F13 vCenter client cert is the live auth credential for vCenter management operations

Findings: HX-F01 (HIGH) through HX-F29 (HIGH).

storfs-restapi_6.0.2b-44423_amd64.deb (81MB) — 11 WARs on stCtlVM:
  auth, coreapi, securityservice, encryption, dataprotection, backupservice,
  hxupgrade, supportservice, iscsi, slservice, ROOT
  auth-1.0.0.war: ALL auth filters enabled (contrast: installer WAR HX-F18 disables them)
    web.xml filters: AuditFilter, SPPrivilegedAuth (SSOPrivilegeAuthImpl),
      SessionAuth (SessionCookieFilterImpl), KerberosAuth (KerberosFilterImpl),
      ServiceAccessAuth (ServiceAccessAuthFilterImpl), SPBasicAuth (SSOBasicAuthImpl),
      SPAuth (SSOAuthFilterImpl) — all mapped to /v1/*
  authfilter-1.0.0.jar (from dependencies.zip) implements filter classes:
    SSOPrivilegeAuthImpl: X-RootSessionID == /etc/hyperflex/secure/root_file.pub
      -> accepts X-LoggedInUser/X-Scope/X-RequestInitiator as identity (HX-F29)
    ServiceAccessAuthFilterImpl: short-circuits if Authenticated=True set upstream
    SSOBasicAuthImpl: standard Basic Auth validation path
    KerberosFilterImpl: Kerberos ticket path (Hyper-V hypervisor only)
    SessionCookieFilterImpl: session cookie path (ESXi hypervisor only)
  HxSecurity.getLocalSessionId(): reads /etc/hyperflex/secure/root_file.pub via FileInputStream
  AuthorizedApiServiceImpl.authorizedRequest() dispatch order:
    1. Authorization: Basic -> SSOManager.validateAuthHeaderForBasicToken()
    2. Authorization: Bearer -> SSOManager.validateAccessTokenConvertToJWT()
    3. No Authorization header -> SSOPrivilegeAuthImpl (X-RootSessionID check)
    4. If ESX: SessionCookieFilterImpl
    5. If HyperV: KerberosFilterImpl
    6. Fallback: SSOBasicAuthImpl

springpath_env_parse.py tunes credential encryption:
  AES-128-CBC; key = md5(Secret.class) as hex string = "1f6d13bcd7753f2d3b2e2da361b7afb5"
  Secret.class path: /usr/share/hyperflex/storfs-misc/Secret.class (firmware-embedded static file)
  Encrypted values stored in INI-format .tunes files:
    /opt/hyperflex/springpath_default.tunes (cluster-wide defaults)
    /opt/hyperflex/springpath_custom_cluster.tunes (cluster overrides)
    /opt/hyperflex/springpath_custom_node.tunes (per-node overrides)
  installer_passwd key: credentials.installer_passwd (read by deployNodes.py at startup)
  AES key is static across all deployments of same firmware version — any extract of firmware
  yields the key; no per-deployment key derivation.

stSSOMgr (auth binary at /opt/hyperflex/auth/auth, 9.5MB):
  Binds localhost:9334, TBinaryProtocol/TFramedTransport Thrift server (no auth)
  Interface: StSSOMgr.Client.getHypervHostCreds() -> JSON string:
    {"host": {"localadminusername": "<hyperv_admin>", "localadminusercred": "<base64_password>"}}
  Credential source: ZooKeeper (fetched and cached by auth service)
  Client (stssoclient.py): no authentication on Thrift connect; returns username + base64-decoded password

hxinstaller (Go binary, /opt/hyperflex/hxinstaller/installer, 15MB, debug info, not stripped):
  Source tree: bitbucket-eng-chn-sjc1.cisco.com/HXDP/installer-v2/server/
  Source files: create_validate.go, deploy_validate.go, hypervBareMetal.go, hyperv.go,
                hypervisor.go, validate.go, validate_hyperv.go, validate_login.go,
                validate_serversIP.go, validate_ucsm.go, validate_vcenter.go
  SQLite embedded (github.com/mattn/go-sqlite3 + CGo); DB path: installer.db
  REST endpoints (gorilla mux, runtime-registered):
    /api/validate_login, /api/upload_catalog, /api/update_catalog, /api/bundle_details
    /api/validate_hyperv, /api/configInstaller, /api/catalog_version, /api/upload_catalog_version
    /api/configure_server_ports, /api/servers/{serial}/disassociate, /api/resolve_mgmthostname
    /api/restart, /api/servers, /api/config, /api/fields, /api/upload, /api/about
    /api/proxy, /api/reset, /api/tech_support/poll, /disassoc_hv-installer
    /rest/deployment/proxy?url=<target>  (explicit SSRF proxy)
    /rest/deployment/upgradeClusterJobUCSM, /rest/deployment/updateCatalog
    /rest/deployment/checkDeployNodesJob, /rest/validate/fqdn, /rest/validate/mgmthostname
  Accepts: hxAdminPassword, vCenterPassword, esxPassword, cimcPassword fields in request bodies
  Command execution: os/exec.Cmd — "Executing command :%s" log prefix
    genisoimage via /usr/bin/genisoimagemanagement: builds hypervisorConfigData.iso
    runOSInstallAndHypervConfig: OS install + Hyper-V network config execution path
"""

import socket
import ssl
import json
import urllib.request
import urllib.error
import urllib.parse
import os
import subprocess
from typing import Optional


# ─── Default Credentials ─────────────────────────────────────────────────────

# Keystore password — static across all deployments (base64 in hyperflex_security.properties)
HX_KEYSTORE_PASSWORD = "springpath"
HX_KEYSTORE_JCEKS    = "/etc/hyperflex/secure/hyperflex_keystore.jceks"
HX_KEYSTORE_P12      = "/etc/hyperflex/secure/hyperflex_keystore.p12"
HX_KEYSTORE_PROPS    = "/etc/hyperflex/secure/hyperflex_security.properties"

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
HX_UNAUTH_PATHS = [
    "/rest/v1/cluster",
    "/rest/v1/version",
    "/rest/v1/about",
]

HX_AUTH_PATHS = {
    "nodes":            "/rest/v1/nodes",
    "datastores":       "/rest/v1/datastores",
    "alarms":           "/rest/v1/alarms",
    "snapshots":        "/rest/v1/clusters/local/snapshots",
    "disks":            "/rest/v1/storage/disks",
    "volumes":          "/rest/v1/volumes",
    "intersight_conn":  "/rest/v1/intersight/connection",
    "network":          "/rest/v1/network",
    "security":         "/rest/v1/cluster/security",
}

ISCSI_PORT = 3260
NFS_PORT   = 2049

UCSM_CREDS = [
    ("admin", "admin"),
    ("admin", "cisco"),
    ("admin", "C1sco12345"),
    ("admin", "password"),
]


# ─── Findings ────────────────────────────────────────────────────────────────

FINDINGS = {
    "HX-F01": {
        "title": "EOL OpenSSL 1.1.1 Private Fork Replaces System OpenSSL and SSH Daemon",
        "severity": "HIGH",
        "component": "cisco-openssl_1.1.1za_amd64.deb",
        "description": (
            "cisco-openssl package (CiscoSSL 1.1.1za.7.2.587, CiscoSSH 1.14.55.2) installs "
            "as a system replacement: libssl.so.1.1 and libcrypto.so.1.1 overwrite "
            "/lib/x86_64-linux-gnu/ originals; sshd overwrites /usr/sbin/sshd. "
            "OpenSSL 1.1.1 went EOL 2023-09-11. The 'za' suffix indicates a private Cisco "
            "patch lineage 26 cycles past the last public release (1.1.1w). "
            "CVE applicability is opaque — Cisco's backports are not disclosed."
        ),
        "code_evidence": {
            "post_install.sh": (
                "backupAndCopy libssl.so.1.1 /lib/x86_64-linux-gnu\n"
                "backupAndCopy libcrypto.so.1.1 /lib/x86_64-linux-gnu\n"
                "backupAndCopy sshd /usr/sbin\n"
                "backupAndCopy sshd_config /etc/ssh"
            ),
            "version": "CiscoSSL 1.1.1za.7.2.587 / CiscoSSH 1.14.55.2",
            "eol_date": "2023-09-11",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F02": {
        "title": "CiscoSSH sshd_config Sets PermitRootLogin yes by Default",
        "severity": "HIGH",
        "component": "cisco-openssl_1.1.1za_amd64.deb / /etc/ssh/sshd_config",
        "description": (
            "The CiscoSSH sshd_config installed to /etc/ssh/sshd_config sets "
            "PermitRootLogin yes. Combined with HX-F01 (system sshd replacement), "
            "root SSH login is permitted by default on every stCtlVM. "
            "Only ECDSA host key is used (RSA and ED25519 deprecated in this build)."
        ),
        "code_evidence": {
            "sshd_config line": "PermitRootLogin yes",
            "HostKey": "HostKey /etc/ssh/ssh_host_ecdsa_key (only)",
            "CiscoSSHFipsMode": "yes",
            "stsso_chroot": "Match group stsso -> ChrootDirectory /var/jail/",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F03": {
        "title": "vCenter Password Exposed via CLI Argument (argv / /proc/pid/cmdline)",
        "severity": "HIGH",
        "component": "storfs-packages / cluster-bootstrap.sh",
        "description": (
            "cluster-bootstrap.sh accepts vCenter credentials as command-line arguments "
            "(--vc-user, --vc-pwd). These are visible in /proc/<pid>/cmdline to any "
            "process with read access. On a shared stCtlVM, all local users or any "
            "process with read access to /proc can recover vCenter credentials during "
            "cluster bootstrap or upgrade."
        ),
        "code_evidence": {
            "option_parsing": "-p | --vc-pwd ) VC_PWD=\"$2\"; shift; shift ;;",
            "exposed_via": "/proc/pid/cmdline",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F04": {
        "title": "Factory-Default nginx TLS Certificate with Known Fingerprint on All Deployments",
        "severity": "MEDIUM",
        "component": "storfs-packages / cluster-bootstrap.sh / /etc/nginx/server.crt",
        "description": (
            "cluster-bootstrap.sh encodes the SHA1 fingerprint of the factory-default "
            "nginx TLS certificate: 28:71:47:9A:C0:58:72:40:C0:E7:9A:DB:39:2A:A3:1A:FD:97:BF:D7. "
            "This cert was shipped with every HyperFlex deployment. Any cluster that "
            "has not rotated its nginx cert (HX Connect REST API / HTTPS) still presents "
            "this known certificate. If the private key is recoverable from the installer "
            "VMDK, full TLS decryption against unrotated clusters is trivial."
        ),
        "code_evidence": {
            "OLD_STATIC_THUMBPRINT": "28:71:47:9A:C0:58:72:40:C0:E7:9A:DB:39:2A:A3:1A:FD:97:BF:D7",
            "key_path": "/etc/nginx/server.key",
            "cert_path": "/etc/nginx/server.crt",
        },
        "versions_affected": ["6.0.2b-44423", "all prior releases"],
        "note": "nginx server.key is NOT pre-provisioned in the installer appliance; generated during cluster deploy. Factory cert thumbprint is evidence of shared cert; private key is not recoverable from installer VMDK.",
    },
    "HX-F05": {
        "title": "cisco-openssl post_install.sh References Stale Version String",
        "severity": "MEDIUM",
        "component": "cisco-openssl_1.1.1za_amd64.deb / post_install.sh",
        "description": (
            "The post_install.sh in cisco-openssl contains "
            "'ciscossl_version=1.1.1l.7.2.289' while the installed package is "
            "version 1.1.1za.7.2.587. This stale hardcoded version string may be "
            "consumed by downstream version-checking logic or health checks, "
            "causing incorrect version reporting."
        ),
        "code_evidence": {
            "post_install.sh stale": "ciscossl_version=1.1.1l.7.2.289",
            "actual_package_version": "1.1.1za.7.2.587",
            "delta": "1.1.1l -> 1.1.1za (14 private patch cycles)",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F06": {
        "title": "NFS-Distributed Auto-Upgrade Bundle Path Without Write-Protection",
        "severity": "MEDIUM",
        "component": "cisco-hxdc / install-connector.sh / /nfs/SYSTEM/",
        "description": (
            "The Intersight Device Connector auto-upgrade mechanism distributes new "
            "connector bundles via NFS: primary node writes to "
            "/nfs/SYSTEM/hx_device_connector/bundle_data/hxdc_active_bundle; "
            "secondary nodes pick up from this path on startup. No write-protection "
            "is enforced in code — only filesystem permissions. If /nfs/SYSTEM is "
            "exported with no_root_squash or accessible to a compromised node, "
            "an attacker can inject a malicious connector bundle that is distributed "
            "to all cluster nodes and executed with the hx_device_connector service identity."
        ),
        "code_evidence": {
            "primary_push": "cp -f \"${src}\" ${hx_shared_active_bundle}  # no integrity check after copy",
            "nfs_path": "/nfs/SYSTEM/hx_device_connector/bundle_data/hxdc_active_bundle",
            "secondary_pickup": "hxdc_nfs_bundle_file=${hxdc_nfs_bundle_dir}/hxdc_active_bundle",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F07": {
        "title": "Device Connector Emulator Mode Path Exposed in Production Binary",
        "severity": "MEDIUM",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary (Go, UPX-packed) contains the path "
            "/.device_connector_emulator/intersight/catalog/Version — "
            "an internal emulator/test mode accessible via the device connector's "
            "HTTP server. If this endpoint is reachable, it may expose device identity, "
            "catalog, or version information without full Intersight authentication."
        ),
        "code_evidence": {
            "string_in_binary": "/.device_connector_emulator/intersight/catalog/Version",
            "binary": "bin/hxdp (Go, UPX-packed, built 2025-03-05)",
            "intersight_endpoint": "svc-static1.ucs-connect.com (WebSocket)",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
    "HX-F08": {
        "title": "Cisco ROMMON Code-Sign Library in Device Connector Verifier (Shared with IOS/NX-OS)",
        "severity": "INFO",
        "component": "cisco-hxdc / hxdc_release_img_verify (32-bit ELF, not stripped)",
        "description": (
            "hxdc_release_img_verify embeds Cisco's IOS/NX-OS ROMMON code-sign library "
            "(cs_rommon_*, code_sign_*, RsaLibBigNum* symbols). RSA PKCS#1 v1.5 + SHA-512. "
            "Custom BigNum implementation (not OpenSSL). Key storage at "
            "/opt/partner/cisco-hxdc/public-key in Cisco TLV format with key version "
            "rollover and revocation support. "
            "Dev keys disabled: main() calls cs_rommon_platform_allow_dev_keys(0). "
            "Bundle format: [gzip tar][440-byte appended signature]."
        ),
        "code_evidence": {
            "cs_rommon_platform_allow_dev_keys": (
                "08048b20: xor edx,edx -> call cs_rommon_platform_allow_dev_keys  ; arg=0, dev keys OFF"
            ),
            "key_storage": "/opt/partner/cisco-hxdc/public-key (binary TLV, Cisco format)",
            "sig_size": "440 bytes (RSA-3072 PKCS#1 + Cisco envelope overhead)",
            "name_in_binary": "Starship_Device_Connector_HX",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F09": {
        "title": "iscsisvc Uses CHAP (MD5) Authentication Only for iSCSI Initiators",
        "severity": "MEDIUM",
        "component": "hx-iscsi / iscsisvc (16MB ELF, not stripped)",
        "description": (
            "iscsisvc provides iSCSI storage access with CHAP authentication "
            "(chap_decrypt_init at 0x28ba30 / chap_decrypt_cleanup). CHAP uses MD5 "
            "which is cryptographically weak. No mutual CHAP (bidirectional) "
            "in the symbol table. iSCSI sessions are vulnerable to initiator spoofing "
            "if the storage network is accessible. CHAP credential storage and "
            "decryption infrastructure is documented in HX-F11."
        ),
        "code_evidence": {
            "chap_functions": "chap_decrypt_init (0x28ba30), chap_decrypt_cleanup",
            "md5": "istgt_md5init / istgt_md5update / istgt_md5final",
            "pdu_exec": "conn_worker_ev_pdu_exec (0x282130, 264-byte stack frame)",
            "redirect": "Iscsi_Redirect / Iscsi_GetRedirectionInfo (IoVisor-aware connection redirect)",
            "luks": "_add_dm_targets, crypt_keyslot_add_by_volume_key (LUKS integration)",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F10": {
        "title": "hxdp Connector Embeds HashiCorp Vault API Paths for Internal PKI",
        "severity": "INFO",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary contains HashiCorp Vault API paths: "
            "/pki/root/sign-self-issued, /sys/config/ui/headers/?$, "
            "/sys/revoke-force/{prefix}, /sys/replication/reindex$. "
            "This indicates the connector either runs a local Vault agent or "
            "communicates with a Vault server for internal certificate management. "
            "The Vault PKI surface is additional attack scope beyond the Intersight API."
        ),
        "code_evidence": {
            "vault_paths": [
                "/pki/root/sign-self-issued",
                "/sys/config/ui/headers/?$",
                "/sys/revoke-force/{prefix}",
                "/sys/replication/reindex$",
            ],
            "sudi": "SUDI certificate authentication to Intersight",
            "cloud_endpoint": "svc-static1.ucs-connect.com",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
    "HX-F11": {
        "title": "iSCSI CHAP Credential Recovery via Co-Located PKCS#12 Keystore",
        "severity": "HIGH",
        "component": "hx-iscsi / iscsisvc / /etc/hyperflex/secure/",
        "description": (
            "All iSCSI CHAP credentials (initiator name and secret) are stored in "
            "ZooKeeper at /chap/<initiator-iqn> as base64-encoded RSA-2048 "
            "ciphertexts (JSON keys: chapName, chapSecret). "
            "decrypt_data() (iscsisvc:0x28bcf0) decrypts them using a private key "
            "from /etc/hyperflex/secure/hyperflex_keystore.p12. The PKCS#12 "
            "keystore password is read from /etc/hyperflex/secure/"
            "hyperflex_security.properties (XML tag: <entry key=\"keystore_password\">). "
            "Both files are in the same directory. Any process or user with read "
            "access to /etc/hyperflex/secure/ can decrypt all iSCSI CHAP "
            "credentials for all initiators. RSA_PKCS1_PADDING (v1.5) is used — "
            "the decryption path is vulnerable to Bleichenbacher oracle attacks "
            "if decryption errors are observable."
        ),
        "code_evidence": {
            "keystore_path": "/etc/hyperflex/secure/hyperflex_keystore.p12",
            "password_path": "/etc/hyperflex/secure/hyperflex_security.properties",
            "xml_tag": "<entry key=\"keystore_password\">",
            "confirmed_password": "springpath  (base64: c3ByaW5ncGF0aA== — confirmed via installer VMDK)",
            "zk_path": "/chap/<initiator-iqn>  {chapName: b64(RSA-enc), chapSecret: b64(RSA-enc)}",
            "decrypt_data": "iscsisvc:0x28bcf0 -> PKCS12_parse -> RSA_private_decrypt(0x100, ct, pt, key, RSA_PKCS1_PADDING=1)",
            "get_keystore_passwd": "iscsisvc:0x28b7e0 -> GetXmlTagValue -> base64 decode -> PKCS12 password",
            "build_path": "/opt/git/cypress/opensrc/istgt/src/chap_util.c",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F12": {
        "title": "Hardcoded Keystore Password 'springpath' Across All HyperFlex Keystores",
        "severity": "HIGH",
        "component": "/etc/hyperflex/secure/hyperflex_security.properties -> /usr/share/hyperflex/storfs-misc/",
        "description": (
            "The file /etc/hyperflex/secure/hyperflex_security.properties (a symlink to "
            "/usr/share/hyperflex/storfs-misc/hyperflex_security.properties) contains "
            "a single XML entry: <entry key=\"keystore_password\">c3ByaW5ncGF0aA==</entry>. "
            "Decoded from base64: 'springpath' (the acquired company name). "
            "This password unlocks both the PKCS#12 keystore used by iscsisvc for CHAP "
            "credential decryption (HX-F11) and the JCEKS keystore "
            "(/etc/hyperflex/secure/hyperflex_keystore.jceks) containing a vCenter client "
            "RSA private key and an AES encryption key. The password is static across "
            "all deployments and versions. The properties file is world-readable via the "
            "world-traversable /etc/hyperflex/secure/ directory (drwxr-xr-x). "
            "Any local process on stCtlVM can read both keystores and the password."
        ),
        "code_evidence": {
            "properties_content": "<entry key=\"keystore_password\">c3ByaW5ncGF0aA==</entry>",
            "decoded_password": "springpath",
            "properties_symlink": "/etc/hyperflex/secure/hyperflex_security.properties -> /usr/share/hyperflex/storfs-misc/hyperflex_security.properties",
            "directory_perms": "drwxr-xr-x 2 root root  /etc/hyperflex/secure/",
            "jceks_perms": "-rw-r--r-- 1 root root 2700  hyperflex_keystore.jceks",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F13": {
        "title": "World-Readable JCEKS Keystore Contains vCenter Client RSA Key and AES Encryption Key",
        "severity": "HIGH",
        "component": "/etc/hyperflex/secure/hyperflex_keystore.jceks",
        "description": (
            "The JCEKS keystore at /etc/hyperflex/secure/hyperflex_keystore.jceks "
            "(world-readable, 2700 bytes) contains two entries decryptable with "
            "the hardcoded password 'springpath' (HX-F12): "
            "(1) 'vcenter_client': RSA private key with certificate CN=*.cisco.com, "
            "OU=Engineering, O='Cisco, Inc.', self-signed, valid until 2055-10-31. "
            "This wildcard certificate is used for authenticating the HyperFlex cluster "
            "to vCenter. An attacker who extracts this key can impersonate the cluster "
            "to any vCenter integration endpoint. "
            "(2) 'aes_encryption': AES SecretKeyEntry — the symmetric key used for "
            "HyperFlex data-at-rest encryption operations. Extracting this key provides "
            "access to encrypted storage data without LUKS key derivation. "
            "Both keys are accessible to any local process on stCtlVM via the world-readable "
            "keystore file and the hardcoded password."
        ),
        "code_evidence": {
            "jceks_magic": "0xCECECECE (Java KeyStore, JCEKS type)",
            "entry_1": "alias=aes_encryption, type=SecretKeyEntry",
            "entry_2": "alias=vcenter_client, type=PrivateKeyEntry",
            "vcenter_cert_cn": "CN=*.cisco.com, OU=Engineering, O=\"Cisco, Inc.\", L=SanJose, ST=California, C=US",
            "vcenter_cert_valid": "2025-11-06 through 2055-10-31 (30-year validity)",
            "vcenter_cert_sig": "SHA512withRSA",
            "vcenter_cert_serial": "7ee31744949b791",
            "vcenter_cert_sha256": "9D:FB:29:E4:B5:AC:A9:21:65:CC:71:C2:A6:81:7A:0C:BD:07:66:4D:4B:01:34:DD:DF:47:FE:79:AE:AC:1C:5A",
            "password": "springpath (see HX-F12)",
            "keytool_cmd": "keytool -list -v -keystore hyperflex_keystore.jceks -storetype JCEKS -storepass springpath",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F14": {
        "title": "hxdp Connector Cloud Domain Overridable via Environment Variable",
        "severity": "MEDIUM",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary reads ENV_ANDROMEDA_DOMAIN_NAME and "
            "ENV_SERVICE_DOMAIN_NAME environment variables at runtime to resolve the "
            "Intersight cloud endpoint. If either variable is set in the connector "
            "process environment on stCtlVM, the connector will direct its WebSocket "
            "management channel to the attacker-specified domain instead of "
            "svc-static1.ucs-connect.com. An attacker with any path to modify the "
            "connector process environment (compromised init system, writable service "
            "unit, environment file injection) can redirect all device management traffic "
            "to an attacker-controlled Intersight lookalike. "
            "ENV_WEB_ELB_DOMAIN_NAME and ENV_WEB_ELB_DNS_NAME are additional domain "
            "override variables also present in the binary."
        ),
        "code_evidence": {
            "env_vars": [
                "ENV_ANDROMEDA_DOMAIN_NAME",
                "ENV_SERVICE_DOMAIN_NAME",
                "ENV_WEB_ELB_DOMAIN_NAME",
                "ENV_WEB_ELB_DNS_NAME",
            ],
            "default_endpoint": "svc-static1.ucs-connect.com (WebSocket)",
            "binary": "bin/hxdp (Go, 1.0.11-20250305, UPX-packed, 25MB unpacked)",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
    "HX-F15": {
        "title": "Go Runtime pprof Debug Endpoints Embedded in hxdp Connector Binary",
        "severity": "MEDIUM",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary imports net/http/pprof, registering "
            "/debug/pprof/, /debug/pprof/cmdline, and /debug/pprof/profile "
            "on the connector's HTTP listener. If the local HTTP service "
            "(Create HTTP service at %s) does not require authentication for the "
            "/debug/ namespace, these endpoints expose: running goroutine stacks, "
            "heap memory profiles, and the connector process command-line arguments. "
            "The connector handles SUDI certificates and Intersight credentials — "
            "goroutine stack dumps may include these in-flight."
        ),
        "code_evidence": {
            "pprof_paths": ["/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/profile"],
            "log_string": "Create HTTP service at %s",
            "restapi_string": "https://localhost/rest/",
            "plugin_strings": ["plugin HttpRequest Start() called", "plugin Net Start() called"],
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
    "HX-F16": {
        "title": "Non-Production Intersight Staging Domain Strings Hardcoded in Production Binary",
        "severity": "LOW",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "Five Cisco-internal non-production Intersight cloud domains are hardcoded "
            "as string literals in the production hxdp connector binary: "
            "cntcicd.starshipcloud.com (CI/CD), staging.starshipcloud.com (staging), "
            "cntperf.starshipcloud.com (performance), sretest.starshipcloud.com (SRE test), "
            "cntqa.starshipcloud.com (QA). These expose Cisco's internal cloud deployment "
            "topology and environment naming. Combined with ENV_ANDROMEDA_DOMAIN_NAME (HX-F14), "
            "any of these domains could be set as the connector target, directing a "
            "deployed cluster to connect to Cisco's internal staging infrastructure."
        ),
        "code_evidence": {
            "staging_domains": [
                "cntcicd.starshipcloud.com",
                "staging.starshipcloud.com",
                "cntperf.starshipcloud.com",
                "sretest.starshipcloud.com",
                "cntqa.starshipcloud.com",
            ],
            "internal_names": "starship (project), apollo (connector code), diesel (build system)",
            "build_path": "/mnt/vol1/jenkins/workspace/starship/master/diesel/code/apollo/",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },

    "HX-F17": {
        "title": "auth Service Links Archived dgrijalva/jwt-go v4.0.0-preview1 with alg:none Path Compiled In",
        "severity": "HIGH",
        "component": "/opt/hyperflex/auth/auth (9.5MB ELF, not stripped)",
        "description": (
            "The HyperFlex stSSOMgr authentication service (hx-auth binary) uses "
            "dgrijalva/jwt-go v4.0.0-preview1, a preview release of an archived Go JWT library "
            "(archived by maintainer 2021-01, superseded by golang-jwt/jwt). "
            "The binary contains the symbol strings '*jwt.signingMethodNone' and "
            "'*jwt.unsafeNoneMagicConstant', confirming the alg:none signing path is "
            "compiled into the binary. CVE-2020-26160 (audience claim validation bypass) "
            "affects dgrijalva/jwt-go <4.0.0. An attacker who can present a token signed "
            "with alg:none — accepted if the token parser does not explicitly reject it — "
            "bypasses signature verification. The service accepts JWTs at localhost:9334 "
            "(stSSOMgr) and issues tokens used across the HXDP REST API surface."
        ),
        "code_evidence": {
            "library": "github.com/dgrijalva/jwt-go v4.0.0-preview1",
            "symbols_confirmed": ["*jwt.signingMethodNone", "*jwt.unsafeNoneMagicConstant"],
            "binary_path": "/opt/hyperflex/auth/auth",
            "service": "stSSOMgr on localhost:9334",
            "http_stack": "Gorilla mux v1.7.1",
            "cve": "CVE-2020-26160 (jwt-go audience bypass, <4.0.0)",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance VMDK)"],
        "remediation": (
            "Replace dgrijalva/jwt-go with golang-jwt/jwt v4+ or v5. "
            "Add explicit algorithm check at token parse: "
            "jwt.ParseWithClaims(token, &claims, keyFunc, jwt.WithValidMethods([]string{\"RS256\"}))."
        ),
    },

    "HX-F18": {
        "title": "Installer REST API Entirely Unauthenticated — All Cluster Operations Exposed",
        "severity": "CRITICAL",
        "component": "installerrestapi-1.0.0.war (WEB-INF/web.xml)",
        "description": (
            "The HyperFlex installer appliance REST API at /rest/* has authentication "
            "intentionally disabled. web.xml contains the comment "
            "'Disable AAA Authentication for installer rest api' wrapping the entire "
            "authentication filter block (SPBasicAuth and SPAuth). No <security-constraint> "
            "elements are present. All REST endpoints — including cluster creation, expansion, "
            "and shutdown; stcli command execution; vCenter credential validation; ESXi credential "
            "retrieval; file upload; and HXDP REST proxying — are accessible to any host on "
            "the management network without credentials. Applies to: "
            "/rest/*, /upload, /internalsupport/*, /st-support/*, /storfs-support/*."
        ),
        "code_evidence": {
            "web_xml_comment": "Disable AAA Authentication for installer rest api",
            "commented_out_filters": [
                "SPBasicAuth -> com.springpath.hx.aaa.filters.basicAuthFilter.SSOBasicAuthImpl",
                "SPAuth -> com.springpath.hx.aaa.filters.ssoFilter.SSOAuthFilterImpl",
            ],
            "commented_out_filter_mappings": ["SPBasicAuth -> /rest/*", "SPAuth -> /rest/*"],
            "unauthenticated_operations": [
                "BootstrapResource: createCluster, expandCluster, shutdownCluster, deployNodes",
                "BootstrapResource: executeCommand (stcli/sysmtool/mkfs.storfs allowlist)",
                "BootstrapResource: validateVcenterCredentials, getVcServerDetails",
                "BootstrapResource: pings (internal host enumeration)",
                "DeploymentResource: getResponseFromHxdpRest (SSRF proxy to HXDP REST)",
                "DeploymentResource: configInstaller, updateCatalog, deployNodesJob",
                "StorvisorFileUploader: /upload (file write to /var/www/localhost/images/)",
                "VirtPlatformResource: getVirtualMachines, getEvents, powerOnOffVM",
            ],
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": (
            "Re-enable the SPBasicAuth and SPAuth servlet filters in web.xml. "
            "At minimum, gate all write-capable endpoints (createCluster, deployNodes, upload) "
            "behind authentication. The installer appliance should not be network-accessible "
            "outside of the dedicated HyperFlex management VLAN."
        ),
    },

    "HX-F19": {
        "title": "Unauthenticated pings() Endpoint Executes OS ping on Caller-Supplied IPs",
        "severity": "MEDIUM",
        "component": "installerrestapi-1.0.0.war / BootstrapResource.pings()",
        "description": (
            "BootstrapResource.pings(List<String>) calls Runtime.exec() on a concatenation "
            "of the caller-supplied IP string with the template "
            "'timeout 1 ping -c 1 <ip>' (confirmed via BootstrapMethods attribute #1 in "
            "BootstrapResource.class). Because Runtime.exec(String) tokenizes by whitespace "
            "without shell invocation, classic shell metacharacters do not achieve code "
            "execution. However, the endpoint is unauthenticated (HX-F18) and accepts a "
            "list of arbitrary IP strings, enabling: (1) internal management network host "
            "enumeration — any IP that returns exit code 0 is added to the response; "
            "(2) argument injection via embedded spaces — flags can be appended to the ping "
            "command. The response is the list of IPs that were reachable."
        ),
        "code_evidence": {
            "call_site": "BootstrapResource.pings() offset 0x40-0x55",
            "exec_call": "java.lang.Runtime.getRuntime().exec(String) at bytecode offset 69",
            "template": "timeout 1 ping -c 1 <userInput>",
            "template_source": "BootstrapMethods attribute #1: '#2567 timeout 1 ping -c 1 \\u0001'",
            "no_shell": "Runtime.exec(String) uses StringTokenizer — no shell metachar expansion",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
    },

    "HX-F20": {
        "title": "Unauthenticated HXDP REST Proxy Enables SSRF into Internal Cluster Services",
        "severity": "HIGH",
        "component": "installerrestapi-1.0.0.war / DeploymentResource.getResponseFromHxdpRest()",
        "description": (
            "DeploymentResource.getResponseFromHxdpRest(HxCredDetails creds, String urlPath) "
            "accepts caller-supplied credentials and a URL path, proxies the request to the "
            "internal HXDP REST API via the installer's Thrift client, and returns the raw "
            "response. The endpoint is unauthenticated (HX-F18). An attacker on the management "
            "network can use the installer as an authenticated relay into the deployed cluster's "
            "REST API — issuing management operations against a live cluster without direct "
            "network access to it, supplying any credentials in the HxCredDetails body. "
            "WebDownloader.trustAllHttpsCertificates() (HX-F22) ensures no TLS validation "
            "occurs on the outbound connection to the cluster."
        ),
        "code_evidence": {
            "method_signature": (
                "public JsonObject getResponseFromHxdpRest("
                "com.storvisor.sysmgmt.bootstrap.model.HxCredDetails, java.lang.String)"
            ),
            "backing_service": "DeploymentServiceAccess.getResponseFromHxdpRest() -> StDeploy$Client Thrift",
            "thrift_endpoint": "strings: 'Connecting to {}' + 'trustAll' -> /stdeploy",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": "Require authentication on all /rest/* endpoints (HX-F18 remediation covers this). "
                       "Validate the URL path parameter against an allowlist; reject paths containing "
                       "scheme prefixes, parent-directory sequences, and internal-only service identifiers.",
    },

    "HX-F21": {
        "title": "Unauthenticated File Upload Writes to Installer Image Serving Directory",
        "severity": "MEDIUM",
        "component": "installerrestapi-1.0.0.war / StorvisorFileUploader (/upload)",
        "description": (
            "StorvisorFileUploader.doPost() at /upload accepts multipart POST requests "
            "without authentication (HX-F18) and writes uploaded files to "
            "/var/www/localhost/images/ (set via StorvisorFileUploadPath context parameter). "
            "No path traversal sanitization is visible in the decompiled bytecode. "
            "An attacker on the management network can write arbitrary files to the "
            "installer image directory — potentially replacing firmware images served to "
            "ESXi hosts during deployment or injecting malicious images that are automatically "
            "consumed by the HyperFlex installation workflow."
        ),
        "code_evidence": {
            "servlet_path": "/upload",
            "target_dir": "/var/www/localhost/images/",
            "context_param": "StorvisorFileUploadPath",
            "upload_lib": "org.apache.commons.fileupload.servlet.ServletFileUpload",
            "auth_present": False,
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": "Require authentication on /upload. "
                       "Validate uploaded file type, name, and size before write. "
                       "Write to a staging path; verify image integrity before promoting to the serving directory.",
    },

    "HX-F22": {
        "title": "Installer JVM Globally Disables TLS Certificate Validation via TrustAllManager",
        "severity": "MEDIUM",
        "component": "installerrestapi-1.0.0.war / WebDownloader.trustAllHttpsCertificates()",
        "description": (
            "WebDownloader.trustAllHttpsCertificates() installs a no-op TrustManager "
            "(TrustAllManager) and an always-accepting HostnameVerifier globally into "
            "javax.net.ssl.HttpsURLConnection via setDefaultSSLSocketFactory() and "
            "setDefaultHostnameVerifier(). Both DeploymentServiceAccess and DataServiceAccess "
            "call trustAll before establishing Thrift connections to backend services, making "
            "this the live execution path during all installer-to-cluster communication. "
            "Any HTTPS connection from the installer JVM process — including cluster deployment "
            "callbacks, catalog downloads, and HXDP REST proxy calls — is susceptible to "
            "MITM on the management network."
        ),
        "code_evidence": {
            "class": "com.storvisor.sysmgmt.service.WebDownloader",
            "inner_class": "WebDownloader$TrustAllManager (implements javax.net.ssl.TrustManager)",
            "install_site": "HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory())",
            "hostname_verifier": "WebDownloader$2 (always returns true)",
            "callers": ["DeploymentServiceAccess.openClientConnection()", "DataServiceAccess.openClientConnection()"],
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": "Remove TrustAllManager and the global SSL socket factory override. "
                       "Use a dedicated SSLContext loaded from the JCEKS keystore (HX-F13) for "
                       "cluster connections; validate cluster certificates against a pinned CA.",
    },

    "HX-F23": {
        "title": "ZooKeeper UUID Authentication Token Derivable from Unauthenticated REST Endpoint",
        "severity": "MEDIUM",
        "component": "storfs-support/zkClient.py + /rest/v1/cluster (unauthenticated)",
        "description": (
            "HyperFlex ZooKeeper authentication uses a cluster UUID as the shared secret. "
            "zkClient.py reads the UUID from /etc/hyperflex/clusteruuid and presents it to "
            "ZooKeeper as auth scheme 'UUID' with the string 'postEvent;<cluster_uuid>'. "
            "The cluster UUID is exposed without authentication at the HX Connect REST endpoint "
            "GET /rest/v1/cluster, which returns the cluster UUID among other fields. "
            "An attacker on the management network can obtain the ZK auth token from the "
            "unauthenticated REST API and then authenticate to the ZooKeeper ensemble at "
            "localhost:2181 (port typically reachable from the stCtlVM management interface). "
            "Successful ZK access exposes: CHAP credential RSA ciphertexts (which are decryptable "
            "via the PKCS12 keystore using the static 'springpath' password — HX-F11/HX-F12), "
            "cluster topology, vCenter registration state, and storage configuration. "
            "Whether ZK auth is enforced depends on the 'useZKAuth' flag in /etc/hyperflex/storfs.cfg."
        ),
        "code_evidence": {
            "auth_scheme": "UUID",
            "auth_string_template": "'postEvent;' + cluster_uuid",
            "uuid_source_file": "/etc/hyperflex/clusteruuid",
            "uuid_public_endpoint": "GET /rest/v1/cluster (no auth required)",
            "zk_connect": "127.0.0.1:2181 (storfs.cfg: zkConnectString or crmZKEnsemble)",
            "auth_flag": "useZKAuth in /etc/hyperflex/storfs.cfg",
            "source_file": "/opt/hyperflex/storfs-support/zkClient.py",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance + stCtlVM)"],
        "remediation": "Replace UUID-based ZK auth with a random per-cluster credential "
                       "generated at deployment time and stored in a protected location. "
                       "Do not expose the cluster UUID via any unauthenticated endpoint if it "
                       "doubles as an authentication credential for other internal services.",
    },

    "HX-F24": {
        "title": "Tunes Credential Encryption AES Key Derived from Static Firmware-Embedded File",
        "severity": "HIGH",
        "component": (
            "/usr/share/hyperflex/storfs-misc/springpath_env_parse.py + "
            "/usr/share/hyperflex/storfs-misc/Secret.class"
        ),
        "description": (
            "springpath_env_parse.parseEnvVariableTunes() uses AES-128-CBC to encrypt and "
            "decrypt credential values stored in the springpath .tunes INI files "
            "(/opt/hyperflex/springpath_default.tunes, springpath_custom_cluster.tunes, "
            "springpath_custom_node.tunes). The AES key is derived as the MD5 hex digest "
            "of Secret.class: md5('/usr/share/hyperflex/storfs-misc/Secret.class') = "
            "'1f6d13bcd7753f2d3b2e2da361b7afb5'. Secret.class is a static firmware-embedded "
            "file shipped in every HyperFlex 6.0.2b installation. The key is identical across "
            "all deployments of the same firmware version — there is no per-deployment key "
            "derivation, no salt, and no secret component outside the firmware image. "
            "Any party with access to the firmware package can compute the key and decrypt "
            "all credentials stored in the tunes infrastructure, including "
            "credentials.installer_passwd (consumed by deployNodes.py at startup)."
        ),
        "code_evidence": {
            "key_derivation": "key = hashlib.md5(open(Secret.class, 'rb').read()).hexdigest()",
            "key_value": "1f6d13bcd7753f2d3b2e2da361b7afb5",
            "secret_class_path": "/usr/share/hyperflex/storfs-misc/Secret.class",
            "cipher": "AES-128-CBC (pycryptodome Crypto.Cipher.AES, MODE_CBC)",
            "iv_handling": "IV prepended to ciphertext, base64-encoded",
            "plaintext_pad": "PKCS#7 equivalent (pad to 16-byte boundary with pad char = chr(pad_len))",
            "affected_credential": "credentials.installer_passwd (deployNodes.py)",
            "source_file": "/usr/share/hyperflex/storfs-misc/springpath_env_parse.py",
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM + installer appliance)"],
        "remediation": (
            "Replace file-MD5-derived key with a per-deployment randomly generated AES key "
            "stored in a protected keystore (e.g., the existing JCEKS keystore under "
            "/etc/hyperflex/secure/). Secret.class should not serve as a key derivation input "
            "since it is publicly distributed with the firmware."
        ),
    },

    "HX-F25": {
        "title": "Installer Go Binary Exposes Explicit SSRF Proxy Endpoint at /rest/deployment/proxy",
        "severity": "HIGH",
        "component": "/opt/hyperflex/hxinstaller/installer (Go binary, REST API)",
        "description": (
            "The HyperFlex installer Go binary (hxinstaller/installer) registers a REST "
            "endpoint at /rest/deployment/proxy?url=<target>. The endpoint accepts an "
            "arbitrary URL via the 'url' query parameter and proxies the request to the "
            "specified target, returning the response. This is an explicit server-side "
            "request forgery primitive built into the installer service. Combined with the "
            "installer appliance's network position on the HyperFlex management network, "
            "the endpoint provides access to internal services not directly reachable from "
            "the attacker's network position. The auth posture of this endpoint in the Go "
            "binary's own mux is not separately confirmed (distinct from the WAR's disabled "
            "auth — HX-F18), but the endpoint is structurally an SSRF proxy regardless of "
            "auth status."
        ),
        "code_evidence": {
            "endpoint_string": "/rest/deployment/proxy?url=",
            "binary": "/opt/hyperflex/hxinstaller/installer (Go, 15MB, not stripped)",
            "source_tree": "bitbucket-eng-chn-sjc1.cisco.com/HXDP/installer-v2/server/",
            "route_registration": "gorilla mux (runtime-assembled routes)",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": (
            "Remove the /rest/deployment/proxy endpoint or gate it to internal use only. "
            "If a proxy is required for cluster communication, restrict the target URL to "
            "an allowlist of known internal service addresses and ports. "
            "Log all proxy requests with full URL for audit."
        ),
    },

    "HX-F26": {
        "title": "stSSOMgr Thrift Service Exposes Hyper-V Host Admin Credentials Without Authentication",
        "severity": "HIGH",
        "component": "/opt/hyperflex/auth/auth (stSSOMgr service, localhost:9334)",
        "description": (
            "The HyperFlex auth binary runs the stSSOMgr Thrift service on localhost:9334 "
            "using TBinaryProtocol/TFramedTransport with no authentication layer on the "
            "Thrift connection. The StSSOMgr.getHypervHostCreds() RPC returns a JSON object "
            "containing the Hyper-V host local admin username and base64-encoded password: "
            "{'host': {'localadminusername': '<user>', 'localadminusercred': '<b64_pass>'}}. "
            "Credentials are sourced from ZooKeeper. Any process on the installer appliance "
            "or stCtlVM that can reach localhost:9334 — including code execution via HX-F18 "
            "or HX-F19 — can retrieve Windows Hyper-V host admin credentials by opening a "
            "raw Thrift connection without presenting any credential. This enables lateral "
            "movement from the HyperFlex management plane to Hyper-V host infrastructure."
        ),
        "code_evidence": {
            "service_port": "localhost:9334 (TSocket.TSocket('localhost', 9334))",
            "transport": "TTransport.TFramedTransport (no auth wrapper)",
            "rpc": "StSSOMgr.Client.getHypervHostCreds()",
            "response_schema": (
                "JSON: {'host': {'localadminusername': str, 'localadminusercred': str (base64)}}"
            ),
            "auth_on_connect": None,
            "source_file": "/opt/hyperflex/stssoclient.py",
            "service_binary": "/opt/hyperflex/auth/auth",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance + stCtlVM)"],
        "remediation": (
            "Add Thrift transport-level authentication to stSSOMgr (e.g., SASL/PLAIN or "
            "a pre-shared token validated on every connection). Restrict port 9334 to "
            "specific authorized callers via process-level controls or Unix domain socket "
            "instead of TCP. Rotate the Hyper-V admin credentials independently of the "
            "stSSOMgr credential vault."
        ),
    },

    "HX-F27": {
        "title": "Installer deployNodes.py Disables TLS Certificate Verification for All HTTP Calls",
        "severity": "MEDIUM",
        "component": "/opt/hyperflex/deployNodes.py",
        "description": (
            "deployNodes.py passes verify=False to every requests.get() and requests.post() "
            "call — covering cluster deployment status polling, checkDeployNodes, and "
            "deployNodes REST calls against the installer appliance. The verify=False flag "
            "disables both certificate chain validation and hostname verification in the "
            "Python requests library. All HTTPS connections from this script — including "
            "those transmitting authentication credentials (Basic Auth via auth=authData) "
            "and cluster deployment payloads — are susceptible to MITM on the management "
            "network. The installer password (credentials.installer_passwd) is transmitted "
            "as HTTP Basic Auth over these unvalidated HTTPS connections."
        ),
        "code_evidence": {
            "pattern": "requests.get/post(url, auth=authData, verify=False, ...)",
            "occurrences": [
                "deploymentsUrl GET (line 148)",
                "progressUrl GET (line 152)",
                "checkDeployNodesUrl POST (lines 156, 164)",
                "deployNodesUrl POST (lines 160, 169)",
            ],
            "credential_exposure": "auth=authData carries (opts.user, opts.password) = INSTALLER_PASSWD",
            "source_file": "/opt/hyperflex/deployNodes.py",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": (
            "Remove verify=False. Load the installer appliance's self-signed certificate "
            "(generated at deploy time) into a trusted bundle and pass verify='<path>' "
            "to requests calls. If mutual TLS is required, use the vcenter_client key from "
            "the JCEKS keystore (HX-F13) for client certificate auth."
        ),
    },

    "HX-F28": {
        "title": "StPlatform Thrift Interface Exposes 40+ Destructive Storage Operations Without Authentication",
        "severity": "HIGH",
        "component": "/opt/hyperflex/storfs-core/storfs (20MB ELF, storfs daemon, port 9966)",
        "description": (
            "The storfs storage daemon exports its core management interface as a Thrift "
            "StPlatformProcessor with over 40 methods covering destructive storage operations: "
            "formatDisks, deleteFiles, createFiles, removeDisk, retireDisks, blacklistDisks, "
            "unclaimDisks, enableZKAuth, cloneDatastore, teardownNRNFS, and others. "
            "Symbol table analysis of the 20MB storfs ELF (28,996 symbols, not stripped) "
            "confirms no StPlatformAuthorizingProcessor class is present — the standard "
            "authorization wrapper used in other Thrift service deployments is absent. "
            "Disassembly of the representative method process_getCluster (0x9692a0) shows "
            "no authentication or authorization check before dispatching to "
            "StPlatform_getCluster_args::read(TProtocol*). The same pattern is expected "
            "for destructive methods. The StPlatform interface port (9966, confirmed from "
            "storfs binary strings) is exposed on the stCtlVM. Any process that can reach "
            "the storfs Thrift socket — including code execution obtained through HX-F18 "
            "or HX-F19 on the installer appliance — can invoke storage-destruction operations "
            "against the HyperFlex cluster data fabric."
        ),
        "code_evidence": {
            "binary": "/opt/hyperflex/storfs-core/storfs (20MB ELF, PIE, partial RELRO, canary, 28996 symbols)",
            "symbol_evidence": "StPlatformProcessor present; StPlatformAuthorizingProcessor absent",
            "destructive_handlers": [
                "process_formatDisks", "process_deleteFiles", "process_createFiles",
                "process_removeDisk", "process_retireDisks", "process_blacklistDisks",
                "process_unclaimDisks", "process_enableZKAuth", "process_cloneDatastore",
                "process_teardownNRNFS",
            ],
            "port": "9966 (from storfs binary string literals)",
            "auth_check_absent": "process_getCluster @ 0x9692a0: direct dispatch to args::read, no auth call",
            "auth_wrapper_absent": "StPlatformAuthorizingProcessor not in symbol table",
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM)"],
        "remediation": (
            "Introduce an authorization wrapper (analogous to StPlatformAuthorizingProcessor) "
            "that validates a session token on every Thrift call before dispatching. "
            "Restrict the StPlatform port (9966) to loopback only via iptables and verify "
            "that the calling process matches an expected service identity. "
            "Audit all process_* handlers to confirm no production path reaches destructive "
            "operations without a prior privilege check."
        ),
    },

    "HX-F29": {
        "title": "SSOPrivilegeAuthImpl Accepts User-Controlled X-RootSessionID Header to Bypass Authentication",
        "severity": "HIGH",
        "component": (
            "authfilter-1.0.0.jar / SSOPrivilegeAuthImpl "
            "(HX Connect REST API filter chain, mapped to /v1/*)"
        ),
        "description": (
            "SSOPrivilegeAuthImpl.validateAuthHeaderForPrivilegeCreds() implements an "
            "intra-node privilege bypass path in the HX Connect REST API filter chain. "
            "When the X-RootSessionID request header is present and matches the content of "
            "/etc/hyperflex/secure/root_file.pub (read by HxSecurity.getLocalSessionId()), "
            "the filter accepts the values of three additional caller-controlled headers as "
            "the authenticated identity without any credential verification: "
            "X-LoggedInUser (becomes com.springpath.hx.aaa.authenticateduser), "
            "X-Scope (becomes com.springpath.hx.aaa.authenticateduserscope), and "
            "X-RequestInitiator (becomes com.springpath.hx.aaa.reqinitiatorip). "
            "The downstream ServiceAccessAuthFilterImpl short-circuits on Authenticated=True "
            "and lets the request through. "
            "An attacker who can read /etc/hyperflex/secure/root_file.pub can impersonate "
            "any user (e.g., X-LoggedInUser: admin) with MODIFY scope on any HX Connect "
            "REST endpoint without presenting any password or token. "
            "The /etc/hyperflex/secure/ directory is world-traversable (drwxr-xr-x) and "
            "other files in that directory (hyperflex_keystore.jceks) are world-readable "
            "(rw-r--r--), suggesting root_file.pub is likely world-readable on the stCtlVM. "
            "A malicious local service or a process with arbitrary file read (e.g., via path "
            "traversal in another endpoint) can extract the file and forge admin sessions."
        ),
        "code_evidence": {
            "filter_class": (
                "com.springpath.hx.aaa.filters.privilegeAuthFilter.SSOPrivilegeAuthImpl"
                " (authfilter-1.0.0.jar)"
            ),
            "session_id_source": "/etc/hyperflex/secure/root_file.pub (HxSecurity.getLocalSessionId())",
            "match_logic": "X-RootSessionID.equals(HxSecurity.getLocalSessionId()) -> authenticated",
            "identity_headers": {
                "X-LoggedInUser": "com.springpath.hx.aaa.authenticateduser",
                "X-Scope": "com.springpath.hx.aaa.authenticateduserscope (READ or MODIFY)",
                "X-RequestInitiator": "com.springpath.hx.aaa.reqinitiatorip",
            },
            "downstream_filter": (
                "ServiceAccessAuthFilterImpl checks getAttribute('Authenticated') == 'True' "
                "and calls chain.doFilter() if true — bypasses all remaining auth filters"
            ),
            "authorized_endpoint": (
                "AuthorizedApiServiceImpl.authorizedRequest() fallback path (offset 253): "
                "SSOPrivilegeAuthImpl.validateAuthHeaderForPrivilegeCreds first, "
                "before SessionCookieFilter and KerberosFilter"
            ),
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM, storfs-restapi)"],
        "remediation": (
            "Replace the file-based session ID with a cryptographically random token "
            "generated at service startup and stored in memory only (not on disk). "
            "Restrict the privilege bypass path to loopback-originated requests at the "
            "network layer — reject X-RootSessionID from any non-127.0.0.1 source. "
            "Audit other services that read root_file.pub (e.g., HostCredentialsAccess) "
            "to ensure they do not expose its content through any API endpoint."
        ),
    },
}


# ─── Probe Functions ──────────────────────────────────────────────────────────

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


def probe_hx_connect(host: str, timeout: int = 8) -> dict:
    result = {
        "host": host, "port": HX_CONNECT_PORT, "reachable": False,
        "version": None, "unauth_data": {}, "cred_result": None,
        "auth_data": {}, "intersight_claim_code": None,
    }

    try:
        s = socket.create_connection((host, HX_CONNECT_PORT), timeout=timeout)
        s.close()
        result["reachable"] = True
    except Exception:
        return result

    for path in HX_UNAUTH_PATHS:
        data = _hx_request(host, path, timeout=timeout)
        if data and "__http_error" not in data:
            result["unauth_data"][path] = data
            if "version" in data or "hxVersion" in data:
                result["version"] = data.get("version") or data.get("hxVersion")

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
            break

    if token:
        for key, path in HX_AUTH_PATHS.items():
            data = _hx_request(host, path, token=token, timeout=timeout)
            if data and "__http_error" not in data:
                result["auth_data"][key] = data

        conn = result["auth_data"].get("intersight_conn", {})
        result["intersight_claim_code"] = conn.get("claimCode") or conn.get("deviceId")

    return result


if __name__ == "__main__":
    import sys

    print("=== Cisco HyperFlex RE Module ===")
    print(f"Findings: {len(FINDINGS)} (HX-F01 through HX-F{max(int(k.split('-F')[1]) for k in FINDINGS)})")
    print()

    for fid, f in FINDINGS.items():
        sev = f["severity"]
        print(f"[{sev:8}] {fid}: {f['title']}")

    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"[*] Probing {target}")
        print(json.dumps(probe_hx_connect(target), indent=2))
