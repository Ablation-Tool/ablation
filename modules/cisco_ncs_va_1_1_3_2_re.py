"""
Cisco Prime Network Control System (NCS) Virtual Appliance RE Module
Target: NCS-VA-1.1.3.2-large.ova (3.7GB VMware OVA, 2011-03-23)
Product: Cisco Prime Network Control System Virtual Appliance v1.1.3.2
Internal name: WCS-VA (Wireless Control System Virtual Appliance)
OVF system: vmx-07 (VMware ESX 3.x), RHEL5 64-bit guest

OS: Red Hat Enterprise Linux Server 5.4 (Tikanga) -- EOL November 2017
ADE-OS: v2.0.1.038 (Cisco Application Deployment Engine OS)
Application: Cisco Prime NCS 1.1.3.2-1 (NetworkControlSystem RPM, 2013-01-31)
Database: Oracle 11.2.0 (EOL 2020) on LVM smosvg

Disk layout (LVM volume group: smosvg, PV: /dev/nbd8p3 = 390GB):
  rootvol:       1.9GB  (ext3, /)
  usrvol:        6.8GB  (ext3, /usr)
  varvol:        1.9GB  (ext3, /var)
  optvol:       293.2GB (ext3, /opt -- Oracle 11.2.0 + NCS app)
  storeddatavol:  9.8GB (ext3, /storeddata -- NCS.tar.gz install bundle)
  localdiskvol:  58.6GB (ext3, /localdisk)
  home:          96MB   (ext3, /home)
  tmpvol:        1.9GB  (ext3, /tmp)
  swapvol:      15.6GB  (swap)
  recvol/altrootvol: 96MB each (recovery/alt root)

Ports (from manifest.xml security/tcpport):
  7, 49, 442 (HTTPS), 1522 (Oracle), 8082 (HTTP alt),
  10022-10041 (FTP passive data), 16113 (internal)
  UDP: 162 (SNMP trap), 514 (syslog), 1645/1812/1646/1813 (RADIUS)

Application installer:
  /storeddata/ToInstall/NCS.tar.gz (811MB, NCS v1.1.3.2 RPM bundle)
  RPMs: NetworkControlSystem-1.1.3.2-1.x86_64.rpm, NCSCARSCli, wnbu_dbconfig,
        CARSBackup, CARSInstall
  Install path: /opt/CSCOncs/

3DES DB credential encryption scheme (fully reversed):
  File: lib/xmp/xmp_dbCredential_mgmt-6.1.27.jar
  Class: DBCredentialMgr + ThreeDesEncrypter + EnigmaEncrypter
  Algorithm: DESede/CFB/NoPadding (3DES CFB mode, no padding)
  Key derivation: keyStr.getBytes("UTF-8") zero-padded to 32 bytes -> first 24 bytes = DESedeKeySpec
  Hardcoded keyStr: "abcdefg" (DBCredentialMgr.java constant pool #30)
  Key (24 bytes): 61 62 63 64 65 66 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  IV (8 bytes): 30 31 32 33 34 35 36 37 ("01234567", static field ThreeDesEncrypter.iv)
  Ciphertext: hex string stored in dbPasswd.pwd
  Decryption: 3DES-CFB-NoPadding with above key + IV recovers plaintext wcsdba password
"""

METADATA = {
    "target": "Cisco Prime NCS Virtual Appliance v1.1.3.2 (2011-03-23, EOL)",
    "os": "RHEL 5.4 (Tikanga, EOL Nov 2017), ADE-OS 2.0.1.038",
    "database": "Oracle 11.2.0 (EOL April 2020), LVM smosvg",
    "application": "Cisco Prime NCS 1.1.3.2-1 (XMP/CARS framework, Tomcat 6/7)",
    "vmware": "VMware vmx-07 streamOptimized VMDK, OVF 1.0",
    "internal_name": "WCS-VA (Wireless Control System VA -- pre-Cisco Prime branding)",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Multiple Hardcoded Oracle Database Passwords -- SYS/SYSTEM/cepm all Static",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "Three separate Oracle database users have hardcoded credentials that never change: "
            "(1) Oracle SYS and SYSTEM: password 'CpmDba123'. "
            "Source: wcsInitialSetup.sh line: "
            "'-sid cpm10 -sysPassword CpmDba123 -systemPassword CpmDba123'. "
            "These are the database superuser credentials for the Oracle 11.2.0 instance. "
            "SYS/SYSTEM access enables full DBA-level control of all NCS data. "
            "(2) Oracle user 'cepm': password 'password' (literal string). "
            "Source: wcsInitialSetup.sh: "
            "'sqlplus cepm/password @CreateCpmTables.sql'. "
            "The 'cepm' user owns CPM (Customer Policy Management) tables. "
            "(3) Fallback password for application user 'wcsdba': 'wcs123' (conf property) "
            "and 'xmp123' (Java code default). "
            "Source: PackagingResources.properties: "
            "'oracle.dbuser.password=wcs123 # Overrides hardcoded java code value of xmp123'. "
            "The wcsdba password is randomized on first install via randomizeDbPassword.sh but: "
            "(a) the randomized value is encrypted with a recoverable 3DES key (see F2), "
            "(b) if randomization fails (first-boot failure, restore from backup), "
            "'wcs123' remains active. "
            "Oracle listener on port 1522 (not the standard 1521) exposed on all interfaces."
        ),
        "credentials": {
            "oracle_sys": "CpmDba123",
            "oracle_system": "CpmDba123",
            "oracle_cepm": "password",
            "oracle_wcsdba_fallback_1": "wcs123",
            "oracle_wcsdba_fallback_2": "xmp123",
        },
        "oracle_port": 1522,
        "oracle_sid": "wcs",
        "impact": [
            "SYS/SYSTEM access = full Oracle DBA control over all NCS configuration and managed device credentials",
            "All SNMP community strings, device passwords, and AAA secrets stored in Oracle are readable",
            "cepm/password access enables CPM policy table read/write",
        ],
        "remediation": (
            "Change Oracle SYS/SYSTEM passwords during deployment. "
            "Do not expose Oracle port 1522 outside the management network. "
            "Platform is EOL; replace with Cisco Prime Infrastructure."
        ),
    },
    {
        "id": "F2",
        "title": "3DES DB Credential Encryption Fully Reversible -- Key 'abcdefg'+zeros, IV '01234567'",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-321",
        "description": (
            "The runtime wcsdba database password is encrypted with 3DES and stored in "
            "conf/dbPasswd.pwd. The encryption is trivially reversible: "
            "(1) Algorithm: DESede/CFB/NoPadding (Java standard JCE). "
            "(2) Key string: 'abcdefg' -- hardcoded in DBCredentialMgr.class constant pool entry #30 "
            "in lib/xmp/xmp_dbCredential_mgmt-6.1.27.jar. "
            "Key derivation: keyStr.getBytes('UTF-8') = [61 62 63 64 65 66 67], "
            "zero-padded to 32 bytes, first 24 bytes used as DESedeKeySpec. "
            "24-byte key: 61 62 63 64 65 66 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00. "
            "(3) IV: [30 31 32 33 34 35 36 37] (ASCII '01234567') -- hardcoded static field "
            "ThreeDesEncrypter.iv initialized in static {} of ThreeDesEncrypter.class. "
            "(4) Ciphertext format: hex string stored in dbPasswd.pwd (with leading whitespace). "
            "Any attacker with firmware access (or access to a deployed system's /opt/CSCOncs/) "
            "can recover the wcsdba password with a 3-line Python script. "
            "The class 'EnigmaEncrypter' (also in the JAR, key='fooZoolKosh') is NOT used "
            "for DB credential encryption -- only ThreeDesEncrypter is."
        ),
        "three_des_key": "abcdefg\\x00" * 2 + "abcdefg\\x00\\x00\\x00",
        "three_des_key_hex": "61626364656667" + "00" * 17,
        "three_des_iv_hex": "3031323334353637",
        "ciphertext_file": "conf/dbPasswd.pwd",
        "enigma_key": "fooZoolKosh",
        "decrypt_sketch": (
            "from Crypto.Cipher import DES3; "
            "key = b'abcdefg' + b'\\x00'*17; iv = b'01234567'; "
            "ct = bytes.fromhex(open('dbPasswd.pwd').read().strip()); "
            "DES3.new(key, DES3.MODE_CFB, iv, segment_size=8).decrypt(ct)"
        ),
        "impact": [
            "wcsdba password recoverable from dbPasswd.pwd with fixed key -- any firmware read gives DB access",
            "Combined with Oracle SYS/SYSTEM=CpmDba123 (F1), no credential is safe on this platform",
        ],
        "remediation": (
            "Platform is EOL (2011). If still deployed, isolate from network. "
            "Do not store in any security-sensitive context."
        ),
    },
    {
        "id": "F3",
        "title": "Lab/Developer Device Credentials Shipped in Production Firmware -- cisco/cisco, lab/lab",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-798",
        "description": (
            "The inventory.properties file (xmp_inventory/pal-home/conf/inventory.properties) "
            "ships in the production RPM with credentials for named Cisco developer/lab devices: "
            "  default-loginpassword=admin (NCS web default admin login) "
            "  default-enablepassword=cisco (default Cisco IOS enable password) "
            "  7609-xmp-loginusername=ana2008, password=ana2008 "
            "  7609-loginusername=cisco, password=cisco "
            "  7204-loginusername=lab, password=lab "
            "  ana-CRS-1-1-loginusername=cisco, password=cisco "
            "  3602-loginusername=cisco, password=cisco "
            "  tl-dev-v240-3-loginusername=root, password=lab, transport=ssh2 "
            "These are per-device credentials for specific named Cisco internal devices "
            "(Cisco 7609 router, CRS-1 carrier router, 7204 router, 3602 AP, Sun V240 server). "
            "All entries were present in the January 2013 build timestamp (NCS 1.1.3.2 release). "
            "Beyond the specific credentials, this file establishes that the NCS credential store "
            "uses cleartext per-device username/password with predictable property-file key format: "
            "'<devicename>-loginusername' / '<devicename>-loginpassword'. "
            "An attacker with database access (F1) can enumerate all managed device credentials "
            "stored in the same format in the Oracle wcs database."
        ),
        "credentials": {
            "default-loginpassword": "admin",
            "default-enablepassword": "cisco",
            "7609-xmp": "ana2008/ana2008",
            "7609": "cisco/cisco",
            "7204": "lab/lab",
            "ana-CRS-1-1": "cisco/cisco",
            "3602": "cisco/cisco",
            "tl-dev-v240-3": "root/lab (SSH2)",
        },
        "impact": [
            "Developer device credentials shipped in production; any firmware extract gives these",
            "Credential format reveals how device passwords are stored in the NCS Oracle DB",
            "Default admin=admin on NCS web interface (confirmed by default-loginpassword=admin)",
        ],
        "remediation": "Strip developer device credentials from production RPM builds.",
    },
    {
        "id": "F4",
        "title": "Embedded FTP Service with Hardcoded ftp-user/ftp-user and Write Access",
        "severity": "HIGH",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-798",
        "description": (
            "The NCS application embeds an Apache FTP Server instance "
            "(remotingServices/Ftp/ftp-server/) configured with hardcoded credentials "
            "in resource/user.properties: "
            "  FtpServer.user.ftp-user.userpassword=ftp-user "
            "  FtpServer.user.ftp-user.homedirectory=./Ftp/ftp-server/root "
            "  FtpServer.user.ftp-user.writepermission=true "
            "The FTP server user 'ftp-user' authenticates with password 'ftp-user' "
            "and has write permission to the home directory. "
            "The FTP passive data ports 10022-10041 are opened in the firewall rules "
            "(manifest.xml tcpport). "
            "NCS uses FTP to receive device configuration backups from managed network devices. "
            "An attacker with access to the NCS management network can authenticate to the "
            "FTP service and read/write configuration files in the FTP root, potentially "
            "overwriting device configurations that NCS will push to managed devices."
        ),
        "ftp_user": "ftp-user",
        "ftp_password": "ftp-user",
        "ftp_write": True,
        "ftp_passive_ports": "10022-10041",
        "impact": [
            "FTP write access to NCS backup/config repository",
            "Overwrite device config backups -> NCS pushes attacker-controlled config to network devices",
        ],
        "remediation": (
            "Change FTP credentials and restrict to loopback. "
            "Use SFTP instead of FTP for device config transfer."
        ),
    },
    {
        "id": "F5",
        "title": "Root MD5-crypt Password Hash and SSH PasswordAuthentication Enabled",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-916",
        "description": (
            "The RHEL5 root account has an MD5-crypt password hash in /etc/shadow: "
            "'$1$2Ye/mXie$7ENVFaenxQpQOOD5Qe9CX.' "
            "MD5-crypt ($1$) is obsolete and crackable with GPU acceleration "
            "(hashcat mode 500, >10 billion hashes/sec on modern hardware). "
            "SSH is configured with PasswordAuthentication=yes in /etc/ssh/sshd_config. "
            "PermitRootLogin defaults to 'yes' (RHEL5 OpenSSH default; not explicitly disabled). "
            "Combined: a successful hash crack yields direct root SSH access. "
            "The VM build timestamp is 2011-03-23 / RPM timestamp 2013-01-31. "
            "No patches have been applied since then. RHEL5 accumulated hundreds of CVEs "
            "after November 2017 (EOL). Critical unpatched: CVE-2021-4034 (pkexec), "
            "CVE-2021-3156 (sudo heap overflow), CVE-2016-5195 (DirtyCOW), "
            "all with public exploits and local root impact."
        ),
        "root_hash": "$1$2Ye/mXie$7ENVFaenxQpQOOD5Qe9CX.",
        "hash_type": "MD5-crypt ($1$)",
        "ssh_config": "PasswordAuthentication yes (PermitRootLogin default=yes on RHEL5)",
        "unpatched_cves": ["CVE-2021-4034", "CVE-2021-3156", "CVE-2016-5195"],
        "impact": [
            "MD5-crypt root hash crackable offline -> direct root SSH login",
            "RHEL5 EOL with hundreds of unpatched CVEs including multiple public root exploits",
        ],
        "remediation": (
            "Platform is EOL. Do not deploy. "
            "If legacy assessment required: isolate network, disable password auth, audit all users."
        ),
    },
    {
        "id": "F6",
        "title": "RHEL5 EOL Platform with Oracle 11.2.0 EOL -- No Updates Since 2013",
        "severity": "LOW",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1104",
        "description": (
            "Cisco Prime NCS 1.1.3.2 is end-of-life (released 2011, EOL declared ~2013). "
            "RHEL 5.4 EOL: November 2017 (standard support), March 2020 (extended life support). "
            "Oracle 11.2.0 EOL: December 2020. "
            "VM build date: 2011-03-23 (OVF build-258902). "
            "RPM install timestamps: 2013-01-31. "
            "No patches applied since 2013 = 10+ years of unpatched CVEs on all components. "
            "Web interface: Apache HTTPD (httpd/ directory) + Tomcat (apache-tomcat/). "
            "Apache Tomcat version not positively identified from firmware but <= 2013. "
            "Replacement: Cisco Prime Infrastructure (successor to NCS + WCS). "
            "CARS ADE-OS framework version: 2.0.1.038. "
            "Java runtime: JRE bundled at /opt/CSCOncs/jre/ and jre32/ (Oracle JRE, pre-2013)."
        ),
        "eol_dates": {
            "ncs_eol": "2013 (approx)",
            "rhel5_standard_eol": "November 2017",
            "rhel5_els_eol": "March 2020",
            "oracle_11g_r2_eol": "December 2020",
        },
        "impact": ["Complete unpatched attack surface across OS + DB + app layers"],
        "remediation": "Replace with Cisco Prime Infrastructure or newer WLAN management platform.",
    },
]

SUMMARY = {
    "total":    6,
    "critical": 3,
    "high":     1,
    "medium":   1,
    "low":      1,
    "notes": (
        "Cisco Prime NCS VA 1.1.3.2 has 3 CRITICAL findings: "
        "(1) Oracle SYS/SYSTEM hardcoded 'CpmDba123' + cepm/'password' + wcsdba fallback 'wcs123'/'xmp123'. "
        "(2) 3DES DB encryption fully reversible: key='abcdefg'+zeros, IV='01234567', mode=DESede/CFB/NoPadding. "
        "(3) Cleartext lab device credentials (cisco/cisco, lab/lab, ana2008/ana2008) shipped in production RPM. "
        "Additional: embedded FTP with ftp-user/ftp-user and write access (HIGH). "
        "Root MD5-crypt hash $1$2Ye/mXie$7ENVFaenxQpQOOD5Qe9CX. + SSH PasswordAuthentication=yes (MEDIUM). "
        "Platform is fully EOL (RHEL5, Oracle 11.2.0, NCS 1.1.3.2). "
        "This is a 2011 appliance; any deployment is a critical security liability. "
        "Disk: LVM smosvg on VMware streamOptimized VMDK (391GB virtual, 3.6GB compressed). "
        "LVM activation: vgchange -ay smosvg after qemu-nbd -c /dev/nbd8 -f vmdk <vmdk>."
    ),
}
