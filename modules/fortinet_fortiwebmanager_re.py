"""
FortiWebManager-VM 7.4.x RE findings
Product: FortiWebManager-VM (FWM-VM, model FWMVMB)
Architecture: Family C -- Debian 9 (Stretch), Django application, NOT FortiOS-based
Image: image-ovf-64/boot.vmdk (from FWM_VM64_OVF)

P1 structure:
  - 4GB ext4, full Debian 9 root filesystem
  - /boot: kernel 4.19.52-default, initrd.img (standard Linux, NOT fortism-encrypted)
  - /install/image.out (173MB, GPG symmetric AES-CFB encrypted)
  - /install/setup.sh (installer: decrypts image.out with hardcoded passphrase)
  - /install/sysinfo.json (product metadata)
P2 structure:
  - 50GB ext4, application data (/var/log mount point after setup)

Decrypted image.out contents (extracted to /tmp/fwm_extract/):
  FortiwebCM/ -- full Django 1.8 application source
  config/     -- TLS keys, DH params
"""

FWM_F01 = {
    "id":       "FWM-F01",
    "product":  "FortiWebManager-VM 7.4.x",
    "severity": "CRITICAL",
    "class":    "Hardcoded GPG Passphrase -- Full Application Archive Exposure",
    "location": "/install/setup.sh:27",
    "evidence":  'gpg --batch --passphrase "HyP>LHD3zMvHi/Ev" -o $tmp_pkg -d $update_pkg',
    "summary": (
        "The installer script /install/setup.sh contains the GPG passphrase in plaintext "
        "to decrypt image.out (173MB, AES-CFB). Anyone who mounts P1 (ext4, no encryption) "
        "can read the passphrase and extract the full FortiwebCM Django application, "
        "private keys, and all configuration. Confirmed: gpg --batch --passphrase decrypts "
        "successfully to a valid gzip archive."
    ),
    "impact": (
        "Complete application source disclosure. All other findings below are derived "
        "from this extraction. Passphrase is static across all FWM deployments."
    ),
    "repro": (
        "sudo qemu-nbd --read-only --connect=/dev/nbd0 FWM_VM_DISK.vmdk && "
        "sudo mount -o ro /dev/nbd0p1 /mnt && "
        "gpg --batch --passphrase 'HyP>LHD3zMvHi/Ev' -o /tmp/out.tgz -d /mnt/install/image.out && "
        "tar -xzf /tmp/out.tgz"
    ),
}

FWM_F02 = {
    "id":       "FWM-F02",
    "product":  "FortiWebManager-VM 7.4.x",
    "severity": "CRITICAL",
    "class":    "Hardcoded DES Key -- Device Password Decryption",
    "location": "FortiwebCM/lib/encrypt.py:7",
    "evidence":  "key = b'\\x34\\x7c\\x08\\x94\\xe3\\x9b\\x04\\x6e'",
    "summary": (
        "encrypt.py uses a static 8-byte DES-CBC key to encrypt device interface passwords "
        "stored in /var/fwbintf_enc_passwd.txt. DES has a 56-bit effective key length "
        "(broken since 1998 EFF DES Cracker). With the static key disclosed via FWM-F01, "
        "all stored device credentials are immediately decryptable. "
        "decrypt_enc_password() XORs a 4-byte random IV prefix into the CBC IV, "
        "then decrypts -- trivially reversible with the known static key."
    ),
    "decrypt_code": (
        "from Crypto.Cipher import DES; import base64\n"
        "key = b'\\x34\\x7c\\x08\\x94\\xe3\\x9b\\x04\\x6e'\n"
        "enc = base64.b64decode(stored_enc_password)\n"
        "iv = bytearray(8); iv[:4] = enc[:4]\n"
        "DES.new(key, DES.MODE_CBC, bytes(iv)).decrypt(enc[4:])"
    ),
}

FWM_F03 = {
    "id":       "FWM-F03",
    "product":  "FortiWebManager-VM 7.4.x",
    "severity": "CRITICAL",
    "class":    "Static Django SECRET_KEY -- Session Cookie Forgery",
    "location": "FortiwebCM/FortiwebCM/settings.py:85",
    "evidence":  "SECRET_KEY = '6nx%2_8g_$i8swg#yr-qol&k-@lruu^k$g=(n0vdrepet99z6+'",
    "summary": (
        "Django SECRET_KEY is hardcoded and static across all FortiWebManager deployments. "
        "Django uses SECRET_KEY to HMAC-sign session cookies and CSRF tokens. "
        "With SECRET_KEY known, an attacker can forge valid session cookies for any user "
        "(including admin) without credentials. "
        "Additionally, request_hash in AuthToken.get_request_hash() is SHA1(SECRET_KEY + IP + UA + port) "
        "-- with the known key and controlled IP/UA, token hashes are precomputable."
    ),
    "impact": "Unauthenticated admin session creation. No credentials required.",
}

FWM_F04 = {
    "id":       "FWM-F04",
    "product":  "FortiWebManager-VM 7.4.x",
    "severity": "HIGH",
    "class":    "Hardcoded Default Credentials -- PostgreSQL, RabbitMQ, Grafana",
    "location": "FortiwebCM/FortiwebCM/settings.py",
    "evidence": {
        "postgresql": "NAME='fwbcm', USER='admin', PASSWORD='fortinet', HOST='localhost', PORT='5432'",
        "rabbitmq":   "BROKER_URL = 'amqp://guest:guest@localhost:5672//'",
        "grafana":    "GRAFANA_PASSWORD = 'admin', GRAFANA_ADMIN_USER = 'admin'",
    },
    "summary": (
        "Three internal services use hardcoded default credentials. "
        "PostgreSQL fwbcm DB: admin/fortinet. "
        "RabbitMQ broker: guest/guest (RabbitMQ default, management UI at :15672). "
        "Grafana admin: admin/admin. "
        "Each is a lateral movement or data exfiltration path if an attacker reaches "
        "the server via any vector (e.g. SSRF from FWM web application)."
    ),
}

FWM_F05 = {
    "id":       "FWM-F05",
    "product":  "FortiWebManager-VM 7.4.x",
    "severity": "HIGH",
    "class":    "LDAP TLS Verification Disabled Globally",
    "location": "FortiwebCM/FortiwebCM/settings.py:79",
    "evidence":  "AUTH_LDAP_GLOBAL_OPTIONS = {ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_NEVER}",
    "summary": (
        "Global python-ldap option OPT_X_TLS_REQUIRE_CERT is set to OPT_X_TLS_NEVER, "
        "disabling TLS certificate verification for ALL LDAP connections. "
        "Any LDAP authentication traffic is vulnerable to MitM credential interception "
        "regardless of whether TLS is configured."
    ),
}

FWM_F06 = {
    "id":       "FWM-F06",
    "product":  "FortiWebManager-VM 7.4.x",
    "severity": "HIGH",
    "class":    "Private RSA Keys in Plaintext Application Archive",
    "location": "config/openssl_nopass.key, FortiwebCM/cooked/fds/fortinet.key",
    "evidence": {
        "openssl_nopass_key": "-----BEGIN RSA PRIVATE KEY----- (2048-bit, no passphrase) modulus prefix: 2xr1siCN3E...",
        "fortinet_fds_key":   "-----BEGIN RSA PRIVATE KEY----- (1024-bit, no passphrase) modulus prefix: 1024-bit, CN likely Fortinet FDS",
    },
    "summary": (
        "Two unprotected RSA private keys are bundled in the application archive, "
        "extracted via FWM-F01. config/openssl_nopass.key appears to be the TLS server key. "
        "cooked/fds/fortinet.key is used for FortiGuard Distribution Server communication. "
        "Both are static across deployments."
    ),
}

FWM_F07 = {
    "id":       "FWM-F07",
    "product":  "FortiWebManager-VM 7.4.x",
    "severity": "INFORMATIONAL",
    "class":    "Weak Simple Encrypt -- XOR-251 with 4-byte Random Prefix",
    "location": "FortiwebCM/lib/encrypt.py:simple_encrypt()",
    "evidence":  "b2 = b1 ^ simple_key  # simple_key = 251",
    "summary": (
        "simple_encrypt() XORs each byte with 251 and base-encodes the result. "
        "The 4-byte random prefix is not a cryptographic IV -- it provides no security. "
        "Output is trivially reversible: simple_decrypt(x) = simple_encrypt(x) with prefix stripped. "
        "Used for non-credential values; does not directly expose credentials."
    ),
}

ARCHITECTURE_NOTE = {
    "product_family": "FortiWebManager-VM -- Family C (Debian-based)",
    "differs_from": "FortiGate/FFW (Family A) and FAZ/FMG (Family B)",
    "p1_format": "Full Debian 9 root filesystem (ext4, unencrypted)",
    "application_protection": "GPG AES-CFB with static passphrase in installer script",
    "kernel": "4.19.52-default (standard mainline, no fortism LSM)",
    "base_os": "Debian GNU/Linux 9 (stretch)",
    "application_framework": "Django 1.8.16 + Celery + DRF + PostgreSQL",
}


FWM_F08 = {
    "id":       "FWM-F08",
    "product":  "FortiWebManager-VM 7.4.x",
    "severity": "CRITICAL",
    "class":    "Hardcoded Empty Admin Password -- KVM/OVF Default Credential (admin:empty)",
    "location": "FortiwebCM/api/management/commands/init_database.py:39,63",
    "evidence": (
        "adminpassword = ''  # line 39 -- default\n"
        "# No branch updates password for FWMVMB (KVM/OVF model)\n"
        "User.objects.create_superuser(adminusername, '', adminpassword)  # line 63"
    ),
    "summary": (
        "init_database.py initializes adminpassword = '' (empty string). "
        "The model-conditional branches only update it for FWM-AZE (Azure) and FWM-AW (AWS). "
        "For FWMVMB (KVM/OVF -- the most widely deployed variant), the password remains empty. "
        "Django 1.8 create_superuser() with empty password creates a valid credential (PBKDF2 hash of empty string). "
        "ANY unauthenticated user can obtain an admin auth token via POST /api/v1/auth-tokens/ with empty password. "
        "API documentation confirms: curl -d '{\"username\":\"admin\",\"password\":\"\"}' /api/v1/auth-tokens/"
    ),
    "repro": (
        "curl -sk https://<fwm-host>/api/v1/auth-tokens/ "
        "-d '{\"username\":\"admin\",\"password\":\"\"}' "
        "-H 'Content-Type: application/json'"
    ),
    "impact": "Complete unauthenticated admin access to all FortiWebManager API endpoints on default installations.",
    "aws_variant": (
        "FWM-AW (AWS): adminpassword = ec2metadata instance-id. "
        "EC2 instance IDs (i-xxxxxxxxxxxxxxxxx) are enumerable via AWS APIs and not secret. "
        "Anyone with basic AWS IAM DescribeInstances access to the account can authenticate as admin."
    ),
}

FWM_F09 = {
    "id":       "FWM-F09",
    "product":  "FortiWebManager-VM 7.4.x",
    "severity": "MEDIUM",
    "class":    "Device Interface Management Credential Exposure -- /var/fwbintf_passwd.txt",
    "location": "FortiwebCM/lib/fortiweb_api.py:19, settings.py:27",
    "evidence":  "DEVICE_DEFAULT_PASS = get_fwbintf_passwd() from /var/fwbintf_passwd.txt",
    "summary": (
        "FWM communicates with managed FortiWeb devices via SSH and HTTPS on port 44422. "
        "The management credential (admin + password from /var/fwbintf_passwd.txt) is used as default "
        "for all device API calls. Encrypted version stored in /var/fwbintf_enc_passwd.txt "
        "is DES-encrypted with the hardcoded key from FWM-F02 -- trivially decryptable. "
        "If /var/fwbintf_passwd.txt contains the default 'admin' credential, "
        "compromise of FWM = compromise of all managed FortiWeb devices."
    ),
}
