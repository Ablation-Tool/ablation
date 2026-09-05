"""
TencentOS 4.6 — cloud-init DataSourceTencentCloud reverse engineering.

Source: /usr/lib/python3.11/site-packages/cloudinit/sources/DataSourceTencentCloud.py
Python source (not compiled), 279 lines.

DataSourceTencentCloud extends DataSourceEc2 (AWS EC2 datasource).
It provides TencentCloud CVM (Cloud Virtual Machine) specific behavior
for cloud-init on TOS 4.6 instances.
"""

METADATA = {
    "source": "/usr/lib/python3.11/site-packages/cloudinit/sources/DataSourceTencentCloud.py",
    "language": "Python 3.11",
    "base_class": "DataSourceEc2.DataSourceEc2",
    "product_name": "Tencent Cloud CVM",
    "min_metadata_version": "2017-09-19",
    "extended_metadata_versions": [],
}

IMDS_ENDPOINTS = {
    "primary": "http://169.254.0.23",
    "secondary": "http://metadata.tencentyun.com",
    "protocol": "HTTP (plaintext)",
    "auth": "None — unauthenticated link-local HTTP",
    "vs_aws": "AWS uses 169.254.169.254; Tencent uses 169.254.0.23",
    "note": (
        "SSRF filters that only block 169.254.169.254 (AWS IMDS) "
        "do NOT block TencentCloud IMDS at 169.254.0.23. "
        "Any SSRF on a TencentCVM that reaches 169.254.0.23 returns "
        "instance credentials, SSH keys, hostname, and runcmd payloads."
    ),
}

METADATA_FIELDS = {
    "runcmd": {
        "source": "metadata.get('runcmd', [])",
        "effect": "Queued for shell execution during cloud-init config stage",
        "trigger": "cloud_config_modules runcmd always when hostname changes",
        "security": (
            "runcmd content is fetched from IMDS and executed as root. "
            "IMDS response modification (via SSRF, ARP spoofing, or "
            "cloud-init re-trigger with malicious user-data) gives RCE."
        ),
    },
    "password": {
        "source": "metadata.get('password')",
        "effect": "Sets root/user password via chpasswd; also enables ssh_pwauth",
        "code": "self.cfg['chpasswd'] = {'expire': False, 'list': [passwd]}",
        "security": "Root password controlled by IMDS — metadata exposure = credential exposure",
    },
    "public-keys": {
        "source": "metadata.get('public-keys', {})",
        "effect": "Appended to ~/.ssh/authorized_keys for root or ubuntu user",
        "parse_func": "parse_users_config / parse_public_keys",
        "security": "IMDS injection adds attacker SSH key to root's authorized_keys",
    },
    "disassociated-public-keys": {
        "source": "metadata.get('disassociated-public-keys', {})",
        "effect": "Removes keys from authorized_keys (del_user_keys call)",
        "security": "IMDS injection removes legitimate SSH keys (availability attack)",
    },
    "hostname": {
        "source": "metadata.get('hostname')",
        "default": "localhost.localdomain",
        "effect": "Sets system hostname; triggers update_etc_hosts",
    },
    "ntp": {
        "source": "metadata.get('ntp', {})",
        "effect": "NTP server configuration via unverified_modules=['ntp']",
        "security": (
            "NTP servers from IMDS are applied via unverified_modules — "
            "the 'unverified' flag allows running even if the module is not "
            "in the verified list. Attacker-controlled NTP servers."
        ),
    },
}

PLATFORM_DETECTION = {
    "method": "dmi.read_dmi_data('system-product-name') == 'Tencent Cloud CVM'",
    "dmi_path": "/sys/class/dmi/id/product_name",
    "todo_comment_chinese": (
        "# todo:\n"
        "# 1, 通过DMI数据判断是否腾讯云平台。DMI数据：/sys/class/dmi/id/product_name\n"
        "# 2, 添加EC2.Platforms.TENCENTCLOUD"
    ),
    "todo_translation": (
        "TODO: 1. Judge TencentCloud platform via DMI data: /sys/class/dmi/id/product_name. "
        "2. Add EC2.Platforms.TENCENTCLOUD constant."
    ),
    "cloud_platform_property": "Returns hardcoded 'TencentCloud' string without verification",
    "security": (
        "The cloud_platform property has an unimplemented TODO — platform detection is "
        "not fully implemented. The property returns 'TencentCloud' unconditionally "
        "without performing the DMI check. Any system that satisfies the datasource "
        "election (DMI product name match) runs as TencentCloud even if the DMI "
        "check is bypassed. A VM spoofing DMI product_name = 'Tencent Cloud CVM' "
        "triggers the TencentCloud datasource on any cloud-init system."
    ),
}

ITEM_CHANGE_TRACKING = {
    "file": "/var/lib/cloud/tencentcloud.item",
    "format": "JSON dict: {item_name: item_value}",
    "purpose": "Tracks previous values to detect changes (password, hostname, ssh_key)",
    "race_condition": (
        "check_item_change() at line 53: "
        "open(item_path, 'r') then (if changed) open(item_path, 'w'). "
        "TOCTOU window between read and write. "
        "If /var/lib/cloud/ is writable by an attacker (non-standard), "
        "a carefully timed write to tencentcloud.item can prevent "
        "password/SSH-key changes from being applied (DoS on key rotation)."
    ),
    "exception_handling": (
        "If any exception occurs during read/write, changed=True is forced. "
        "Exception swallowed with LOG.debug only — file corruption silently "
        "triggers 'always apply' mode."
    ),
}

AUTHORIZED_KEYS_HANDLING = {
    "del_authorized_keys": {
        "location": "line 82",
        "logic": "Matches old entries by base64 fingerprint, removes from file",
        "note": "del_authorized_keys replaces entry with 'better' key if base64 matches",
    },
    "del_user_keys": {
        "location": "line 103",
        "creates_dir": "ssh_util.users_ssh_info creates .ssh dir if missing (mode 0o700)",
        "selinux": "util.SeLinuxGuard wraps write for SELinux label restoration",
    },
    "parse_users_config": {
        "location": "line 253",
        "input": "public-keys dict from IMDS",
        "extracts": ["key_body['user']", "key_body.get('openssh-key', '')"],
        "no_sanitization": (
            "user field from IMDS is used directly as the username in the "
            "users config dict. No validation that username is a valid system user. "
            "If cloud-init user creation trusts this name, injection of special "
            "characters could affect user provisioning."
        ),
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "IMDS at 169.254.0.23 (not 169.254.169.254) — bypasses AWS-centric SSRF filters",
        "detail": (
            "TencentCloud IMDS primary endpoint is http://169.254.0.23 (plaintext HTTP). "
            "AWS-focused SSRF mitigations blocklist 169.254.169.254 (AWS) or use IMDSv2 tokens. "
            "169.254.0.23 is a different IP in the same link-local range (169.254.0.0/16) "
            "but would not be caught by AWS-specific SSRF blocklists. "
            "Any SSRF vulnerability in a TencentCVM application that can reach 169.254.0.23 "
            "returns instance metadata including SSH keys, hostname, and runcmd payloads. "
            "Secondary endpoint: http://metadata.tencentyun.com — DNS-resolvable hostname "
            "that may not be blocked by SSRF filters at all."
        ),
        "imds_primary": "http://169.254.0.23",
        "imds_secondary": "http://metadata.tencentyun.com",
        "api_version": "2017-09-19",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "runcmd pulled from IMDS and executed as root during cloud-init config stage",
        "detail": (
            "Line 133: self.cfg['runcmd'] = self.metadata.get('runcmd', []). "
            "This runcmd list is passed to the cloud-init runcmd module and executed "
            "as root via /bin/sh. "
            "Trigger conditions: hostname change (adds runcmd to 'always' mode via "
            "set_config_mod_always). "
            "Attack vector: modify IMDS response for 'runcmd' key before cloud-init re-runs "
            "(e.g., via user-data update on CVM console, IMDS SSRF injection, or "
            "ARP spoofing of 169.254.0.23 link-local)."
        ),
        "code_ref": "line 133: self.cfg['runcmd'] = self.metadata.get('runcmd', [])",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Root password delivered via IMDS plaintext — metadata exposure = credential exposure",
        "detail": (
            "Line 140-146: if passwd := metadata.get('password'), sets chpasswd with expire=False. "
            "The password is fetched via unauthenticated HTTP to 169.254.0.23. "
            "On shared network segments (bare metal, misconfigured VPC), "
            "the password is visible in plaintext IMDS response. "
            "check_item_change stores the password value in /var/lib/cloud/tencentcloud.item "
            "as a JSON file — the password is written to disk in plaintext."
        ),
        "disk_persistence": "/var/lib/cloud/tencentcloud.item (plaintext JSON)",
        "code_ref": "line 143: self.cfg['chpasswd'] = {'expire': False, 'list': [passwd]}",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "cloud_platform property returns hardcoded 'TencentCloud' without verification (TODO unimplemented)",
        "detail": (
            "The cloud_platform property (line 214) has a Chinese-language TODO comment: "
            "'Judge TencentCloud platform via DMI data /sys/class/dmi/id/product_name'. "
            "The property body returns 'TencentCloud' unconditionally without implementing "
            "the check. Platform detection for datasource election uses _is_tencentcloud() "
            "at line 224 (DMI check is there), but the cloud_platform property itself is broken. "
            "Any downstream code querying cloud_platform for conditional behavior gets "
            "'TencentCloud' regardless of actual platform."
        ),
        "chinese_todo": "通过DMI数据判断是否腾讯云平台",
        "code_ref": "line 214-221: cloud_platform property always returns 'TencentCloud'",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "NTP servers from IMDS applied via unverified_modules — attacker-controlled time source",
        "detail": (
            "Line 136: 'unverified_modules': ['ntp'] with ntp config from metadata. "
            "The 'unverified_modules' key allows cloud-init to run the ntp module "
            "even if it's not in the verified list. "
            "NTP servers from IMDS are applied to the system. "
            "An attacker who controls IMDS responses can set NTP servers to "
            "attacker-controlled hosts, enabling time-based attack surfaces "
            "(certificate validity bypass, replay window expansion, Kerberos ticket attacks)."
        ),
        "code_ref": "line 136: 'unverified_modules': ['ntp']",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "SSRF-accessible disassociated-public-keys removes authorized_keys entries",
        "detail": (
            "Line 162-167: disassociated-public-keys from IMDS triggers del_user_keys. "
            "An attacker who can inject IMDS responses or modify user-data can "
            "specify a victim's public key in disassociated-public-keys, "
            "causing cloud-init to remove it from authorized_keys. "
            "This is an availability attack: legitimate SSH access is revoked "
            "without the instance owner's knowledge."
        ),
        "code_ref": "line 162: disassociated_ssh_keys = self.get_disassociated_public_ssh_keys()",
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "parse_users_config extracts username from IMDS public-keys.*.user without sanitization",
        "detail": (
            "Line 253-267: parse_users_config iterates public-keys dict, uses k_body['user'] "
            "as the username in the users config. No validation that the username is a valid "
            "POSIX username. If cloud-init's users-groups module processes this without "
            "sanitization, special characters in the user field may affect user provisioning. "
            "The KeyError on missing 'user' key (line 257: k_body['user']) would cause an "
            "unhandled exception if IMDS omits the key — cloud-init may silently fail "
            "or skip the key entry."
        ),
        "code_ref": "line 257: name = k_body['user']  # no .get(), raises KeyError if missing",
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "check_item_change writes metadata values (including password) to /var/lib/cloud/tencentcloud.item",
        "detail": (
            "Line 63-79: check_item_change persists metadata values to disk as JSON. "
            "This includes the password (if present in IMDS metadata). "
            "File is created with default umask — likely world-readable depending on umask. "
            "If world-readable, local users can read the last-applied password from disk. "
            "Exception handling swallows all errors (LOG.debug only), meaning a broken "
            "item file causes check_item_change to always return changed=True, "
            "triggering always-mode for all modules."
        ),
        "disk_path": "/var/lib/cloud/tencentcloud.item",
        "code_ref": "line 72: with open(item_path, 'w') as f: json.dump(d_item, f)",
    },
]

if __name__ == '__main__':
    print(f"DataSourceTencentCloud — {len(FINDINGS)} findings")
    print(f"IMDS primary: {IMDS_ENDPOINTS['primary']}")
    print(f"IMDS note: {IMDS_ENDPOINTS['note'][:80]}...")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
