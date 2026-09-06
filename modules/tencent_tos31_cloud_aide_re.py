"""
TencentOS 3.1 — cloud-init DataSourceTencentCloud, aide, WALinuxAgent RE
Packages: cloud-init-23.4-7.tl3.8.ap.1, aide-0.16-14.tl3.1, WALinuxAgent-2.7.0.6-8.tl3
Source: gdrive:tencent-re/3.1/Updates-srpms/
"""

MODULE_ID = "tencent_tos31_cloud_aide_re"
TARGET = "TencentOS 3.1 (TLinux 3)"
BASE = "RHEL 8 / packages tagged .tl3 / .ap.1 Asia-Pacific variant"


# ---------------------------------------------------------------------------
# aide-0.16-14.tl3.1
# ---------------------------------------------------------------------------

FINDING_01 = {
    "id": "F01",
    "package": "aide-0.16-14.tl3.1",
    "cve": "CVE-2021-45417",
    "severity": "HIGH",
    "title": "encode_base64/decode_base64: fixed B64_BUF=16384 → heap overflow on large input",
    "patch": "aide-0.16-CVE-2021-45417.patch",
    "description": (
        "aide's base64 encoder in src/base64.c allocated a fixed B64_BUF=16384 byte "
        "output buffer regardless of input size. Input > 12288 bytes (base64 output "
        "4/3 ratio fills 16384 bytes) overflows into adjacent heap memory. AIDE uses "
        "base64 to encode file digests for comparison — a crafted filesystem state "
        "with a large digest output could trigger the overflow."
    ),
    "old_code": (
        "#define B64_BUF 16384\n"
        "outbuf = (char *)malloc(sizeof(char)*B64_BUF);\n"
        "/* encode loop fills outbuf, possible overflow if pos > B64_BUF */\n"
        "retbuf = (char*)malloc(sizeof(char)*(pos+1));\n"
        "memcpy(retbuf, outbuf, pos);  /* double-malloc pattern */"
    ),
    "fix": (
        "/* Removed B64_BUF constant entirely */\n"
        "size_t length = sizeof(char) * ((ssize + 2) / 3) * 4;\n"
        "outbuf = (char *)malloc(length + 1);\n"
        "/* No retbuf — outbuf returned directly; allocation exactly fits output */"
    ),
    "note": (
        "TOS 4.6 aide adds SM3 (Chinese national hash standard) support; "
        "TOS 3.1 aide-0.16 does not — only FIPS-approved algorithms remain "
        "after aide-0.16-crypto-disable-haval-and-others.patch."
    ),
}


# ---------------------------------------------------------------------------
# cloud-init-23.4-7.tl3.8.ap.1 — DataSourceTencentCloud
# Patch: 0001-add-TencentCloud-support.patch (jiaxinyyang@tencent.com, Jan 2024)
# ---------------------------------------------------------------------------

FINDING_02 = {
    "id": "F02",
    "package": "cloud-init-23.4-7.tl3.8.ap.1",
    "cve": "N/A",
    "severity": "MEDIUM",
    "title": "DataSourceTencentCloud: IMDS over HTTP only, no IMDSv2 token enforcement",
    "description": (
        "TencentOS 3.1 adds a custom cloud-init datasource for Tencent Cloud "
        "(cloudinit/sources/DataSourceTencentCloud.py). The datasource subclasses "
        "DataSourceEc2 and inherits its HTTP-based IMDS fetch logic. "
        "Two metadata endpoints, both HTTP: "
        "  - http://169.254.0.23 (link-local, Tencent CVM internal) "
        "  - http://metadata.tencentyun.com (DNS name, also internal but cleartext) "
        "No extended_metadata_versions configured, so IMDSv2 (token-gated) path "
        "is not used — the datasource uses the EC2 v1-compatible unauthenticated "
        "metadata fetch."
    ),
    "imds_detection": (
        "_is_tencentcloud() reads system-product-name from DMI: "
        "dmi.read_dmi_data('system-product-name') == 'Tencent Cloud CVM'. "
        "In nested virtualization, a crafted DMI string could spoof detection."
    ),
    "ssh_key_surface": (
        "get_public_ssh_keys() fetches 'public-keys' dict from IMDS.\n"
        "get_disassociated_public_ssh_keys() fetches 'disassociated-public-keys'.\n"
        "The disassociated keys path triggers key rotation: keys returned here "
        "are deleted from ~/.ssh/authorized_keys on the next boot. "
        "An SSRF or IMDS poisoning attack could cause legitimate SSH keys to be removed."
    ),
    "state_file": (
        "check_item_change() reads/writes /var/lib/cloud/tencentcloud.item (JSON). "
        "Tracks hostname, IP, and SSH key fingerprints between boots. "
        "File permissions inherited from /var/lib/cloud (root:root 0711). "
        "Readable only by root — no information leak but failure to update "
        "(e.g., IMDS timeout) sets changed=True, triggering spurious config re-runs."
    ),
    "config_mod_always": (
        "set_config_mod_always()/add_config_mod_always() promote cloud-config "
        "modules to run='always' mode at runtime. Modules in always mode re-execute "
        "on every boot including cc_ssh_authkey_fingerprints, cc_users_groups, etc. "
        "This is intentional for cloud key rotation but expands the cloud-data trust surface."
    ),
    "metadata_url_fallback": (
        "metadata_urls = ['http://169.254.0.23', 'http://metadata.tencentyun.com']. "
        "cloud-init tries each URL in order. On failure it falls back to the DNS name. "
        "If metadata.tencentyun.com resolves outside the expected Tencent Cloud range "
        "(e.g., DNS hijack), cloud-init fetches VM identity and SSH keys from the rogue server."
    ),
}

FINDING_03 = {
    "id": "F03",
    "package": "cloud-init-23.4-7.tl3.8.ap.1",
    "cve": "N/A",
    "severity": "LOW",
    "title": "DataSourceTencentCloud: authorized_keys deletion keyed on base64 match only",
    "description": (
        "del_authorized_keys() identifies keys to remove by comparing base64 field "
        "only — no comment or options fields considered. Two authorized_keys entries "
        "with identical base64 but different options (e.g., command= restrict) are "
        "treated as the same key. The 'better' key (from IMDS) replaces both."
    ),
    "code": (
        "for k in keys:\n"
        "    if k.base64 == ent.base64:\n"
        "        ent = k  # replace with 'our better one'\n"
        "        to_del.append(k)"
    ),
    "impact": (
        "If a VM operator has added the same public key with restrictive options "
        "(force-command, no-X11-forwarding) and the IMDS-provided key carries no "
        "options, the IMDS version wins — removing the operator's restrictions. "
        "Not exploitable from outside the Tencent IMDS trust boundary."
    ),
}


# ---------------------------------------------------------------------------
# WALinuxAgent-2.7.0.6-8.tl3
# ---------------------------------------------------------------------------

FINDING_04 = {
    "id": "F04",
    "package": "WALinuxAgent-2.7.0.6-8.tl3",
    "cve": "CVE-2019-0804",
    "severity": "LOW",
    "title": "WALinuxAgent: swapfile created with weak permissions",
    "description": (
        "WALinuxAgent (Azure Linux Guest Agent) created swap files world-readable "
        "before the CVE-2019-0804 fix. A local attacker could read swap pages "
        "containing sensitive process memory (cryptographic keys, passwords, etc.). "
        "TOS 3.1 version 2.7.0.6 includes this fix. "
        "TOS 3.1 also ships the earlier 2.3.0.2-2.tl3 variant — both are present "
        "in the Updates-srpms directory, suggesting 2.7.0.6 is the intended replacement."
    ),
    "tos_version_matrix": {
        "TOS 3.1 (Updates-srpms)": ["2.3.0.2-2.tl3", "2.7.0.6-8.tl3"],
        "TOS 4.6": "WALinuxAgent 2.9.x (covered in separate module)",
    },
}


# ---------------------------------------------------------------------------
# Cross-package: TOS 3.1 cloud security posture
# ---------------------------------------------------------------------------

CLOUD_POSTURE = {
    "summary": (
        "TOS 3.1 cloud-init adds a Tencent-specific datasource inheriting the EC2 "
        "IMDS v1 unauthenticated fetch model. The primary security surface is the "
        "HTTP IMDS trust chain: VM identity, SSH key injection, and hostname/IP "
        "assignment all originate from the unencrypted metadata endpoint. "
        "No IMDSv2-equivalent token mechanism is configured in the TOS 3.1 implementation."
    ),
    "comparison_vs_tos46": (
        "TOS 4.6 is RHEL 9-based with cloud-init 22.1 using a different patch set. "
        "The DataSourceTencentCloud addition (Jan 2024) targets the TOS 3.1 RHEL 8 line "
        "specifically. TOS 4.6 may carry the same datasource via a separate backport — "
        "not confirmed without examining 4.6 cloud-init packages."
    ),
    "aide_sm3_gap": (
        "TOS 4.6 AIDE supports SM3 (GM/T 0004-2012 Chinese national hash). "
        "TOS 3.1 aide-0.16 does not — only SHA-256, SHA-512, SHA3 via FIPS paths. "
        "Sites using TOS 3.1 and requiring SM3 file integrity checks must use TOS 4.6 aide."
    ),
}

FINDINGS = [FINDING_01, FINDING_02, FINDING_03, FINDING_04]
