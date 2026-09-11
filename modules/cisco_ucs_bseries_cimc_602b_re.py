"""
Cisco UCS B-Series CIMC 6.0.2b — RE module
Target: ucs-b200-m6-k9-cimc.6.0.2.260040.bin (51MB, extracted from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Source: /media/cowboy/research/Cisco-UCS/b-series/ucs-k9-bundle-b-series.6.0.2b.B.bin
Build path leaked: /sums/build/BSeriesM6/

B-Series bundle structure:
  offset 0:     Cisco SN header (852 bytes; magic=6401534E, hsize=0354)
  offset 852:   gzip → tar archive (582 entries: plugin_img CIMC, VIC, BIOS, RAID, storage)
  Inner CIMC structure (ucs-b200-m6-k9-cimc.6.0.2.260040.bin):
    SN header:  776 bytes (hsize=0308)
    blob:       52567896 bytes tar containing ./blob (52MB) + ./isan/etc/imghdr.bin (776B)

CIMC blob structure:
  header:       55aa0007 000c804d (Cisco proprietary B-Series CIMC container)
  offset 689920: U-Boot uImage — Linux 5.15.196.1 kernel, ARM 32-bit, no compression
                 load=0x81008000, entry=0x81008000, size=14942338B
  offset 16254720: SquashFS primary (zlib, 4.0, 5689 inodes, 24.85MB)
  offset 42315520: SquashFS secondary (zlib, 4.0, 765 inodes, 9.65MB)

Primary SquashFS layout: /bin /sbin /lib /etc /usr /nuova /nv /configs /debug /var
  Key binaries: usr/local/bin/credfish (Redfish auth+API daemon, 7616 strings)
                usr/local/bin/fcgi_cisco_opaque (Cisco blob FCGI, /cisco/blob/ endpoint)
                usr/local/bin/mcserver (main mgmt server, 440KB)
                lib/security/pam_bmc.so (custom PAM module; LDAP + OTP + SQLCipher)
                usr/local/lib/libjolt_cisco_opaque.so (opaque handler library)
  Web server:   usr/local/bin/nginx (port 443 TLS + ports 4101/444/445/447/9000/9005)
  Auth stack:   credfish → pam_client → pam_bmc.so → SQLCipher user DB / LDAP

Secondary SquashFS layout: /cisco/bin /cisco/etc /cisco/www /cisco/scripts
  Key binaries: cisco/bin/ucs_mgmt_cloud_connector (Intersight connector)
  Web assets:   cisco/www/ (React SPA, i18n, webcomponents)
  Scripts:      cisco/scripts/vdupgrade.sh, nvfs_update.sh, sd_update.sh

Intersight connector:
  Port 9754 local; nginx proxies /intersight/ → localhost:9754
  dc.conf: location /intersight/ { proxy_pass http://localhost:9754/; }
"""

FIRMWARE = {
    "target":   "Cisco UCS B-Series CIMC 6.0.2b (B200 M6)",
    "file":     "ucs-b200-m6-k9-cimc.6.0.2.260040.bin",
    "kernel":   "Linux 5.15.196.1 ARM 32-bit (U-Boot uImage)",
    "rootfs":   "SquashFS 4.0 zlib (24.85MB primary, 9.65MB secondary)",
    "findings": ["BSERIES-F1", "BSERIES-F2", "BSERIES-F3"],
}

# BSERIES-F1: nginx serves /nv/scratchpad/ with autoindex on and no authentication
BSERIES_F1 = {
    "id":       "BSERIES-F1",
    "title":    "nginx serves /nv/scratchpad/ with autoindex on and no authentication — "
                "pre-auth directory listing and file read on CIMC HTTPS port 443",
    "severity": "HIGH",
    "status":   "CONFIRMED — nginx.conf.template extracted from primary SquashFS; "
                "location block verbatim, no auth_request, no auth_basic, no FastCGI auth wrapper",
    "cwe":      ["CWE-284 (Improper Access Control)", "CWE-538 (File and Directory Information Exposure)"],
    "file":     "usr/local/nginx/conf/nginx.conf.template",
    "verbatim_nginx_block": """
        # nv
        location /nv/scratchpad/ {
            root /;
            autoindex on;
        }
        # nv
""",
    "exploit_sketch": "curl -k https://<cimc-ip>/nv/scratchpad/  # directory listing, no creds required",
    "files_at_risk": {
        "vic_tech_uploads":  "/nv/scratchpad/vic_tech_uploads/  — VIC tech support files (nginx client_body_temp_path from /vic_upload/ PUT)",
        "vic_core_uploads":  "/nv/scratchpad/vic_core_temp_uploads/  — VIC core files (port 9005 /vic_core_upload/)",
        "any_cimc_process":  "any CIMC service that writes to /nv/scratchpad/ during normal operation",
    },
    "context": {
        "port":     "443 (external TLS, dual-stack IPv6+IPv4)",
        "auth":     "NONE — the location block has no auth directives",
        "other_locations": "all other sensitive endpoints (/redfish/, /cisco/blob/, /vic_upload/) route through FastCGI daemons that enforce auth",
        "only_exception": "/nv/scratchpad/ is a static file serve with autoindex — no FastCGI, no auth_request",
    },
    "threat_model": "Unauthenticated network attacker connected to CIMC management port reads "
                    "directory listing and all files in /nv/scratchpad/ — potential exposure of "
                    "VIC tech support bundles (contain network diagnostics, MAC addresses, config data) "
                    "or any other file written there by firmware processes",
}

# BSERIES-F2: Cisco Opaque handler exposes one-time boot modification
BSERIES_F2 = {
    "id":       "BSERIES-F2",
    "title":    "Cisco Opaque handler (fcgi_cisco_opaque / /cisco/blob/) exposes "
                "__jolt_cisco_opaque_set_one_time_boot — authenticated attacker can redirect "
                "next boot to attacker-controlled media via the CIMC management API",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — function __jolt_cisco_opaque_set_one_time_boot extracted from "
                "libjolt_cisco_opaque.so; nginx route /cisco/blob/ confirmed; "
                "cisco_opaque_fetch/set/read/delete primitives confirmed in fcgi_cisco_opaque binary",
    "cwe":      ["CWE-284 (Improper Access Control)", "CWE-693 (Protection Mechanism Failure)"],
    "files":    [
        "usr/local/bin/fcgi_cisco_opaque",
        "usr/local/lib/libjolt_cisco_opaque.so",
        "usr/local/nginx/conf/nginx.conf.template",
    ],
    "nginx_route": "location /cisco/blob/ { fastcgi_pass unix:/var/cisco_opaque/cisco_opaque_fcgi_handler_socket; }",
    "libjolt_functions": [
        "__jolt_cisco_opaque_fetch",
        "__jolt_cisco_opaque_fetch_with_sha",
        "__jolt_cisco_opaque_delete",
        "__jolt_cisco_opaque_set_one_time_boot",
        "__jolt_cisco_opaque_set",
        "__jolt_cisco_opaque_read",
        "set_personality",
        "delete_personality",
        "set_default_token_values",
        "set_service_profile_data",
        "set_bios_tokens_data",
    ],
    "bios_token_paths": {
        "/var/nuova/BIOS/BIOS2UCSM_Tokens":     "Bios2IntersightTokens (live BIOS → UCSM sync)",
        "/var/nuova/BIOS/UCSM2BIOS_Tokens":     "Intersight2BiosTokens (UCSM → BIOS pending tokens)",
        "/nv/etc/BIOS/bt/OneTimeConfigPolicy":   "one-time boot config policy (NV-persistent)",
        "/nv/etc/backup/ActualOrder":            "current boot order backup",
    },
    "threat_model": "An attacker with any valid CIMC credential (readonly user is sufficient if the "
                    "opaque handler doesn't gate by privilege) can call /cisco/blob/ to set "
                    "one-time boot order, redirecting the next server reboot to a PXE/USB/ISO "
                    "controlled by the attacker — bypassing Secure Boot at the boot sequence level",
    "note": "Distinct from CSERIES-F6 (bios_config D-Bus property on C-Series OpenBMC). "
            "This is the B-Series CIMC's own proprietary opaque API which wraps BIOS token "
            "management behind the /cisco/blob/ HTTP endpoint. The function name confirms "
            "one-time-boot is an exposed operation, not just a read-only status.",
    "requires_auth": True,
}

# BSERIES-F3: FI shadow password stored in predictable NV location
BSERIES_F3 = {
    "id":       "BSERIES-F3",
    "title":    "FI shadow password stored at /nv/security/fi_shadow — predictable NV path "
                "for Fabric Interconnect authentication credential ('SldpShadowPasswordAuth'), "
                "readable by any process with NV access",
    "severity": "MEDIUM",
    "status":   "CANDIDATE — string SldpShadowPasswordAuth and path /nv/security/fi_shadow "
                "extracted from libjolt_cisco_opaque.so; NV storage is persistent, unencrypted "
                "storage layer; credential format (hash vs plaintext) unconfirmed",
    "cwe":      ["CWE-256 (Plaintext Storage of Password)", "CWE-312 (Cleartext Storage of Sensitive Information)"],
    "file":     "usr/local/lib/libjolt_cisco_opaque.so",
    "verbatim_strings": {
        "label":  "SldpShadowPasswordAuth",
        "path":   "/nv/security/fi_shadow",
    },
    "context": {
        "nv_layout": "/nv/ is the B-Series CIMC non-volatile storage, mounted from flash, "
                     "persistent across reboots; contains /nv/etc/, /nv/security/, /nv/log/",
        "fi_sync":   "SLDP = Service Link Discovery Protocol — used for FI ↔ blade CIMC communication; "
                     "fi_shadow is the FI auth credential stored on the blade CIMC side",
        "opaque_read_path": "libjolt_cisco_opaque.so exposes __jolt_cisco_opaque_read which reads from "
                             "/nv/etc/backup/ paths; fi_shadow is in /nv/security/ — separate from backup "
                             "but same NV mount point",
        "other_nv_security_paths": [
            "/nv/security/audit_log/",
            "/nv/security/ldap/LDAPCert.pem",
            "/nv/security/mTLS-common/mTLS_ca_store.pem",
        ],
    },
    "threat_model": "An attacker who gains filesystem read access to /nv/ (e.g., via physical access, "
                    "exploited CIMC bug, or from the host OS over the PPP BMC-to-host bridge at "
                    "169.254.254.1) reads /nv/security/fi_shadow and recovers the FI authentication "
                    "credential — enabling lateral movement from blade CIMC to the Fabric Interconnect "
                    "that controls all blade networking",
}

FINDINGS = [BSERIES_F1, BSERIES_F2, BSERIES_F3]
