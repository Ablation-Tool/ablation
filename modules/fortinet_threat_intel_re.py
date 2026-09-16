"""
Fortinet threat intelligence RE -- COATHANGER + BOLDMOVE FortiOS implants
Sources:
  - threat-intel/COATHANGER_advisory.pdf (NLD MIVD/AIVD, 2024-02-06)
  - threat-intel/COATHANGER_advisory_real.pdf
  - threat-intel/BOLDMOVE_mandiant_report.pdf (Mandiant, 2022)
  - threat-intel/mal_fortinet_coathanger_feb24.yar (NLD MIVD/JSCU)
Products: Fortinet FortiOS (FortiGate appliances)
Attribution: COATHANGER = Chinese state nexus (MIVD/AIVD); BOLDMOVE = UNC4841 (Mandiant)
"""

# ---------------------------------------------------------
# COATHANGER: FortiOS implant (2024, NLD MIVD/AIVD advisory)
# ---------------------------------------------------------
COATHANGER_OVERVIEW = {
    "malware":      "COATHANGER",
    "attribution":  "Chinese state-nexus threat actor (NLD MIVD/AIVD advisory Feb 2024)",
    "target":       "FortiGate appliances (FortiOS)",
    "initial_access": "CVE-2022-42475 (FortiOS SSL VPN heap overflow) or CVE-2023-27997",
    "persistence_mechanism": "ld.so.preload hijacking; survives firmware upgrades",
    "capability":   "Covert shell; read/write host FS; intercept FortiOS processes",
    "source":       "threat-intel/COATHANGER_advisory.pdf + mal_fortinet_coathanger_feb24.yar",
    "tlp":          "CLEAR",
}

COATHANGER_F01_PERSISTENCE = {
    "id":       "COATH-F01",
    "product":  "Fortinet FortiOS (FortiGate appliances)",
    "severity": "CRITICAL -- firmware-upgrade-persistent FortiOS implant via ld.so.preload hijacking",
    "class":    "Supply chain persistence via Linux dynamic linker preload (CWE-506)",

    "description": (
        "COATHANGER achieves persistence that survives FortiOS firmware upgrades by: "
        "1. Writing implant ELF to /data2/preload.so (writable partition). "
        "2. Modifying /etc/ld.so.preload to include /data2/preload.so. "
        "3. On every process startup, ld.so loads preload.so BEFORE all other libraries. "
        "4. The implant hooks FortiOS process functions to hide itself and maintain C2. "
        "/data2/ is a persistent data partition that survives firmware upgrades on FortiGate. "
        "Implication: firmware upgrade detection bypass -- standard Fortinet 'recover firmware' "
        "does not wipe /data2/; the implant reactivates post-upgrade."
    ),

    "persistence_files": {
        "/data2/preload.so":    "Implant shared library loaded by ld.so on every process start",
        "/etc/ld.so.preload":   "Modified to include /data2/preload.so",
        "/data2/httpsd":        "Backdoored httpsd replacement (FortiOS web daemon)",
        "/data2/authd":         "Backdoored authd replacement (FortiOS auth daemon)",
        "/tmp/packfile":        "Temporary payload staging file",
        "/data2/smartctl":      "Masquerades as smartctl (S.M.A.R.T. tool) for C2 comms",
        "/newcli":              "Backdoor CLI binary",
    },

    "beacon_signature": {
        "method":  "COATHANGER beacon mimics HTTP GET to www.google.com",
        "bytes":   "{ 48 B8 47 45 54 20 2F 20 48 54 48 89 45 B0 48 B8 54 50 2F 32 0A ... }",
        "decoded": "GET / HTTP/2\\nHost: www.google.com (constructed inline with x64 MOV immediate ops)",
        "note":    "C2 traffic disguised as Google HTTP requests; detected by byte pattern not content",
    },

    "yara_detection": {
        "rule_beacon": "MAL_Fortinet_COATHANGER_Beacon: ELF magic + $chunk_1 (x64 HTTP header construction bytes)",
        "rule_files":  "MAL_Fortinet_COATHANGER_Files: ELF magic + 4+ of {/data2/, /httpsd, /preload.so, /authd, /tmp/packfile, /smartctl, /etc/ld.so.preload, /newcli, /bin/busybox}",
    },

    "re_relevance": (
        "ld.so.preload hijacking requires writable /data2/ partition. "
        "FortiOS mounts /data2/ as a persistent ext4 partition. "
        "Ablation semantic sweep on FortiOS binaries for filesystem write operations "
        "to /data2/ and /etc/ld.so.preload reveals what processes have write capability. "
        "Detection: compare /etc/ld.so.preload hash against known-good; "
        "check for non-Fortinet ELFs in /data2/."
    ),
}

COATHANGER_F02_PROCESS_HIDING = {
    "id":       "COATH-F02",
    "product":  "Fortinet FortiOS (FortiGate appliances)",
    "severity": "HIGH -- COATHANGER hooks FortiOS process management to hide implant files/processes",
    "class":    "Rootkit-style process hiding via LD_PRELOAD function interposition (CWE-506)",

    "description": (
        "The preload.so implant intercepts libc functions used by FortiOS admin tools: "
        "readdir(), stat(), open() -- to hide files in /data2/ from directory listings. "
        "Intercepted ps/top output hides the COATHANGER C2 process. "
        "COATHANGER also patches the FortiOS IPS process (miglogd?) or other daemons "
        "to prevent detection via FortiOS internal health checks. "
        "The httpsd/authd replacements maintain the original function behavior "
        "while adding backdoor capability -- FortiOS functionality appears normal."
    ),

    "evasion_techniques": [
        "LD_PRELOAD / ld.so.preload interposition of readdir/stat/open",
        "Process name masquerading (/data2/smartctl mimics smartctl binary)",
        "C2 traffic mimics Google HTTP GET requests",
        "Survives firmware upgrades via /data2/ persistence",
        "Hides own ELF from FortiOS file integrity checks",
    ],

    "re_relevance": (
        "FortiOS file integrity checking (if enabled) uses paths from a known-good manifest. "
        "If the manifest is not stored on a separate read-only partition, COATHANGER can modify it. "
        "Ablation semantic sweep for 'file integrity', 'hash verify', 'manifest' in FortiOS binaries "
        "reveals the integrity checking implementation -- a target for COATHANGER-style bypass."
    ),
}


# ---------------------------------------------------------
# BOLDMOVE: FortiOS implant (2022, Mandiant/UNC4841)
# ---------------------------------------------------------
BOLDMOVE_OVERVIEW = {
    "malware":      "BOLDMOVE",
    "attribution":  "UNC4841 (Mandiant) -- Chinese state nexus",
    "target":       "Fortinet FortiGate (FortiOS) via FortiEmail gateway (CVE-2023-27997 or FortiOS SSLYF)",
    "initial_access": "CVE-2022-42475 (FortiOS heap overflow) or related FortiEmail vulnerability",
    "variants":     ["Linux ELF (FortiOS/FortiGate)", "Windows ELF"],
    "capability":   "Full-featured backdoor; shell access; file read/write; network tunneling",
    "source":       "threat-intel/BOLDMOVE_mandiant_report.pdf (Mandiant, 2022)",
    "tlp":          "CLEAR (public Mandiant report)",
}

BOLDMOVE_F01_FORTIOS_SPECIFIC = {
    "id":       "BM-F01",
    "product":  "Fortinet FortiOS (FortiGate appliances)",
    "severity": "CRITICAL -- BOLDMOVE backdoor has FortiOS-specific extensions reading internal FortiOS structs",
    "class":    "Platform-specific implant with FortiOS internal API knowledge (CWE-506)",

    "description": (
        "BOLDMOVE's Linux variant has FortiOS-specific code that: "
        "1. Reads FortiOS internal data structures to extract device configuration. "
        "2. Uses FortiOS-specific paths and binaries to maintain stealth. "
        "3. Has a FortiOS version check routine that branches on specific firmware versions. "
        "4. Communicates over port 443 (HTTPS) or 8888 -- blends with FortiGate management traffic. "
        "The FortiOS-specific code suggests the attacker had deep knowledge of FortiOS internals "
        "or had access to FortiOS source code or JTAG debugging during development. "
        "BOLDMOVE reads FortiOS's internal configuration database (cmdb) directly "
        "to extract credentials and network topology without using the FortiOS CLI."
    ),

    "fortios_internals_accessed": [
        "FortiOS cmdb (configuration database) -- direct file read, not via CLI",
        "FortiOS sslvpn session data -- extracts active SSL VPN sessions",
        "FortiOS admin credential hashes -- from cmdb",
        "Network interface configuration -- from FortiOS internal structs",
    ],

    "c2_protocol": {
        "port":     "443 (HTTPS) or 8888",
        "encoding": "Custom binary protocol over TLS",
        "features": ["remote shell", "file upload/download", "SOCKS proxy tunnel", "port forwarding"],
    },

    "re_relevance": (
        "BOLDMOVE's ability to read cmdb directly means the cmdb file format is fully reversible. "
        "Ablation semantic sweep for 'cmdb' and 'config database' operations in FortiOS binaries "
        "reveals the internal config storage format used by both FortiOS and implants like BOLDMOVE. "
        "Understanding this format enables: config extraction from disk images, "
        "offline credential recovery (complements CVE-2019-6693 AES key for encrypted fields)."
    ),
}

BOLDMOVE_F02_EVASION = {
    "id":       "BM-F02",
    "product":  "Fortinet FortiOS (FortiGate appliances)",
    "severity": "HIGH -- BOLDMOVE has specific FortiOS process injection and evasion techniques",
    "class":    "Process injection / function hooking specific to FortiOS daemons (CWE-506)",

    "description": (
        "BOLDMOVE injects into FortiOS daemons to evade detection: "
        "1. Hooks FortiOS's /bin/miglogd (log daemon) to suppress implant activity from system logs. "
        "2. Injects into sslvpnd or httpsd to intercept authentication traffic. "
        "3. Modifies FortiOS startup scripts to persist across reboots. "
        "The Mandiant report notes BOLDMOVE is 'one of the most sophisticated malware families "
        "targeting Fortinet products' due to its platform-specific FortiOS knowledge."
    ),

    "log_suppression_targets": [
        "/bin/miglogd (FortiOS log daemon)",
        "/bin/httpsd (web admin interface)",
        "/bin/sslvpnd (SSL VPN daemon)",
        "FortiOS system audit log (/var/log/audit.log or FortiLog equivalent)",
    ],

    "re_relevance": (
        "miglogd is the FortiOS process responsible for all log event generation. "
        "Hooking miglogd allows complete log suppression. "
        "Ablation semantic sweep for 'log', 'audit', 'syslog' function calls in miglogd binary "
        "reveals the internal logging API -- relevant for developing FortiOS log integrity monitoring "
        "and detecting BOLDMOVE-style suppression."
    ),
}


# ---------------------------------------------------------
# Cross-implant analysis: FortiOS persistent compromise patterns
# ---------------------------------------------------------
FORTIOS_IMPLANT_PATTERNS = {
    "id":       "TI-SYSTEMIC",
    "product":  "Fortinet FortiOS (all FortiGate appliances)",
    "severity": "CRITICAL -- systemic: FortiOS architecture enables firmware-upgrade-persistent implants",
    "class":    "Platform architecture enables persistent implant deployment",

    "common_persistence_paths": {
        "/data2/":           "Persistent ext4 partition; survives firmware upgrade",
        "/etc/ld.so.preload": "Controls what shared libraries load before libc in every process",
        "/bin/miglogd":      "Log daemon; hooking suppresses all audit trails",
        "/bin/busybox":      "Shell access; replacement enables arbitrary command execution",
    },

    "common_initial_access_cves": [
        "CVE-2022-42475 (FortiOS SSL VPN heap overflow, CVSS 9.3)",
        "CVE-2023-27997 (FortiOS SSL VPN heap overflow, CVSS 9.8)",
        "CVE-2024-21762 (FortiOS SSL VPN OOB write, CVSS 9.6)",
        "CVE-2024-55591 (FortiOS WebSocket auth bypass, CVSS 9.6)",
    ],

    "fortios_architecture_weaknesses": [
        "/data2/ partition is writable and persists across upgrades -- enables firmware-persistent implants",
        "ld.so.preload is modifiable with root access -- enables process-wide function interposition",
        "FortiOS lacks Secure Boot on older hardware -- allows unsigned firmware modifications",
        "cmdb (config database) is stored in plaintext or with AES-128 (Mary had a littl key) on disk",
        "No mandatory code signing for binaries in /data2/ or /tmp/",
    ],

    "detection_gaps": (
        "FortiOS file integrity checking: verify if Fortinet signs binary integrity manifests "
        "stored on a separate read-only partition (if writable, COATHANGER can modify it). "
        "FortiOS log integrity: miglogd hooking means logs cannot be trusted on a compromised device. "
        "FortiOS IDS: no kernel-level integrity monitoring (eBPF, AIDE-equivalent) on FortiOS. "
        "Incident response: /data2/ must be separately imaged; firmware upgrade alone does NOT remediate."
    ),

    "remediation_note": (
        "Per MIVD/AIVD advisory: firmware upgrade is INSUFFICIENT for COATHANGER removal. "
        "Required: factory reset + /data2/ wipe + verify ld.so.preload is clean + "
        "verify all binaries in /bin/ against Fortinet-provided hashes."
    ),
}
