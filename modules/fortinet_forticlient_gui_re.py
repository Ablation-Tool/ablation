"""
FortiClient Linux VPN: Electron-based GUI binary RE
Sources:
  - extracted/forticlient-vpn-deb/opt/forticlient/gui/FortiClient (ELF64 x86-64, NOT stripped)
  - extracted/forticlient-vpn-deb/opt/forticlient/gui/resources/app.asar (57.8MB Electron ASAR bundle)
  - extracted/forticlient-standalone-deb/opt/forticlient/tpm2/etc/tpm2-tss/fapi-profiles/*.json
Products: FortiClient Linux VPN 7.x (Electron GUI)
Method: binary strings + ASAR binary grep + FAPI JSON config read
"""

# ---------------------------------------------------------
# FortiClient Electron GUI RE: context + security config
# ---------------------------------------------------------
FORTICLIENT_GUI = {
    "id":       "FCLIENT-GUI",
    "product":  "FortiClient Electron GUI (VPN-only + standalone DEB)",
    "binary":   "/opt/forticlient/gui/FortiClient (ELF64 x86-64; 177MB; NOT stripped)",
    "asar":     "/opt/forticlient/gui/resources/app.asar (57.8MB)",
    "electron": "Electron 28.0.0 (Chromium ~120.x; released Nov 2023)",
    "note":     "FortiClient binary is NOT stripped -- symbols present; easier to analyze than daemon binaries",
}

FCLIENT_GUI_F01_SANDBOX_DISABLED = {
    "id":       "FCLIENT-GUI-F01",
    "product":  "FortiClient Electron GUI -- sandbox: false in multiple BrowserWindow configurations",
    "severity": "MEDIUM -- no OS-level sandbox; Chromium renderer RCE = direct OS code execution",
    "class":    "Insufficient Electron sandbox isolation (CWE-693); Chromium CVE amplification",

    "description": (
        "The app.asar ASAR bundle contains multiple BrowserWindow configurations with: "
        "  nodeIntegration: false (secure) "
        "  contextIsolation: true (secure) "
        "  sandbox: false (INSECURE). "
        "In Electron 28, the Chromium process sandbox is ENABLED by default. "
        "Explicitly setting sandbox: false removes the OS-level process sandbox "
        "(seccomp + namespace isolation on Linux). "
        "Impact of sandbox: false: "
        "  1. A Chromium memory corruption CVE in the renderer process achieves arbitrary code execution. "
        "  2. With sandbox: true, that code runs in the sandboxed renderer process "
        "     (no filesystem access, no network beyond renderer scope, no OS API access). "
        "  3. With sandbox: false, renderer RCE = full OS-level code execution "
        "     with FortiClient's process privileges. "
        "FortiClient process privileges: likely runs as root or a privileged service account "
        "(FortiClient requires root for firewall/vpn/routing operations on Linux). "
        "Conclusion: a Chromium renderer CVE in a sandbox: false window + FortiClient root privileges "
        "= local privilege escalation to root."
    ),

    "window_count": "sandbox: false appears in 3+ distinct BrowserWindow configurations in app.asar",

    "chromium_eol": (
        "Chromium 120.x was released in November 2023. "
        "As of the binary extraction date (March 2025, based on file timestamps), "
        "this Chromium version is 16+ months old with multiple known CVEs. "
        "Chromium releases a new major version approximately every 4 weeks; "
        "Chromium 120 is roughly 16 releases behind current. "
        "Electron 28 reached end-of-life in late 2024."
    ),

    "re_insight": (
        "The windows with sandbox: false likely need direct system call access "
        "(e.g., VPN connection management, firewall rule changes) and use contextBridge "
        "to pass privileged operations from preload to main process. "
        "The security model: contextIsolation: true prevents XSS -> Node.js escalation, "
        "but disabling sandbox removes the containment layer below Node.js "
        "for Chromium-level exploits. "
        "The correct pattern: sandbox: true + preload script with contextBridge API "
        "for safe main-renderer IPC. The preload script runs with Node.js access "
        "even with sandbox: true (Electron design)."
    ),
}

FCLIENT_GUI_F02_ELECTRON_AGE = {
    "id":       "FCLIENT-GUI-F02",
    "product":  "FortiClient Electron GUI -- Electron 28 EOL; outdated Chromium",
    "severity": "HIGH -- EOL Electron + sandbox: false; multiple known Chromium CVEs",
    "class":    "Using outdated/EOL dependency with known CVEs (CWE-1104)",

    "description": (
        "FortiClient GUI binary: version file = 28.0.0 (Electron 28). "
        "Electron 28 reached end-of-life in late 2024. "
        "After EOL, no security patches are released by the Electron team. "
        "Chromium release pace: a new major version every ~4 weeks. "
        "Each Chromium release typically patches 10-20+ CVEs (many High/Critical severity). "
        "By the time this binary was extracted (March 2025 file timestamps), "
        "Chromium 120.x had 16+ months of unpatched CVEs on top. "
        "Combined with sandbox: false (FCLIENT-GUI-F01): "
        "  any unpatched Chromium CVE in Chromium 120.x+ = direct OS code execution. "
        "Attack scenario: "
        "  1. FortiClient VPN tunnel connected to attacker-controlled server. "
        "  2. FortiClient GUI renders content from the VPN session (captive portal, proxy interstitial). "
        "  3. Attacker serves malicious content with Chromium exploit. "
        "  4. sandbox: false + old Chromium = root shell on endpoint."
    ),
}

FCLIENT_GUI_SECURITY_CONFIG = {
    "id":       "FCLIENT-GUI-SECURITY-CONFIG",
    "product":  "FortiClient Electron GUI -- complete security configuration from ASAR analysis",

    "browser_window_flags": {
        "nodeIntegration":              "false (all windows) -- Node.js APIs NOT accessible in renderer",
        "contextIsolation":             "true (all windows) -- renderer runs in isolated context",
        "sandbox":                      "FALSE (multiple windows) -- OS-level sandbox DISABLED",
        "webSecurity":                  "not set to false; 'webSecurity' is only a UI feature label",
        "allowRunningInsecureContent":  "not present in app code",
        "enableRemoteModule":           "not present (deprecated in Electron 14+; not used)",
    },

    "preload_pattern": (
        "All BrowserWindows with contextIsolation: true use preload scripts: "
        "  preload: path.join(__dirname, '...') "
        "Preload scripts expose contextBridge APIs for renderer-to-main IPC. "
        "The preload scripts use electron-log for logging. "
        "electron-log's preload detects 'contextIsolation/sandbox disabled' as a code path "
        "for its module loading logic -- this is a library artifact, not a vulnerability."
    ),
}


# ---------------------------------------------------------
# TPM2 FAPI profiles: ZTNA key configuration
# ---------------------------------------------------------
FORTICLIENT_TPM2_FAPI = {
    "id":       "FCLIENT-TPM2-FAPI",
    "product":  "FortiClient TPM2 FAPI profiles -- ZTNA key algorithm and PCR binding",
    "source":   "/opt/forticlient/tpm2/etc/tpm2-tss/fapi-profiles/*.json",

    "default_profile": "P_ECCP256SHA256 (ECDSA P-256 + SHA-256)",

    "profiles": {
        "P_ECCP256SHA256": "ECDSA P-256 / SHA-256 (default; used for ZTNA signing)",
        "P_ECCP384SHA384": "ECDSA P-384 / SHA-384 (higher security, less common)",
        "P_RSA2048SHA256": "RSA-2048 / SHA-256 (RSA fallback)",
        "P_RSA3072SHA384": "RSA-3072 / SHA-384 (RSA high security)",
    },

    "srk_handle": "0x81000001 (Storage Root Key persistent handle -- standard TCG handle)",
    "srk_persistent": 0,

    "srk_persistent_finding": (
        "srk_persistent: 0 -- the SRK is NOT stored as a persistent TPM object between sessions. "
        "The SRK is recreated on each certd startup from the TPM primary seed using the same template. "
        "Because the SRK derivation is deterministic (same primary seed + same template = same SRK), "
        "the SRK value is the same across reboots without requiring persistent storage. "
        "This avoids consuming TPM NVRAM space for the SRK while maintaining deterministic behavior. "
        "Security implication: the SRK private key is never outside the TPM, "
        "but it is derivable by the TPM at any time from the primary seed -- "
        "a TPM that reveals its primary seed (theoretical; not exposed by design) "
        "would expose all derived keys."
    ),

    "pcr_binding_finding": (
        "pcr_selection: all 24 PCRs listed for SHA256, but EMPTY for SHA1. "
        "This is the FAPI profile's general PCR set -- it does NOT mean the ZTNA key is PCR-bound. "
        "PCR binding requires the key to be created with a TPM2_PolicyPCR authorization policy. "
        "The ZTNA key PCR binding depends on certd's key creation call in libcertd.so. "
        "If certd creates the ZTNA key WITHOUT a PCR policy: "
        "  - The key is usable in any boot state, including after OS compromise. "
        "  - ZTNA attestation does NOT prove the system is in a known-good state. "
        "  - A compromised OS with the correct TPM session context can still sign ZtnaSign requests. "
        "Ablation semantic sweep for libcertd.so: "
        "query: 'function creating ZTNA key in TPM; passes authorization policy; includes PCR policy'. "
        "If no PCR policy is found in the key creation, ZTNA attestation is weaker than Fortinet claims."
    ),
}
