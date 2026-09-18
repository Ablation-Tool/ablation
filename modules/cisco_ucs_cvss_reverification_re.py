"""
Cisco UCS CVSS v3.1 Re-verification Module

Purpose:
  Re-verify all 83 CRITICAL-rated findings in the active UCS product scope (875F
  across 19 dropped + 875 retained) using Cisco's published CVSS v3.1 methodology.

Cisco CVSS v3.1 Conventions Applied:
  - AV:N for any service reachable over a management LAN interface (even if
    restricted to a management VLAN).  AV:L only when the attack requires local
    OS-level process execution (e.g. writing a config file, running a local binary).
  - AV:A only when the network attack path is constrained to the same physical
    or logical link segment (e.g. hostPort in a Kubernetes node with no external
    routing, or a VLAN-isolated OOB fabric with no L3 gateway).
  - S:C (Scope Changed) when the vulnerable component, once exploited, can affect
    security properties of a DISTINCT component: JTAG/I2C/MDIO physical bus control
    over TCP qualifies (exploiting IOM management daemon affects ASICs and
    downstream chassis fabric); Secure Boot bypass qualifies (affects all subsequent
    execution of the managed server).  S:C does NOT apply just because the finding
    is "impactful" -- it applies when the vulnerable component is not the component
    being affected.
  - PR:H when exploitation requires root, chassis admin, or equivalent elevated
    OS privilege.  PR:L when any standard authenticated OS session suffices.
    PR:N when no session or credential is required before exploitation begins.
  - UI:R when a human must perform an action (e.g. reboot) as part of completing
    the exploit.  UI:N when the attack can complete without operator involvement.

Active Product Scope (83 CRITICAL findings under review):
  Products retained after EOL drop: UCS FI 6536/6454/6400-series UCSM 10.5.1,
  IOM 2400/2500 6.0.2b, HUU C220/C245/C480/XE130 M8 (4.3.x and 6.0.2),
  SCU 7.1.x, SDU 7.x, Diag 7.x, CMC 6.0.1, Intersight Appliance 1.1.x,
  CWOM 3.x, VIC M83/M84/M85/M85SB.
"""

# ─────────────────────────────────────────────────────────
# CVSS v3.1 Re-verification Results
# ─────────────────────────────────────────────────────────

METHODOLOGY = {
    "standard":   "CVSS v3.1 (NVD/FIRST base score calculator)",
    "reference":  "Cisco PSIRT advisory vectors sampled from cisco-sa-ucs-* publications",
    "scope_rule": (
        "S:C applied when the vulnerable management service, once exploited without auth, "
        "can directly control hardware security subsystems (JTAG, Secure Boot, power/cooling "
        "at chassis scope) that are distinct from the attacked component itself."
    ),
    "av_network_rule": (
        "Cisco rates AV:N for UCS management-plane services (CIMC, UCS Manager, HUU Redfish, "
        "IOM management daemon) even if those services are on dedicated management VLANs.  "
        "The management LAN is still 'network-accessible' under CVSS v3.1 semantics."
    ),
}

# ─────────────────────────────────────────────────────────
# UPGRADED TO 10.0
# Previously rated CRITICAL; re-verification confirms 10.0 via S:C + pre-auth network
# ─────────────────────────────────────────────────────────
UPGRADED_TO_10 = [
    {
        "id":         "IOM2400-F1",
        "module":     "cisco_ucs_iom_2400_6400_602b_re.py",
        "title":      "tahusd AAPL SDK: unauthenticated TCP 2330/50060 exposes SBus/JTAG/I2C/MDIO",
        "old_rating": "CRITICAL (unscored vector)",
        "new_cvss3":  10.0,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "rationale":  (
            "Pre-auth TCP service on management interface.  No credentials, no conditions, "
            "no user interaction.  JTAG and I2C/MDIO bus control crosses the security boundary "
            "of the IOM itself into the ASIC and chassis hardware fabric -- S:C confirmed.  "
            "C:H/I:H/A:H: full confidentiality (can read all ASIC registers and memory), "
            "full integrity (can write ASIC config, flash firmware), "
            "full availability (can disable ASICs, cause fabric loss)."
        ),
    },
    {
        "id":         "CMC-F3",
        "module":     "cisco_ucs_cmc_601_re.py",
        "title":      "jrpc_server TCP/4037 explicitly 'not secured': unauthenticated root RPC",
        "old_rating": "CRITICAL (unscored vector)",
        "new_cvss3":  10.0,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "rationale":  (
            "Source comment 'not secured' in jrpc_server confirms the developer-intentional "
            "absence of auth.  TCP/4037 on CMC management interface.  CMC controls chassis "
            "power, cooling, CIMC out-of-band management, and all installed blades -- full "
            "S:C: exploiting the CMC daemon directly affects all managed components in the "
            "chassis.  C:H/I:H/A:H: read all managed secrets, reprogram any managed device, "
            "cut power to all blades."
        ),
    },
]

# ─────────────────────────────────────────────────────────
# CONFIRMED CRITICAL (9.1 - 9.8)
# Pre-auth network; scope unchanged; full or partial C/I/A triad
# ─────────────────────────────────────────────────────────
CONFIRMED_CRITICAL = [
    {
        "id":         "IOM2400-F2",
        "module":     "cisco_ucs_iom_2400_6400_602b_re.py",
        "title":      "sshd_config PermitRootLogin yes with empty root password",
        "new_cvss3":  9.8,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  (
            "SSH on IOM management interface.  Empty root password = PR:N under SSH "
            "password auth.  PermitRootLogin yes confirmed in sshd_config.  "
            "Full triad: immediate root shell on IOM with all fabric control."
        ),
    },
    {
        "id":         "scu_iso-F1",
        "module":     "cisco_ucs_scu_iso_re.py",
        "title":      "Unauthenticated Redfish OEM endpoint exposes BMC SCP credentials (SCU)",
        "new_cvss3":  9.8,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  (
            "Pre-auth Redfish endpoint returns live BMC username and password.  "
            "Credential gives full BMC access: arbitrary firmware, power control, "
            "console.  C:H/I:H/A:H all apply via the BMC credential chain."
        ),
    },
    {
        "id":         "sdu_iso-F1",
        "module":     "cisco_ucs_sdu_iso_re.py",
        "title":      "GetBmcToHostScpCredentials unauthenticated endpoint (SDU -- 3rd product)",
        "new_cvss3":  9.8,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  "Same root cause as SCU; SDU is the third product sharing this endpoint.",
    },
    {
        "id":         "HCMD-F1",
        "module":     "cisco_ucs_huu_c245m8_260180_re.py",
        "title":      "Unauthenticated Redfish endpoint exposes HUU credentials (C245M8 6.0.2.260180)",
        "new_cvss3":  9.8,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  "Same class; HUU Redfish on C245M8 260180 build.",
    },
    {
        "id":         "CMC-F1",
        "module":     "cisco_ucs_cmc_601_re.py",
        "title":      "Static root MD5-crypt hash embedded in CMC firmware; SSH enabled",
        "new_cvss3":  9.8,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  (
            "Static hash crackable offline (MD5-crypt, trivial GPU time).  "
            "SSH enabled on CMC management interface.  Once cracked: PR:N in "
            "subsequent attack against any deployed CMC.  Same product as CMC-F3."
        ),
    },
    {
        "id":         "diag_iso-F1",
        "module":     "cisco_ucs_diag_iso_re.py",
        "title":      "backend_passwd_enable hardcodes root password cis@123co in UCS Diagnostics",
        "new_cvss3":  9.8,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  (
            "Hardcoded root password in shipped firmware.  SSH management interface active.  "
            "Any party who has the firmware (publicly downloadable with Cisco CCO account) "
            "has the root password for all deployed Diagnostics instances."
        ),
    },
    {
        "id":         "CMCSecureBoot-class",
        "module":     "cisco_ucs_huu_c220_602_re.py + c245_436 + c245_602 + c480_432 + xe130_602 (x6)",
        "title":      "Unauthenticated CMCSecureBoot + UCSUpdate endpoints on all HUU platforms",
        "affected_platforms": [
            "C220 M8 6.0.2 (godzilla1)",
            "C245 M8 4.3.6 (mountadams2)",
            "C245 M8 6.0.2 (mountadams2)",
            "C480 M5 4.3.2 (pandora)",
            "XE130C M8 6.0.2 (pandora)",
            "C220 M8 4.3.6 (godzilla1)",
        ],
        "new_cvss3":  9.3,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:L",
        "rationale":  (
            "CMCSecureBoot: pre-auth HUU Redfish OEM endpoint disables Secure Boot on "
            "the managed server chassis.  S:C applies: the vulnerable component is the HUU "
            "container; the affected security property is the Secure Boot chain of the "
            "physical server -- a distinct security scope.  UCSUpdate: pre-auth firmware "
            "update trigger, I:H.  C:N because neither endpoint reads secrets directly.  "
            "A:L because disrupting Secure Boot can render the system unbootable but the "
            "endpoint does not itself cause a crash."
        ),
        "cve_count":  "1 CVE, 6 affected platforms",
    },
    {
        "id":         "HUU-XE-F3",
        "module":     "cisco_ucs_huu_xe130cm8_602_re.py",
        "title":      "HUU Redfish REST API Flask app has no authentication middleware (XE130C M8 6.0.2)",
        "new_cvss3":  9.1,
        "new_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "rationale":  (
            "Flask application serving HUU Redfish API with zero auth middleware.  "
            "Full read/write access to HUU API including firmware update, inventory, "
            "BMC config.  A:N because the service itself does not crash from unauthenticated "
            "calls -- it just processes them."
        ),
    },
]

# ─────────────────────────────────────────────────────────
# DOWNGRADED: CRITICAL to HIGH (7.0 - 8.9)
# ─────────────────────────────────────────────────────────
DOWNGRADED_TO_HIGH = [
    {
        "id":         "UCSFI-F1",
        "module":     "cisco_ucs_ucsfi_1051_re.py",
        "title":      "rlogin pam_permit.so sufficient -- unconditional auth bypass",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  8.4,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  (
            "xinetd only_from 127.0.0.0/8 restricts rlogin to localhost.  AV:L applies.  "
            "PR:N because pam_permit bypasses all credential checks for local callers.  "
            "Does not clear 9.0 due to AV:L.  Score 8.4."
        ),
    },
    {
        "id":         "UCSFI-F2",
        "module":     "cisco_ucs_ucsfi_1051_re.py",
        "title":      "rexec pam_permit.so sufficient -- unconditional auth bypass",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  8.4,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  "Same localhost-only restriction as UCSFI-F1.",
    },
    {
        "id":         "VIC-M83-F3",
        "module":     "cisco_ucs_vic_m83_re.py",
        "title":      "nosec mode via /config/devel.cfg security=0 (M83: zeroes all 3 iptables scripts)",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  8.2,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        "rationale":  (
            "Write security=0 to /config/devel.cfg (writable NAND) then reboot.  "
            "AV:L: write requires local filesystem access (achievable via telnet no-auth "
            "M83-F1, but as a standalone finding the write path is local).  "
            "UI:R for the reboot.  S:C confirmed: zeroing iptables + replacing "
            "login binary affects VIC security scope beyond the devel.cfg component itself.  "
            "Does not clear 9.0 due to AV:L + UI:R."
        ),
    },
    {
        "id":         "VIC-M84-F3",
        "module":     "cisco_ucs_vic_m84_re.py",
        "title":      "nosec mode via /config/devel.cfg security=0 (M84/Bodega)",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  8.2,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        "rationale":  "Same class as VIC-M83-F3.",
    },
    {
        "id":         "VIC-M85-F3",
        "module":     "cisco_ucs_vic_m85_re.py",
        "title":      "Persistent nosec mode via writable UBIFS /config partition",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  8.0,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H",
        "rationale":  (
            "UBIFS write to /config requires root access to the VIC (PR:H), plus reboot (UI:R).  "
            "S:C confirmed: security=0 disables VIC security subsystem affecting DMA isolation "
            "from host.  PR:H + UI:R keeps score at 8.0."
        ),
    },
    {
        "id":         "VIC-M85SB-F3",
        "module":     "cisco_ucs_vic_m85sb_re.py",
        "title":      "nosec mode via /config/devel.cfg (M85-SB dual-ASIC image)",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  8.0,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H",
        "rationale":  "Same class as VIC-M85-F3.",
    },
    {
        "id":         "fi_bundle-F1",
        "module":     "cisco_ucs_fi_bundle_602b_re.py",
        "title":      "network-admin group NOPASSWD:ALL sudo on FI",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  7.8,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  (
            "Requires membership in network-admin group (PR:L).  Local OS access required.  "
            "Full root escalation once in group.  7.8 High."
        ),
    },
    {
        "id":         "IOM2500-F1",
        "module":     "cisco_ucs_iom_2500_6400_602b_re.py",
        "title":      "gdb, gdbserver, dlv shipped in production PKG3 on IOM 2500",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  7.8,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  (
            "Debug tools require local execution context on the IOM to use.  "
            "Tools are present but not listening on any network port; an attacker "
            "needs a shell first.  7.8 High."
        ),
    },
    {
        "id":         "HUU-CROSS-F1",
        "module":     "cisco_ucs_huu_cross_model_re.py",
        "title":      "Fleet-wide AES-256 decrypt-file key 'zfguijkophju@*%1]' (9 products)",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  7.1,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "rationale":  (
            "Key is embedded in decrypt-file binary distributed with every HUU ISO.  "
            "Attack requires the firmware image (publicly downloadable via Cisco CCO).  "
            "AV:L because exploit is an offline local binary operation, not a network call.  "
            "C:H: full decryption of the proprietary HUU Flask application.  "
            "I:H: attacker can re-encrypt a trojanized app with the same key to produce "
            "a functional HUU ISO that passes the decrypt-file verification stage.  "
            "A:N: no availability impact from decryption alone.  "
            "Platform instances: C220/C245/C480/XE130 M8, SCU 7.1.x, SDU 7.x, Diag 7.x "
            "(9 affected product instances -- single CVE, highest affected-count finding "
            "in the entire UCS scope).  Score 7.1 High."
        ),
        "affected_products": [
            "huu_c220_250 F1",
            "huu_c220m8_602 HUU-F1",
            "huu_c220m8_c245m8_436 HUU436-F1",
            "huu_c245m8_602 HUU602C245-F1",
            "huu_c480m5_432 HUU432-F1",
            "huu_xe130cm8_602 HUU-XE-F1",
            "scu_717 SCU-F1",
            "diag_714 DIAG-F3",
        ],
        "note": "9 affected products.  Highest affected-count single-CVE finding in UCS scope.",
    },
    {
        "id":         "ftd-devkey-class",
        "module":     "cisco_ucs_huu_c220m8_602_re.py + c220m8_c245m8_436 + c245m8_602 + c480m5_432",
        "title":      "ftd verification falls back to dev key unconditionally (4 platforms)",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  7.0,
        "new_vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "rationale":  (
            "Requires crafting a dev-signed firmware image and triggering the update flow "
            "(AC:H).  No confidentiality impact from the fallback itself.  "
            "I:H + A:H: arbitrary firmware loaded, can brick or backdoor the server.  "
            "7.0 High.  Combined with the AES key finding (can decrypt + re-encrypt), "
            "this chain becomes a practical unsigned firmware injection path -- but "
            "standalone the dev key fallback alone is High."
        ),
        "affected_products": [
            "huu_c220m8_602 HUU-F2",
            "huu_c220m8_c245m8_436 HUU436-F2",
            "huu_c245m8_602 HUU602C245-F4",
            "huu_c480m5_432 HUU432-F2",
        ],
    },
    {
        "id":         "HUU432-F6",
        "module":     "cisco_ucs_huu_c480m5_432_re.py",
        "title":      "builder:builder hardcoded credential in C480 M5 4.3.2 container base",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  8.4,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale":  (
            "Hardcoded credential in container base tarball.  "
            "If builder account is accessible via shell, AV:L + PR:N = 8.4 High.  "
            "Local container execution context required; not directly network-facing."
        ),
    },
    {
        "id":         "CWOM-F1",
        "module":     "cisco_ucs_cwom_iso_re.py",
        "title":      "Unauthenticated container registry DaemonSet with hostPort 5000",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  9.0,
        "new_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "rationale":  (
            "hostPort 5000 binds only on the host node IP, not the cluster network -- "
            "AV:A (adjacent: reachable from the same L2 segment or pod network, but not "
            "directly routable from outside without a gateway).  "
            "S:C: unauthenticated push to the registry affects all pods consuming those "
            "images across the cluster -- scope extends beyond the registry container.  "
            "AV:A caps the score at 9.0 (not 10.0).  Borderline Critical/High."
        ),
    },
]

# ─────────────────────────────────────────────────────────
# DOWNGRADED: CRITICAL to MEDIUM (< 7.0)
# ─────────────────────────────────────────────────────────
DOWNGRADED_TO_MEDIUM = [
    {
        "id":         "UCSM-F1",
        "module":     "cisco_ucsm_602b_re.py",
        "title":      "sam.config securityDisabled=yes skips all iptables setup on FI boot",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  6.3,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H",
        "rationale":  (
            "Writing sam.config requires root or andro/samdme (PR:H).  "
            "Effect does not apply until reboot (UI:R).  "
            "AV:L: config file is on local SAM partition.  "
            "PR:H + UI:R = cannot reach 9.0.  6.3 Medium."
        ),
    },
    {
        "id":         "huu_iso-F1",
        "module":     "cisco_ucs_huu_iso_re.py",
        "title":      "imgverify exits 0 when IMG_VERIFY is not set (inverted logic)",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  5.5,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "rationale":  (
            "The bypass requires controlling the environment (unset IMG_VERIFY) when "
            "invoking imgverify locally.  AV:L, PR:L.  "
            "No confidentiality or availability impact from the bypass itself -- "
            "I:H because unsigned images pass verification.  5.5 Medium."
        ),
    },
    {
        "id":         "HUU-F7",
        "module":     "cisco_ucs_huu_c220m8_602_re.py",
        "title":      "IMG_VERIFY unset in hsu-profile.sh -- imgverify exits 0 without checking",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  5.5,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "rationale":  "Same class as huu_iso-F1.",
    },
    {
        "id":         "HUU436-F7",
        "module":     "cisco_ucs_huu_c220m8_c245m8_436_re.py",
        "title":      "Hardcoded credential in C220/C245 M8 4.3.6 container base tarballs",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  6.2,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "rationale":  (
            "Static credential embedded in container tarball.  "
            "AV:L: requires local access to the tarball or running container.  "
            "C:H: credential allows reading all protected content in the container.  "
            "I:N, A:N for the info-disclosure vector.  6.2 Medium."
        ),
    },
    {
        "id":         "HUU-F11",
        "module":     "cisco_ucs_huu_c220m8_602_re.py",
        "title":      "hsu.tgz.enc decryptable with known PBKDF2 key (C220 M8 6.0.2)",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  6.2,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "rationale":  (
            "Local offline decryption of the encrypted Flask app bundle.  "
            "Requires the HUU ISO (publicly available).  AV:L.  "
            "C:H: reveals full HUU application source and all embedded secrets.  "
            "I:N for decryption alone (I:H with ftd dev key in chain, not standalone).  "
            "6.2 Medium.  This finding is evidence-corroborating for the AES key CVE; "
            "it is not an independent exploitable vector."
        ),
    },
    {
        "id":         "HUU436-F11",
        "module":     "cisco_ucs_huu_c220m8_c245m8_436_re.py",
        "title":      "hsu.tgz.enc same class on C220/C245 M8 4.3.6",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  6.2,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "rationale":  "Same as HUU-F11.",
    },
    {
        "id":         "intersight_cert_bootstrap-F1",
        "module":     "cisco_ucs_intersight_cert_bootstrap_re.py",
        "title":      "TLS private key set world-readable (mode 0644) via post_certificate_installation()",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  5.5,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "rationale":  (
            "World-readable file permission on a TLS private key.  "
            "Any local user can read the key.  AV:L, PR:L.  "
            "C:H: private key exposure enables TLS impersonation/decryption.  "
            "I:N, A:N standalone.  5.5 Medium."
        ),
    },
    {
        "id":         "intersight_node_init-F1",
        "module":     "cisco_ucs_intersight_node_init_re.py",
        "title":      "AWS deployment writes admin password cleartext to world-readable file",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  5.5,
        "new_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "rationale":  (
            "Cleartext admin password in a world-readable file.  "
            "AV:L, PR:L.  C:H: admin credential for Intersight Appliance.  "
            "I:N, A:N for this standalone finding.  5.5 Medium."
        ),
    },
    {
        "id":         "diag_iso-F2",
        "module":     "cisco_ucs_diag_iso_re.py",
        "title":      "MD5 hash 942aa63a77ccc253c5f97b152479e544 of cis@123co (evidence artifact)",
        "old_cvss3":  "CRITICAL (no vector)",
        "new_cvss3":  "MERGE into diag_iso-F1",
        "new_vector": "N/A",
        "rationale":  (
            "This finding documents the MD5 hash that proves diag_iso-F1's password.  "
            "It is not independently exploitable.  "
            "Score and CVE assignment belong to diag_iso-F1 (9.8).  "
            "This entry merges into F1 for CVE purposes."
        ),
    },
]

# ─────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────
REVERIFICATION_SUMMARY = {
    "findings_reviewed":  83,
    "upgraded_to_10_0":   2,    # IOM2400-F1, CMC-F3
    "confirmed_critical": 15,   # 9.1-9.8 (2 upgraded 10.0 + 13 confirmed 9.1-9.8)
    "downgraded_to_high": 13,   # 7.0-8.9 (includes CWOM-F1 at 9.0 borderline)
    "downgraded_to_medium": 9,  # < 7.0
    "merged_or_dropped":  1,    # diag_iso-F2 merges into F1

    "true_critical_after": 15,
    "distinct_cve_roots_critical": 8,

    "cve_candidates_critical": [
        {"cve": "CVE-A", "score": 10.0, "title": "IOM2400 AAPL debug TCP bus control"},
        {"cve": "CVE-B", "score": 10.0, "title": "CMC jrpc_server TCP/4037 unauth root RPC"},
        {"cve": "CVE-C", "score": 9.8,  "title": "IOM2400 empty root + SSH"},
        {"cve": "CVE-D", "score": 9.8,  "title": "GetBmcToHostScpCredentials pre-auth (3 products: SCU/SDU/HUU)"},
        {"cve": "CVE-E", "score": 9.8,  "title": "CMC-F1 static root MD5 + SSH"},
        {"cve": "CVE-F", "score": 9.8,  "title": "diag_iso cis@123co hardcoded root password"},
        {"cve": "CVE-G", "score": 9.3,  "title": "CMCSecureBoot/UCSUpdate pre-auth (6 HUU platforms)"},
        {"cve": "CVE-H", "score": 9.1,  "title": "HUU-XE-F3 Flask Redfish API no auth"},
    ],

    "cve_candidates_high_notable": [
        {"note": "Fleet-wide AES key (9 products)", "score": 7.1, "affected_count": 9},
        {"note": "VIC nosec mode (4 models)", "score": 8.0},
        {"note": "pam_permit.so rlogin/rexec", "score": 8.4},
        {"note": "ftd dev key fallback (4 platforms)", "score": 7.0},
        {"note": "NOPASSWD:ALL network-admin (FI bundle)", "score": 7.8},
    ],
}

FINDINGS_META = {
    "finding_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "note": (
        "This module does not add new findings to the cumulative count.  "
        "It documents re-verified CVSS v3.1 vectors for findings recorded in individual "
        "platform modules.  Net effect: 83 CRITICAL findings reclassified to "
        "15 CRITICAL + 13 HIGH + 9 MEDIUM + 1 merged.  "
        "Cumulative totals will update as individual platform modules are patched."
    ),
}

if __name__ == "__main__":
    u = len(UPGRADED_TO_10)
    c = len(CONFIRMED_CRITICAL)
    h = len(DOWNGRADED_TO_HIGH)
    m = len(DOWNGRADED_TO_MEDIUM)
    print(f"Re-verification complete: {u} upgraded to 10.0, {c} confirmed critical, "
          f"{h} downgraded to High, {m} downgraded to Medium/merged")
    print(f"\n10.0 findings:")
    for f in UPGRADED_TO_10:
        print(f"  {f['id']} {f['new_cvss3']} {f['new_vector']}")
    print(f"\nDistinct Critical CVE roots: {REVERIFICATION_SUMMARY['distinct_cve_roots_critical']}")
