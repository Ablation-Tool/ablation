"""
Cisco UCS 6400 Series and 6600 Series FI Infrastructure Bundles 6.0(2b)A — RE Module
Sources:
  ucs-6400-k9-bundle-infra.6.0.2b.A.bin (3.3GB)
  ucs-6600-k9-bundle-infra.6.0.2b.A.bin (3.3GB)
Both from /media/cowboy/research/Cisco-UCS/fi-bundles/

Format: Cisco SN bundle (magic 0x6401534e, 808-byte header) + gzip+tar
Both bundles have identical payload file list to FI 6500 infra bundle.

Key finding: ucsfi.10.5.1.I60.2b.F.bin in FI 6400 and FI 6600 is IDENTICAL
to the binary in the FI 6500 bundle (SHA256 prefix 720fc65d).
All FI6500 findings apply unchanged to FI 6400 and FI 6600.
"""

FIRMWARE = {
    "targets": [
        {
            "name": "UCS 6400 Series FI Infrastructure Bundle",
            "file": "ucs-6400-k9-bundle-infra.6.0.2b.A.bin",
            "sn_offset": 808,
        },
        {
            "name": "UCS 6600 Series FI Infrastructure Bundle",
            "file": "ucs-6600-k9-bundle-infra.6.0.2b.A.bin",
            "sn_offset": 808,
        },
    ],
    "component_images": {
        "ucsfi.10.5.1.I60.2b.F.bin":  "FI NX-OS — IDENTICAL to FI6500 binary (SHA256: 720fc65d...)",
        "ucs-manager-k9.6.0.2b.bin":  "UCSM 6.0.2b — same image as cisco_ucsm_602b_re.py",
        "ucs-2400-6400.6.0.2b.bin":   "UCS 2400/6400 IOM firmware",
        "ucs-2500-6400.6.0.2b.bin":   "UCS 2500/6400 IOM firmware",
    },
    "findings": ["FI64XX-F1"],
}

# ─────────────────────────────────────────────────────────
# FI64XX-F1: NX-OS image identical to FI 6500 — all FI6500 findings apply
#            across all three FI generations
# ─────────────────────────────────────────────────────────
FI64XX_F1 = {
    "id":       "FI64XX-F1",
    "title":    "FI 6400 and FI 6600 infra bundles ship the IDENTICAL NX-OS binary as FI 6500 "
                "(ucsfi.10.5.1.I60.2b.F.bin, SHA256 720fc65d...) — FI6500-F1 through F4 apply "
                "to all three FI hardware generations",
    "status":   "CONFIRMED — SHA256 hash match across all three bundle extractions",
    "severity": "INFORMATIONAL",

    "binary_sha256_prefix": {
        "FI6400_6.0.2b.A": "720fc65dc55eaf54",
        "FI6500_6.0.2b.A": "720fc65dc55eaf54",
        "FI6600_6.0.2b.A": "720fc65dc55eaf54",
    },

    "applicable_findings": {
        "FI6500-F1": "sudoers NOPASSWD 'strings /proc/*/environ' to all authenticated users — HIGH",
        "FI6500-F2": "sudoers NOPASSWD loadplugin from bootflash/volatile/slot",
        "FI6500-F3": "see cisco_ucs_fi6500_602b_re.py",
        "FI6500-F4": "see cisco_ucs_fi6500_602b_re.py",
    },

    "scope_note": (
        "UCS FI 6400 series (2 RU, 32/48-port, Cloudscale ASIC) and FI 6600 series "
        "(newest generation, replacing 6500) ship the same NX-OS software image "
        "ucsfi.10.5.1.I60.2b.F.bin, version 10.5(1)I60(2b). "
        "All sudoers, credential, and NX-OS configuration findings from the FI 6500 analysis "
        "apply without modification to 6400 and 6600 hardware."
    ),
}

CROSS_REFERENCE = {
    "primary_analysis": "cisco_ucs_fi6500_602b_re.py",
    "infra_bundle_analysis": "cisco_ucs_fi6500_infra_602b_re.py",
    "sn_format": (
        "Same SN bundle format as FI 6500 (magic 0x6401534e, 808-byte header, "
        "no cryptographic verification of payload integrity). "
        "See SECURITY_NOTES.sn_format_confirmed in cisco_ucs_fi6500_infra_602b_re.py."
    ),
}

FINDINGS = [FI64XX_F1]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:12s}] {f['id']}: {f['title'][:80]}")
