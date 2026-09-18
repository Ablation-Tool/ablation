"""
Cisco Catalyst USB Console Driver 3.1 and IOS-XE 26.01.02 Compatibility Matrix RE

Targets:
  Cisco_usbconsole_driver_3_1.zip -- USB console cable driver, Windows 32/64/2k
  26.01.02-comp_matrix.xml        -- IOS-XE 26.01.02 platform compatibility matrix
Source: /media/cowboy/research/Cisco-Catalyst/

USB Driver Structure:
  Windows_32/setup32.exe     -- InstallShield 15.0 stub (PE32 x86, 3.87MB)
  Windows_64/setup(x64).exe  -- InstallShield 15.0 stub (PE32 x86, 5.73MB)
  Windows_2k/setup(Win2k).exe -- Windows 2000 variant
  Each stub decompresses CiscoVirtualCom*.msi to %TEMP% and launches msiexec

Driver Package: CiscoVirtualCom (virtual serial port)
  Architecture: Windows kernel mode driver (WDM)
  Extracted method: not possible without Windows; MSI embedded in InstallShield payload
  Build date: 2009-12-21 (setup exes), 2010-01-04 (READMEs)

comp_matrix.xml:
  IOS-XE 26.01.02, released 2026-07-31
  Covers 69 platforms: ASR1001-HX, ASR1002-HX, ASR1001-X/2-X/4/6/13,
  ASR1006-X, ASR1009-X, Catalyst 9400/9500/9600/9800/CW9800 series
  Use: platform-level SMU compatibility reference, no software binaries

Findings: 3 [0C+0H+0M+3L]
"""

METADATA = {
    "target":   "Cisco USB Console Driver 3.1 + IOS-XE 26.01.02 comp_matrix",
    "version":  "3.1 (driver), 26.01.02 (matrix)",
    "source":   "/media/cowboy/research/Cisco-Catalyst/",
    "analyst":  "static: strings, PE header, binwalk, manifest parse",
}

FINDINGS = [
    {
        "id":    "F1",
        "title": "Setup executables unsigned -- no Authenticode signature",
        "cvss3": 3.9,
        "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
        "detail": (
            "Both setup32.exe and setup(x64).exe have Security Directory "
            "RVA=0x0, size=0 in the PE Optional Header -- no Authenticode "
            "signature present. Any file placed on a network share or update "
            "server as this installer can be silently replaced by an attacker "
            "with write access. No Windows signature validation will fire at "
            "launch time; the substituted binary runs with the privileges of "
            "whoever invokes it. Contrast with the inner CiscoVirtualCom MSI "
            "which is presumably WHQL-signed (not extractable for verification)."
        ),
        "evidence": "PE header offset 0x80 (security dir): RVA=0x00000000 size=0x00000000",
        "affected":  "setup32.exe, setup(x64).exe",
        "remediation": "Sign the outer stub executable with an Authenticode certificate.",
    },
    {
        "id":    "F2",
        "title": "Production installer built with evaluation version of InstallShield",
        "cvss3": 2.6,
        "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N",
        "detail": (
            "The string 'This Setup was created with an EVALUATION VERSION of "
            "InstallShield' is embedded verbatim in both stub executables. "
            "InstallShield 15.0 Professional evaluation builds are feature-limited "
            "and unlicensed for production distribution. This indicates the installer "
            "was assembled outside normal Cisco build infrastructure, raising questions "
            "about which security controls (code review gates, signing requirements, "
            "QA processes) applied during its creation. No functional impact but a "
            "supply-chain process indicator."
        ),
        "evidence": "strings setup32.exe | grep -i eval",
        "affected":  "Cisco_usbconsole_driver_3_1.zip (all variants)",
        "remediation": "Rebuild with licensed InstallShield or WiX in the standard Cisco CI pipeline.",
    },
    {
        "id":    "F3",
        "title": "Embedded zlib 1.2.3 (2005) with known CVEs",
        "cvss3": 2.6,
        "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L",
        "detail": (
            "The InstallShield stub links zlib 1.2.3 (copyright 1995-2005, "
            "Jean-loup Gailly / Mark Adler, embedded in the .text section). "
            "zlib 1.2.3 is affected by CVE-2005-2096 (heap overflow in inflate via "
            "large dynamic tree) and CVE-2005-1849 (DoS via malformed compressed "
            "stream). Exploitability is low in this context because the decompressed "
            "input is the installer payload sourced from the exe itself -- not from "
            "a network or attacker-controlled stream. However, if the installer is "
            "run against a tampered file (see F1), a crafted payload could trigger "
            "the heap overflow in the installer process context."
        ),
        "evidence": "binwalk setup32.exe -> Copyright 1995-2005 Jean-loup Gailly/Mark Adler at 0x6DD27",
        "affected":  "setup32.exe (x86), setup(x64).exe (x86 stub)",
        "remediation": "Update to zlib >= 1.2.4.",
    },
]

COMP_MATRIX_SUMMARY = {
    "file":     "26.01.02-comp_matrix.xml",
    "version":  "26.01.02",
    "date":     "2026-07-31",
    "platform_count": 69,
    "families": ["ASR1001-HX", "ASR1002-HX", "ASR1001-X", "ASR1002-X",
                 "ASR1004", "ASR1006", "ASR1013", "ASR1006-X", "ASR1009-X",
                 "C9404R", "C9407R", "C9410R", "C9500", "C9600",
                 "C9800-L", "C9800-40", "C9800-80", "C9800-CL",
                 "C9800X-H-40F-K9", "CW9800M", "CW9800H1", "CW9800H2", "CW9800L"],
    "security_surface": "None. Compatibility matrix XML only; no executables, no keys, no credentials.",
    "note": "Lists HA-STANDALONE mode and SMU requirements for each platform in 26.01.02. "
            "Useful as a platform enumeration reference for future firmware acquisition "
            "targeting (ASR1000 and CW9800 series not yet covered in ablation modules).",
}

if __name__ == "__main__":
    print(f"Findings: {len(FINDINGS)}")
    for f in FINDINGS:
        print(f"  {f['id']} {f['cvss3']} -- {f['title']}")
    print(f"\ncomp_matrix: {COMP_MATRIX_SUMMARY['platform_count']} platforms, no security findings")
