"""
pseries_fw_re.py — IBM RS/6000 pSeries Raw Firmware RE findings

Targets:  5 raw firmware images for IBM RS/6000 eServer pSeries machines
          Platform: PowerPC (PPC32), Open Firmware / PPS BIOS, flat binary
          All images: no ELF, no compressed payload, IBM/Apple PPS Microcode

Files:    /media/cowboy/research/IBM-RE/collections/firmware/eserver-pseries/
            firmware-7025-F40/TR97069.img   (1,048,576 bytes)
            firmware-7043-140/tig97161.img  (1,048,576 bytes)
            firmware-7043-240/DOR97069.img  (1,048,576 bytes)
            firmware-7248-43p/beta112.img     (524,288 bytes)
            firmware-7020-40p/P12H0456.IMG    (524,288 bytes)

Session:  Session 14 — pSeries firmware triage (2026-10-25)
"""

# ── Image inventory ──────────────────────────────────────────────────────────

IMAGES = {
    'TR97069.img': {
        'machine':    'IBM RS/6000 7025-F40 (Hydra, CHRP workstation)',
        'fw_level':   '12H0656',
        'size':       1_048_576,
        'type':       'PPS Microcode',
        'copyright':  'IBM Corp 1994, 1996 + Apple Computer Inc 1994, 1996',
        'format':     'Flat binary, Open Firmware / PPS BIOS',
        'notes':      'Shares firmware level 12H0656 with DOR97069 (7043-240)',
    },
    'tig97161.img': {
        'machine':    'IBM RS/6000 7043-140 (Salmon, CHRP workstation)',
        'fw_level':   '40H5090',
        'size':       1_048_576,
        'type':       'PPS Microcode',
        'copyright':  'IBM Corp 1994, 1996 + Apple Computer Inc 1994, 1996',
        'format':     'Flat binary, Open Firmware / PPS BIOS',
        'notes':      'Two copyright strings with slightly different spacing',
    },
    'DOR97069.img': {
        'machine':    'IBM RS/6000 7043-240 (Trombone, CHRP workstation)',
        'fw_level':   '12H0656',
        'size':       1_048_576,
        'type':       'PPS Microcode',
        'copyright':  'IBM Corp 1994, 1996 + Apple Computer Inc 1994, 1996',
        'format':     'Flat binary, Open Firmware / PPS BIOS',
        'notes':      'Same firmware level as TR97069 (7025-F40) — same BIOS lineage',
    },
    'beta112.img': {
        'machine':    'IBM RS/6000 7248-43p (PowerPC workstation)',
        'fw_level':   '40H5218',
        'fw_level2':  '93x7075',   # secondary partition (diagnostics ROM?)
        'size':       524_288,
        'type':       'RS/6000 Microcode',
        'copyright':  'IBM Corp. 1994, 1996 (no Apple copyright)',
        'format':     'Flat binary, Open Firmware BIOS',
        'notes':      'Two firmware level strings — 40H5218 (primary) + 93x7075 (secondary)',
    },
    'P12H0456.IMG': {
        'machine':    'IBM RS/6000 7020-40p (CHRP entry server)',
        'fw_level':   '12H0455',
        'fw_level2':  '12H0456',   # second copy (filename matches second level)
        'size':       524_288,
        'type':       'PPS Firmware',
        'copyright':  'IBM Corp. 1994 (no Apple copyright)',
        'format':     'Flat binary, Open Firmware BIOS',
        'notes':      'Two firmware levels (12H0455 + 12H0456) — incremental update image',
    },
}

# ── Format analysis ──────────────────────────────────────────────────────────

FORMAT_ANALYSIS = {
    'why_no_binarycontext': (
        'No ELF headers found in any of the 5 images. '
        'Format is flat raw Open Firmware / PPS BIOS binary (IBM RS/6000 PReP/CHRP platform). '
        'Contains: PPC32 machine code, OpenFirmware FCode bytecode, device tree data. '
        'BinaryContext.load_or_build() requires ELF — not applicable here.'
    ),
    'compression': (
        'All gzip (\\x1f\\x8b) and zlib (\\x78\\x9c/\\xDA) magic byte occurrences are '
        'false positives — none decompress successfully. '
        'Firmware is not packed/compressed; the 1MB/512KB images are flat binary.'
    ),
    'of_fcode': (
        'OpenFirmware FCode (\\xf1\\x08 magic) found in all 5 images: '
        'TR97069: 2, tig97161: 7, DOR97069: 3, beta112: 5, P12H0456: 4 occurrences. '
        'FCode is OpenFirmware Forth bytecode used for device driver initialization. '
        'Expected content in any PReP/CHRP platform firmware.'
    ),
    'function_symbols': (
        'TR97069 exposes function names in the .text section (unstripped BIOS): '
        'transfer_uncompressed_image, transfer_compressed_image, transfer_ROM_code '
        '(bootloader), diskette_init/read/write/read_RBA/write_RBA (floppy driver), '
        'ReadPC87312Regs/WritePC87312Regs (PC87312 Super I/O chip driver), '
        'pci_config_read_8/16/32, pci_config_write_8/16/32 (PCI config space), '
        'get_rtc, init_rtc_parms (RTC driver), sens_intr, dma_setup, dma_check. '
        'Standard BIOS device driver inventory. No user-space code.'
    ),
    'platform_note': (
        'IBM + Apple joint copyright on TR97069/tig97161/DOR97069 confirms these are '
        'Power Platform Standard (PPS) BIOS images, shared IP between IBM and Apple '
        'for the PReP/CHRP specification (used on IBM RS/6000 workstations and '
        'early Power Mac systems in the mid-1990s).'
    ),
}

# ── Security sweep results ───────────────────────────────────────────────────

SECURITY_SWEEP = {
    'method':  'Full-image ASCII string extraction (>= 6 chars) + pattern matching',
    'strings': {
        'TR97069.img':  1023,
        'tig97161.img': 677,
        'DOR97069.img': 769,
        'beta112.img':  729,
        'P12H0456.IMG': 577,
    },
    'credentials':   'None found — no password, passwd, secret, debug, backdoor, token strings',
    'ip_addresses':  'None found',
    'debug_ports':   'None found',
    'network_boot':  'None found — no BOOTP, DHCP, TFTP, PXE, RARP, NETBOOT strings',
    'urls':          'None found',
    'exec_sinks':    'None — bare-metal firmware, no OS exec()/system() surface',
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'PSERIES-FW-001',
        'verdict': 'SAFE',
        'title':   'IBM RS/6000 pSeries PPS BIOS firmware — no vulnerability',
        'notes': (
            'Five IBM RS/6000 flat binary BIOS firmware images (1MB/512KB each). '
            'All five: no ELF headers, no successfully decompressed compressed payload, '
            'no credentials, no IP addresses, no network boot strings, no debug ports. '
            'Format: Open Firmware PPS BIOS (IBM/Apple joint copyright, PReP/CHRP spec). '
            'OpenFirmware FCode present in all images — expected device driver bytecode. '
            'TR97069 function symbols confirm standard BIOS device driver set: '
            '  floppy (PC87312 Super I/O), PCI config, RTC, DMA, interrupt handlers. '
            'No network stack identified (no BOOTP/TFTP/DHCP strings). '
            'TR97069 and DOR97069 share firmware level 12H0656 — same BIOS codebase. '
            'No security vulnerability. Bare-metal firmware, no attack surface.'
        ),
        'eliminated_classes': [
            'exec-class sinks (no OS, no Unix shell — bare-metal BIOS)',
            'hardcoded credentials',
            'hardcoded IP addresses or debug ports',
            'network boot injection surface (no BOOTP/TFTP/DHCP)',
            'embedded ELF binaries with findable vulnerabilities',
        ],
    },
]

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'Scanned all 5 images for ELF headers (none), compression (all false positives), '
            'OpenFirmware FCode (found in all — expected). '
            'String sweep: 577-1023 strings per image, all low-entropy BIOS function names. '
            'No credentials, IPs, network boot strings, or debug ports in any image. '
            'Identified platform: IBM/Apple PPS Microcode (CHRP/PReP, 1994-1996). '
            'TR97069 + DOR97069 share firmware level 12H0656. '
            'All five images: PSERIES-FW-001 SAFE.'
        ),
        'open': [],
    },
]
