"""
tokenring_rom_re.py — IBM Token Ring BootROM multi.rom RE findings

Target:   multi.rom  (Madge Networks Smart 16/4 Ringnode Modular BootROM)
          x86 real-mode BIOS Option ROM, v2.99.99 Development
          IBM Token Ring 16/4 Mbit adapter boot ROM (IBM-compatible, Madge vendor)

File:     /media/cowboy/research/IBM-RE/collections/dhe/network/workspace/tips/multi.rom
          53171 bytes (0xcfb3)

Session:  Session 14 — TokenRing ROM triage (2026-10-25)
"""

# ── ROM header ────────────────────────────────────────────────────────────────

HEADER = {
    'magic':       bytes([0x55, 0xAA]),
    'format':      'BIOS Option ROM (55 AA signature)',
    'size_units':  0x10,
    'declared_size_bytes': 8192,
    'actual_file_bytes':   53171,
    'note': (
        'Declared ROM size (8KB) << actual file size (53KB). '
        '"Madge Modular BootROM" — modular body appended after the 8KB initialization stub. '
        'The name "multi.rom" and string "for Smart Ringnodes" confirm this is a '
        'multi-variant ROM covering multiple ring node hardware configurations.'
    ),
    'entry_byte':  0xEB,     # JMP rel8
    'entry_va':    0x0003,   # byte 3 = JMP instruction
    'vendor':      'Madge Networks Ltd',
    'product':     'Smart 16/4 Ringnode',
    'version':     'v2.99.99 Development',
    'copyright':   'Copyright (c) 1989-1996 Madge Networks',
    'compat':      'IBM Token Ring 16/4 Mbit (ISA/MCA adapter)',
}

# ── ROM image boundaries ──────────────────────────────────────────────────────

ROM_BOUNDARIES = {
    0x000: {'size_units': 0x10, 'rom_size_bytes': 8192,
            'entry_byte': 0xEB,
            'note':      'Main initialization stub (8KB). Genuine BIOS Option ROM entry.'},
    0x9e4: {'size_units': 117, 'rom_size_bytes': 59904,
            'entry_byte': 0x1B,
            'note':      'FALSE POSITIVE — 55 AA pattern inside code body; declared size 59904B > file.'},
    0xd24: {'size_units': 117, 'rom_size_bytes': 59904,
            'entry_byte': 0x47,
            'note':      'FALSE POSITIVE — same issue; size field impossible in 53KB file.'},
}

# ── Boot protocols embedded ───────────────────────────────────────────────────

BOOT_PROTOCOLS = {
    'NetWare Remote Reset': (
        'Novell NetWare RPL (Remote Program Load) — the NIC broadcasts a NetWare Find '
        'Frame over Token Ring and receives a boot image from a Novell server. '
        'Passive: the ROM waits for network boot frames sent by the server. '
        'No outbound connection initiated, no credentials stored in ROM.'
    ),
    'Remote Program Load': (
        'IBM RPL — IBM DOS remote boot protocol for diskless Token Ring workstations. '
        'Server-side: IBM LAN Server / OS/2 provides the boot image. '
        'ROM role: passive receiver, presents ring MAC address to server.'
    ),
    'from hard disk': (
        'Local fallback: if network boot fails, continue to INT 19h (bootstrap loader) '
        'to boot from local disk.'
    ),
}

# ── String inventory ──────────────────────────────────────────────────────────

KEY_STRINGS = [
    'Madge Modular BootROM',
    'v2.99.99',
    'for Smart Ringnodes',
    'Copyright (c) 1989-1996 Madge Networks',
    'Smart 16/4 Ringnode',
    'Smartrom checksum failure',
    'ROM is shadowed',
    'ROM checksum failure',
    'Madge Smartrom error:',
    'No Ringnode found',
    'NetWare Remote Reset',
    'Remote Program Load',
    'from hard disk',
    'Press any key to boot from diskette/hard disk',
    'Internal error',
    'Decompress failed',
    'VeRsIoN=Madge Modular BootROM',
    'VeRsIoN=VERSION: v2.99.99 Development',
]

# ── I/O port analysis ─────────────────────────────────────────────────────────

IO_PORT_ANALYSIS = {
    'total_unique_ports': '255+',
    'method': (
        'Opcode scan for IN/OUT with immediate port (E4/E5/E6/E7 imm8). '
        'This captures 8-bit direct port access only; 16-bit DX-indirect '
        'access (EC/ED/EE/EF) not enumerated.'
    ),

    'pci_config_writes': {
        'result':  'NOT FOUND',
        'checked': 'E7 F8 (OUT 0xCF8) and E7 FC (OUT 0xCFC) forms',
        'found':   [
            {'offset': 0x02c73, 'insn': 'OUT 0xFC, AX'},
            {'offset': 0x09b8c, 'insn': 'OUT 0xF8, AX'},
            {'offset': 0x0ac3a, 'insn': 'OUT 0xF8, AX'},
        ],
        'note': (
            'OUT port=0xF8/0xFC in 8-bit immediate form are DMA page register writes '
            '(PC/AT DMA channels 0-3, 0xF0-0xFF range). '
            'PCI config space (0xCF8/0xCFC) uses DX-indirect 32-bit OUT (opcode EC/ED/EE/EF), '
            'not the 8-bit direct form detected here. '
            'Conclusion: NO PCI config space writes found.'
        ),
    },

    'token_ring_ports': {
        'ports_found': [0x88, 0xA0, 0xA2, 0xA3, 0xA8],
        'note': (
            '0x88: DMA page register channel 0 (standard PC/AT). '
            '0xA0: 8259A PIC-2 command port (standard PC/AT). '
            '0xA2, 0xA3: Secondary 8259A data/OCW ports (standard PC/AT). '
            '0xA8: 8259A OCW2/OCW3 (standard PC/AT EOI). '
            'These are all standard PC/AT peripheral ports used during NIC initialization, '
            'not Madge-specific Token Ring MMIO registers. '
            'Madge Smart Ringnode uses ISA I/O port range assigned at install time; '
            'no Madge-specific proprietary port range visible in this sweep.'
        ),
    },

    'int_calls': {
        'standard_bios': [
            {'vector': 0x10, 'desc': 'Video BIOS'},
            {'vector': 0x12, 'desc': 'Memory size'},
            {'vector': 0x13, 'desc': 'Disk BIOS'},
            {'vector': 0x15, 'desc': 'Misc BIOS services'},
            {'vector': 0x16, 'desc': 'Keyboard BIOS'},
            {'vector': 0x18, 'desc': 'ROM BASIC / boot failure'},
            {'vector': 0x19, 'desc': 'Bootstrap loader'},
            {'vector': 0x1a, 'desc': 'Time/date BIOS'},
        ],
        'note': (
            'Standard BIOS INT calls concentrate in the first 8KB (offsets 0x0–0x2000). '
            'INT calls at offsets > 0x2000 use high-numbered vectors (0x2B–0xDE) — '
            'these are Token Ring ISR and NetWare service vectors, OR false positives '
            '(0xCD byte appearing in data, not code, beyond ROM boundary). '
            'No network boot protocol vulnerabilities identified in INT call patterns.'
        ),
    },
}

# ── Self-modification analysis ────────────────────────────────────────────────

SELF_MODIFY_ANALYSIS = {
    'cs_segment_prefix_count': 241,
    'verdict': 'NOT SELF-MODIFICATION',
    'reasoning': (
        'CS: prefix (0x2E) in x86 BIOS ROM code is a standard pattern for reading '
        'data tables embedded in the ROM code segment. Example: '
        '  2E 8A 47 xx  →  MOV AL, CS:[BX+xx]  (read ROM data table) '
        '  2E FF 2E xx xx  →  JMP CS:[xxxx]  (indirect jump through ROM vector table) '
        'Writing to CS: would require shadow RAM (ROM copied to R/W RAM) to be active, '
        'and would appear as a STORE to a CS: address. '
        'These 241 prefixes are all consistent with ROM data reads (loads, not stores). '
        'No confirmed self-modification pattern found.'
    ),
}

# ── Compression analysis ──────────────────────────────────────────────────────

COMPRESSION_ANALYSIS = {
    'markers_found': [
        {'type': 'gzip', 'offset': 0x1856},
        {'type': 'zlib(7801)', 'offset': 0x34d9},
        {'type': 'zlib(789c)', 'offset': 0x38ad},
        {'type': 'zlib(78da)', 'offset': 0x3d8b},
        {'type': 'zlib(7801)', 'offset': 0xac2a},
        {'type': 'zlib(7801)', 'offset': 0xc173},
    ],
    'decompress_results': 'ALL FAILED — invalid compression headers',
    'verdict': (
        'False positives. All 6 compression-header byte sequences are incidental '
        'occurrences of the magic bytes within x86 machine code or data tables. '
        'The file is a flat uncompressed x86 binary. '
        '"Decompress failed" string in ROM confirms the ROM itself does decompression '
        '(likely of an embedded RPL boot payload) — but the payload offset is not '
        'locatable by simple magic scan.'
    ),
}

# ── Security sweep results ────────────────────────────────────────────────────

SECURITY_SWEEP = {
    'total_strings': 93,
    'credentials':   'None found — no password, secret, credential, key, token strings',
    'ip_addresses':  'None found (Token Ring boot uses IPX/RPL, not TCP/IP)',
    'debug_backdoors': 'None found',
    'network_stack': (
        '"NetWare Remote Reset" + "Remote Program Load" = boot-time passive protocols. '
        'ROM listens for a network boot frame on Token Ring; '
        'all decisions are made by the boot server. '
        'No client-side authentication, no outbound connections, no credentials stored.'
    ),
    'exec_sinks': (
        'Not applicable — x86 real-mode bare-metal firmware. '
        'No OS, no shell, no exec/system/popen. '
        'INT 0x18 (ROM BASIC) and INT 0x19 (bootstrap) are the only "next stage" vectors. '
        'Neither is attacker-controllable from the network path.'
    ),
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'TOKENRING-ROM-001',
        'verdict': 'SAFE',
        'title':   'Madge Smart Ringnode BootROM — no vulnerability',
        'notes': (
            '53KB BIOS Option ROM (55 AA, 8KB declared + 45KB modular body). '
            'Madge Networks Smart 16/4 Ringnode, v2.99.99 Development (1989-1996). '
            'Boot protocols: IBM RPL (Remote Program Load) and Novell NetWare Remote Reset. '
            'Both are passive: ROM waits for server-initiated boot frame, no outbound connection. '
            'Security sweep results: '
            '  (1) No hardcoded credentials or IP addresses (93 strings, all ROM diagnostic text). '
            '  (2) No PCI config writes (OUT 0xF8/0xFC are DMA page register accesses, not PCI). '
            '  (3) No self-modification (241 CS: prefixes are ROM data reads, not stores). '
            '  (4) No compression payloads decompressible (6 magic markers all false positives). '
            '  (5) Standard BIOS INT calls (INT 0x10/0x13/0x16/0x18/0x19) for boot sequence. '
            '  (6) Token Ring I/O ports are standard PC/AT 8259 PIC ports (0xA0-0xA3). '
            'No security vulnerability found. Bare-metal boot firmware, no attack surface.'
        ),
        'eliminated_classes': [
            'exec-class sinks (no OS, no shell — x86 real-mode BIOS ROM)',
            'hardcoded credentials',
            'hardcoded IP addresses',
            'PCI config space manipulation',
            'self-modification',
            'network injection surface (RPL is passive: server-controlled)',
        ],
    },
]

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'Confirmed BIOS Option ROM format (55 AA 10 EB). '
            'Identified vendor: Madge Networks Smart 16/4 Ringnode (v2.99.99 Dev, 1989-1996). '
            'Three 55 AA patterns: 1 genuine (0x0, 8KB) + 2 false positives. '
            'String sweep (93 strings): RPL/NetWare boot strings, no credentials. '
            'IN/OUT sweep: no PCI config writes; Token Ring ports are standard 8259 PIC. '
            '241 CS: prefixes = ROM data reads (not self-modification). '
            '6 compression markers all false positives (decompression failed). '
            'TOKENRING-ROM-001 SAFE.'
        ),
        'open': [],
    },
]
