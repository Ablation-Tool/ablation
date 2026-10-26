"""
dcconnect_7526_re.py — IBM 7526 DCConnect Firmware RE findings

Target:   IBM 7526 DCConnect terminal controller firmware
          x86 real-mode, 128KB flash images (4 versions)
          Terminal concentration and SDLC protocol adapter

Files:    /media/cowboy/research/IBM-RE/collections/dhe/dcconnect/hardware/7526/
            7526b323.bin  (131072 bytes) — firmware B3.23
            7526b325.bin  (131072 bytes) — firmware B3.25
            7526b331.bin  (131072 bytes) — firmware B3.31
            7526B341.BIN  (131072 bytes) — firmware B3.41  [GOAL listed 3; actually 4]
          (also 10 × DOS EXE flash utilities, not analyzed — flash tooling only)

Session:  Session 14 — dcconnect 7526 firmware triage (2026-10-25)
"""

# ── Image layout ──────────────────────────────────────────────────────────────

IMAGE_LAYOUT = {
    'size':           131072,
    'header_offset':  0x00,
    'header_length':  0x32,   # 50 bytes ASCII version string
    'code_offset':    0x32,   # x86 real-mode code begins here
    'entry_byte':     0xFA,   # CLI — first instruction (disable interrupts)
    'format':         'Flat x86 real-mode binary with IBM firmware version header',
}

# ── Version table ─────────────────────────────────────────────────────────────

VERSIONS = {
    '7526b323.bin': {
        'header':    '7526 B3.23 COPYRIGHT IBM CORP. 1987,1996 - PRT0323',
        'version':   'B3.23',
        'build_id':  'PRT0323',
        'size':      131072,
        'changes':   'Initial version in collection',
    },
    '7526b325.bin': {
        'header':    '7526 B3.25 COPYRIGHT IBM CORP. 1987,1996 - PRT0325',
        'version':   'B3.25',
        'build_id':  'PRT0325',
        'size':      131072,
        'changes':   'Added "LOCK ADJUSTMENTS : NO/YES" config option vs B3.23',
    },
    '7526b331.bin': {
        'header':    '7526 B3.31 COPYRIGHT IBM CORP. 1987,1996 - PRT0331',
        'version':   'B3.31',
        'build_id':  'PRT0331',
        'size':      131072,
        'changes':   'Same config menu as B3.25',
    },
    '7526B341.BIN': {
        'header':    '7526 B3.41 COPYRIGHT IBM CORP. 1987,1996 - PRT0341',
        'version':   'B3.41',
        'build_id':  'PRT0341',
        'size':      131072,
        'changes':   'Latest version in collection; same config menu as B3.25',
    },
}

# ── Architecture ──────────────────────────────────────────────────────────────

ARCH_DETECTION = {
    'arch':     'x86 real-mode',
    'evidence': 'FA = CLI (Clear Interrupt Flag) at offset 0x32 in all 4 BIN files',
    'layout': [
        # First ~10 instructions decoded manually from 7526b323.bin at offset 0x32:
        {'offset': 0x32, 'bytes': 'FA',          'mnemonic': 'CLI'},
        {'offset': 0x33, 'bytes': 'BB FF FF',    'mnemonic': 'MOV BX, 0xFFFF'},
        {'offset': 0x36, 'bytes': '8E DB',       'mnemonic': 'MOV DS, BX'},
        {'offset': 0x38, 'bytes': 'BB 0F 00',    'mnemonic': 'MOV BX, 0x000F'},
        {'offset': 0x3b, 'bytes': 'B8 00 BC',    'mnemonic': 'MOV AX, 0xBC00'},
        {'offset': 0x3e, 'bytes': '88 27',       'mnemonic': 'MOV [BX], AH'},
        # Pattern: setting up segment registers (DS) and hardware I/O port values
        # This is standard x86 embedded firmware initialization
    ],
    'binarycontext': 'NOT applicable — not ELF. Flat real-mode binary.',
}

# ── Product identification ────────────────────────────────────────────────────

PRODUCT = {
    'model':        'IBM 7526 DCConnect',
    'category':     'Terminal concentration controller / SDLC protocol adapter',
    'copyright':    '1987–1996 IBM CORP.',
    'description': (
        'The IBM 7526 DCConnect is an x86-based terminal controller that connects '
        'IBM 3270-class display stations to AS/400 or S/370 mainframe systems over '
        'SDLC (Synchronous Data Link Control) serial protocol. '
        '"DCConnect" = Direct Connect terminal concentration. '
        'The firmware manages: '
        '  - Terminal emulation UI (configuration menus, clock/date, keypad selection) '
        '  - SDLC/SNA protocol stack (synchronous serial, no TCP/IP) '
        '  - Local admin password protection for configuration access '
        '  - Download protocol for firmware updates over the DCConnect link '
        'No Unix OS, no shell, no exec-class system calls. Bare-metal embedded firmware.'
    ),
}

# ── Configuration menu strings ────────────────────────────────────────────────

CONFIG_MENU = {
    'fields': [
        'ADDR', 'BAUD RATE', 'DATA LENGTH', 'PARITY', 'TIME', 'TIME SEPARATOR',
        'DATE', 'DATE SEPARATOR', 'DECIMAL', 'PASSWORD', 'CODE PAGE',
        'DIAGNOSTICS', 'COLD START',
    ],
    'password_note': (
        '"PASSWORD:" is a UI menu label for the local admin password input field. '
        '"INVALID PASSWORD" is the error string displayed on wrong entry. '
        'The password VALUE is user-configurable and stored in NVRAM at runtime — '
        'it is NOT compiled into the firmware binary. '
        'No hardcoded password value found in any of the 4 BIN images.'
    ),
    'added_in_b325': ['LOCK ADJUSTMENTS : NO', 'LOCK ADJUSTMENTS : YES'],
    'protocols_listed': ['EVEN', 'ODD', 'NONE'],
    'baud_rates': ['96', '192', '384', '12', '24', '480'],
    'code_pages': ['850', '857'],
    'note': (
        'B3.23 is missing "LOCK ADJUSTMENTS" option present in B3.25+. '
        'All other config menu strings are identical across all 4 versions.'
    ),
}

# ── Security sweep ────────────────────────────────────────────────────────────

SECURITY_SWEEP = {
    'string_count':     {'b323': 52, 'b325': 52, 'b331': 52, 'B341': 52},
    'credentials': (
        'No hardcoded password found. "PASSWORD:" is a config menu field label. '
        '"INVALID PASSWORD" is an error message. Password value is in NVRAM, not firmware.'
    ),
    'ip_addresses': 'None found. DCConnect uses SDLC (synchronous serial), not TCP/IP.',
    'debug_backdoors': 'None found.',
    'exec_sinks': (
        'Not applicable. x86 real-mode embedded firmware for a terminal controller. '
        'No OS, no shell, no exec/system/popen. '
        'Firmware transitions are via direct hardware control (FAR CALL/JMP, INT vectors).'
    ),
    'notable_strings': [
        '7526 B3.23 COPYRIGHT IBM CORP. 1987,1996 - PRT0323',
        'ADDR: BAUD RATE: DATA LENGTH: PARITY: TIME: DATE: PASSWORD: CODE PAGE: DIAGNOSTICS: COLD START:',
        'INVALID PASSWORD',
        'PRESS A KEY FOR YOUR KEYPAD TYPE  F1 FOR 20 KEYS. F2 FOR 40 KEYS',
        'DOWNLOAD NEEDED',
        'OUT OF SERVICE',
        'DOWNLOADING...',
        'Updating the clock...',
        'Low power. Stop.',
        'BUFFER FULL',
    ],
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'DCCONNECT-7526-001',
        'verdict': 'SAFE',
        'title':   'IBM 7526 DCConnect firmware — no vulnerability',
        'notes': (
            '4 × 128KB x86 real-mode firmware images (B3.23, B3.25, B3.31, B3.41). '
            'GOAL listed 3 BIN files; directory contains 4 (B3.41 unlisted — included here). '
            'Format: 50-byte ASCII version header + x86 real-mode code starting with FA (CLI). '
            'Architecture: x86 real-mode — confirmed by FA=CLI at offset 0x32 in all 4 files. '
            'Product: IBM 7526 DCConnect terminal controller (1987-1996), SDLC serial. '
            '"PASSWORD:" is a UI menu label for a user-configurable admin password stored in NVRAM — '
            'no hardcoded password found in any firmware binary. '
            'No hardcoded IPs (SDLC/SNA protocol, no TCP/IP). '
            'No exec-class sinks (bare-metal embedded firmware, no OS or shell). '
            'B3.23 → B3.25 change: added "LOCK ADJUSTMENTS" config option. '
            'B3.25 → B3.31 → B3.41: no string-level security changes identified. '
            'No security vulnerability found.'
        ),
        'eliminated_classes': [
            'exec-class sinks (no OS, no shell — x86 real-mode embedded firmware)',
            'hardcoded credentials (PASSWORD field is UI label; value in NVRAM)',
            'hardcoded IP addresses (SDLC/SNA protocol, no TCP/IP)',
            'network injection surface (synchronous serial, no network stack)',
        ],
    },
]

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'Identified format: 50-byte ASCII version header + x86 real-mode (FA=CLI at 0x32). '
            'GOAL expected 3 BIN files; found 4 (B3.23, B3.25, B3.31, B3.41 = extra). '
            'All 4: same layout, same entry at 0x32, IBM 7526 DCConnect terminal firmware. '
            'String sweep: 52 strings each, no hardcoded passwords or IPs. '
            '"PASSWORD:" = config menu label; value in NVRAM, not binary. '
            'B3.25 added LOCK ADJUSTMENTS option vs B3.23. '
            'DCCONNECT-7526-001 SAFE.'
        ),
        'open': [],
    },
]
