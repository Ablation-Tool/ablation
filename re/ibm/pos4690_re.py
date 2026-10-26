"""
pos4690_re.py — IBM 4690 POS OS RE findings

Targets:  4690gsa-csd.iso   — IBM 4680/4690 General Sales Application CSD PTF Q001
          4690saem-csd.iso  — IBM 4680 Electronic Marketing Support (SAEM) CSD PTF Q001

Files:    /media/cowboy/research/IBM-RE/IBM4690/4690gsa-csd.iso   (9.0MB, 2007-08-06)
          /media/cowboy/research/IBM-RE/IBM4690/4690saem-csd.iso  (1.7MB, 2013-08-19)

Session:  Session 14 — IBM 4690 POS OS triage (2026-10-25)
"""

# ── ISO metadata ──────────────────────────────────────────────────────────────

IMAGES = {
    '4690gsa-csd.iso': {
        'file':      '/media/cowboy/research/IBM-RE/IBM4690/4690gsa-csd.iso',
        'size':      9_437_184,
        'product':   'IBM 4680-4690 General Sales Application (GSA)',
        'release':   'Release 1 Version 1, PTF Q001',
        'arch':      'IBM 4690 OS 286 protected-mode (NOT DOS, NOT ELF)',
        'files':     53,
        'ext_types': {'.bat': 20, '.286': 14, '.dat': 10, '.doc': 7, '.pdf': 1, '.me': 1},
        'key_dirs':  ['USA/ (US English locale)'],
        'mount':     'mount -t iso9660 -o loop,ro 4690gsa-csd.iso /mnt/pos4690',
    },
    '4690saem-csd.iso': {
        'file':      '/media/cowboy/research/IBM-RE/IBM4690/4690saem-csd.iso',
        'size':      1_783_808,
        'product':   'IBM 4680 Electronic Marketing Support PRPQ (5799-PNH) — SAEM',
        'release':   'PTF Q001 (all fixes since GA)',
        'arch':      'IBM 4690 OS 286 protected-mode (NOT ELF)',
        'files':     15,
        'ext_types': {'.bat': 9, '.dat': 3, '.doc': 3},
        'key_dirs':  ['USA/ (US English locale)'],
        'mount':     'mount -t iso9660 -o loop,ro 4690saem-csd.iso /mnt/pos4690sm',
    },
}

# ── Architecture ──────────────────────────────────────────────────────────────

ARCH = {
    'os':       'IBM 4690 OS',
    'cpu':      'Intel 286 protected mode (16-bit segmented)',
    'format':   (
        'IBM 4690 `.286` load modules — IBM\'s proprietary 286 protected-mode executable '
        'format. NOT DOS COM/EXE, NOT ELF. The IBM 4690 OS is a real-time POS operating '
        'system for x86/286 hardware, proprietary to IBM.'
    ),
    'tooling':  (
        'BinaryContext, SemanticSearcher, SinkArgClassifier: NOT APPLICABLE. '
        'All require ELF format. `.286` is a proprietary IBM binary format. '
        'Analysis limited to: (1) file format identification, (2) string sweep, '
        '(3) documentation review from .DOC/.ME files in same CSD.'
    ),
    'csd_type': (
        'Corrective Service Distribution (CSD) = PTF bundle containing application-level '
        'fixes. Contains only the application load modules changed by the PTF, plus '
        'installation documentation. Does NOT contain the full OS.'
    ),
}

# ── Module inventory ──────────────────────────────────────────────────────────

GSA_MODULES = {
    'ADXNSXZL.286':  {'size': 58096,  'strings': 128, 'note': 'ADX namespace utility (L=linked)'},
    'EALADX1L.286':  {'size': 96080,  'strings': 57,  'note': 'EAL ADX load module 1 (references EALSDESC.DAT)'},
    'EALCON1L.286':  {'size': 95824,  'strings': 55,  'note': 'EAL configuration module (references EALRDESC.DAT)'},
    'EALMIG0L.286':  {'size': 227920, 'strings': 374, 'note': 'EAL migration module 0 — largest, 374 strings'},
    'EALMIG1L.286':  {'size': 43984,  'strings': 84,  'note': 'EAL migration module 1'},
    'EALMIG2L.286':  {'size': 23504,  'strings': 61,  'note': 'EAL migration module 2'},
    'EALMIG3L.286':  {'size': 84048,  'strings': 30,  'note': 'EAL migration module 3'},
    'EALMIG4L.286':  {'size': 36048,  'strings': 62,  'note': 'EAL migration module 4'},
    'EALMIG5L.286':  {'size': 17616,  'strings': 50,  'note': 'EAL migration module 5'},
    'EALMIG6L.286':  {'size': 19920,  'strings': 62,  'note': 'EAL migration module 6'},
    'EALMIGNL.286':  {'size': 84944,  'strings': 18,  'note': 'EAL migration (NL?) — tightly packed'},
    'EALMIGSL.286':  {'size': 82384,  'strings': 16,  'note': 'EAL migration (SL?)  — tightly packed'},
    'EALMIGXL.286':  {'size': 80464,  'strings': 16,  'note': 'EAL migration (XL?)  — tightly packed'},
    'EALMIV1L.286':  {'size': 34384,  'strings': 45,  'note': 'EAL MI version 1 load — references EALRDESCT'},
}

SAEM_MODULES = {
    'COMUPGM1.DAT':  {'size': 1_413_692, 'note': '1.4MB binary — main SAEM module bundle (DAT extension, not .286)'},
    'ADXCSTPD.DAT':  {'size': 2231,      'note': 'ADX customer/cost data table'},
    'ADXEMBPF.DAT':  {'size': 17,        'note': 'ADX embedded prefix data (17 bytes)'},
}

# ── Security sweep ────────────────────────────────────────────────────────────

SECURITY_SWEEP = {
    'method': (
        'String regex sweep across ALL files for: track data, PAN, card number, '
        'payment, encrypt/decrypt, DUKPT, DES, PIN, password, credential, telnet, '
        'FTP, TFTP, backdoor, debug port, IP addresses. Scan both binary and text files.'
    ),

    'credentials': {
        'result': 'NO HARDCODED CREDENTIALS',
        'password_refs': (
            'All "password" matches are in .DOC APAR notes describing bug fixes: '
            '"IO06528 adds complex password support", "complex password support on controller", '
            '"encrypted operator passwords (IR25274)". These are FIX descriptions, not values. '
            'No hardcoded password found in any .286 binary or .DAT file.'
        ),
        'wrong_password': '"wrong password" in README1.DOC = APAR documenting a fix for incorrect error prompt. Not a credential.',
    },

    'track_data': {
        'result': 'DOCUMENTATION ONLY',
        'hits': 'READAPL1.DOC: 64 track references; PRGUPDTE.DOC: ~9 track references',
        'analysis': (
            'All track data references are in APAR documentation (.DOC files), not in .286 binaries. '
            'Context: IR39115 "TRACK1.3.DATA$ IN EALTSCAC DID NOT CONTAIN ENOUGH BYTES TO FILL THE PIPE '
            'FOR SUBSEQUENT READ" — describes fixing an MSR pipe buffer underflow. '
            'Track 1 = 106 bytes, Track 2 = standard 40 bytes, Track 3 = 106 bytes. '
            'This is IBM\'s MSR interface specification, not hardcoded card data.'
        ),
    },

    'pan_hits': {
        'result': 'ALL FALSE POSITIVES',
        'analysis': (
            'EALIMNT1.DAT, EALIMNT2.DAT, COMUPGM1.DAT: `pan` regex matches binary byte sequences '
            'like `pAn`, `Pan` in the middle of binary 286 code. Word boundary `\\b` in binary '
            'data triggers on null bytes (0x00) and space bytes (0x20), producing false positives. '
            'No PAN (Primary Account Number) data structure found.'
        ),
    },

    'card_number': {
        'result': 'BUG FIX REFERENCES, NOT VULNERABILITIES',
        'apar_ir48076': (
            'README1.DOC: "customer card number is used as credit card number when terminal is reloaded." '
            'This APAR documents a bug that was FIXED by PTF Q001. The loyalty card (SAEM) number '
            'was being confused with the credit card number after terminal reload. The CSD FIXES this. '
            'This is a historical bug description, not a current vulnerability.'
        ),
        'customer_card': (
            'All other "card number" refs in README1.DOC are for IBM loyalty/bonus card programs '
            '(SAEM = Electronic Marketing Support = loyalty rewards program). '
            'Not credit card PANs.'
        ),
    },

    'encryption': {
        'result': 'NO CRYPTO PRIMITIVES FOUND IN BINARY',
        'des_hits': (
            'All "DES" matches in .286 binaries are false positives: "DES" appears as a substring '
            'of IBM file names like EALSDESC.DAT, EALRDESC.DAT embedded in binary module headers. '
            'No 3DES/DES/AES algorithm implementation strings. No DUKPT key management. '
            'IR25274 in README1.DOC: "Electronic Marketing Support for encrypted operator passwords" '
            '= APAR adding encrypted password support (a security IMPROVEMENT, not a finding).'
        ),
    },

    'network': {
        'result': 'NO NETWORK LISTENER STRINGS IN BINARY',
        'analysis': (
            'No telnet, FTP, TFTP, HTTP, socket, bind, listen strings in any .286 or .DAT binary. '
            'No IP addresses in binary modules (only "1.6.2.1.5" in a UPC coupon spec section number). '
            'IBM 4690 network communication is via the 4690 OS system calls, not direct socket I/O. '
            'The application layer does not implement its own network protocol stack.'
        ),
    },

    'exec_sinks': {
        'result': 'NOT APPLICABLE',
        'note': (
            'IBM 4690 OS does not use POSIX exec-class calls. It uses IBM 4690 OS system call '
            'interface (INT-based or FAR CALL to OS entry points). Neither exec() nor system() '
            'exist in this OS environment. BinaryContext/SemanticSearcher/SinkArgClassifier '
            'require ELF format and are not applicable to `.286` load modules.'
        ),
    },
}

# ── Documentation summary ─────────────────────────────────────────────────────

DOCUMENTATION = {
    'PRGUPDTE.DOC': (
        'IBM 4680-4690 GSA Programming Guide updates. Documents: '
        'new user exits (DISP.SCR.EXIT, FS.SIGCAP.EXIT, FS.DELAYED.PRINT$, ERROR.EXIT), '
        'accounting file format additions (AMTTEND16-20 tender type fields), '
        'MSR track data pipe interface (106-byte Track 1/3 buffers, 40-byte Track 2).'
    ),
    'READAPL1.DOC': (
        'APAR history for GSA PTF Q001: IR52454, IR52473, IR52552, IR52759, IR52798, '
        'IR52840, IR52863, IR53131, IR53329, IR53803, IR54003, IR54097, IR54128 and many more. '
        'Mix of POS transaction logic fixes, memory management, XML/AEF integration. '
        'Track data refs: MSR pipe buffer fixes for EALTSCAC module.'
    ),
    'MICR.DOC': 'Check Payment Service Provider integration guide for MICR. Not analyzed further.',
    'README1.DOC': (
        'SAEM APAR history. IR25274 (encrypted operator passwords), IR36818 (card number truncation), '
        'IR44513 (bonus card reporting), IR48076 (customer card ≠ credit card after reload), '
        'IR06528/IO06528 (complex password support). All are fixes, not vulnerabilities.'
    ),
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'POS4690-001',
        'verdict': 'SAFE',
        'title':   'IBM 4690 GSA + SAEM CSD ISO — no vulnerability found',
        'notes': (
            'Target: 4690gsa-csd.iso (9MB, 53 files, PTF Q001) + 4690saem-csd.iso (1.7MB, 15 files). '
            'Architecture: IBM 4690 OS 286 protected-mode `.286` load modules. '
            'NOT ELF — BinaryContext/SemanticSearcher/SinkArgClassifier not applicable. '
            'Format: IBM proprietary CSD (Corrective Service Distribution) = PTF patch bundle. '
            'String sweep results: '
            '  (1) No hardcoded credentials. Password refs are APAR fix descriptions. '
            '  (2) No PAN/track data in binaries. Track refs are MSR format specs in .DOC files. '
            '  (3) No network listener strings (telnet/FTP/TFTP/HTTP) in binary modules. '
            '  (4) No crypto primitives. "DES" matches = EALSDESC.DAT filename substrings. '
            '  (5) No hardcoded IP addresses in binary modules. '
            '  (6) No exec-class sinks (IBM 4690 OS uses its own syscall interface, not POSIX). '
            'APAR IR48076: "customer card number used as credit card number after reload" = '
            '  historical bug FIXED by this PTF. Not a current vulnerability. '
            'APAR IR25274: encrypted operator password support added = security improvement. '
            'No IBM 4690 POS vulnerability found.'
        ),
        'eliminated_classes': [
            'hardcoded credentials (only APAR documentation about password support features)',
            'payment card data exposure (track data refs are MSR format specs in .DOC files)',
            'network injection (no network protocol strings in binary modules)',
            'exec-class sinks (IBM 4690 OS does not use POSIX exec/system/popen)',
            'crypto key exposure (no DES/3DES/DUKPT key material found)',
        ],
    },
]

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'Mounted 4690gsa-csd.iso: 53 files, 14 × .286 + 10 × .DAT + 20 × .bat + 7 × .doc. '
            'Mounted 4690saem-csd.iso: 15 files, 1 × COMUPGM1.DAT (1.4MB binary). '
            'Identified: IBM 4690 OS 286 protected-mode load modules — NOT ELF. '
            'BinaryContext/SemanticSearcher not applicable. '
            'String sweep (.286 modules): 0 credential/net/crypto hits. '
            '  DES false positives = EALSDESC.DAT filename substring. '
            'Documentation sweep: track data refs are MSR format specs (APAR fix descriptions). '
            'Password refs are APAR notes for complex password + encrypted password features. '
            'Card number refs in README1.DOC: loyalty card bugs, all FIXED by PTF Q001. '
            'APAR IR48076: customer card ≠ credit card confusion — historical bug, patched here. '
            'POS4690-001 SAFE.'
        ),
        'open': [],
    },
]
