"""
as400_re.py — IBM AS/400 NC-AS400 SAVLIB RE findings

Target:   qzrdu0mm.sav (and variants nsm30/qzrdu0mm.sav, v3r7/qzrdu0mm.sav)
          IBM OS/400 SAVLIB, V3R1 minimum to restore
          Pack file display/extraction utility library (library PACKDEV)
          NC = NC (Network Client?) redistribution utility

Files:    /media/cowboy/research/IBM-RE/NC-AS400/qzrdu0mm.sav (185856B, 1997-11-03)
          /media/cowboy/research/IBM-RE/NC-AS400/v3r7/qzrdu0mm.sav (185856B, 1997-11-18)
          /media/cowboy/research/IBM-RE/NC-AS400/nsm30/qzrdu0mm.sav (205392B, 1999-04-14)

Format:   IBM OS/400 SAVLIB binary (proprietary). Confirmed by `file` command.
          Not extractable with savf2zip (not installed). TIMI disasm requires
          live V3R1 system — not attempted per GOAL plan.

Session:  Session 14 — AS/400 SAVLIB format triage (2026-10-25)
"""

# ── SAVLIB header fields ─────────────────────────────────────────────────────

HEADER = {
    'format':          'IBM OS/400 SAVLIB (proprietary)',
    'min_restore_ver': 'V3R1',
    # From EBCDIC string at offset 0x10
    'source_system':   {
        'root':  '9406 D80  (IBM AS/400, model D80), system RCHASP06',
        'v3r7':  '9406 D80  (same hardware as root)',
        'nsm30': '9406 E90  (newer IBM AS/400, system RCHASL2K)',
    },
    'library_name': 'PACKDEV',
}

# ── Object inventory (all three versions contain the same 9 objects) ─────────

OBJECTS = [
    {
        'name':        'QZRDPACK',
        'type':        '*SRVPGM or *PGM (likely *SRVPGM)',
        'owner':       'QPGMR',
        'sysval_ref':  True,
        'description': 'Main pack file service program',
    },
    {
        'name':        'QZRDPDSP',
        'type':        '*PGM (ILE C)',
        'owner':       'QPGMR',
        'compiled':    {'root/v3r7': '1997-01-13 15:40', 'nsm30': '1998-07-07 10:38'},
        'description': 'Main display pack file program',
        'service_progs': ['QC2IO', 'QC2UTIL1', 'QLEAWI'],   # root
    },
    {
        'name':        'QZRDPDSPCL',
        'type':        '*PGM (CLP)',
        'owner':       'QPGMR',
        'compiled':    {'root/v3r7': '1997-01-13 15:40', 'nsm30': '1998-07-07 10:38'},
        'description': 'Main CL program for display pack file',
        'cl_calls':    ['QZRDPDSP'],
        'parms':       ['&NAME', '&RLIB'],
    },
    {
        'name':        'QZRDPEXT',
        'type':        '*PGM (ILE C)',
        'owner':       'QPGMR',
        'compiled':    {'root/v3r7': '1997-01-13 15:41', 'nsm30': '1998-07-07 10:38'},
        'description': 'Main extract pack file program',
        'service_progs': ['QC2SYS', 'QC2IO', 'QC2UTIL1', 'QLEAWI'],  # root
    },
    {
        'name':        'QZRDPEXTCL',
        'type':        '*PGM (CLP)',
        'owner':       'QPGMR',
        'compiled':    {'root/v3r7': '1997-01-13 15:41', 'nsm30': '1998-07-07 10:38'},
        'description': 'Main CL program for extract pack file',
        'cl_calls':    ['QZRDPEXT'],
        'parms':       ['&PFILE', '&PLIB'],
    },
    {
        'name':        'DSPPCKF',
        'type':        '*CMD',
        'owner':       'QPGMR',
        'description': 'Display pack file command',
    },
    {
        'name':        'EXTPCKF',
        'type':        '*CMD',
        'owner':       'QPGMR',
        'description': 'Extract pack file command',
    },
    {
        'name':        'QDZRDPDSP',
        'type':        '*FILE (display file / DDS)',
        'owner':       'QPGMR',
        'compiled':    {'root/v3r7': '1996-12-12 08:22', 'nsm30': '?'},
        'description': 'Display file for display pack file program',
    },
    {
        'name':        'QHZRDCMD1',
        'type':        '*PNLGRP (help panel group)',
        'owner':       'QPGMR',
        'description': 'Help text for DSPPCKF and EXTPCKF commands',
    },
]

# ── Version comparison ───────────────────────────────────────────────────────

VERSIONS = {
    'root (V3R1, 1997-11-03)': {
        'size': 185856,
        'system': 'RCHASP06',
        'objects': 9,
        'compile_date': '1997-01-13',
        'notes': 'Original V3R1 build',
    },
    'v3r7 (V3R1, 1997-11-18)': {
        'size': 185856,
        'system': 'RCHASP06',
        'objects': 9,
        'compile_date': '1997-01-13',
        'notes': 'Identical compile dates to root — likely re-saved from same compiled objects',
    },
    'nsm30 (V3R1, 1999-04-14)': {
        'size': 205392,
        'system': 'RCHASL2K',
        'objects': 9,
        'compile_date': '1998-07-07',
        'notes': 'Recompile on newer 9406 E90 hardware; nsm30 = NSM v3.0 release',
    },
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'AS400-001',
        'verdict': 'SAFE',
        'title':   'Pack file utility library — no security vulnerability',
        'notes': (
            'PACKDEV library provides 9 OS/400 objects for displaying/extracting '
            'IBM pack files (compressed distribution format). '
            'No network listeners, no authentication logic, no credentials. '
            'Programs: DSPPCKF (display), EXTPCKF (extract). '
            'ILE C programs link to IBM-supplied QC2IO/QC2SYS/QLEAWI service programs '
            '(standard I/O and LE runtime — expected for ILE C). '
            'Three versions (1997 × 2, 1998): same 9 objects, no new objects added. '
            'TIMI disasm not attempted (requires live V3R1 system — per GOAL plan). '
            'No TIMI analysis needed: string content is non-security-relevant utilities.'
        ),
    },
]

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'Confirmed savf2zip not installed. '
            'Hex-parsed SAVLIB format: identified QSYS L/D OBJECT DESCRIPTOR records, '
            'EBCDIC object names, owner (QPGMR), compilation info. '
            'Identified 9 objects in all 3 versions of qzrdu0mm.sav. '
            'Product: PACKDEV library (pack file display/extract utilities). '
            'Source system: RCHASP06 (9406-D80) / RCHASL2K (9406-E90). '
            'Compiled V3R1M0 (1997 and 1998). '
            'No credentials, no network code, no security vulnerability. '
            'AS400-001 SAFE.'
        ),
        'open': [],
    },
]
