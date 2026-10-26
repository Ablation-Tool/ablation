"""
z390_ptf_re.py — IBM z390 OnDemand PTF RE findings

Targets:  uq33628, uq33629, uq33906
          IBM Content Manager OnDemand for z/OS, product 5655-A88
          SMP/E MCS format (EBCDIC, 80-byte card-image records)
          Date: 1999-08-20 (DAY 99231 = August 19, 1999)

Files:    /media/cowboy/research/IBM-RE/z390-PTFs/uq33628 (1.1MB, 14141 records)
          /media/cowboy/research/IBM-RE/z390-PTFs/uq33629 (2.1MB, 26734 records)
          /media/cowboy/research/IBM-RE/z390-PTFs/uq33906 (408KB, 5099 records)

Format:   NOT XMIT. SMP/E Modification Control Statement (MCS) format.
          Begins with '++ PTF (name)' in EBCDIC. 80-byte card-image records.
          Contains ++ MOD (object code), ++ DATA (database content),
          ++ DATA3 (JCL), ++ SAMP (sample code), ++ JCLIN (link-edit JCL),
          ++ HOLD (install instructions).

Session:  Session 14 — z390-PTF format triage (2026-10-25)
"""

# ── PTF identification ───────────────────────────────────────────────────────

PTF_HEADERS = {
    'UQ33628': {
        'product':  '5655-A88-00-H07L210',
        'fmid':     'H07L210',
        'apar':     'PQ23885',
        'prereqs':  ['UQ32442', 'UQ30568', 'UQ30472', 'UQ27617', 'UQ27445'],
        'co_req':   {'J07L212': 'UQ33906', 'J07L211': 'UQ33629'},
        'description': (
            'Adds IODEXPVW pre-view exit for document retrieval. '
            'Called from IODXDOCG before document is returned to client. '
            'Adds SDT row IODXDOCG to control exit invocation.'
        ),
    },
    'UQ33629': {
        'product':  '5655-A88-00-J07L211',
        'fmid':     'J07L211',
        'apar':     'PQ23885',
        'prereqs':  ['UQ33628'],
        'co_req':   {'J07L212': 'UQ33906'},
        'description': (
            'Adds IODEXPVW preview exit to GUI Server component (IODXDOCG). '
            'Also patches IODXSECV (security verification) for GUI Server path. '
            'Functional enhancement; not a security fix.'
        ),
    },
    'UQ33906': {
        'product':  '5655-A88-00-J07L212',
        'fmid':     'J07L212',
        'apar':     'PQ24468',
        'prereqs':  ['UQ27532', 'UQ33628'],
        'co_req':   {'J07L211': 'UQ33629'},
        'description': (
            'Modifies IODIAMIG (IAFC→OnDemand migration) to include SRT processing exit '
            'for generating additional POSTING DATES for IAFC archive access compatibility. '
            'Functional enhancement.'
        ),
    },
}

# ── Module inventory ─────────────────────────────────────────────────────────

MODULES = {
    # UQ33628 (H07L210) — batch/base features
    'IODBERF':  {'ptf': 'UQ33628', 'type': 'MOD+DATA+JCL', 'notes': 'Batch error/report function'},
    'IODBOBPT': {'ptf': 'UQ33628', 'type': 'MOD+DATA+JCL', 'notes': 'Batch object print'},
    'IODBPRNT': {'ptf': 'UQ33628', 'type': 'MOD+DATA+JCL', 'notes': 'Batch print'},
    'IODBSAR':  {'ptf': 'UQ33628', 'type': 'MOD+DATA+JCL', 'notes': 'Batch store/archive'},
    'IODCFOBJ': {'ptf': 'UQ33628', 'type': 'MOD+DATA',     'notes': 'Cache/file object management'},
    'IODCRASL': {'ptf': 'UQ33628', 'type': 'MOD+DATA',     'notes': 'Cache RASL (random access)'},
    'IODCSDIR': {'ptf': 'UQ33628', 'type': 'MOD+DATA',     'notes': 'Cache/store directory'},
    'IODCSRPT': {'ptf': 'UQ33628', 'type': 'MOD+DATA',     'notes': 'Cache/store report'},
    'IODEXPVW': {'ptf': 'UQ33628', 'type': 'MOD+SAMP+JCLIN',
                 'notes': 'Preview exit — CICS-linked (DFHECI). User exit called before doc delivery.'},
    'IODMODIR': {'ptf': 'UQ33628', 'type': 'MOD',          'notes': 'Module directory'},
    'IODSDAPI': {'ptf': 'UQ33628', 'type': 'MOD+DATA',     'notes': 'System data (SDT) API'},
    'IODSDIRM': {'ptf': 'UQ33628', 'type': 'MOD',          'notes': 'Store directory management'},
    'IODSQLB':  {'ptf': 'UQ33628', 'type': 'MOD',          'notes': 'SQL batch'},
    'IODSQLIR': {'ptf': 'UQ33628', 'type': 'MOD+DATA',     'notes': 'SQL index/retrieval'},
    'IODULAPI': {'ptf': 'UQ33628', 'type': 'MOD+DATA',     'notes': 'User-level API'},
    'IODDSDPV': {'ptf': 'UQ33628', 'type': 'DATA1',        'notes': 'Default SDT row delete JCL for IODXDOCG'},
    'IODISDPV': {'ptf': 'UQ33628', 'type': 'DATA1',        'notes': 'Default SDT row insert JCL for IODXDOCG'},
    # UQ33629 (J07L211) — GUI/XML server features
    'IODXANNO': {'ptf': 'UQ33629', 'type': 'MOD+DATA',     'notes': 'XML annotation'},
    'IODXDOCG': {'ptf': 'UQ33629', 'type': 'MOD+DATA',     'notes': 'XML document get — calls IODEXPVW preview exit'},
    'IODXDOCP': {'ptf': 'UQ33629', 'type': 'MOD+DATA',     'notes': 'XML document put'},
    'IODXDOCQ': {'ptf': 'UQ33629', 'type': 'MOD',          'notes': 'XML document query'},
    'IODXFLDG': {'ptf': 'UQ33629', 'type': 'MOD+DATA',     'notes': 'XML field get'},
    'IODXFLDQ': {'ptf': 'UQ33629', 'type': 'MOD+DATA',     'notes': 'XML field query'},
    'IODXLOGN': {'ptf': 'UQ33629', 'type': 'MOD+DATA',     'notes': 'XML server logon'},
    'IODXLSTN': {'ptf': 'UQ33629', 'type': 'MOD',          'notes': 'XML server listener'},
    'IODXSECV': {'ptf': 'UQ33629', 'type': 'MOD',          'notes': 'XML security verification — patched for preview exit'},
    'IODXSRVR': {'ptf': 'UQ33629', 'type': 'MOD',          'notes': 'XML server main module'},
    # UQ33906 (J07L212) — IAFC migration features
    'IODEXMIG': {'ptf': 'UQ33906', 'type': 'MOD+SAMP+JCLIN',
                 'notes': 'IAFC→OnDemand migration program; adds SRT exit. REUS=YES, not APF.'},
    'IODIADEL': {'ptf': 'UQ33906', 'type': 'MOD+DATA+JCLIN',
                 'notes': 'IAFC archive index delete — PL/I (PLISTART entry), APF authorized (AC=1), '
                          'DB2 CAF (DSNALI). Deletes index/archive records from OnDemand DB2 tables.'},
    'IODIAMIG': {'ptf': 'UQ33906', 'type': 'MOD+DATA+JCL', 'notes': 'IAFC→OnDemand migration'},
    'IODIFAPI': {'ptf': 'UQ33906', 'type': 'MOD',
                 'notes': 'IAFC full API — CICS + DB2 CLI (DSNCLI/IODIFAPC). Not APF-authorized.'},
    'IODMODIA': {'ptf': 'UQ33906', 'type': 'MOD+DATA',     'notes': 'Module directory for IAFC'},
    'IODSQLIA': {'ptf': 'UQ33906', 'type': 'MOD+DATA',     'notes': 'SQL IAFC access'},
}

# ── DB2 schema extracted from DBRM in UQ33906 ───────────────────────────────

DB2_SCHEMA = {
    'VUSERIN2': {
        'purpose': 'User/archive index — primary object table',
        'columns': [
            'CLIENT_NO CHAR(2) NOT NULL',
            'APPLIC_AKZ CHAR(2) NOT NULL',
            'ARCHIV_IDENT CHAR(8) NOT NULL',
            'ALIAS_COL SMALLINT NOT NULL',
            'OAM_OBJEKT_LENGTH INTEGER NOT NULL',
            'OAM_TIME_ST TIMESTAMP NOT NULL',
            'OAM_NR SMALLINT NOT NULL',
            'OAM_OBJEKT_OFFSET INTEGER NOT NULL',
            'HIGH_INDEX1 VARCHAR(55) NOT NULL',
            'LOW_INDEX1 VARCHAR(55) NOT NULL',
            'HIGH_INDEX2 VARCHAR(55) NOT NULL',
            'LOW_INDEX2 VARCHAR(55) NOT NULL',
            'HIGH_INDEX3 VARCHAR(55) NOT NULL',
            'LOW_INDEX3 VARCHAR(55) NOT NULL',
            'OAM_OBJECT_NAME VARCHAR(44) NOT NULL',
        ],
    },
    'VCOLIND': {
        'purpose': 'Collection index table',
        'columns': [
            'ALIAS_COL SMALLINT NOT NULL',
            'M_INDEX_LENGTH INTEGER NOT NULL',
            'M_OBJEKT_SIZE INTEGER NOT NULL',
            'COLL_LENGTH SMALLINT NOT NULL',
            'COLLECTIONNAME VARCHAR(44) NOT NULL',
        ],
    },
    'VPRO08': {
        'purpose': 'Process log (LFN transaction log)',
        'columns': [
            'LFN_NR SMALLINT NOT NULL',
            'TRANS_ID CHAR(4) NOT NULL',
            'TEXT CHAR(133)',
        ],
    },
    'VCIK01': {
        'purpose': 'Collection information table',
        'columns': [
            'CLIENT_NO CHAR(2) NOT NULL',
            'APPLIC_AKZ CHAR(2) NOT NULL',
            'APPLIC_NAME CHAR(15)',
            'COMP_NAME CHAR(20)',
            'OBJ_SIZE INTEGER NOT NULL',
            'IDATA_NAME CHAR(8) NOT NULL',
            'COLL_NAME CHAR(44)',
            'COMPR_FLAG CHAR(1)',
            'COMPR_NAME CHAR(8)',
            'LINE_LL SMALLINT NOT NULL',
        ],
    },
}

# ── Findings ────────────────────────────────────────────────────────────────

FINDINGS = [

    # ── PTF-001 ────────────────────────────────────────────────────────────
    {
        'id':      'PTF-001',
        'verdict': 'SAFE',
        'scope':   'UQ33628, UQ33629, UQ33906',
        'title':   'No security vulnerability — functional enhancements',
        'notes': (
            'Three PTFs for IBM Content Manager OnDemand 5655-A88 (1999). '
            'APAR PQ23885 (UQ33628/UQ33629): adds IODEXPVW document preview exit for '
            '  batch/CICS and GUI Server paths. Not a security fix. '
            'APAR PQ24468 (UQ33906): adds SRT exit to IAFC migration tool. Not a security fix. '
            'No hardcoded credentials. No shell injection vectors. No network listeners added. '
            'IODXSECV (security verification) patched in UQ33629 for preview exit integration '
            '  — not for a security vulnerability. '
            'IODIADEL (UQ33906) is APF-authorized (AC=1) and PL/I, using DB2 CAF (DSNALI): '
            '  this is normal for z/OS batch archive deletion utilities; the APF auth is '
            '  needed for OAM (Object Access Method) object management. No vulnerability. '
            'DB2 schema recovered from DBRM: VUSERIN2 (archive index), VCOLIND (collections), '
            '  VPRO08 (transaction log), VCIK01 (collection info). No sensitive data in schema. '
            'GOAL plan note: actual format is SMP/E MCS, not XMIT. No code RE needed — '
            '  no critical security LMOD. IODIADEL is AC=1 but implements expected behavior.'
        ),
    },
]

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'Decoded EBCDIC 80-byte card-image records. '
            'Extracted ++ PTF/MOD/DATA/HOLD/JCLIN statements from all three files. '
            'Identified product: IBM Content Manager OnDemand 5655-A88. '
            'APARs: PQ23885 (preview exit), PQ24468 (IAFC migration exit). '
            'Identified IODIADEL as APF-authorized PL/I program using DB2 CAF. '
            'Extracted DB2 schema from DBRM payload in UQ33906 DATA section. '
            'Confirmed: no credentials, no shell injection, no security vulnerability. '
            'Result: PTF-001 SAFE.'
        ),
        'open': [],
    },
]
