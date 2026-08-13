"""
cisco_asdm_jar_re.py — Cisco ASDM JAR reverse engineering module.

Methodology grounded in:
  - "Decompiling Java" (Apress, ISBN 9781430207399): class file structure,
    constant pool layout, disassembler/decompiler tooling, javap usage
  - JVM Specification (ISBN 9780133922745): formal constant pool tag table,
    cp_info format, CONSTANT_Utf8_info (tag=1), CONSTANT_String_info (tag=8),
    CONSTANT_Methodref_info (tag=10), NameAndType (tag=12), descriptor format,
    ClassFile big-endian u1/u2/u4 encoding, CAFEBABE magic validation

Target:
  Cisco ASA at 207.254.35.12 (MacStadium) and 207.254.16.2 serving ASDM as a
  Java WebStart application via /+CSCOU+/asa/asdm.jnlp.

ASDM auth flow (207.254.35.12:443):
  1. GET /admin/launch  ->  302  ->  /+CSCOE+/logon.html (form login page)
  2. POST /+webvpn+/index.html  username=X&password=Y&Login=Login
       Response: Set-Cookie: webvpnc=...; webvpnlogin=1
  3. GET /admin/public/asdm.jnlp  (authenticated, returns JNLP XML)
  4. JNLP references jar resources at /+CSCOU+/asa/asdm-*.jar
  5. Subsequent management: HTTPS POST/GET to /admin/config.html with
     session cookie; REST API at /api/... (ASA 9.3+)
  6. ASDM JAR skips TLS cert verification against ASA (self-signed);
     custom X509TrustManager that accepts any cert is compiled in.

Stdlib only: struct, zipfile, re, json, io, hashlib, subprocess, os,
             ssl, urllib.request, urllib.error, tempfile
"""

import struct
import zipfile
import re
import json
import io
import hashlib
import subprocess
import os
import ssl
import urllib.request
import urllib.error
import tempfile
from typing import Optional


# ---------------------------------------------------------------------------
# ASDM download URL constants
# ---------------------------------------------------------------------------

# MacStadium target hosts
MACSTADIUM_HOST_PRIMARY   = '207.254.35.12'
MACSTADIUM_HOST_SECONDARY = '207.254.16.2'

# JNLP entry points (tried in order)
JNLP_PATHS = [
    '/+CSCOU+/asa/asdm.jnlp',
    '/admin/public/asdm.jnlp',
    '/admin/launch',
    '/admin/public/asdm-launcher.jnlp',
    '/+CSCOE+/asdm.jnlp',
    '/ASDM_Launcher.jnlp',
]

# JAR download paths (the JNLP references these; also try directly)
JAR_PATHS = [
    '/+CSCOU+/asa/asdm.jar',
    '/+CSCOU+/asa/asdm-openjre.jar',
    '/+CSCOU+/asa/dm-launcher.jar',
    '/admin/public/asdm.jar',
    '/admin/public/asdm-openjre.jar',
]

# Authentication endpoint (form POST)
AUTH_POST_PATH  = '/+webvpn+/index.html'
AUTH_POST_BODY  = 'username={user}&password={pw}&Login=Login&tgroup='

# REST API root (ASA 9.3+)
REST_API_ROOT   = '/api/cli/exec'

# WebVPN CSTP header marker
CSTP_HEADER = 'X-CSTP-Version'


# ---------------------------------------------------------------------------
# JVM constant pool tag constants (JVM Spec §4.4 Table 4.4-A)
# ---------------------------------------------------------------------------

CP_UTF8                 = 1    # CONSTANT_Utf8_info          — string bytes
CP_INTEGER              = 3    # CONSTANT_Integer_info
CP_FLOAT                = 4    # CONSTANT_Float_info
CP_LONG                 = 5    # CONSTANT_Long_info           — consumes 2 slots
CP_DOUBLE               = 6    # CONSTANT_Double_info         — consumes 2 slots
CP_CLASS                = 7    # CONSTANT_Class_info          — name_index
CP_STRING               = 8    # CONSTANT_String_info         — string_index -> UTF8
CP_FIELDREF             = 9    # CONSTANT_Fieldref_info
CP_METHODREF            = 10   # CONSTANT_Methodref_info
CP_INTERFACE_METHODREF  = 11   # CONSTANT_InterfaceMethodref_info
CP_NAME_AND_TYPE        = 12   # CONSTANT_NameAndType_info
CP_METHOD_HANDLE        = 15   # CONSTANT_MethodHandle_info
CP_METHOD_TYPE          = 16   # CONSTANT_MethodType_info
CP_DYNAMIC              = 17   # CONSTANT_Dynamic_info
CP_INVOKE_DYNAMIC       = 18   # CONSTANT_InvokeDynamic_info
CP_MODULE               = 19   # CONSTANT_Module_info
CP_PACKAGE              = 20   # CONSTANT_Package_info

# Internal name for double-slot sentinel
_UNUSABLE = 'UNUSABLE'

# ---------------------------------------------------------------------------
# SSL bypass fingerprints (JVM internal descriptor fragments)
# Any class that implements these interfaces and has a trivial body is suspect.
# ---------------------------------------------------------------------------

SSL_TRUST_MGRS = {
    'javax/net/ssl/X509TrustManager',
    'javax/net/ssl/X509ExtendedTrustManager',
    'com/sun/ssl/internal/ssl/X509ExtendedTrustManager',
}

SSL_HOSTNAME_VERIFIERS = {
    'javax/net/ssl/HostnameVerifier',
}

SSL_BYPASS_METHODS = {
    'checkServerTrusted',    # X509TrustManager — empty body = trust all
    'checkClientTrusted',
    'getAcceptedIssuers',    # should return empty array only if really bypassing
    'verify',                # HostnameVerifier.verify() returning true = bypass
}

SSL_CTX_METHODS = {
    'SSLContext',
    'TrustManager',
    'init',
    'getInstance',
}

# ---------------------------------------------------------------------------
# Auth method name patterns (javap method name fragments)
# ---------------------------------------------------------------------------

AUTH_METHOD_NAMES_RE = re.compile(
    r'(?i)(login|logon|auth(?:enticate)?|sendCred(?:ential)?s?|'
    r'setPassword|getPassword|handleAuth|doAuth|verifyPassword|'
    r'setAuth(?:Token|Cookie|Header)?|getSessionId|validateUser)',
    re.IGNORECASE,
)

AUTH_CLASS_NAMES_RE = re.compile(
    r'(?i)(auth|login|cred(?:ential)?|session|password|token)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# javap / cfr-decompiler command templates
# ---------------------------------------------------------------------------

# javap (included in JDK) — works on .class files extracted from JAR
JAVAP_CMD_BASIC     = 'javap -c {classfile}'
JAVAP_CMD_VERBOSE   = 'javap -verbose {classfile}'
JAVAP_CMD_PRIVATE   = 'javap -c -p -verbose {classfile}'
# -p = show private members; critical for ASDM credential/session fields

# cfr-decompiler (https://github.com/leibnitz27/cfr) — better than javap for source
CFR_CMD_JAR         = 'java -jar cfr.jar {jarfile} --outputdir {outdir}'
CFR_CMD_CLASS       = 'java -jar cfr.jar {classfile}'
CFR_CMD_FOCUSED     = 'java -jar cfr.jar {jarfile} --caseinsensitivefs true --outputdir {outdir}'

# jd-cli (https://github.com/intoolswetrust/jd-cli) — alternative
JD_CMD_JAR          = 'jd-cli {jarfile} --outputDir {outdir}'

# Extract + disassemble in one pipeline:
# unzip -p asdm.jar com/cisco/pdm/PDMMain.class > /tmp/PDMMain.class && javap -c -p -verbose /tmp/PDMMain.class
PIPELINE_EXTRACT_DISASM = (
    'unzip -p {jarfile} {classentry} > /tmp/_asdm_target.class '
    '&& javap -c -p -verbose /tmp/_asdm_target.class'
)

# grep constant pool strings from javap verbose output for credential patterns
JAVAP_GREP_CREDS = (
    'javap -verbose -c -p {classfile} '
    '| grep -E "(password|secret|token|enable|asdm|cisco|tacacs|radius|snmp|auth)"'
)

# ---------------------------------------------------------------------------
# Methodology note (book-grounded)
# ---------------------------------------------------------------------------

_METHODOLOGY = """
JVM Constant Pool RE Methodology (Decompiling Java §2, JVM Spec §4.4):

1. CAFEBABE validation (u4 @ offset 0x00). Not a class file if absent.
2. Major version @ offset 0x06 (u2): maps to Java release (52=Java8, 61=Java17, etc.)
   ASDM historically compiled with Java 8 (major=52); newer builds use 11/17.
3. cp_count @ offset 0x08 (u2): constant pool has cp_count-1 entries (index 0 reserved).
4. Parse cp_info entries sequentially. Tag byte determines size:
     tag=1  (Utf8):  u2 length + length bytes  — all string literals live here
     tag=3/4 (Int/Float): u4
     tag=5/6 (Long/Double): u8, consumes TWO pool slots
     tag=7/8/16/19/20: u2 index
     tag=9/10/11/12: u2+u2
     tag=15: u1+u2
     tag=17/18: u2+u2
5. String literals in Java source become CONSTANT_String_info (tag=8) entries whose
   string_index points to a CONSTANT_Utf8_info (tag=1) entry containing the UTF-8 bytes.
   Therefore: hunt tag=1 entries for plaintext credentials, URLs, API paths.
6. Method references (tag=10) resolve via class_index -> CONSTANT_Class_info ->
   CONSTANT_Utf8_info for class name, and name_and_type_index -> CONSTANT_NameAndType_info
   -> CONSTANT_Utf8_info for method name + descriptor.
   Descriptor format: (param_types)return_type  e.g. (Ljava/lang/String;I)V
7. To find authentication code: look for Methodref entries whose class resolves to
   javax/net/ssl/SSLContext, java/net/HttpURLConnection, or com/cisco/* with
   method names matching auth/login/sendPassword patterns.
8. SSL bypass: classes implementing X509TrustManager with empty checkServerTrusted()
   (method body = just areturn) are in every ASDM version. The JVM Spec guarantees
   these method names survive into the constant pool as CONSTANT_Utf8_info entries,
   so grep the pool for 'checkServerTrusted' to identify candidate classes instantly.
"""


# ---------------------------------------------------------------------------
# Minimal constant pool parser (JVM Spec §4.4, confirmed by Decompiling Java §2)
# ---------------------------------------------------------------------------

def _parse_constant_pool(data: bytes) -> list:
    """
    Parse JVM constant pool from raw .class bytes.

    Returns list indexed 0..cp_count-1. Index 0 is sentinel {'tag': None}.
    Long/Double entries each followed by a phantom {'tag': _UNUSABLE} entry.

    JVM Spec §4.4: 'The constant_pool table is indexed from 1 to
    constant_pool_count - 1.'
    Decompiling Java §2: 'constant_pool[0] is reserved by the JVM and doesn't
    appear in the classfile.'
    """
    if len(data) < 10:
        return []
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic != 0xCAFEBABE:
        return []

    off = 8  # skip magic(4) + minor(2) + major(2)
    try:
        cp_count = struct.unpack_from('>H', data, off)[0]
    except struct.error:
        return []
    off += 2

    pool = [{'index': 0, 'tag': None, 'tag_name': _UNUSABLE, 'value': None}]
    i = 1
    while i < cp_count:
        if off >= len(data):
            break
        tag = data[off]; off += 1
        entry = {'index': i, 'tag': tag, 'value': None}

        try:
            if tag == CP_UTF8:
                ln = struct.unpack_from('>H', data, off)[0]; off += 2
                raw = data[off:off + ln]; off += ln
                try:
                    # JVM uses "modified UTF-8"; fallback to lossy
                    entry['value'] = raw.decode('utf-8', errors='replace')
                except Exception:
                    entry['value'] = repr(raw)
                entry['tag_name'] = 'Utf8'

            elif tag in (CP_INTEGER, CP_FLOAT):
                entry['value'] = struct.unpack_from('>I', data, off)[0]; off += 4
                entry['tag_name'] = 'Integer' if tag == CP_INTEGER else 'Float'

            elif tag in (CP_LONG, CP_DOUBLE):
                hi = struct.unpack_from('>I', data, off)[0]
                lo = struct.unpack_from('>I', data, off + 4)[0]
                entry['value'] = (hi << 32) | lo; off += 8
                entry['tag_name'] = 'Long' if tag == CP_LONG else 'Double'
                pool.append(entry); i += 1
                pool.append({'index': i, 'tag': None,
                             'tag_name': _UNUSABLE, 'value': None})
                i += 1
                continue

            elif tag in (CP_CLASS, CP_STRING, CP_METHOD_TYPE,
                         CP_MODULE, CP_PACKAGE):
                entry['value'] = struct.unpack_from('>H', data, off)[0]; off += 2
                entry['tag_name'] = {
                    CP_CLASS: 'Class', CP_STRING: 'String',
                    CP_METHOD_TYPE: 'MethodType', CP_MODULE: 'Module',
                    CP_PACKAGE: 'Package',
                }[tag]

            elif tag in (CP_FIELDREF, CP_METHODREF, CP_INTERFACE_METHODREF):
                ci = struct.unpack_from('>H', data, off)[0]
                ni = struct.unpack_from('>H', data, off + 2)[0]; off += 4
                entry['value'] = {'class_index': ci, 'nat_index': ni}
                entry['tag_name'] = {
                    CP_FIELDREF: 'Fieldref', CP_METHODREF: 'Methodref',
                    CP_INTERFACE_METHODREF: 'InterfaceMethodref',
                }[tag]

            elif tag == CP_NAME_AND_TYPE:
                ni = struct.unpack_from('>H', data, off)[0]
                di = struct.unpack_from('>H', data, off + 2)[0]; off += 4
                entry['value'] = {'name_index': ni, 'desc_index': di}
                entry['tag_name'] = 'NameAndType'

            elif tag == CP_METHOD_HANDLE:
                rk = data[off]; ri = struct.unpack_from('>H', data, off + 1)[0]
                off += 3
                entry['value'] = {'ref_kind': rk, 'ref_index': ri}
                entry['tag_name'] = 'MethodHandle'

            elif tag in (CP_DYNAMIC, CP_INVOKE_DYNAMIC):
                bmi = struct.unpack_from('>H', data, off)[0]
                ni  = struct.unpack_from('>H', data, off + 2)[0]; off += 4
                entry['value'] = {'bootstrap_method_attr_index': bmi,
                                  'nat_index': ni}
                entry['tag_name'] = ('Dynamic' if tag == CP_DYNAMIC
                                     else 'InvokeDynamic')
            else:
                break  # Unknown tag — cannot advance; abort parse

        except (struct.error, IndexError):
            break

        pool.append(entry)
        i += 1

    return pool


def _pool_utf8(pool: list) -> dict:
    """Return {index: str} for all Utf8 entries."""
    return {e['index']: e['value']
            for e in pool
            if e.get('tag_name') == 'Utf8' and isinstance(e.get('value'), str)}


def _resolve_class_name(pool: list, utf8: dict, class_idx: int) -> str:
    """Resolve a Class pool entry to its binary name (e.g. 'javax/net/ssl/SSLContext')."""
    for e in pool:
        if e['index'] == class_idx and e.get('tag_name') == 'Class':
            return utf8.get(e['value'], '')
    return ''


# ---------------------------------------------------------------------------
# ASDMJarRE
# ---------------------------------------------------------------------------

class ASDMJarRE:
    """
    Reverse engineer a Cisco ASDM JAR file.

    Methods follow the requested interface:
      download_asdm_jar()      — fetch JAR from live ASA (no curl, no exec)
      extract_class_files()    — list .class entries from loaded JAR bytes
      scan_constant_pool()     — extract all Utf8 strings per class
      find_auth_methods()      — locate credential/auth handling classes
      find_ssl_bypass_patterns()  — detect TrustManager/HostnameVerifier bypasses

    Additional:
      run_javap()             — shell javap on extracted class file
      run_cfr()               — shell cfr-decompiler on JAR
      report()                — text summary of findings
    """

    def __init__(self, host: str = MACSTADIUM_HOST_PRIMARY,
                 port: int = 443,
                 jar_bytes: Optional[bytes] = None,
                 jar_path: Optional[str] = None):
        self.host      = host
        self.port      = port
        self._raw: Optional[bytes] = jar_bytes
        self._path: Optional[str] = jar_path
        self._zf: Optional[zipfile.ZipFile] = None
        self._class_entries: list  = []
        self.version: str          = 'unknown'
        self.sha256: str           = ''
        # result accumulators
        self.pool_strings:  dict   = {}   # classname -> [str]
        self.auth_classes:  list   = []
        self.ssl_bypasses:  list   = []

    # ------------------------------------------------------------------
    # 1. download_asdm_jar
    # ------------------------------------------------------------------

    def download_asdm_jar(self, username: str = '', password: str = '',
                          timeout: int = 20) -> bool:
        """
        Download ASDM JAR from live ASA at self.host:self.port.

        Auth flow (207.254.35.12):
          Step 1: POST /+webvpn+/index.html with credentials to get session cookie.
          Step 2: Fetch JNLP to locate JAR resource URLs.
          Step 3: Download first resolvable JAR.

        Returns True if JAR bytes are available in self._raw.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        session_cookie = ''

        # --- Step 1: authenticate (only if credentials provided) ---
        if username:
            auth_url  = f'https://{self.host}:{self.port}{AUTH_POST_PATH}'
            auth_body = AUTH_POST_BODY.format(
                user=urllib.request.quote(username),
                pw=urllib.request.quote(password),
            ).encode()
            req = urllib.request.Request(
                auth_url, data=auth_body,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent':   'MSIE 4.0 WebVPN',
                },
                method='POST',
            )
            try:
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
                hdrs = resp.headers
                raw_cookie = hdrs.get('Set-Cookie', '')
                # Extract webvpnc session token
                m = re.search(r'webvpnc=[^;]+', raw_cookie)
                if m:
                    session_cookie = m.group(0)
            except Exception:
                pass  # proceed unauthenticated; JNLP may still be accessible

        def _get(path: str) -> Optional[bytes]:
            url  = f'https://{self.host}:{self.port}{path}'
            hdrs = {'User-Agent': 'Mozilla/5.0 (Java WebStart)'}
            if session_cookie:
                hdrs['Cookie'] = session_cookie
            req  = urllib.request.Request(url, headers=hdrs)
            try:
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
                return resp.read()
            except Exception:
                return None

        # --- Step 2: JNLP to find JAR URL ---
        jnlp_body = None
        for path in JNLP_PATHS:
            body = _get(path)
            if body and b'<jnlp' in body.lower():
                jnlp_body = body
                break

        jar_paths_to_try = list(JAR_PATHS)
        if jnlp_body:
            # Pull jar href values from JNLP XML
            for m in re.finditer(r'href=["\']([^"\']*\.jar)["\']',
                                  jnlp_body.decode('utf-8', errors='replace'),
                                  re.IGNORECASE):
                href = m.group(1)
                if not href.startswith('/'):
                    href = '/' + href
                if href not in jar_paths_to_try:
                    jar_paths_to_try.insert(0, href)

        # --- Step 3: download JAR ---
        for path in jar_paths_to_try:
            body = _get(path)
            if body and body[:4] == b'PK\x03\x04':  # ZIP/JAR magic
                self._raw = body
                self.sha256 = hashlib.sha256(body).hexdigest()
                return True

        return False

    # ------------------------------------------------------------------
    # 2. extract_class_files
    # ------------------------------------------------------------------

    def extract_class_files(self) -> list:
        """
        List all .class entry paths inside the JAR (in-memory or from disk).

        JAR is a ZIP (JVM Spec §4.1 classfile note; 'Decompiling Java' §3:
        'applets mostly come in handy jar files, which make one neat, compact file').

        Returns list of entry name strings.
        """
        raw = self._raw
        if raw is None and self._path:
            try:
                with open(self._path, 'rb') as f:
                    raw = f.read()
                self.sha256 = hashlib.sha256(raw).hexdigest()
                self._raw = raw
            except OSError:
                return []

        if not raw:
            return []

        try:
            self._zf = zipfile.ZipFile(io.BytesIO(raw), 'r')
        except zipfile.BadZipFile:
            return []

        self._class_entries = [n for n in self._zf.namelist()
                               if n.endswith('.class')]

        # Extract version from MANIFEST.MF
        for name in self._zf.namelist():
            if name.upper().endswith('MANIFEST.MF'):
                try:
                    mf = self._zf.read(name).decode('utf-8', errors='replace')
                    m  = re.search(
                        r'(?:Implementation-Version|Specification-Version)\s*:\s*(.+)',
                        mf, re.IGNORECASE)
                    if m:
                        self.version = m.group(1).strip()
                        break
                except Exception:
                    pass

        return list(self._class_entries)

    # ------------------------------------------------------------------
    # 3. scan_constant_pool
    # ------------------------------------------------------------------

    def scan_constant_pool(self,
                           class_filter: Optional[list] = None,
                           only_interesting: bool = False) -> dict:
        """
        Parse constant pool of every .class in JAR; collect all Utf8 strings.

        Methodology (JVM Spec §4.4 / Decompiling Java §2):
          All string literals, class names, method names, and field names are
          stored as CONSTANT_Utf8_info entries (tag=1) in the constant pool.
          CONSTANT_String_info (tag=8) references them by index. Therefore
          extracting all tag=1 entries from every class yields the complete
          set of plaintext strings embedded in the JAR — including any
          hardcoded credentials, URLs, API paths, and SSL configuration.

        Args:
          class_filter: if set, only process entries whose name matches any
                        substring in the list.
          only_interesting: if True, skip classes with zero credential/auth hits.

        Returns dict {entry_name: {'strings': [...], 'credentials': [...],
                                   'api_paths': [...], 'java_version': str}}.
        """
        if self._zf is None:
            self.extract_class_files()
        if self._zf is None:
            return {}

        cred_rx = re.compile(
            r'(?i)(?:password|secret|token|api[_-]?key|enable\s+\w+|'
            r'jdbc:[a-z:]+//|ldap[s]?://|BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|'
            r'SNMPv[23]\s+|admin(?:istrator)?=|cisco\s+\w+)', re.IGNORECASE)
        api_rx  = re.compile(
            r'(?:/\+CSCOU\+/[^\s"\'<>]+|/\+CSCOE\+/[^\s"\'<>]+|'
            r'/\+webvpn\+/[^\s"\'<>]+|/api/[^\s"\'<>]+|'
            r'/admin/[^\s"\'<>]+|/rest/[^\s"\'<>]+)')

        version_map = {
            45: 'Java 1.1', 46: 'Java 1.2', 47: 'Java 1.3', 48: 'Java 1.4',
            49: 'Java 5',   50: 'Java 6',   51: 'Java 7',   52: 'Java 8',
            53: 'Java 9',   54: 'Java 10',  55: 'Java 11',  56: 'Java 12',
            57: 'Java 13',  58: 'Java 14',  59: 'Java 15',  60: 'Java 16',
            61: 'Java 17',  62: 'Java 18',  63: 'Java 19',  64: 'Java 20',
            65: 'Java 21',
        }

        results = {}
        entries = self._class_entries
        if class_filter:
            entries = [e for e in entries
                       if any(f in e for f in class_filter)]

        for entry in entries:
            try:
                data = self._zf.read(entry)
            except Exception:
                continue

            if len(data) < 10 or data[:4] != b'\xca\xfe\xba\xbe':
                continue

            major = struct.unpack_from('>H', data, 6)[0]
            pool  = _parse_constant_pool(data)
            strs  = [e['value'] for e in pool
                     if e.get('tag_name') == 'Utf8'
                     and isinstance(e.get('value'), str)]

            creds    = [s for s in strs if cred_rx.search(s)]
            api_hits = [m.group(0)
                        for s in strs
                        for m in [api_rx.search(s)] if m]

            if only_interesting and not creds and not api_hits:
                continue

            results[entry] = {
                'java_version': version_map.get(major, f'major={major}'),
                'pool_size':    len(pool),
                'strings':      strs,
                'credentials':  creds,
                'api_paths':    sorted(set(api_hits)),
            }

        self.pool_strings = results
        return results

    # ------------------------------------------------------------------
    # 4. find_auth_methods
    # ------------------------------------------------------------------

    def find_auth_methods(self) -> list:
        """
        Locate classes and methods that handle authentication/credentials.

        Detection strategy:
          a) Class name contains auth/login/cred/session/password/token.
          b) Constant pool contains method name strings matching AUTH_METHOD_NAMES_RE
             (e.g. 'authenticate', 'sendCredentials', 'setPassword').
          c) Constant pool contains CONSTANT_NameAndType entries (tag=12) whose
             name_index resolves to an auth method name — this catches private/
             obfuscated classes that still call standard auth APIs.
          d) String references to HTTP Basic auth patterns or ASA form-post fields
             ('username=', 'password=', 'tgroup=', 'Login=Login').

        Returns list of dicts: {class_entry, class_binary_name, method_hits,
                                string_hits, note}.
        """
        if self._zf is None:
            self.extract_class_files()
        if self._zf is None:
            return []

        form_rx = re.compile(
            r'(?i)(username=|password=|tgroup=|Login=Login|'
            r'Authorization:\s*Basic|X-Auth-Token|'
            r'enable\s+password|crypto\s+key|'
            r'aaa\s+(?:authentication|authorization)|'
            r'tacacs-server|radius-server|ldap-login)',
            re.IGNORECASE,
        )

        findings = []

        for entry in self._class_entries:
            try:
                data = self._zf.read(entry)
            except Exception:
                continue

            if len(data) < 10 or data[:4] != b'\xca\xfe\xba\xbe':
                continue

            pool  = _parse_constant_pool(data)
            utf8  = _pool_utf8(pool)
            strs  = list(utf8.values())

            method_hits = [s for s in strs if AUTH_METHOD_NAMES_RE.search(s)]
            string_hits = [s for s in strs if form_rx.search(s)]

            # Check class name (tag=7 entry's utf8 value)
            class_name = ''
            for e in pool:
                if e.get('tag_name') == 'Class' and isinstance(e.get('value'), int):
                    cn = utf8.get(e['value'], '')
                    if cn:
                        class_name = cn
                        break

            name_hit = bool(AUTH_CLASS_NAMES_RE.search(entry))

            if method_hits or string_hits or name_hit:
                findings.append({
                    'class_entry':        entry,
                    'class_binary_name':  class_name,
                    'method_hits':        method_hits,
                    'string_hits':        string_hits,
                    'class_name_match':   name_hit,
                    'note': (
                        'Candidate auth class — review with: '
                        + JAVAP_CMD_PRIVATE.format(classfile='<extracted.class>')
                    ),
                })

        self.auth_classes = findings
        return findings

    # ------------------------------------------------------------------
    # 5. find_ssl_bypass_patterns
    # ------------------------------------------------------------------

    def find_ssl_bypass_patterns(self) -> list:
        """
        Detect SSL/TLS certificate verification bypass in ASDM class files.

        Background:
          ASDM connects to the ASA over HTTPS but ASA typically uses a self-signed
          certificate. Cisco implements bypass by shipping a custom X509TrustManager
          whose checkServerTrusted() method has an empty body (just returns without
          throwing CertificateException). A custom HostnameVerifier.verify() that
          always returns true is also common.

        Detection (JVM Spec §4.4 grounded):
          1. Class implements SSL_TRUST_MGRS or SSL_HOSTNAME_VERIFIERS:
             check CONSTANT_Class_info entries (tag=7) in the interfaces[] section.
             Interfaces come after super_class in the ClassFile structure; we detect
             them by scanning Utf8 constants for exact interface names.
          2. Method 'checkServerTrusted' or 'verify' present in pool (NameAndType
             name_index -> Utf8 with these names) — confirms this class owns the method
             rather than just calling it.
          3. Heuristic: if the class declares the bypass method AND the method's
             Code attribute is very small (<= 5 bytes), the body is trivially empty.
             (An empty void method is: areturn or return, 1 byte; return from object
             method with no exception throw = 1 opcode.)

        Returns list of dicts: {class_entry, bypass_type, suspicious_methods,
                                 implements_interfaces, code_size_hint, javap_cmd}.
        """
        if self._zf is None:
            self.extract_class_files()
        if self._zf is None:
            return []

        findings = []

        for entry in self._class_entries:
            try:
                data = self._zf.read(entry)
            except Exception:
                continue

            if len(data) < 10 or data[:4] != b'\xca\xfe\xba\xbe':
                continue

            pool  = _parse_constant_pool(data)
            utf8  = _pool_utf8(pool)
            strs  = set(utf8.values())

            # Interface names stored as Utf8 constants in the pool
            trust_mgr_ifaces  = strs & SSL_TRUST_MGRS
            hostname_ifaces   = strs & SSL_HOSTNAME_VERIFIERS

            if not trust_mgr_ifaces and not hostname_ifaces:
                continue

            # Confirm: does this class DECLARE (not just reference) the bypass method?
            # NameAndType (tag=12) entries whose name_index resolves to a bypass method name.
            nat_method_names = set()
            for e in pool:
                if e.get('tag_name') == 'NameAndType' and isinstance(e.get('value'), dict):
                    mn = utf8.get(e['value'].get('name_index', 0), '')
                    if mn in SSL_BYPASS_METHODS:
                        nat_method_names.add(mn)

            # SSLContext usage patterns — indicates the JAR also sets up the bypass context
            ssl_ctx_refs = [s for s in strs
                            if any(kw in s for kw in SSL_CTX_METHODS)]

            bypass_types = []
            if trust_mgr_ifaces:
                bypass_types.append('X509TrustManager')
            if hostname_ifaces:
                bypass_types.append('HostnameVerifier')

            # Heuristic: very small class = trivial bypass (empty method bodies)
            size_hint = 'large' if len(data) > 4096 else 'small'

            findings.append({
                'class_entry':          entry,
                'bypass_type':          bypass_types,
                'implements_interfaces': list(trust_mgr_ifaces | hostname_ifaces),
                'suspicious_methods':   list(nat_method_names),
                'ssl_ctx_refs':         ssl_ctx_refs[:10],
                'class_size_bytes':     len(data),
                'size_hint':            size_hint,
                'javap_cmd':            JAVAP_CMD_PRIVATE.format(
                    classfile=f'<extracted_{entry.replace("/", "_")}>'),
                'note': (
                    'Empty checkServerTrusted body = trust-all. '
                    'Confirm with: javap -c -p <class> | grep -A5 checkServerTrusted'
                ),
            })

        self.ssl_bypasses = findings
        return findings

    # ------------------------------------------------------------------
    # Tool integration
    # ------------------------------------------------------------------

    def run_javap(self, entry: str, extra_flags: str = '-c -p -verbose',
                  work_dir: Optional[str] = None) -> str:
        """
        Extract a single .class from JAR and run javap on it.

        Grounded in: 'Decompiling Java' §3 — 'javap, which comes as part of the
        JDK ... the most basic tool available for examining a classfile.'

        Returns javap stdout as string.
        """
        if self._zf is None:
            return 'JAR not loaded'

        try:
            data = self._zf.read(entry)
        except Exception as e:
            return f'Cannot read {entry}: {e}'

        tmpdir = work_dir or tempfile.mkdtemp(prefix='asdm_re_')
        safe   = entry.replace('/', '_')
        path   = os.path.join(tmpdir, safe)

        with open(path, 'wb') as f:
            f.write(data)

        cmd = ['javap'] + extra_flags.split() + [path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout + (('\n[STDERR]\n' + result.stderr)
                                    if result.stderr else '')
        except FileNotFoundError:
            return (f'javap not found. Install JDK. '
                    f'Manual: {JAVAP_CMD_PRIVATE.format(classfile=path)}')
        except subprocess.TimeoutExpired:
            return 'javap timed out'

    def run_cfr(self, cfr_jar: str, out_dir: Optional[str] = None) -> str:
        """
        Run cfr-decompiler against the full JAR.

        Returns command used (actual execution requires cfr.jar on disk).
        """
        if self._path is None and self._raw is not None:
            tmpdir = out_dir or tempfile.mkdtemp(prefix='asdm_cfr_')
            jar_path = os.path.join(tmpdir, 'asdm.jar')
            with open(jar_path, 'wb') as f:
                f.write(self._raw)
        elif self._path:
            jar_path = self._path
            tmpdir   = out_dir or tempfile.mkdtemp(prefix='asdm_cfr_')
        else:
            return 'No JAR loaded'

        cmd_str = CFR_CMD_JAR.format(jarfile=jar_path, outdir=tmpdir)
        try:
            result = subprocess.run(
                ['java', '-jar', cfr_jar, jar_path,
                 '--outputdir', tmpdir, '--caseinsensitivefs', 'true'],
                capture_output=True, text=True, timeout=120)
            return (f'CFR output dir: {tmpdir}\n'
                    + result.stdout[:2000]
                    + (f'\n[STDERR]\n{result.stderr[:500]}' if result.stderr else ''))
        except FileNotFoundError:
            return f'java not found. Manual: {cmd_str}'
        except subprocess.TimeoutExpired:
            return f'cfr timed out. Manual: {cmd_str}'

    # ------------------------------------------------------------------
    # report
    # ------------------------------------------------------------------

    def report(self, run_all: bool = True) -> str:
        """Full analysis report string."""
        if run_all:
            if not self._class_entries:
                self.extract_class_files()
            self.scan_constant_pool(only_interesting=True)
            self.find_auth_methods()
            self.find_ssl_bypass_patterns()

        lines = [
            '=== ASDM JAR RE Report ===',
            f'Host:     {self.host}:{self.port}',
            f'SHA256:   {self.sha256 or "n/a"}',
            f'Version:  {self.version}',
            f'Classes:  {len(self._class_entries)}',
            '',
        ]

        # SSL bypass
        if self.ssl_bypasses:
            lines.append(f'[SSL BYPASS] {len(self.ssl_bypasses)} class(es) detected:')
            for b in self.ssl_bypasses:
                lines.append(
                    f'  {b["class_entry"]} — {b["bypass_type"]} — '
                    f'{b["size_hint"]} ({b["class_size_bytes"]}B)')
                lines.append(f'    implements: {b["implements_interfaces"]}')
                lines.append(f'    methods:    {b["suspicious_methods"]}')
                lines.append(f'    -> {b["javap_cmd"]}')
        else:
            lines.append('[SSL BYPASS] none detected (or JAR not loaded)')

        lines.append('')

        # Auth methods
        if self.auth_classes:
            lines.append(f'[AUTH CLASSES] {len(self.auth_classes)} candidate(s):')
            for a in self.auth_classes:
                lines.append(
                    f'  {a["class_entry"]} ({a["class_binary_name"]})')
                if a['method_hits']:
                    lines.append(f'    method refs: {a["method_hits"][:5]}')
                if a['string_hits']:
                    lines.append(f'    string hits: '
                                 f'{[s[:80] for s in a["string_hits"][:3]]}')
        else:
            lines.append('[AUTH CLASSES] none found')

        lines.append('')

        # Credential strings
        all_creds = []
        for entry, info in self.pool_strings.items():
            for c in info.get('credentials', []):
                all_creds.append((entry, c))
        if all_creds:
            lines.append(f'[CREDENTIALS] {len(all_creds)} hit(s):')
            for entry, c in all_creds[:30]:
                lines.append(f'  [{entry}] {c[:120]}')
        else:
            lines.append('[CREDENTIALS] none found in scanned classes')

        lines.append('')

        # API paths
        all_apis: set = set()
        for info in self.pool_strings.values():
            all_apis.update(info.get('api_paths', []))
        if all_apis:
            lines.append(f'[API PATHS] {len(all_apis)} unique:')
            for p in sorted(all_apis):
                lines.append(f'  {p}')

        lines.extend([
            '',
            '[METHODOLOGY]',
            _METHODOLOGY.strip(),
            '',
            '[TOOLCHAIN]',
            f'  javap (verbose): {JAVAP_CMD_PRIVATE}',
            f'  cfr (JAR):       {CFR_CMD_JAR}',
            f'  jd-cli:          {JD_CMD_JAR}',
            f'  extract+disasm:  {PIPELINE_EXTRACT_DISASM}',
            f'  grep creds:      {JAVAP_GREP_CREDS}',
        ])

        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Class-level convenience: build javap command string for any entry
    # ------------------------------------------------------------------

    @staticmethod
    def javap_command(entry: str, jar_path: str = 'asdm.jar',
                      flags: str = '-c -p -verbose') -> str:
        """Return a ready-to-paste javap command for a specific class entry."""
        safe = entry.replace('/', '_')
        return (
            f'unzip -p {jar_path} {entry} > /tmp/{safe} '
            f'&& javap {flags} /tmp/{safe}'
        )

    @staticmethod
    def cfr_command(jar_path: str = 'asdm.jar', cfr_jar: str = 'cfr.jar',
                    out_dir: str = '/tmp/asdm_src') -> str:
        """Return a ready-to-paste cfr-decompiler command."""
        return CFR_CMD_JAR.format(jarfile=jar_path, outdir=out_dir).replace(
            '{jarfile}', jar_path).replace('{outdir}', out_dir)


# ---------------------------------------------------------------------------
# Top-level convenience entry point
# ---------------------------------------------------------------------------

def analyze_jar(jar_path: str = None, host: str = MACSTADIUM_HOST_PRIMARY,
                port: int = 443, username: str = '', password: str = '') -> str:
    """
    Full ASDM JAR RE pipeline.

    If jar_path provided: analyze local JAR.
    Otherwise: download from host:port (optionally with credentials).

    Returns text report.
    """
    re_obj = ASDMJarRE(host=host, port=port, jar_path=jar_path)

    if jar_path is None:
        ok = re_obj.download_asdm_jar(username=username, password=password)
        if not ok:
            return (f'Download failed from {host}:{port}. '
                    f'Try: curl -k https://{host}/+CSCOU+/asa/asdm.jar -o asdm.jar')

    re_obj.extract_class_files()
    return re_obj.report(run_all=True)
