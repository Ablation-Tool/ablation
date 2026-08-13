"""
cisco_asdm_re.py — Cisco ASDM JAR/class binary reverse engineering module.

Extracts hardcoded credentials, internal endpoints, API paths, and crypto
material from ASDM JAR files and raw JVM .class files without executing them.

Stdlib only: struct, zipfile, os, re, json, io, hashlib
"""

import struct
import zipfile
import os
import re
import json
import io
import hashlib


# ---------------------------------------------------------------------------
# JVM constant pool parser
# ---------------------------------------------------------------------------

class JVMConstantPool:
    """Parse JVM constant pool from raw .class bytes."""

    TAGS = {
        1:  'Utf8',
        3:  'Integer',
        4:  'Float',
        5:  'Long',
        6:  'Double',
        7:  'Class',
        8:  'String',
        9:  'Fieldref',
        10: 'Methodref',
        11: 'InterfaceMethodref',
        12: 'NameAndType',
        15: 'MethodHandle',
        16: 'MethodType',
        17: 'Dynamic',
        18: 'InvokeDynamic',
        19: 'Module',
        20: 'Package',
    }

    CRED_PATTERNS = [
        (r'(?i)password\s*[=:]\s*\S+',                              'PASSWORD'),
        (r'(?i)secret\s*[=:]\s*\S+',                               'SECRET'),
        (r'jdbc:[a-z:]+//[^\s"\']+',                               'JDBC_URL'),
        (r'ldap[s]?://[^\s"\']+',                                  'LDAP_URL'),
        (r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*\S+', 'API_KEY'),
        (r'https?://10\.\d+\.\d+\.\d+[^\s"\']*',                  'INTERNAL_URL'),
        (r'https?://192\.168\.[^\s"\']+',                          'INTERNAL_URL'),
        (r'https?://172\.(?:1[6-9]|2\d|3[01])\.[^\s"\']+',        'INTERNAL_URL'),
        (r'(?i)enable\s+(?:secret|password)\s+\S+',               'ENABLE_CRED'),
        (r'snmpv3\s+\S+',                                          'SNMPV3'),
        (r'BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY',                     'PRIVATE_KEY'),
        (r'(?i)admin(?:istrator)?\s*[=:@]\s*\S+',                 'ADMIN_CRED'),
    ]

    def __init__(self, class_data: bytes):
        self.data = class_data
        self._pool = []   # index 0 unused; entries at 1..count-1

    # ------------------------------------------------------------------
    # Internal read helpers
    # ------------------------------------------------------------------

    def _u1(self, buf: bytes, off: int) -> tuple:
        return struct.unpack_from('>B', buf, off)[0], off + 1

    def _u2(self, buf: bytes, off: int) -> tuple:
        return struct.unpack_from('>H', buf, off)[0], off + 2

    def _u4(self, buf: bytes, off: int) -> tuple:
        return struct.unpack_from('>I', buf, off)[0], off + 4

    def _u8(self, buf: bytes, off: int) -> tuple:
        hi, = struct.unpack_from('>I', buf, off)
        lo, = struct.unpack_from('>I', buf, off + 4)
        return (hi << 32) | lo, off + 8

    # ------------------------------------------------------------------

    def parse(self) -> list:
        """
        Parse the full constant pool from class_data.

        Returns list of dicts: {index, tag, tag_name, value}.
        Index 0 is a sentinel placeholder.
        Long/Double entries consume two slots; the phantom slot has
        tag_name='Unusable' and value=None.
        """
        buf = self.data
        if len(buf) < 10:
            return []

        magic = struct.unpack_from('>I', buf, 0)[0]
        if magic != 0xCAFEBABE:
            return []

        off = 4   # skip magic
        # minor(u2) + major(u2)
        off += 4

        try:
            cp_count, off = self._u2(buf, off)
        except struct.error:
            return []

        pool = [{'index': 0, 'tag': 0, 'tag_name': 'Unusable', 'value': None}]
        i = 1
        while i < cp_count:
            entry = {'index': i, 'tag': None, 'tag_name': 'Unknown', 'value': None}
            try:
                tag, off = self._u1(buf, off)
            except struct.error:
                break

            entry['tag'] = tag
            entry['tag_name'] = self.TAGS.get(tag, f'Unknown({tag})')

            try:
                if tag == 1:   # Utf8
                    length, off = self._u2(buf, off)
                    raw = buf[off:off + length]
                    off += length
                    try:
                        entry['value'] = raw.decode('mutf-8')
                    except (UnicodeDecodeError, LookupError):
                        try:
                            entry['value'] = raw.decode('utf-8', errors='replace')
                        except Exception:
                            entry['value'] = repr(raw)

                elif tag in (3, 4):   # Integer, Float
                    v, off = self._u4(buf, off)
                    entry['value'] = v

                elif tag in (5, 6):   # Long, Double (two slots)
                    v, off = self._u8(buf, off)
                    entry['value'] = v
                    pool.append(entry)
                    i += 1
                    # phantom entry
                    pool.append({'index': i, 'tag': None,
                                 'tag_name': 'Unusable', 'value': None})
                    i += 1
                    continue

                elif tag in (7, 8, 16, 19, 20):   # Class, String, MethodType, Module, Package
                    idx, off = self._u2(buf, off)
                    entry['value'] = idx

                elif tag in (9, 10, 11):   # Fieldref, Methodref, InterfaceMethodref
                    ci, off = self._u2(buf, off)
                    ni, off = self._u2(buf, off)
                    entry['value'] = {'class_index': ci, 'name_and_type_index': ni}

                elif tag == 12:   # NameAndType
                    ni, off = self._u2(buf, off)
                    di, off = self._u2(buf, off)
                    entry['value'] = {'name_index': ni, 'descriptor_index': di}

                elif tag == 15:   # MethodHandle
                    rk, off = self._u1(buf, off)
                    ri, off = self._u2(buf, off)
                    entry['value'] = {'ref_kind': rk, 'ref_index': ri}

                elif tag in (17, 18):   # Dynamic, InvokeDynamic
                    bmi, off = self._u2(buf, off)
                    ni, off  = self._u2(buf, off)
                    entry['value'] = {'bootstrap_method_attr_index': bmi,
                                      'name_and_type_index': ni}

                else:
                    # Unknown tag — cannot advance safely; stop
                    break

            except (struct.error, IndexError):
                break

            pool.append(entry)
            i += 1

        self._pool = pool
        return pool

    # ------------------------------------------------------------------

    def get_strings(self) -> list:
        """Return all Utf8 constant values as strings."""
        if not self._pool:
            self.parse()
        return [
            e['value'] for e in self._pool
            if e.get('tag_name') == 'Utf8' and isinstance(e.get('value'), str)
        ]

    def get_class_names(self) -> list:
        """Return Utf8 strings that look like JVM class names (contain '/', no spaces)."""
        return [
            s for s in self.get_strings()
            if '/' in s and ' ' not in s and len(s) < 256
        ]

    def hunt_credentials(self) -> list:
        """
        Scan all Utf8 string constants for credential / sensitive-data patterns.

        Returns list of {pattern_type, matched_string, pool_index}.
        """
        if not self._pool:
            self.parse()

        compiled = [(re.compile(pat), ptype) for pat, ptype in self.CRED_PATTERNS]
        findings = []

        for entry in self._pool:
            if entry.get('tag_name') != 'Utf8':
                continue
            s = entry.get('value')
            if not isinstance(s, str):
                continue
            for rx, ptype in compiled:
                m = rx.search(s)
                if m:
                    findings.append({
                        'pattern_type':   ptype,
                        'matched_string': m.group(0),
                        'pool_index':     entry['index'],
                    })

        return findings


# ---------------------------------------------------------------------------
# ASDM JAR reverse engineer
# ---------------------------------------------------------------------------

_INTERESTING_CLASS_KEYWORDS = (
    'auth', 'login', 'cred', 'password', 'token', 'session',
    'http', 'rest', 'api', 'config', 'mgmt', 'management',
    'keystore', 'certificate', 'ssl', 'tls', 'crypto', 'cipher',
    'snmp', 'radius', 'tacacs', 'ldap', 'tunnel', 'vpn',
)

_API_PATH_PATTERNS = [
    re.compile(r'/api/[^\s"\'<>]+'),
    re.compile(r'/\+CSCOE\+/[^\s"\'<>]*'),
    re.compile(r'/\+webvpn\+/[^\s"\'<>]*'),
    re.compile(r'/admin/[^\s"\'<>]+'),
    re.compile(r'/monitoring/[^\s"\'<>]+'),
    re.compile(r'/rest/[^\s"\'<>]+'),
    re.compile(r'/asa/[^\s"\'<>]+'),
]

_CRYPTO_PATTERNS = [
    re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
    re.compile(r'-----BEGIN\s+CERTIFICATE-----'),
    re.compile(r'-----BEGIN\s+PUBLIC\s+KEY-----'),
    re.compile(r'-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----'),
]

_DER_MAGIC   = bytes([0x30, 0x82])
_JKS_MAGIC   = bytes([0xFE, 0xED, 0xFE, 0xED])
_P12_MAGIC   = bytes([0x30, 0x82])   # same as DER; context check needed

_VERSION_LINE_RE = re.compile(
    r'(?i)(?:Implementation-Version|Specification-Version)\s*:\s*(.+)')
_ASDM_VER_RE     = re.compile(r'(?i)ASDM\s+Version\s+([\d.()]+)')


def _is_class_interesting(name: str) -> bool:
    low = name.lower()
    return any(kw in low for kw in _INTERESTING_CLASS_KEYWORDS)


class ASDMJarRE:
    """Reverse engineer a Cisco ASDM JAR file."""

    def __init__(self, jar_path: str):
        self.path = jar_path
        self.version: str | None = None
        self.class_files: list  = []
        self.manifests: dict    = {}
        self.credentials: list  = []
        self.internal_endpoints: list = []
        self.api_paths: list    = []
        self.crypto_material: list    = []
        self.class_hierarchy: list    = []
        self._zf: zipfile.ZipFile | None = None

    # ------------------------------------------------------------------

    def load(self) -> bool:
        """Open JAR as a ZIP. Populate class_files and manifests."""
        if not zipfile.is_zipfile(self.path):
            return False
        try:
            self._zf = zipfile.ZipFile(self.path, 'r')
        except (zipfile.BadZipFile, OSError):
            return False

        for name in self._zf.namelist():
            if name.endswith('.class'):
                self.class_files.append(name)
            elif name.upper().endswith('MANIFEST.MF') or name.upper().endswith('.SF'):
                try:
                    self.manifests[name] = self._zf.read(name).decode('utf-8', errors='replace')
                except Exception:
                    pass

        return True

    # ------------------------------------------------------------------

    def extract_version(self) -> str:
        """Return ASDM version from MANIFEST.MF or embedded class strings."""
        for content in self.manifests.values():
            m = _VERSION_LINE_RE.search(content)
            if m:
                self.version = m.group(1).strip()
                return self.version

        # Fallback: scan a handful of class files for "ASDM Version X"
        if self._zf:
            checked = 0
            for cf in self.class_files:
                if checked > 20:
                    break
                try:
                    data = self._zf.read(cf)
                    cp = JVMConstantPool(data)
                    for s in cp.get_strings():
                        m = _ASDM_VER_RE.search(s)
                        if m:
                            self.version = m.group(1)
                            return self.version
                except Exception:
                    pass
                checked += 1

        return ''

    # ------------------------------------------------------------------

    def analyze_class(self, class_data: bytes) -> dict:
        """
        Parse a single .class and extract security-relevant signals.

        Returns {class_name, superclass, java_version, credentials,
                 endpoints, api_paths, interesting_strings, crypto_hits}.
        """
        result = {
            'class_name':          '',
            'superclass':          '',
            'java_version':        '',
            'credentials':         [],
            'endpoints':           [],
            'api_paths':           [],
            'interesting_strings': [],
            'crypto_hits':         [],
        }

        if len(class_data) < 10:
            return result

        magic = struct.unpack_from('>I', class_data, 0)[0]
        if magic != 0xCAFEBABE:
            return result

        major = struct.unpack_from('>H', class_data, 6)[0]
        java_map = {52: 'Java 8', 53: 'Java 9', 54: 'Java 10',
                    55: 'Java 11', 56: 'Java 12', 57: 'Java 13',
                    58: 'Java 14', 59: 'Java 15', 60: 'Java 16',
                    61: 'Java 17', 62: 'Java 18', 63: 'Java 19',
                    64: 'Java 20', 65: 'Java 21'}
        result['java_version'] = java_map.get(major, f'major={major}')

        cp = JVMConstantPool(class_data)
        pool = cp.parse()

        # Build a quick index of Utf8 entries for class/super name resolution
        utf8 = {e['index']: e['value']
                for e in pool
                if e.get('tag_name') == 'Utf8' and isinstance(e.get('value'), str)}

        # this_class / super_class are at fixed offsets relative to cp_count
        try:
            cp_count = struct.unpack_from('>H', class_data, 8)[0]
            # Recompute the offset to after the constant pool
            off = 10
            i = 1
            while i < cp_count:
                tag = struct.unpack_from('>B', class_data, off)[0]
                off += 1
                if tag == 1:   # Utf8
                    l = struct.unpack_from('>H', class_data, off)[0]
                    off += 2 + l
                elif tag in (3, 4):
                    off += 4
                elif tag in (5, 6):
                    off += 8
                    i += 1  # double slot
                elif tag in (7, 8, 16, 19, 20):
                    off += 2
                elif tag in (9, 10, 11, 12):
                    off += 4
                elif tag == 15:
                    off += 3
                elif tag in (17, 18):
                    off += 4
                else:
                    break
                i += 1

            # access_flags(u2), this_class(u2), super_class(u2)
            _flags, this_idx, super_idx = struct.unpack_from('>HHH', class_data, off)
            # Resolve class indices
            if this_idx in {e['index']: e for e in pool if e.get('tag_name') == 'Class'}:
                ci = next((e['value'] for e in pool
                           if e['index'] == this_idx and e.get('tag_name') == 'Class'), None)
                result['class_name'] = utf8.get(ci, '')
            ci = next((e['value'] for e in pool
                       if e['index'] == super_idx and e.get('tag_name') == 'Class'), None)
            result['superclass'] = utf8.get(ci, '') if ci else ''
        except (struct.error, StopIteration, KeyError):
            pass

        # Credentials
        result['credentials'] = cp.hunt_credentials()

        # Strings
        strings = cp.get_strings()

        # API paths
        for s in strings:
            for rx in _API_PATH_PATTERNS:
                m = rx.search(s)
                if m:
                    result['api_paths'].append(m.group(0))

        # Endpoints (internal IPs/URLs beyond credential-pattern matches)
        ep_rx = re.compile(
            r'https?://(?:10\.\d+\.\d+\.\d+|192\.168\.[^\s"\'<>]*|'
            r'172\.(?:1[6-9]|2\d|3[01])\.[^\s"\'<>]*|localhost|127\.0\.0\.1)[^\s"\'<>]*')
        for s in strings:
            m = ep_rx.search(s)
            if m:
                result['endpoints'].append(m.group(0))

        # Crypto in string constants
        for s in strings:
            for rx in _CRYPTO_PATTERNS:
                if rx.search(s):
                    result['crypto_hits'].append(s[:200])

        # Interesting strings (short, non-class, potentially significant)
        _noise = re.compile(r'^[\w$/.<>\[\];()]+$')
        for s in strings:
            if (5 < len(s) < 500
                    and not _noise.fullmatch(s)
                    and any(kw in s.lower() for kw in (
                        'password', 'secret', 'token', 'key', 'auth',
                        'admin', 'cisco', 'asdm', 'enable', 'tacacs',
                        'radius', 'snmp', 'crypto', 'cert', 'trust'))):
                result['interesting_strings'].append(s)

        return result

    # ------------------------------------------------------------------

    def scan_all_classes(self) -> list:
        """
        Iterate all .class entries in JAR and analyze interesting ones.

        Prioritizes classes whose names match security-relevant keywords,
        then falls back to remaining classes for credential/endpoint hunting.
        """
        if self._zf is None:
            return []

        results = []
        priority = [cf for cf in self.class_files if _is_class_interesting(cf)]
        rest     = [cf for cf in self.class_files if cf not in priority]

        for cf in priority + rest:
            try:
                data = self._zf.read(cf)
            except Exception:
                continue
            r = self.analyze_class(data)
            r['source_file'] = cf
            # Always add if it came from the priority list; for the rest
            # only add if we found something useful
            if cf in priority or r['credentials'] or r['api_paths'] or r['crypto_hits']:
                results.append(r)

        return results

    # ------------------------------------------------------------------

    def find_api_endpoints(self) -> list:
        """
        Aggregate all API path strings from scanned classes.
        """
        paths = set()
        for cf in self.class_files:
            try:
                data = self._zf.read(cf) if self._zf else b''
            except Exception:
                continue
            cp = JVMConstantPool(data)
            for s in cp.get_strings():
                for rx in _API_PATH_PATTERNS:
                    m = rx.search(s)
                    if m:
                        paths.add(m.group(0))
        return sorted(paths)

    # ------------------------------------------------------------------

    def find_crypto_material(self) -> list:
        """
        Scan JAR entries for PEM headers, DER sequences, JKS keystores,
        and base64 blobs that decode to valid DER.
        """
        hits = []
        if self._zf is None:
            return hits

        b64_rx = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

        for name in self._zf.namelist():
            try:
                data = self._zf.read(name)
            except Exception:
                continue

            # JKS magic
            if data[:4] == _JKS_MAGIC:
                hits.append({'type': 'JKS_KEYSTORE', 'source': name,
                             'size': len(data)})
                continue

            # PEM in text-ish files
            if name.endswith(('.pem', '.crt', '.cer', '.key', '.p7b', '.p7c',
                              '.properties', '.xml', '.config', '.cfg',
                              '.txt', '.class')):
                try:
                    text = data.decode('utf-8', errors='ignore')
                except Exception:
                    text = ''
                for rx in _CRYPTO_PATTERNS:
                    if rx.search(text):
                        hits.append({'type': 'PEM_BLOCK', 'source': name,
                                     'header': rx.pattern})

                # Try base64 blobs -> DER
                for m in b64_rx.finditer(text):
                    blob = m.group(0)
                    try:
                        import base64
                        decoded = base64.b64decode(blob)
                        if decoded[:2] == _DER_MAGIC:
                            hits.append({'type': 'DER_B64', 'source': name,
                                         'length': len(decoded)})
                    except Exception:
                        pass

            # Raw DER sequences embedded in binary files
            if data[:2] == _DER_MAGIC and len(data) > 4:
                hits.append({'type': 'DER_RAW', 'source': name,
                             'size': len(data)})

        return hits

    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """Full analysis pipeline. Returns unified findings dict."""
        if not self.load():
            return {'error': f'Cannot open JAR: {self.path}',
                    'path': self.path}

        self.extract_version()

        class_results = self.scan_all_classes()

        # Aggregate
        all_creds    = []
        all_endpoints = []
        all_api      = []
        all_crypto_str = []
        all_classes  = []

        for r in class_results:
            all_creds.extend(r.get('credentials', []))
            all_endpoints.extend(r.get('endpoints', []))
            all_api.extend(r.get('api_paths', []))
            all_crypto_str.extend(r.get('crypto_hits', []))
            if r.get('class_name'):
                all_classes.append(r['class_name'])

        self.credentials        = _dedup(all_creds, key='matched_string')
        self.internal_endpoints = sorted(set(all_endpoints))
        self.api_paths          = sorted(set(all_api))
        self.class_hierarchy    = sorted(set(all_classes))
        self.crypto_material    = self.find_crypto_material()

        # Hash the JAR for attribution
        sha256 = hashlib.sha256(open(self.path, 'rb').read()).hexdigest()

        return {
            'path':               self.path,
            'sha256':             sha256,
            'version':            self.version or 'unknown',
            'class_count':        len(self.class_files),
            'manifests':          list(self.manifests.keys()),
            'credentials':        self.credentials,
            'endpoints':          self.internal_endpoints,
            'api_paths':          self.api_paths,
            'crypto_material':    self.crypto_material,
            'class_hierarchy':    self.class_hierarchy[:200],  # cap output size
        }

    # ------------------------------------------------------------------

    def report(self) -> str:
        result = self.analyze()
        lines = [
            f"=== ASDM JAR RE Report ===",
            f"Path:     {result['path']}",
            f"SHA256:   {result.get('sha256', 'n/a')}",
            f"Version:  {result.get('version', 'unknown')}",
            f"Classes:  {result.get('class_count', 0)}",
            "",
        ]
        creds = result.get('credentials', [])
        if creds:
            lines.append(f"[CREDENTIALS] {len(creds)} found:")
            for c in creds:
                lines.append(f"  [{c['pattern_type']}] {c['matched_string'][:120]}")
        else:
            lines.append("[CREDENTIALS] none found")

        eps = result.get('endpoints', [])
        if eps:
            lines.append(f"\n[INTERNAL ENDPOINTS] {len(eps)} found:")
            for e in eps:
                lines.append(f"  {e}")

        apis = result.get('api_paths', [])
        if apis:
            lines.append(f"\n[API PATHS] {len(apis)} found:")
            for a in apis:
                lines.append(f"  {a}")

        crypto = result.get('crypto_material', [])
        if crypto:
            lines.append(f"\n[CRYPTO MATERIAL] {len(crypto)} found:")
            for c in crypto:
                lines.append(f"  [{c['type']}] {c['source']}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Single .class file reverse engineer
# ---------------------------------------------------------------------------

_JAVA_VERSION_MAP = {
    45: 'Java 1.1', 46: 'Java 1.2', 47: 'Java 1.3', 48: 'Java 1.4',
    49: 'Java 5',   50: 'Java 6',   51: 'Java 7',   52: 'Java 8',
    53: 'Java 9',   54: 'Java 10',  55: 'Java 11',  56: 'Java 12',
    57: 'Java 13',  58: 'Java 14',  59: 'Java 15',  60: 'Java 16',
    61: 'Java 17',  62: 'Java 18',  63: 'Java 19',  64: 'Java 20',
    65: 'Java 21',
}


class CiscoClassFileRE:
    """Reverse engineer a single JVM .class file."""

    def __init__(self, class_data: bytes, name: str = ''):
        self.data = class_data
        self.name = name

    def analyze(self) -> dict:
        result = {
            'name':         self.name,
            'valid':        False,
            'java_version': 'unknown',
            'pool_size':    0,
            'credentials':  [],
            'strings':      [],
            'class_refs':   [],
        }

        if len(self.data) < 10:
            return result

        magic = struct.unpack_from('>I', self.data, 0)[0]
        if magic != 0xCAFEBABE:
            return result

        result['valid'] = True
        major = struct.unpack_from('>H', self.data, 6)[0]
        result['java_version'] = _JAVA_VERSION_MAP.get(major, f'major={major}')

        cp = JVMConstantPool(self.data)
        pool = cp.parse()
        result['pool_size']   = len(pool)
        result['credentials'] = cp.hunt_credentials()
        result['strings']     = cp.get_strings()
        result['class_refs']  = cp.get_class_names()

        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dedup(items: list, key: str) -> list:
    seen = set()
    out  = []
    for item in items:
        k = item.get(key)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------

def analyze_asdm(path: str) -> dict:
    """
    Detect whether path is a JAR, .class file, or directory of class files.
    Dispatch to the appropriate analyzer and return unified findings.
    """
    if not os.path.exists(path):
        return {'error': f'Path not found: {path}', 'path': path}

    # Directory: scan all .class files within
    if os.path.isdir(path):
        all_creds    = []
        all_endpoints = []
        all_api      = []
        all_crypto   = []
        classes_analyzed = 0

        for root, _dirs, files in os.walk(path):
            for fname in files:
                if not fname.endswith('.class'):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    data = open(fpath, 'rb').read()
                except OSError:
                    continue
                r = CiscoClassFileRE(data, name=fpath).analyze()
                classes_analyzed += 1
                all_creds.extend(r.get('credentials', []))

                for s in r.get('strings', []):
                    for rx in _API_PATH_PATTERNS:
                        m = rx.search(s)
                        if m:
                            all_api.append(m.group(0))
                    ep_rx = re.compile(
                        r'https?://(?:10\.\d+\.\d+\.\d+|192\.168\.[^\s"\'<>]*|'
                        r'172\.(?:1[6-9]|2\d|3[01])\.[^\s"\'<>]*|'
                        r'localhost|127\.0\.0\.1)[^\s"\'<>]*')
                    m = ep_rx.search(s)
                    if m:
                        all_endpoints.append(m.group(0))

        return {
            'path':            path,
            'type':            'directory',
            'class_count':     classes_analyzed,
            'credentials':     _dedup(all_creds, key='matched_string'),
            'endpoints':       sorted(set(all_endpoints)),
            'api_paths':       sorted(set(all_api)),
            'crypto_material': [],
        }

    # Single .class file
    if path.endswith('.class'):
        try:
            data = open(path, 'rb').read()
        except OSError as e:
            return {'error': str(e), 'path': path}
        r = CiscoClassFileRE(data, name=path).analyze()

        api_paths = []
        endpoints = []
        ep_rx = re.compile(
            r'https?://(?:10\.\d+\.\d+\.\d+|192\.168\.[^\s"\'<>]*|'
            r'172\.(?:1[6-9]|2\d|3[01])\.[^\s"\'<>]*|'
            r'localhost|127\.0\.0\.1)[^\s"\'<>]*')
        for s in r.get('strings', []):
            for rx in _API_PATH_PATTERNS:
                m = rx.search(s)
                if m:
                    api_paths.append(m.group(0))
            m = ep_rx.search(s)
            if m:
                endpoints.append(m.group(0))

        return {
            'path':         path,
            'type':         'class',
            'valid':        r['valid'],
            'java_version': r['java_version'],
            'pool_size':    r['pool_size'],
            'credentials':  r['credentials'],
            'strings':      r['strings'][:500],
            'class_refs':   r['class_refs'],
            'endpoints':    sorted(set(endpoints)),
            'api_paths':    sorted(set(api_paths)),
        }

    # JAR (or anything zipfile will accept)
    if zipfile.is_zipfile(path):
        jar = ASDMJarRE(path)
        return jar.analyze()

    # Fallback: attempt to parse as raw .class regardless of extension
    try:
        data = open(path, 'rb').read()
        magic = struct.unpack_from('>I', data, 0)[0] if len(data) >= 4 else 0
        if magic == 0xCAFEBABE:
            r = CiscoClassFileRE(data, name=path).analyze()
            return {'path': path, 'type': 'class_raw', **r}
    except OSError:
        pass

    return {'error': f'Unrecognised file type: {path}', 'path': path}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <jar|class|directory>", file=sys.stderr)
        sys.exit(1)

    result = analyze_asdm(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

    for c in result.get('credentials', []):
        print(f"[CRED] {c['pattern_type']}: {c['matched_string'][:120]}")
