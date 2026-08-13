"""
cisco_asdm_download_re.py — Download Cisco ASDM JAR from live ASA and RE it.

Stdlib only: urllib.request, urllib.error, ssl, re, json, struct, zipfile, io, os, hashlib, tempfile
"""

import urllib.request
import urllib.error
import ssl
import re
import json
import struct
import zipfile
import io
import os
import hashlib
import tempfile


# ---------------------------------------------------------------------------
# ASDMDownloader
# ---------------------------------------------------------------------------

class ASDMDownloader:
    """Downloads ASDM artifacts from a live Cisco ASA."""

    JNLP_PATHS = [
        '/admin/public/asdm.jnlp',
        '/admin/launch',
        '/ASDM_Launcher.jnlp',
        '/admin/public/asdm-launcher.jnlp',
        '/+CSCOE+/asdm.jnlp',
    ]

    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
        self.jnlp_content = None
        self.jar_urls = []
        self.jar_data = {}     # url -> bytes
        self.version = None

    def _get(self, path: str, timeout: int = 15) -> tuple:
        """HTTP GET, return (status_code, headers_dict, body_bytes).
        Uses ssl with check_hostname=False, CERT_NONE.
        Follows redirects manually up to 3 hops.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url = f"https://{self.host}:{self.port}{path}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; ASDM-Downloader/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }

        hops = 0
        while hops < 3:
            req = urllib.request.Request(url, headers=headers)
            try:
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
                body = resp.read()
                status = resp.status
                hdrs = dict(resp.headers)
                return status, hdrs, body
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get('Location', '')
                    if not location:
                        return e.code, dict(e.headers), b''
                    # Handle relative redirects
                    if location.startswith('/'):
                        url = f"https://{self.host}:{self.port}{location}"
                    elif location.startswith('http'):
                        url = location
                    else:
                        url = f"https://{self.host}:{self.port}/{location}"
                    hops += 1
                    continue
                return e.code, dict(e.headers), b''
            except (urllib.error.URLError, OSError, ConnectionResetError, BrokenPipeError) as e:
                return 0, {}, b''
        return 0, {}, b''

    def find_jnlp(self) -> str:
        """Try each JNLP_PATH, return first path that returns 200 with JNLP content."""
        for path in self.JNLP_PATHS:
            status, hdrs, body = self._get(path)
            if status == 200 and body:
                body_text = body.decode('utf-8', errors='replace')
                # Must be actual JNLP XML — reject HTML error pages
                # JNLP always starts with <?xml or <jnlp and contains <jar
                is_xml = body_text.lstrip().startswith('<?xml') or body_text.lstrip().startswith('<jnlp')
                has_jar_tag = '<jar' in body_text.lower()
                has_jnlp_tag = '<jnlp' in body_text.lower()
                # Also accept if Content-Type hints at XML/JNLP
                ct = hdrs.get('Content-Type', hdrs.get('content-type', ''))
                is_jnlp_ct = 'jnlp' in ct.lower() or 'xml' in ct.lower()

                if (is_xml and (has_jar_tag or has_jnlp_tag)) or is_jnlp_ct:
                    self.jnlp_content = body_text
                    return path
        return ''

    def parse_jnlp(self, jnlp_text: str) -> list:
        """
        Parse JNLP XML for JAR URLs.
        Patterns:
          <jar href="path/to/asdm.jar"/>
          <jar href="path/to/asdm.jar" version="..."/>
          <resources><jar href="..."/></resources>
        Also extract:
          <j2se version="..."/> -> Java version required
          <application-desc main-class="..."/> -> main class name
          <title>...</title> -> ASDM version title
        Return [jar_href_string, ...]
        """
        jar_hrefs = []

        # <jar href="..."/>  or  <jar href="..." .../>
        jar_pattern = re.compile(r'<jar\s+[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
        for m in jar_pattern.finditer(jnlp_text):
            href = m.group(1)
            if href not in jar_hrefs:
                jar_hrefs.append(href)

        # Also look for href="...jar..." anywhere
        generic_jar = re.compile(r'href=["\']([^"\']*\.jar[^"\']*)["\']', re.IGNORECASE)
        for m in generic_jar.finditer(jnlp_text):
            href = m.group(1)
            if href not in jar_hrefs:
                jar_hrefs.append(href)

        # <j2se version="..."/>
        j2se_m = re.search(r'<j2se\s+[^>]*version=["\']([^"\']+)["\']', jnlp_text, re.IGNORECASE)
        if j2se_m:
            self._java_version = j2se_m.group(1)

        # <application-desc main-class="..."/>
        mc_m = re.search(r'main-class=["\']([^"\']+)["\']', jnlp_text, re.IGNORECASE)
        if mc_m:
            self._main_class = mc_m.group(1)

        # <title>...</title>
        title_m = re.search(r'<title>([^<]+)</title>', jnlp_text, re.IGNORECASE)
        if title_m:
            self.version = title_m.group(1).strip()

        # version from filename patterns in text: asdm-782.jar or asdm-7_2_1.jar etc.
        if not self.version:
            ver_m = re.search(r'asdm[-_](\d[\d._-]+)\.jar', jnlp_text, re.IGNORECASE)
            if ver_m:
                self.version = ver_m.group(1)

        self.jar_urls = jar_hrefs
        return jar_hrefs

    def download_jar(self, jar_path: str) -> bytes:
        """Download JAR bytes from the ASA. Return raw bytes or None."""
        # Normalise: if absolute URL, strip host; if relative path, ensure leading /
        if jar_path.startswith('http'):
            # Extract path portion
            m = re.match(r'https?://[^/]+(/.+)', jar_path)
            if m:
                jar_path = m.group(1)
            else:
                return None

        if not jar_path.startswith('/'):
            jar_path = '/' + jar_path

        status, hdrs, body = self._get(jar_path, timeout=60)
        if status == 200 and body:
            # Verify it looks like a JAR (ZIP magic or PK header)
            if body[:2] == b'PK' or body[:4] == b'\xca\xfe\xba\xbe':
                return body
            # Accept anything non-empty on a .jar path
            if jar_path.lower().endswith('.jar'):
                return body if len(body) > 100 else None
            return None
        return None

    def save_jar(self, jar_data: bytes, out_dir: str = '/tmp') -> str:
        """Save JAR bytes to out_dir/asdm_<host>.jar. Return path."""
        safe_host = self.host.replace('.', '_').replace(':', '_')
        path = os.path.join(out_dir, f'asdm_{safe_host}.jar')
        with open(path, 'wb') as f:
            f.write(jar_data)
        return path


# ---------------------------------------------------------------------------
# Constant pool tag names
# ---------------------------------------------------------------------------

_CP_TAG_NAMES = {
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


# ---------------------------------------------------------------------------
# ASDMJarRE
# ---------------------------------------------------------------------------

class ASDMJarRE:
    """
    Reverse engineers a Cisco ASDM JAR file.

    JVM Constant Pool RE:
    - Class files start with magic 0xCAFEBABE (u4)
    - Then minor_version (u2), major_version (u2)
    - Then constant_pool_count (u2) — actual pool has count-1 entries
    - Pool entries: tag (u1) determines structure
    """

    CRED_PATTERNS = [
        (r'(?i)password\s*[=:]\s*\S+', 'PASSWORD'),
        (r'(?i)secret\s*[=:]\s*\S+', 'SECRET'),
        (r'jdbc:[a-z:]+//[^\s"\']+', 'JDBC_URL'),
        (r'ldap[s]?://[^\s"\']+', 'LDAP_URL'),
        (r'https?://10\.\d+\.\d+\.\d+[^\s"\']*', 'INTERNAL_URL'),
        (r'https?://192\.168\.[^\s"\']+', 'INTERNAL_URL'),
        (r'https?://172\.(?:1[6-9]|2\d|3[01])\.[^\s"\']+', 'INTERNAL_URL'),
        (r'(?i)enable\s+(?:secret|password)\s+\S+', 'ENABLE_CRED'),
        (r'(?i)(api[_-]?key|apikey|token)\s*[=:]\s*[A-Za-z0-9+/=]{8,}', 'API_TOKEN'),
        (r'BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY', 'PRIVATE_KEY'),
        (r'(?i)admin(?:istrator)?\s*[=:@]\s*[^\s"\']{4,}', 'ADMIN_CRED'),
        (r'/api/[a-zA-Z0-9/_-]+', 'API_PATH'),
        (r'/\+CSCOE\+/[^\s"\']+', 'ASA_PATH'),
        (r'/\+webvpn\+/[^\s"\']+', 'ASA_PATH'),
        (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'INTERNAL_IP'),
        (r'192\.168\.\d{1,3}\.\d{1,3}', 'INTERNAL_IP'),
        (r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', 'INTERNAL_IP'),
    ]

    # Compiled patterns (lazy)
    _compiled = None

    @classmethod
    def _get_compiled(cls):
        if cls._compiled is None:
            cls._compiled = [(re.compile(p), t) for p, t in cls.CRED_PATTERNS]
        return cls._compiled

    def __init__(self, jar_data: bytes, jar_name: str = ''):
        self.jar_data = jar_data
        self.jar_name = jar_name
        self.class_count = 0
        self.findings = []
        self.credentials = []
        self.internal_ips = []
        self.api_paths = []
        self.version = None

    def parse_class_constant_pool(self, class_bytes: bytes) -> list:
        """
        Full constant pool parser. Returns list of {index, tag, tag_name, value}.
        Handle Long/Double two-slot entries correctly.
        Skip entries that fail to parse (malformed class file subset).
        """
        entries = []
        if len(class_bytes) < 10:
            return entries

        try:
            magic = struct.unpack_from('>I', class_bytes, 0)[0]
            if magic != 0xCAFEBABE:
                return entries

            # skip magic(4) + minor(2) + major(2)
            offset = 8
            cp_count = struct.unpack_from('>H', class_bytes, offset)[0]
            offset += 2

            idx = 1
            while idx < cp_count:
                if offset >= len(class_bytes):
                    break
                tag = class_bytes[offset]
                offset += 1

                tag_name = _CP_TAG_NAMES.get(tag, f'Unknown({tag})')
                entry = {'index': idx, 'tag': tag, 'tag_name': tag_name, 'value': None}

                try:
                    if tag == 1:  # Utf8
                        length = struct.unpack_from('>H', class_bytes, offset)[0]
                        offset += 2
                        raw = class_bytes[offset:offset + length]
                        offset += length
                        # Modified UTF-8: replace null surrogate pairs, then decode
                        try:
                            text = raw.decode('mutf-8', errors='replace')
                        except (LookupError, UnicodeDecodeError):
                            text = raw.decode('utf-8', errors='replace')
                        entry['value'] = text

                    elif tag in (3, 4):  # Integer, Float
                        entry['value'] = struct.unpack_from('>I', class_bytes, offset)[0]
                        offset += 4

                    elif tag in (5, 6):  # Long, Double — two slots
                        entry['value'] = struct.unpack_from('>Q', class_bytes, offset)[0]
                        offset += 8
                        entries.append(entry)
                        # Slot idx+1 is unusable placeholder
                        entries.append({'index': idx + 1, 'tag': 0, 'tag_name': 'Placeholder', 'value': None})
                        idx += 2
                        continue

                    elif tag == 7:  # Class
                        entry['value'] = struct.unpack_from('>H', class_bytes, offset)[0]
                        offset += 2

                    elif tag == 8:  # String
                        entry['value'] = struct.unpack_from('>H', class_bytes, offset)[0]
                        offset += 2

                    elif tag in (9, 10, 11):  # Fieldref, Methodref, InterfaceMethodref
                        ci = struct.unpack_from('>H', class_bytes, offset)[0]
                        ni = struct.unpack_from('>H', class_bytes, offset + 2)[0]
                        entry['value'] = (ci, ni)
                        offset += 4

                    elif tag == 12:  # NameAndType
                        ni = struct.unpack_from('>H', class_bytes, offset)[0]
                        di = struct.unpack_from('>H', class_bytes, offset + 2)[0]
                        entry['value'] = (ni, di)
                        offset += 4

                    elif tag == 15:  # MethodHandle
                        rk = class_bytes[offset]
                        ri = struct.unpack_from('>H', class_bytes, offset + 1)[0]
                        entry['value'] = (rk, ri)
                        offset += 3

                    elif tag in (16, 17, 18):  # MethodType, Dynamic, InvokeDynamic
                        a = struct.unpack_from('>H', class_bytes, offset)[0]
                        b = struct.unpack_from('>H', class_bytes, offset + 2)[0]
                        entry['value'] = (a, b)
                        offset += 4

                    elif tag in (19, 20):  # Module, Package
                        entry['value'] = struct.unpack_from('>H', class_bytes, offset)[0]
                        offset += 2

                    else:
                        # Unknown tag — cannot continue safely
                        break

                except (struct.error, IndexError):
                    # Truncated entry — skip rest of pool
                    break

                entries.append(entry)
                idx += 1

        except (struct.error, IndexError):
            pass

        return entries

    def analyze_class(self, class_bytes: bytes, class_name: str) -> dict:
        """
        Parse constant pool, extract all Utf8 strings,
        match CRED_PATTERNS against each string.
        Return {class_name, pool_size, credentials, paths, ips, interesting_strings}
        """
        result = {
            'class_name': class_name,
            'pool_size': 0,
            'credentials': [],
            'paths': [],
            'ips': [],
            'interesting_strings': [],
        }

        pool = self.parse_class_constant_pool(class_bytes)
        result['pool_size'] = len(pool)

        compiled = self._get_compiled()

        for entry in pool:
            if entry['tag'] != 1 or not entry['value']:
                continue
            text = entry['value']
            if len(text) < 4:
                continue

            for pattern, ptype in compiled:
                for m in pattern.finditer(text):
                    matched = m.group(0)
                    rec = {
                        'class': class_name,
                        'pattern_type': ptype,
                        'matched_string': matched,
                        'context': text[:200] if len(text) > 200 else text,
                    }
                    if ptype in ('INTERNAL_IP',):
                        result['ips'].append(matched)
                    elif ptype in ('API_PATH', 'ASA_PATH'):
                        result['paths'].append(matched)
                    elif ptype in ('PASSWORD', 'SECRET', 'JDBC_URL', 'LDAP_URL',
                                   'INTERNAL_URL', 'ENABLE_CRED', 'API_TOKEN',
                                   'PRIVATE_KEY', 'ADMIN_CRED'):
                        result['credentials'].append(rec)
                    result['interesting_strings'].append(rec)

        return result

    def scan_jar(self) -> dict:
        """
        Open JAR as zipfile.ZipFile(io.BytesIO(self.jar_data)).
        For each .class entry:
          - Read bytes
          - Verify CAFEBABE magic
          - Run analyze_class
        Also read META-INF/MANIFEST.MF for version info.
        Aggregate all findings.
        """
        aggregated = {
            'class_count': 0,
            'classes_parsed': 0,
            'credentials': [],
            'internal_ips': [],
            'api_paths': [],
            'interesting_strings': [],
            'manifest': {},
            'errors': [],
        }

        try:
            zf = zipfile.ZipFile(io.BytesIO(self.jar_data), 'r')
        except zipfile.BadZipFile as e:
            aggregated['errors'].append(f'BadZipFile: {e}')
            return aggregated

        # Read MANIFEST
        try:
            with zf.open('META-INF/MANIFEST.MF') as mf:
                manifest_text = mf.read().decode('utf-8', errors='replace')
            for line in manifest_text.splitlines():
                if ':' in line:
                    k, _, v = line.partition(':')
                    aggregated['manifest'][k.strip()] = v.strip()
                    # Extract version
                    if k.strip().lower() in ('implementation-version', 'specification-version',
                                              'bundle-version', 'manifest-version'):
                        if not self.version:
                            self.version = v.strip()
        except (KeyError, Exception):
            pass

        seen_ips = set()
        seen_paths = set()

        for entry in zf.infolist():
            if not entry.filename.endswith('.class'):
                continue
            aggregated['class_count'] += 1

            try:
                data = zf.read(entry.filename)
            except Exception as e:
                aggregated['errors'].append(f'read {entry.filename}: {e}')
                continue

            # Verify CAFEBABE
            if len(data) < 4:
                continue
            magic = struct.unpack_from('>I', data, 0)[0]
            if magic != 0xCAFEBABE:
                continue

            class_name = entry.filename.replace('/', '.').removesuffix('.class')
            result = self.analyze_class(data, class_name)
            aggregated['classes_parsed'] += 1

            for c in result['credentials']:
                aggregated['credentials'].append(c)

            for ip in result['ips']:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    aggregated['internal_ips'].append(ip)

            for p in result['paths']:
                if p not in seen_paths:
                    seen_paths.add(p)
                    aggregated['api_paths'].append(p)

        zf.close()
        aggregated['class_count'] = aggregated['class_count']
        self.class_count = aggregated['class_count']
        self.credentials = aggregated['credentials']
        self.internal_ips = aggregated['internal_ips']
        self.api_paths = aggregated['api_paths']
        return aggregated

    def analyze(self) -> dict:
        """Full analysis pipeline. Return aggregated findings dict."""
        scan = self.scan_jar()

        # Build structured findings
        findings = []

        if scan['credentials']:
            findings.append({
                'severity': 'CRITICAL',
                'title': f"Credentials in bytecode ({len(scan['credentials'])} matches)",
                'detail': [c['matched_string'][:120] for c in scan['credentials'][:10]],
            })

        if scan['internal_ips']:
            findings.append({
                'severity': 'HIGH',
                'title': f"Internal IPs hardcoded ({len(scan['internal_ips'])} unique)",
                'detail': scan['internal_ips'][:20],
            })

        if scan['api_paths']:
            findings.append({
                'severity': 'MEDIUM',
                'title': f"API/ASA paths extracted ({len(scan['api_paths'])} unique)",
                'detail': scan['api_paths'][:30],
            })

        if scan['manifest']:
            findings.append({
                'severity': 'INFO',
                'title': 'MANIFEST.MF metadata',
                'detail': scan['manifest'],
            })

        self.findings = findings

        return {
            'jar_name': self.jar_name,
            'jar_size_bytes': len(self.jar_data),
            'jar_sha256': hashlib.sha256(self.jar_data).hexdigest(),
            'version': self.version,
            'class_count': scan['class_count'],
            'classes_parsed': scan['classes_parsed'],
            'credentials': scan['credentials'],
            'internal_ips': scan['internal_ips'],
            'api_paths': scan['api_paths'],
            'findings': findings,
            'manifest': scan['manifest'],
            'errors': scan['errors'][:20],
        }

    def report(self) -> str:
        """Human-readable summary."""
        lines = [
            f"JAR: {self.jar_name} ({len(self.jar_data)} bytes)",
            f"SHA256: {hashlib.sha256(self.jar_data).hexdigest()}",
            f"Version: {self.version or 'unknown'}",
            f"Classes: {self.class_count} total",
            f"Credentials: {len(self.credentials)}",
            f"Internal IPs: {len(self.internal_ips)}",
            f"API paths: {len(self.api_paths)}",
        ]
        for f in self.findings:
            lines.append(f"[{f['severity']}] {f['title']}")
            detail = f['detail']
            if isinstance(detail, list):
                for d in detail[:5]:
                    lines.append(f"  {d}")
            elif isinstance(detail, dict):
                for k, v in list(detail.items())[:5]:
                    lines.append(f"  {k}: {v}")
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# End-to-end entry point
# ---------------------------------------------------------------------------

def _tls_fingerprint(host: str, port: int) -> dict:
    """Extract TLS cert metadata without verifying trust chain."""
    info = {'tls': None, 'cert_sha256': None, 'cert_subject': None,
            'cert_san': None, 'cert_issuer': None, 'cert_not_after': None}
    try:
        import socket as _socket
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with _socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                info['tls'] = ssock.version()
                info['cert_sha256'] = hashlib.sha256(der).hexdigest()
                # Parse subject/SAN from DER using openssl subprocess if available
                import subprocess as _sp, tempfile as _tf, os as _os
                with _tf.NamedTemporaryFile(suffix='.der', delete=False) as f:
                    f.write(der)
                    fname = f.name
                r = _sp.run(
                    ['openssl', 'x509', '-inform', 'DER', '-in', fname,
                     '-noout', '-subject', '-issuer', '-enddate', '-ext', 'subjectAltName'],
                    capture_output=True, text=True
                )
                _os.unlink(fname)
                if r.returncode == 0:
                    for line in r.stdout.splitlines():
                        if line.startswith('subject='):
                            info['cert_subject'] = line[8:].strip()
                        elif line.startswith('issuer='):
                            info['cert_issuer'] = line[7:].strip()
                        elif line.startswith('notAfter='):
                            info['cert_not_after'] = line[9:].strip()
                        elif 'DNS:' in line:
                            info['cert_san'] = line.strip()
    except Exception as e:
        info['tls_error'] = str(e)
    return info


def _asa_surface_enum(host: str, port: int) -> dict:
    """
    Enumerate the ASA web surface without ASDM: collect server headers,
    ASA version hints from logon page, exposed paths, WebVPN presence.
    """
    surface = {
        'webvpn_present': False,
        'asdm_present': False,
        'server_header': None,
        'asa_version_hint': None,
        'exposed_paths': [],
        'response_headers': {},
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    probe_paths = [
        ('/+CSCOE+/logon.html', 'webvpn'),
        ('/+webvpn+/', 'webvpn'),
        ('/admin/public/asdm.jnlp', 'asdm'),
        ('/admin/', 'asdm'),
        ('/+CSCOE+/files/FILE_LIST', 'files'),
        ('/+CSCOE+/session.html', 'session'),
    ]

    for path, category in probe_paths:
        url = f"https://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            resp = urllib.request.urlopen(req, context=ctx, timeout=8)
            body = resp.read(4096).decode('utf-8', errors='replace')
            hdrs = dict(resp.headers)
            surface['exposed_paths'].append({'path': path, 'status': 200, 'category': category})
            if category == 'webvpn':
                surface['webvpn_present'] = True
            if category == 'asdm':
                surface['asdm_present'] = True
            if not surface['server_header']:
                surface['server_header'] = hdrs.get('Server', hdrs.get('server'))
            if not surface['response_headers'] and path == '/+CSCOE+/logon.html':
                surface['response_headers'] = {k: v for k, v in hdrs.items()
                                                if k.lower() not in ('set-cookie',)}
            # ASA sometimes embeds version in logon page comments or JS
            ver_m = re.search(r'(?:ASA|ASDM|Version)[^\d]*(\d+\.\d+[\.\d]*)', body)
            if ver_m and not surface['asa_version_hint']:
                surface['asa_version_hint'] = ver_m.group(1)
            # Cisco copyright / product string
            cp_m = re.search(r'Cisco Systems.*?(\d{4})', body)
            if cp_m:
                surface['cisco_copyright_year'] = cp_m.group(1)
        except urllib.error.HTTPError as e:
            surface['exposed_paths'].append({'path': path, 'status': e.code, 'category': category})
        except Exception:
            pass

    return surface


def analyze_asdm_live(host: str, port: int = 443, save_jar: bool = True) -> dict:
    """
    End-to-end: download ASDM from live host, RE it.
    1. TLS fingerprint
    2. ASDMDownloader.find_jnlp()
    3. ASDMDownloader.parse_jnlp() -> jar URLs
    4. ASDMDownloader.download_jar() for each
    5. ASDMJarRE.analyze() on downloaded data
    6. ASA surface enum if JAR not found
    7. Return aggregated result dict.
    """
    dl = ASDMDownloader(host, port)

    result = {
        'host': host,
        'port': port,
        'jnlp_path': None,
        'jnlp_content_snippet': None,
        'jar_path': None,
        'jar_size_bytes': 0,
        'version': None,
        'class_count': 0,
        'credentials': [],
        'internal_ips': [],
        'api_paths': [],
        'findings': [],
        'error': None,
        'tls': {},
        'surface': {},
    }

    # Step 0: TLS fingerprint
    result['tls'] = _tls_fingerprint(host, port)

    # Step 1: find JNLP
    jnlp_path = dl.find_jnlp()
    result['jnlp_path'] = jnlp_path or None

    jar_data = None
    jar_url_used = None

    if jnlp_path and dl.jnlp_content:
        result['jnlp_content_snippet'] = dl.jnlp_content[:500]

        # Step 2: parse JNLP for JAR URLs
        jar_hrefs = dl.parse_jnlp(dl.jnlp_content)

        # Step 3: download first working JAR
        for href in jar_hrefs:
            data = dl.download_jar(href)
            if data:
                jar_data = data
                jar_url_used = href
                dl.jar_data[href] = data
                break

    # If JNLP didn't yield a JAR, try common direct paths
    if jar_data is None:
        DIRECT_JAR_PATHS = [
            '/admin/public/asdm.jar',
            '/admin/public/asdm-782.jar',
            '/admin/public/asdm-783.jar',
            '/admin/public/asdm-785.jar',
            '/admin/public/asdm-786.jar',
            '/admin/public/asdm-790.jar',
            '/admin/public/asdm-791.jar',
            '/admin/public/asdm-792.jar',
            '/admin/public/asdm-794.jar',
            '/admin/public/asdm-7161.jar',
            '/admin/public/asdm-7171.jar',
            '/admin/public/asdm-7181.jar',
        ]
        for path in DIRECT_JAR_PATHS:
            data = dl.download_jar(path)
            if data:
                jar_data = data
                jar_url_used = path
                break

    if jar_data is None:
        result['error'] = 'Could not download ASDM JAR (JNLP not found or JAR not served)'
        result['version'] = dl.version
        # Fallback: enumerate ASA surface even without JAR
        result['surface'] = _asa_surface_enum(host, port)
        result['findings'].append({
            'severity': 'INFO',
            'title': 'ASDM not served from this interface',
            'detail': 'JNLP and JAR paths returned 404. ASA may restrict ASDM to management interface only.',
        })
        if result['surface'].get('webvpn_present'):
            result['findings'].append({
                'severity': 'INFO',
                'title': 'WebVPN/AnyConnect interface confirmed',
                'detail': result['surface'].get('exposed_paths', []),
            })
        return result

    # Save JAR
    if save_jar:
        jar_path = dl.save_jar(jar_data, out_dir='/tmp')
        result['jar_path'] = jar_path

    result['jar_size_bytes'] = len(jar_data)
    result['jar_url'] = jar_url_used

    # Step 4: RE
    re_engine = ASDMJarRE(jar_data, jar_name=jar_url_used or 'asdm.jar')
    analysis = re_engine.analyze()

    result['version'] = analysis.get('version') or dl.version
    result['class_count'] = analysis.get('class_count', 0)
    result['classes_parsed'] = analysis.get('classes_parsed', 0)
    result['credentials'] = analysis.get('credentials', [])
    result['internal_ips'] = analysis.get('internal_ips', [])
    result['api_paths'] = analysis.get('api_paths', [])
    result['findings'] = analysis.get('findings', [])
    result['manifest'] = analysis.get('manifest', {})
    result['jar_sha256'] = analysis.get('jar_sha256')
    result['parse_errors'] = analysis.get('errors', [])

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else '207.254.16.2'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print(f"[*] Downloading ASDM from {host}:{port}...")
    result = analyze_asdm_live(host, port)

    print(f"[*] JNLP: {result.get('jnlp_path')}")
    print(f"[*] JAR:  {result.get('jar_path')} ({result.get('jar_size_bytes', 0)} bytes)")
    if result.get('jar_sha256'):
        print(f"[*] SHA256: {result.get('jar_sha256')}")
    print(f"[*] Version: {result.get('version')}")
    print(f"[*] Classes: {result.get('class_count', 0)} total, {result.get('classes_parsed', 0)} parsed")
    print(f"[!] Credentials found: {len(result.get('credentials', []))}")
    for c in result.get('credentials', []):
        print(f"    [{c.get('pattern_type')}] {str(c.get('matched_string', ''))[:120]}")
    print(f"[!] Internal IPs: {result.get('internal_ips', [])}")
    print(f"[!] API paths: {len(result.get('api_paths', []))}")
    for p in result.get('api_paths', [])[:20]:
        print(f"    {p}")

    if result.get('error'):
        print(f"[!] Error: {result['error']}")

    tls = result.get('tls', {})
    if tls:
        print(f"[*] TLS: {tls.get('tls')} cert={tls.get('cert_subject')} SAN={tls.get('cert_san')}")
        print(f"[*] Cert SHA256: {tls.get('cert_sha256')}")

    surface = result.get('surface', {})
    if surface:
        print(f"[*] WebVPN present: {surface.get('webvpn_present')}")
        print(f"[*] ASDM present:   {surface.get('asdm_present')}")
        if surface.get('asa_version_hint'):
            print(f"[*] ASA version hint: {surface.get('asa_version_hint')}")
        for ep in surface.get('exposed_paths', []):
            print(f"    {ep.get('status')} {ep.get('path')} [{ep.get('category')}]")
        if surface.get('response_headers'):
            print("[*] Response headers from /+CSCOE+/logon.html:")
            for k, v in list(surface['response_headers'].items())[:10]:
                print(f"    {k}: {v}")

    if result.get('manifest'):
        print(f"[*] Manifest entries: {len(result['manifest'])}")
        for k, v in list(result['manifest'].items())[:10]:
            print(f"    {k}: {v}")

    print()
    print(json.dumps(result, indent=2, default=str))
