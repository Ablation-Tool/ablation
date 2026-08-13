"""
cisco_nxos_guestshell_re.py — NX-OS Guest Shell (LXC) Reverse Engineering Module
Analyzes extracted/mounted Cisco NX-OS guestshell+ rootfs artifacts for security findings.
Stdlib only: os, re, json, struct, tarfile, gzip, hashlib, subprocess, pathlib
"""

import os
import re
import json
import struct
import hashlib
import subprocess
import pathlib
import stat
import tempfile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXT4_MAGIC = 0xEF53
EXT4_MAGIC_OFFSET = 0x438  # superblock offset + magic word offset within superblock

CREDENTIAL_PATTERNS = [
    (r'(?i)password\s*[=:]\s*\S+', 'PASSWORD'),
    (r'(?i)(api[_-]?key|token)\s*[=:]\s*\S+', 'API_TOKEN'),
    (r'^\S+:\$[156y]\$[^\s:]+', 'SHADOW_HASH'),
    (r'^\S+::[^:]*:[^:]*:', 'NO_PASSWORD_ENTRY'),
    (r'jdbc:[^\s]+', 'JDBC_URL'),
    (r'BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY', 'PRIVATE_KEY'),
    (r'snmp[_-]?community\s*[=:]\s*\S+', 'SNMP_COMMUNITY'),
    (r'(?i)secret\s*[=:]\s*\S+', 'SECRET'),
    (r'(?i)passwd\s*[=:]\s*\S+', 'PASSWD_KEY'),
    (r'(?i)credentials?\s*[=:]\s*\S+', 'CREDENTIAL'),
]

SECURITY_PACKAGES = {
    'requests', 'paramiko', 'cryptography', 'scapy', 'impacket',
    'pycryptodome', 'pycrypto', 'pyopenssl', 'httplib2', 'urllib3',
    'twisted', 'pyshark', 'netmiko', 'napalm', 'nornir',
}

EXPECTED_SUID = {
    'su', 'sudo', 'passwd', 'newgrp', 'gpasswd', 'chsh', 'chfn',
    'mount', 'umount', 'ping', 'ping6', 'traceroute', 'pkexec',
    'ssh-agent', 'crontab', 'at', 'write',
}

HIGH_RISK_WRITABLE = {
    '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly',
    '/etc/cron.monthly', '/etc/crontab', '/etc/sudoers', '/etc/sudoers.d',
    '/etc/ld.so.conf.d', '/usr/local/bin', '/usr/local/sbin',
    '/etc/profile.d', '/etc/init.d', '/etc/rc.d',
}

CREDENTIAL_SCAN_PATHS = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/nxapi.cfg',
    '/etc/nxos_creds',
    '/root/.bash_history',
    '/root/.bashrc',
]

CREDENTIAL_SCAN_GLOBS = [
    '/isan/conf/**/*.cfg',
    '/isan/conf/**/*.conf',
    '/isan/**/*.ini',
    '/isan/**/*.env',
    '/opt/**/*.cfg',
    '/opt/**/*.conf',
    '/opt/**/*.ini',
    '/opt/**/*.env',
    '/home/*/.bashrc',
    '/home/*/.bash_history',
    '/home/*/.profile',
]

SCRIPT_SEARCH_DIRS = [
    '/isan',
    '/opt',
    '/home',
    '/usr/local',
    '/cisco',
]

SCRIPT_EXTENSIONS = {'.sh', '.py', '.pl', '.rb', '.php'}

NXAPI_PATHS = [
    '/etc/nxapi.cfg',
    '/isan/conf/nxapi.cfg',
    '/isan/conf/nxapi.conf',
    '/tmp/nxapi.cfg',
    '/tmp/nxapi.conf',
]

NETWORK_CONFIG_FILES = {
    'hosts': '/etc/hosts',
    'resolv': '/etc/resolv.conf',
    'interfaces': '/etc/network/interfaces',
    'sysconfig_network': '/etc/sysconfig/network',
    'hostname': '/etc/hostname',
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _safe_read(path: str, max_bytes: int = 524288) -> str:
    """Read a file returning text; silently return '' on any error."""
    try:
        with open(path, 'r', errors='replace') as fh:
            return fh.read(max_bytes)
    except Exception:
        return ''


def _safe_read_bytes(path: str, max_bytes: int = 524288) -> bytes:
    try:
        with open(path, 'rb') as fh:
            return fh.read(max_bytes)
    except Exception:
        return b''


def _file_mode_str(mode: int) -> str:
    """Return octal string like '0o2777'."""
    return oct(mode)


def _severity_for_pattern(pattern_type: str) -> str:
    high = {'SHADOW_HASH', 'NO_PASSWORD_ENTRY', 'PRIVATE_KEY'}
    critical = {'NO_PASSWORD_ENTRY', 'PRIVATE_KEY'}
    if pattern_type in critical:
        return 'CRITICAL'
    if pattern_type in high:
        return 'HIGH'
    return 'MEDIUM'


def _glob_expand(rootfs: str, pattern: str) -> list:
    """Expand a glob pattern rooted at rootfs; return absolute paths."""
    import glob
    full_pattern = rootfs.rstrip('/') + pattern
    return glob.glob(full_pattern, recursive=True)


# ---------------------------------------------------------------------------
# Minimal YAML-like parser (no PyYAML)
# ---------------------------------------------------------------------------

def _parse_simple_yaml(text: str) -> dict:
    """
    Minimal key:value / nested YAML parser.
    Handles:
      - top-level key: value
      - indented sub-keys (2 or 4 spaces)
      - list items with '-'
      - inline comments (#)
    """
    result = {}
    stack = [(0, result)]  # (indent, dict_ref)

    for raw_line in text.splitlines():
        # Strip inline comments, skip blanks/comment-only lines
        line = raw_line.split('#')[0].rstrip()
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        # Pop stack back to appropriate parent level
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        parent = stack[-1][1]

        if stripped.startswith('- '):
            # List item
            value = stripped[2:].strip()
            key = f'_list_{len(parent)}'
            parent[key] = value
            continue

        if ':' in stripped:
            key, _, value = stripped.partition(':')
            key = key.strip()
            value = value.strip()
            if value:
                # Scalar value
                parent[key] = value
            else:
                # Nested dict
                nested = {}
                parent[key] = nested
                stack.append((indent + 1, nested))

    return result


# ---------------------------------------------------------------------------
# GuestShellRE
# ---------------------------------------------------------------------------

class GuestShellRE:
    """Analyzes an extracted/mounted NX-OS guestshell+ rootfs."""

    def __init__(self, rootfs_path: str):
        self.rootfs = rootfs_path.rstrip('/')
        self.is_mounted = os.path.isdir(rootfs_path)
        self.descriptor: dict = {}
        self.credentials: list = []
        self.scripts: list = []
        self.python_packages: list = []
        self.nxapi_config: dict = {}
        self.writable_paths: list = []
        self.suid_binaries: list = []
        self.cron_jobs: list = []
        self.network_config: dict = {}
        self._findings: list = []

    # ------------------------------------------------------------------
    # detect_rootfs_type
    # ------------------------------------------------------------------

    def detect_rootfs_type(self) -> str:
        """Return 'directory' or 'ext4' or 'unknown'."""
        p = self.rootfs
        if os.path.isdir(p):
            return 'directory'
        if os.path.isfile(p):
            raw = _safe_read_bytes(p, EXT4_MAGIC_OFFSET + 4)
            if len(raw) >= EXT4_MAGIC_OFFSET + 2:
                magic = struct.unpack_from('<H', raw, EXT4_MAGIC_OFFSET)[0]
                if magic == EXT4_MAGIC:
                    return 'ext4'
        return 'unknown'

    # ------------------------------------------------------------------
    # parse_cisco_descriptor
    # ------------------------------------------------------------------

    def parse_cisco_descriptor(self) -> dict:
        """Read /cisco/*.yaml or /cisco/package.yaml and parse manually."""
        cisco_dir = os.path.join(self.rootfs, 'cisco')
        if not os.path.isdir(cisco_dir):
            return {}

        candidates = []
        try:
            for entry in os.listdir(cisco_dir):
                if entry.endswith('.yaml') or entry.endswith('.yml'):
                    candidates.append(os.path.join(cisco_dir, entry))
        except OSError:
            return {}

        # Prefer package.yaml
        preferred = os.path.join(cisco_dir, 'package.yaml')
        if preferred in candidates:
            candidates = [preferred] + [c for c in candidates if c != preferred]

        parsed = {}
        for path in candidates:
            text = _safe_read(path)
            if text:
                parsed = _parse_simple_yaml(text)
                break

        # Normalize expected fields
        result = {
            'name': parsed.get('name', ''),
            'version': parsed.get('version', ''),
            'apptype': parsed.get('apptype', ''),
            'cpuarch': parsed.get('cpuarch', ''),
            'resources': {},
            '_raw_path': candidates[0] if candidates else '',
        }
        if 'resources' in parsed and isinstance(parsed['resources'], dict):
            result['resources'] = parsed['resources']
        elif isinstance(parsed.get('resources'), str):
            result['resources'] = {'raw': parsed['resources']}

        self.descriptor = result
        return result

    # ------------------------------------------------------------------
    # hunt_credentials
    # ------------------------------------------------------------------

    def hunt_credentials(self) -> list:
        compiled = [(re.compile(p, re.MULTILINE), t) for p, t in CREDENTIAL_PATTERNS]
        findings = []

        def scan_file(path: str):
            text = _safe_read(path)
            if not text:
                return
            for lineno, line in enumerate(text.splitlines(), 1):
                for pattern, ptype in compiled:
                    m = pattern.search(line)
                    if m:
                        findings.append({
                            'file': path.replace(self.rootfs, '', 1) or path,
                            'line_num': lineno,
                            'pattern_type': ptype,
                            'matched_text': m.group(0)[:200],
                            'severity': _severity_for_pattern(ptype),
                        })

        # Fixed paths
        for rel in CREDENTIAL_SCAN_PATHS:
            scan_file(self.rootfs + rel)

        # Home directories
        home_dir = os.path.join(self.rootfs, 'home')
        if os.path.isdir(home_dir):
            try:
                for user in os.listdir(home_dir):
                    user_dir = os.path.join(home_dir, user)
                    for fname in ['.bashrc', '.bash_history', '.profile', '.netrc']:
                        scan_file(os.path.join(user_dir, fname))
            except OSError:
                pass

        # Glob-expanded paths
        for glob_pattern in CREDENTIAL_SCAN_GLOBS:
            for fpath in _glob_expand(self.rootfs, glob_pattern):
                if os.path.isfile(fpath):
                    scan_file(fpath)

        self.credentials = findings
        return findings

    # ------------------------------------------------------------------
    # enumerate_scripts
    # ------------------------------------------------------------------

    def enumerate_scripts(self) -> list:
        cred_compiled = [(re.compile(p, re.MULTILINE), t) for p, t in CREDENTIAL_PATTERNS]
        net_pattern = re.compile(
            r'(?i)(urllib|requests\.|httplib|curl|wget|socket\.|connect\(|'
            r'ssh\.|paramiko|ftplib|smtplib|telnetlib)', re.MULTILINE
        )
        sudo_pattern = re.compile(r'\bsudo\b', re.MULTILINE)

        scripts = []

        for search_dir in SCRIPT_SEARCH_DIRS:
            abs_dir = os.path.join(self.rootfs, search_dir.lstrip('/'))
            if not os.path.isdir(abs_dir):
                continue
            for dirpath, dirnames, filenames in os.walk(abs_dir):
                # Avoid deep rabbit holes in large trees
                dirnames[:] = [d for d in dirnames if not d.startswith('.')]
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    ext = pathlib.Path(fname).suffix.lower()
                    is_script = ext in SCRIPT_EXTENSIONS
                    if not is_script:
                        # Check shebang
                        try:
                            header = _safe_read_bytes(fpath, 128)
                            is_script = header.startswith(b'#!')
                        except Exception:
                            pass
                    if not is_script:
                        continue

                    try:
                        fsize = os.path.getsize(fpath)
                    except OSError:
                        fsize = 0

                    content = _safe_read(fpath, 65536)
                    has_creds = any(p.search(content) for p, _ in cred_compiled)
                    has_network = bool(net_pattern.search(content))
                    has_sudo = bool(sudo_pattern.search(content))
                    snippet = content[:300].replace('\n', ' ').strip()

                    scripts.append({
                        'path': fpath.replace(self.rootfs, '', 1),
                        'type': ext or 'shebang',
                        'size': fsize,
                        'has_creds': has_creds,
                        'has_network_calls': has_network,
                        'has_sudo': has_sudo,
                        'snippet': snippet,
                    })

        self.scripts = scripts
        return scripts

    # ------------------------------------------------------------------
    # find_python_packages
    # ------------------------------------------------------------------

    def find_python_packages(self) -> list:
        import glob

        search_patterns = [
            '/usr/lib/python*/site-packages',
            '/usr/local/lib/python*/site-packages',
            '/usr/lib/python*/dist-packages',
            '/usr/local/lib/python*/dist-packages',
        ]

        packages = []
        seen = set()

        for pattern in search_patterns:
            for site_dir in glob.glob(self.rootfs + pattern):
                if not os.path.isdir(site_dir):
                    continue
                try:
                    entries = os.listdir(site_dir)
                except OSError:
                    continue

                for entry in entries:
                    entry_path = os.path.join(site_dir, entry)
                    pkg_name = None
                    pkg_version = None

                    if entry.endswith('.dist-info') and os.path.isdir(entry_path):
                        # Read METADATA
                        meta_path = os.path.join(entry_path, 'METADATA')
                        meta = _safe_read(meta_path, 4096)
                        for line in meta.splitlines():
                            if line.startswith('Name:'):
                                pkg_name = line.split(':', 1)[1].strip()
                            elif line.startswith('Version:'):
                                pkg_version = line.split(':', 1)[1].strip()
                            if pkg_name and pkg_version:
                                break
                        if not pkg_name:
                            pkg_name = entry.replace('.dist-info', '').rsplit('-', 1)[0]

                    elif entry.endswith('.egg-info'):
                        # Might be directory or file
                        if os.path.isdir(entry_path):
                            pkg_info_path = os.path.join(entry_path, 'PKG-INFO')
                        else:
                            pkg_info_path = entry_path
                        meta = _safe_read(pkg_info_path, 4096)
                        for line in meta.splitlines():
                            if line.startswith('Name:'):
                                pkg_name = line.split(':', 1)[1].strip()
                            elif line.startswith('Version:'):
                                pkg_version = line.split(':', 1)[1].strip()
                            if pkg_name and pkg_version:
                                break
                        if not pkg_name:
                            pkg_name = entry.replace('.egg-info', '').rsplit('-', 1)[0]

                    if pkg_name and pkg_name not in seen:
                        seen.add(pkg_name)
                        norm = pkg_name.lower().replace('-', '_')
                        is_security = norm in SECURITY_PACKAGES or any(
                            s in norm for s in SECURITY_PACKAGES
                        )
                        packages.append({
                            'name': pkg_name,
                            'version': pkg_version or 'unknown',
                            'site_dir': site_dir.replace(self.rootfs, '', 1),
                            'security_relevant': is_security,
                        })

        self.python_packages = packages
        return packages

    # ------------------------------------------------------------------
    # find_nxapi_config
    # ------------------------------------------------------------------

    def find_nxapi_config(self) -> dict:
        config = {}
        for rel_path in NXAPI_PATHS:
            abs_path = os.path.join(self.rootfs, rel_path.lstrip('/'))
            text = _safe_read(abs_path)
            if not text:
                continue

            # Parse key=value or key: value
            kv_pattern = re.compile(r'^\s*([a-zA-Z_][\w.-]*)\s*[=:]\s*(.+)', re.MULTILINE)
            for m in kv_pattern.finditer(text):
                k = m.group(1).strip().lower().replace('-', '_')
                v = m.group(2).strip().strip('"\'')
                config[k] = v

            config['_source_file'] = rel_path
            break

        # Normalize common field names
        result = {
            'hostname': config.get('hostname', config.get('host', '')),
            'port': config.get('port', ''),
            'auth_type': config.get('auth_type', config.get('auth', '')),
            'certificate': config.get('certificate', config.get('cert', config.get('ssl_cert', ''))),
            'username': config.get('username', config.get('user', '')),
            'password': config.get('password', config.get('passwd', '')),
            '_source_file': config.get('_source_file', ''),
            '_raw': {k: v for k, v in config.items() if not k.startswith('_')},
        }

        self.nxapi_config = result
        return result

    # ------------------------------------------------------------------
    # enumerate_writable
    # ------------------------------------------------------------------

    def enumerate_writable(self) -> list:
        writable = []

        for dirpath, dirnames, filenames in os.walk(self.rootfs):
            # Avoid /proc and /sys bind mounts if somehow present
            dirnames[:] = [
                d for d in dirnames
                if d not in ('proc', 'sys', 'dev')
            ]

            rel_dir = dirpath.replace(self.rootfs, '', 1) or '/'

            try:
                dir_stat = os.stat(dirpath)
                dir_mode = dir_stat.st_mode
                if dir_mode & 0o002:
                    risk = 'HIGH' if rel_dir in HIGH_RISK_WRITABLE else 'MEDIUM'
                    writable.append({
                        'path': rel_dir,
                        'mode_octal': _file_mode_str(dir_mode & 0o7777),
                        'type': 'directory',
                        'risk': risk,
                    })
            except OSError:
                pass

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                rel_path = fpath.replace(self.rootfs, '', 1)
                try:
                    fstat = os.stat(fpath)
                    fmode = fstat.st_mode
                    if fmode & 0o002:
                        # Determine risk
                        risk = 'MEDIUM'
                        for hr in HIGH_RISK_WRITABLE:
                            if rel_path.startswith(hr):
                                risk = 'HIGH'
                                break
                        if rel_dir in ('/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin'):
                            risk = 'CRITICAL'
                        writable.append({
                            'path': rel_path,
                            'mode_octal': _file_mode_str(fmode & 0o7777),
                            'type': 'file',
                            'risk': risk,
                        })
                except OSError:
                    pass

        self.writable_paths = writable
        return writable

    # ------------------------------------------------------------------
    # find_suid_binaries
    # ------------------------------------------------------------------

    def find_suid_binaries(self) -> list:
        suid = []

        for dirpath, dirnames, filenames in os.walk(self.rootfs):
            dirnames[:] = [d for d in dirnames if d not in ('proc', 'sys', 'dev')]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    fstat = os.stat(fpath)
                    fmode = fstat.st_mode
                    if not (fmode & 0o4000):
                        continue
                    rel_path = fpath.replace(self.rootfs, '', 1)
                    is_expected = fname in EXPECTED_SUID
                    suid.append({
                        'path': rel_path,
                        'name': fname,
                        'mode_octal': _file_mode_str(fmode & 0o7777),
                        'expected': is_expected,
                        'risk': 'LOW' if is_expected else 'HIGH',
                    })
                except OSError:
                    pass

        self.suid_binaries = suid
        return suid

    # ------------------------------------------------------------------
    # read_cron_jobs
    # ------------------------------------------------------------------

    def read_cron_jobs(self) -> list:
        cron_jobs = []
        cron_line = re.compile(
            r'^(@\w+|\*[\d*/,-]*\s+\*[\d*/,-]*\s+\*[\d*/,-]*\s+\*[\d*/,-]*\s+\*[\d*/,-]*'
            r'|\d[\d*/,-]*\s+\d[\d*/,-]*\s+\d[\d*/,-]*\s+\d[\d*/,-]*\s+\d[\d*/,-]*)'
            r'\s+(.+)'
        )
        user_cron_line = re.compile(
            r'^\s*(@\w+|\d[\d*/,-]*\s+\d[\d*/,-]*\s+\d[\d*/,-]*\s+\d[\d*/,-]*\s+\d[\d*/,-]*)'
            r'\s+(\w+)\s+(.+)'
        )

        def parse_crontab(path: str, default_user: str = 'root'):
            text = _safe_read(path)
            for lineno, line in enumerate(text.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Try system crontab format (with user field)
                m = user_cron_line.match(line)
                if m:
                    cron_jobs.append({
                        'schedule': m.group(1).strip(),
                        'user': m.group(2).strip(),
                        'command': m.group(3).strip(),
                        'file': path.replace(self.rootfs, '', 1),
                    })
                    continue
                # Try user crontab format
                m = cron_line.match(line)
                if m:
                    cron_jobs.append({
                        'schedule': m.group(1).strip(),
                        'user': default_user,
                        'command': m.group(2).strip(),
                        'file': path.replace(self.rootfs, '', 1),
                    })

        # /etc/crontab
        parse_crontab(os.path.join(self.rootfs, 'etc', 'crontab'), 'root')

        # /etc/cron.d/*
        cron_d = os.path.join(self.rootfs, 'etc', 'cron.d')
        if os.path.isdir(cron_d):
            try:
                for fname in os.listdir(cron_d):
                    parse_crontab(os.path.join(cron_d, fname))
            except OSError:
                pass

        # /var/spool/cron/*
        spool = os.path.join(self.rootfs, 'var', 'spool', 'cron')
        if os.path.isdir(spool):
            try:
                for username in os.listdir(spool):
                    parse_crontab(os.path.join(spool, username), username)
            except OSError:
                pass

        self.cron_jobs = cron_jobs
        return cron_jobs

    # ------------------------------------------------------------------
    # read_network_config
    # ------------------------------------------------------------------

    def _read_network_config(self) -> dict:
        net_cfg = {}
        for key, rel_path in NETWORK_CONFIG_FILES.items():
            abs_path = os.path.join(self.rootfs, rel_path.lstrip('/'))
            text = _safe_read(abs_path)
            if text:
                net_cfg[key] = text.strip()

        # Parse interfaces for IPs
        ips = []
        interfaces_text = net_cfg.get('interfaces', '')
        for m in re.finditer(r'\baddress\s+([\d.]+)', interfaces_text):
            ips.append(m.group(1))
        # Also check sysconfig network
        sysnet = net_cfg.get('sysconfig_network', '')
        for m in re.finditer(r'IPADDR=([\d.]+)', sysnet):
            ips.append(m.group(1))

        net_cfg['parsed_ips'] = ips
        self.network_config = net_cfg
        return net_cfg

    # ------------------------------------------------------------------
    # _build_findings
    # ------------------------------------------------------------------

    def _build_findings(self) -> list:
        findings = []

        # Credential findings
        for cred in self.credentials:
            sev = cred.get('severity', 'MEDIUM')
            findings.append({
                'severity': sev,
                'title': f"Credential exposure ({cred['pattern_type']})",
                'detail': f"{cred['file']}:{cred['line_num']} -> {cred['matched_text']}",
                'category': 'CREDENTIAL',
            })

        # SUID findings
        for suid in self.suid_binaries:
            if not suid.get('expected'):
                findings.append({
                    'severity': 'HIGH',
                    'title': f"Non-standard SUID binary",
                    'detail': f"{suid['path']} (mode {suid['mode_octal']})",
                    'category': 'PRIVESC',
                })

        # Writable critical paths
        critical_w = [w for w in self.writable_paths if w.get('risk') == 'CRITICAL']
        for w in critical_w:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'World-writable critical path',
                'detail': f"{w['path']} (mode {w['mode_octal']})",
                'category': 'CONTAINER_ESCAPE',
            })

        high_w = [w for w in self.writable_paths if w.get('risk') == 'HIGH']
        for w in high_w:
            findings.append({
                'severity': 'HIGH',
                'title': 'World-writable high-risk path',
                'detail': f"{w['path']} (mode {w['mode_octal']})",
                'category': 'CONTAINER_ESCAPE',
            })

        # Scripts with embedded creds
        for script in self.scripts:
            if script.get('has_creds'):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'Script with embedded credentials',
                    'detail': f"{script['path']} ({script['type']}, {script['size']} bytes)",
                    'category': 'CREDENTIAL',
                })

        # NX-API cleartext password
        if self.nxapi_config.get('password'):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'NX-API cleartext password in config',
                'detail': f"Source: {self.nxapi_config.get('_source_file', 'unknown')}",
                'category': 'CREDENTIAL',
            })

        # Security-relevant Python packages
        sec_pkgs = [p for p in self.python_packages if p.get('security_relevant')]
        if sec_pkgs:
            names = ', '.join(p['name'] for p in sec_pkgs)
            findings.append({
                'severity': 'INFO',
                'title': 'Security-relevant Python packages installed',
                'detail': names,
                'category': 'INVENTORY',
            })

        # Cron jobs running as root
        root_crons = [c for c in self.cron_jobs if c.get('user') == 'root']
        for cron in root_crons:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'Root cron job',
                'detail': f"{cron['schedule']} -> {cron['command']} (from {cron['file']})",
                'category': 'PRIVESC',
            })

        self._findings = findings
        return findings

    # ------------------------------------------------------------------
    # analyze
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        rootfs_type = self.detect_rootfs_type()

        descriptor = self.parse_cisco_descriptor()
        credentials = self.hunt_credentials()
        scripts = self.enumerate_scripts()
        python_packages = self.find_python_packages()
        nxapi_config = self.find_nxapi_config()
        writable_paths = self.enumerate_writable()
        suid_binaries = self.find_suid_binaries()
        cron_jobs = self.read_cron_jobs()
        network_config = self._read_network_config()

        findings = self._build_findings()

        # Severity summary
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in findings:
            sev = f.get('severity', 'INFO')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            'rootfs_path': self.rootfs,
            'rootfs_type': rootfs_type,
            'descriptor': descriptor,
            'credentials': credentials,
            'scripts': scripts,
            'python_packages': python_packages,
            'nxapi_config': nxapi_config,
            'writable_paths': writable_paths,
            'suid_binaries': suid_binaries,
            'cron_jobs': cron_jobs,
            'network_config': network_config,
            'findings': findings,
            'summary': {
                'total_findings': len(findings),
                'severity_counts': severity_counts,
                'credential_count': len(credentials),
                'script_count': len(scripts),
                'suid_count': len(suid_binaries),
                'writable_count': len(writable_paths),
                'cron_count': len(cron_jobs),
            },
        }

    # ------------------------------------------------------------------
    # report
    # ------------------------------------------------------------------

    def report(self) -> str:
        if not self._findings:
            self.analyze()

        lines = [
            '=' * 70,
            f'NX-OS GuestShell RE Report — {self.rootfs}',
            '=' * 70,
        ]

        if self.descriptor:
            lines.append(f"\nDescriptor:")
            lines.append(f"  Name    : {self.descriptor.get('name', 'N/A')}")
            lines.append(f"  Version : {self.descriptor.get('version', 'N/A')}")
            lines.append(f"  Type    : {self.descriptor.get('apptype', 'N/A')}")
            lines.append(f"  Arch    : {self.descriptor.get('cpuarch', 'N/A')}")

        lines.append(f"\nFindings ({len(self._findings)} total):")
        for f in sorted(self._findings, key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].index(x.get('severity','INFO'))):
            lines.append(f"  [{f['severity']:<8}] {f['title']}")
            lines.append(f"             {f['detail'][:100]}")

        lines.append(f"\nCredentials found : {len(self.credentials)}")
        lines.append(f"Scripts analyzed  : {len(self.scripts)}")
        lines.append(f"SUID binaries     : {len(self.suid_binaries)}")
        lines.append(f"Writable paths    : {len(self.writable_paths)}")
        lines.append(f"Cron jobs         : {len(self.cron_jobs)}")
        lines.append('=' * 70)

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# NXOSRootfsExtractor
# ---------------------------------------------------------------------------

class NXOSRootfsExtractor:
    """Extracts an ext4 image to a temp directory for analysis."""

    def __init__(self, ext4_path: str):
        self.ext4_path = ext4_path
        self.extract_dir: str = None
        self._tmpdir_owned = False

    def extract(self) -> str:
        """
        Try debugfs rdump; fallback to strings-based credential extraction.
        Returns path to extracted directory, or None on complete failure.
        """
        self.extract_dir = tempfile.mkdtemp(prefix='nxos_rootfs_')
        self._tmpdir_owned = True

        if self._try_debugfs():
            return self.extract_dir

        # debugfs failed — fallback
        # Can't walk the ext4 tree without tools; create a synthetic dir
        # and write strings output as a pseudo-file for credential scanning
        strings_findings = self.extract_strings_fallback()
        if strings_findings:
            synthetic_path = os.path.join(self.extract_dir, 'etc', 'nxos_creds')
            os.makedirs(os.path.dirname(synthetic_path), exist_ok=True)
            with open(synthetic_path, 'w') as fh:
                for line in strings_findings:
                    fh.write(line + '\n')
            return self.extract_dir

        return None

    def _try_debugfs(self) -> bool:
        """
        Use debugfs to recursively dump rootfs content.
        Returns True if extraction produced any files.
        """
        try:
            result = subprocess.run(
                ['which', 'debugfs'],
                capture_output=True, timeout=5
            )
            if result.returncode != 0:
                return False

            # Use debugfs rdump to extract all files
            cmd = [
                'debugfs', '-R',
                f'rdump / {self.extract_dir}',
                self.ext4_path
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=120,
                text=True,
            )
            # Check if any files appeared
            count = sum(len(files) for _, _, files in os.walk(self.extract_dir))
            return count > 0

        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return False
        except Exception:
            return False

    def extract_strings_fallback(self) -> list:
        """
        Read raw ext4 bytes; extract printable ASCII strings >= 8 chars.
        Filter for credential patterns. Works even without debugfs.
        """
        cred_compiled = [(re.compile(p, re.MULTILINE), t) for p, t in CREDENTIAL_PATTERNS]

        matches = []
        min_len = 8
        chunk_size = 1 << 20  # 1MB at a time

        try:
            file_size = os.path.getsize(self.ext4_path)
        except OSError:
            return []

        printable = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')

        try:
            with open(self.ext4_path, 'rb') as fh:
                offset = 0
                # Skip first 4KB (ext4 boot sector + start of superblock)
                fh.seek(4096)
                offset = 4096

                while offset < file_size:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    for m in printable.finditer(chunk):
                        s = m.group(0).decode('ascii', errors='replace')
                        for cred_pat, ptype in cred_compiled:
                            if cred_pat.search(s):
                                matches.append(f'[{ptype}] offset=0x{offset + m.start():x}: {s[:200]}')
                                break
                    offset += len(chunk)
        except (OSError, PermissionError):
            pass

        return matches

    def cleanup(self):
        """Remove the temp extraction directory."""
        if self._tmpdir_owned and self.extract_dir and os.path.isdir(self.extract_dir):
            import shutil
            try:
                shutil.rmtree(self.extract_dir)
            except Exception:
                pass
            self.extract_dir = None
            self._tmpdir_owned = False


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def analyze_guestshell(path: str) -> dict:
    """
    Auto-detect input type and run full analysis.
    - Directory: GuestShellRE direct
    - ext4 file: NXOSRootfsExtractor -> GuestShellRE
    Returns unified findings dict.
    """
    if not os.path.exists(path):
        return {
            'error': f'Path does not exist: {path}',
            'findings': [],
            'summary': {},
        }

    extractor = None

    if os.path.isdir(path):
        re_obj = GuestShellRE(path)
        result = re_obj.analyze()
        result['input_type'] = 'directory'
        return result

    # File — check for ext4 magic
    rtype = GuestShellRE(path).detect_rootfs_type()

    if rtype == 'ext4':
        extractor = NXOSRootfsExtractor(path)
        extracted_path = extractor.extract()

        if extracted_path:
            re_obj = GuestShellRE(extracted_path)
            result = re_obj.analyze()
            result['input_type'] = 'ext4_extracted'
            result['ext4_source'] = path

            # If debugfs fallback was used, also include raw strings findings
            if not re_obj.credentials and extracted_path:
                strings_file = os.path.join(extracted_path, 'etc', 'nxos_creds')
                if os.path.isfile(strings_file):
                    result['strings_fallback'] = True

            extractor.cleanup()
            return result
        else:
            # Pure strings fallback
            strings = NXOSRootfsExtractor(path).extract_strings_fallback()
            return {
                'input_type': 'ext4_strings_only',
                'ext4_source': path,
                'strings_findings': strings,
                'findings': [
                    {
                        'severity': 'INFO',
                        'title': 'Strings-only extraction (no debugfs)',
                        'detail': f'{len(strings)} credential pattern matches from raw ext4 bytes',
                        'category': 'EXTRACTION',
                    }
                ] + [
                    {
                        'severity': 'MEDIUM',
                        'title': 'Raw string credential match',
                        'detail': s[:200],
                        'category': 'CREDENTIAL',
                    }
                    for s in strings
                ],
                'summary': {
                    'total_findings': len(strings) + 1,
                    'strings_count': len(strings),
                },
            }
    else:
        # Unknown file type
        return {
            'error': f'Unrecognized file type (not ext4, not directory): {path}',
            'detected_type': rtype,
            'findings': [],
            'summary': {},
        }


# ---------------------------------------------------------------------------
# Standalone execution
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <rootfs_dir_or_ext4_image>', file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]
    result = analyze_guestshell(target)
    print(json.dumps(result, indent=2, default=str))

    print('\n--- Findings ---')
    for f in result.get('findings', []):
        print(f"[{f['severity']}] {f['title']}: {f['detail'][:120]}")

    summary = result.get('summary', {})
    if summary:
        print(f"\nTotal findings: {summary.get('total_findings', 0)}")
        sc = summary.get('severity_counts', {})
        if sc:
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sc.get(sev):
                    print(f"  {sev}: {sc[sev]}")
