#!/usr/bin/env python3
"""
ISE ISO Filesystem Analyzer

Mounts an ISE appliance ISO (ISO9660 / ADEOS/RHEL8-based) and extracts
security-relevant artifacts: root hash, Oracle/TimesTen config, TACACS+
pam config, package list, ISE application config, SELinux status.

Usage:
    python3 ise_iso.py /path/to/ise-3.1.0.518c.SPA.x86_64_SNS-37x5.iso
    python3 ise_iso.py --mountpoint /mnt/ise    # already mounted
"""

import os
import re
import sys
import json
import stat
import struct
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
import socket
import ssl
import urllib.request
import urllib.error


# ---------------------------------------------------------------------------
# ISE 3.1 filesystem layout constants (ADEOS = RHEL8-based)
# ---------------------------------------------------------------------------
ISE_SHADOW_PATH       = 'etc/shadow'
ISE_PASSWD_PATH       = 'etc/passwd'
ISE_PAM_DIR           = 'etc/pam.d'
ISE_SUDOERS_PATH      = 'etc/sudoers'
ISE_SELINUX_PATH      = 'etc/selinux/config'
ISE_HOSTNAME_PATH     = 'etc/hostname'
ISE_NETWORK_DIR       = 'etc/sysconfig/network-scripts'
ISE_ORACLE_DIR        = 'opt/oracle'
ISE_TIMESTEN_DIR      = 'opt/timesten'
ISE_APP_DIR           = 'opt/CSCOcpm'
ISE_APP_CONFIG        = 'opt/CSCOcpm/conf/ise.properties'
ISE_DB_CONFIG         = 'opt/CSCOcpm/conf/ise_oracle.properties'
ISE_TACPLUS_LIB_PATHS = [
    'usr/lib64/security/pam_tacplus.so',
    'usr/lib/security/pam_tacplus.so',
    'lib64/security/pam_tacplus.so',
]
ISE_RPM_DB_PATH       = 'var/lib/rpm'
ISE_CONTAINER_DIR     = 'var/lib/containers'
ISE_SSH_KEYS_DIR      = 'etc/ssh'
ISE_CRON_DIRS         = ['etc/cron.d', 'etc/cron.daily', 'etc/cron.weekly']

# Known ISE 3.1 Oracle TimesTen in-memory DB port
TIMESTEN_PORT = 53384

# ISE internal Oracle DB (local only in 3.1.0)
ORACLE_SID    = 'isedb'
ORACLE_PORT   = 1521


# ---------------------------------------------------------------------------
# ISO9660 mount helpers
# ---------------------------------------------------------------------------

def _isoinfo_list(iso_path: str) -> list:
    """List ISO contents using isoinfo without root (no loop mount needed)."""
    try:
        out = subprocess.check_output(
            ['isoinfo', '-l', '-i', iso_path],
            stderr=subprocess.DEVNULL, timeout=30
        ).decode('utf-8', errors='replace')
        return out.splitlines()
    except Exception:
        return []


def _isoinfo_extract(iso_path: str, iso_path_in: str, dest: str) -> bool:
    """Extract a single file from ISO using isoinfo (no root required)."""
    try:
        data = subprocess.check_output(
            ['isoinfo', '-R', '-i', iso_path, '-x', iso_path_in],
            stderr=subprocess.DEVNULL, timeout=15
        )
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        Path(dest).write_bytes(data)
        return True
    except Exception:
        return False


def _mount_iso(iso_path: str, mountpoint: str) -> bool:
    """Mount ISO using loop device (requires root or FUSE)."""
    try:
        result = subprocess.run(
            ['mount', '-o', 'loop,ro', iso_path, mountpoint],
            capture_output=True, timeout=15
        )
        return result.returncode == 0
    except Exception:
        return False


def _umount(mountpoint: str) -> None:
    try:
        subprocess.run(['umount', mountpoint], capture_output=True, timeout=10)
    except Exception:
        pass


def _can_mount() -> bool:
    return os.geteuid() == 0


# ---------------------------------------------------------------------------
# Hash identification
# ---------------------------------------------------------------------------

def identify_hash(h: str) -> dict:
    if h.startswith('$5$'):
        return {
            'type':    'sha256crypt',
            'hashcat': '7400',
            'john':    'sha256crypt',
            'cmd':     f"hashcat -m 7400 '{h}' /usr/share/wordlists/rockyou.txt",
        }
    if h.startswith('$6$'):
        return {
            'type':    'sha512crypt',
            'hashcat': '1800',
            'john':    'sha512crypt',
            'cmd':     f"hashcat -m 1800 '{h}' /usr/share/wordlists/rockyou.txt",
        }
    if h.startswith('$y$') or h.startswith('$2y$'):
        return {
            'type': 'bcrypt/yescrypt', 'hashcat': '3200', 'john': 'bcrypt',
            'cmd':  f"hashcat -m 3200 '{h}' /usr/share/wordlists/rockyou.txt",
        }
    if h.startswith('$1$'):
        return {
            'type': 'md5crypt', 'hashcat': '500', 'john': 'md5crypt',
            'cmd':  f"hashcat -m 500 '{h}' /usr/share/wordlists/rockyou.txt",
        }
    return {'type': 'unknown', 'hashcat': None, 'john': None, 'cmd': None}


# ---------------------------------------------------------------------------
# Extractors (operate on a root directory — mounted or tempdir)
# ---------------------------------------------------------------------------

def extract_shadow(root: Path) -> list:
    """Parse /etc/shadow, return list of user/hash entries."""
    results = []
    shadow = root / ISE_SHADOW_PATH
    if not shadow.exists():
        return results
    for line in shadow.read_text(errors='replace').splitlines():
        parts = line.split(':')
        if len(parts) < 2:
            continue
        user, pw_hash = parts[0], parts[1]
        if pw_hash in ('', '!', '*', 'x', '!!'):
            continue
        results.append({
            'user':     user,
            'hash':     pw_hash,
            'hash_id':  identify_hash(pw_hash),
        })
    return results


def extract_passwd(root: Path) -> list:
    results = []
    passwd = root / ISE_PASSWD_PATH
    if not passwd.exists():
        return results
    for line in passwd.read_text(errors='replace').splitlines():
        parts = line.split(':')
        if len(parts) < 7:
            continue
        results.append({
            'user': parts[0], 'uid': parts[2], 'gid': parts[3],
            'home': parts[5], 'shell': parts[6].strip(),
        })
    return results


def extract_selinux_status(root: Path) -> dict:
    p = root / ISE_SELINUX_PATH
    if not p.exists():
        return {'status': 'unknown', 'file_missing': True}
    content = p.read_text(errors='replace')
    mode = 'unknown'
    for line in content.splitlines():
        if line.startswith('SELINUX='):
            mode = line.split('=', 1)[1].strip()
    return {'status': mode, 'content': content}


def extract_pam_tacplus(root: Path) -> dict:
    """Find pam_tacplus.so and any PAM configs that reference it."""
    result = {
        'so_found':  False,
        'so_paths':  [],
        'pam_configs': [],
    }
    for rel in ISE_TACPLUS_LIB_PATHS:
        p = root / rel
        if p.exists():
            result['so_found'] = True
            result['so_paths'].append(str(p))

    pam_dir = root / ISE_PAM_DIR
    if pam_dir.is_dir():
        for f in pam_dir.iterdir():
            try:
                content = f.read_text(errors='replace')
                if 'tacplus' in content.lower() or 'tac_plus' in content.lower():
                    result['pam_configs'].append({
                        'file':    f.name,
                        'content': content,
                    })
            except Exception:
                pass
    return result


def extract_ise_app_config(root: Path) -> dict:
    """Extract ISE application properties — DB passwords, service URLs."""
    result = {'files': {}}
    targets = [
        ISE_APP_CONFIG,
        ISE_DB_CONFIG,
        'opt/CSCOcpm/conf/props/adeos.properties',
        'opt/CSCOcpm/conf/props/database.properties',
        'opt/CSCOcpm/conf/props/ncs.properties',
        'opt/CSCOcpm/conf/server.xml',
        'etc/ise/ise_config',
    ]
    for rel in targets:
        p = root / rel
        if p.exists():
            try:
                result['files'][rel] = p.read_text(errors='replace')
            except Exception:
                pass
    # Grep for credentials in all found files
    cred_patterns = [
        r'password\s*[=:]\s*\S+',
        r'passwd\s*[=:]\s*\S+',
        r'jdbc:oracle[^\s"\']+',
        r'dburl\s*[=:]\s*\S+',
        r'secret\s*[=:]\s*\S+',
        r'key\s*[=:]\s*[A-Za-z0-9+/=]{16,}',
    ]
    creds_found = []
    for path, content in result['files'].items():
        for pat in cred_patterns:
            for m in re.finditer(pat, content, re.IGNORECASE):
                creds_found.append({'file': path, 'match': m.group()[:200]})
    result['credentials'] = creds_found
    return result


def extract_oracle_config(root: Path) -> dict:
    """Oracle + TimesTen config files."""
    result = {'files': {}, 'timesten_found': False}
    targets = [
        'opt/oracle/product/18c/dbhome_1/network/admin/tnsnames.ora',
        'opt/oracle/product/18c/dbhome_1/network/admin/listener.ora',
        'opt/timesten/tt1122/conf/sys.odbc.ini',
        'opt/timesten/tt1122/conf/timesten.conf',
        'etc/oracle/oracle.conf',
        'etc/sysconfig/oracle',
    ]
    for rel in targets:
        p = root / rel
        if p.exists():
            try:
                result['files'][rel] = p.read_text(errors='replace')
                if 'timesten' in rel.lower():
                    result['timesten_found'] = True
            except Exception:
                pass
    # Glob for any tnsnames.ora
    for p in root.rglob('tnsnames.ora'):
        rel = str(p.relative_to(root))
        if rel not in result['files']:
            try:
                result['files'][rel] = p.read_text(errors='replace')
            except Exception:
                pass
    return result


def extract_packages(root: Path) -> list:
    """Query RPM DB at var/lib/rpm — returns installed package names."""
    rpm_db = root / ISE_RPM_DB_PATH
    if not rpm_db.exists():
        return []
    try:
        out = subprocess.check_output(
            ['rpm', '--dbpath', str(rpm_db), '-qa', '--queryformat',
             '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'],
            stderr=subprocess.DEVNULL, timeout=30
        ).decode('utf-8', errors='replace')
        return [l.strip() for l in out.splitlines() if l.strip()]
    except Exception:
        return []


def extract_ssh_host_keys(root: Path) -> list:
    """SSH host private keys — can be used for host spoofing."""
    results = []
    ssh_dir = root / ISE_SSH_KEYS_DIR
    if not ssh_dir.is_dir():
        return results
    for f in ssh_dir.iterdir():
        if 'key' in f.name and not f.name.endswith('.pub'):
            try:
                content = f.read_text(errors='replace')
                if 'PRIVATE KEY' in content:
                    results.append({'file': f.name, 'key': content})
            except Exception:
                pass
    return results


def extract_suid_binaries(root: Path) -> list:
    """SUID/SGID binaries in the ISO filesystem — privesc surface."""
    results = []
    try:
        for p in root.rglob('*'):
            if not p.is_file():
                continue
            try:
                mode = p.stat().st_mode
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    results.append({
                        'path': str(p.relative_to(root)),
                        'suid': bool(mode & stat.S_ISUID),
                        'sgid': bool(mode & stat.S_ISGID),
                        'mode': oct(mode),
                    })
            except Exception:
                pass
    except Exception:
        pass
    return results


def extract_cron_jobs(root: Path) -> list:
    results = []
    for d in ISE_CRON_DIRS:
        cron_dir = root / d
        if not cron_dir.is_dir():
            continue
        for f in cron_dir.iterdir():
            try:
                results.append({'dir': d, 'file': f.name,
                                 'content': f.read_text(errors='replace')})
            except Exception:
                pass
    return results


def scan_ise_binaries(root: Path) -> dict:
    """
    Route ISE artifacts to the correct analyzer by file type.

    ISE 3.1 language profile: Java ~50%, C/C++ ~30%, Go ~8%, Python ~7%.
    Priorities:
      .jar/.class → java_re.JavaREAnalyzer (Spring endpoints, Log4j, JDBC creds, deserialization)
      ELF x86-64  → elf_parser.ELFParser    (RELRO/NX/PIE, GOT hooks, SUID surface)
      .py         → credential regex scan    (hardcoded secrets in Python automation)
      Go binary   → ELF parser + strings extraction (Podman/container runtime)
    """
    result = {
        'java_jars':   [],
        'elf_bins':    [],
        'python_creds': [],
        'go_bins':     [],
        'java_findings':  [],
        'elf_findings':   [],
    }

    # Import analyzers lazily
    sys.path.insert(0, str(Path(__file__).parent))
    sys.path.insert(0, str(Path(__file__).parent.parent / 'core'))
    try:
        from java_re import JavaREAnalyzer
        has_java = True
    except ImportError:
        has_java = False
    try:
        from elf_parser import ELFParser
        has_elf = True
    except ImportError:
        has_elf = False

    # ISE Java search paths (bulk of Java is under /opt/CSCOcpm)
    jar_search_dirs = [
        root / 'opt' / 'CSCOcpm',
        root / 'opt' / 'oracle',
    ]
    elf_search_dirs = [
        root / 'usr' / 'sbin',
        root / 'usr' / 'bin',
        root / 'opt' / 'CSCOcpm' / 'bin',
    ]

    _CRED_RE = re.compile(
        r'(password|passwd|secret|api_key|token|credential)\s*=\s*["\']?([^\s"\']{6,})',
        re.IGNORECASE
    )

    # Java JARs
    for search_dir in jar_search_dirs:
        if not search_dir.exists():
            continue
        for jar in list(search_dir.rglob('*.jar'))[:40]:
            result['java_jars'].append(str(jar.relative_to(root)))
            if has_java:
                try:
                    analyzer = JavaREAnalyzer(str(jar))
                    findings = analyzer.analyze()
                    vulns = [f for f in findings.get('findings', [])
                             if f.get('severity') in ('CRITICAL', 'HIGH')]
                    if vulns:
                        result['java_findings'].extend([{
                            'jar': str(jar.relative_to(root)),
                            **v,
                        } for v in vulns[:5]])
                except Exception:
                    pass

    # ELF binaries (ISE C/C++ core services)
    for search_dir in elf_search_dirs:
        if not search_dir.exists():
            continue
        for f in list(search_dir.iterdir())[:30]:
            if not f.is_file():
                continue
            try:
                with open(f, 'rb') as fh:
                    magic = fh.read(4)
                if magic != b'\x7fELF':
                    continue
                rel = str(f.relative_to(root))
                result['elf_bins'].append(rel)
                if has_elf:
                    ep = ELFParser(str(f))
                    ep.parse()
                    sec = ep.to_dict().get('security', {})
                    issues = []
                    if not sec.get('pie'):    issues.append('no-PIE')
                    if not sec.get('nx'):     issues.append('no-NX')
                    if sec.get('relro') == 'none': issues.append('no-RELRO')
                    if not sec.get('canary'): issues.append('no-canary')
                    if issues:
                        result['elf_findings'].append({
                            'binary': rel, 'issues': issues,
                            'severity': 'HIGH' if 'no-NX' in issues else 'MEDIUM',
                        })
            except Exception:
                pass

    # Python credential scan
    for py in list((root / 'opt' / 'CSCOcpm').rglob('*.py'))[:100] \
               if (root / 'opt' / 'CSCOcpm').exists() else []:
        try:
            content = py.read_text(errors='replace')
            for m in _CRED_RE.finditer(content):
                result['python_creds'].append({
                    'file':  str(py.relative_to(root)),
                    'key':   m.group(1),
                    'value': m.group(2)[:60],
                })
                if len(result['python_creds']) >= 20:
                    break
        except Exception:
            pass
        if len(result['python_creds']) >= 20:
            break

    return result


def check_containers(root: Path) -> dict:
    """Podman container storage detection."""
    container_dir = root / ISE_CONTAINER_DIR
    result = {'found': container_dir.exists(), 'images': []}
    if container_dir.exists():
        for p in (container_dir / 'storage').glob('*') if (container_dir / 'storage').exists() else []:
            result['images'].append(str(p.name))
    return result


# ---------------------------------------------------------------------------
# ISO analysis orchestrator
# ---------------------------------------------------------------------------

class ISEISOAnalyzer:
    def __init__(self, iso_path: Optional[str] = None,
                 mountpoint: Optional[str] = None):
        self.iso_path   = iso_path
        self.mountpoint = mountpoint
        self._tmpdir    = None
        self._mounted   = False
        self.findings   = []

    def _get_root(self) -> Optional[Path]:
        if self.mountpoint:
            return Path(self.mountpoint)
        if self.iso_path and _can_mount():
            self._tmpdir = tempfile.mkdtemp(prefix='ise_iso_')
            if _mount_iso(self.iso_path, self._tmpdir):
                self._mounted = True
                return Path(self._tmpdir)
        return None

    def cleanup(self):
        if self._mounted and self._tmpdir:
            _umount(self._tmpdir)
        if self._tmpdir and Path(self._tmpdir).exists():
            try:
                import shutil
                shutil.rmtree(self._tmpdir)
            except Exception:
                pass

    def analyze(self) -> dict:
        root = self._get_root()
        result = {
            'iso_path':         self.iso_path,
            'mountpoint':       str(root) if root else None,
            'mounted':          self._mounted,
            'shadow':           [],
            'passwd':           [],
            'selinux':          {},
            'pam_tacplus':      {},
            'ise_app_config':   {},
            'oracle_config':    {},
            'packages':         [],
            'ssh_host_keys':    [],
            'suid_binaries':    [],
            'cron_jobs':        [],
            'containers':       {},
            'findings':         [],
        }

        if root is None:
            result['error'] = ('No root: supply --mountpoint of already-mounted ISO, '
                               'or run as root with --iso for loop mount.')
            return result

        # Shadow / password hashes
        result['shadow'] = extract_shadow(root)
        for entry in result['shadow']:
            sev = 'CRITICAL' if entry['user'] == 'root' else 'HIGH'
            self.findings.append({
                'severity': sev,
                'title':    f"ISE ISO: Password Hash ({entry['user']})",
                'detail':   (f"hash={entry['hash'][:60]}... | "
                             f"type={entry['hash_id']['type']} | "
                             f"crack: {entry['hash_id']['cmd']}"),
            })

        # Users
        result['passwd'] = extract_passwd(root)

        # SELinux
        result['selinux'] = extract_selinux_status(root)
        if result['selinux'].get('status') in ('permissive', 'disabled'):
            self.findings.append({
                'severity': 'HIGH',
                'title':    f"ISE ISO: SELinux {result['selinux']['status'].upper()}",
                'detail':   'Kernel MAC disabled — privesc without LSM enforcement',
            })

        # pam_tacplus — ISE is the TACACS+ server for all Cisco devices
        result['pam_tacplus'] = extract_pam_tacplus(root)
        if result['pam_tacplus']['so_found']:
            self.findings.append({
                'severity': 'HIGH',
                'title':    'ISE ISO: pam_tacplus Present',
                'detail':   ('ISE acts as TACACS+ auth server for Cisco devices. '
                             'Root on ISE → extract /etc/tacplus_srv.conf or '
                             'ISE Oracle DB → all Cisco device credentials'),
            })

        # ISE app config (DB passwords, JDBC strings)
        result['ise_app_config'] = extract_ise_app_config(root)
        if result['ise_app_config']['credentials']:
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    'ISE ISO: Application Credentials in Config',
                'detail':   str(result['ise_app_config']['credentials'])[:400],
            })

        # Oracle / TimesTen
        result['oracle_config'] = extract_oracle_config(root)
        if result['oracle_config']['timesten_found']:
            self.findings.append({
                'severity': 'HIGH',
                'title':    'ISE ISO: Oracle TimesTen In-Memory DB Config Found',
                'detail':   f"Port {TIMESTEN_PORT} (default). JDBC: jdbc:timesten:direct:{ORACLE_SID}",
            })

        # SSH host keys
        result['ssh_host_keys'] = extract_ssh_host_keys(root)
        if result['ssh_host_keys']:
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    f"ISE ISO: SSH Host Keys Extracted ({len(result['ssh_host_keys'])})",
                'detail':   'Can spoof ISE SSH identity; use for MITM on device mgmt sessions',
            })

        # Packages
        result['packages'] = extract_packages(root)
        if result['packages']:
            # Flag interesting packages
            interesting = [p for p in result['packages']
                           if any(kw in p.lower() for kw in
                                  ('oracle', 'timesten', 'java', 'openssl', 'podman',
                                   'container', 'tacacs', 'radius', 'pam'))]
            self.findings.append({
                'severity': 'INFO',
                'title':    f"ISE ISO: {len(result['packages'])} packages ({len(interesting)} security-relevant)",
                'detail':   str(interesting[:20]),
            })

        # SUID (sampled — full scan slow on large ISO)
        result['suid_binaries'] = extract_suid_binaries(root)

        # Cron jobs
        result['cron_jobs'] = extract_cron_jobs(root)

        # Containers
        result['containers'] = check_containers(root)
        if result['containers']['found']:
            self.findings.append({
                'severity': 'INFO',
                'title':    'ISE ISO: Podman Container Storage Present',
                'detail':   f"Images: {result['containers']['images'][:10]}",
            })

        # Binary analysis — Java JARs, ELF, Python creds
        result['binaries'] = scan_ise_binaries(root)
        for f in result['binaries'].get('java_findings', []):
            self.findings.append({
                'severity': f.get('severity', 'HIGH'),
                'title':    f"ISE ISO: Java Finding in {f.get('jar', '?')}",
                'detail':   str(f)[:200],
            })
        for f in result['binaries'].get('elf_findings', []):
            self.findings.append({
                'severity': f.get('severity', 'MEDIUM'),
                'title':    f"ISE ISO: ELF {f.get('binary','?')} — {', '.join(f.get('issues',[]))}",
                'detail':   'Binary hardening gap in ISE C/C++ service layer',
            })
        if result['binaries'].get('python_creds'):
            self.findings.append({
                'severity': 'CRITICAL',
                'title':    f"ISE ISO: Hardcoded Credentials in Python ({len(result['binaries']['python_creds'])} matches)",
                'detail':   str(result['binaries']['python_creds'][:5])[:300],
            })

        result['findings'] = self.findings
        return result


# ---------------------------------------------------------------------------
# Standalone extraction without mount (isoinfo-based, no root needed)
# ---------------------------------------------------------------------------

def analyze_iso_no_root(iso_path: str) -> dict:
    """
    Extract key files from ISO using isoinfo (no root/mount required).
    Slower and path-sensitive but works unprivileged.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix='ise_nf_'))
    result = {'method': 'isoinfo', 'files': {}, 'shadow': [], 'findings': []}

    targets = {
        '/ETC/SHADOW':          ISE_SHADOW_PATH,
        '/ETC/PASSWD':          ISE_PASSWD_PATH,
        '/ETC/SELINUX/CONFIG':  ISE_SELINUX_PATH,
    }

    for iso_fn, local_rel in targets.items():
        dest = str(tmpdir / local_rel)
        if _isoinfo_extract(iso_path, iso_fn, dest):
            result['files'][local_rel] = dest

    root = tmpdir
    if (root / ISE_SHADOW_PATH).exists():
        result['shadow'] = extract_shadow(root)
        for e in result['shadow']:
            sev = 'CRITICAL' if e['user'] == 'root' else 'HIGH'
            result['findings'].append({
                'severity': sev,
                'title':    f"ISE ISO: Hash ({e['user']})",
                'detail':   f"{e['hash']} — {e['hash_id']['cmd']}",
            })

    return result


# ---------------------------------------------------------------------------
# Live network probes — TrustSec SXP / ERS identity store / TC-NAC / Syslog
# ---------------------------------------------------------------------------

def probe_ise_sxp_peer(host: str, port: int = 64999, timeout: float = 5.0) -> list:
    """
    Probe ISE SXP (TrustSec SGT-to-IP mapping exchange) on TCP/64999.

    Sends an SXP Open message (8-byte header + 16-byte Connection-Mode TLV)
    and checks whether the peer completes the handshake without authentication.
    An SXP protocol response indicates unauthenticated SGT-IP binding table access.
    """
    findings = []
    sxp_response = False
    tcp_open = False

    # SXP Open message layout (SXP v4, RFC-draft-smith-sxp):
    #   Header [4B total_length][2B version=4][2B type=1(OPEN)]       = 8 bytes
    #   TLV    [4B type=3(Connection-Mode)][4B len=16][4B mode=3(both)][4B reserved] = 16 bytes
    #   Total  = 24 bytes
    hdr = struct.pack(">IHH", 24, 4, 1)
    tlv = struct.pack(">IIII", 3, 16, 3, 0)
    open_msg = hdr + tlv

    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            tcp_open = True
            s.sendall(open_msg)
            s.settimeout(timeout)
            try:
                resp = s.recv(64)
                if len(resp) >= 8:
                    r_len, r_ver, r_type = struct.unpack(">IHH", resp[:8])
                    # Valid SXP versions 1-4, message types 1-5
                    if r_ver in (1, 2, 3, 4) and r_type in (1, 2, 3, 4, 5):
                        sxp_response = True
            except (socket.timeout, OSError):
                pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        return findings

    if sxp_response:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'SXP_PEER_OPEN_UNAUTH — SGT-IP mappings exposed',
            'detail':   (
                f'SXP peer exchange accepted on {host}:{port} without authentication. '
                'Unauthenticated SXP Open handshake completed — SGT-to-IP binding table '
                'readable. TrustSec policy bypass and full lateral-movement map exposed.'
            ),
            'host': host,
            'port': port,
        })
    elif tcp_open:
        findings.append({
            'severity': 'HIGH',
            'title':    'SXP_PORT_OPEN — TrustSec mapping service reachable',
            'detail':   (
                f'TCP/{port} accepted connection on {host} but returned no SXP protocol '
                'response. TrustSec SXP service surface reachable; auth posture unconfirmed.'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_ise_rest_id_store(host: str, port: int = 9060, timeout: float = 5.0) -> list:
    """
    Probe ISE External RESTful Services (ERS) API on HTTPS/9060.

    Tests identity store sequences, identity groups, authorization profiles,
    and Active Directory join config for unauthenticated read access.
    ERS API requires explicit enablement; when left open it exposes the full
    policy model without credentials.
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    endpoints = [
        (
            '/ers/config/idstoresequence',
            'CRITICAL',
            'ISE_ID_STORE_SEQUENCE_UNAUTH — identity store sequence readable',
            'Authentication order (AD / LDAP / local DB) readable without credentials. '
            'Maps the full auth-bypass surface; sequence manipulation enables policy '
            'subversion by forcing weaker identity stores.',
        ),
        (
            '/ers/config/identitygroup',
            'HIGH',
            'ISE_IDENTITY_GROUPS_READABLE — group membership enumerable',
            'Identity group memberships readable unauthenticated. '
            'Enables targeted privilege-group identification prior to credential attack.',
        ),
        (
            '/ers/config/authorizationprofile',
            'CRITICAL',
            'ISE_AUTHZ_PROFILES_UNAUTH — policy bypass map exposed',
            'Authorization profiles (VLAN assignments, dACL names, SGT tags) readable '
            'without credentials. Full policy bypass map — discloses the authorization '
            'outcome for every identity class on the network.',
        ),
        (
            '/ers/config/activedirectory',
            'HIGH',
            'ISE_AD_JOIN_CONFIG_READABLE — AD integration config exposed',
            'Active Directory join points and domain config readable unauthenticated. '
            'Exposes domain names, join account references, and AD probe settings.',
        ),
    ]

    for path, severity, title, detail in endpoints:
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json', 'Connection': 'close'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(512)
                if resp.status in (200, 206) and body:
                    findings.append({
                        'severity': severity,
                        'title':    title,
                        'detail':   detail,
                        'host':     host,
                        'port':     port,
                    })
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                pass  # unexpected HTTP error — surface open, auth posture unclear
        except (urllib.error.URLError, OSError, TimeoutError):
            pass

    return findings


def probe_ise_threat_centric_nac(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Probe ISE Threat-Centric NAC (TC-NAC) Open API endpoints on HTTPS/443.

    Checks vulnerability data, threat feed, and passive DAC policy for
    unauthenticated read access.  TC-NAC integrates AMP/Rapid Threat
    Containment; unauth reads expose the full endpoint threat posture.
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    endpoints = [
        (
            '/api/v1/threat/vulnerabilities',
            'CRITICAL',
            'ISE_VULN_DATA_UNAUTH — endpoint vulnerability list exposed',
            'TC-NAC vulnerability data readable without authentication. '
            'Full endpoint CVE/CVSS posture disclosed — enables targeted exploitation '
            'of the weakest devices on the segment before containment triggers.',
        ),
        (
            '/api/v1/threat/feed',
            'HIGH',
            'ISE_THREAT_FEED_READABLE — threat intelligence feed accessible',
            'ISE threat feed config readable unauthenticated. '
            'Discloses active threat correlation rules and IOC subscription parameters.',
        ),
        (
            '/api/v1/pasive/dac',
            'HIGH',
            'ISE_DAC_POLICY_UNAUTH — dynamic access control policy readable',
            'Passive DAC policy readable without credentials. '
            'Maps network segmentation rules and exception-handling logic for bypass.',
        ),
    ]

    for path, severity, title, detail in endpoints:
        url = f'https://{host}:{port}{path}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json', 'Connection': 'close'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(512)
                if resp.status in (200, 206) and body:
                    findings.append({
                        'severity': severity,
                        'title':    title,
                        'detail':   detail,
                        'host':     host,
                        'port':     port,
                    })
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                pass
        except (urllib.error.URLError, OSError, TimeoutError):
            pass

    return findings


def probe_ise_syslog_export(host: str, port: int = 514, timeout: float = 5.0) -> list:
    """
    Probe ISE syslog export surface: UDP/514 (RFC 5424), TCP/514 (RFC 6587),
    and the ISE Open API remote-syslog configuration endpoint.

    A live UDP or TCP port indicates the ISE log-export path is reachable from
    the probe host.  An unauth read of the syslog config endpoint discloses
    SIEM destinations and transport settings.
    """
    findings = []

    # RFC 5424 test message (PRI=134 = facility:16 local0, severity:6 informational)
    syslog_probe = (
        b'<134>1 2000-01-01T00:00:00Z ise-probe ise-iso 0 - - '
        b'ISE-audit-probe'
    )

    # UDP/514 — RFC 5424 datagram
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(syslog_probe, (host, port))
            try:
                data, _ = s.recvfrom(512)
                if data:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title':    'SYSLOG_PORT_OPEN — ISE logs exportable (UDP)',
                        'detail':   (
                            f'UDP/{port} on {host} returned data in response to '
                            'RFC 5424 syslog probe. Bidirectional UDP syslog confirmed; '
                            'ISE audit log stream reachable from probe position.'
                        ),
                        'host': host,
                        'port': port,
                    })
            except socket.timeout:
                pass
    except OSError:
        pass

    # TCP/514 — RFC 6587 reliable syslog (octet-count framing)
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            framed = b'47 ' + syslog_probe   # octet-count SP syslog-msg
            s.sendall(framed)
            findings.append({
                'severity': 'MEDIUM',
                'title':    'SYSLOG_TCP_OPEN — reliable syslog port accepts connections',
                'detail':   (
                    f'TCP/{port} on {host} accepted connection. '
                    'Reliable syslog (RFC 6587) export surface reachable — '
                    'log stream interception or injection possible on path.'
                ),
                'host': host,
                'port': port,
            })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    # ISE Open API — remote syslog configuration (always probes port 443)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    api_url = f'https://{host}:443/api/v1/config/remotesyslog'
    req = urllib.request.Request(
        api_url,
        headers={'Accept': 'application/json', 'Connection': 'close'},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(512)
            if resp.status in (200, 206) and body:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_SYSLOG_CONFIG_READABLE — SIEM targets disclosed',
                    'detail':   (
                        f'GET /api/v1/config/remotesyslog on {host}:443 returned data '
                        'without authentication. SIEM destinations, log categories, and '
                        'transport config exposed — maps the log-export architecture.'
                    ),
                    'host': host,
                    'port': 443,
                })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    return findings


def probe_ise_byod_portal(host: str, port: int = 8443, timeout: float = 10.0) -> list:
    """
    Probe ISE BYOD enrollment and device registration surfaces on HTTPS/8443.

    Checks the BYOD self-service portal, device registration API, and ERS
    endpoint list for unauthenticated access.  ISE BYOD relies on a guest
    portal flow (PortalSetup.action) backed by the Open API and ERS; when
    misconfigured the enrollment surface is reachable without credentials and
    the full registered-device inventory — including MAC addresses — becomes
    readable.  Port 8443 is the default ISE portal listener; ERS lives on 9060
    but the endpoint list is also reachable via 8443 in some deployments.
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # --- BYOD portal page ---------------------------------------------------
    byod_url = f'https://{host}:{port}/portal/PortalSetup.action?portal=byod'
    req = urllib.request.Request(
        byod_url,
        headers={'Accept': 'text/html,application/xhtml+xml', 'Connection': 'close'},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(1024)
            if resp.status in (200, 206) and body:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_BYOD_PORTAL_EXPOSED — BYOD enrollment surface',
                    'detail':   (
                        f'GET /portal/PortalSetup.action?portal=byod on {host}:{port} '
                        'returned content without authentication. BYOD self-service '
                        'enrollment portal reachable unauthenticated — enables device '
                        'registration by arbitrary users and potential portal abuse.'
                    ),
                    'host': host,
                    'port': port,
                })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # --- Device registration API --------------------------------------------
    dreg_url = f'https://{host}:{port}/api/v1/endpoint/deviceRegistrationPortal'
    req = urllib.request.Request(
        dreg_url,
        headers={'Accept': 'application/json', 'Connection': 'close'},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(512)
            if resp.status in (200, 206) and body:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_DEVICE_REG_API_UNAUTH',
                    'detail':   (
                        f'GET /api/v1/endpoint/deviceRegistrationPortal on {host}:{port} '
                        'returned data without credentials. Device registration API '
                        'accessible unauthenticated — permits enumeration of portal '
                        'config, registration workflows, and enrolled device state.'
                    ),
                    'host': host,
                    'port': port,
                })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # --- ERS endpoint list (via port 8443 fallback) -------------------------
    ers_url = f'https://{host}:{port}/ers/config/endpoint'
    req = urllib.request.Request(
        ers_url,
        headers={'Accept': 'application/json', 'Connection': 'close'},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192)
            if resp.status in (200, 206) and body:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_ERS_ENDPOINT_LIST_UNAUTH — all registered devices visible',
                    'detail':   (
                        f'GET /ers/config/endpoint on {host}:{port} returned data '
                        'without authentication. Full registered-device inventory '
                        'readable — discloses identity store, policy assignment, and '
                        'device classification for every NAC-enrolled endpoint.'
                    ),
                    'host': host,
                    'port': port,
                })

                # MAC address enumeration secondary check
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    data = {}

                body_str = body.decode('utf-8', errors='replace').lower()
                if '"mac"' in body_str or '"macaddress"' in body_str:
                    # count occurrences of mac field as rough endpoint count
                    count = body_str.count('"mac"') + body_str.count('"macaddress"')
                    findings.append({
                        'severity': 'HIGH',
                        'title':    (
                            f'DEVICE_MAC_ADDRESSES_EXPOSED — {count} endpoints'
                        ),
                        'detail':   (
                            f'ERS /ers/config/endpoint response on {host}:{port} contains '
                            f'MAC address fields ({count} occurrences in sampled body). '
                            'Hardware identifiers for registered endpoints are readable '
                            'unauthenticated — enables targeted device impersonation and '
                            'MAC-bypass attacks against NAC policy.'
                        ),
                        'host': host,
                        'port': port,
                    })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    return findings


def probe_ise_profiling_policy(host: str, port: int = 9060, timeout: float = 10.0) -> list:
    """
    Probe ISE device profiling and network access policy surfaces on HTTPS/9060.

    Checks ERS profiling policy and profiler profile endpoints, and the Open
    API policy-set endpoint, for unauthenticated read access.  ISE profiling
    uses DHCP, HTTP, RADIUS, SNMP, and NetFlow probes to classify endpoints;
    when the policy and profile config is readable without credentials an
    attacker learns the exact fingerprinting rules and can craft traffic that
    misclassifies a device into a less-restricted policy bucket.  The
    network-access policy-set endpoint discloses the full authorization logic
    tree including condition expressions and rule ordering.
    """
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # --- ERS profiling policy -----------------------------------------------
    pp_url = f'https://{host}:{port}/ers/config/profilepolicy'
    req = urllib.request.Request(
        pp_url,
        headers={'Accept': 'application/json', 'Connection': 'close'},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096)
            if resp.status in (200, 206) and body:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_PROFILING_POLICY_UNAUTH — fingerprint rules exposed',
                    'detail':   (
                        f'GET /ers/config/profilepolicy on {host}:{port} returned data '
                        'without authentication. Device profiling policy (DHCP class IDs, '
                        'HTTP user-agent patterns, RADIUS attributes) readable — exposes '
                        'the fingerprint ruleset enabling targeted evasion of device '
                        'classification and NAC policy assignment.'
                    ),
                    'host': host,
                    'port': port,
                })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # --- ERS profiler profile list ------------------------------------------
    pprofile_url = f'https://{host}:{port}/ers/config/profilerprofile'
    req = urllib.request.Request(
        pprofile_url,
        headers={'Accept': 'application/json', 'Connection': 'close'},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096)
            if resp.status in (200, 206) and body:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ISE_PROFILER_PROFILES_UNAUTH',
                    'detail':   (
                        f'GET /ers/config/profilerprofile on {host}:{port} returned data '
                        'without authentication. Profiler endpoint profile definitions '
                        'readable — discloses device taxonomy, classification certainty '
                        'thresholds, and probe assignment per endpoint category.'
                    ),
                    'host': host,
                    'port': port,
                })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # --- Open API network-access policy-set ---------------------------------
    # This endpoint lives on port 443; probe it unconditionally regardless of
    # the caller-supplied port since policy-set is an Open API path.
    ps_url = f'https://{host}:443/api/v1/policy/network-access/policy-set'
    req = urllib.request.Request(
        ps_url,
        headers={'Accept': 'application/json', 'Connection': 'close'},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(16384)
            if resp.status in (200, 206) and body:
                body_str = body.decode('utf-8', errors='replace')

                # count rules/conditions disclosed
                rule_count = body_str.lower().count('"condition"') + body_str.lower().count('"rule"')

                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ISE_POLICY_SET_UNAUTH — auth policy logic exposed',
                    'detail':   (
                        f'GET /api/v1/policy/network-access/policy-set on {host}:443 '
                        f'returned data without authentication ({rule_count} rule/condition '
                        'references in sampled body). Full network access policy-set tree '
                        'readable — discloses authentication policy order, authorization '
                        'condition expressions, and exception rules enabling precise '
                        'bypass construction without internal access.'
                    ),
                    'host': host,
                    'port': 443,
                })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    return findings


def probe_activemq_exposure(host: str, port: int = 8161, timeout: float = 10.0) -> list:
    """Probe ActiveMQ broker for default credentials, Jolokia JMX, queue list, and OpenWire port."""
    import urllib.request
    import urllib.error
    import socket
    import ssl

    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = f'http://{host}:{port}'

    # --- admin console with default creds (admin:admin) ----------------------
    import base64 as _b64
    _creds = _b64.b64encode(b'admin:admin').decode()
    admin_req = urllib.request.Request(
        f'{base}/admin/',
        headers={
            'Authorization': f'Basic {_creds}',
            'Accept': 'text/html',
            'Connection': 'close',
        },
    )
    try:
        with urllib.request.urlopen(admin_req, timeout=timeout) as resp:
            body = resp.read(4096).decode('utf-8', errors='replace')
            if resp.status == 200 and ('ActiveMQ' in body or 'queue' in body.lower()):
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ACTIVEMQ_DEFAULT_CREDS — ActiveMQ admin console accessible with default credentials (admin:admin)',
                    'detail':   (
                        f'GET {base}/admin/ with Authorization: Basic admin:admin returned HTTP 200. '
                        'ActiveMQ web console is reachable with vendor default credentials, granting '
                        'full broker management access including queue creation, message injection, '
                        'consumer enumeration, and network topology disclosure.'
                    ),
                    'host': host,
                    'port': port,
                })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403, 404):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # --- Jolokia JMX API (unauthenticated) ------------------------------------
    jolokia_url = (
        f'{base}/api/jolokia/read/'
        'org.apache.activemq:type=Broker,brokerName=localhost/TotalConsumerCount'
    )
    jolokia_req = urllib.request.Request(
        jolokia_url,
        headers={'Accept': 'application/json', 'Connection': 'close'},
    )
    try:
        with urllib.request.urlopen(jolokia_req, timeout=timeout) as resp:
            body = resp.read(4096).decode('utf-8', errors='replace')
            if resp.status == 200 and ('value' in body or 'TotalConsumerCount' in body):
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ACTIVEMQ_JMX_JOLOKIA_UNAUTH — ActiveMQ JMX Jolokia API accessible (broker stats and management)',
                    'detail':   (
                        f'GET {jolokia_url} returned HTTP 200 without authentication. '
                        'Jolokia bridges JMX over HTTP; unauthenticated access exposes broker '
                        'metrics, consumer counts, queue depths, and management operations '
                        'including message purging and consumer disconnection.'
                    ),
                    'host': host,
                    'port': port,
                })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403, 404):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # --- queue list (unauthenticated) -----------------------------------------
    queues_req = urllib.request.Request(
        f'{base}/admin/queues.jsp',
        headers={'Accept': 'text/html', 'Connection': 'close'},
    )
    try:
        with urllib.request.urlopen(queues_req, timeout=timeout) as resp:
            body = resp.read(8192).decode('utf-8', errors='replace')
            if resp.status == 200 and ('queue' in body.lower() or 'Queue' in body):
                q_count = body.lower().count('<td') // 4  # rough row estimate
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ACTIVEMQ_QUEUES_UNAUTH — ActiveMQ message queue list accessible',
                    'detail':   (
                        f'GET {base}/admin/queues.jsp returned HTTP 200 without authentication '
                        f'(~{q_count} table rows). Full queue inventory including names, '
                        'pending message counts, consumer counts, and enqueue/dequeue rates '
                        'is readable, enabling targeted message interception or injection.'
                    ),
                    'host': host,
                    'port': port,
                })
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403, 404):
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # --- OpenWire port (61616) ------------------------------------------------
    openwire_port = 61616
    try:
        with socket.create_connection((host, openwire_port), timeout=timeout) as s:
            # read banner — ActiveMQ sends an OpenWire WIREFORMAT_INFO on connect
            s.settimeout(timeout)
            banner = s.recv(256)
            if banner:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ACTIVEMQ_OPENWIRE_EXPOSED — ActiveMQ OpenWire messaging port accessible',
                    'detail':   (
                        f'TCP connect to {host}:{openwire_port} succeeded and broker returned '
                        f'{len(banner)}-byte OpenWire banner. Direct broker access enables '
                        'message production/consumption, queue enumeration, and potential '
                        'deserialization exploitation (CVE-2023-46604 and variants).'
                    ),
                    'host': host,
                    'port': openwire_port,
                })
    except (OSError, TimeoutError, ConnectionRefusedError):
        pass

    return findings


def probe_zeromq_exposure(host: str, port: int = 5555, timeout: float = 5.0) -> list:
    """Probe ZeroMQ socket for unauthenticated ZMTP access and NULL security mechanism."""
    import socket
    import struct

    findings = []

    # ZMTP/3.0 greeting: 0xff + 8 zero bytes + 0x7f (signature)
    ZMTP_GREETING = b'\xff\x00\x00\x00\x00\x00\x00\x00\x00\x7f'

    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(ZMTP_GREETING)
            try:
                response = s.recv(64)
            except (OSError, TimeoutError):
                response = b''

            if not response:
                return findings

            # ZMTP greeting reply starts with 0xff
            if response[0:1] == b'\xff':
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ZEROMQ_ZMTP_EXPOSED — ZeroMQ ZMTP socket accessible without authentication',
                    'detail':   (
                        f'TCP connect to {host}:{port} and ZMTP/3.0 greeting exchange succeeded. '
                        f'Server replied with {len(response)}-byte ZMTP response (first byte 0xff). '
                        'The ZeroMQ socket is publicly reachable and responds to the protocol '
                        'handshake, enabling message interception, injection, or pattern analysis.'
                    ),
                    'host': host,
                    'port': port,
                })

                # NULL mechanism check: bytes 11-14 of the full greeting encode the mechanism
                # Full ZMTP/3.0 greeting is 64 bytes; mechanism occupies bytes 12-31 (20 bytes, space-padded)
                if len(response) >= 32:
                    # mechanism field starts at offset 12 in the 64-byte greeting frame
                    mechanism_raw = response[12:32] if len(response) >= 32 else b''
                    mechanism = mechanism_raw.rstrip(b'\x00').decode('ascii', errors='replace').strip()
                    if mechanism.upper() in ('NULL', '') or mechanism_raw == b'\x00' * len(mechanism_raw):
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'ZEROMQ_NULL_MECHANISM — ZeroMQ using NULL security mechanism (no authentication)',
                            'detail':   (
                                f'ZMTP/3.0 greeting from {host}:{port} indicates NULL security '
                                f'mechanism (mechanism field: {mechanism!r}). NULL mechanism '
                                'disables all authentication and encryption; any client can '
                                'connect and exchange messages without credentials or identity '
                                'verification, exposing all transported data.'
                            ),
                            'host': host,
                            'port': port,
                        })
    except (OSError, TimeoutError, ConnectionRefusedError):
        pass

    return findings


def probe_opcua_exposure(host: str, port: int = 4840, timeout: float = 5.0) -> list:
    """Probe OPC-UA industrial automation port and protocol handshake."""
    import socket
    import struct

    findings = []

    # Phase 1: TCP connect to port 4840
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except (OSError, TimeoutError, ConnectionRefusedError):
        return findings

    findings.append({
        'severity': 'HIGH',
        'title':    'OPCUA_PORT_OPEN — OPC Unified Architecture industrial automation port accessible',
        'detail':   (
            f'TCP connect to {host}:{port} succeeded. Port 4840 is the IANA-registered '
            'OPC-UA (Unified Architecture) port used by industrial automation systems '
            'including PLCs, DCS controllers, SCADA servers, and HMI gateways. '
            'An accessible OPC-UA port indicates an industrial control system endpoint '
            'reachable from this network segment.'
        ),
        'host': host,
        'port': port,
    })

    # Phase 2: OPC-UA Hello (HEL) message
    # Structure: MessageType(3) + Reserved(1) + MessageSize(4) + Version(4) +
    #            ReceiveBufSize(4) + SendBufSize(4) + MaxMsgSize(4) + MaxChunkCount(4) +
    #            EndpointURL length-prefixed string
    try:
        endpoint_url = f'opc.tcp://{host}:{port}'.encode('utf-8')
        endpoint_len = len(endpoint_url)
        # HEL\x46 = HEL + 'F' (chunk type Final, single message)
        msg_size = 28 + 4 + endpoint_len  # header(8) + fixed fields(20) + url_len(4) + url
        hel = (
            b'HEL\x46'                          # MessageType + ChunkType
            + struct.pack('<I', msg_size)        # MessageSize
            + struct.pack('<I', 0)               # Version
            + struct.pack('<I', 65536)           # ReceiveBufferSize
            + struct.pack('<I', 65536)           # SendBufferSize
            + struct.pack('<I', 0)               # MaxMessageSize (0 = unlimited)
            + struct.pack('<I', 0)               # MaxChunkCount (0 = unlimited)
            + struct.pack('<I', endpoint_len)    # EndpointURL length prefix
            + endpoint_url                       # EndpointURL
        )
        sock.sendall(hel)
        response = sock.recv(1024)

        if response and response[:3] == b'ACK':
            findings.append({
                'severity': 'CRITICAL',
                'title':    'OPCUA_HELLO_ACK — OPC-UA server responding (industrial automation control system accessible)',
                'detail':   (
                    f'OPC-UA server at {host}:{port} responded with ACK to HEL handshake '
                    f'({len(response)}-byte response). An ACK confirms a live OPC-UA server '
                    'accepting connections. OPC-UA servers expose process data, alarms, '
                    'historical records, and — without authentication — allow reading and '
                    'writing process variables directly on PLCs, DCS, or SCADA endpoints.'
                ),
                'host': host,
                'port': port,
            })

            # Phase 3: OpenSecureChannel with SecurityMode=None
            # Minimal OpenSecureChannel request (binary protocol, SecurityMode=1=None)
            # RequestedLifetime=600000ms, SecurityPolicyURI=None
            security_policy_uri = b'http://opcfoundation.org/UA/SecurityPolicy#None'
            sp_len = len(security_policy_uri)
            # OpenSecureChannel body (simplified, no sender cert or thumbprint)
            osc_body = (
                struct.pack('<I', 0)          # ClientProtocolVersion
                + struct.pack('<I', 0)        # RequestType=Issue(0)
                + struct.pack('<I', 1)        # SecurityMode=None(1)
                + struct.pack('<I', sp_len)   # SecurityPolicyURI length
                + security_policy_uri         # SecurityPolicyURI
                + struct.pack('<I', 0xFFFFFFFF)  # SenderCertificate (null, -1)
                + struct.pack('<I', 0xFFFFFFFF)  # ReceiverCertificateThumbprint (null, -1)
                + struct.pack('<I', 600000)   # RequestedLifetime
            )
            # OPN message header: OPN\x46 + size(4) + SecureChannelId(4) + SecurityHeaderLen(4) + body
            osc_inner = (
                struct.pack('<I', 0)              # SecureChannelId=0 (new channel)
                + struct.pack('<I', len(osc_body))
                + osc_body
            )
            osc_size = 8 + len(osc_inner)
            osc_msg = b'OPN\x46' + struct.pack('<I', osc_size) + osc_inner

            try:
                sock.sendall(osc_msg)
                osc_response = sock.recv(4096)

                if osc_response and len(osc_response) >= 12:
                    # SecureChannelId is at byte offset 8 in the OPN response
                    channel_id = struct.unpack('<I', osc_response[8:12])[0]
                    if channel_id > 0:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'OPCUA_NO_SECURITY — OPC-UA connection without message security (industrial data readable/writable)',
                            'detail':   (
                                f'OPC-UA server at {host}:{port} accepted OpenSecureChannel '
                                f'with SecurityMode=None (channel ID {channel_id}). '
                                'SecurityMode=None disables message signing and encryption; '
                                'all OPC-UA traffic (process values, alarms, method calls) '
                                'is transmitted in cleartext and is subject to interception '
                                'and injection by any network-adjacent attacker. An attacker '
                                'with channel access can read sensor data, write setpoints, '
                                'invoke control methods, and potentially cause unsafe process states.'
                            ),
                            'host': host,
                            'port': port,
                        })
            except (OSError, TimeoutError):
                pass
    except (OSError, TimeoutError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return findings


def probe_ics_firmware_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Probe ICS device web interface for unauthenticated information and firmware exposure."""
    import urllib.request
    import urllib.error

    findings = []

    # ICS vendor signature patterns for web interface detection
    ics_vendor_patterns = [
        # Siemens
        b'SIMATIC', b'Siemens', b'S7-', b'SCALANCE', b'SINEMA', b'WinCC',
        # Schneider Electric
        b'Schneider', b'Modicon', b'EcoStruxure', b'PowerLogic', b'APC',
        # ABB
        b'ABB', b'AC500', b'Ability', b'800xA',
        # Rockwell / Allen-Bradley
        b'Rockwell', b'Allen-Bradley', b'ControlLogix', b'CompactLogix',
        b'FactoryTalk', b'RSLinx',
        # GE / GE Digital
        b'GE Automation', b'GE Digital', b'Proficy', b'iFIX', b'CIMPLICITY',
        # Honeywell
        b'Honeywell', b'Experion', b'PlantScape',
        # Generic ICS/SCADA web patterns
        b'SCADA', b'HMI', b'PLC', b'DCS', b'RTU', b'IED',
        b'industrial', b'Industrial', b'automation', b'Automation',
        b'controller', b'Controller',
    ]

    base_url = f'http://{host}:{port}'

    # Phase 1: Root page — detect ICS web management interface
    try:
        req = urllib.request.Request(
            base_url + '/',
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; ICS-Scanner/1.0)',
                'Accept': 'text/html,application/xhtml+xml,*/*',
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536)
            matched = [p.decode('utf-8', errors='replace') for p in ics_vendor_patterns if p in body]
            if matched:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'ICS_WEB_INTERFACE — ICS device web management interface accessible',
                    'detail':   (
                        f'HTTP GET {base_url}/ returned a response containing ICS/SCADA vendor '
                        f'or technology signatures: {matched[:5]}. '
                        'An accessible ICS web management interface may expose device '
                        'configuration, network topology, process data, alarm history, '
                        'and — if unauthenticated — direct control capabilities. '
                        'ICS web interfaces are frequently targeted for initial access '
                        'in OT/ICS intrusion campaigns.'
                    ),
                    'host': host,
                    'port': port,
                })
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # Phase 2: Device info endpoints — unauthenticated API exposure
    info_paths = ['/api/info', '/api/device', '/api/v1/info', '/api/v1/device',
                  '/device/info', '/cgi-bin/info', '/system/info']
    for path in info_paths:
        try:
            req = urllib.request.Request(
                base_url + path,
                headers={
                    'User-Agent': 'Mozilla/5.0 (compatible; ICS-Scanner/1.0)',
                    'Accept': 'application/json,text/html,*/*',
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read(8192)
                    # Accept JSON-like or XML-like responses with device data
                    content_type = resp.headers.get('Content-Type', '')
                    if body and (
                        b'{' in body or b'<' in body
                        or b'model' in body.lower() or b'firmware' in body.lower()
                        or b'serial' in body.lower() or b'version' in body.lower()
                    ):
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'ICS_DEVICE_INFO_UNAUTH — ICS device information accessible without authentication',
                            'detail':   (
                                f'HTTP GET {base_url}{path} returned HTTP 200 with device '
                                f'information ({len(body)} bytes, Content-Type: {content_type}). '
                                'Unauthenticated access to ICS device information exposes '
                                'model numbers, firmware versions, serial numbers, and network '
                                'configuration — intelligence that enables targeted exploitation, '
                                'CVE mapping, and supply-chain attack planning against the '
                                'operational technology environment.'
                            ),
                            'host': host,
                            'port': port,
                        })
                        break  # one confirmed finding per host is sufficient
        except (urllib.error.URLError, OSError, TimeoutError):
            continue

    # Phase 3: Firmware download paths
    firmware_paths = [
        '/firmware.bin', '/update.bin', '/firmware/firmware.bin',
        '/upgrade.bin', '/fw.bin', '/image.bin',
        '/firmware.tar', '/firmware.tar.gz',
    ]
    for path in firmware_paths:
        try:
            req = urllib.request.Request(
                base_url + path,
                headers={
                    'User-Agent': 'Mozilla/5.0 (compatible; ICS-Scanner/1.0)',
                    'Accept': '*/*',
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    content_type = resp.headers.get('Content-Type', '')
                    content_length = resp.headers.get('Content-Length', 'unknown')
                    # Peek at the first bytes to confirm binary content
                    peek = resp.read(16)
                    if peek and len(peek) >= 4:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'ICS_FIRMWARE_DOWNLOAD_UNAUTH — ICS firmware image accessible for download',
                            'detail':   (
                                f'HTTP GET {base_url}{path} returned HTTP 200 with binary '
                                f'content (first bytes: {peek[:8].hex()}, '
                                f'Content-Length: {content_length}, '
                                f'Content-Type: {content_type}). '
                                'Unauthenticated firmware download enables offline analysis '
                                'to extract hardcoded credentials, cryptographic keys, '
                                'and proprietary protocol implementations. Firmware images '
                                'are the primary attack surface for ICS supply-chain '
                                'implants and persistent backdoor installation.'
                            ),
                            'host': host,
                            'port': port,
                        })
                        break  # one confirmed finding per host is sufficient
        except (urllib.error.URLError, OSError, TimeoutError):
            continue

    return findings


def probe_upnp_exposure(host: str, port: int = 1900, timeout: float = 5.0) -> list:
    """
    Detect UPnP/SSDP exposure on IoT devices and network equipment.

    SSDP M-SEARCH → LOCATION header → device description XML → device identity
    extraction → IGD SOAP AddPortMapping firewall punch test → NAT-PMP probe →
    PCP probe.  Primary risk: unauthenticated IGD AddPortMapping allows an attacker
    to punch arbitrary holes in the device NAT/firewall (HD Moore 2013: 81M devices;
    Akamai UPnProxy 2017: 73 manufacturer stacks with NAT injection).
    """
    findings = []

    # ------------------------------------------------------------------
    # Phase 1: SSDP M-SEARCH discovery (UDP 1900)
    # ------------------------------------------------------------------
    ssdp_msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    location_url = None
    ssdp_raw = b''

    for ssdp_target in (host, '239.255.255.250'):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(timeout)
                sock.sendto(ssdp_msg, (ssdp_target, 1900))
                ssdp_raw, _ = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                pass
            finally:
                sock.close()
        except OSError:
            pass
        if ssdp_raw:
            break

    if ssdp_raw:
        findings.append({
            'severity': 'HIGH',
            'title':    'UPNP_SSDP_RESPONSIVE — UPnP SSDP responds to M-SEARCH without authentication',
            'detail':   (
                f'SSDP M-SEARCH received a response from {host}:{port}/UDP. '
                'UPnP SSDP requires no authentication — any LAN host can enumerate device '
                'capabilities, firmware version, and SOAP control URLs. '
                f'Response (first 256 bytes): {ssdp_raw[:256].decode(errors="replace")!r}'
            ),
            'host': host,
            'port': port,
        })
        loc_m = re.search(rb'(?i)LOCATION:\s*(\S+)', ssdp_raw)
        if loc_m:
            location_url = loc_m.group(1).decode(errors='replace').strip()
            findings.append({
                'severity': 'HIGH',
                'title':    'UPNP_DEVICE_DESCRIPTION_EXPOSED — SSDP response contains LOCATION URL',
                'detail':   (
                    f'SSDP response from {host} includes LOCATION: {location_url}. '
                    'The device description XML at this URL discloses model, manufacturer, '
                    'firmware version, and SOAP control URLs used in IGD port-mapping attacks '
                    'and UPnProxy NAT injection.'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Phase 2: Fetch device description XML
    # ------------------------------------------------------------------
    http_port = 80
    desc_xml = b''
    desc_url_used = None

    candidate_urls = []
    if location_url:
        candidate_urls.append(location_url)
    for path in ('/rootDesc.xml', '/device.xml', '/upnp/description.xml'):
        candidate_urls.append(f'http://{host}:{http_port}{path}')

    for url in candidate_urls:
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'UPnP/1.0 Scanner/1.0'},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    raw = resp.read(65536)
                    if raw and (b'<root' in raw or b'<device' in raw or b'xml' in raw):
                        desc_xml = raw
                        desc_url_used = url
                        ct = resp.headers.get('Content-Type', '')
                        findings.append({
                            'severity': 'HIGH',
                            'title':    'UPNP_DESCRIPTION_XML — Device description XML accessible unauthenticated',
                            'detail':   (
                                f'HTTP GET {url} returned HTTP 200 with a {len(raw)}-byte '
                                f'XML device description (Content-Type: {ct}). '
                                'XML exposes SOAP control URLs for AddPortMapping, '
                                'GetExternalIPAddress, and DeletePortMapping — all operable '
                                'without authentication per the UPnP specification.'
                            ),
                            'host': host,
                            'port': port,
                        })
                        break
        except (urllib.error.URLError, OSError, TimeoutError):
            continue

    # ------------------------------------------------------------------
    # Phase 3: Extract device identity fields from description XML
    # ------------------------------------------------------------------
    if desc_xml:
        info = {}
        for field in ('friendlyName', 'manufacturer', 'modelName', 'serialNumber'):
            m = re.search(
                rb'<' + field.encode() + rb'>\s*(.*?)\s*</' + field.encode() + rb'>',
                desc_xml,
                re.DOTALL,
            )
            if m:
                val = m.group(1).decode(errors='replace').strip()
                if val:
                    info[field] = val
        if info:
            info_str = '; '.join(f'{k}={v!r}' for k, v in info.items())
            findings.append({
                'severity': 'MEDIUM',
                'title':    'UPNP_DEVICE_INFO_DISCLOSED — Device identity exposed via description XML',
                'detail':   (
                    f'Description XML at {desc_url_used} discloses device identity: {info_str}. '
                    'Manufacturer and model enables targeted CVE selection, default-credential '
                    'lookup, and supply-chain attribution. serialNumber may constitute PII '
                    'exposure under GDPR/CCPA for consumer-deployed devices.'
                ),
                'host': host,
                'port': port,
            })

    # ------------------------------------------------------------------
    # Phase 4: IGD SOAP AddPortMapping — firewall punch test
    # ------------------------------------------------------------------
    soap_payload = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
        ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        '<s:Body>'
        '<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        '<NewRemoteHost></NewRemoteHost>'
        '<NewExternalPort>62345</NewExternalPort>'
        '<NewProtocol>TCP</NewProtocol>'
        '<NewInternalPort>62345</NewInternalPort>'
        f'<NewInternalClient>{host}</NewInternalClient>'
        '<NewEnabled>1</NewEnabled>'
        '<NewPortMappingDescription>probe</NewPortMappingDescription>'
        '<NewLeaseDuration>1</NewLeaseDuration>'
        '</u:AddPortMapping>'
        '</s:Body>'
        '</s:Envelope>'
    ).encode()

    ctrl_urls = []
    if desc_xml:
        cu_m = re.search(rb'<controlURL>\s*(.*?)\s*</controlURL>', desc_xml, re.DOTALL)
        if cu_m:
            cu = cu_m.group(1).decode(errors='replace').strip()
            if cu:
                ctrl_urls.append(
                    cu if cu.startswith('http') else f'http://{host}:{http_port}{cu}'
                )
    for p in ('/ctl/IPConn', '/ctl/WANIPConn', '/upnp/control/WANIPConn1'):
        ctrl_urls.append(f'http://{host}:{http_port}{p}')

    for ctrl_url in ctrl_urls:
        try:
            req = urllib.request.Request(
                ctrl_url,
                data=soap_payload,
                headers={
                    'Content-Type': 'text/xml; charset="utf-8"',
                    'SOAPAction':   '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
                    'User-Agent':   'UPnP/1.0 Scanner/1.0',
                },
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(4096)
                if resp.status in (200, 204) and b'errorCode' not in body:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'UPNP_IGD_PORT_MAPPING_OPEN — IGD AddPortMapping accepted without authentication',
                        'detail':   (
                            f'SOAP AddPortMapping POST to {ctrl_url} returned HTTP {resp.status} '
                            'with no authentication challenge or errorCode response. '
                            'An attacker can punch arbitrary holes in the NAT/firewall, '
                            'expose any internal service to the WAN, or create a proxy tunnel '
                            '(UPnProxy). HD Moore (2013) found 81M internet-facing UPnP devices; '
                            'Akamai (2017) confirmed NAT injection in 73 manufacturer stacks.'
                        ),
                        'host': host,
                        'port': port,
                    })
                    break
        except (urllib.error.URLError, OSError, TimeoutError):
            continue

    # ------------------------------------------------------------------
    # Phase 5: NAT-PMP version probe (RFC 6886, UDP 5351)
    # ------------------------------------------------------------------
    natpmp_port = 5351
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            natpmp_req = struct.pack('!BB', 0, 0)  # version=0, opcode=0 (external address)
            sock.sendto(natpmp_req, (host, natpmp_port))
            data, _ = sock.recvfrom(256)
            # NAT-PMP response: version=0, opcode byte=128 (response bit 0x80 set on opcode 0)
            if len(data) >= 4 and data[0] == 0 and data[1] == 128:
                result_code = struct.unpack('!H', data[2:4])[0]
                findings.append({
                    'severity': 'HIGH',
                    'title':    'NAT_PMP_EXPOSED — NAT-PMP responds to version request without authentication',
                    'detail':   (
                        f'NAT-PMP version request to {host}:{natpmp_port}/UDP received a '
                        f'valid version-0 response (result_code={result_code}). '
                        'NAT-PMP (RFC 6886) provides unauthenticated port mapping — '
                        'identical firewall bypass risk to UPnP IGD AddPortMapping. '
                        'RFC 6886 mandates LAN-only operation; internet exposure enables '
                        'arbitrary inbound port mappings from any remote attacker.'
                    ),
                    'host': host,
                    'port': natpmp_port,
                })
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
    except OSError:
        pass

    # ------------------------------------------------------------------
    # Phase 6: PCP MAP probe (RFC 6887, UDP 5351)
    # ------------------------------------------------------------------
    pcp_port = 5351
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            # Build IPv4-mapped IPv6 client address (::ffff:x.x.x.x) for PCP client IP field
            if '.' in host:
                try:
                    raw_ip = socket.inet_aton(host)
                    client_ip = b'\x00' * 10 + b'\xff\xff' + raw_ip
                except OSError:
                    client_ip = b'\x00' * 16
            else:
                client_ip = b'\x00' * 16
            # PCP MAP request: version=2, opcode=1 (MAP), reserved=0, lifetime=0, then client IP
            pcp_req = struct.pack('!BBHI', 2, 1, 0, 0) + client_ip  # 8 + 16 = 24 bytes
            sock.sendto(pcp_req, (host, pcp_port))
            data, _ = sock.recvfrom(256)
            # PCP response: version=2, opcode has R-bit (0x80) set
            if len(data) >= 4 and data[0] == 2 and (data[1] & 0x80):
                findings.append({
                    'severity': 'HIGH',
                    'title':    'PORT_CONTROL_PROTOCOL_EXPOSED — PCP service responds to MAP request',
                    'detail':   (
                        f'PCP MAP request to {host}:{pcp_port}/UDP received a version-2 '
                        'response (R-bit set in opcode byte). Port Control Protocol (RFC 6887) '
                        'supersedes NAT-PMP and provides unauthenticated firewall mapping on '
                        'the same port. Exposure enables inbound port-mapping creation, '
                        'external IP disclosure, and NAT bypass without any authentication.'
                    ),
                    'host': host,
                    'port': pcp_port,
                })
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
    except OSError:
        pass

    return findings


def probe_telnet_and_serial_console(host: str, port: int = 23, timeout: float = 5.0) -> list:
    """
    Detect telnet and serial-console-over-IP exposure on IoT and network devices.

    Probes standard and alternative telnet ports for open access, banner leakage,
    and login prompt exposure.  Tests Mirai-class default credentials (admin/admin,
    root/root, etc.) via full telnet IAC negotiation.  Checks serial-to-IP adapters
    (Digi port 4001, generic 5000/7000, Cisco console 4000) and Lantronix Device
    Server (port 9999) — physical console access vectors that bypass OS-level
    authentication and are primary targets for persistent post-compromise access.
    """
    findings = []

    # ------------------------------------------------------------------
    # Telnet IAC helpers
    # ------------------------------------------------------------------
    def _strip_iac(raw: bytes) -> bytes:
        """Return bytes with IAC WILL/WONT/DO/DONT 3-byte sequences removed."""
        out = []
        i = 0
        while i < len(raw):
            if raw[i] == 0xFF:  # IAC
                i += 1
                if i < len(raw):
                    cmd = raw[i]
                    i += 1
                    if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i < len(raw):
                        i += 1  # skip option byte
            else:
                out.append(raw[i])
                i += 1
        return bytes(out)

    def _respond_iac(sock, raw: bytes) -> None:
        """Respond WONT/DONT to server-sent DO/WILL option requests."""
        i = 0
        while i < len(raw):
            if raw[i] == 0xFF and i + 2 < len(raw):
                cmd = raw[i + 1]
                opt = raw[i + 2]
                try:
                    if cmd == 0xFD:     # DO   → reply WONT (0xFC)
                        sock.sendall(bytes([0xFF, 0xFC, opt]))
                    elif cmd == 0xFB:   # WILL → reply DONT (0xFE)
                        sock.sendall(bytes([0xFF, 0xFE, opt]))
                except OSError:
                    break
                i += 3
            else:
                i += 1

    def _recv_all(sock, max_bytes: int = 2048) -> bytes:
        """Read until timeout, EOF, or max_bytes; return raw bytes."""
        buf = b''
        try:
            while len(buf) < max_bytes:
                chunk = sock.recv(256)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, OSError):
            pass
        return buf

    # ------------------------------------------------------------------
    # Phase 1: Standard and alternative telnet ports
    # ------------------------------------------------------------------
    telnet_ports = [port]
    for alt in (2323, 24, 992):
        if alt != port:
            telnet_ports.append(alt)

    DEFAULT_CREDS = [
        (b'admin', b'admin'),
        (b'admin', b'password'),
        (b'admin', b''),
        (b'root',  b'root'),
        (b'root',  b'password'),
        (b'root',  b''),
        (b'',      b''),
        (b'user',  b'user'),
        (b'admin', b'1234'),
        (b'root',  b'admin'),
    ]

    login_re   = re.compile(rb'(?i)(login\s*:|username\s*:|user\s*name\s*:|password\s*:|enter\s+password)')
    shell_re   = re.compile(rb'[\$#>]\s*$')
    autherr_re = re.compile(rb'(?i)(incorrect|invalid|failed|denied|wrong|bad password)')

    for t_port in telnet_ports:
        try:
            sock = socket.create_connection((host, t_port), timeout=timeout)
        except (ConnectionRefusedError, socket.timeout, OSError):
            continue

        port_label = 'TELNET_PORT_OPEN' if t_port == port else 'ALTERNATIVE_TELNET_PORT'
        findings.append({
            'severity': 'HIGH',
            'title':    f'{port_label} — Telnet service reachable on {t_port}/TCP',
            'detail':   (
                f'TCP/{t_port} accepted connection on {host}. Telnet transmits credentials '
                'and all session data in cleartext. This is the primary Mirai botnet '
                'propagation vector — Mirai compromised 600 000+ devices via default '
                'credentials on exactly this surface. NIST SP 800-41 and CIS Benchmarks '
                'prohibit telnet on managed devices.'
            ),
            'host': host,
            'port': t_port,
        })

        sock.settimeout(timeout)
        banner_raw = _recv_all(sock, 2048)
        _respond_iac(sock, banner_raw)
        banner_clean = _strip_iac(banner_raw)

        if banner_clean and login_re.search(banner_clean):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'TELNET_LOGIN_PROMPT_EXPOSED — Telnet login prompt accessible',
                'detail':   (
                    f'Telnet on {host}:{t_port} presented a login prompt: '
                    f'{banner_clean[:200].decode(errors="replace")!r}. '
                    'A reachable login prompt enables systematic default-credential '
                    'and brute-force attacks. Mirai propagation begins at this prompt.'
                ),
                'host': host,
                'port': t_port,
            })

        # Default credential test — open a fresh connection per credential pair
        cred_found = False
        for uname, passwd in DEFAULT_CREDS:
            if cred_found:
                break
            try:
                ts = socket.create_connection((host, t_port), timeout=timeout)
                try:
                    ts.settimeout(timeout)
                    init_raw = _recv_all(ts, 1024)
                    _respond_iac(ts, init_raw)
                    ts.sendall(uname + b'\r\n')
                    ts.settimeout(min(timeout, 3.0))
                    pw_prompt_raw = _recv_all(ts, 256)
                    _respond_iac(ts, pw_prompt_raw)
                    ts.sendall(passwd + b'\r\n')
                    ts.settimeout(timeout)
                    resp_raw = _recv_all(ts, 512)
                    resp_clean = _strip_iac(resp_raw).strip()
                    if resp_clean and shell_re.search(resp_clean) and not autherr_re.search(resp_clean):
                        u_str = uname.decode(errors='replace') or '(empty)'
                        p_str = passwd.decode(errors='replace') or '(empty)'
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'TELNET_DEFAULT_CREDS — Default credentials accepted on telnet',
                            'detail':   (
                                f'Telnet login on {host}:{t_port} accepted '
                                f'username={u_str!r} / password={p_str!r}. '
                                'Default credential access grants an interactive shell. '
                                'Mirai used this exact propagation step to infect 600 000+ '
                                'devices; internet-exposed telnet with default creds is '
                                f'compromised within minutes. Response: '
                                f'{resp_clean[:128].decode(errors="replace")!r}'
                            ),
                            'host': host,
                            'port': t_port,
                        })
                        cred_found = True
                finally:
                    ts.close()
            except (ConnectionRefusedError, socket.timeout, OSError):
                continue

        try:
            sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Phase 2: Serial-over-IP adapters
    # ------------------------------------------------------------------
    serial_targets = [
        (4001, 'SERIAL_CONSOLE_EXPOSED',       'Digi/generic serial-over-IP (port 4001)'),
        (5000, 'SERIAL_CONSOLE_EXPOSED',       'Generic serial-to-Ethernet (port 5000)'),
        (7000, 'SERIAL_CONSOLE_EXPOSED',       'Generic serial-to-Ethernet (port 7000)'),
        (4000, 'CISCO_CONSOLE_SERVER_EXPOSED', 'Cisco console server (port 4000)'),
    ]

    for s_port, label, desc in serial_targets:
        try:
            sock = socket.create_connection((host, s_port), timeout=timeout)
            try:
                sock.settimeout(timeout)
                findings.append({
                    'severity': 'HIGH',
                    'title':    f'{label} — {desc} reachable',
                    'detail':   (
                        f'TCP/{s_port} accepted connection on {host} ({desc}). '
                        'Serial-over-IP adapters bridge physical RS-232/RS-485 consoles to '
                        'the network, exposing debug consoles, bootloaders, and root shells '
                        'that bypass OS-level authentication. Physical console access is '
                        'normally assumed to require on-site presence.'
                    ),
                    'host': host,
                    'port': s_port,
                })
                try:
                    sock.sendall(b'\r\n')
                    sock.settimeout(min(timeout, 3.0))
                    banner = _recv_all(sock, 512)
                    if banner and banner.strip():
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'SERIAL_CONSOLE_INTERACTIVE — Serial console responded interactively',
                            'detail':   (
                                f'TCP/{s_port} on {host} returned interactive data after CR/LF: '
                                f'{banner[:200].decode(errors="replace")!r}. '
                                'Interactive response confirms live serial pass-through to a '
                                'physical device port. Attacker gains bootloader, debug shell, '
                                'or root console access equivalent to direct hardware access.'
                            ),
                            'host': host,
                            'port': s_port,
                        })
                except (socket.timeout, OSError):
                    pass
            finally:
                sock.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            continue

    # ------------------------------------------------------------------
    # Phase 3: Lantronix Device Server (port 9999)
    # ------------------------------------------------------------------
    lantronix_port = 9999
    try:
        sock = socket.create_connection((host, lantronix_port), timeout=timeout)
        try:
            sock.settimeout(timeout)
            sock.sendall(b'\r\n')
            data = _recv_all(sock, 512)
            if data:
                data_text = data.decode(errors='replace')
                if re.search(r'(?i)lantronix|\*\*\*\s*welcome', data_text):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'LANTRONIX_DEVICE_SERVER — Lantronix serial-to-IP device server exposed',
                        'detail':   (
                            f'TCP/9999 on {host} returned a Lantronix Device Server banner: '
                            f'{data_text[:200]!r}. Lantronix device servers bridge RS-232/RS-485 '
                            'serial lines to TCP/IP, exposing attached device consoles '
                            '(routers, switches, UPS, industrial controllers) without '
                            'authentication. Config port TCP/30718 (0x7786) may expose '
                            'credentials and full device configuration.'
                        ),
                        'host': host,
                        'port': lantronix_port,
                    })
                else:
                    findings.append({
                        'severity': 'HIGH',
                        'title':    'SERIAL_CONSOLE_EXPOSED — Unknown service on port 9999 (Lantronix console port)',
                        'detail':   (
                            f'TCP/9999 accepted connection on {host} with non-Lantronix '
                            f'response: {data_text[:200]!r}. Port 9999 is the Lantronix '
                            'Device Server console port; any responsive service here '
                            'warrants investigation as a potential serial console or '
                            'management interface.'
                        ),
                        'host': host,
                        'port': lantronix_port,
                    })
            else:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'SERIAL_CONSOLE_EXPOSED — Port 9999 open (Lantronix console port)',
                    'detail':   (
                        f'TCP/9999 accepted connection on {host} with no banner returned. '
                        'Port 9999 is the Lantronix Device Server console port. '
                        'Silent-open may indicate authentication state or firmware variant; '
                        'service surface warrants further investigation.'
                    ),
                    'host': host,
                    'port': lantronix_port,
                })
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass

    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import sys
    import argparse

    ap = argparse.ArgumentParser(description='ISE ISO Analyzer')
    ap.add_argument('--iso',        metavar='PATH', help='ISE ISO image path')
    ap.add_argument('--mountpoint', metavar='DIR',  help='Already-mounted ISO root')
    ap.add_argument('--no-root',    action='store_true',
                    help='Use isoinfo (no mount, limited extraction)')
    args = ap.parse_args()

    if args.no_root and args.iso:
        out = analyze_iso_no_root(args.iso)
    else:
        analyzer = ISEISOAnalyzer(iso_path=args.iso, mountpoint=args.mountpoint)
        try:
            out = analyzer.analyze()
        finally:
            analyzer.cleanup()

    print(json.dumps(out, indent=2, default=str))
