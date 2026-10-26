"""
embedded_rootfs_scanner.py: security scanner for embedded Linux rootfs images.

Gap this fills:
  1. Every PetaLinux/OpenWRT/Yocto rootfs image requires the same manual
     enumeration: credentials, inetd services, systemd autostart units, SUID
     binaries, SSH config, NFS/TCF exposure. This is repetitive across targets.
  2. Reading an ext4 partition inside a WIC image without root access requires
     knowing the Sleuth Kit CLI; there is no ablation abstraction for this.

Inputs accepted:
  a) Raw WIC/img disk image path (DiskImageExtractor locates the ext4 partition)
  b) Extracted rootfs directory path (find + open directly)

Findings emitted (RootfsFinding dataclass):
  severity  HIGH | MEDIUM | LOW | INFO
  category  CREDENTIAL | SERVICE | SSH | SUID | INETD | NFS | DEBUG
  title     short description
  detail    evidence string (file path, key content)

Usage:
    # From extracted directory:
    scanner = EmbeddedRootfsScanner.from_dir('/tmp/rootfs_extract/')
    findings = scanner.scan()
    print(scanner.report(findings))

    # From raw WIC image (uses DiskImageExtractor):
    scanner = EmbeddedRootfsScanner.from_image('/path/to/image.wic')
    findings = scanner.scan()
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_HIGH   = 'HIGH'
_MEDIUM = 'MEDIUM'
_LOW    = 'LOW'
_INFO   = 'INFO'


@dataclass
class RootfsFinding:
    severity: str
    category: str
    title:    str
    detail:   str

    def fmt(self) -> str:
        return f'  {self.severity:6s}  [{self.category}]  {self.title}\n          {self.detail}'


class EmbeddedRootfsScanner:
    """
    Security scanner for embedded Linux rootfs images.

    Accepts either an extracted directory tree or a raw disk image (WIC/img).
    For raw images, delegates filesystem access to DiskImageExtractor.
    """

    def __init__(self, rootfs_dir: Optional[str] = None, disk_extractor=None):
        self._dir = Path(rootfs_dir).resolve() if rootfs_dir else None
        self._ext = disk_extractor  # DiskImageExtractor or None

    @classmethod
    def from_dir(cls, rootfs_dir: str) -> 'EmbeddedRootfsScanner':
        """Build scanner from an already-extracted rootfs directory tree."""
        return cls(rootfs_dir=rootfs_dir)

    @classmethod
    def from_image(cls, image_path: str, partition_index: int = 1) -> 'EmbeddedRootfsScanner':
        """Build scanner from a raw WIC/img disk image.

        partition_index: 0-based index of the rootfs partition (default 1 = second partition).
        Requires DiskImageExtractor and Sleuth Kit (fls/icat) to be available.
        """
        from ablation.analyzers.disk_image_extractor import DiskImageExtractor
        ext = DiskImageExtractor.from_path(image_path, partition_index=partition_index)
        return cls(disk_extractor=ext)

    # ── file access abstraction ───────────────────────────────────────────────

    def _read_file(self, rel_path: str) -> Optional[str]:
        """Read a file from the rootfs as text, handling both directory and image sources."""
        if self._dir is not None:
            p = self._dir / rel_path.lstrip('/')
            try:
                return p.read_text(errors='replace')
            except (OSError, IsADirectoryError):
                return None
        if self._ext is not None:
            try:
                raw = self._ext.read_path(rel_path)
                return raw.decode('utf-8', errors='replace') if raw else None
            except Exception:
                return None
        return None

    def _file_exists(self, rel_path: str) -> bool:
        if self._dir is not None:
            return (self._dir / rel_path.lstrip('/')).exists()
        if self._ext is not None:
            return self._ext.path_exists(rel_path)
        return False

    def _list_dir(self, rel_path: str) -> List[str]:
        """Return entry names in a directory (not recursive)."""
        if self._dir is not None:
            p = self._dir / rel_path.lstrip('/')
            try:
                return [e.name for e in p.iterdir()]
            except (OSError, NotADirectoryError):
                return []
        if self._ext is not None:
            try:
                return self._ext.list_path(rel_path)
            except Exception:
                return []
        return []

    def _find_suid(self) -> List[str]:
        """Return list of SUID binary paths."""
        if self._dir is not None:
            results: List[str] = []
            try:
                out = subprocess.check_output(
                    ['find', str(self._dir), '-perm', '-4000', '-type', 'f'],
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
                for line in out.decode(errors='replace').splitlines():
                    rel = line[len(str(self._dir)):]
                    results.append(rel or line)
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
            return results
        if self._ext is not None:
            try:
                return self._ext.find_suid()
            except Exception:
                return []
        return []

    # ── individual checks ─────────────────────────────────────────────────────

    def _check_shadow(self) -> List[RootfsFinding]:
        findings: List[RootfsFinding] = []
        shadow = self._read_file('/etc/shadow')
        if shadow is None:
            return findings
        for line in shadow.splitlines():
            parts = line.split(':')
            if len(parts) < 2:
                continue
            user, pw_hash = parts[0], parts[1]
            if pw_hash == '' or pw_hash == '0':
                findings.append(RootfsFinding(
                    severity=_HIGH, category='CREDENTIAL',
                    title=f'Empty password for user "{user}"',
                    detail=f'/etc/shadow: {line[:80]}',
                ))
            elif pw_hash in ('*', '!', '!!', 'x'):
                pass  # locked / disabled — not a finding
            elif len(pw_hash) < 13 or not pw_hash.startswith('$'):
                findings.append(RootfsFinding(
                    severity=_MEDIUM, category='CREDENTIAL',
                    title=f'Unusual shadow hash for user "{user}"',
                    detail=f'/etc/shadow hash field: {pw_hash[:40]}',
                ))
        return findings

    def _check_passwd(self) -> List[RootfsFinding]:
        findings: List[RootfsFinding] = []
        passwd = self._read_file('/etc/passwd')
        if passwd is None:
            return findings
        for line in passwd.splitlines():
            parts = line.split(':')
            if len(parts) < 7:
                continue
            user, pw_inline, uid, shell = parts[0], parts[1], parts[2], parts[6].strip()
            if pw_inline not in ('x', '*', ''):
                findings.append(RootfsFinding(
                    severity=_HIGH, category='CREDENTIAL',
                    title=f'Inline password in /etc/passwd for "{user}"',
                    detail=f'uid={uid} shell={shell}',
                ))
        return findings

    def _check_inetd(self) -> List[RootfsFinding]:
        findings: List[RootfsFinding] = []
        inetd = self._read_file('/etc/inetd.conf')
        if inetd is None:
            return findings
        dangerous = {'telnet', 'ftp', 'rsh', 'rlogin', 'rexec', 'tftp'}
        for line in inetd.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            service = line.split()[0].lower() if line.split() else ''
            if service in dangerous:
                # Check for a 'root' in the user field (position 4)
                fields = line.split()
                svc_user = fields[4] if len(fields) > 4 else ''
                sev = _HIGH if svc_user == 'root' else _MEDIUM
                findings.append(RootfsFinding(
                    severity=sev, category='INETD',
                    title=f'inetd: {service} enabled (user={svc_user or "?"})',
                    detail=f'/etc/inetd.conf: {line[:120]}',
                ))
            elif service and not line.startswith('#'):
                findings.append(RootfsFinding(
                    severity=_INFO, category='INETD',
                    title=f'inetd: {service} configured',
                    detail=f'/etc/inetd.conf: {line[:120]}',
                ))
        return findings

    def _check_ssh_config(self) -> List[RootfsFinding]:
        findings: List[RootfsFinding] = []
        sshd = self._read_file('/etc/ssh/sshd_config')
        if sshd is None:
            return findings

        settings: Dict[str, str] = {}
        for line in sshd.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                settings[parts[0].lower()] = parts[1].lower()

        permit_root = settings.get('permitrootlogin', 'prohibit-password')
        password_auth = settings.get('passwordauthentication', 'yes')
        kbd_auth = settings.get('kbdinteractiveauthentication', 'yes')
        use_pam = settings.get('usepam', 'no')

        if 'yes' in permit_root:
            findings.append(RootfsFinding(
                severity=_HIGH, category='SSH',
                title='SSH: PermitRootLogin yes',
                detail=f'sshd_config: PermitRootLogin {permit_root}',
            ))
        if 'yes' in password_auth and 'yes' not in kbd_auth and 'yes' in use_pam:
            findings.append(RootfsFinding(
                severity=_MEDIUM, category='SSH',
                title='SSH: PasswordAuthentication yes with UsePAM yes (PAM-based auth active)',
                detail=f'sshd_config: PasswordAuthentication={password_auth} UsePAM={use_pam}',
            ))
        return findings

    def _check_systemd_autostart(self) -> List[RootfsFinding]:
        findings: List[RootfsFinding] = []
        wants_dirs = [
            '/etc/systemd/system/multi-user.target.wants',
            '/usr/lib/systemd/system/multi-user.target.wants',
            '/lib/systemd/system/multi-user.target.wants',
        ]
        # Known dangerous/notable services
        risky = {
            'tcf-agent.service':  (_HIGH,   'DEBUG',   'TCF agent (Xilinx remote debugger, no auth)'),
            'telnet.service':     (_HIGH,   'SERVICE', 'Telnet service (cleartext, no auth)'),
            'inetd.service':      (_MEDIUM, 'SERVICE', 'inetd (check /etc/inetd.conf for dangerous services)'),
            'dropbear.service':   (_INFO,   'SERVICE', 'Dropbear SSH server'),
            'sshd.service':       (_INFO,   'SERVICE', 'OpenSSH server'),
            'rpcbind.service':    (_INFO,   'NFS',     'rpcbind (NFS portmapper)'),
            'nfs-server.service': (_INFO,   'NFS',     'NFS server'),
            'nfs-mountd.service': (_INFO,   'NFS',     'NFS mountd'),
            'nfs-statd.service':  (_INFO,   'NFS',     'NFS statd'),
        }
        for wants_dir in wants_dirs:
            entries = self._list_dir(wants_dir)
            for entry in entries:
                if entry in risky:
                    sev, cat, desc = risky[entry]
                    findings.append(RootfsFinding(
                        severity=sev, category=cat,
                        title=f'Autostart: {entry} — {desc}',
                        detail=f'{wants_dir}/{entry}',
                    ))
                else:
                    findings.append(RootfsFinding(
                        severity=_INFO, category='SERVICE',
                        title=f'Autostart: {entry}',
                        detail=f'{wants_dir}/{entry}',
                    ))
        return findings

    def _check_ipbus_shim(self) -> List[RootfsFinding]:
        """Check for versalTcpIpbusShim / any TCP-to-devmem shim pattern."""
        findings: List[RootfsFinding] = []
        for script_path in ['/usr/bin/runGepIpbusShim.sh', '/usr/bin/runIpbusShim.sh']:
            script = self._read_file(script_path)
            if script is None:
                continue
            # Extract -p PORT and -m ADDRESS lines
            ports = re.findall(r'-p\s+(\d+)', script)
            addrs = re.findall(r'-m\s+(0x[0-9a-fA-F]+)', script)
            if ports:
                findings.append(RootfsFinding(
                    severity=_HIGH, category='SERVICE',
                    title=f'IPBus TCP shim: ports {", ".join(ports)} → /dev/mem (no auth)',
                    detail=f'{script_path}: {len(ports)} instance(s), '
                           f'base addrs: {", ".join(addrs[:4])}',
                ))
        return findings

    def _check_suid(self) -> List[RootfsFinding]:
        findings: List[RootfsFinding] = []
        suid_paths = self._find_suid()
        for path in suid_paths[:50]:  # cap to avoid noise on large rootfs
            findings.append(RootfsFinding(
                severity=_INFO, category='SUID',
                title=f'SUID binary: {path}',
                detail=path,
            ))
        if len(suid_paths) > 50:
            findings.append(RootfsFinding(
                severity=_INFO, category='SUID',
                title=f'SUID binary: ... ({len(suid_paths) - 50} more not shown)',
                detail=f'total SUID count: {len(suid_paths)}',
            ))
        return findings

    # ── public interface ──────────────────────────────────────────────────────

    def scan(self) -> List[RootfsFinding]:
        """Run all checks and return findings sorted by severity."""
        findings: List[RootfsFinding] = []
        findings.extend(self._check_shadow())
        findings.extend(self._check_passwd())
        findings.extend(self._check_inetd())
        findings.extend(self._check_ssh_config())
        findings.extend(self._check_systemd_autostart())
        findings.extend(self._check_ipbus_shim())
        findings.extend(self._check_suid())

        _order = {_HIGH: 0, _MEDIUM: 1, _LOW: 2, _INFO: 3}
        findings.sort(key=lambda f: _order.get(f.severity, 4))
        return findings

    def report(self, findings: Optional[List[RootfsFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return '[embedded_rootfs_scanner] no findings\n'
        by_sev: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        hdr = (
            f'[embedded_rootfs_scanner] {len(findings)} finding(s)  '
            + '  '.join(f'{k}={v}' for k, v in sorted(by_sev.items()))
            + '\n'
        )
        lines = [hdr]
        for f in findings:
            lines.append(f.fmt())
        return '\n'.join(lines) + '\n'
