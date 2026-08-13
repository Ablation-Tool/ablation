#!/usr/bin/env python3
"""
macOS Sysadmin Attack Surface Enumeration Module
Synthesized from:
  - Apple macOS and iOS System Administration (Drew Smith, 2020)
    Ch2 macOS Client Administration (Keychain, directory structure, users/groups)
    Ch3 macOS Security (FileVault, Gatekeeper, TCC, SIP, APFS)
    Ch6 Managing macOS Clients with Apple Remote Desktop (ARD, VNC, port 3283)
    Ch8 Mobile Device Management (DEP, MDM, Configuration Profiles)
  - Mac Security Bible (Kissell, Wiley 2010)
    Ch5 The Mac OS X Keychain (keychain storage, ~/Library/Keychains, /Library/Keychains)
    Ch7 Remote Login (SSH/OpenSSH, authorized_keys)
    Ch13 FileVault (fdesetup, master keychain, IRK)
    Ch25 Open Directory (LDAP, password server, Kerberos)
    Ch26 Directory Services (dscl, ShadowHashData, dslocal)
  - Take Control of the Mac Command Line with Terminal 3e (Kissell)
    Ch11 Log In to Another Computer (SSH, SFTP, SCP, authorized_keys)
    Ch14 Work with Permissions (POSIX, file modes)

Targets: post-compromise macOS host (authorized assessment context).
Context: MacStadium Orka nodes and bare macOS hosts in scope.
"""

import os
import re
import subprocess
import platform as _platform
import plistlib
import stat
import json
import base64
from pathlib import Path
from typing import Any

_IS_MACOS = _platform.system() == 'Darwin'

# ── Interesting keychain service names ───────────────────────────────────────
# Sources: Orka RE findings F96/F105, common sysadmin credentials
_KEYCHAIN_SERVICES = [
    'orka',
    'licensespring',
    'github',
    'gitlab',
    'api',
    'aws',
    'ssh',
    'vpn',
    'docker',
    'kubectl',
    'kube',
    'token',
    'password',
    'secret',
    'credential',
    'macstadium',
    'jenkins',
    'terraform',
    'ansible',
    'vault',
    'slack',
]

# ── Apple/MacStadium plist publisher prefixes ─────────────────────────────────
_APPLE_PREFIXES = ('com.apple.', 'com.macOS.', 'com.macstadium.')

# ── Orka-specific paths (from orka_enum.py RE findings F96/F104/F105) ────────
_ORKA_PATHS = {
    'root_creds':   '/var/root/.orka/',
    'etc_orka':     '/etc/orka/',
    'engine_plist': '/Library/LaunchDaemons/com.macstadium.orka-engine.server.managed.plist',
    'agent_plist':  '/Library/LaunchAgents/com.macstadium.orka-engine.server.plist',
    'opt_orka':     '/opt/orka',
    'vm_dir':       '/opt/orka/vms',
    'dhcp_leases':  '/var/db/dhcpd_leases',
    'engine_log':   '/opt/orka/logs/com.macstadium.orka-engine.server.managed.log',
    'engine_binary': '/usr/local/libexec/orka-engine.app/Contents/MacOS/com.macstadium.orka-engine.server',
    'profile':      '/usr/local/libexec/orka-engine.app/Contents/embedded.provisionprofile',
}


def _run(cmd: list, timeout: int = 10) -> tuple[int, str, str]:
    """Run a subprocess, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, '', 'timeout'
    except FileNotFoundError:
        return -1, '', f'not found: {cmd[0]}'
    except Exception as e:
        return -1, '', str(e)


def _read_plist(path: str) -> dict:
    """Parse a plist file. Returns empty dict on failure."""
    try:
        with open(path, 'rb') as fh:
            return plistlib.load(fh)
    except Exception:
        return {}


def _readable(path: str) -> bool:
    return os.access(path, os.R_OK)


def _exists(path: str) -> bool:
    return Path(path).exists()


class MacOSSysadminEnumerator:
    """
    macOS sysadmin attack surface enumerator.

    Covers: Keychain, Directory Services (dscl/dslocal), LaunchDaemons/Agents,
    remote management (ARD/SSH/VNC), SIP, FileVault, sudo, MDM, and
    Orka/MacStadium-specific paths.

    Run on a deployed macOS host (post-compromise, authorized testing).
    Does not require root for most checks; escalated checks are flagged.
    """

    def __init__(self):
        self.findings: list[dict] = []
        self._uid = os.getuid()
        self._user = os.environ.get('USER', 'unknown')
        self._home = str(Path.home())

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Execute all checks and return findings dict.

        Returns:
            {
                'platform': str,
                'user': str,
                'uid': int,
                'is_root': bool,
                'findings': list[dict],
                'summary': dict,
            }
        """
        self.check_keychain()
        self.check_directory_services()
        self.check_launchd_persistence()
        self.check_remote_management()
        self.check_sip_status()
        self.check_filevault()
        self.check_sudo_config()
        self.check_mdm_enrollment()
        self.check_tcc_database()
        self.check_orka_paths()
        self.check_sysadmin_credentials()
        self.check_network_services()
        self.check_apfs_snapshots()
        self.scan_launch_agents_daemons()
        self.scan_keychain_accessible()
        self.scan_ard_vnc_exposure()
        self.enumerate_mdm_profiles()
        self.scan_ssh_config()
        self.scan_world_writable_paths()
        self.scan_pf_firewall_state()
        self.enumerate_system_profiler()

        crit  = [f for f in self.findings if f.get('severity') == 'CRITICAL']
        high  = [f for f in self.findings if f.get('severity') == 'HIGH']
        med   = [f for f in self.findings if f.get('severity') == 'MEDIUM']
        low   = [f for f in self.findings if f.get('severity') == 'LOW']

        return {
            'platform': _platform.platform(),
            'user': self._user,
            'uid': self._uid,
            'is_root': self._uid == 0,
            'findings': self.findings,
            'summary': {
                'total': len(self.findings),
                'critical': len(crit),
                'high': len(high),
                'medium': len(med),
                'low': len(low),
            },
        }

    def _add(self, severity: str, category: str, title: str,
             detail: Any = None, chain: str = '', remediation: str = ''):
        """Append a finding."""
        self.findings.append({
            'severity': severity,
            'category': category,
            'title': title,
            'detail': detail,
            'chain': chain,
            'remediation': remediation,
        })

    # ── 1. Keychain enumeration ───────────────────────────────────────────────
    # Source: Mac Security Bible Ch5 (keychains at ~/Library/Keychains,
    #         /Library/Keychains; 3DES-encrypted; unlocked on login by default)
    # Source: Apple sysadmin book Ch2 (Keychain Access utility, login keychain)

    def check_keychain(self):
        """Enumerate keychain files and probe for interesting service entries."""
        # List all keychains in the search list
        rc, out, _ = _run(['security', 'list-keychains'])
        keychains = []
        if rc == 0 and out:
            keychains = [line.strip().strip('"') for line in out.splitlines() if line.strip()]

        # Canonical keychain paths — supplement list-keychains output
        login_kc = os.path.join(self._home, 'Library', 'Keychains', 'login.keychain-db')
        system_kc = '/Library/Keychains/System.keychain'
        fv_master_kc = '/Library/Keychains/FileVaultMaster.keychain'
        local_items = os.path.join(self._home, 'Library', 'Keychains', 'LocalItems.db')

        all_kc_paths = set(keychains)
        for p in [login_kc, system_kc, fv_master_kc, local_items]:
            if _exists(p):
                all_kc_paths.add(p)

        # Check for FileVault Institutional Recovery Key keychain (IRK)
        # Source: Apple sysadmin book Ch3 — IRK deployed to /Library/Keychains/
        if _exists(fv_master_kc):
            self._add(
                'CRITICAL', 'Keychain', 'FileVault Master Keychain present',
                detail={'path': fv_master_kc},
                chain='IRK can decrypt FileVault on any org Mac if private key retained',
                remediation='Verify IRK has private key stripped; rotate if compromised',
            )

        # Probe for interesting generic password entries by service name
        interesting_entries = []
        for svc in _KEYCHAIN_SERVICES:
            rc, out, _ = _run(['security', 'find-generic-password', '-s', svc,
                                '-g', '/dev/null'], timeout=5)
            # security exits 0 on match; -g writes password to stderr
            rc2, out2, err2 = _run(['security', 'find-generic-password', '-s', svc], timeout=5)
            if rc2 == 0 and out2:
                entry = {'service': svc, 'raw': out2[:500]}
                # Try to extract account/password fields
                for line in out2.splitlines():
                    if 'acct' in line or 'svce' in line or 'class' in line:
                        entry[line.split('=')[0].strip()] = line.split('=', 1)[-1].strip()
                interesting_entries.append(entry)

        if interesting_entries:
            self._add(
                'HIGH', 'Keychain', f'Interesting keychain entries found ({len(interesting_entries)} services)',
                detail=interesting_entries,
                chain='Keychain entries may contain API keys, tokens, SSH passphrases',
                remediation='Audit keychain ACLs; rotate exposed credentials',
            )

        # Attempt dump-keychain on login keychain (root or keychain owner required)
        if self._uid == 0 or _readable(login_kc):
            rc, out, _ = _run(['security', 'dump-keychain', login_kc], timeout=15)
            if rc == 0 and out:
                # Count items
                item_count = out.count('keychain:')
                self._add(
                    'HIGH', 'Keychain', 'Login keychain dump successful',
                    detail={'item_count': item_count, 'path': login_kc,
                            'preview': out[:1000]},
                    chain='Full credential access without interactive auth',
                    remediation='Enforce keychain lock-on-sleep; disable auto-unlock',
                )

        # List all keychain db files in ~/Library/Keychains (iCloud, custom)
        kc_dir = os.path.join(self._home, 'Library', 'Keychains')
        kc_files = []
        try:
            for p in Path(kc_dir).rglob('*.keychain-db'):
                kc_files.append(str(p))
            for p in Path(kc_dir).rglob('*.keychain'):
                kc_files.append(str(p))
        except Exception:
            pass

        if kc_files:
            self._add(
                'MEDIUM', 'Keychain', f'Keychain files on disk ({len(kc_files)} files)',
                detail={'files': kc_files, 'keychains_in_search': list(all_kc_paths)},
                chain='Offline cracking possible if file exfiltrated; key is login password',
                remediation='Enforce strong login passwords; enable keychain lock on sleep',
            )

    # ── 2. Directory Services ─────────────────────────────────────────────────
    # Source: Mac Security Bible Ch25/Ch26 (Open Directory, LDAP, password server,
    #         Kerberos, ShadowHashData, dslocal node)
    # Source: Apple sysadmin book Ch2 (Users & Groups, dscl, shell, home dir)

    def check_directory_services(self):
        """Enumerate local users via dscl; extract ShadowHashData where accessible."""
        # List all local users
        rc, out, _ = _run(['dscl', '.', '-list', '/Users'])
        if rc != 0 or not out:
            return

        users = [u.strip() for u in out.splitlines() if u.strip() and not u.startswith('_')]

        user_details = []
        admin_users = []
        shadow_hash_users = []

        # Enumerate admin group membership
        rc2, admin_out, _ = _run(['dscl', '.', '-read', '/Groups/admin', 'GroupMembership'])
        admin_members = set()
        if rc2 == 0 and admin_out:
            # Output: "GroupMembership: user1 user2 ..."
            parts = admin_out.split(':', 1)
            if len(parts) > 1:
                admin_members = set(parts[1].split())

        for user in users:
            rc3, attrs, _ = _run(['dscl', '.', '-read', f'/Users/{user}'], timeout=5)
            info = {'username': user, 'is_admin': user in admin_members}

            if rc3 == 0 and attrs:
                for line in attrs.splitlines():
                    if ': ' in line:
                        key, val = line.split(': ', 1)
                        key = key.strip()
                        if key in ('UserShell', 'NFSHomeDirectory', 'UniqueID',
                                   'PrimaryGroupID', 'RealName', 'AuthenticationAuthority'):
                            info[key] = val.strip()
                        # ShadowHashData is the PBKDF2 password hash
                        # Source: Mac Security Bible Ch26 — stored as base64 blob in dslocal
                        if 'ShadowHashData' in line:
                            info['has_shadow_hash'] = True
                            shadow_hash_users.append(user)

            user_details.append(info)
            if user in admin_members:
                admin_users.append(user)

        self._add(
            'MEDIUM', 'Directory Services', f'Local users enumerated ({len(users)} users)',
            detail={'users': user_details, 'admin_users': admin_users},
            chain='Admin users = full local privilege; ShadowHashData = offline crackable',
            remediation='Audit unnecessary admin accounts; enforce strong passwords',
        )

        if admin_users:
            self._add(
                'HIGH', 'Directory Services', f'Admin accounts present ({len(admin_users)})',
                detail={'admin_users': admin_users},
                chain='Admin context + sudo = root; admin can modify LaunchDaemons',
                remediation='Minimize admin count; use MDM to enforce standard user baseline',
            )

        # ShadowHashData extraction from dslocal (requires root)
        # Source: Mac Security Bible Ch26 — /var/db/dslocal/nodes/Default/users/
        dslocal_dir = '/var/db/dslocal/nodes/Default/users'
        if _readable(dslocal_dir):
            hash_files = []
            for user in users:
                plist_path = os.path.join(dslocal_dir, f'{user}.plist')
                if _exists(plist_path):
                    data = _read_plist(plist_path)
                    if data:
                        shadow = data.get('ShadowHashData')
                        if shadow:
                            # shadow is a list containing bytes
                            raw = shadow[0] if isinstance(shadow, list) else shadow
                            try:
                                inner = plistlib.loads(bytes(raw))
                                salted = inner.get('SALTED-SHA512-PBKDF2', {})
                                hash_info = {
                                    'user': user,
                                    'iterations': salted.get('Iterations'),
                                    'entropy_b64': base64.b64encode(
                                        bytes(salted['entropy'])
                                    ).decode() if 'entropy' in salted else None,
                                    'salt_b64': base64.b64encode(
                                        bytes(salted['salt'])
                                    ).decode() if 'salt' in salted else None,
                                }
                                hash_files.append(hash_info)
                            except Exception:
                                hash_files.append({'user': user, 'raw_bytes': len(bytes(raw))})

            if hash_files:
                self._add(
                    'CRITICAL', 'Directory Services',
                    f'ShadowHashData (PBKDF2 hashes) extracted ({len(hash_files)} users)',
                    detail={'hashes': hash_files},
                    chain='Hashes → hashcat -m 7100 (PBKDF2-SHA512) → plaintext passwords',
                    remediation='Enforce strong passwords; enable FileVault; restrict root access',
                )

        # Check for Open Directory / LDAP binding
        rc4, ldap_out, _ = _run(['dscl', '-list', '/Search', 'dsAttrTypeStandard:SearchPath'])
        if rc4 == 0 and 'LDAPv3' in (ldap_out or ''):
            self._add(
                'MEDIUM', 'Directory Services', 'Mac bound to LDAP/Open Directory',
                detail={'search_path': ldap_out},
                chain='Network accounts authenticated against LDAP; LDAP creds in use',
                remediation='Audit LDAP binding credentials; enforce certificate validation',
            )

    # ── 3. LaunchDaemon/LaunchAgent persistence ───────────────────────────────
    # Source: Apple sysadmin book Ch2 (Login Items, launchctl)
    # Source: Apple sysadmin book Ch3 (SIP — system LaunchDaemons read-only under SIP)
    # Paths: /Library/LaunchDaemons, /Library/LaunchAgents,
    #        ~/Library/LaunchAgents, /System/Library/LaunchDaemons (SIP-protected)

    def check_launchd_persistence(self):
        """Enumerate LaunchDaemons and LaunchAgents; flag non-Apple/suspicious entries."""
        search_dirs = [
            ('/Library/LaunchDaemons', 'system-daemon', 'HIGH'),
            ('/Library/LaunchAgents', 'system-agent', 'MEDIUM'),
            (os.path.join(self._home, 'Library', 'LaunchAgents'), 'user-agent', 'MEDIUM'),
            ('/System/Library/LaunchDaemons', 'os-daemon', 'LOW'),
            ('/System/Library/LaunchAgents', 'os-agent', 'LOW'),
        ]

        # launchctl list — running services
        rc, launchctl_out, _ = _run(['launchctl', 'list'], timeout=10)
        running_labels = set()
        if rc == 0 and launchctl_out:
            for line in launchctl_out.splitlines()[1:]:  # skip header
                parts = line.split('\t')
                if len(parts) >= 3:
                    running_labels.add(parts[2].strip())

        suspicious = []
        all_items = []

        for dirpath, context, base_sev in search_dirs:
            if not _exists(dirpath):
                continue
            try:
                plists = list(Path(dirpath).glob('*.plist'))
            except Exception:
                continue

            for pfile in plists:
                data = _read_plist(str(pfile))
                if not data:
                    continue

                label = data.get('Label', pfile.stem)
                prog_args = data.get('ProgramArguments', data.get('Program', []))
                run_at_load = data.get('RunAtLoad', False)
                keep_alive = data.get('KeepAlive', False)
                program = prog_args[0] if isinstance(prog_args, list) and prog_args else str(prog_args)

                item = {
                    'label': label,
                    'path': str(pfile),
                    'context': context,
                    'program': program,
                    'run_at_load': run_at_load,
                    'keep_alive': keep_alive,
                    'running': label in running_labels,
                    'prog_args': prog_args if isinstance(prog_args, list) else [prog_args],
                }
                all_items.append(item)

                # Flag non-Apple, non-MacStadium entries with RunAtLoad
                is_apple = label.startswith(_APPLE_PREFIXES)
                if not is_apple and run_at_load:
                    # Check if program binary actually exists
                    prog_exists = _exists(program) if program else False
                    item['program_exists'] = prog_exists
                    suspicious.append(item)

        if suspicious:
            self._add(
                'HIGH', 'Persistence', f'Suspicious LaunchDaemons/Agents ({len(suspicious)} items)',
                detail={'items': suspicious},
                chain='Persistent execution at boot/login; common persistence mechanism',
                remediation='Audit non-Apple launch items; verify binary provenance and signing',
            )

        # Orka-specific LaunchDaemons
        orka_items = [i for i in all_items if 'macstadium' in i['label'].lower() or 'orka' in i['label'].lower()]
        if orka_items:
            self._add(
                'MEDIUM', 'Persistence', f'MacStadium/Orka LaunchDaemons present ({len(orka_items)})',
                detail={'items': orka_items},
                chain='Orka engine runs as root daemon; ORKA_ENGINE_HELPER plist write = privesc (F104)',
                remediation='Verify Orka plist permissions are root:wheel 644',
            )

        if all_items:
            self._add(
                'LOW', 'Persistence', f'LaunchDaemon/Agent inventory ({len(all_items)} items)',
                detail={'items': all_items, 'running_count': len(running_labels)},
            )

    # ── 4. Remote management surface ─────────────────────────────────────────
    # Source: Apple sysadmin book Ch6 (ARD, VNC port 5900, ARD port 3283)
    # Source: Mac Security Bible Ch7 (SSH/Remote Login)
    # Paths: /Library/Application Support/Apple/Remote Desktop/,
    #        /Library/Preferences/com.apple.RemoteDesktop.plist

    def check_remote_management(self):
        """Check SSH authorized_keys, ARD/VNC config, Screen Sharing, Remote Login."""
        # SSH authorized_keys for all users
        # Source: Take Control of Mac Terminal Ch11 — SSH enabled via Sharing > Remote Login
        auth_keys_findings = []
        rc, users_out, _ = _run(['dscl', '.', '-list', '/Users', 'NFSHomeDirectory'])
        home_dirs = {}
        if rc == 0 and users_out:
            for line in users_out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    home_dirs[parts[0]] = parts[1]

        for user, homedir in home_dirs.items():
            if not homedir or homedir in ('/var/empty', '/dev/null'):
                continue
            ak_path = os.path.join(homedir, '.ssh', 'authorized_keys')
            if _readable(ak_path):
                try:
                    content = Path(ak_path).read_text(errors='replace')
                    keys = [l for l in content.splitlines() if l.strip() and not l.startswith('#')]
                    if keys:
                        auth_keys_findings.append({
                            'user': user,
                            'path': ak_path,
                            'key_count': len(keys),
                            'keys': keys[:10],  # first 10
                        })
                except Exception:
                    pass

        if auth_keys_findings:
            self._add(
                'HIGH', 'Remote Access', f'SSH authorized_keys present ({len(auth_keys_findings)} users)',
                detail={'users': auth_keys_findings},
                chain='Authorized keys allow passwordless SSH from attacker-controlled host',
                remediation='Audit key provenance; remove unknown keys; enforce key rotation policy',
            )

        # SSH config files — host-based auth, IdentityFile refs
        ssh_config_paths = [
            os.path.join(self._home, '.ssh', 'config'),
            '/etc/ssh/sshd_config',
            '/etc/ssh/ssh_config',
        ]
        ssh_configs = []
        for p in ssh_config_paths:
            if _readable(p):
                try:
                    content = Path(p).read_text(errors='replace')
                    ssh_configs.append({'path': p, 'content': content[:2000]})
                    # Flag dangerous directives
                    if 'PermitRootLogin yes' in content:
                        self._add(
                            'CRITICAL', 'Remote Access', 'SSH PermitRootLogin enabled',
                            detail={'path': p},
                            chain='Direct root SSH access without sudo escalation',
                            remediation='Set PermitRootLogin no in sshd_config; restart sshd',
                        )
                    if 'PasswordAuthentication yes' in content:
                        self._add(
                            'MEDIUM', 'Remote Access', 'SSH PasswordAuthentication enabled',
                            detail={'path': p},
                            remediation='Disable PasswordAuthentication; enforce key-only auth',
                        )
                    if 'HostbasedAuthentication yes' in content:
                        self._add(
                            'HIGH', 'Remote Access', 'SSH HostbasedAuthentication enabled',
                            detail={'path': p},
                            chain='Host-based auth bypasses per-user authentication',
                        )
                except Exception:
                    pass

        # SSH private keys in ~/.ssh/
        ssh_dir = os.path.join(self._home, '.ssh')
        private_keys = []
        if _exists(ssh_dir):
            try:
                for f in Path(ssh_dir).iterdir():
                    if f.suffix in ('', '.pem', '.key') and f.is_file() and _readable(str(f)):
                        try:
                            content = f.read_text(errors='replace')[:100]
                            if 'PRIVATE KEY' in content or 'BEGIN RSA' in content:
                                st = f.stat()
                                private_keys.append({
                                    'path': str(f),
                                    'mode': oct(st.st_mode),
                                    'world_readable': bool(st.st_mode & stat.S_IROTH),
                                })
                        except Exception:
                            pass
            except Exception:
                pass

        if private_keys:
            world_readable = [k for k in private_keys if k['world_readable']]
            sev = 'CRITICAL' if world_readable else 'HIGH'
            self._add(
                sev, 'Remote Access', f'SSH private keys found ({len(private_keys)} keys)',
                detail={'keys': private_keys,
                        'world_readable_count': len(world_readable)},
                chain='Private keys → lateral movement to other hosts in authorized_keys',
                remediation='Set mode 600 on private keys; use ssh-agent; rotate exposed keys',
            )

        # Apple Remote Desktop (ARD)
        # Source: Apple sysadmin book Ch6 — ARD uses VNC (port 5900) + ARD port 3283
        # ARD pref: /Library/Preferences/com.apple.RemoteDesktop.plist
        ard_pref = '/Library/Preferences/com.apple.RemoteDesktop.plist'
        ard_data = _read_plist(ard_pref)
        if ard_data:
            self._add(
                'HIGH', 'Remote Access', 'Apple Remote Desktop configuration present',
                detail={'pref_path': ard_pref, 'config': ard_data},
                chain='ARD = remote code exec, file copy, screen capture, admin to all enrolled Macs',
                remediation='Restrict ARD access; enforce ARD authentication; disable if unused',
            )

        # Check ARD support directory
        ard_support = '/Library/Application Support/Apple/Remote Desktop'
        if _exists(ard_support):
            ard_files = []
            try:
                for f in Path(ard_support).rglob('*'):
                    if f.is_file():
                        ard_files.append(str(f))
            except Exception:
                pass
            if ard_files:
                self._add(
                    'MEDIUM', 'Remote Access', f'ARD support files present ({len(ard_files)} files)',
                    detail={'dir': ard_support, 'files': ard_files[:20]},
                    remediation='Review ARD support files for stored credentials or task scripts',
                )

        # Screen Sharing / VNC (port 5900)
        # Check Sharing pref for active services
        sharing_plist = '/Library/Preferences/com.apple.ScreenSharing.plist'
        sharing_data = _read_plist(sharing_plist)
        if sharing_data:
            self._add(
                'MEDIUM', 'Remote Access', 'Screen Sharing (VNC/port 5900) configured',
                detail={'pref_path': sharing_plist, 'config': sharing_data},
                chain='VNC = full graphical remote access; default VNC auth often weak',
                remediation='Restrict Screen Sharing to specific users; enforce strong VNC password',
            )

        # Remote Login (SSH) status via sharing preference
        rc2, ssh_status, _ = _run(['systemsetup', '-getremotelogin'])
        if rc2 == 0 and 'On' in ssh_status:
            self._add(
                'MEDIUM', 'Remote Access', 'Remote Login (SSH) enabled',
                detail={'status': ssh_status},
                chain='SSH attack surface open; combine with weak credentials or authorized_keys',
                remediation='Restrict to specific users; disable if not required',
            )

    # ── 5. SIP (System Integrity Protection) ─────────────────────────────────
    # Source: Apple sysadmin book Ch2 (SIP — most system dirs read-only)
    # Source: Apple sysadmin book Ch3 (SIP protects /System, disables kext loading)

    def check_sip_status(self):
        """Check SIP status; disabled SIP = kernel extension loading possible."""
        rc, out, _ = _run(['csrutil', 'status'])
        if rc != 0 and not out:
            return

        disabled = 'disabled' in out.lower()
        sev = 'CRITICAL' if disabled else 'LOW'

        self._add(
            sev, 'System Security', f'SIP (System Integrity Protection) {"DISABLED" if disabled else "enabled"}',
            detail={'csrutil_output': out},
            chain='SIP disabled = kernel extension loading, /System write, rootkit persistence' if disabled else '',
            remediation='Enable SIP via Recovery Mode: csrutil enable' if disabled else '',
        )

        # NVRAM boot-args (SIP partial disablement)
        rc2, nvram_out, _ = _run(['nvram', '-x', '-p'])
        if rc2 == 0 and nvram_out:
            if 'csr-active-config' in nvram_out:
                self._add(
                    'HIGH', 'System Security', 'Custom SIP configuration in NVRAM (csr-active-config set)',
                    detail={'nvram': nvram_out[:500]},
                    chain='Partial SIP disablement — specific protections may be bypassed',
                    remediation='Audit boot-args; restore default SIP configuration',
                )
            if 'amfi_get_out_of_my_way' in nvram_out or 'amfi=0xff' in nvram_out:
                self._add(
                    'CRITICAL', 'System Security', 'AMFI (Apple Mobile File Integrity) disabled in NVRAM',
                    detail={'nvram_excerpt': nvram_out[:500]},
                    chain='AMFI bypass = unsigned code exec, code injection, privilege escalation',
                    remediation='Remove amfi flags from boot-args; re-enable AMFI; full security audit',
                )

    # ── 6. FileVault ─────────────────────────────────────────────────────────
    # Source: Mac Security Bible Ch13 (FileVault — fdesetup, master password,
    #         sparse bundle, cold boot attack)
    # Source: Apple sysadmin book Ch3 (FileVault 2 — AES-XTS, IRK deployment)

    def check_filevault(self):
        """Check FileVault encryption status and recovery key configuration."""
        rc, out, _ = _run(['fdesetup', 'status'])
        if rc != 0 and not out:
            return

        enabled = 'on' in out.lower() or 'enabled' in out.lower()

        if not enabled:
            self._add(
                'HIGH', 'Disk Encryption', 'FileVault NOT enabled',
                detail={'fdesetup_output': out},
                chain='Unencrypted disk = offline data extraction via target disk mode; no cold boot protection',
                remediation='Enable FileVault in Security & Privacy System Preferences',
            )
            return

        self._add(
            'LOW', 'Disk Encryption', 'FileVault is enabled',
            detail={'fdesetup_output': out},
        )

        # List FileVault-enabled users and recovery key type
        rc2, users_out, _ = _run(['fdesetup', 'list'])
        if rc2 == 0 and users_out:
            self._add(
                'LOW', 'Disk Encryption', 'FileVault-enabled users',
                detail={'users': users_out},
            )

        # Check for Institutional Recovery Key (IRK)
        # Source: Apple sysadmin book Ch3 — IRK at /Library/Keychains/FileVaultMaster.keychain
        irk_path = '/Library/Keychains/FileVaultMaster.keychain'
        if _exists(irk_path):
            self._add(
                'HIGH', 'Disk Encryption', 'FileVault Institutional Recovery Key (IRK) keychain present',
                detail={'path': irk_path},
                chain='IRK can decrypt disk; if private key retained in IRK, attacker with IRK file = full disk access',
                remediation='Verify private key was removed from deployed IRK keychain; secure master copy offline',
            )

        # Check fdesetup recovery key escrow (MDM)
        rc3, escrow_out, _ = _run(['fdesetup', 'showrecovery'])
        if rc3 == 0 and escrow_out and 'personal' in escrow_out.lower():
            self._add(
                'MEDIUM', 'Disk Encryption', 'FileVault personal recovery key exists',
                detail={'output': escrow_out[:200]},
                chain='Personal recovery key = filesystem bypass; key location may be documented',
                remediation='Escrow recovery key to MDM; rotate after use',
            )

    # ── 7. Sudo configuration ─────────────────────────────────────────────────
    # Source: Apple sysadmin book Ch2 (sudo, root user, admin group)

    def check_sudo_config(self):
        """Parse /etc/sudoers and /etc/sudoers.d/ for NOPASSWD and broad grants."""
        sudoers_paths = ['/etc/sudoers']
        sudoers_d = '/etc/sudoers.d'
        if _exists(sudoers_d):
            try:
                for f in Path(sudoers_d).iterdir():
                    if f.is_file():
                        sudoers_paths.append(str(f))
            except Exception:
                pass

        nopasswd_entries = []
        all_entries = []

        for sp in sudoers_paths:
            if not _readable(sp):
                continue
            try:
                content = Path(sp).read_text(errors='replace')
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith('#') or not stripped:
                        continue
                    all_entries.append({'file': sp, 'line': stripped})
                    if 'NOPASSWD' in stripped:
                        nopasswd_entries.append({'file': sp, 'line': stripped})
                    # ALL=(ALL) ALL or (ALL:ALL) ALL for any user
                    if 'ALL' in stripped and ('ALL)' in stripped or 'ALL:ALL' in stripped):
                        if not stripped.startswith('%admin') and not stripped.startswith('%wheel'):
                            nopasswd_entries.append({'file': sp, 'line': stripped,
                                                     'note': 'broad ALL grant'})
            except Exception:
                pass

        if nopasswd_entries:
            self._add(
                'CRITICAL', 'Privilege Escalation', f'Sudo NOPASSWD entries found ({len(nopasswd_entries)})',
                detail={'entries': nopasswd_entries},
                chain='NOPASSWD sudo = root without credentials; trivial privesc',
                remediation='Remove NOPASSWD from sudoers; require password for all sudo invocations',
            )

        if all_entries:
            self._add(
                'LOW', 'Privilege Escalation', f'Sudoers configuration ({len(all_entries)} rules)',
                detail={'entries': all_entries},
            )

        # Current user's sudo privileges
        rc, sudo_out, _ = _run(['sudo', '-l', '-n'], timeout=5)
        if rc == 0 and sudo_out:
            has_nopasswd = 'NOPASSWD' in sudo_out
            sev = 'CRITICAL' if has_nopasswd else 'MEDIUM'
            self._add(
                sev, 'Privilege Escalation',
                f'Current user ({self._user}) sudo privileges',
                detail={'sudo_l_output': sudo_out, 'nopasswd': has_nopasswd},
                chain='Sudo access = root command execution; NOPASSWD = no auth required',
            )

    # ── 8. MDM enrollment ─────────────────────────────────────────────────────
    # Source: Apple sysadmin book Ch8 (MDM, DEP, VPP, Configuration Profiles)
    # Source: Apple sysadmin book Ch9 (Profile Manager — .mobileconfig payloads)
    # MDM client: /Library/Application Support/com.apple.mdmclient/
    # Configuration Profiles: /Library/Profiles/

    def check_mdm_enrollment(self):
        """Check MDM enrollment, installed profiles, and DEP status."""
        # MDM enrollment status
        rc, prof_out, _ = _run(['profiles', 'status', '-type', 'enrollment'])
        if rc == 0 and prof_out:
            enrolled = 'enrolled' in prof_out.lower()
            dep = 'dep' in prof_out.lower() or 'device enrollment' in prof_out.lower()
            self._add(
                'MEDIUM' if enrolled else 'LOW',
                'MDM',
                f'MDM enrollment: {"ENROLLED" if enrolled else "not enrolled"}' +
                (' (DEP)' if dep else ''),
                detail={'profiles_status': prof_out},
                chain='MDM-enrolled Mac = remote config push, wipe, app install; MDM server = admin' if enrolled else '',
                remediation='Verify MDM server identity; audit installed profiles',
            )

        # List installed profiles
        rc2, profiles_list, _ = _run(['profiles', '-P'], timeout=10)
        if rc2 == 0 and profiles_list:
            self._add(
                'MEDIUM', 'MDM', 'Installed configuration profiles',
                detail={'profiles': profiles_list[:3000]},
                chain='Profiles may contain WiFi PSKs, VPN creds, LDAP passwords, app configs',
                remediation='Audit profile content for embedded credentials',
            )

        # MDM client directory
        mdm_dir = '/Library/Application Support/com.apple.mdmclient'
        mdm_files = []
        if _exists(mdm_dir):
            try:
                for f in Path(mdm_dir).rglob('*'):
                    if f.is_file():
                        mdm_files.append(str(f))
            except Exception:
                pass
            if mdm_files:
                self._add(
                    'MEDIUM', 'MDM', f'MDM client files ({len(mdm_files)} files)',
                    detail={'dir': mdm_dir, 'files': mdm_files[:30]},
                    chain='MDM client certs/tokens may enable MDM server impersonation or enrollment bypass',
                    remediation='Restrict access to MDM client directory; rotate MDM certs periodically',
                )

        # MDM identity certificate
        mdm_cert_paths = [
            '/Library/Profiles/MDMClientIdentity.cer',
            '/Library/Keychains/com.apple.mdm.plist',
        ]
        for cp in mdm_cert_paths:
            if _exists(cp):
                self._add(
                    'HIGH', 'MDM', f'MDM identity certificate present: {cp}',
                    detail={'path': cp},
                    chain='MDM identity cert = can authenticate to MDM server; potential pivot',
                    remediation='Rotate MDM certificates; restrict certificate access',
                )

        # DEP enrollment plist
        dep_plists = [
            '/Library/Preferences/com.apple.apsd.plist',
            '/var/db/ConfigurationProfiles/Settings/.cloudConfigIsActive',
            '/var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound',
        ]
        for dp in dep_plists:
            if _exists(dp):
                data = _read_plist(dp) if dp.endswith('.plist') else None
                self._add(
                    'MEDIUM', 'MDM', f'DEP marker present: {dp}',
                    detail={'path': dp, 'data': data},
                    chain='DEP enrollment = supervised by org MDM; enforced profiles cannot be removed by user',
                )
                break

    # ── 9. TCC (Transparency, Consent, and Control) database ─────────────────
    # Source: Apple sysadmin book Ch3 (TCC, PPPC — privacy permissions)
    # TCC db: ~/Library/Application Support/com.apple.TCC/TCC.db (per-user)
    #         /Library/Application Support/com.apple.TCC/TCC.db (system-wide)

    def check_tcc_database(self):
        """Check TCC database for apps with sensitive permission grants."""
        tcc_paths = [
            os.path.join(self._home, 'Library', 'Application Support', 'com.apple.TCC', 'TCC.db'),
            '/Library/Application Support/com.apple.TCC/TCC.db',
        ]
        for tcc_path in tcc_paths:
            if _readable(tcc_path):
                # Don't execute sqlite3 on TCC.db directly (SIP may block); note its existence
                st = Path(tcc_path).stat()
                self._add(
                    'MEDIUM', 'Privacy Controls',
                    f'TCC database accessible: {tcc_path}',
                    detail={
                        'path': tcc_path,
                        'size_bytes': st.st_size,
                        'note': 'Contains per-app permissions for Camera/Mic/Screen/Contacts/etc.',
                    },
                    chain='TCC.db read = enumerate which apps have Camera, Microphone, Screen Recording grants; '
                          'TCC.db write (root) = bypass privacy prompts',
                    remediation='Ensure TCC.db is not world-readable; SIP normally protects system TCC',
                )

        # PPPC policy from MDM profiles
        rc, pppc_out, _ = _run(['profiles', '-P', '-v'], timeout=10)
        if rc == 0 and 'com.apple.TCC.configuration-profile-policy' in (pppc_out or ''):
            self._add(
                'MEDIUM', 'Privacy Controls', 'PPPC policy payload present in MDM profiles',
                detail={'excerpt': pppc_out[:1000]},
                chain='MDM-pushed PPPC can pre-authorize apps for Camera/Mic without user prompt',
                remediation='Audit PPPC payloads; ensure only org-approved apps are pre-authorized',
            )

    # ── 10. Orka/MacStadium-specific paths ───────────────────────────────────
    # Source: orka_enum.py RE findings F96/F104/F105; Orka filesystem layout

    def check_orka_paths(self):
        """Check for Orka platform presence and credential artifacts."""
        found_paths = {}
        for name, path in _ORKA_PATHS.items():
            if _exists(path):
                st = None
                try:
                    st = Path(path).stat()
                except Exception:
                    pass
                found_paths[name] = {
                    'path': path,
                    'readable': _readable(path),
                    'size': st.st_size if st else None,
                    'mode': oct(st.st_mode) if st else None,
                }

        if not found_paths:
            return

        self._add(
            'HIGH', 'Orka Platform', f'Orka engine artifacts present ({len(found_paths)} paths)',
            detail={'paths': found_paths},
            chain='Orka node = macOS VM hypervisor; gRPC engine socket = unauth VM control (F99)',
            remediation='Restrict orka-engine.sock permissions; audit LaunchDaemon plist ownership',
        )

        # Orka credential cache
        orka_cred_dir = '/var/root/.orka'
        if _readable(orka_cred_dir):
            cred_files = []
            try:
                for f in Path(orka_cred_dir).rglob('*'):
                    if f.is_file():
                        cred_files.append({'path': str(f), 'size': f.stat().st_size})
            except Exception:
                pass
            if cred_files:
                self._add(
                    'CRITICAL', 'Orka Platform', 'Orka root credential cache accessible',
                    detail={'files': cred_files},
                    chain='Orka API tokens → cluster admin; enumerate/destroy/clone all VMs',
                    remediation='Restrict /var/root/.orka to root; rotate Orka credentials',
                )

        # Orka env vars in LaunchDaemon plist
        engine_plist = _ORKA_PATHS['engine_plist']
        if _readable(engine_plist):
            data = _read_plist(engine_plist)
            if data:
                env_vars = data.get('EnvironmentVariables', {})
                sensitive = {k: v for k, v in env_vars.items()
                             if any(s in k.upper() for s in
                                    ('KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'LICENSE', 'SENTRY', 'DSN'))}
                if sensitive:
                    self._add(
                        'CRITICAL', 'Orka Platform', 'Sensitive env vars in Orka LaunchDaemon plist',
                        detail={'plist': engine_plist, 'sensitive_vars': sensitive},
                        chain='ORKA_ENGINE_LICENSE_KEY, SENTRY_DSN readable from plist (F96/F105)',
                        remediation='Move secrets to keychain; restrict plist read permissions',
                    )

                # F104: ORKA_ENGINE_HELPER controls runvz binary path
                helper = env_vars.get('ORKA_ENGINE_HELPER')
                if helper:
                    helper_path = Path(helper)
                    parent_writable = os.access(str(helper_path.parent), os.W_OK)
                    if parent_writable:
                        self._add(
                            'CRITICAL', 'Orka Platform',
                            'ORKA_ENGINE_HELPER dir writable — plist-write privesc path (F104)',
                            detail={'helper': helper, 'parent': str(helper_path.parent)},
                            chain='Writable ORKA_ENGINE_HELPER dir → replace runvz binary → root code exec on next VM start',
                            remediation='Set ORKA_ENGINE_HELPER to read-only root-owned path; restrict parent dir',
                        )

        # Engine gRPC socket (unauth access)
        engine_sock = _ORKA_PATHS['sock'] if 'sock' in _ORKA_PATHS else '/var/run/orka-engine.sock'
        if _exists(engine_sock):
            sock_stat = Path(engine_sock).stat()
            world_accessible = bool(sock_stat.st_mode & (stat.S_IROTH | stat.S_IWOTH))
            self._add(
                'CRITICAL' if world_accessible else 'HIGH',
                'Orka Platform',
                f'Orka engine gRPC socket present (world_accessible={world_accessible})',
                detail={'socket': engine_sock, 'mode': oct(sock_stat.st_mode)},
                chain='Socket access = all VirtualMachineService RPCs unauth (F99); VM create/delete/clone/console',
                remediation='Restrict socket to orka group; add socket-level authentication',
            )

        # DHCP leases — VM MAC→IP oracle
        dhcp_leases = _ORKA_PATHS['dhcp_leases']
        if _readable(dhcp_leases):
            try:
                content = Path(dhcp_leases).read_text(errors='replace')
                leases = [l for l in content.splitlines() if '{' in l or 'name' in l or 'ip_address' in l]
            except Exception:
                leases = []
            self._add(
                'MEDIUM', 'Orka Platform', 'DHCP leases file readable (VM MAC→IP oracle)',
                detail={'path': dhcp_leases, 'lease_lines': leases[:30]},
                chain='Lease file reveals all VM IP addresses; enables targeted lateral movement',
            )

    # ── 11. Sysadmin credential storage ──────────────────────────────────────
    # Source: Apple sysadmin book Ch2, Ch6 (ARD scripts, /tmp installer staging)
    # Source: Mac Security Bible Ch7 (SSH config files)

    def check_sysadmin_credentials(self):
        """Check common sysadmin credential storage locations."""
        # AWS credentials
        aws_paths = [
            os.path.join(self._home, '.aws', 'credentials'),
            os.path.join(self._home, '.aws', 'config'),
            '/root/.aws/credentials',
            '/var/root/.aws/credentials',
        ]
        for ap in aws_paths:
            if _readable(ap):
                try:
                    content = Path(ap).read_text(errors='replace')
                    if 'aws_access_key_id' in content or 'aws_secret_access_key' in content:
                        self._add(
                            'CRITICAL', 'Credentials', f'AWS credentials file: {ap}',
                            detail={'path': ap, 'preview': content[:500]},
                            chain='AWS creds → cloud account compromise → S3 data, EC2, IAM escalation',
                            remediation='Rotate AWS credentials; use IAM roles; store in Secrets Manager',
                        )
                except Exception:
                    pass

        # kubeconfig
        kube_paths = [
            os.path.join(self._home, '.kube', 'config'),
            '/root/.kube/config',
            '/var/root/.kube/config',
            '/etc/kubernetes/admin.conf',
        ]
        for kp in kube_paths:
            if _readable(kp):
                try:
                    content = Path(kp).read_text(errors='replace')
                    if 'certificate-authority' in content or 'client-certificate' in content:
                        self._add(
                            'CRITICAL', 'Credentials', f'Kubeconfig with credentials: {kp}',
                            detail={'path': kp, 'preview': content[:800]},
                            chain='Kubeconfig → cluster-admin → pod exec, secret dump, lateral movement',
                            remediation='Rotate kubeconfig credentials; restrict file permissions to 600',
                        )
                except Exception:
                    pass

        # .netrc (plain-text credentials for FTP/SFTP/curl)
        netrc = os.path.join(self._home, '.netrc')
        if _readable(netrc):
            try:
                content = Path(netrc).read_text(errors='replace')
                if 'password' in content.lower() or 'login' in content.lower():
                    self._add(
                        'HIGH', 'Credentials', f'.netrc credentials file: {netrc}',
                        detail={'path': netrc, 'preview': content[:500]},
                        chain='.netrc plain-text passwords used by curl, ftp, sftp automatically',
                        remediation='Remove .netrc; use SSH keys or keychain-stored credentials',
                    )
            except Exception:
                pass

        # Common config files with embedded credentials
        config_patterns = [
            (os.path.join(self._home, '.gitconfig'), ['url', 'token', 'password']),
            ('/etc/passwd', ['x', ':']),
            ('/etc/shadow', [':']),  # macOS uses dslocal, but check if shadow-style file exists
            (os.path.join(self._home, '.bash_history'), ['password', 'token', 'secret', '--pass', 'curl -u', 'wget --password']),
            (os.path.join(self._home, '.zsh_history'), ['password', 'token', 'secret', '--pass', 'curl -u']),
        ]
        for cpath, keywords in config_patterns:
            if _readable(cpath):
                try:
                    content = Path(cpath).read_text(errors='replace')
                    matches = []
                    for line in content.splitlines():
                        if any(kw.lower() in line.lower() for kw in keywords):
                            matches.append(line.strip()[:200])
                    if matches and cpath.endswith('history'):
                        self._add(
                            'HIGH', 'Credentials',
                            f'Credential keywords in shell history: {cpath}',
                            detail={'path': cpath, 'matches': matches[:20]},
                            chain='Shell history contains passwords/tokens typed at prompt — plaintext exposure',
                            remediation='Clear history; configure HISTIGNORE for sensitive commands',
                        )
                except Exception:
                    pass

        # Ansible vault password files
        ansible_paths = [
            os.path.join(self._home, '.vault_pass'),
            os.path.join(self._home, '.ansible', 'vault_password'),
            '/etc/ansible/vault_password',
        ]
        for ap in ansible_paths:
            if _readable(ap):
                self._add(
                    'CRITICAL', 'Credentials', f'Ansible vault password file: {ap}',
                    detail={'path': ap},
                    chain='Vault password → decrypt all encrypted Ansible vars (credentials, API keys)',
                    remediation='Remove vault password files from disk; use --vault-password-file with restricted access',
                )

    # ── 12. Network services (Bonjour/zero-conf, listening ports) ────────────
    # Source: Apple sysadmin book Ch2 (Sharing pref, Computer Name, mDNS)
    # Bonjour/mDNS: port 5353/UDP; zero-conf service discovery

    def check_network_services(self):
        """Check listening ports and Bonjour/mDNS service registrations."""
        # netstat or ss for listening services
        rc, netstat_out, _ = _run(['netstat', '-an', '-p', 'tcp'], timeout=10)
        if rc != 0 or not netstat_out:
            rc, netstat_out, _ = _run(['ss', '-tlnp'], timeout=10)

        listening = []
        if netstat_out:
            for line in netstat_out.splitlines():
                if 'LISTEN' in line or ('*.*.tcp' in line and 'LISTEN' in line):
                    listening.append(line.strip())

        # Flag high-value ports
        interesting_ports = {
            '5900': 'VNC/Screen Sharing',
            '3283': 'Apple Remote Desktop',
            '22': 'SSH',
            '548': 'Apple Filing Protocol (AFP)',
            '5353': 'mDNS/Bonjour',
            '443': 'HTTPS',
            '8080': 'HTTP alt',
            '50051': 'gRPC',
            '8765': 'Custom API',
        }
        flagged = []
        for port, svc in interesting_ports.items():
            matches = [l for l in listening if f'.{port} ' in l or f':{port} ' in l]
            if matches:
                flagged.append({'port': port, 'service': svc, 'lines': matches})

        if flagged:
            self._add(
                'MEDIUM', 'Network Services',
                f'Interesting listening ports ({len(flagged)} services)',
                detail={'ports': flagged, 'all_listening': listening[:50]},
                chain='Open remote management ports = attack surface; VNC port 5900 + ARD port 3283 = full remote access',
                remediation='Disable unused sharing services; firewall restrict remote management ports',
            )

        # Bonjour DNS-SD service enumeration
        rc2, dns_sd_out, _ = _run(['dns-sd', '-B', '_services._dns-sd._udp', 'local'], timeout=3)
        if rc2 == 0 and dns_sd_out:
            self._add(
                'LOW', 'Network Services', 'Bonjour/mDNS services broadcasting',
                detail={'dns_sd': dns_sd_out[:1000]},
                chain='mDNS reveals hostname, service types, OS version to LAN neighbors',
                remediation='Disable unnecessary Bonjour services; isolate management network',
            )

        # Hostname and computer name (mDNS discovery surface)
        rc3, scutil_out, _ = _run(['scutil', '--get', 'ComputerName'])
        rc4, host_out, _ = _run(['scutil', '--get', 'LocalHostName'])
        if rc3 == 0 or rc4 == 0:
            self._add(
                'LOW', 'Network Services', 'Host identity (mDNS discovery)',
                detail={
                    'ComputerName': scutil_out if rc3 == 0 else None,
                    'LocalHostName': host_out if rc4 == 0 else None,
                },
            )

    # ── 13. APFS snapshots ───────────────────────────────────────────────────
    # Source: Apple sysadmin book Ch2 (APFS snapshots, tmutil, containers/volumes)

    def check_apfs_snapshots(self):
        """Enumerate APFS local snapshots; may expose deleted/modified files."""
        rc, snaps_out, _ = _run(['tmutil', 'listlocalsnapshots', '/'], timeout=10)
        if rc != 0 or not snaps_out:
            return

        snaps = [l.strip() for l in snaps_out.splitlines() if l.strip()]
        if snaps:
            self._add(
                'MEDIUM', 'APFS', f'Local APFS snapshots present ({len(snaps)} snapshots)',
                detail={'snapshots': snaps},
                chain='Snapshots may contain data deleted after incident; forensic recovery path',
                remediation='Audit snapshot retention policy; delete unnecessary snapshots with tmutil delete',
            )

        # APFS volume info (Catalina+ dual-volume System/Data split)
        rc2, diskutil_out, _ = _run(['diskutil', 'apfs', 'list'], timeout=10)
        if rc2 == 0 and diskutil_out:
            self._add(
                'LOW', 'APFS', 'APFS volume layout',
                detail={'diskutil_apfs': diskutil_out[:2000]},
            )

    # ── 14. LaunchAgents/Daemons structured scan ─────────────────────────────
    # Source: Apple sysadmin book Ch2 (launchctl, RunAtLoad, KeepAlive, plist keys)
    # Source: Apple sysadmin book Ch3 (SIP — /System/Library/LaunchDaemons read-only)
    # Persistence vectors: writable program path + RunAtLoad, remote-fetch ProgramArguments

    def scan_launch_agents_daemons(self) -> list:
        """
        Scan LaunchAgent/Daemon plists for persistence vectors.

        Checks:
          ~/Library/LaunchAgents/, /Library/LaunchAgents/,
          /Library/LaunchDaemons/, /System/Library/LaunchDaemons/

        Flags:
          CRITICAL — RunAtLoad=True AND ProgramArguments[0] is writable
          HIGH     — ProgramArguments contains curl/wget/python fetching remote URL

        Returns:
            list of {
                'label': str,
                'path': str,
                'severity': str,   # 'CRITICAL'|'HIGH'|'INFO'
                'program': str,
            }
        """
        if not _IS_MACOS:
            return []

        _REMOTE_FETCH_TOKENS = ('curl', 'wget', 'python', 'python3', 'ruby', 'perl', 'bash -c')
        _REMOTE_URL_PATTERNS = ('http://', 'https://', 'ftp://')

        scan_dirs = [
            os.path.join(self._home, 'Library', 'LaunchAgents'),
            '/Library/LaunchAgents',
            '/Library/LaunchDaemons',
            '/System/Library/LaunchDaemons',
        ]

        results = []

        for dirpath in scan_dirs:
            if not _exists(dirpath):
                continue
            try:
                plists = list(Path(dirpath).glob('*.plist'))
            except Exception:
                continue

            for pfile in plists:
                data = _read_plist(str(pfile))
                if not data:
                    continue

                label = data.get('Label', pfile.stem)
                prog_args = data.get('ProgramArguments', [])
                program_key = data.get('Program', '')
                run_at_load = bool(data.get('RunAtLoad', False))
                keep_alive = data.get('KeepAlive', False)

                # Resolve program path
                if isinstance(prog_args, list) and prog_args:
                    program = prog_args[0]
                    args_list = prog_args
                elif program_key:
                    program = program_key
                    args_list = [program_key]
                else:
                    program = ''
                    args_list = []

                severity = 'INFO'

                # CRITICAL: RunAtLoad=True and the program binary path is writable
                if run_at_load and program:
                    prog_path = Path(program)
                    parent_writable = (
                        os.access(str(prog_path.parent), os.W_OK)
                        if prog_path.parent.exists() else False
                    )
                    binary_writable = (
                        os.access(program, os.W_OK) if _exists(program) else False
                    )
                    if parent_writable or binary_writable:
                        severity = 'CRITICAL'
                        self._add(
                            'CRITICAL', 'Persistence',
                            f'RunAtLoad plist with writable program path: {label}',
                            detail={
                                'plist': str(pfile),
                                'program': program,
                                'binary_writable': binary_writable,
                                'parent_writable': parent_writable,
                            },
                            chain='Writable RunAtLoad binary → replace binary → exec as launchd '
                                  'context (root for Daemons) on next boot/login',
                            remediation='chown root:wheel and chmod 755 program binary and parent dir',
                        )

                # HIGH: ProgramArguments contain remote-fetch command + URL
                if severity != 'CRITICAL':
                    args_str = ' '.join(str(a) for a in args_list).lower()
                    has_fetch_cmd = any(t in args_str for t in _REMOTE_FETCH_TOKENS)
                    has_remote_url = any(u in args_str for u in _REMOTE_URL_PATTERNS)
                    if has_fetch_cmd and has_remote_url:
                        severity = 'HIGH'
                        self._add(
                            'HIGH', 'Persistence',
                            f'LaunchAgent/Daemon fetches from remote URL: {label}',
                            detail={
                                'plist': str(pfile),
                                'program_arguments': args_list[:20],
                            },
                            chain='Remote fetch at boot/login = C2 staging, supply-chain risk, '
                                  'or legitimate but verifiable update mechanism',
                            remediation='Verify publisher; pin fetched resource hash; prefer signed pkg delivery',
                        )

                results.append({
                    'label': label,
                    'path': str(pfile),
                    'severity': severity,
                    'program': program,
                })

        return results

    # ── 15. Keychain accessible check ────────────────────────────────────────
    # Source: Mac Security Bible Ch5 (keychain unlock state, login.keychain-db)
    # Source: Apple sysadmin book Ch2 (Keychain Access, automatic unlock on login)

    def scan_keychain_accessible(self) -> dict:
        """
        Probe keychain unlock state and surface accessible secrets.

        Checks:
          - security list-keychains (keychain search list)
          - login.keychain-db lock state via show-keychain-info
          - Generic password lookup for common service names (wifi, vpn, etc.)

        Returns:
            {
                'keychains': list[str],
                'locked': bool,         # True = login keychain is locked
                'accessible_secrets': list[dict],  # entries retrievable without auth prompt
            }
        """
        if not _IS_MACOS:
            return {'keychains': [], 'locked': True, 'accessible_secrets': []}

        # List keychain search path
        rc, out, _ = _run(['security', 'list-keychains'])
        keychains = []
        if rc == 0 and out:
            keychains = [line.strip().strip('"') for line in out.splitlines() if line.strip()]

        # Check login keychain lock state
        # security show-keychain-info exits 0 and prints nothing if unlocked;
        # prints "SecKeychainCopySettings" error or "Keychain is locked" if locked
        login_kc = os.path.join(self._home, 'Library', 'Keychains', 'login.keychain-db')
        locked = True
        if _exists(login_kc):
            rc2, out2, err2 = _run(['security', 'show-keychain-info', login_kc], timeout=5)
            combined = (out2 + err2).lower()
            if 'locked' in combined or rc2 != 0:
                locked = True
            else:
                locked = False

        if not locked:
            self._add(
                'HIGH', 'Keychain',
                'Login keychain is unlocked — secrets accessible without auth',
                detail={'keychain': login_kc},
                chain='Unlocked keychain = any process running as this user can read stored '
                      'passwords/tokens without triggering an auth dialog',
                remediation='Enable keychain lock on sleep/idle in Keychain Access preferences',
            )

        # Probe common service names for accessible generic password entries
        _PROBE_SERVICES = [
            'AirPort',        # WiFi passwords (macOS stores them as AirPort network name)
            'Wi-Fi',
            'wifi',
            'vpn',
            'VPN',
            'com.cisco.anyconnect',
            'com.apple.network.eap.user.identity',
        ]

        accessible_secrets = []
        for svc in _PROBE_SERVICES:
            rc3, out3, _ = _run(
                ['security', 'find-generic-password', '-s', svc], timeout=5
            )
            if rc3 == 0 and out3:
                entry = {'service': svc, 'raw': out3[:400]}
                for line in out3.splitlines():
                    if '=' in line:
                        k, _, v = line.partition('=')
                        k = k.strip()
                        if k in ('"acct"', '"svce"', '"icmt"', '"type"'):
                            entry[k.strip('"')] = v.strip().strip('"')
                accessible_secrets.append(entry)

        if accessible_secrets:
            self._add(
                'HIGH', 'Keychain',
                f'Keychain entries accessible for probe services ({len(accessible_secrets)})',
                detail={'entries': accessible_secrets},
                chain='WiFi PSKs and VPN credentials recoverable via security CLI; '
                      'no user prompt if keychain is unlocked',
                remediation='Audit keychain ACLs; restrict per-app ACL on sensitive entries',
            )

        return {
            'keychains': keychains,
            'locked': locked,
            'accessible_secrets': accessible_secrets,
        }

    # ── 16. ARD / VNC / Screen Sharing structured check ─────────────────────
    # Source: Apple sysadmin book Ch6 (ARD — port 3283 and VNC port 5900, kickstart)
    # Source: Mac Security Bible Ch17 (remote access — Screen Sharing, VNC)

    def scan_ard_vnc_exposure(self) -> dict:
        """
        Detect Apple Remote Desktop, Screen Sharing, and VNC listener.

        Checks:
          - launchctl list for ARD agent label
          - /var/db/RemoteManagement presence (ARD activation marker)
          - launchctl list com.apple.screensharing
          - TCP :5900 socket open (netstat/ss probe)

        Returns:
            {
                'ard_active': bool,
                'screen_sharing': bool,
                'vnc_port_open': bool,
            }
        """
        if not _IS_MACOS:
            return {'ard_active': False, 'screen_sharing': False, 'vnc_port_open': False}

        # Apple Remote Desktop — launchctl + filesystem marker
        ard_active = False
        rc, lctl_out, _ = _run(['launchctl', 'list'], timeout=10)
        if rc == 0 and lctl_out:
            for line in lctl_out.splitlines():
                lbl = line.split('\t')[-1].strip() if '\t' in line else ''
                if 'ARD' in lbl or 'RemoteDesktop' in lbl or 'remote.desktop' in lbl.lower():
                    ard_active = True
                    break

        # Filesystem marker written by ARD kickstart
        if not ard_active and _exists('/var/db/RemoteManagement'):
            ard_active = True

        # Also check the ARD pref (written when ARD has ever been activated)
        ard_pref = '/Library/Preferences/com.apple.RemoteDesktop.plist'
        if not ard_active and _readable(ard_pref):
            data = _read_plist(ard_pref)
            if data.get('ARD_AllLocalUsers') or data.get('ScreenSharingReqsMasterPwd') is not None:
                ard_active = True

        if ard_active:
            self._add(
                'HIGH', 'Remote Access',
                'Apple Remote Desktop (ARD) is active',
                detail={
                    'launchctl_match': True,
                    'db_marker': _exists('/var/db/RemoteManagement'),
                    'pref_plist': ard_pref,
                },
                chain='ARD = full remote admin: screen capture, file copy, execute commands, '
                      'reboot/shutdown; port 3283 + VNC port 5900',
                remediation='Disable ARD if unused (kickstart -deactivate); restrict to known admin hosts',
            )

        # Screen Sharing — com.apple.screensharing launchd job
        screen_sharing = False
        rc2, ss_out, _ = _run(
            ['launchctl', 'list', 'com.apple.screensharing'], timeout=5
        )
        if rc2 == 0 and ss_out:
            # Job exists and is loaded (not necessarily running — check PID field)
            parts = ss_out.split()
            # launchctl list <label> output: "PID Status Label"
            if parts and parts[0] not in ('-', ''):
                try:
                    if int(parts[0]) > 0:
                        screen_sharing = True
                except (ValueError, IndexError):
                    screen_sharing = True  # job loaded, assume active

        # Fallback: sharing pref
        sharing_plist = '/Library/Preferences/com.apple.ScreenSharing.plist'
        if not screen_sharing and _readable(sharing_plist):
            data = _read_plist(sharing_plist)
            if data:
                screen_sharing = True

        if screen_sharing:
            self._add(
                'MEDIUM', 'Remote Access',
                'Screen Sharing (VNC/port 5900) is active',
                detail={'launchd_label': 'com.apple.screensharing'},
                chain='Screen Sharing = graphical access; combined with weak VNC password = trivial takeover',
                remediation='Restrict Screen Sharing to specific users; enforce strong VNC password',
            )

        # VNC port 5900 — TCP socket probe via netstat
        vnc_port_open = False
        rc3, net_out, _ = _run(['netstat', '-an', '-p', 'tcp'], timeout=8)
        if rc3 != 0 or not net_out:
            rc3, net_out, _ = _run(['ss', '-tnlp'], timeout=8)
        if net_out:
            for line in net_out.splitlines():
                if '.5900 ' in line or ':5900 ' in line:
                    if 'LISTEN' in line or 'ESTABLISHED' in line or '*' in line:
                        vnc_port_open = True
                        break

        if vnc_port_open and not screen_sharing:
            self._add(
                'MEDIUM', 'Remote Access',
                'TCP :5900 (VNC) is listening but com.apple.screensharing not detected',
                detail={'note': 'Third-party VNC server may be running'},
                chain='Third-party VNC server may have weaker auth than macOS Screen Sharing',
                remediation='Identify VNC process (lsof -i :5900); verify auth strength',
            )

        return {
            'ard_active': ard_active,
            'screen_sharing': screen_sharing,
            'vnc_port_open': vnc_port_open,
        }

    # ── 17. MDM profiles structured enumeration ──────────────────────────────
    # Source: Apple sysadmin book Ch8 (MDM, DEP, Configuration Profiles, mobileconfig)
    # Source: Apple sysadmin book Ch9 (Profile Manager — payload types, MDM server URL)
    # Profiles stored: /Library/Managed Preferences/, /Library/Profiles/

    def enumerate_mdm_profiles(self) -> list:
        """
        Enumerate installed MDM/configuration profiles and extract MDM server URLs.

        Tries:
          1. profiles list -all (requires root on modern macOS but may work as user)
          2. profiles -P (deprecated but wider compatibility)
          3. Direct plist reads from /Library/Managed Preferences/

        Returns:
            list of {
                'identifier': str,
                'name': str,
                'mdm_url': str,   # empty string if not found
            }
        """
        if not _IS_MACOS:
            return []

        profiles_found: list[dict] = []
        seen_ids: set[str] = set()

        def _add_profile(identifier: str, name: str, mdm_url: str):
            if identifier not in seen_ids:
                seen_ids.add(identifier)
                profiles_found.append({
                    'identifier': identifier,
                    'name': name,
                    'mdm_url': mdm_url,
                })

        # Method 1: profiles list -all (XML output)
        rc, out, _ = _run(
            ['profiles', 'list', '-all', '-output', 'stdout-xml'], timeout=15
        )
        if rc == 0 and out and '<?xml' in out:
            try:
                data = plistlib.loads(out.encode())
                # profiles list -all returns a dict with '_computerlevel' and '_allusers' keys
                for section_key in ('_computerlevel', '_allusers', '_currentUser'):
                    for prof in (data.get(section_key) or []):
                        pid = prof.get('ProfileIdentifier', '')
                        pname = prof.get('ProfileDisplayName', prof.get('ProfileName', ''))
                        # MDM server URL lives in a payload of type com.apple.mdm
                        mdm_url = ''
                        for payload in (prof.get('ProfilePayloads') or []):
                            if payload.get('PayloadType') == 'com.apple.mdm':
                                mdm_url = payload.get('ServerURL', payload.get('CheckInURL', ''))
                                break
                        _add_profile(pid, pname, mdm_url)
            except Exception:
                pass

        # Method 2: profiles -P (text output fallback)
        if not profiles_found:
            rc2, out2, _ = _run(['profiles', '-P'], timeout=10)
            if rc2 == 0 and out2:
                current_id = ''
                current_name = ''
                for line in out2.splitlines():
                    stripped = line.strip()
                    if stripped.startswith('profileIdentifier:'):
                        current_id = stripped.split(':', 1)[-1].strip()
                    elif stripped.startswith('profileDisplayName:'):
                        current_name = stripped.split(':', 1)[-1].strip()
                    elif stripped.startswith('ServerURL:') or stripped.startswith('CheckInURL:'):
                        url = stripped.split(':', 1)[-1].strip()
                        _add_profile(current_id, current_name, url)
                        current_id = ''
                        current_name = ''
                # catch profiles with no MDM URL
                if current_id:
                    _add_profile(current_id, current_name, '')

        # Method 3: /Library/Managed Preferences/ plist files (no root needed on older macOS)
        managed_prefs = '/Library/Managed Preferences'
        if _exists(managed_prefs):
            try:
                for pfile in Path(managed_prefs).glob('*.plist'):
                    data = _read_plist(str(pfile))
                    if not data:
                        continue
                    pid = data.get('ProfileIdentifier', pfile.stem)
                    pname = data.get('ProfileDisplayName', pfile.stem)
                    mdm_url = data.get('ServerURL', data.get('CheckInURL', ''))
                    _add_profile(pid, pname, mdm_url)
            except Exception:
                pass

        # Surface interesting findings
        mdm_profiles = [p for p in profiles_found if p['mdm_url']]
        if mdm_profiles:
            self._add(
                'MEDIUM', 'MDM',
                f'MDM enrollment profiles with server URLs ({len(mdm_profiles)})',
                detail={'profiles': mdm_profiles},
                chain='MDM server URL = pivot target; org can push config, apps, wipe; '
                      'MDM identity cert + URL = potential MDM server impersonation vector',
                remediation='Verify MDM server certificate; audit profile restrictions for security regressions',
            )

        if profiles_found and not mdm_profiles:
            self._add(
                'LOW', 'MDM',
                f'Configuration profiles installed ({len(profiles_found)}, no MDM enrollment)',
                detail={'profiles': profiles_found[:20]},
            )

        return profiles_found

    # ── 18. SSH config deep scan ─────────────────────────────────────────────
    # Source: Mac Security Bible Ch112 (sshd_config — PermitRootLogin, PasswordAuthentication,
    #         PermitEmptyPasswords, authorized_keys; /etc/ssh/sshd_config canonical path)
    # Source: Mac Security Bible Ch177 (authorized_keys per user; ~/.ssh/ layout)
    # Extends check_remote_management() — adds PermitEmptyPasswords and unencrypted key check.

    def scan_ssh_config(self) -> list:
        """
        Deep SSH configuration scan.

        Checks:
          - /etc/sshd_config and /etc/ssh/sshd_config (fallback)
          - PermitRootLogin yes -> CRITICAL
          - PasswordAuthentication yes -> HIGH
          - PermitEmptyPasswords yes -> CRITICAL
          - All user home dirs: ~/.ssh/authorized_keys -> HIGH if entries present
          - ~/.ssh/id_rsa, id_ecdsa, id_ed25519: unencrypted (no "ENCRYPTED") -> CRITICAL

        Returns:
            list of finding dicts appended (same objects as self.findings entries).
        """
        results = []

        # Locate sshd_config — /etc/sshd_config is legacy macOS; /etc/ssh/sshd_config is canonical
        sshd_paths = ['/etc/ssh/sshd_config', '/etc/sshd_config']
        sshd_content = ''
        sshd_path_used = ''
        for sp in sshd_paths:
            if _readable(sp):
                try:
                    sshd_content = Path(sp).read_text(errors='replace')
                    sshd_path_used = sp
                    break
                except Exception:
                    pass

        if sshd_content:
            # Parse directives (ignore comment lines)
            directives: dict[str, str] = {}
            for line in sshd_content.splitlines():
                stripped = line.strip()
                if stripped.startswith('#') or not stripped:
                    continue
                parts = stripped.split(None, 1)
                if len(parts) == 2:
                    directives[parts[0].lower()] = parts[1].strip()

            permit_root = directives.get('permitrootlogin', '')
            if permit_root.lower() == 'yes':
                f = {
                    'severity': 'CRITICAL',
                    'category': 'SSH Config',
                    'title': 'PermitRootLogin yes — direct root SSH enabled',
                    'detail': {'path': sshd_path_used, 'directive': f'PermitRootLogin {permit_root}'},
                    'chain': 'Root SSH = no sudo escalation needed; direct root shell from network',
                    'remediation': 'Set PermitRootLogin no (or prohibit-password) and restart sshd',
                }
                self.findings.append(f)
                results.append(f)

            pwd_auth = directives.get('passwordauthentication', '')
            if pwd_auth.lower() == 'yes':
                f = {
                    'severity': 'HIGH',
                    'category': 'SSH Config',
                    'title': 'PasswordAuthentication yes — SSH password auth enabled',
                    'detail': {'path': sshd_path_used, 'directive': f'PasswordAuthentication {pwd_auth}'},
                    'chain': 'Password auth enables brute-force / credential stuffing attacks on SSH',
                    'remediation': 'Set PasswordAuthentication no; enforce public-key only auth',
                }
                self.findings.append(f)
                results.append(f)

            empty_pwd = directives.get('permitemptypasswords', '')
            if empty_pwd.lower() == 'yes':
                f = {
                    'severity': 'CRITICAL',
                    'category': 'SSH Config',
                    'title': 'PermitEmptyPasswords yes — empty password SSH login allowed',
                    'detail': {'path': sshd_path_used, 'directive': f'PermitEmptyPasswords {empty_pwd}'},
                    'chain': 'Accounts with no password = unauthenticated SSH shell access',
                    'remediation': 'Set PermitEmptyPasswords no immediately; audit accounts with empty passwords',
                }
                self.findings.append(f)
                results.append(f)

        # Enumerate all user home dirs via dscl for authorized_keys and private keys
        rc, users_out, _ = _run(['dscl', '.', '-list', '/Users', 'NFSHomeDirectory'])
        home_dirs: dict[str, str] = {}
        if rc == 0 and users_out:
            for line in users_out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    home_dirs[parts[0]] = parts[1].strip()

        _KEY_FILES = ('id_rsa', 'id_ecdsa', 'id_ed25519', 'id_dsa')

        for user, homedir in home_dirs.items():
            if not homedir or homedir in ('/var/empty', '/dev/null'):
                continue

            # authorized_keys check
            ak_path = os.path.join(homedir, '.ssh', 'authorized_keys')
            if _readable(ak_path):
                try:
                    content = Path(ak_path).read_text(errors='replace')
                    active_keys = [l for l in content.splitlines()
                                   if l.strip() and not l.strip().startswith('#')]
                    if active_keys:
                        f = {
                            'severity': 'HIGH',
                            'category': 'SSH Config',
                            'title': f'SSH authorized_keys present for user {user} ({len(active_keys)} keys)',
                            'detail': {
                                'path': ak_path,
                                'key_count': len(active_keys),
                                'keys': active_keys[:5],
                            },
                            'chain': 'authorized_keys = passwordless SSH from any host holding the matching private key',
                            'remediation': 'Audit key provenance; remove unknown keys; enforce key rotation',
                        }
                        self.findings.append(f)
                        results.append(f)
                except Exception:
                    pass

            # Unencrypted private key check
            ssh_dir = os.path.join(homedir, '.ssh')
            if not _exists(ssh_dir):
                continue
            for key_name in _KEY_FILES:
                key_path = os.path.join(ssh_dir, key_name)
                if not _readable(key_path):
                    continue
                try:
                    header = Path(key_path).read_text(errors='replace')[:512]
                    has_private_marker = ('PRIVATE KEY' in header or 'BEGIN RSA' in header
                                          or 'BEGIN DSA' in header or 'BEGIN EC' in header
                                          or 'BEGIN OPENSSH' in header)
                    is_encrypted = 'ENCRYPTED' in header
                    if has_private_marker and not is_encrypted:
                        f = {
                            'severity': 'CRITICAL',
                            'category': 'SSH Config',
                            'title': f'Unencrypted SSH private key: {key_path} (user {user})',
                            'detail': {
                                'path': key_path,
                                'user': user,
                                'encrypted': False,
                            },
                            'chain': 'Unencrypted key = immediate lateral movement to any host with '
                                     'matching authorized_keys; no passphrase crack required',
                            'remediation': 'Add passphrase with ssh-keygen -p; use ssh-agent; rotate exposed keys',
                        }
                        self.findings.append(f)
                        results.append(f)
                except Exception:
                    pass

        return results

    # ── 19. World-writable path scan ─────────────────────────────────────────
    # Source: Mac Security Bible Ch25 (POSIX permissions — world-write bit 0o002,
    #         sticky bit 0o1000; /tmp without sticky = unprivileged file clobber)
    # Source: Mac Security Bible Ch177 (forensic enumeration — /tmp, /var/tmp staging)

    def scan_world_writable_paths(self) -> list:
        """
        Check key paths for world-writable permissions and sticky-bit state.

        Checks:
          /tmp, /var/tmp, /private/tmp, /private/var/tmp
          /Library/Application Support/ and /Library/Preferences/ top-level items

        Returns:
            list of finding dicts appended.
        """
        results = []

        # Core temp dirs — sticky bit expected on /tmp equivalents
        _TEMP_PATHS = [
            '/tmp',
            '/var/tmp',
            '/private/tmp',
            '/private/var/tmp',
        ]

        for p in _TEMP_PATHS:
            if not _exists(p):
                continue
            try:
                st = os.stat(p)
                mode = st.st_mode
                world_write = bool(mode & 0o002)
                sticky = bool(mode & 0o1000)

                if world_write and not sticky:
                    f = {
                        'severity': 'CRITICAL',
                        'category': 'Permissions',
                        'title': f'World-writable temp dir without sticky bit: {p}',
                        'detail': {'path': p, 'mode': oct(mode), 'sticky': sticky},
                        'chain': 'Missing sticky bit on world-writable /tmp = any user can rename/delete '
                                 'other users\' files -> symlink attacks, file-clobber race conditions',
                        'remediation': f'chmod +t {p} to restore sticky bit',
                    }
                    self.findings.append(f)
                    results.append(f)
                elif world_write and sticky:
                    f = {
                        'severity': 'LOW',
                        'category': 'Permissions',
                        'title': f'World-writable temp dir (sticky bit set — normal): {p}',
                        'detail': {'path': p, 'mode': oct(mode), 'sticky': sticky},
                        'chain': '',
                        'remediation': '',
                    }
                    self.findings.append(f)
                    results.append(f)
            except Exception:
                pass

        # /Library/Application Support and /Library/Preferences — top-level items
        _LIBRARY_DIRS = [
            '/Library/Application Support',
            '/Library/Preferences',
        ]

        for lib_dir in _LIBRARY_DIRS:
            if not _exists(lib_dir):
                continue
            try:
                for entry in Path(lib_dir).iterdir():
                    try:
                        st = entry.stat()
                        mode = st.st_mode
                        if mode & 0o002:  # world-writable
                            f = {
                                'severity': 'HIGH',
                                'category': 'Permissions',
                                'title': f'World-writable library path: {entry}',
                                'detail': {
                                    'path': str(entry),
                                    'mode': oct(mode),
                                    'is_dir': entry.is_dir(),
                                },
                                'chain': 'World-writable /Library path = any local user can plant '
                                         'malicious plist/config/dylib picked up by privileged processes',
                                'remediation': f'chmod o-w "{entry}"; audit owner:group',
                            }
                            self.findings.append(f)
                            results.append(f)
                    except Exception:
                        pass
            except Exception:
                pass

        return results

    # ── 20. pf and Application Firewall state ────────────────────────────────
    # Source: Mac Security Bible Ch162 (IPFW/pf — pfctl -s info; disabled by default;
    #         Application Firewall = socketfilterfw separate from pf)
    # Both pf and Application Firewall can be independently disabled.

    def scan_pf_firewall_state(self) -> list:
        """
        Check pf packet filter and Application Firewall (socketfilterfw) state.

        Returns:
            list of finding dicts appended.
        """
        results = []

        # pf state via pfctl
        rc, pf_out, pf_err = _run(['pfctl', '-s', 'info'], timeout=8)
        combined = (pf_out + pf_err).lower()
        if rc != -1:  # pfctl responded (even with errors means pf exists)
            if 'status: disabled' in combined or ('enabled' not in combined and rc != 0):
                f = {
                    'severity': 'MEDIUM',
                    'category': 'Firewall',
                    'title': 'pf packet filter is disabled',
                    'detail': {'pfctl_output': (pf_out + pf_err)[:500]},
                    'chain': 'No pf rules = no network-level egress/ingress filtering; '
                             'all ports reachable if service is listening',
                    'remediation': 'Enable pf: pfctl -e; load ruleset from /etc/pf.conf',
                }
                self.findings.append(f)
                results.append(f)
            elif 'status: enabled' in combined:
                f = {
                    'severity': 'LOW',
                    'category': 'Firewall',
                    'title': 'pf packet filter is enabled',
                    'detail': {'pfctl_excerpt': (pf_out)[:300]},
                    'chain': '',
                    'remediation': '',
                }
                self.findings.append(f)
                results.append(f)

        # Application Firewall (ALF) via socketfilterfw
        _SOCKETFILTERFW = '/usr/libexec/ApplicationFirewall/socketfilterfw'
        rc2, alf_out, _ = _run([_SOCKETFILTERFW, '--getglobalstate'], timeout=8)
        if rc2 != -1 or alf_out:
            if 'disabled' in alf_out.lower():
                f = {
                    'severity': 'MEDIUM',
                    'category': 'Firewall',
                    'title': 'Application Firewall (socketfilterfw) is disabled',
                    'detail': {'socketfilterfw_output': alf_out[:300]},
                    'chain': 'Application Firewall disabled = no per-app inbound filtering; '
                             'any process can open listening sockets without user prompt',
                    'remediation': f'{_SOCKETFILTERFW} --setglobalstate on; '
                                   'enable in System Settings > Network > Firewall',
                }
                self.findings.append(f)
                results.append(f)
            elif 'enabled' in alf_out.lower():
                f = {
                    'severity': 'LOW',
                    'category': 'Firewall',
                    'title': 'Application Firewall (socketfilterfw) is enabled',
                    'detail': {'socketfilterfw_output': alf_out[:300]},
                    'chain': '',
                    'remediation': '',
                }
                self.findings.append(f)
                results.append(f)

            # Check stealth mode (drops unreachable ICMP for probe resistance)
            rc3, stealth_out, _ = _run([_SOCKETFILTERFW, '--getstealthmode'], timeout=5)
            if 'disabled' in stealth_out.lower():
                f = {
                    'severity': 'LOW',
                    'category': 'Firewall',
                    'title': 'Application Firewall stealth mode disabled (host responds to ICMP probes)',
                    'detail': {'stealth_output': stealth_out[:200]},
                    'chain': 'Host visible to network scanners via ICMP; increases discoverability',
                    'remediation': f'{_SOCKETFILTERFW} --setstealthmode on',
                }
                self.findings.append(f)
                results.append(f)

        return results

    # ── 21. system_profiler enumeration ─────────────────────────────────────
    # Source: Mac Security Bible Ch177 (system_profiler data types — SPSoftwareDataType,
    #         SPHardwareDataType, SPNetworkDataType; forensic system info baseline)
    # Surfaces: OS version, Boot Mode (Safe Boot = reduced attack surface but unusual),
    #           Secure Boot state, hardware UUID, serial number for asset tracking.

    def enumerate_system_profiler(self) -> dict:
        """
        Collect hardware/software baseline via system_profiler.

        Data types: SPSoftwareDataType, SPHardwareDataType, SPNetworkDataType

        Returns:
            {
                'os_version': str,
                'boot_mode': str,
                'hardware_uuid': str,
                'serial_number': str,
                'secure_boot_state': str,
                'network_interfaces': list[str],
                'raw_excerpt': str,
            }
        """
        rc, out, _ = _run(
            ['system_profiler', 'SPSoftwareDataType', 'SPHardwareDataType', 'SPNetworkDataType'],
            timeout=30,
        )

        info: dict = {
            'os_version': '',
            'boot_mode': '',
            'hardware_uuid': '',
            'serial_number': '',
            'secure_boot_state': '',
            'network_interfaces': [],
            'raw_excerpt': '',
        }

        if rc != 0 or not out:
            return info

        info['raw_excerpt'] = out[:3000]

        for line in out.splitlines():
            stripped = line.strip()
            low = stripped.lower()

            if low.startswith('system version:') or low.startswith('macos:'):
                info['os_version'] = stripped.split(':', 1)[-1].strip()
            elif low.startswith('boot mode:'):
                info['boot_mode'] = stripped.split(':', 1)[-1].strip()
            elif low.startswith('hardware uuid:'):
                info['hardware_uuid'] = stripped.split(':', 1)[-1].strip()
            elif low.startswith('serial number'):
                info['serial_number'] = stripped.split(':', 1)[-1].strip()
            elif 'secure boot' in low and ':' in stripped:
                info['secure_boot_state'] = stripped.split(':', 1)[-1].strip()
            elif low.startswith('interface name:') or low.startswith('bsd device name:'):
                info['network_interfaces'].append(stripped.split(':', 1)[-1].strip())

        # Surface findings
        secure_boot = info['secure_boot_state'].lower()
        if secure_boot and ('off' in secure_boot or 'disabled' in secure_boot
                            or 'no security' in secure_boot):
            self._add(
                'MEDIUM', 'System Security',
                f'Secure Boot is off or reduced: {info["secure_boot_state"]}',
                detail={'secure_boot_state': info['secure_boot_state'],
                        'os_version': info['os_version']},
                chain='Secure Boot off = unsigned boot images allowed; '
                      'cold-boot or DFU-mode attacks possible without firmware resistance',
                remediation='Re-enable Full Security in macOS Startup Security Utility (Apple Silicon: '
                            'hold power at boot; Intel: Recovery Mode)',
            )

        boot_mode = info['boot_mode'].lower()
        if 'safe' in boot_mode:
            self._add(
                'MEDIUM', 'System Security',
                f'Host booted in Safe Boot mode: {info["boot_mode"]}',
                detail={'boot_mode': info['boot_mode']},
                chain='Safe Boot disables third-party kexts/LaunchDaemons — may indicate incident response '
                      'or deliberate defense evasion by attacker who rebooted the host',
                remediation='Verify Safe Boot is intentional; normal operation should not require it',
            )

        if info['os_version'] or info['hardware_uuid']:
            self._add(
                'LOW', 'System Info',
                'Hardware/software baseline collected via system_profiler',
                detail={
                    'os_version': info['os_version'],
                    'boot_mode': info['boot_mode'],
                    'hardware_uuid': info['hardware_uuid'],
                    'serial_number': info['serial_number'],
                    'secure_boot_state': info['secure_boot_state'],
                    'network_interfaces': info['network_interfaces'],
                },
            )

        return info

    # ── Report helper ─────────────────────────────────────────────────────────

    def report(self) -> str:
        """Human-readable text report of findings."""
        lines = [f'macOS Sysadmin Enumeration — {_platform.node()}',
                 f'User: {self._user} (uid={self._uid})',
                 f'Total findings: {len(self.findings)}', '']

        by_sev = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for f in self.findings:
            by_sev.get(f.get('severity', 'LOW'), by_sev['LOW']).append(f)

        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            items = by_sev[sev]
            if not items:
                continue
            lines.append(f'[{sev}] ({len(items)} findings)')
            for f in items:
                lines.append(f'  {f["category"]} — {f["title"]}')
                if f.get('chain'):
                    lines.append(f'    Chain: {f["chain"][:120]}')
                if f.get('remediation'):
                    lines.append(f'    Fix:   {f["remediation"][:120]}')
            lines.append('')

        return '\n'.join(lines)


# ── Standalone filesystem-based security checks ───────────────────────────────
# Stdlib only (os, re, plistlib, stat, Path). No subprocess calls.
# Return format: list[{severity, title, detail, host, port}]
# Complement the MacOSSysadminEnumerator class methods; do not duplicate them.


def check_macos_filevault(scan_path: str = '/') -> list:
    """
    FileVault status heuristic and SSH key exposure check via filesystem reads.
    No subprocess — uses /var/db/FileVault sentinel and ~/.ssh/config parse.

    Sources:
      Mac Security Bible Ch13 (FileVault, deferred encryption, /var/db/FileVault sentinel,
      recovery key storage, institutional recovery key path)
      Mac Security Bible Ch7 (SSH private key storage, identity files, authorized_keys)

    Checks:
      - /var/db/FileVault existence as FileVault-active indicator
      - /Library/Preferences/com.apple.security.libraryvalidation.plist as fallback read
      - ~/.ssh/config IdentityFile entries for key files with permissive modes (group/other
        readable) — heuristic proxy for missing passphrase protection

    Note: fdesetup-based checks are covered by MacOSSysadminEnumerator.check_filevault();
    this function operates without subprocess and produces the flat {host, port} format.

    Returns:
        list of {severity, title, detail, host, port} dicts.
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    # FileVault active sentinel: /var/db/FileVault exists when FV has been provisioned
    # Source: Mac Security Bible Ch13 — deferred-encryption state written here on enable
    fv_db = '/var/db/FileVault'
    fv_active = os.path.exists(fv_db)

    if not fv_active:
        # Secondary read: com.apple.security.libraryvalidation.plist
        lv_plist = '/Library/Preferences/com.apple.security.libraryvalidation.plist'
        lv_keys: list = []
        lv_readable = os.access(lv_plist, os.R_OK)
        if lv_readable:
            try:
                with open(lv_plist, 'rb') as fh:
                    lv_data = plistlib.load(fh)
                lv_keys = list(lv_data.keys())[:10]
            except Exception:
                pass

        results.append({
            'severity': 'MEDIUM',
            'title': 'FILEVAULT_STATUS_UNKNOWN',
            'detail': {
                'reason': '/var/db/FileVault absent — cannot confirm disk encryption without fdesetup',
                'fv_db_checked': fv_db,
                'lv_plist_readable': lv_readable,
                'lv_plist_keys': lv_keys,
            },
            'host': _h,
            'port': _p,
        })

    # SSH IdentityFile permission check
    # Key files should be 0o600; group/other read bit = offline-copyable without user notice
    # Source: Mac Security Bible Ch7 — private key file permission hardening
    ssh_config = os.path.expanduser('~/.ssh/config')
    if os.access(ssh_config, os.R_OK):
        try:
            content = Path(ssh_config).read_text(errors='replace')
            for line in content.splitlines():
                m = re.match(r'^\s*[Ii]dentity[Ff]ile\s+(\S+)', line)
                if not m:
                    continue
                key_path = os.path.expanduser(m.group(1))
                if not os.path.exists(key_path):
                    continue
                mode = os.stat(key_path).st_mode & 0o777
                if mode & 0o044:  # group or other read bit set
                    results.append({
                        'severity': 'MEDIUM',
                        'title': 'SSH_KEY_POSSIBLY_UNENCRYPTED',
                        'detail': {
                            'key_path': key_path,
                            'mode_octal': oct(mode),
                            'reason': (
                                'Key file is group/other readable; '
                                'passphrase presence cannot be verified without execution, '
                                'and open permissions enable silent offline copy'
                            ),
                        },
                        'host': _h,
                        'port': _p,
                    })
        except Exception:
            pass

    return results


def check_macos_firewall_config() -> list:
    """
    Application Firewall (ALF) and pf ruleset check via direct file reads.
    No subprocess — reads com.apple.alf.plist and /etc/pf.conf directly.

    Sources:
      Mac Security Bible Ch100 (SSL/TLS baseline, firewall posture)
      Mac Security Bible Ch114-119 (VPN, network filtering, pf packet filter ruleset)

    Checks:
      - /Library/Preferences/com.apple.alf.plist globalstate:
          0  = HIGH MACOS_FIREWALL_DISABLED
          1  = MEDIUM MACOS_FIREWALL_SIGNED_ONLY (signed apps bypass)
      - /etc/pf.conf absent or empty = MEDIUM PF_FIREWALL_NOT_CONFIGURED
      - /etc/pf.conf contains 'pass all' without qualifiers = HIGH PF_PASS_ALL_RULE

    Note: pfctl/socketfilterfw subprocess checks covered by scan_pf_firewall_state();
    this function reads files directly and uses the flat {host, port} return format.

    Returns:
        list of {severity, title, detail, host, port} dicts.
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    # Application Firewall plist
    # globalstate: 0=off, 1=signed-apps allowed, 2=essential services only
    # Source: Mac Security Bible Ch100 — ALF is distinct from pf; controls per-app inbound
    alf_plist = '/Library/Preferences/com.apple.alf.plist'
    if os.access(alf_plist, os.R_OK):
        try:
            with open(alf_plist, 'rb') as fh:
                alf = plistlib.load(fh)
            gs = alf.get('globalstate', -1)
            if gs == 0:
                results.append({
                    'severity': 'HIGH',
                    'title': 'MACOS_FIREWALL_DISABLED',
                    'detail': {
                        'path': alf_plist,
                        'globalstate': gs,
                        'meaning': 'ALF off — no per-application inbound connection filtering',
                    },
                    'host': _h,
                    'port': _p,
                })
            elif gs == 1:
                results.append({
                    'severity': 'MEDIUM',
                    'title': 'MACOS_FIREWALL_SIGNED_ONLY',
                    'detail': {
                        'path': alf_plist,
                        'globalstate': gs,
                        'meaning': (
                            'ALF allows all signed applications; unsigned processes '
                            'may receive inbound connections without user prompt'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except Exception:
            pass

    # pf packet filter ruleset
    # Source: Mac Security Bible Ch119 — pf stateful filtering; 'pass all' = no restriction
    pf_conf = '/etc/pf.conf'
    if os.path.exists(pf_conf):
        if os.access(pf_conf, os.R_OK):
            try:
                content = Path(pf_conf).read_text(errors='replace')
                active_lines = [
                    l.strip() for l in content.splitlines()
                    if l.strip() and not l.strip().startswith('#')
                ]
                if not active_lines:
                    results.append({
                        'severity': 'MEDIUM',
                        'title': 'PF_FIREWALL_NOT_CONFIGURED',
                        'detail': {
                            'path': pf_conf,
                            'reason': '/etc/pf.conf exists but contains no active rules',
                        },
                        'host': _h,
                        'port': _p,
                    })
                else:
                    pass_all = [
                        l for l in active_lines
                        if re.match(r'^pass\s+all\b', l, re.IGNORECASE)
                    ]
                    if pass_all:
                        results.append({
                            'severity': 'HIGH',
                            'title': 'PF_PASS_ALL_RULE',
                            'detail': {
                                'path': pf_conf,
                                'matching_lines': pass_all,
                                'reason': (
                                    '"pass all" rule with no qualifiers allows unrestricted '
                                    'inbound and outbound traffic through pf'
                                ),
                            },
                            'host': _h,
                            'port': _p,
                        })
            except Exception:
                pass
    else:
        results.append({
            'severity': 'MEDIUM',
            'title': 'PF_FIREWALL_NOT_CONFIGURED',
            'detail': {
                'path': pf_conf,
                'reason': '/etc/pf.conf absent — pf has no defined ruleset loaded',
            },
            'host': _h,
            'port': _p,
        })

    return results


def check_macos_keychain_exposure() -> list:
    """
    Credential file and keychain permission checks via filesystem reads.
    No subprocess — stat(2) on keychain files, read .netrc and Chrome Login Data path.

    Sources:
      Mac Security Bible Ch5 (Keychain architecture, ~/Library/Keychains, /Library/Keychains,
      System.keychain root ownership, login.keychain-db 0o600 expectation)
      Mac Security Bible Ch120-125 (file encryption, plaintext credential risk, .netrc)
      Mac Security Bible Ch7 (browser credential storage, remote login credential files)

    Checks:
      - ~/Library/Keychains/*.keychain-db with world-read bit = HIGH KEYCHAIN_WORLD_READABLE
      - /Library/Keychains/System.keychain writable by non-root = MEDIUM SYSTEM_KEYCHAIN_WRITABLE
      - ~/Library/Application Support/Google/Chrome/Default/Login Data present = MEDIUM CHROME_CREDENTIALS_FILE
      - ~/.netrc with machine/login/password directives = CRITICAL NETRC_CREDENTIALS_EXPOSED

    Note: keychain content enumeration via 'security' commands is covered by
    MacOSSysadminEnumerator.check_keychain() and scan_keychain_accessible().

    Returns:
        list of {severity, title, detail, host, port} dicts.
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    # User keychain files — expected mode 0o600 (owner rw only)
    # Source: Mac Security Bible Ch5 — login.keychain-db is the primary user credential store
    kc_dir = os.path.expanduser('~/Library/Keychains')
    if os.path.isdir(kc_dir):
        try:
            for entry in Path(kc_dir).rglob('*.keychain-db'):
                try:
                    mode = os.stat(entry).st_mode & 0o777
                    if mode & 0o004:  # world-readable bit
                        results.append({
                            'severity': 'HIGH',
                            'title': 'KEYCHAIN_WORLD_READABLE',
                            'detail': {
                                'path': str(entry),
                                'mode_octal': oct(mode),
                                'reason': (
                                    'Keychain db is world-readable; any local user can '
                                    'copy and attempt offline bruteforce via login password'
                                ),
                            },
                            'host': _h,
                            'port': _p,
                        })
                except OSError:
                    pass
        except Exception:
            pass

    # System.keychain — root-owned, should not be group/world writable
    # Source: Mac Security Bible Ch5 — System.keychain holds system-level TLS certs and keys
    sys_kc = '/Library/Keychains/System.keychain'
    if os.path.exists(sys_kc):
        try:
            st = os.stat(sys_kc)
            mode = st.st_mode & 0o777
            if mode & 0o022:  # group or world write bit
                results.append({
                    'severity': 'MEDIUM',
                    'title': 'SYSTEM_KEYCHAIN_WRITABLE',
                    'detail': {
                        'path': sys_kc,
                        'mode_octal': oct(mode),
                        'uid': st.st_uid,
                        'gid': st.st_gid,
                        'reason': (
                            'System.keychain is group/world writable; '
                            'expected root:wheel 0o644 at most'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except OSError:
            pass

    # Chrome Login Data — SQLite file containing AES-encrypted saved passwords
    # Encryption key stored in Keychain; both files together = decryptable credentials
    # Source: Mac Security Bible Ch120 (browser credential storage, encryption key proximity)
    chrome_login = os.path.expanduser(
        '~/Library/Application Support/Google/Chrome/Default/Login Data'
    )
    if os.path.exists(chrome_login):
        try:
            sz = os.path.getsize(chrome_login)
            results.append({
                'severity': 'MEDIUM',
                'title': 'CHROME_CREDENTIALS_FILE',
                'detail': {
                    'path': chrome_login,
                    'size_bytes': sz,
                    'reason': (
                        'Chrome Login Data SQLite file present; contains encrypted saved passwords '
                        'whose AES key is stored in the login Keychain — decryptable by keychain owner'
                    ),
                },
                'host': _h,
                'port': _p,
            })
        except OSError:
            pass

    # ~/.netrc — machine/login/password triples in plaintext
    # Source: Mac Security Bible Ch7 — .netrc used by ftp/curl; no encryption
    netrc = os.path.expanduser('~/.netrc')
    if os.access(netrc, os.R_OK):
        try:
            content = Path(netrc).read_text(errors='replace')
            if re.search(r'^\s*(machine|login|password)\s+\S+', content, re.MULTILINE | re.IGNORECASE):
                machines = re.findall(r'(?im)^\s*machine\s+(\S+)', content)
                results.append({
                    'severity': 'CRITICAL',
                    'title': 'NETRC_CREDENTIALS_EXPOSED',
                    'detail': {
                        'path': netrc,
                        'machine_count': len(machines),
                        'machines': machines[:10],
                        'reason': (
                            '~/.netrc contains plaintext credentials; '
                            'readable by any process running as this user or as root'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except Exception:
            pass

    return results


def check_macos_network_settings() -> list:
    """
    Network configuration security checks via filesystem reads (no subprocess).

    Sources:
      Mac Security Bible Ch100 (SSL, DNS poisoning, hosts-file integrity)
      Mac Security Bible Ch114-119 (VPN, firewall tools, resolver configuration)
      Mac Security Bible Ch7 (SSH daemon supplemental hardening: X11, agent forwarding)

    Checks:
      - /etc/hosts: non-loopback 127.x entries or sensitive hostnames redirected = HIGH HOSTS_FILE_HIJACKED
      - /etc/resolv.conf: RFC1918 nameservers = MEDIUM SUSPICIOUS_NAMESERVERS
      - /Library/Little Snitch or /Library/Lulu presence = INFO HOST_FIREWALL_INSTALLED
      - /etc/ssh/sshd_config X11Forwarding yes = MEDIUM SSH_X11_FORWARDING_ENABLED
      - /etc/ssh/sshd_config AllowAgentForwarding yes = HIGH SSH_AGENT_FORWARDING_ENABLED

    Note: PermitRootLogin and PasswordAuthentication are covered by
    MacOSSysadminEnumerator.scan_ssh_config(); this function checks supplemental
    directives not examined there.

    Returns:
        list of {severity, title, detail, host, port} dicts.
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    # /etc/hosts hijack detection
    # Redirecting update/OCSP/git hosts to 127.x = common malware persistence and IR-evasion
    # Source: Mac Security Bible Ch100 — hosts-file poisoning as DNS bypass
    hosts_file = '/etc/hosts'
    _SENSITIVE_HOSTS = frozenset({
        'github.com', 'apple.com', 'icloud.com', 'ocsp.apple.com',
        'swscan.apple.com', 'mesu.apple.com', 'google.com',
        'software-update.apple.com', 'oscp.digicert.com',
    })
    _LOOPBACK_NAMES = frozenset({'localhost', 'broadcasthost', 'local', 'loopback', 'ip6-localhost'})
    if os.access(hosts_file, os.R_OK):
        try:
            content = Path(hosts_file).read_text(errors='replace')
            suspicious: list = []
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                parts = stripped.split()
                if len(parts) < 2:
                    continue
                ip, names = parts[0], parts[1:]
                # Non-standard 127.x mapping (not the canonical loopback names)
                if ip.startswith('127.') and not all(n in _LOOPBACK_NAMES for n in names):
                    suspicious.append({'ip': ip, 'names': names})
                # Sensitive hostname redirected to any non-loopback IP
                for name in names:
                    if name.lower().rstrip('.') in _SENSITIVE_HOSTS and not ip.startswith('127.'):
                        suspicious.append({'ip': ip, 'names': names, 'flag': 'sensitive_host_redirected'})
            if suspicious:
                results.append({
                    'severity': 'HIGH',
                    'title': 'HOSTS_FILE_HIJACKED',
                    'detail': {
                        'path': hosts_file,
                        'suspicious_entries': suspicious,
                        'reason': (
                            'Non-standard 127.x entries or known hosts redirected; '
                            'potential update-blocking or OCSP-stapling bypass'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except Exception:
            pass

    # /etc/resolv.conf nameserver check
    # RFC1918 nameservers are not inherently malicious but indicate split-horizon DNS
    # Source: Mac Security Bible Ch100 — resolver config, DNS interception risk
    resolv_conf = '/etc/resolv.conf'
    _KNOWN_SAFE_NS = frozenset({
        '8.8.8.8', '8.8.4.4',              # Google
        '1.1.1.1', '1.0.0.1',              # Cloudflare
        '9.9.9.9', '149.112.112.112',      # Quad9
        '208.67.222.222', '208.67.220.220', # OpenDNS
    })
    _RFC1918 = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)')
    if os.access(resolv_conf, os.R_OK):
        try:
            content = Path(resolv_conf).read_text(errors='replace')
            nameservers: list = [
                m.group(1)
                for line in content.splitlines()
                for m in [re.match(r'^\s*nameserver\s+(\S+)', line)]
                if m
            ]
            unusual = [ns for ns in nameservers if ns not in _KNOWN_SAFE_NS and _RFC1918.match(ns)]
            if unusual:
                results.append({
                    'severity': 'MEDIUM',
                    'title': 'SUSPICIOUS_NAMESERVERS',
                    'detail': {
                        'path': resolv_conf,
                        'all_nameservers': nameservers,
                        'rfc1918_nameservers': unusual,
                        'reason': (
                            'RFC1918 nameservers in use; DNS responses are not from known-safe '
                            'public resolvers — split-horizon or interception possible'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except Exception:
            pass

    # Host-based firewall presence — Little Snitch and Lulu
    # Source: Mac Security Bible Ch119 (host-based outbound firewall tools on macOS)
    fw_tools: list = []
    _FW_PATHS = [
        ('Little Snitch', '/Library/Little Snitch'),
        ('Lulu',          '/Library/Lulu'),
        ('Lulu',          '/Applications/LuluHelper.app'),
        ('Little Snitch', '/Applications/Little Snitch Monitor.app'),
    ]
    seen: set = set()
    for name, path in _FW_PATHS:
        if os.path.exists(path) and name not in seen:
            fw_tools.append({'name': name, 'path': path})
            seen.add(name)
    if fw_tools:
        results.append({
            'severity': 'INFO',
            'title': 'HOST_FIREWALL_INSTALLED',
            'detail': {
                'tools': fw_tools,
                'reason': 'Host-based outbound firewall present; limits exfiltration surface',
            },
            'host': _h,
            'port': _p,
        })

    # sshd_config supplemental checks (X11Forwarding, AllowAgentForwarding)
    # PermitRootLogin / PasswordAuthentication / PermitEmptyPasswords already covered by
    # MacOSSysadminEnumerator.scan_ssh_config(); only check directives not examined there.
    # Source: Mac Security Bible Ch7 — X11 forwarding enables display hijack; agent forwarding
    # allows hop-host to reuse forwarded SSH credentials for lateral movement.
    sshd_paths = ['/etc/ssh/sshd_config', '/etc/sshd_config']
    sshd_content = ''
    sshd_path_used = ''
    for sp in sshd_paths:
        if os.access(sp, os.R_OK):
            try:
                sshd_content = Path(sp).read_text(errors='replace')
                sshd_path_used = sp
                break
            except Exception:
                pass

    if sshd_content:
        directives: dict = {}
        for line in sshd_content.splitlines():
            stripped = line.strip()
            if stripped.startswith('#') or not stripped:
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                directives[parts[0].lower()] = parts[1].strip()

        if directives.get('x11forwarding', '').lower() == 'yes':
            results.append({
                'severity': 'MEDIUM',
                'title': 'SSH_X11_FORWARDING_ENABLED',
                'detail': {
                    'path': sshd_path_used,
                    'directive': 'X11Forwarding yes',
                    'reason': (
                        'X11 forwarding allows connected clients to open windows on the '
                        'server display; exploitable for display hijack and keylogging'
                    ),
                },
                'host': _h,
                'port': _p,
            })

        if directives.get('allowagentforwarding', '').lower() == 'yes':
            results.append({
                'severity': 'HIGH',
                'title': 'SSH_AGENT_FORWARDING_ENABLED',
                'detail': {
                    'path': sshd_path_used,
                    'directive': 'AllowAgentForwarding yes',
                    'reason': (
                        'Agent forwarding allows a compromised intermediate host to '
                        'reuse the forwarded SSH-agent socket for lateral movement '
                        'to additional hosts without knowing the private key'
                    ),
                },
                'host': _h,
                'port': _p,
            })

    return results


def check_macos_tcc_exposure() -> list:
    """
    Detect readable TCC (Transparency, Consent, Control) databases and Full Disk Access indicators.

    Sources:
      Apple macOS and iOS System Administration Ch3 (TCC privacy framework, SIP, APFS)
      Mac Security Bible Ch9 (major macOS security features — permission gating)

    TCC.db is the SQLite database macOS uses to store per-app privacy permission grants,
    including Full Disk Access (kTCCServiceSystemPolicyAllFiles), Contacts, Camera,
    Microphone, Screen Recording, and Calendar. If readable from a non-root context the
    entire access table is enumerable: which processes hold which grants, and whether those
    grants were user-approved or MDM-provisioned.

    Checks:
      - ~/Library/Application Support/com.apple.TCC/TCC.db readable = CRITICAL TCC_DB_READABLE
      - /Library/Application Support/com.apple.TCC/TCC.db readable  = CRITICAL SYSTEM_TCC_DB_READABLE
      - Either TCC.db readable + SQLite magic (53 51 4c 69 74 65)   = CRITICAL TCC_DB_PARSEABLE
      - ~/.config/com.apple.security.plist or
        ~/Library/Preferences/com.apple.security.plist with
        full-disk-access=true                                        = HIGH    FULL_DISK_ACCESS_GRANTED

    Returns:
        list of {severity, title, detail, host, port} dicts.
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    home = os.path.expanduser('~')
    _SQLITE_MAGIC = b'SQLite'

    def _is_sqlite(path: str) -> bool:
        """Return True if path can be opened and begins with the SQLite magic header."""
        try:
            with open(path, 'rb') as fh:
                return fh.read(6) == _SQLITE_MAGIC
        except (OSError, IOError):
            return False

    # User TCC database — normally protected by SIP but readable after SIP disable or FDA grant
    user_tcc = os.path.join(home, 'Library', 'Application Support', 'com.apple.TCC', 'TCC.db')
    if os.access(user_tcc, os.R_OK):
        results.append({
            'severity': 'CRITICAL',
            'title': 'TCC_DB_READABLE',
            'detail': {
                'path': user_tcc,
                'reason': (
                    'User TCC database is readable; Full Disk Access grants and all '
                    'per-app privacy permissions (Contacts, Camera, Microphone, '
                    'Screen Recording, Calendar) are enumerable without privilege escalation. '
                    'SIP is likely disabled or FDA has been granted to the current process.'
                ),
            },
            'host': _h,
            'port': _p,
        })
        if _is_sqlite(user_tcc):
            results.append({
                'severity': 'CRITICAL',
                'title': 'TCC_DB_PARSEABLE',
                'detail': {
                    'path': user_tcc,
                    'reason': (
                        'TCC.db is a valid SQLite file accessible in user context; '
                        'the access table is directly queryable — '
                        'sqlite3 "TCC.db" "SELECT service,client,auth_value,auth_reason FROM access"'
                    ),
                },
                'host': _h,
                'port': _p,
            })

    # System TCC database — holds MDM-provisioned and system-wide grants
    system_tcc = '/Library/Application Support/com.apple.TCC/TCC.db'
    if os.access(system_tcc, os.R_OK):
        results.append({
            'severity': 'CRITICAL',
            'title': 'SYSTEM_TCC_DB_READABLE',
            'detail': {
                'path': system_tcc,
                'reason': (
                    'System-wide TCC database is readable; system-level privacy grants '
                    'including MDM-provisioned Full Disk Access and per-device enterprise '
                    'entitlements are enumerable from the current context'
                ),
            },
            'host': _h,
            'port': _p,
        })
        if _is_sqlite(system_tcc):
            results.append({
                'severity': 'CRITICAL',
                'title': 'TCC_DB_PARSEABLE',
                'detail': {
                    'path': system_tcc,
                    'reason': (
                        'System TCC.db is a valid SQLite file readable in current context; '
                        'enumerate system-wide grants with: '
                        r'sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" '
                        '"SELECT service,client,auth_value,auth_reason FROM access"'
                    ),
                },
                'host': _h,
                'port': _p,
            })

    # Full Disk Access indicator plist — may be written by MDM profiles or custom agents
    fda_plists = [
        os.path.join(home, '.config', 'com.apple.security.plist'),
        os.path.join(home, 'Library', 'Preferences', 'com.apple.security.plist'),
    ]
    for plist_path in fda_plists:
        if not os.access(plist_path, os.R_OK):
            continue
        try:
            with open(plist_path, 'rb') as fh:
                data = plistlib.load(fh)
            if data.get('full-disk-access') is True:
                results.append({
                    'severity': 'HIGH',
                    'title': 'FULL_DISK_ACCESS_GRANTED',
                    'detail': {
                        'path': plist_path,
                        'reason': (
                            'Plist declares full-disk-access=true; this process or '
                            'profile has been granted FDA outside the standard TCC prompt, '
                            'bypassing per-directory consent and granting read access to '
                            'Mail, Messages, Safari history, and all user directories'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
                break
        except Exception:
            pass

    return results


def check_macos_esf_endpoint_security() -> list:
    """
    Detect system extensions, ESF (Endpoint Security Framework) indicators, and
    unified logging / crash report exposure.

    Sources:
      Apple macOS and iOS System Administration Ch3 (SIP, security subsystems)
      Mac Security Bible Ch9 (major macOS security features — security framework)

    The Endpoint Security Framework (ESF) provides kernel-adjacent event subscription
    for security tools (EDR, AV, sandbox monitoring). System extensions using ESF are
    loaded into userspace with elevated trust adjacent to the kernel and can intercept
    every process exec, file open, network connection, and authentication event on the host.

    Third-party ESF subscribers on a compromised host are dual-purpose signals: (1) an IR
    indicator that active monitoring is present, and (2) a potential interception vector if
    the extension itself is compromised or is the implant.

    Checks:
      - /Library/SystemExtensions/: .systemextension bundles present
          = MEDIUM SYSTEM_EXTENSION_INSTALLED
      - Bundle IDs not starting with com.apple.
          = HIGH   THIRD_PARTY_SYSTEM_EXTENSION
      - /var/db/diagnostics/ world-readable (other read bit set)
          = MEDIUM UNIFIED_LOGS_WORLD_READABLE
      - /private/var/log/DiagnosticReports/*.crash readable
          = MEDIUM CRASH_REPORTS_ACCESSIBLE

    Returns:
        list of {severity, title, detail, host, port} dicts.
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    # System extensions — stored under per-container UUID subdirectories
    sysext_root = '/Library/SystemExtensions'
    sysext_bundles: list = []
    if os.path.isdir(sysext_root):
        try:
            for container in os.scandir(sysext_root):
                if not container.is_dir(follow_symlinks=False):
                    continue
                try:
                    for entry in os.scandir(container.path):
                        if entry.name.endswith('.systemextension') and entry.is_dir(follow_symlinks=False):
                            sysext_bundles.append(entry.path)
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass

    if sysext_bundles:
        results.append({
            'severity': 'MEDIUM',
            'title': 'SYSTEM_EXTENSION_INSTALLED',
            'detail': {
                'count': len(sysext_bundles),
                'paths': sysext_bundles[:10],
                'reason': (
                    'System extensions run kernel-adjacent userspace code with elevated '
                    'trust; DriverKit extensions control hardware I/O, NetworkExtension '
                    'intercepts traffic, and ESF subscribers receive every process exec, '
                    'file open, and authentication event before it reaches the application'
                ),
            },
            'host': _h,
            'port': _p,
        })

        # Third-party detection via Contents/Info.plist CFBundleIdentifier
        third_party: list = []
        for bundle_path in sysext_bundles:
            info_plist = os.path.join(bundle_path, 'Contents', 'Info.plist')
            if not os.access(info_plist, os.R_OK):
                continue
            try:
                with open(info_plist, 'rb') as fh:
                    info = plistlib.load(fh)
                bundle_id = info.get('CFBundleIdentifier', '')
                if bundle_id and not bundle_id.startswith('com.apple.'):
                    parts = bundle_id.split('.')
                    vendor = parts[1] if len(parts) > 1 else bundle_id
                    third_party.append({
                        'bundle_id': bundle_id,
                        'vendor': vendor,
                        'path': bundle_path,
                    })
            except Exception:
                pass

        if third_party:
            results.append({
                'severity': 'HIGH',
                'title': 'THIRD_PARTY_SYSTEM_EXTENSION',
                'detail': {
                    'count': len(third_party),
                    'extensions': third_party[:10],
                    'reason': (
                        'Third-party system extensions are external code with near-kernel '
                        'privileges; an ESF subscriber can observe every process exec, '
                        'file open, and network connection on the host. Presence on a '
                        'compromised system indicates persistent process-level visibility '
                        'by a non-Apple vendor — assess whether the vendor is expected '
                        'and whether the extension is still the original signed binary'
                    ),
                },
                'host': _h,
                'port': _p,
            })

    # Unified log diagnostics directory world-readable check
    # /var/db/diagnostics holds the binary .tracev3 Unified Log store files
    diag_path = '/var/db/diagnostics'
    if os.path.exists(diag_path):
        try:
            st = os.stat(diag_path)
            if st.st_mode & stat.S_IROTH:
                results.append({
                    'severity': 'MEDIUM',
                    'title': 'UNIFIED_LOGS_WORLD_READABLE',
                    'detail': {
                        'path': diag_path,
                        'mode': oct(stat.S_IMODE(st.st_mode)),
                        'reason': (
                            'Unified log store is world-readable; macOS unified logs '
                            '(.tracev3 files) contain process exec events, network '
                            'connections, authentication attempts, XPC calls, and kernel '
                            'messages accessible to any local process without the '
                            'com.apple.private.logging.admin entitlement'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except (PermissionError, OSError):
            pass

    # Crash reports — binary execution traces with stack frames, register state, memory maps
    crash_dirs = [
        '/private/var/log/DiagnosticReports',
        os.path.join(os.path.expanduser('~'), 'Library', 'Logs', 'DiagnosticReports'),
    ]
    crash_files: list = []
    for crash_dir in crash_dirs:
        if not os.path.isdir(crash_dir):
            continue
        try:
            for entry in os.scandir(crash_dir):
                if entry.name.endswith('.crash') and entry.is_file(follow_symlinks=False):
                    if os.access(entry.path, os.R_OK):
                        crash_files.append(entry.path)
        except (PermissionError, OSError):
            pass

    if crash_files:
        results.append({
            'severity': 'MEDIUM',
            'title': 'CRASH_REPORTS_ACCESSIBLE',
            'detail': {
                'count': len(crash_files),
                'sample': crash_files[:5],
                'reason': (
                    'Crash reports (.crash) contain binary execution traces including '
                    'stack frames, register state, memory region maps, and loaded '
                    'dylib paths at time of crash; readable crash files expose internal '
                    'application structure, security tool behavior patterns, and '
                    'system process state useful for exploit development'
                ),
            },
            'host': _h,
            'port': _p,
        })

    return results


def check_macos_sip_status() -> list:
    """SIP (System Integrity Protection) integrity checks.

    Stdlib only (os, stat). No subprocess.
    Source: Mac Security Bible (Kissell, Wiley 2010)
      Ch1.2 Major Mac OS X Security Features (application signing, access permissions,
             download tagging — precursor mechanisms to SIP protection boundary)
      Ch10.4 Protecting Yourself from Harmful Downloads (OS integrity, quarantine metadata)
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    # SIP rootless configuration — presence confirms SIP framework is loaded and enumerates
    # the exact set of protected paths (useful for path-specific bypass planning)
    rootless_conf = '/System/Library/Sandbox/rootless.conf'
    if os.path.exists(rootless_conf):
        results.append({
            'severity': 'INFO',
            'title': 'SIP_CONFIG_READABLE',
            'detail': {
                'path': rootless_conf,
                'reason': (
                    'SIP rootless config is accessible; rootless.conf enumerates all '
                    'paths protected by SIP and is present when SIP is active; '
                    'accessible configuration reveals the exact boundary of SIP '
                    'protection for path-specific bypass planning'
                ),
            },
            'host': _h,
            'port': _p,
        })

    # SIP preference plist — contains csr-active-config flags written by csrutil in
    # recovery mode; reveals which SIP subsystems are selectively disabled
    sip_plist = '/Library/Preferences/com.apple.security.plist'
    if os.path.exists(sip_plist):
        try:
            st = os.stat(sip_plist)
            if st.st_mode & stat.S_IROTH:
                results.append({
                    'severity': 'MEDIUM',
                    'title': 'SIP_PREF_READABLE',
                    'detail': {
                        'path': sip_plist,
                        'mode': oct(stat.S_IMODE(st.st_mode)),
                        'reason': (
                            'SIP preference file is world-readable; '
                            'com.apple.security.plist encodes csr-active-config flags '
                            'that reveal which SIP subsystems are disabled '
                            '(e.g. CSR_ALLOW_UNTRUSTED_KEXTS, CSR_ALLOW_TASK_FOR_PID, '
                            'CSR_ALLOW_KERNEL_DEBUGGER); readable plist confirms SIP '
                            'configuration state without requiring a root context'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except (PermissionError, OSError):
            pass

    # Kernel directory writability — SIP enforces immutability of /System/Library/Kernels
    # even for root; writability here means SIP is disabled or recovery-mode bypass applied
    kernel_dir = '/System/Library/Kernels'
    if os.path.isdir(kernel_dir) and os.access(kernel_dir, os.W_OK):
        results.append({
            'severity': 'CRITICAL',
            'title': 'KERNEL_DIR_WRITABLE',
            'detail': {
                'path': kernel_dir,
                'reason': (
                    'SIP may be disabled: kernel directory is writable by current user; '
                    'SIP protects /System/Library/Kernels from modification even as root '
                    '— a writable kernel dir means SIP is fully disabled or a recovery-mode '
                    'csrutil bypass was applied; attacker can replace or inject into '
                    'kernelcache, install a persistent rootkit, or disable security '
                    'extensions with no further privilege escalation required'
                ),
            },
            'host': _h,
            'port': _p,
        })

    # /System directory writability — top-level SIP protection boundary; macOS 11+ additionally
    # seals /System as a cryptographically signed read-only volume (SSV)
    system_dir = '/System'
    if os.path.isdir(system_dir) and os.access(system_dir, os.W_OK):
        results.append({
            'severity': 'CRITICAL',
            'title': 'SYSTEM_DIR_WRITABLE',
            'detail': {
                'path': system_dir,
                'reason': (
                    'SIP disabled: /System is writable by current user; SIP enforces an '
                    'immutable /System volume via the Signed System Volume seal in macOS '
                    '11+; writability here means SIP is fully disabled, the SSV seal is '
                    'broken, or the Mac is booted from a degraded or compromised volume; '
                    'full /System write access enables persistent implant installation, '
                    'dyld injection into system processes, and OS modification that '
                    'survives reboots'
                ),
            },
            'host': _h,
            'port': _p,
        })

    return results


def check_macos_gatekeeper_config() -> list:
    """Gatekeeper and application quarantine configuration checks.

    Stdlib only (os, stat, plistlib). No subprocess.
    Source: Mac Security Bible (Kissell, Wiley 2010)
      Ch1.2.9 Download tagging (com.apple.quarantine xattr, origin URL tagging)
      Ch1.2.10 Application signing (code-signature verification at launch)
      Ch10.4 Protecting Yourself from Harmful Downloads (quarantine database,
              disk image first-run alerts, AppleDouble resource fork containers)
      Ch14.4 Common-Sense Malware Protection (Gatekeeper behavioral controls,
              download source trust evaluation)
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    # Gatekeeper auto-rearm check — GKAutoRearm=False disables periodic re-validation
    # of previously approved applications (breaks post-install trojanization detection)
    gk_plist_path = '/Library/Preferences/com.apple.security.plist'
    if os.path.exists(gk_plist_path):
        try:
            with open(gk_plist_path, 'rb') as fh:
                gk_data = plistlib.load(fh)
            auto_rearm = gk_data.get('GKAutoRearm', True)
            if auto_rearm is False or auto_rearm == 0:
                results.append({
                    'severity': 'HIGH',
                    'title': 'GATEKEEPER_AUTOREARM_DISABLED',
                    'detail': {
                        'path': gk_plist_path,
                        'key': 'GKAutoRearm',
                        'value': auto_rearm,
                        'reason': (
                            'Gatekeeper auto-rearm is disabled; GKAutoRearm=false means '
                            'macOS does not re-check quarantine flags after the first user '
                            'approval — any app approved once runs without re-validation '
                            'even if later modified or replaced; disables the periodic '
                            'integrity re-check that catches post-install trojanization '
                            'and supply-chain substitution attacks'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except (PermissionError, OSError, plistlib.InvalidFileException, Exception):
            pass

    # Quarantine database — records every downloaded app with origin URL, download timestamp,
    # and user approval state; readable copy exposes full software installation history
    quarantine_plist = os.path.join(
        os.path.expanduser('~'),
        'Library', 'Preferences', 'com.apple.LaunchServices',
        'com.apple.launchservices.secure.plist',
    )
    if os.path.exists(quarantine_plist):
        try:
            st = os.stat(quarantine_plist)
            if os.access(quarantine_plist, os.R_OK):
                results.append({
                    'severity': 'MEDIUM',
                    'title': 'QUARANTINE_DB_ACCESSIBLE',
                    'detail': {
                        'path': quarantine_plist,
                        'mode': oct(stat.S_IMODE(st.st_mode)),
                        'reason': (
                            'App quarantine history plist is readable; '
                            'com.apple.launchservices.secure.plist records every '
                            'quarantined application including origin URL, download '
                            'timestamp, and user approval state; readable quarantine '
                            'history reveals installed software inventory, browser '
                            'download behavior, and approved-but-suspicious apps '
                            'useful for targeted social engineering and lateral '
                            'movement planning'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except (PermissionError, OSError):
            pass

    # Gatekeeper policy database — SQLite file containing all enforcement rules,
    # code-signing requirement strings, and user-approved exceptions
    gk_db = '/private/var/db/SystemPolicy'
    if os.path.exists(gk_db):
        try:
            if os.access(gk_db, os.R_OK):
                results.append({
                    'severity': 'HIGH',
                    'title': 'GATEKEEPER_DB_READABLE',
                    'detail': {
                        'path': gk_db,
                        'reason': (
                            'Gatekeeper policy database is readable; SystemPolicy is an '
                            'SQLite database containing all Gatekeeper enforcement rules, '
                            'code-signing requirement strings, and user-approved exceptions; '
                            'read access exposes the exact rule set Gatekeeper uses for '
                            'allow/deny decisions and reveals any weakened or custom '
                            'policies exploitable to bypass code-signing enforcement'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
        except (PermissionError, OSError):
            pass

    # AppleDouble (/._) files — quarantine xattr containers written by Safari, Mail, iChat
    # when tagging downloaded files; world-readable copies expose origin URL and quarantine state
    scan_dirs = [
        os.path.expanduser('~/Downloads'),
        '/tmp',
        '/private/tmp',
    ]
    apple_double_files: list = []
    for scan_dir in scan_dirs:
        if not os.path.isdir(scan_dir):
            continue
        try:
            for entry in os.scandir(scan_dir):
                if entry.name.startswith('._') and entry.is_file(follow_symlinks=False):
                    try:
                        st = entry.stat(follow_symlinks=False)
                        if st.st_mode & stat.S_IROTH:
                            apple_double_files.append(entry.path)
                    except (PermissionError, OSError):
                        pass
        except (PermissionError, OSError):
            pass

    if apple_double_files:
        results.append({
            'severity': 'MEDIUM',
            'title': 'QUARANTINE_XATTR_METADATA',
            'detail': {
                'count': len(apple_double_files),
                'sample': apple_double_files[:5],
                'reason': (
                    'World-readable AppleDouble (._) files found in download staging '
                    'directories; ._ files are AppleDouble resource fork containers that '
                    'store com.apple.quarantine xattr data (origin URL, download agent, '
                    'timestamp, and quarantine flags) as a portable binary blob; readable '
                    'metadata reveals browser/app download provenance and quarantine '
                    'bypass state for each associated file'
                ),
            },
            'host': _h,
            'port': _p,
        })

    return results


def probe_mdm_enrollment_server(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe MDM enrollment and management endpoints for unauthenticated access."""
    import ssl
    import urllib.request

    results = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    checks = [
        (
            f'https://{host}:443/mdm/enroll',
            'HIGH',
            'MDM_ENROLL_ENDPOINT',
            'MDM enrollment endpoint accessible',
            443,
        ),
        (
            f'https://{host}:443/.well-known/apple-mdm',
            'HIGH',
            'MDM_DISCOVERY_ENDPOINT',
            'Apple MDM discovery document accessible',
            443,
        ),
        (
            f'https://{host}:443/api/v1/mdm/devices',
            'CRITICAL',
            'MDM_DEVICE_LIST_UNAUTH',
            'MDM managed device list accessible without authentication',
            443,
        ),
        (
            f'https://{host}:8443/api/v1/policies',
            'CRITICAL',
            'MDM_POLICIES_UNAUTH',
            'MDM policy configuration accessible (contains device restrictions and certificates)',
            8443,
        ),
    ]

    for url, severity, title, detail, endpoint_port in checks:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status < 500:
                    results.append({
                        'severity': severity,
                        'title': title,
                        'detail': detail,
                        'host': host,
                        'port': endpoint_port,
                    })
        except Exception:
            pass

    return results


def probe_macos_remote_management(host: str, port: int = 5900, timeout: float = 5.0) -> list:
    """Probe macOS remote management ports (ARD, VNC, SSH, AFP)."""
    import socket

    results = []

    checks = [
        (
            5900,
            'HIGH',
            'ARD_VNC_EXPOSED',
            'Apple Remote Desktop VNC port accepting connections',
            b'RFB',
        ),
        (
            22,
            'HIGH',
            'SSH_MACOS_EXPOSED',
            'macOS SSH server accessible',
            b'SSH',
        ),
        (
            3283,
            'HIGH',
            'ARD_MAIN_PORT_EXPOSED',
            'Apple Remote Desktop management port open',
            None,
        ),
        (
            548,
            'MEDIUM',
            'AFP_SERVER_EXPOSED',
            'Apple Filing Protocol server accessible (legacy file sharing)',
            None,
        ),
    ]

    for check_port, severity, title, detail, banner_prefix in checks:
        try:
            with socket.create_connection((host, check_port), timeout=timeout) as s:
                banner = b''
                if banner_prefix is not None:
                    try:
                        s.settimeout(timeout)
                        banner = s.recv(64)
                    except Exception:
                        pass
                    if banner_prefix and banner_prefix not in banner:
                        continue
                results.append({
                    'severity': severity,
                    'title': title,
                    'detail': detail,
                    'host': host,
                    'port': check_port,
                })
        except Exception:
            pass

    return results


def check_macos_privacy_tcc_apps() -> list:
    """
    Detect overpermissioned apps in macOS TCC (Transparency, Consent, Control)
    database by querying via the sqlite3 command-line binary.

    Sources:
      Mac Security Bible Ch14 (spyware/keyloggers silently accessing mic, camera, screen)
      Mac Security Bible Ch9 (macOS privacy framework — per-app permission gating via TCC)

    Executes: sqlite3 -separator '|' <TCC.db> 'SELECT service,client FROM access WHERE auth_value=2'
    Falls back to 'WHERE allowed=1' for pre-Catalina schema (where column was boolean 'allowed').

    Flags per-service:
      kTCCServiceCamera / kTCCServiceMicrophone     -> MEDIUM  TCC_CAMERA_MIC_PERMISSION
      kTCCServiceScreenCapture                      -> HIGH    TCC_SCREEN_CAPTURE_PERMISSION
      kTCCServiceAccessibility                      -> CRITICAL TCC_ACCESSIBILITY_PERMISSION
      kTCCServiceAppleEvents                        -> HIGH    TCC_APPLE_EVENTS_PERMISSION
      kTCCServiceSystemPolicyAllFiles               -> CRITICAL TCC_FULL_DISK_ACCESS
    Apps with >5 granted permissions across both DBs -> HIGH   TCC_OVER_PERMISSIONED_APP

    Returns:
        list of {severity, title, detail, host, port} dicts.
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    SERVICE_MAP: dict = {
        'kTCCServiceCamera':               ('MEDIUM',   'TCC_CAMERA_MIC_PERMISSION'),
        'kTCCServiceMicrophone':           ('MEDIUM',   'TCC_CAMERA_MIC_PERMISSION'),
        'kTCCServiceScreenCapture':        ('HIGH',     'TCC_SCREEN_CAPTURE_PERMISSION'),
        'kTCCServiceAccessibility':        ('CRITICAL', 'TCC_ACCESSIBILITY_PERMISSION'),
        'kTCCServiceAppleEvents':          ('HIGH',     'TCC_APPLE_EVENTS_PERMISSION'),
        'kTCCServiceSystemPolicyAllFiles': ('CRITICAL', 'TCC_FULL_DISK_ACCESS'),
    }

    home = os.path.expanduser('~')
    tcc_candidates = [
        (os.path.join(home, 'Library', 'Application Support', 'com.apple.TCC', 'TCC.db'), 'user'),
        ('/Library/Application Support/com.apple.TCC/TCC.db', 'system'),
    ]

    def _query_tcc(db_path: str) -> list:
        """Query TCC.db via sqlite3 CLI; returns list of (service, client) pairs."""
        if not os.path.exists(db_path):
            return []
        # Try Catalina+ schema first (auth_value=2 means granted),
        # fall back to pre-Catalina boolean allowed=1.
        for where_clause in (
            'SELECT service,client FROM access WHERE auth_value=2',
            'SELECT service,client FROM access WHERE allowed=1',
        ):
            rc, out, _ = _run(
                ['sqlite3', '-separator', '|', db_path, where_clause],
                timeout=5,
            )
            if rc == 0:
                rows = []
                for line in out.splitlines():
                    parts = line.split('|')
                    if len(parts) >= 2:
                        rows.append((parts[0].strip(), parts[1].strip()))
                return rows
        return []

    app_grant_counts: dict = {}

    for db_path, scope in tcc_candidates:
        rows = _query_tcc(db_path)
        for service, client in rows:
            app_grant_counts[client] = app_grant_counts.get(client, 0) + 1
            if service in SERVICE_MAP:
                severity, title = SERVICE_MAP[service]
                results.append({
                    'severity': severity,
                    'title': title,
                    'detail': {
                        'db': db_path,
                        'scope': scope,
                        'service': service,
                        'client': client,
                        'note': (
                            'TCC permission granted; spyware using this service can silently '
                            'access the resource without visible UI indicator '
                            '(Mac Security Bible Ch14 — spyware/keylogger access vectors)'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })

    for app, count in app_grant_counts.items():
        if count > 5:
            results.append({
                'severity': 'HIGH',
                'title': 'TCC_OVER_PERMISSIONED_APP',
                'detail': {
                    'client': app,
                    'granted_permission_count': count,
                    'note': (
                        'Application holds >5 TCC grants across user and system databases — '
                        'atypical breadth; warrants review for trojan or spyware characteristics '
                        '(Mac Security Bible Ch14.1 — trojan horses bundling broad access)'
                    ),
                },
                'host': _h,
                'port': _p,
            })

    return results


def check_macos_malware_persistence() -> list:
    """
    Detect suspicious LaunchAgent and LaunchDaemon persistence entries indicative
    of trojan, spyware, or zombie software installation.

    Sources:
      Mac Security Bible Ch14.1 (trojan horses, spyware, zombie software, keyloggers)
      Mac Security Bible Ch14.6 (outbound firewalls — programs phoning home)

    Scans standard persistence directories for plist files and inspects:
      ProgramArguments pointing to /tmp, /var/tmp or hidden dotfile paths
        -> HIGH    SUSPICIOUS_PERSISTENCE_TMPPATH
      ProgramArguments with download utilities combined with inline-exec flags
        (curl, wget, python -c, bash -c, base64 -d, http://)
        -> CRITICAL MALWARE_DOWNLOAD_PERSISTENCE
      Inline base64/eval/exec obfuscation in arguments
        -> CRITICAL OBFUSCATED_PERSISTENCE_PAYLOAD
      Binary in a hidden (dotfile) directory outside standard system prefixes
        -> HIGH    UNUSUAL_BINARY_PATH
      World-writable plist file (any local user can hijack the persistence entry)
        -> HIGH    WORLD_WRITABLE_LAUNCHAGENT

    Directories checked:
      ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons

    Returns:
        list of {severity, title, detail, host, port} dicts.
    """
    results: list = []
    _h = 'localhost'
    _p = 0

    home = os.path.expanduser('~')

    SCAN_DIRS = [
        (os.path.join(home, 'Library', 'LaunchAgents'), 'user_agent'),
        ('/Library/LaunchAgents', 'system_agent'),
        ('/Library/LaunchDaemons', 'system_daemon'),
    ]

    _DOWNLOAD_TOOLS = re.compile(r'\b(curl|wget|python3?|ruby|perl|bash|sh)\b')
    _EXEC_FLAGS     = re.compile(r'(-c\s|--exec\b|eval|base64\s+-d|/dev/stdin|https?://)')
    _TEMP_PATHS     = re.compile(r'^(/private)?/var/(tmp|folders)|^/tmp/')
    _HIDDEN_PATH    = re.compile(r'(/\.[^/]+/|/\.[^/]+$)')
    _LEGIT_PREFIXES = (
        '/usr/', '/bin/', '/sbin/', '/System/', '/Applications/',
        '/Library/Apple/', '/opt/homebrew/', '/opt/local/',
    )

    for scan_dir, scope in SCAN_DIRS:
        if not os.path.isdir(scan_dir):
            continue
        try:
            entries = os.listdir(scan_dir)
        except OSError:
            continue

        for fname in entries:
            if not fname.endswith('.plist'):
                continue
            plist_path = os.path.join(scan_dir, fname)
            if not os.access(plist_path, os.R_OK):
                continue

            # World-writable plist = any user can replace the binary path
            try:
                mode = os.stat(plist_path).st_mode
                if mode & stat.S_IWOTH:
                    results.append({
                        'severity': 'HIGH',
                        'title': 'WORLD_WRITABLE_LAUNCHAGENT',
                        'detail': {
                            'path': plist_path,
                            'scope': scope,
                            'mode': oct(mode),
                            'note': (
                                'World-writable persistence plist; any local user can '
                                'replace ProgramArguments to hijack execution at next login'
                            ),
                        },
                        'host': _h,
                        'port': _p,
                    })
            except OSError:
                pass

            plist = _read_plist(plist_path)
            if not plist:
                continue

            prog_args    = plist.get('ProgramArguments', [])
            program      = plist.get('Program', '')
            run_at_load  = plist.get('RunAtLoad', False)
            binary       = (prog_args[0] if prog_args else program) or ''
            all_args     = ' '.join(str(a) for a in prog_args)

            if not binary:
                continue

            # Binary in temp/volatile path — classic trojan drop location
            if _TEMP_PATHS.search(binary):
                results.append({
                    'severity': 'HIGH',
                    'title': 'SUSPICIOUS_PERSISTENCE_TMPPATH',
                    'detail': {
                        'path': plist_path,
                        'scope': scope,
                        'binary': binary,
                        'run_at_load': run_at_load,
                        'note': (
                            'Persistence agent binary in temp/volatile path — '
                            'consistent with trojan dropper staging '
                            '(Mac Security Bible Ch14.1)'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })

            # Download-then-execute chain in args
            if _DOWNLOAD_TOOLS.search(all_args) and _EXEC_FLAGS.search(all_args):
                results.append({
                    'severity': 'CRITICAL',
                    'title': 'MALWARE_DOWNLOAD_PERSISTENCE',
                    'detail': {
                        'path': plist_path,
                        'scope': scope,
                        'args': all_args[:256],
                        'run_at_load': run_at_load,
                        'note': (
                            'Persistence plist executes download utility with inline execution '
                            'flag — consistent with zombie software or trojan dropper '
                            '(Mac Security Bible Ch14.1/14.5/14.6)'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })
            elif re.search(r'base64\s*-d|eval\s*\(|exec\s*\(|/dev/stdin', all_args):
                # Standalone obfuscation patterns not caught above
                results.append({
                    'severity': 'CRITICAL',
                    'title': 'OBFUSCATED_PERSISTENCE_PAYLOAD',
                    'detail': {
                        'path': plist_path,
                        'scope': scope,
                        'args': all_args[:256],
                        'run_at_load': run_at_load,
                        'note': (
                            'Persistence plist contains obfuscated payload (base64/eval/exec) '
                            '— consistent with rootkit or spyware hiding its dropper logic'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })

            # Binary in hidden dotfile directory outside known-good prefixes
            if _HIDDEN_PATH.search(binary) and not any(
                binary.startswith(p) for p in _LEGIT_PREFIXES
            ):
                results.append({
                    'severity': 'HIGH',
                    'title': 'UNUSUAL_BINARY_PATH',
                    'detail': {
                        'path': plist_path,
                        'scope': scope,
                        'binary': binary,
                        'run_at_load': run_at_load,
                        'note': (
                            'Persistence agent binary resides in a hidden dotfile directory — '
                            'common spyware/keylogger installation pattern '
                            '(Mac Security Bible Ch14.1.6/14.1.8)'
                        ),
                    },
                    'host': _h,
                    'port': _p,
                })

    return results


if __name__ == '__main__':
    enum = MacOSSysadminEnumerator()
    result = enum.run()
    print(enum.report())
    print(json.dumps({
        'summary': result['summary'],
        'user': result['user'],
        'uid': result['uid'],
        'is_root': result['is_root'],
    }, indent=2))
