#!/usr/bin/env python3
"""
Privilege Escalation Enumeration Module
Synthesized from: Hacking: The Art of Exploitation, Linux Privilege Escalation guides

Enumerate common privilege escalation vectors.
"""

import os
import subprocess
from pathlib import Path
import stat

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
        self.check_writable_paths()
        self.check_sudo_access()
        self.check_cron_jobs()
        self.check_capabilities()
        self.check_docker_group()
        self.check_kernel_exploits()
        
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
        try:
            with open('/proc/version') as f:
                kernel_version = f.read().strip()
            
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

if __name__ == '__main__':
    enum = PrivescEnumerator()
    enum.enumerate_all()
    print(enum.report())
