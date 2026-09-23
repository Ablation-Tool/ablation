#!/usr/bin/env python3
"""
Platform Detection Module
Synthesized from: Learning Linux Binary Analysis, Practical Binary Analysis, Hacking: The Art of Exploitation

Detects OS, architecture, kernel version, libc variant, and system capabilities.
"""

import os
import sys
import platform
import struct
import subprocess
from pathlib import Path

class PlatformDetector:
    def __init__(self):
        self.info = {}
        
    def detect_all(self):
        """Run all detection routines"""
        self.detect_os()
        self.detect_arch()
        self.detect_kernel()
        self.detect_libc()
        self.detect_capabilities()
        self.detect_security_features()
        return self.info
    
    def detect_os(self):
        """Detect operating system"""
        self.info['os'] = platform.system()
        self.info['os_release'] = platform.release()
        self.info['os_version'] = platform.version()
        
        # More specific detection
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('ID='):
                        self.info['distro'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('VERSION_ID='):
                        self.info['distro_version'] = line.split('=')[1].strip().strip('"')
        
        return self.info['os']
    
    def detect_arch(self):
        """Detect CPU architecture"""
        self.info['machine'] = platform.machine()
        self.info['processor'] = platform.processor()
        
        # Detect pointer size (32 vs 64 bit)
        self.info['pointer_size'] = struct.calcsize("P") * 8
        self.info['byte_order'] = sys.byteorder
        
        # Detailed architecture
        if self.info['machine'] in ['x86_64', 'AMD64']:
            self.info['arch_family'] = 'x86'
            self.info['arch_bits'] = 64
        elif self.info['machine'] in ['i386', 'i686']:
            self.info['arch_family'] = 'x86'
            self.info['arch_bits'] = 32
        elif 'arm' in self.info['machine'].lower() or 'aarch' in self.info['machine'].lower():
            self.info['arch_family'] = 'ARM'
            self.info['arch_bits'] = 64 if 'aarch64' in self.info['machine'] or 'arm64' in self.info['machine'] else 32
        elif 'mips' in self.info['machine'].lower():
            self.info['arch_family'] = 'MIPS'
        
        return self.info['machine']
    
    def detect_kernel(self):
        """Detect kernel version and features"""
        if self.info['os'] == 'Linux':
            self.info['kernel'] = platform.release()
            
            # Parse kernel version
            parts = self.info['kernel'].split('.')
            if len(parts) >= 2:
                self.info['kernel_major'] = int(parts[0])
                self.info['kernel_minor'] = int(parts[1])
                
            # Check kernel config if available
            config_paths = ['/proc/config.gz', '/boot/config-' + platform.release()]
            for path in config_paths:
                if os.path.exists(path):
                    self.info['kernel_config'] = path
                    break
                    
        return self.info.get('kernel')
    
    def detect_libc(self):
        """Detect libc variant and version"""
        try:
            # Try to detect glibc
            output = subprocess.check_output(['ldd', '--version'], stderr=subprocess.STDOUT, text=True)
            if 'GNU' in output:
                self.info['libc'] = 'glibc'
                # Extract version
                first_line = output.split('\n')[0]
                if ')' in first_line:
                    version = first_line.split(')')[1].strip()
                    self.info['libc_version'] = version
            elif 'musl' in output:
                self.info['libc'] = 'musl'
        except:
            pass
            
        # Check for other libc variants
        if os.path.exists('/lib/ld-musl-x86_64.so.1'):
            self.info['libc'] = 'musl'
        elif os.path.exists('/system/lib/libc.so'):
            self.info['libc'] = 'bionic'  # Android
            
        return self.info.get('libc')
    
    def detect_capabilities(self):
        """Detect system capabilities"""
        caps = {}
        
        # Check if running as root
        caps['is_root'] = os.geteuid() == 0
        
        # Check for ptrace capability
        try:
            if os.path.exists('/proc/sys/kernel/yama/ptrace_scope'):
                with open('/proc/sys/kernel/yama/ptrace_scope') as f:
                    caps['ptrace_scope'] = int(f.read().strip())
        except:
            pass
            
        # Check for common tools
        tools = ['gdb', 'strace', 'ltrace', 'objdump', 'readelf', 'nm', 'strings']
        caps['available_tools'] = [t for t in tools if self._command_exists(t)]
        
        self.info['capabilities'] = caps
        return caps
    
    def detect_security_features(self):
        """Detect security features (ASLR, NX, PIE, etc.)"""
        sec = {}
        
        if self.info['os'] == 'Linux':
            # Check ASLR
            try:
                with open('/proc/sys/kernel/randomize_va_space') as f:
                    aslr_level = int(f.read().strip())
                    sec['aslr'] = {0: 'disabled', 1: 'partial', 2: 'full'}.get(aslr_level, 'unknown')
            except:
                pass
                
            # Check if SELinux/AppArmor enabled
            sec['selinux'] = os.path.exists('/sys/fs/selinux')
            sec['apparmor'] = os.path.exists('/sys/kernel/security/apparmor')
            
        self.info['security'] = sec
        return sec
    
    def _command_exists(self, cmd):
        """Check if command exists in PATH"""
        try:
            subprocess.run([cmd, '--version'], capture_output=True, timeout=1)
            return True
        except:
            return False
    
    def report(self):
        """Generate human-readable report"""
        lines = []
        lines.append("=" * 60)
        lines.append("PLATFORM DETECTION REPORT")
        lines.append("=" * 60)
        lines.append(f"OS: {self.info.get('os')} {self.info.get('os_release', '')}")
        if 'distro' in self.info:
            lines.append(f"Distribution: {self.info['distro']} {self.info.get('distro_version', '')}")
        lines.append(f"Architecture: {self.info.get('machine')} ({self.info.get('arch_bits', '?')} bit)")
        lines.append(f"Byte Order: {self.info.get('byte_order')}")
        if 'kernel' in self.info:
            lines.append(f"Kernel: {self.info['kernel']}")
        if 'libc' in self.info:
            lines.append(f"libc: {self.info['libc']} {self.info.get('libc_version', '')}")
        
        if 'security' in self.info:
            lines.append("\nSecurity Features:")
            for k, v in self.info['security'].items():
                lines.append(f"  {k}: {v}")
                
        if 'capabilities' in self.info:
            caps = self.info['capabilities']
            lines.append("\nCapabilities:")
            lines.append(f"  Root: {caps.get('is_root', False)}")
            if 'available_tools' in caps and caps['available_tools']:
                lines.append(f"  Available tools: {', '.join(caps['available_tools'])}")
                
        lines.append("=" * 60)
        return "\n".join(lines)

if __name__ == '__main__':
    detector = PlatformDetector()
    detector.detect_all()
    print(detector.report())
    
    # Also print JSON for programmatic use
    import json
    print("\nJSON Output:")
    print(json.dumps(detector.info, indent=2))
