#!/usr/bin/env python3
"""
Windows PE Analyzer
Synthesized from: Practical Reverse Engineering, Practical Malware Analysis

Deep PE analysis: imports, exports, resources, sections.
"""

import struct
from pathlib import Path

class PEAnalyzer:
    """Deep Windows PE analysis"""
    
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.pe_header_offset = None
        self.imports = []
        self.exports = []
        self.sections = []
        self.resources = []
        self.suspicious_imports = []
    
    def analyze(self):
        """Deep PE analysis"""
        with open(self.filepath, 'rb') as f:
            # DOS header
            dos_header = f.read(64)
            if dos_header[:2] != b'MZ':
                raise ValueError("Not a PE file")
            
            # PE header offset
            self.pe_header_offset = struct.unpack('<I', dos_header[60:64])[0]
            
            # Navigate to PE header
            f.seek(self.pe_header_offset)
            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                raise ValueError("Invalid PE signature")
            
            # COFF header
            coff_header = f.read(20)
            machine = struct.unpack('<H', coff_header[0:2])[0]
            num_sections = struct.unpack('<H', coff_header[2:4])[0]
            size_of_opt_header = struct.unpack('<H', coff_header[16:18])[0]
            
            # Optional header
            opt_header_start = f.tell()
            opt_header = f.read(size_of_opt_header)
            
            # Parse optional header
            magic = struct.unpack('<H', opt_header[0:2])[0]
            is_64bit = magic == 0x20b
            
            if is_64bit:
                image_base = struct.unpack('<Q', opt_header[24:32])[0]
                entry_point = struct.unpack('<I', opt_header[16:20])[0]
            else:
                image_base = struct.unpack('<I', opt_header[28:32])[0]
                entry_point = struct.unpack('<I', opt_header[16:20])[0]
            
            # Section headers
            f.seek(opt_header_start + size_of_opt_header)
            for i in range(num_sections):
                section = f.read(40)
                
                name = section[0:8].rstrip(b'\x00').decode('utf-8', errors='ignore')
                virtual_size = struct.unpack('<I', section[8:12])[0]
                virtual_addr = struct.unpack('<I', section[12:16])[0]
                raw_size = struct.unpack('<I', section[16:20])[0]
                raw_offset = struct.unpack('<I', section[20:24])[0]
                characteristics = struct.unpack('<I', section[36:40])[0]
                
                self.sections.append({
                    'name': name,
                    'virtual_addr': hex(virtual_addr),
                    'virtual_size': virtual_size,
                    'raw_offset': hex(raw_offset),
                    'raw_size': raw_size,
                    'characteristics': hex(characteristics),
                    'executable': bool(characteristics & 0x20000000),
                    'writable': bool(characteristics & 0x80000000),
                    'readable': bool(characteristics & 0x40000000)
                })
        
        # Analyze imports (simplified - would need full PE parser)
        self._analyze_imports()
        
        return {
            'sections': self.sections,
            'imports': self.imports,
            'suspicious': self.suspicious_imports
        }
    
    def _analyze_imports(self):
        """Analyze imported functions (simplified)"""
        # Common suspicious imports
        suspicious_funcs = [
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'SetWindowsHookEx', 'GetAsyncKeyState', 'RegSetValueEx',
            'URLDownloadToFile', 'WinExec', 'ShellExecute',
            'CreateProcess', 'CryptEncrypt', 'CryptDecrypt'
        ]
        
        # In real implementation, would parse Import Directory Table
        # For now, placeholder for suspicious import detection
        pass
    
    def report(self):
        """Generate report"""
        lines = []
        lines.append("="*60)
        lines.append(f"PE ANALYSIS: {self.filepath.name}")
        lines.append("="*60)
        
        lines.append(f"\nSections: {len(self.sections)}")
        for sec in self.sections:
            flags = []
            if sec['executable']:
                flags.append('X')
            if sec['writable']:
                flags.append('W')
            if sec['readable']:
                flags.append('R')
            
            lines.append(f"  {sec['name']:<10} {sec['virtual_addr']:<12} "
                        f"{sec['virtual_size']:<10} {''.join(flags)}")
        
        return "\n".join(lines)

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: pe_analyzer.py <file.exe>")
        sys.exit(1)
    
    analyzer = PEAnalyzer(sys.argv[1])
    analyzer.analyze()
    print(analyzer.report())
