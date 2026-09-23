#!/usr/bin/env python3
"""
macOS Mach-O Analyzer
Synthesized from: macOS Internals, The Art of Mac Malware

Deep Mach-O analysis: load commands, segments, dylibs, code signing.
"""

import struct
from pathlib import Path

class MachoAnalyzer:
    """Deep macOS Mach-O analysis"""
    
    # Mach-O constants
    MH_MAGIC = 0xfeedface
    MH_CIGAM = 0xcefaedfe
    MH_MAGIC_64 = 0xfeedfacf
    MH_CIGAM_64 = 0xcffaedfe
    
    # Load commands
    LC_SEGMENT = 0x1
    LC_SYMTAB = 0x2
    LC_DYSYMTAB = 0xb
    LC_LOAD_DYLIB = 0xc
    LC_ID_DYLIB = 0xd
    LC_LOAD_DYLINKER = 0xe
    LC_SEGMENT_64 = 0x19
    LC_UUID = 0x1b
    LC_CODE_SIGNATURE = 0x1d
    LC_ENCRYPTION_INFO = 0x21
    LC_DYLD_INFO = 0x22
    LC_MAIN = 0x80000028
    
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.is_64bit = False
        self.is_little_endian = True
        self.segments = []
        self.dylibs = []
        self.load_commands = []
        self.code_signature = None
        self.encryption_info = None
        self.entry_point = None
    
    def analyze(self):
        """Deep Mach-O analysis"""
        with open(self.filepath, 'rb') as f:
            # Read magic
            magic_bytes = f.read(4)
            magic = struct.unpack('<I', magic_bytes)[0]
            
            # Determine architecture and endianness
            if magic == self.MH_MAGIC:
                self.is_64bit = False
                self.is_little_endian = True
            elif magic == self.MH_CIGAM:
                self.is_64bit = False
                self.is_little_endian = False
            elif magic == self.MH_MAGIC_64:
                self.is_64bit = True
                self.is_little_endian = True
            elif magic == self.MH_CIGAM_64:
                self.is_64bit = True
                self.is_little_endian = False
            else:
                raise ValueError("Not a Mach-O file")
            
            # Read header
            endian = '<' if self.is_little_endian else '>'
            
            cputype = struct.unpack(f'{endian}i', f.read(4))[0]
            cpusubtype = struct.unpack(f'{endian}i', f.read(4))[0]
            filetype = struct.unpack(f'{endian}I', f.read(4))[0]
            ncmds = struct.unpack(f'{endian}I', f.read(4))[0]
            sizeofcmds = struct.unpack(f'{endian}I', f.read(4))[0]
            flags = struct.unpack(f'{endian}I', f.read(4))[0]
            
            if self.is_64bit:
                reserved = struct.unpack(f'{endian}I', f.read(4))[0]
            
            # Parse load commands
            for i in range(ncmds):
                cmd_start = f.tell()
                
                cmd = struct.unpack(f'{endian}I', f.read(4))[0]
                cmdsize = struct.unpack(f'{endian}I', f.read(4))[0]
                
                self.load_commands.append({
                    'cmd': cmd,
                    'cmdsize': cmdsize,
                    'name': self._cmd_name(cmd)
                })
                
                # Parse specific commands
                if cmd == self.LC_SEGMENT or cmd == self.LC_SEGMENT_64:
                    self._parse_segment(f, cmd_start + 8, cmd == self.LC_SEGMENT_64, endian)
                
                elif cmd == self.LC_LOAD_DYLIB or cmd == self.LC_ID_DYLIB:
                    self._parse_dylib(f, cmd_start + 8, cmdsize - 8, endian)
                
                elif cmd == self.LC_MAIN:
                    entryoff = struct.unpack(f'{endian}Q', f.read(8))[0]
                    self.entry_point = entryoff
                
                elif cmd == self.LC_CODE_SIGNATURE:
                    dataoff = struct.unpack(f'{endian}I', f.read(4))[0]
                    datasize = struct.unpack(f'{endian}I', f.read(4))[0]
                    self.code_signature = {
                        'offset': hex(dataoff),
                        'size': datasize
                    }
                
                elif cmd == self.LC_ENCRYPTION_INFO:
                    cryptoff = struct.unpack(f'{endian}I', f.read(4))[0]
                    cryptsize = struct.unpack(f'{endian}I', f.read(4))[0]
                    cryptid = struct.unpack(f'{endian}I', f.read(4))[0]
                    self.encryption_info = {
                        'offset': hex(cryptoff),
                        'size': cryptsize,
                        'encrypted': bool(cryptid)
                    }
                
                # Move to next command
                f.seek(cmd_start + cmdsize)
        
        return {
            'segments': self.segments,
            'dylibs': self.dylibs,
            'load_commands': self.load_commands,
            'code_signature': self.code_signature,
            'encryption_info': self.encryption_info,
            'entry_point': hex(self.entry_point) if self.entry_point else None
        }
    
    def _parse_segment(self, f, offset, is_64, endian):
        """Parse segment command"""
        f.seek(offset)
        
        segname = f.read(16).rstrip(b'\x00').decode('utf-8', errors='ignore')
        
        if is_64:
            vmaddr = struct.unpack(f'{endian}Q', f.read(8))[0]
            vmsize = struct.unpack(f'{endian}Q', f.read(8))[0]
            fileoff = struct.unpack(f'{endian}Q', f.read(8))[0]
            filesize = struct.unpack(f'{endian}Q', f.read(8))[0]
        else:
            vmaddr = struct.unpack(f'{endian}I', f.read(4))[0]
            vmsize = struct.unpack(f'{endian}I', f.read(4))[0]
            fileoff = struct.unpack(f'{endian}I', f.read(4))[0]
            filesize = struct.unpack(f'{endian}I', f.read(4))[0]
        
        maxprot = struct.unpack(f'{endian}i', f.read(4))[0]
        initprot = struct.unpack(f'{endian}i', f.read(4))[0]
        
        self.segments.append({
            'name': segname,
            'vmaddr': hex(vmaddr),
            'vmsize': vmsize,
            'fileoff': hex(fileoff),
            'filesize': filesize,
            'maxprot': maxprot,
            'initprot': initprot,
            'readable': bool(initprot & 0x1),
            'writable': bool(initprot & 0x2),
            'executable': bool(initprot & 0x4)
        })
    
    def _parse_dylib(self, f, offset, size, endian):
        """Parse dylib load command"""
        f.seek(offset)
        
        name_offset = struct.unpack(f'{endian}I', f.read(4))[0]
        timestamp = struct.unpack(f'{endian}I', f.read(4))[0]
        current_version = struct.unpack(f'{endian}I', f.read(4))[0]
        compat_version = struct.unpack(f'{endian}I', f.read(4))[0]
        
        # Read name
        f.seek(offset + name_offset - 8)
        name_bytes = f.read(size - name_offset + 8)
        name = name_bytes.rstrip(b'\x00').decode('utf-8', errors='ignore')
        
        self.dylibs.append({
            'name': name,
            'current_version': self._format_version(current_version),
            'compat_version': self._format_version(compat_version)
        })
    
    def _cmd_name(self, cmd):
        """Get load command name"""
        names = {
            self.LC_SEGMENT: 'LC_SEGMENT',
            self.LC_SEGMENT_64: 'LC_SEGMENT_64',
            self.LC_SYMTAB: 'LC_SYMTAB',
            self.LC_DYSYMTAB: 'LC_DYSYMTAB',
            self.LC_LOAD_DYLIB: 'LC_LOAD_DYLIB',
            self.LC_ID_DYLIB: 'LC_ID_DYLIB',
            self.LC_LOAD_DYLINKER: 'LC_LOAD_DYLINKER',
            self.LC_UUID: 'LC_UUID',
            self.LC_CODE_SIGNATURE: 'LC_CODE_SIGNATURE',
            self.LC_ENCRYPTION_INFO: 'LC_ENCRYPTION_INFO',
            self.LC_DYLD_INFO: 'LC_DYLD_INFO',
            self.LC_MAIN: 'LC_MAIN'
        }
        return names.get(cmd, f'LC_UNKNOWN({hex(cmd)})')
    
    def _format_version(self, version):
        """Format version number"""
        major = (version >> 16) & 0xffff
        minor = (version >> 8) & 0xff
        patch = version & 0xff
        return f"{major}.{minor}.{patch}"
    
    def report(self):
        """Generate report"""
        lines = []
        lines.append("="*60)
        lines.append(f"MACH-O ANALYSIS: {self.filepath.name}")
        lines.append("="*60)
        
        lines.append(f"\nArchitecture: {'64-bit' if self.is_64bit else '32-bit'}")
        lines.append(f"Endianness: {'Little' if self.is_little_endian else 'Big'}")
        
        if self.entry_point:
            lines.append(f"Entry Point: {hex(self.entry_point)}")
        
        lines.append(f"\nSegments: {len(self.segments)}")
        for seg in self.segments:
            flags = []
            if seg['readable']:
                flags.append('R')
            if seg['writable']:
                flags.append('W')
            if seg['executable']:
                flags.append('X')
            
            lines.append(f"  {seg['name']:<16} {seg['vmaddr']:<12} "
                        f"{seg['vmsize']:<10} {''.join(flags)}")
        
        lines.append(f"\nLinked Libraries: {len(self.dylibs)}")
        for dylib in self.dylibs[:10]:
            lines.append(f"  {dylib['name']}")
        
        if self.code_signature:
            lines.append(f"\nCode Signature: Present (size {self.code_signature['size']} bytes)")
        
        if self.encryption_info:
            enc = "Encrypted" if self.encryption_info['encrypted'] else "Not encrypted"
            lines.append(f"Encryption: {enc}")
        
        return "\n".join(lines)

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: macho_analyzer.py <file>")
        sys.exit(1)
    
    analyzer = MachoAnalyzer(sys.argv[1])
    analyzer.analyze()
    print(analyzer.report())
