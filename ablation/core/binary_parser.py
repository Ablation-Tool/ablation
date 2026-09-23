#!/usr/bin/env python3
"""
Binary Parser Module
Synthesized from: Learning Linux Binary Analysis, Practical Binary Analysis

Parses ELF, PE, and Mach-O binary formats without external dependencies.
"""

import struct
import os
from pathlib import Path

class BinaryParser:
    """Universal binary format parser"""
    
    # ELF constants
    ELF_MAGIC = b'\x7fELF'
    PE_MAGIC = b'MZ'
    MACHO_MAGIC_32 = 0xfeedface
    MACHO_MAGIC_64 = 0xfeedfacf
    MACHO_CIGAM_32 = 0xcefaedfe  # reverse
    MACHO_CIGAM_64 = 0xcffaedfe
    
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.format = None
        self.bits = None
        self.endian = None
        self.sections = []
        self.symbols = []
        self.imports = []
        self.exports = []
        self.entry_point = None
        
    def detect_format(self):
        """Detect binary format from magic bytes"""
        with open(self.filepath, 'rb') as f:
            magic = f.read(4)
            
        if magic == self.ELF_MAGIC:
            self.format = 'ELF'
        elif magic[:2] == self.PE_MAGIC:
            self.format = 'PE'
        else:
            # Check Mach-O
            magic_int = struct.unpack('<I', magic)[0]
            if magic_int in [self.MACHO_MAGIC_32, self.MACHO_MAGIC_64, 
                            self.MACHO_CIGAM_32, self.MACHO_CIGAM_64]:
                self.format = 'Mach-O'
        
        return self.format
    
    def parse(self):
        """Parse based on detected format"""
        if not self.format:
            self.detect_format()
            
        if self.format == 'ELF':
            return self._parse_elf()
        elif self.format == 'PE':
            return self._parse_pe()
        elif self.format == 'Mach-O':
            return self._parse_macho()
        else:
            raise ValueError(f"Unknown format: {self.format}")
    
    def _parse_elf(self):
        """Parse ELF binary"""
        with open(self.filepath, 'rb') as f:
            # Read ELF header
            elf_header = f.read(64)
            
            # EI_CLASS (byte 4) - 1=32bit, 2=64bit
            ei_class = elf_header[4]
            self.bits = 32 if ei_class == 1 else 64
            
            # EI_DATA (byte 5) - 1=little, 2=big
            ei_data = elf_header[5]
            self.endian = 'little' if ei_data == 1 else 'big'
            
            # Entry point offset varies by arch
            if self.bits == 32:
                entry_offset = 24
                entry_fmt = '<I' if self.endian == 'little' else '>I'
            else:
                entry_offset = 24
                entry_fmt = '<Q' if self.endian == 'little' else '>Q'
                
            self.entry_point = struct.unpack(entry_fmt, 
                elf_header[entry_offset:entry_offset + (4 if self.bits == 32 else 8)])[0]
            
            # Parse section headers
            if self.bits == 32:
                e_shoff = struct.unpack(entry_fmt, elf_header[32:36])[0]
                e_shentsize = struct.unpack('<H', elf_header[46:48])[0]
                e_shnum = struct.unpack('<H', elf_header[48:50])[0]
                e_shstrndx = struct.unpack('<H', elf_header[50:52])[0]
            else:
                e_shoff = struct.unpack('<Q', elf_header[40:48])[0]
                e_shentsize = struct.unpack('<H', elf_header[58:60])[0]
                e_shnum = struct.unpack('<H', elf_header[60:62])[0]
                e_shstrndx = struct.unpack('<H', elf_header[62:64])[0]
            
            # Read section headers
            f.seek(e_shoff)
            sections_data = f.read(e_shentsize * e_shnum)
            
            # Parse each section
            for i in range(e_shnum):
                offset = i * e_shentsize
                sh_data = sections_data[offset:offset + e_shentsize]
                
                if self.bits == 32:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                        struct.unpack('<IIIIII', sh_data[:24])
                else:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                        struct.unpack('<IIQQqq', sh_data[:40])
                
                self.sections.append({
                    'index': i,
                    'name_offset': sh_name,
                    'type': sh_type,
                    'flags': sh_flags,
                    'addr': sh_addr,
                    'offset': sh_offset,
                    'size': sh_size
                })
            
        return {
            'format': 'ELF',
            'bits': self.bits,
            'endian': self.endian,
            'entry_point': hex(self.entry_point),
            'sections': len(self.sections)
        }
    
    def _parse_pe(self):
        """Parse PE binary"""
        with open(self.filepath, 'rb') as f:
            # DOS header
            dos_header = f.read(64)
            e_lfanew = struct.unpack('<I', dos_header[60:64])[0]
            
            # PE header
            f.seek(e_lfanew)
            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                raise ValueError("Invalid PE signature")
            
            # COFF header
            coff_header = f.read(20)
            machine = struct.unpack('<H', coff_header[0:2])[0]
            
            # Determine architecture
            if machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
                self.bits = 32
            elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                self.bits = 64
            else:
                self.bits = None
            
            # Optional header
            size_of_opt_header = struct.unpack('<H', coff_header[16:18])[0]
            opt_header = f.read(size_of_opt_header)
            
            if size_of_opt_header > 0:
                # Entry point is at offset 16 in optional header
                self.entry_point = struct.unpack('<I', opt_header[16:20])[0]
            
        return {
            'format': 'PE',
            'bits': self.bits,
            'entry_point': hex(self.entry_point) if self.entry_point else None
        }
    
    def _parse_macho(self):
        """Parse Mach-O binary"""
        with open(self.filepath, 'rb') as f:
            magic_bytes = f.read(4)
            magic = struct.unpack('<I', magic_bytes)[0]
            
            if magic in [self.MACHO_MAGIC_32, self.MACHO_CIGAM_32]:
                self.bits = 32
                self.endian = 'little' if magic == self.MACHO_MAGIC_32 else 'big'
            elif magic in [self.MACHO_MAGIC_64, self.MACHO_CIGAM_64]:
                self.bits = 64
                self.endian = 'little' if magic == self.MACHO_MAGIC_64 else 'big'
            
            # Read header
            cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = \
                struct.unpack('<iiIIII' if self.endian == 'little' else '>iiIIII', f.read(24))
            
            # 64-bit has extra reserved field
            if self.bits == 64:
                f.read(4)
            
            # Parse load commands
            for _ in range(ncmds):
                cmd_start = f.tell()
                cmd, cmdsize = struct.unpack('<II', f.read(8))
                
                # LC_MAIN (0x80000028) contains entry point
                if cmd == 0x80000028:
                    entryoff, stacksize = struct.unpack('<QQ', f.read(16))
                    self.entry_point = entryoff
                
                # Move to next command
                f.seek(cmd_start + cmdsize)
            
        return {
            'format': 'Mach-O',
            'bits': self.bits,
            'endian': self.endian,
            'entry_point': hex(self.entry_point) if self.entry_point else None
        }
    
    def report(self):
        """Generate human-readable report"""
        info = self.parse()
        lines = []
        lines.append(f"Binary: {self.filepath.name}")
        lines.append(f"Format: {info['format']}")
        lines.append(f"Architecture: {info.get('bits', '?')} bit")
        if 'endian' in info:
            lines.append(f"Endianness: {info['endian']}")
        if info.get('entry_point'):
            lines.append(f"Entry Point: {info['entry_point']}")
        if 'sections' in info:
            lines.append(f"Sections: {info['sections']}")
        return "\n".join(lines)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: binary_parser.py <file>")
        sys.exit(1)
    
    parser = BinaryParser(sys.argv[1])
    print(parser.report())
    
    # Also print JSON
    import json
    print("\nJSON Output:")
    print(json.dumps(parser.parse(), indent=2))
