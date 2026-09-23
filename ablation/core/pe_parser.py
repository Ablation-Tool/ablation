#!/usr/bin/env python3
"""
Windows PE file parser -- static analysis for malware indicators.
Sources: Practical Malware Analysis (Sikorski/Honig), PE/COFF spec.
"""
import struct
import re
import math
import os
from typing import Optional


class PEParser:
    # Signatures
    IMAGE_DOS_SIGNATURE   = 0x5A4D        # 'MZ'
    IMAGE_NT_SIGNATURE    = 0x00004550    # 'PE\0\0'

    # Machine types
    IMAGE_FILE_MACHINE_I386  = 0x014C
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64

    # Optional header magic
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010B
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B

    # Section characteristic flags
    IMAGE_SCN_CNT_CODE               = 0x00000020
    IMAGE_SCN_MEM_EXECUTE            = 0x20000000
    IMAGE_SCN_MEM_READ               = 0x40000000
    IMAGE_SCN_MEM_WRITE              = 0x80000000
    IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000

    # Data directory indices
    DIRECTORY_ENTRY_IMPORT  = 1
    DIRECTORY_ENTRY_EXPORT  = 0
    DIRECTORY_ENTRY_RESOURCE = 2

    # Suspicious section names from malware:
    # UPX packers use UPX0/UPX1; mpress uses .MPRESS1/.MPRESS2;
    # custom packers often use blank names, 'packed', 'stub', '.nsp0'
    SUSPICIOUS_SECTIONS = {
        'UPX0', 'UPX1', 'UPX2',
        '.MPRESS1', '.MPRESS2',
        '.packed', '.stub', '.nsp0', '.nsp1',
        '.themida', '.winlicens',
        'PEPACK!!',
    }

    # Entropy thresholds (bits/byte)
    ENTROPY_HIGH    = 7.0   # packed / encrypted
    ENTROPY_MEDIUM  = 6.0   # compressed data or mix

    def __init__(self, data: bytes):
        self.data = data
        self.valid = False
        self.pe_offset = 0
        self.machine = 0
        self.is_64bit = False
        self.num_sections = 0
        self.timestamp = 0
        self.size_of_optional_header = 0
        self.characteristics = 0
        self.entry_point_rva = 0
        self.image_base = 0
        self.size_of_image = 0
        self.sections = []      # list of section dicts
        self.imports = {}       # {dll: [func, ...]}
        self.exports = []       # [func_name, ...]
        self.resources = []     # [{'type': int, 'id': int, 'size': int}, ...]
        self._data_dirs = []    # [(rva, size), ...] x 16
        self._parse()

    # ------------------------------------------------------------------
    # Core parser
    # ------------------------------------------------------------------

    def _parse(self):
        """Parse DOS + PE headers, section table, data directories."""
        try:
            if len(self.data) < 64:
                return
            dos_sig = struct.unpack_from('<H', self.data, 0)[0]
            if dos_sig != self.IMAGE_DOS_SIGNATURE:
                return

            self.pe_offset = struct.unpack_from('<I', self.data, 0x3C)[0]
            if self.pe_offset + 24 > len(self.data):
                return

            nt_sig = struct.unpack_from('<I', self.data, self.pe_offset)[0]
            if nt_sig != self.IMAGE_NT_SIGNATURE:
                return

            # IMAGE_FILE_HEADER (20 bytes at pe_offset+4)
            fh_off = self.pe_offset + 4
            (self.machine,
             self.num_sections,
             self.timestamp,
             _sym_ptr,
             _num_sym,
             self.size_of_optional_header,
             self.characteristics
            ) = struct.unpack_from('<HHIIIHH', self.data, fh_off)

            # IMAGE_OPTIONAL_HEADER
            oh_off = fh_off + 20
            if oh_off + 2 > len(self.data):
                return
            magic = struct.unpack_from('<H', self.data, oh_off)[0]
            self.is_64bit = (magic == self.IMAGE_NT_OPTIONAL_HDR64_MAGIC)

            if self.is_64bit:
                # PE32+: AddressOfEntryPoint at +16, ImageBase at +24 (8 bytes), SizeOfImage at +56
                if oh_off + 60 > len(self.data):
                    return
                self.entry_point_rva = struct.unpack_from('<I', self.data, oh_off + 16)[0]
                self.image_base      = struct.unpack_from('<Q', self.data, oh_off + 24)[0]
                self.size_of_image   = struct.unpack_from('<I', self.data, oh_off + 56)[0]
                dd_off = oh_off + 112   # data directories start
            else:
                # PE32: AddressOfEntryPoint at +16, ImageBase at +28 (4 bytes), SizeOfImage at +56
                if oh_off + 60 > len(self.data):
                    return
                self.entry_point_rva = struct.unpack_from('<I', self.data, oh_off + 16)[0]
                self.image_base      = struct.unpack_from('<I', self.data, oh_off + 28)[0]
                self.size_of_image   = struct.unpack_from('<I', self.data, oh_off + 56)[0]
                dd_off = oh_off + 96    # data directories start

            # Data directories (16 entries x 8 bytes each)
            self._data_dirs = []
            for i in range(16):
                dd_entry_off = dd_off + i * 8
                if dd_entry_off + 8 > len(self.data):
                    self._data_dirs.append((0, 0))
                    continue
                rva, sz = struct.unpack_from('<II', self.data, dd_entry_off)
                self._data_dirs.append((rva, sz))

            # Section table starts after optional header
            sect_off = oh_off + self.size_of_optional_header
            for i in range(self.num_sections):
                s_off = sect_off + i * 40
                if s_off + 40 > len(self.data):
                    break
                raw = self.data[s_off: s_off + 40]
                name       = raw[0:8].rstrip(b'\x00').decode('ascii', errors='replace')
                vsize      = struct.unpack_from('<I', raw, 8)[0]
                vaddr      = struct.unpack_from('<I', raw, 12)[0]
                raw_size   = struct.unpack_from('<I', raw, 16)[0]
                raw_offset = struct.unpack_from('<I', raw, 20)[0]
                chars      = struct.unpack_from('<I', raw, 36)[0]

                # Shannon entropy on raw section data
                sect_data = self.data[raw_offset: raw_offset + raw_size]
                entropy = self._shannon_entropy(sect_data) if sect_data else 0.0

                self.sections.append({
                    'name':       name,
                    'vaddr':      vaddr,
                    'vsize':      vsize,
                    'raw_offset': raw_offset,
                    'raw_size':   raw_size,
                    'chars':      chars,
                    'entropy':    entropy,
                    'executable': bool(chars & self.IMAGE_SCN_MEM_EXECUTE),
                    'writable':   bool(chars & self.IMAGE_SCN_MEM_WRITE),
                    'readable':   bool(chars & self.IMAGE_SCN_MEM_READ),
                })

            self.valid = True

            # Parse imports and exports
            self._parse_imports()
            self._parse_exports()
            self._parse_resources()

        except (struct.error, IndexError, UnicodeDecodeError):
            pass

    # ------------------------------------------------------------------
    # Import Directory Table
    # ------------------------------------------------------------------

    def _parse_imports(self):
        """Parse IMAGE_IMPORT_DESCRIPTOR table."""
        try:
            if len(self._data_dirs) <= self.DIRECTORY_ENTRY_IMPORT:
                return
            import_rva, import_size = self._data_dirs[self.DIRECTORY_ENTRY_IMPORT]
            if not import_rva or not import_size:
                return

            off = self._rva_to_offset(import_rva)
            if off is None:
                return

            # Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes
            # { OriginalFirstThunk(4), TimeDateStamp(4), ForwarderChain(4),
            #   Name(4), FirstThunk(4) }
            while off + 20 <= len(self.data):
                (orig_thunk, _ts, _fc, name_rva, first_thunk
                ) = struct.unpack_from('<IIIII', self.data, off)
                off += 20

                if name_rva == 0 and first_thunk == 0:
                    break   # sentinel

                dll_name = self._read_str(self._rva_to_offset(name_rva))
                if not dll_name:
                    continue

                # Use OriginalFirstThunk (INT) if non-zero, else FirstThunk (IAT)
                thunk_rva = orig_thunk if orig_thunk else first_thunk
                thunk_off = self._rva_to_offset(thunk_rva)
                if thunk_off is None:
                    continue

                funcs = []
                ptr_size = 8 if self.is_64bit else 4
                fmt = '<Q' if self.is_64bit else '<I'
                ordinal_flag = (1 << 63) if self.is_64bit else (1 << 31)

                while thunk_off + ptr_size <= len(self.data):
                    entry = struct.unpack_from(fmt, self.data, thunk_off)[0]
                    thunk_off += ptr_size
                    if entry == 0:
                        break
                    if entry & ordinal_flag:
                        funcs.append(f'Ordinal({entry & 0xFFFF})')
                    else:
                        # IMAGE_IMPORT_BY_NAME: Hint(2) + Name(variable)
                        ibn_off = self._rva_to_offset(entry & 0x7FFFFFFF)
                        if ibn_off is not None and ibn_off + 2 < len(self.data):
                            fn = self._read_str(ibn_off + 2)
                            if fn:
                                funcs.append(fn)

                dll_key = dll_name.lower()
                if dll_key not in self.imports:
                    self.imports[dll_key] = []
                self.imports[dll_key].extend(funcs)

        except (struct.error, IndexError):
            pass

    # ------------------------------------------------------------------
    # Export Directory
    # ------------------------------------------------------------------

    def _parse_exports(self):
        """Parse IMAGE_EXPORT_DIRECTORY."""
        try:
            if len(self._data_dirs) <= self.DIRECTORY_ENTRY_EXPORT:
                return
            exp_rva, exp_size = self._data_dirs[self.DIRECTORY_ENTRY_EXPORT]
            if not exp_rva or not exp_size:
                return

            off = self._rva_to_offset(exp_rva)
            if off is None or off + 40 > len(self.data):
                return

            # IMAGE_EXPORT_DIRECTORY (40 bytes)
            (_chars, _ts, _major, _minor, _name_rva,
             _base, num_funcs, num_names, func_rva_arr, name_rva_arr, ord_arr
            ) = struct.unpack_from('<IIHIIIIIII', off and self.data[off: off + 40])[0:0]  # placeholder
            (
                _flags, _ts, _maj, _min,
                _mod_name_rva,
                _base,
                num_funcs,
                num_names,
                func_table_rva,
                name_table_rva,
                ordinal_table_rva
            ) = struct.unpack_from('<IIHHIIIIIII', self.data, off)

            name_arr_off = self._rva_to_offset(name_table_rva)
            if name_arr_off is None:
                return

            for i in range(num_names):
                n_off = name_arr_off + i * 4
                if n_off + 4 > len(self.data):
                    break
                name_rva = struct.unpack_from('<I', self.data, n_off)[0]
                fn = self._read_str(self._rva_to_offset(name_rva))
                if fn:
                    self.exports.append(fn)

        except (struct.error, IndexError):
            pass

    # ------------------------------------------------------------------
    # Resource Directory
    # ------------------------------------------------------------------

    def _parse_resources(self):
        """Parse IMAGE_RESOURCE_DIRECTORY (top level only)."""
        try:
            if len(self._data_dirs) <= self.DIRECTORY_ENTRY_RESOURCE:
                return
            rsrc_rva, rsrc_size = self._data_dirs[self.DIRECTORY_ENTRY_RESOURCE]
            if not rsrc_rva or not rsrc_size:
                return

            rsrc_off = self._rva_to_offset(rsrc_rva)
            if rsrc_off is None or rsrc_off + 16 > len(self.data):
                return

            # IMAGE_RESOURCE_DIRECTORY header: 16 bytes
            # named_entries (2) + id_entries (2) at offsets 12/14
            named = struct.unpack_from('<H', self.data, rsrc_off + 12)[0]
            ident = struct.unpack_from('<H', self.data, rsrc_off + 14)[0]
            total = named + ident

            for i in range(total):
                entry_off = rsrc_off + 16 + i * 8
                if entry_off + 8 > len(self.data):
                    break
                res_id   = struct.unpack_from('<I', self.data, entry_off)[0]
                res_data = struct.unpack_from('<I', self.data, entry_off + 4)[0]
                self.resources.append({
                    'type': res_id & 0x7FFFFFFF,
                    'is_named': bool(res_id & 0x80000000),
                    'data_offset': res_data,
                })

        except (struct.error, IndexError):
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_sections(self) -> list:
        """
        Returns list of section dicts:
        { name, vaddr, vsize, raw_offset, raw_size, entropy,
          executable, writable, readable }
        Also flags sections with suspicious names or high entropy.
        """
        result = []
        for s in self.sections:
            entry = dict(s)
            flags = []
            if s['name'].strip() in self.SUSPICIOUS_SECTIONS:
                flags.append('suspicious_name')
            if s['entropy'] >= self.ENTROPY_HIGH:
                flags.append('high_entropy')
            elif s['entropy'] >= self.ENTROPY_MEDIUM:
                flags.append('medium_entropy')
            # Executable + writable = rare, classic shellcode injection target
            if s['executable'] and s['writable']:
                flags.append('wx_section')
            # Executable section with zero raw size = virtual-only (packed stub pattern)
            if s['executable'] and s['raw_size'] == 0 and s['vsize'] > 0:
                flags.append('virtual_exec_section')
            entry['flags'] = flags
            result.append(entry)
        return result

    def get_imports(self) -> dict:
        """Returns {dll_name_lower: [function_name, ...]}."""
        return dict(self.imports)

    def get_strings(self, min_len: int = 6) -> list:
        """
        Extract ASCII and UTF-16LE strings from the raw binary.
        Returns list of {'value': str, 'encoding': str, 'offset': int}.
        """
        results = []

        # ASCII
        pattern_ascii = re.compile(rb'[\x20-\x7E]{' + str(min_len).encode() + rb',}')
        for m in pattern_ascii.finditer(self.data):
            results.append({
                'value':    m.group().decode('ascii', errors='replace'),
                'encoding': 'ascii',
                'offset':   m.start(),
            })

        # UTF-16LE: pairs of (printable, \x00)
        pattern_wide = re.compile(
            rb'(?:[\x20-\x7E]\x00){' + str(min_len).encode() + rb',}'
        )
        for m in pattern_wide.finditer(self.data):
            try:
                val = m.group().decode('utf-16-le', errors='replace')
                results.append({
                    'value':    val,
                    'encoding': 'utf-16le',
                    'offset':   m.start(),
                })
            except UnicodeDecodeError:
                pass

        return results

    def scan_ioc_strings(self) -> list:
        """
        Scan extracted strings for IOC patterns.
        Returns list of {'type': str, 'value': str, 'severity': str, 'offset': int}.
        """
        iocs = []
        strings = self.get_strings(min_len=5)

        # Patterns derived from PMA chapters on persistence, C2, and malware behavior
        ipv4_re       = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        url_re        = re.compile(r'https?://[^\s"\'<>]{5,}', re.IGNORECASE)
        domain_re     = re.compile(
            r'\b(?:[a-z0-9\-]{2,63}\.)+(?:ru|cn|onion|xyz|pw|tk|ml|ga|cf|gq|top|cc|to)\b',
            re.IGNORECASE
        )
        # Registry autorun paths (PMA ch11: persistence mechanisms)
        reg_run_re    = re.compile(
            r'(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|'
            r'HKLM|HKCU|HKU|HKCR)'
            r'(?:\\[^\\\s"\']{1,128})+',
            re.IGNORECASE
        )
        # File-based autorun locations
        startup_re    = re.compile(
            r'(?:\\Startup\\|\\Start Menu\\|\\CurrentVersion\\Run|'
            r'\\RunOnce|\\RunOnceEx|AppData\\Roaming)',
            re.IGNORECASE
        )
        # Mutex names: GUIDs, svchost variants, well-known malware mutexes
        mutex_re      = re.compile(
            r'(?:\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
            r'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}|'
            r'Global\\[^\s"\']{4,}|'
            r'Local\\[^\s"\']{4,})',
            re.IGNORECASE
        )
        # Suspicious file extensions in paths
        dropper_ext_re = re.compile(
            r'[^\s"\']{3,}\.(?:exe|dll|bat|cmd|vbs|ps1|scr|pif|com|sys|drv)\b',
            re.IGNORECASE
        )
        # PEM / base64-encoded crypto material
        crypto_re     = re.compile(
            r'-----BEGIN (?:RSA |EC )?(?:PRIVATE KEY|CERTIFICATE)-----'
        )
        # C2 user-agents used by commodity RATs
        ua_re         = re.compile(
            r'Mozilla/[0-9]\.[0-9] \([^)]{5,}\)',
            re.IGNORECASE
        )

        seen = set()
        for s in strings:
            val = s['value']
            off = s['offset']

            def emit(typ, severity, v=val):
                key = (typ, v)
                if key not in seen:
                    seen.add(key)
                    iocs.append({
                        'type':     typ,
                        'value':    v,
                        'severity': severity,
                        'offset':   off,
                    })

            for m in ipv4_re.finditer(val):
                ip = m.group()
                # Skip loopback/link-local
                if not ip.startswith(('127.', '169.254.', '0.')):
                    emit('ipv4', 'HIGH', ip)

            for m in url_re.finditer(val):
                emit('url', 'HIGH', m.group())

            for m in domain_re.finditer(val):
                emit('domain_suspicious_tld', 'HIGH', m.group())

            for m in reg_run_re.finditer(val):
                emit('registry_path', 'MEDIUM', m.group())

            for m in startup_re.finditer(val):
                emit('autorun_path', 'HIGH', m.group())

            for m in mutex_re.finditer(val):
                emit('mutex', 'MEDIUM', m.group())

            for m in dropper_ext_re.finditer(val):
                emit('dropper_extension', 'LOW', m.group())

            for m in crypto_re.finditer(val):
                emit('crypto_material', 'CRITICAL', m.group())

            for m in ua_re.finditer(val):
                emit('http_user_agent', 'LOW', m.group())

        return iocs

    def scan_malware_apis(self) -> list:
        """
        Check parsed imports against dangerous API sets.
        Categories sourced from PMA appendix A (Important Windows Functions)
        and ch11/ch12/ch16/ch17 (malware behavior, anti-debug, anti-VM).

        Returns list of {'api': str, 'dll': str, 'severity': str, 'category': str}.
        """
        # Map: function_name -> (severity, category)
        # PMA chapter references:
        #   Process injection: ch12 covert malware launching
        #   Keylogging: ch11 credential stealers
        #   Anti-debug: ch16 anti-debugging
        #   Timing: ch16 timing checks / ch17 anti-VM
        #   Persistence: ch11 persistence mechanisms
        #   Crypto: ch11 ransomware / ch12 malware behavior
        SUSPICIOUS_APIS = {
            # --- CRITICAL: direct code injection primitives ---
            'VirtualAllocEx':          ('CRITICAL', 'process_injection'),
            'VirtualAlloc':            ('CRITICAL', 'process_injection'),
            'WriteProcessMemory':      ('CRITICAL', 'process_injection'),
            'CreateRemoteThread':      ('CRITICAL', 'process_injection'),
            'CreateRemoteThreadEx':    ('CRITICAL', 'process_injection'),
            # Process hollowing (NtUnmapViewOfSection + VirtualAllocEx)
            'NtUnmapViewOfSection':    ('CRITICAL', 'process_hollowing'),
            'ZwUnmapViewOfSection':    ('CRITICAL', 'process_hollowing'),
            # Reflective DLL injection
            'NtCreateSection':         ('CRITICAL', 'process_injection'),
            'NtMapViewOfSection':      ('CRITICAL', 'process_injection'),
            # Hook-based keyloggers: SetWindowsHookEx + WH_KEYBOARD_LL
            'SetWindowsHookEx':        ('CRITICAL', 'keylogging_hook'),
            'SetWindowsHookExA':       ('CRITICAL', 'keylogging_hook'),
            'SetWindowsHookExW':       ('CRITICAL', 'keylogging_hook'),
            # Raw keystroke polling (no hook DLL needed)
            'GetAsyncKeyState':        ('CRITICAL', 'keylogging_poll'),
            'GetKeyState':             ('HIGH',     'keylogging_poll'),
            # Ransomware crypto
            'CryptEncrypt':            ('CRITICAL', 'ransomware_crypto'),
            'CryptDecrypt':            ('CRITICAL', 'ransomware_crypto'),
            'BCryptEncrypt':           ('CRITICAL', 'ransomware_crypto'),
            'BCryptDecrypt':           ('CRITICAL', 'ransomware_crypto'),
            'CryptGenKey':             ('HIGH',     'ransomware_crypto'),
            'CryptImportKey':          ('HIGH',     'ransomware_crypto'),
            # SSDT hooking / rootkit (ch10 kernel debugging / ch rootkits)
            'NtLoadDriver':            ('CRITICAL', 'rootkit_driver'),
            'ZwLoadDriver':            ('CRITICAL', 'rootkit_driver'),

            # --- HIGH: persistence, C2, enumeration ---
            'RegSetValueEx':           ('HIGH', 'persistence_registry'),
            'RegSetValueExA':          ('HIGH', 'persistence_registry'),
            'RegSetValueExW':          ('HIGH', 'persistence_registry'),
            'RegCreateKeyEx':          ('HIGH', 'persistence_registry'),
            'RegCreateKeyExA':         ('HIGH', 'persistence_registry'),
            'RegCreateKeyExW':         ('HIGH', 'persistence_registry'),
            'CreateService':           ('HIGH', 'persistence_service'),
            'CreateServiceA':          ('HIGH', 'persistence_service'),
            'CreateServiceW':          ('HIGH', 'persistence_service'),
            'StartService':            ('HIGH', 'persistence_service'),
            'StartServiceA':           ('HIGH', 'persistence_service'),
            'StartServiceW':           ('HIGH', 'persistence_service'),
            'ChangeServiceConfig':     ('HIGH', 'persistence_service'),
            # C2 / downloader (PMA ch11: downloaders and launchers)
            'InternetOpenUrl':         ('HIGH', 'c2_http'),
            'InternetOpenUrlA':        ('HIGH', 'c2_http'),
            'InternetOpenUrlW':        ('HIGH', 'c2_http'),
            'HttpSendRequest':         ('HIGH', 'c2_http'),
            'HttpSendRequestA':        ('HIGH', 'c2_http'),
            'HttpSendRequestW':        ('HIGH', 'c2_http'),
            'WinHttpSendRequest':      ('HIGH', 'c2_http'),
            'URLDownloadToFile':       ('HIGH', 'c2_downloader'),
            'URLDownloadToFileA':      ('HIGH', 'c2_downloader'),
            'URLDownloadToFileW':      ('HIGH', 'c2_downloader'),
            'InternetWriteFile':       ('HIGH', 'c2_upload'),
            # Raw socket C2
            'WSASend':                 ('MEDIUM', 'c2_raw_socket'),
            'WSARecv':                 ('MEDIUM', 'c2_raw_socket'),
            # File enumeration (ransomware target walk)
            'FindFirstFile':           ('HIGH', 'file_enumeration'),
            'FindFirstFileA':          ('HIGH', 'file_enumeration'),
            'FindFirstFileW':          ('HIGH', 'file_enumeration'),
            'FindNextFile':            ('HIGH', 'file_enumeration'),
            'FindNextFileA':           ('HIGH', 'file_enumeration'),
            'FindNextFileW':           ('HIGH', 'file_enumeration'),
            # Clipboard theft
            'GetClipboardData':        ('HIGH', 'credential_theft'),
            'OpenClipboard':           ('MEDIUM', 'credential_theft'),
            # Process enumeration
            'EnumProcesses':           ('HIGH', 'process_enumeration'),
            'CreateToolhelp32Snapshot':('HIGH', 'process_enumeration'),
            'Process32First':          ('HIGH', 'process_enumeration'),
            'Process32Next':           ('HIGH', 'process_enumeration'),
            'OpenProcess':             ('HIGH', 'process_access'),
            # Screen capture
            'BitBlt':                  ('HIGH', 'screen_capture'),
            'GetDC':                   ('MEDIUM', 'screen_capture'),
            # Token/privilege manipulation
            'AdjustTokenPrivileges':   ('HIGH', 'privilege_escalation'),
            'LookupPrivilegeValue':    ('MEDIUM', 'privilege_escalation'),
            'OpenProcessToken':        ('MEDIUM', 'privilege_escalation'),
            # WMI lateral movement
            'CoCreateInstance':        ('MEDIUM', 'wmi_lateral'),

            # --- MEDIUM: anti-analysis / sandbox evasion ---
            # Anti-debug: Windows API methods (PMA ch16)
            'IsDebuggerPresent':           ('MEDIUM', 'anti_debug'),
            'CheckRemoteDebuggerPresent':  ('MEDIUM', 'anti_debug'),
            'OutputDebugString':           ('MEDIUM', 'anti_debug'),
            'NtQueryInformationProcess':   ('MEDIUM', 'anti_debug'),
            'ZwQueryInformationProcess':   ('MEDIUM', 'anti_debug'),
            # Timing-based anti-debug/anti-VM (PMA ch16 timing checks, ch17 anti-VM)
            'GetTickCount':                ('MEDIUM', 'anti_analysis_timing'),
            'GetTickCount64':              ('MEDIUM', 'anti_analysis_timing'),
            'QueryPerformanceCounter':     ('MEDIUM', 'anti_analysis_timing'),
            'QueryPerformanceFrequency':   ('MEDIUM', 'anti_analysis_timing'),
            # Sleep-based sandbox evasion (PMA ch17: sandbox detection)
            'Sleep':                       ('MEDIUM', 'sandbox_evasion'),
            'SleepEx':                     ('MEDIUM', 'sandbox_evasion'),
            'NtDelayExecution':            ('MEDIUM', 'sandbox_evasion'),
            'WaitForSingleObject':         ('MEDIUM', 'sandbox_evasion'),
            # Anti-VM: CPUID / RDTSC are checked inline, not via imports;
            # these registry/file checks are the import-visible surface
            'RegQueryValueEx':             ('MEDIUM', 'anti_vm_registry'),
            'GetSystemInfo':               ('MEDIUM', 'anti_vm_detection'),
            'GetSystemTime':               ('MEDIUM', 'anti_vm_detection'),
            # Self-deletion / covering tracks (PMA ch11: covering its tracks)
            'DeleteFile':                  ('MEDIUM', 'cover_tracks'),
            'MoveFileEx':                  ('MEDIUM', 'cover_tracks'),
            # Shellcode helpers
            'VirtualProtect':              ('MEDIUM', 'shellcode_execution'),
            'VirtualProtectEx':            ('MEDIUM', 'shellcode_execution'),
            # IAT hook detection bypass
            'GetProcAddress':              ('MEDIUM', 'api_resolution'),
            'LoadLibrary':                 ('MEDIUM', 'api_resolution'),
            'LoadLibraryA':                ('MEDIUM', 'api_resolution'),
            'LoadLibraryW':                ('MEDIUM', 'api_resolution'),
        }

        findings = []
        seen = set()
        for dll, funcs in self.imports.items():
            for fn in funcs:
                if fn in SUSPICIOUS_APIS:
                    key = (fn, dll)
                    if key not in seen:
                        seen.add(key)
                        severity, category = SUSPICIOUS_APIS[fn]
                        findings.append({
                            'api':      fn,
                            'dll':      dll,
                            'severity': severity,
                            'category': category,
                        })

        # Sort CRITICAL first
        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda x: order.get(x['severity'], 9))
        return findings

    def scan_anti_debug_patterns(self) -> list:
        """
        Scan raw bytes for anti-debug byte patterns that don't appear in imports.
        Sources: PMA ch16 (INT scanning, NtGlobalFlag, heap flags, timing).

        Returns list of {'pattern': str, 'offset': int, 'description': str, 'severity': str}.
        """
        findings = []

        # INT 3 sled (0xCC repeated >= 3 times) -- checksum INT scanning defense
        for m in re.finditer(rb'\xcc{3,}', self.data):
            findings.append({
                'pattern':     'INT3_SLED',
                'offset':      m.start(),
                'description': 'INT 3 sled; possible breakpoint scanning or shellcode NOP equivalent',
                'severity':    'LOW',
            })

        # RDTSC opcode (0F 31) -- timing check, used as anti-debug and anti-VM
        for m in re.finditer(rb'\x0f\x31', self.data):
            findings.append({
                'pattern':     'RDTSC',
                'offset':      m.start(),
                'description': 'RDTSC instruction; timing-based anti-debug or anti-VM',
                'severity':    'MEDIUM',
            })

        # CPUID (0F A2) -- used to detect hypervisor (ECX bit 31 in leaf 1)
        for m in re.finditer(rb'\x0f\xa2', self.data):
            findings.append({
                'pattern':     'CPUID',
                'offset':      m.start(),
                'description': 'CPUID instruction; hypervisor/VM detection',
                'severity':    'MEDIUM',
            })

        # NtGlobalFlag check pattern: 0x70 offset from PEB
        # Typical asm: mov eax, fs:[30h]; cmp dword ptr [eax+68h], 70h
        # Byte seq: 64 A1 30 00 00 00 (mov eax, fs:[0x30]) + later 68 check
        for m in re.finditer(rb'\x64\xa1\x30\x00\x00\x00', self.data):
            findings.append({
                'pattern':     'PEB_ACCESS',
                'offset':      m.start(),
                'description': 'Direct PEB access via FS:[0x30]; NtGlobalFlag or BeingDebugged check',
                'severity':    'HIGH',
            })

        # 64-bit PEB: GS:[60h]
        for m in re.finditer(rb'\x65\x48\x8b\x04\x25\x60\x00\x00\x00', self.data):
            findings.append({
                'pattern':     'PEB_ACCESS_64',
                'offset':      m.start(),
                'description': 'Direct PEB access via GS:[0x60]; BeingDebugged or NtGlobalFlag check (64-bit)',
                'severity':    'HIGH',
            })

        # VMware I/O port backdoor: IN EAX, DX with magic 'VMXh'
        for m in re.finditer(rb'VMXh', self.data):
            findings.append({
                'pattern':     'VMWARE_MAGIC',
                'offset':      m.start(),
                'description': 'VMware magic string VMXh; anti-VM I/O port backdoor check',
                'severity':    'HIGH',
            })

        # VirtualBox string artifacts
        for m in re.finditer(rb'(?:VBoxGuest|VirtualBox|VBOX)', self.data, re.IGNORECASE):
            findings.append({
                'pattern':     'VIRTUALBOX_STRING',
                'offset':      m.start(),
                'description': 'VirtualBox artifact string; anti-VM detection',
                'severity':    'HIGH',
            })

        return findings

    def scan_rootkit_indicators(self) -> list:
        """
        Scan for rootkit-related strings and patterns.
        Sources: PMA ch10 (kernel debugging), ch rootkits (SSDT, DKOM, IAT hooks).

        Returns list of {'indicator': str, 'value': str, 'severity': str}.
        """
        findings = []
        seen = set()

        # Known rootkit / driver strings
        rootkit_strings = [
            # SSDT hooking infrastructure
            b'KeServiceDescriptorTable',
            b'KeServiceDescriptorTableShadow',
            b'NtfsControlFile',
            # DKOM (Direct Kernel Object Manipulation)
            b'PsGetCurrentProcess',
            b'PsLookupProcessByProcessId',
            b'ObReferenceObjectByHandle',
            # Driver load paths used by rootkits
            b'\\\\.\\',         # device namespace (raw device access)
            b'\\Device\\',
            b'\\DosDevices\\',
            b'\\BaseNamedObjects\\',
            # MBR/bootkit markers
            b'BOOTMGR',
            b'ntldr',
            # Usermode IAT hook artifacts
            b'ntdll.dll',       # common IAT hook target
            b'KiUserExceptionDispatcher',
            b'LdrLoadDll',
        ]

        for pat in rootkit_strings:
            for m in re.finditer(re.escape(pat), self.data, re.IGNORECASE):
                val = pat.decode('ascii', errors='replace')
                key = ('rootkit_string', val)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        'indicator': 'rootkit_string',
                        'value':     val,
                        'offset':    m.start(),
                        'severity':  'HIGH',
                    })

        # SE_DEBUG_PRIVILEGE strings (privilege escalation prelude)
        for m in re.finditer(rb'SeDebugPrivilege', self.data, re.IGNORECASE):
            key = ('privilege', 'SeDebugPrivilege')
            if key not in seen:
                seen.add(key)
                findings.append({
                    'indicator': 'debug_privilege',
                    'value':     'SeDebugPrivilege',
                    'offset':    m.start(),
                    'severity':  'HIGH',
                })

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _rva_to_offset(self, rva: int) -> Optional[int]:
        """Convert RVA to file offset using the section table. Returns None on failure."""
        if rva == 0:
            return None
        for s in self.sections:
            va   = s['vaddr']
            vsz  = s['vsize']
            raw  = s['raw_offset']
            rsz  = s['raw_size']
            # Use max(vsize, raw_size) as the upper bound for the section's virtual extent
            extent = max(vsz, rsz)
            if va <= rva < va + extent:
                offset = raw + (rva - va)
                if 0 <= offset < len(self.data):
                    return offset
        # Fallback: identity map for RVAs that land in header area
        if rva < self.sections[0]['vaddr'] if self.sections else True:
            if rva < len(self.data):
                return rva
        return None

    def _read_str(self, offset: Optional[int]) -> Optional[str]:
        """Read null-terminated ASCII string from offset. Returns None on failure."""
        if offset is None or offset >= len(self.data):
            return None
        end = self.data.find(b'\x00', offset)
        if end == -1 or end - offset > 256:
            end = offset + 256
        try:
            return self.data[offset:end].decode('ascii', errors='replace').strip()
        except Exception:
            return None

    def _shannon_entropy(self, data: bytes) -> float:
        """Shannon entropy in bits/byte. Returns 0.0 on empty input."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for f in freq:
            if f:
                p = f / length
                entropy -= p * math.log2(p)
        return entropy

    def summary(self) -> dict:
        """Return a dict with machine type, section count, import DLL count."""
        arch_map = {
            self.IMAGE_FILE_MACHINE_I386:  'x86',
            self.IMAGE_FILE_MACHINE_AMD64: 'x86-64',
            self.IMAGE_FILE_MACHINE_ARM64: 'ARM64',
        }
        return {
            'valid':        self.valid,
            'arch':         arch_map.get(self.machine, f'unknown({self.machine:#06x})'),
            'is_64bit':     self.is_64bit,
            'timestamp':    self.timestamp,
            'sections':     len(self.sections),
            'import_dlls':  len(self.imports),
            'exports':      len(self.exports),
            'entry_point':  hex(self.entry_point_rva),
            'image_base':   hex(self.image_base),
        }


# ------------------------------------------------------------------
# Module-level convenience function
# ------------------------------------------------------------------

def scan_pe_file(path: str) -> dict:
    """
    Read a PE file, parse it, and run all analysis passes.

    Returns consolidated dict:
    {
        'path':            str,
        'summary':         dict,
        'sections':        list,
        'imports':         dict,
        'exports':         list,
        'strings':         list,
        'iocs':            list,
        'malware_apis':    list,
        'anti_debug':      list,
        'rootkit':         list,
        'error':           str or None,
    }
    """
    result = {
        'path':          path,
        'summary':       {},
        'sections':      [],
        'imports':       {},
        'exports':       [],
        'strings':       [],
        'iocs':          [],
        'malware_apis':  [],
        'anti_debug':    [],
        'rootkit':       [],
        'error':         None,
    }
    try:
        with open(path, 'rb') as fh:
            data = fh.read()
    except OSError as exc:
        result['error'] = str(exc)
        return result

    try:
        pe = PEParser(data)
        if not pe.valid:
            result['error'] = 'Not a valid PE file (bad MZ/PE signature)'
            return result

        result['summary']        = pe.summary()
        result['sections']       = pe.get_sections()
        result['imports']        = pe.get_imports()
        result['exports']        = pe.exports
        result['strings']        = pe.get_strings()
        result['iocs']           = pe.scan_ioc_strings()
        result['malware_apis']   = pe.scan_malware_apis()
        result['anti_debug']     = pe.scan_anti_debug_patterns()
        result['rootkit']        = pe.scan_rootkit_indicators()
    except Exception as exc:  # noqa: BLE001
        result['error'] = f'Parse error: {exc}'

    return result


if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <pe_file>')
        sys.exit(1)

    out = scan_pe_file(sys.argv[1])
    if out['error']:
        print(f'ERROR: {out["error"]}', file=sys.stderr)
        sys.exit(1)

    # Compact report to stdout
    s = out['summary']
    print(f"PE: {out['path']}")
    print(f"Arch={s['arch']}  EP={s['entry_point']}  Sections={s['sections']}  Imports={s['import_dlls']}")
    if out['malware_apis']:
        print(f"\nSuspicious APIs ({len(out['malware_apis'])}):")
        for a in out['malware_apis']:
            print(f"  [{a['severity']:<8}] {a['api']:<35} ({a['category']})  from {a['dll']}")
    if out['iocs']:
        print(f"\nIOC strings ({len(out['iocs'])}):")
        for i in out['iocs']:
            print(f"  [{i['severity']:<8}] {i['type']:<30} {i['value'][:80]}")
    if out['anti_debug']:
        print(f"\nAnti-debug patterns ({len(out['anti_debug'])}):")
        for p in out['anti_debug']:
            print(f"  [{p['severity']:<8}] {p['pattern']:<20} @{p['offset']:#010x}  {p['description']}")
    if out['rootkit']:
        print(f"\nRootkit indicators ({len(out['rootkit'])}):")
        for r in out['rootkit']:
            print(f"  [{r['severity']:<8}] {r['indicator']:<25} {r['value']}")
