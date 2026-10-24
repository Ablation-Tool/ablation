"""Tests for CommandTableScanner.

Known-positive: IBM Storage Defender Sentinel dispatch (non-PIE ET_EXEC, 183MB,
18584 funcs) — Q-shell command dispatch table at VA 0xbadca80 confirmed in session 12.

Known-negative: a small ELF with no pointer tables produces no tables.
"""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

DISPATCH = '/tmp/ds_re/cyberv_extracted/opt/ie/bin/dispatch'


def _dispatch_available():
    return Path(DISPATCH).exists()


# ---------------------------------------------------------------------------
# Synthetic minimal ELF — no data pointers → no tables
# ---------------------------------------------------------------------------

def _make_empty_elf() -> bytes:
    """Return a minimal x86-64 ELF with a .text section and no data section."""
    # ELF header
    e_ident = b'\x7fELF\x02\x01\x01' + b'\x00' * 9  # 16 bytes
    # Build sections: just a tiny .text with a ret instruction
    text_data = b'\xc3'  # ret
    shstrtab  = b'\x00.text\x00.shstrtab\x00'
    # Section headers at offset 64 + len(text) + len(shstrtab)
    text_off    = 64
    shstrtab_off = text_off + len(text_data)
    sh_off      = shstrtab_off + len(shstrtab)
    # Pad to 8-byte align
    pad = (8 - len(shstrtab) % 8) % 8
    sh_off += pad
    shstrtab_padded = shstrtab + b'\x00' * pad

    SHT_NULL   = 0
    SHT_PROGBITS = 1
    SHT_STRTAB = 3
    SHF_ALLOC  = 0x2
    SHF_EXEC   = 0x4

    def sh_entry(name_idx, stype, flags, addr, offset, size, link=0, info=0, align=1, entsize=0):
        return struct.pack('<IIQQQQIIQQ', name_idx, stype, flags, addr, offset, size,
                           link, info, align, entsize)

    sh_null     = sh_entry(0, SHT_NULL, 0, 0, 0, 0)
    sh_text     = sh_entry(1, SHT_PROGBITS, SHF_ALLOC | SHF_EXEC, 0x400000, text_off,
                            len(text_data), align=16)
    sh_shstrtab = sh_entry(7, SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab))

    shdrs = sh_null + sh_text + sh_shstrtab

    e_shoff     = sh_off
    e_shnum     = 3
    e_shstrndx  = 2
    e_shentsize = 64

    header = (
        e_ident
        + struct.pack('<HHI', 2, 62, 1)          # e_type=ET_EXEC, e_machine=x86-64, e_version
        + struct.pack('<QQQ', 0x400000, 64, 0)   # e_entry, e_phoff=0, e_shoff placeholder
        + struct.pack('<IHH', 0, 64, 0)          # e_flags, e_ehsize, e_phentsize
        + struct.pack('<HHH', 0, e_shentsize, e_shnum)
        + struct.pack('<H', e_shstrndx)
    )
    # Patch e_shoff at offset 40
    header = header[:40] + struct.pack('<Q', e_shoff) + header[48:]

    return header + text_data + shstrtab_padded + shdrs


class TestCommandTableScannerSynthetic:
    def test_no_tables_on_minimal_elf(self, tmp_path):
        from ablation.analyzers.command_table_scanner import CommandTableScanner
        elf = tmp_path / 'minimal.elf'
        elf.write_bytes(_make_empty_elf())
        scanner = CommandTableScanner.from_path(str(elf))
        tables = scanner.scan()
        assert tables == [], f'expected no tables, got {tables}'

    def test_from_path_and_from_context_equivalent(self, tmp_path):
        from ablation.analyzers.command_table_scanner import CommandTableScanner

        class FakeCtx:
            binary_path = None
            path = None

        elf = tmp_path / 'minimal.elf'
        elf.write_bytes(_make_empty_elf())
        FakeCtx.binary_path = str(elf)
        FakeCtx.path = str(elf)

        s1 = CommandTableScanner.from_path(str(elf))
        s2 = CommandTableScanner.from_context(FakeCtx)
        assert s1.scan() == s2.scan()

    def test_report_no_tables(self, tmp_path):
        from ablation.analyzers.command_table_scanner import CommandTableScanner
        elf = tmp_path / 'minimal.elf'
        elf.write_bytes(_make_empty_elf())
        scanner = CommandTableScanner.from_path(str(elf))
        rep = CommandTableScanner.report(scanner.scan())
        assert 'no dispatch tables found' in rep

    def test_report_with_tables_contains_command_names(self, tmp_path):
        from ablation.analyzers.command_table_scanner import CommandTableScanner, CommandTable, CommandEntry
        fake_tables = [
            CommandTable(
                start_va=0xbadca80,
                start_offset=0x100,
                stride=3,
                entries=[
                    CommandEntry(
                        table_offset=0x100, entry_va=0xbadca80,
                        name='query', name_va=0x1234, handler_va=0x5678, stride=3,
                    ),
                    CommandEntry(
                        table_offset=0x118, entry_va=0xbadca98,
                        name='echo', name_va=0x1240, handler_va=0x5700, stride=3,
                    ),
                ],
            )
        ]
        rep = CommandTableScanner.report(fake_tables)
        assert 'query' in rep
        assert 'echo' in rep
        assert 'badca80' in rep


@pytest.mark.skipif(not _dispatch_available(), reason='dispatch binary not extracted')
class TestCommandTableScannerDispatch:
    def test_finds_qshell_command_table(self):
        from ablation.analyzers.command_table_scanner import CommandTableScanner
        scanner = CommandTableScanner.from_path(DISPATCH)
        tables  = scanner.scan()
        assert tables, 'expected at least one command table in dispatch'

    def test_qshell_table_contains_known_commands(self):
        from ablation.analyzers.command_table_scanner import CommandTableScanner
        scanner = CommandTableScanner.from_path(DISPATCH)
        tables  = scanner.scan()
        all_names = {e.name for tbl in tables for e in tbl.entries}
        expected = {'query', 'echo', 'help', 'source', 'exit'}
        found = expected & all_names
        assert found, f'expected Q-shell commands in table, found names: {sorted(all_names)[:20]}'

    def test_source_command_has_handler_in_text(self):
        from ablation.analyzers.command_table_scanner import CommandTableScanner
        scanner = CommandTableScanner.from_path(DISPATCH)
        tables  = scanner.scan()
        source_entries = [
            e for tbl in tables for e in tbl.entries if e.name == 'source'
        ]
        assert source_entries, '"source" command not found in any table'
        for e in source_entries:
            assert scanner._in_text(e.handler_va), (
                f'"source" handler_va {e.handler_va:#x} not in text section'
            )
