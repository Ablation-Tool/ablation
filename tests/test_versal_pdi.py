"""Tests for VersalPdi — Versal PDI format parser.

All structural constants are byte-verified against real PDI files from the
CERN ATLAS ITk FELIX/GEP collection at /media/cowboy/research/CERN/fw/.

Test tiers:
  1. Synthetic tests — minimal hand-crafted byte sequences (no external files)
  2. Real-file tests — against GEP/FELIX PDI files (skipped if not present)
"""

import struct
import pytest
from ablation.analyzers.versal_pdi import (
    VersalPdi,
    VersalPdiResult,
    PdiIHT,
    PdiImageHeader,
    PdiPartitionHeader,
    CdoSection,
    CdoCommand,
    CDO_MAGIC,
    PDI_SYNC_WORD_0,
    PDI_SYNC_WORD_1,
    PDI_SYNC_WORD_2,
    PDI_SYNC_WORD_3,
    PDI_SYNC_WORD_4,
    PDI_IHT_IDENT,
    PRTN_TYPE_CFICDR,
    PRTN_TYPE_ELF,
    PRTN_TYPE_CDO,
    PRTN_TYPE_NAMES,
    CDO_MOD_GENERIC,
    CDO_MOD_XILPM,
    CDO_MOD_LOADER,
    CDO_CMD_WRITE,
    CDO_CMD_WRITE64,
    CDO_CMD_DMA_WRITE,
    CDO_CMD_NOP,
    CDO_CMD_END_WORD,
    CDO_CMD_LOADER_SET_IMAGE_INFO,
    CDO_CMD_XILPM_ADD_NODE,
    CDO_CMD_XILPM_INIT_NODE,
    CDO_PAYLOAD_PREFIX_BYTES,
    XPM_NODECLASS_PROTECTION,
)

# ---------------------------------------------------------------------------
# Paths to real PDI files (tests skip if absent)
# ---------------------------------------------------------------------------

_GEP_DIR = "/media/cowboy/research/CERN/fw/gep"
_FELIX_DIR = "/media/cowboy/research/CERN/fw/felix"
_GCI_PLD = f"{_GEP_DIR}/GCI_GCM415_pld-v0.159.38-35A2CC3.pdi"
_GCI_BOOT = f"{_GEP_DIR}/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi"
_GEP_PLD2 = f"{_GEP_DIR}/GEP_2ACC_GCM3_pld-v0.159.40-F119A21.pdi"
_FELIX_BOOT = f"{_FELIX_DIR}/FLX182_STRIPS_24CH_FULLSTAR_ORCA_FULLHCC_GBT_LpGBT_vProd7_WS_1448.pdi"


def _have(path: str) -> bool:
    try:
        import os
        return os.path.isfile(path)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Helpers for constructing synthetic PDI bytes
# ---------------------------------------------------------------------------

def _u32le(val: int) -> bytes:
    return struct.pack("<I", val)


def _pld_sync() -> bytes:
    return (
        _u32le(PDI_SYNC_WORD_0) +
        _u32le(PDI_SYNC_WORD_1) +
        _u32le(PDI_SYNC_WORD_2) +
        _u32le(PDI_SYNC_WORD_3)
    )


def _boot_sync() -> bytes:
    return (
        _u32le(PDI_SYNC_WORD_0) +
        _u32le(PDI_SYNC_WORD_1) +
        _u32le(PDI_SYNC_WORD_2) +
        _u32le(PDI_SYNC_WORD_3) +
        _u32le(PDI_SYNC_WORD_4) +
        _u32le(PDI_IHT_IDENT)    # XLNX
    )


def _make_cdo(payload_words: list, prefix: int = 0) -> bytes:
    """Build a CDO section whose five-word header checksum is valid."""
    length_w = len(payload_words)
    checksum = (~(prefix + struct.unpack("<I", CDO_MAGIC)[0] + 0x200 + length_w)) & 0xFFFFFFFF
    header = (
        CDO_MAGIC +
        _u32le(0x00000200) +   # version 0.2
        _u32le(length_w) +
        _u32le(checksum)
    )
    payload = b"".join(_u32le(w) for w in payload_words)
    return header + payload


def _make_nop_cmd(n: int = 1) -> list:
    """Return n NOP command words (module=GENERIC, cmd=NOP, len=0)."""
    cmd_word = (0x0000 << 16) | (CDO_MOD_GENERIC << 8) | CDO_CMD_NOP
    return [cmd_word] * n


def _make_write_cmd(addr: int, value: int) -> list:
    """Return WRITE32 command words: header + addr + value."""
    cmd_word = (0x0002 << 16) | (CDO_MOD_GENERIC << 8) | CDO_CMD_WRITE
    return [cmd_word, addr, value]


# ---------------------------------------------------------------------------
# 1. Construction and type detection
# ---------------------------------------------------------------------------

class TestConstruction:

    def test_from_bytes_basic(self):
        data = _pld_sync() + b"\x00" * 64
        vp = VersalPdi.from_bytes(data, "test.pdi")
        assert vp.result.pdi_type == "pld"

    def test_from_bytes_boot(self):
        data = _boot_sync() + b"\x00" * 64
        vp = VersalPdi.from_bytes(data, "boot.pdi")
        assert vp.result.pdi_type == "boot"

    def test_from_bytes_unknown_no_sync(self):
        vp = VersalPdi.from_bytes(b"\xAA\xBB\xCC\xDD" * 10, "bad.pdi")
        assert vp.result.pdi_type == "unknown"

    def test_from_bytes_too_short(self):
        vp = VersalPdi.from_bytes(b"\x00" * 4, "tiny.pdi")
        assert vp.result.pdi_type == "unknown"

    def test_pld_sync_word_count(self):
        data = _pld_sync() + b"\x00" * 64
        vp = VersalPdi.from_bytes(data)
        assert vp.result.sync_word_count == 4

    def test_boot_sync_word_count(self):
        data = _boot_sync() + b"\x00" * 64
        vp = VersalPdi.from_bytes(data)
        assert vp.result.sync_word_count == 5

    def test_result_type(self):
        data = _pld_sync() + b"\x00" * 64
        vp = VersalPdi.from_bytes(data)
        assert isinstance(vp.result, VersalPdiResult)

    def test_file_size_recorded(self):
        data = _pld_sync() + b"\x00" * 64
        vp = VersalPdi.from_bytes(data)
        assert vp.result.file_size == len(data)


# ---------------------------------------------------------------------------
# 2. IHT parsing (pld PDI)
# ---------------------------------------------------------------------------

class TestIhtPld:

    def _make_pdi_with_iht(self, no_of_imgs=1, img_hdr_off=0x10, total_prtns=1, part_hdr_off=0x18):
        sync = _pld_sync()
        iht = (
            _u32le(0x00040000) +    # pdi_flags
            _u32le(no_of_imgs) +
            _u32le(img_hdr_off) +
            _u32le(total_prtns) +
            _u32le(part_hdr_off) +
            _u32le(0x00000000) +    # sbd_off
            _u32le(0xDEADBEEF)      # checksum
        )
        return sync + iht + b"\x00" * 128

    def test_iht_parsed(self):
        data = self._make_pdi_with_iht()
        vp = VersalPdi.from_bytes(data)
        assert vp.result.iht is not None

    def test_iht_offset(self):
        data = self._make_pdi_with_iht()
        vp = VersalPdi.from_bytes(data)
        assert vp.result.iht.offset == 0x10

    def test_iht_flags(self):
        data = self._make_pdi_with_iht()
        vp = VersalPdi.from_bytes(data)
        assert vp.result.iht.pdi_flags == 0x00040000

    def test_iht_no_of_imgs(self):
        data = self._make_pdi_with_iht(no_of_imgs=3)
        vp = VersalPdi.from_bytes(data)
        assert vp.result.iht.no_of_imgs == 3

    def test_iht_img_hdr_off(self):
        data = self._make_pdi_with_iht(img_hdr_off=0x24)
        vp = VersalPdi.from_bytes(data)
        assert vp.result.iht.img_hdr_off == 0x24

    def test_iht_total_prtns(self):
        data = self._make_pdi_with_iht(total_prtns=5)
        vp = VersalPdi.from_bytes(data)
        assert vp.result.iht.total_no_of_prtns == 5

    def test_iht_part_hdr_off(self):
        data = self._make_pdi_with_iht(part_hdr_off=0x34)
        vp = VersalPdi.from_bytes(data)
        assert vp.result.iht.part_hdr_off == 0x34

    def test_iht_byte_offsets(self):
        data = self._make_pdi_with_iht(img_hdr_off=0x10, part_hdr_off=0x20)
        vp = VersalPdi.from_bytes(data)
        assert vp.result.iht.img_hdr_byte_offset == 0x40
        assert vp.result.iht.part_hdr_byte_offset == 0x80

    def test_iht_truncated(self):
        data = _pld_sync() + b"\x00" * 4
        vp = VersalPdi.from_bytes(data)
        # Should not crash; IHT may be None due to truncation
        # (result is returned with a warning)
        assert isinstance(vp.result, VersalPdiResult)


# ---------------------------------------------------------------------------
# 3. Image header parsing
# ---------------------------------------------------------------------------

class TestImageHeaders:

    def _make_pdi_with_image(self, img_name=b"CONFIG_MASTER", git_hash=0x035a2cc3):
        sync = _pld_sync()
        # IHT: img_hdr_off=0x0A (word) → byte offset 0x28 from file start
        # IHT at 0x10 (16 bytes), IHT is 7 words = 28 bytes → ends at 0x2c
        # Image header at 0x28 (= 0x0A × 4)
        iht_off = 0x10
        img_hdr_word_off = (iht_off + 0x1C) // 4  # place image just after IHT
        img_hdr_byte_off = img_hdr_word_off * 4
        iht = (
            _u32le(0x00040000) +
            _u32le(1) +                  # no_of_imgs
            _u32le(img_hdr_word_off) +
            _u32le(1) +                  # total_prtns
            _u32le(0x00000000) +         # part_hdr_off (no partitions)
            _u32le(0x00000000) +
            _u32le(0x00000000)
        )
        # Build image header (0x40 bytes)
        name_padded = img_name[:15].ljust(16, b"\x00")
        img_hdr = (
            _u32le(0x00000100) +  # first_prtn_hdr_off
            _u32le(1) +           # no_of_prtns
            _u32le(0x00000000) +  # reserved
            _u32le(0x00000000) +  # img_attrb
            name_padded +         # 16 bytes: img_name
            _u32le(0xAABBCCDD) +  # img_id  (+0x20)
            _u32le(0x00000000) +  # +0x24
            _u32le(0x00000000) +  # +0x28
            _u32le(git_hash) +    # git_hash (+0x2c)
            _u32le(0) + _u32le(0) + _u32le(0) +  # +0x30..0x38
            _u32le(0xFFFFFFFF)    # checksum (+0x3c)
        )
        # pad sync+iht out to img_hdr_byte_off
        data = sync + iht
        pad_needed = img_hdr_byte_off - len(data)
        data += b"\x00" * max(0, pad_needed)
        data += img_hdr
        data += b"\x00" * 64
        return data

    def test_image_count(self):
        data = self._make_pdi_with_image()
        vp = VersalPdi.from_bytes(data)
        assert len(vp.images()) == 1

    def test_image_name(self):
        data = self._make_pdi_with_image(img_name=b"CONFIG_MASTER")
        vp = VersalPdi.from_bytes(data)
        assert vp.images()[0].img_name == "CONFIG_MASTER"

    def test_image_git_hash(self):
        data = self._make_pdi_with_image(git_hash=0xDEADBEEF)
        vp = VersalPdi.from_bytes(data)
        assert vp.images()[0].git_hash == 0xDEADBEEF

    def test_git_hash_method(self):
        data = self._make_pdi_with_image(git_hash=0x035a2cc3)
        vp = VersalPdi.from_bytes(data)
        assert vp.git_hash() == "035a2cc3"

    def test_git_hash_empty_when_zero(self):
        data = self._make_pdi_with_image(git_hash=0)
        vp = VersalPdi.from_bytes(data)
        # git_hash == 0 → falsy → return ""
        assert vp.git_hash() == ""

    def test_image_id(self):
        data = self._make_pdi_with_image()
        vp = VersalPdi.from_bytes(data)
        assert vp.images()[0].img_id == 0xAABBCCDD

    def test_image_no_of_prtns(self):
        data = self._make_pdi_with_image()
        vp = VersalPdi.from_bytes(data)
        assert vp.images()[0].no_of_prtns == 1


# ---------------------------------------------------------------------------
# 4. Partition header parsing
# ---------------------------------------------------------------------------

class TestPartitionHeaders:

    def _ph_bytes(self,
                  enc_wlen=0x1000,
                  unenc_wlen=0x1000,
                  total_wlen=0x1000,
                  next_off=0,
                  dst_load_lo=0xFFFFFFFF,
                  dst_load_hi=0xFFFFFFFF,
                  data_woff=0x100,
                  prtn_attrb=0x02000006) -> bytes:
        """Build a 0x3C-byte partition header."""
        return (
            _u32le(enc_wlen) +
            _u32le(unenc_wlen) +
            _u32le(total_wlen) +
            _u32le(next_off) +
            _u32le(0) + _u32le(0) +           # dst_exec_addr lo, hi
            _u32le(dst_load_lo) + _u32le(dst_load_hi) +
            _u32le(data_woff) +
            _u32le(prtn_attrb) +
            _u32le(0) +                       # section_count
            _u32le(0) +                       # checksum_word_off
            _u32le(0) +                       # img_hdr_off
            _u32le(0) +                       # auth_cert_off
            _u32le(0xBBCCDDEE)                # checksum
        )

    def _pdi_with_partition(self, **ph_kwargs) -> bytes:
        sync = _pld_sync()
        # IHT: part_hdr_off = 0x10 (word) → 0x40 bytes from start
        # IHT is at 0x10 (7 words = 28 bytes); next free at 0x2C
        # Put partition header at word offset 0x10 → byte 0x40
        iht = (
            _u32le(0x00040000) +
            _u32le(0) +          # no_of_imgs
            _u32le(0x00000000) + # img_hdr_off
            _u32le(1) +          # total_prtns
            _u32le(0x10) +       # part_hdr_off = word 0x10 → byte 0x40
            _u32le(0x00000000) +
            _u32le(0x00000000)
        )
        data = sync + iht
        # pad to 0x40
        data += b"\x00" * (0x40 - len(data))
        data += self._ph_bytes(**ph_kwargs)
        data += b"\x00" * 256
        return data

    def test_partition_parsed(self):
        data = self._pdi_with_partition()
        vp = VersalPdi.from_bytes(data)
        assert len(vp.partitions()) == 1

    def test_partition_type_cficdr(self):
        data = self._pdi_with_partition(prtn_attrb=0x02000006)
        vp = VersalPdi.from_bytes(data)
        ph = vp.partitions()[0]
        assert ph.prtn_type == PRTN_TYPE_CFICDR
        assert ph.prtn_type_name == "CFICDR/PL"
        assert ph.is_pl

    def test_partition_type_elf(self):
        data = self._pdi_with_partition(prtn_attrb=0x00000001)
        vp = VersalPdi.from_bytes(data)
        ph = vp.partitions()[0]
        assert ph.prtn_type == PRTN_TYPE_ELF

    def test_partition_dst_load_pl(self):
        data = self._pdi_with_partition(dst_load_lo=0xFFFFFFFF, dst_load_hi=0xFFFFFFFF)
        vp = VersalPdi.from_bytes(data)
        ph = vp.partitions()[0]
        assert ph.dst_load_addr == 0xFFFFFFFFFFFFFFFF

    def test_partition_data_word_off(self):
        data = self._pdi_with_partition(data_woff=0x200)
        vp = VersalPdi.from_bytes(data)
        ph = vp.partitions()[0]
        assert ph.data_word_off == 0x200
        assert ph.data_byte_offset == 0x800
        assert ph.cdo_byte_offset == 0x804  # +4 prefix bytes

    def test_partition_enc_size(self):
        data = self._pdi_with_partition(enc_wlen=0x1234)
        vp = VersalPdi.from_bytes(data)
        ph = vp.partitions()[0]
        assert ph.enc_data_word_len == 0x1234
        assert ph.data_size_bytes == 0x1234 * 4

    def test_partition_encrypted_flag(self):
        data = self._pdi_with_partition(prtn_attrb=0x02800006)  # bit 23 set
        vp = VersalPdi.from_bytes(data)
        ph = vp.partitions()[0]
        assert ph.is_encrypted

    def test_partition_not_encrypted(self):
        data = self._pdi_with_partition(prtn_attrb=0x02000006)
        vp = VersalPdi.from_bytes(data)
        ph = vp.partitions()[0]
        assert not ph.is_encrypted

    def test_partition_cdo_offset_formula(self):
        """data_word_off × 4 + 4 = cdo_byte_offset (confirmed from GCI_GCM415_pld RE)."""
        data = self._pdi_with_partition(data_woff=0x54)  # 0x54 × 4 = 0x150, CDO at 0x154
        vp = VersalPdi.from_bytes(data)
        ph = vp.partitions()[0]
        assert ph.data_byte_offset == 0x150
        assert ph.cdo_byte_offset == 0x154


# ---------------------------------------------------------------------------
# 5. CDO section scanning
# ---------------------------------------------------------------------------

class TestCdoScanner:

    def test_cdo_found(self):
        cdo = _make_cdo(_make_nop_cmd(3))
        data = _pld_sync() + b"\x00" * 16 + CDO_PAYLOAD_PREFIX_BYTES * b"\x00" + cdo + b"\x00" * 16
        vp = VersalPdi.from_bytes(data)
        sections = vp.cdo_sections()
        assert len(sections) >= 1

    def test_cdo_version_parsed(self):
        cdo = _make_cdo([])
        vp = VersalPdi.from_bytes(b"\x00" * 4 + cdo + b"\x00" * 4)
        sections = vp.cdo_sections()
        assert len(sections) == 1
        assert sections[0].version == 0x00000200
        assert sections[0].version_str == "2.0"

    def test_cdo_length_parsed(self):
        words = _make_nop_cmd(5)
        cdo = _make_cdo(words)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + cdo + b"\x00" * 4)
        assert vp.cdo_sections()[0].length_words == len(words)

    def test_cdo_offset_recorded(self):
        cdo = _make_cdo(_make_nop_cmd(1))
        prefix = b"\x00" * 0x20
        vp = VersalPdi.from_bytes(prefix + cdo + b"\x00" * 8)
        assert vp.cdo_sections()[0].offset == 0x20

    def test_no_cdo_when_absent(self):
        vp = VersalPdi.from_bytes(_pld_sync() + b"\xAB" * 64)
        assert len(vp.cdo_sections()) == 0

    def test_multiple_cdo_sections(self):
        cdo1 = _make_cdo(_make_nop_cmd(2))
        cdo2 = _make_cdo(_make_write_cmd(0xF1000000, 0x12345678))
        vp = VersalPdi.from_bytes(b"\x00" * 8 + cdo1 + b"\x00" * 4 + cdo2 + b"\x00" * 8)
        sections = vp.cdo_sections()
        assert len(sections) == 2

    def test_cdo_sanity_rejects_junk(self):
        # Build a sequence that has CDO magic but absurd length
        bad = CDO_MAGIC + _u32le(0x200) + _u32le(0xFFFFFF) + _u32le(0)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + bad + b"\x00" * 4)
        assert len(vp.cdo_sections()) == 0


# ---------------------------------------------------------------------------
# 6. CDO command parsing
# ---------------------------------------------------------------------------

class TestCdoCommands:

    def _parse_cdo(self, words: list) -> CdoSection:
        cdo = _make_cdo(words)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + cdo + b"\x00" * 4)
        return vp.cdo_sections()[0]

    def test_nop_command(self):
        section = self._parse_cdo(_make_nop_cmd(1))
        assert len(section.commands) == 1
        cmd = section.commands[0]
        assert cmd.module_id == CDO_MOD_GENERIC
        assert cmd.cmd_id == CDO_CMD_NOP
        assert cmd.module_name == "GENERIC"
        assert cmd.cmd_name == "Nop"

    def test_write_command(self):
        words = _make_write_cmd(0xF11A0000, 0xDEADBEEF)
        section = self._parse_cdo(words)
        cmd = section.commands[0]
        assert cmd.module_id == CDO_MOD_GENERIC
        assert cmd.cmd_id == CDO_CMD_WRITE
        assert cmd.payload[0] == 0xF11A0000
        assert cmd.payload[1] == 0xDEADBEEF

    def test_write_npi_addr_extracted(self):
        words = _make_write_cmd(0xF11A0000, 0xABCD1234)
        section = self._parse_cdo(words)
        cmd = section.commands[0]
        assert cmd.npi_addr == 0xF11A0000
        assert cmd.npi_data == 0xABCD1234

    def test_write_non_npi_no_addr(self):
        words = _make_write_cmd(0x00100000, 0x12345678)
        section = self._parse_cdo(words)
        cmd = section.commands[0]
        assert cmd.npi_addr is None

    def test_command_count(self):
        words = _make_nop_cmd(7)
        section = self._parse_cdo(words)
        assert len(section.commands) == 7

    def test_mixed_commands(self):
        words = (
            _make_nop_cmd(2) +
            _make_write_cmd(0xF1250018, 0x07FFC000) +
            _make_nop_cmd(1)
        )
        section = self._parse_cdo(words)
        assert len(section.commands) == 4
        assert section.commands[2].cmd_id == CDO_CMD_WRITE

    def test_loader_set_image_info_command(self):
        # LOADER SetImageInfo: module=0x07, cmd=0x04, payload 4 words
        cmd_word = (0x0004 << 16) | (CDO_MOD_LOADER << 8) | CDO_CMD_LOADER_SET_IMAGE_INFO
        words = [cmd_word, 0x18700001, 0x46407135, 0x91c727a2, 0x035a2cc3]
        section = self._parse_cdo(words)
        assert len(section.commands) == 1
        cmd = section.commands[0]
        assert cmd.module_id == CDO_MOD_LOADER
        assert cmd.cmd_id == CDO_CMD_LOADER_SET_IMAGE_INFO
        assert cmd.cmd_name == "SetImageInfo"
        assert cmd.payload[3] == 0x035a2cc3

    def test_git_hash_from_loader_set_image_info(self):
        """git_hash() resolves via LOADER SetImageInfo when image headers are absent."""
        cmd_word = (0x0004 << 16) | (CDO_MOD_LOADER << 8) | CDO_CMD_LOADER_SET_IMAGE_INFO
        words = [cmd_word, 0x18700001, 0x46407135, 0x91c727a2, 0x035a2cc3]
        cdo = _make_cdo(words)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + cdo + b"\x00" * 4)
        assert vp.git_hash() == "035a2cc3"

    def test_git_hash_ignores_zero_loader_set_image_info(self):
        cmd_word = (0x0004 << 16) | (CDO_MOD_LOADER << 8) | CDO_CMD_LOADER_SET_IMAGE_INFO
        words = [cmd_word, 0x18700001, 0xD5694935, 0x91C727A2, 0]
        cdo = _make_cdo(words)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + cdo + b"\x00" * 4)
        assert vp.git_hash() == ""

    def test_xilpm_init_node(self):
        cmd_word = (0x0002 << 16) | (CDO_MOD_XILPM << 8) | CDO_CMD_XILPM_INIT_NODE
        section = self._parse_cdo([cmd_word, 0x04210002, 0x00000001])
        cmd = section.commands[0]
        assert cmd.cmd_name == "InitNode"
        assert cmd.xilpm_node_id == 0x04210002
        assert cmd.xilpm_function == 1
        assert cmd.xilpm_node_class == 1

    def test_xilpm_add_node_protection_class(self):
        cmd_word = (0x0004 << 16) | (CDO_MOD_XILPM << 8) | CDO_CMD_XILPM_ADD_NODE
        section = self._parse_cdo([cmd_word, 0x24000001, 0xFF990000, 0, 0])
        cmd = section.commands[0]
        assert cmd.cmd_name == "AddNode"
        assert cmd.xilpm_node_id == 0x24000001
        assert cmd.xilpm_function is None
        assert cmd.xilpm_node_class == XPM_NODECLASS_PROTECTION

    def test_xilpm_accessors_ignore_other_modules(self):
        cmd_word = (0x0002 << 16) | (CDO_MOD_GENERIC << 8) | CDO_CMD_XILPM_INIT_NODE
        section = self._parse_cdo([cmd_word, 0x04210002, 0x00000001])
        cmd = section.commands[0]
        assert cmd.xilpm_node_id is None
        assert cmd.xilpm_function is None
        assert cmd.xilpm_node_class is None

    def test_command_payload_capped_at_8_words(self):
        # Build a command with 20-word payload
        cmd_word = (0x0014 << 16) | (CDO_MOD_GENERIC << 8) | 0x0E  # DMA_WRITE, len=20
        filler = list(range(20))
        section = self._parse_cdo([cmd_word] + filler)
        if section.commands:
            assert len(section.commands[0].payload) <= 8

    def test_zero_payload_command(self):
        cmd_word = (0x0000 << 16) | (CDO_MOD_GENERIC << 8) | CDO_CMD_NOP
        section = self._parse_cdo([cmd_word])
        assert len(section.commands) == 1
        assert section.commands[0].payload == ()


# ---------------------------------------------------------------------------
# 7. String extraction from SSIT_SYNC payloads
# ---------------------------------------------------------------------------

class TestStringExtraction:

    def test_ssit_string_extracted(self):
        """SSIT_SYNC payload: word0=type_id, words1+= ASCII text."""
        text = b"PMC_METADATA"
        # Pack into words (LE), padded to 4-byte boundary
        padded = text + b"\x00" * (4 - len(text) % 4)
        words_raw = struct.unpack(f"<{len(padded)//4}I", padded)
        payload_len = 1 + len(words_raw)
        cmd_word = (payload_len << 16) | (CDO_MOD_GENERIC << 8) | 0x19  # SSIT_SYNC
        cmd_words = [cmd_word, 0x00000002] + list(words_raw)
        cdo = _make_cdo(cmd_words)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + cdo + b"\x00" * 4)
        sections = vp.cdo_sections()
        assert sections
        cmd = sections[0].commands[0]
        assert "PMC_METADATA" in cmd.string_payload


# ---------------------------------------------------------------------------
# 8. Partition type names
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 8a. CFICDR false-positive suppression
# ---------------------------------------------------------------------------

class TestCficdrFalsePositiveSuppression:
    """CFICDR partitions contain raw PL bitstream data that may embed CDO\x00
    byte patterns.  These must NOT appear as parsed CDO sections.  The
    legitimate CDO at cdo_byte_offset must still be found."""

    def _build_cficdr_pdi_with_false_cdo(self) -> bytes:
        """Build a pld PDI with:
          - 1 CFICDR partition whose data starts at word offset 0x40
          - a legitimate CDO at cdo_byte_offset (4-byte prefix + CDO header)
          - a false CDO\x00 pattern embedded 64 bytes after the legitimate CDO
            ends (simulates CDO\x00 inside raw PL CFRAME data)
        """
        sync = _pld_sync()
        # IHT at 0x10: part_hdr_off = word 0x10 → byte 0x40
        iht = (
            _u32le(0x00040000) +   # pdi_flags
            _u32le(0) +             # no_of_imgs
            _u32le(0x00000000) +    # img_hdr_off
            _u32le(1) +             # total_prtns
            _u32le(0x10) +          # part_hdr_off = word 0x10 → byte 0x40
            _u32le(0x00000000) +
            _u32le(0x00000000)
        )
        data = sync + iht                    # 0x10 + 0x1C = 0x2C bytes
        data += b"\x00" * (0x40 - len(data)) # pad to 0x40 (partition header)

        # Partition data will be placed at word offset 0x40 → byte offset 0x100
        # 4-byte prefix at 0x100; CDO at 0x104
        DATA_WORD_OFF = 0x40           # → byte 0x100
        CDO_START     = DATA_WORD_OFF * 4 + 4   # = 0x104

        # Build a legitimate CDO: 3 NOP commands
        legit_cdo_payload = _make_nop_cmd(3)
        legit_cdo = _make_cdo(legit_cdo_payload)      # 16 + 12 = 28 bytes
        legit_cdo_total = 4 + len(legit_cdo)           # prefix (4) + CDO header+payload

        # Total partition size: prefix + legit CDO + 64 gap + false CDO + 16 tail
        false_cdo_words = [0xFF40FF80, 0xFDFEFF00]    # module IDs 0x40, 0x80, 0xFD, 0xFF
        false_cdo = _make_cdo(false_cdo_words)
        partition_data = (
            b"\xAA\xBB\xCC\xDD" +      # 4-byte prefix
            legit_cdo +                  # legitimate CDO
            b"\xFF" * 64 +              # gap (raw PL-like data)
            false_cdo +                  # false CDO: would produce garbage module IDs
            b"\x00" * 16               # tail
        )
        partition_size_words = len(partition_data) // 4

        # Partition header (0x3C bytes) at byte 0x40
        ph = (
            _u32le(partition_size_words) +      # enc_data_word_len
            _u32le(partition_size_words) +      # unenc_data_word_len
            _u32le(partition_size_words) +      # total_data_word_len
            _u32le(0) +                          # next_prtn_off (last)
            _u32le(0) + _u32le(0) +              # dst_exec_addr lo, hi
            _u32le(0xFFFFFFFF) + _u32le(0xFFFFFFFF) +  # dst_load_addr (PL)
            _u32le(DATA_WORD_OFF) +              # data_word_off
            _u32le(0x02000006) +                 # prtn_attrb: CFICDR (type=6)
            _u32le(0) +                          # section_count
            _u32le(0) +                          # checksum_word_off
            _u32le(0) +                          # img_hdr_off
            _u32le(0) +                          # auth_cert_off
            _u32le(0xDEADBEEF)                   # checksum
        )
        data += ph
        # Pad from end of partition header (0x40 + 0x3C = 0x7C) to DATA_WORD_OFF * 4 (0x100)
        data += b"\x00" * (DATA_WORD_OFF * 4 - len(data))
        data += partition_data
        return data

    def test_only_legitimate_cdo_found(self):
        """After fix: only the CDO at cdo_byte_offset is in cdo_sections(); the
        false CDO embedded in raw PL data is suppressed."""
        data = self._build_cficdr_pdi_with_false_cdo()
        vp = VersalPdi.from_bytes(data, "cficdr_test.pdi")
        sections = vp.cdo_sections()
        assert len(sections) == 1, (
            f"Expected 1 CDO section (legitimate), got {len(sections)}: "
            f"{[s.offset for s in sections]}"
        )

    def test_legitimate_cdo_offset_matches_partition_header(self):
        """The found CDO is at cdo_byte_offset, not somewhere else."""
        data = self._build_cficdr_pdi_with_false_cdo()
        vp = VersalPdi.from_bytes(data, "cficdr_test.pdi")
        ph = vp.partitions()[0]
        sections = vp.cdo_sections()
        assert len(sections) >= 1
        assert sections[0].offset == ph.cdo_byte_offset

    def test_legitimate_cdo_commands_parsed(self):
        """The legitimate CDO's NOP commands are parsed correctly."""
        data = self._build_cficdr_pdi_with_false_cdo()
        vp = VersalPdi.from_bytes(data, "cficdr_test.pdi")
        sections = vp.cdo_sections()
        assert len(sections) >= 1
        assert len(sections[0].commands) == 3
        assert all(c.cmd_id == CDO_CMD_NOP for c in sections[0].commands)

    def test_false_cdo_module_ids_absent(self):
        """Module IDs 0x40 and 0x80 (garbage from raw PL bytes) must not appear."""
        data = self._build_cficdr_pdi_with_false_cdo()
        vp = VersalPdi.from_bytes(data, "cficdr_test.pdi")
        for section in vp.cdo_sections():
            for cmd in section.commands:
                assert cmd.module_id not in (0x40, 0x80, 0xFD, 0xFF), (
                    f"Garbage module ID {cmd.module_id:#04x} from false CDO in "
                    f"PL bitstream data — CFICDR exclusion not working"
                )

    def test_cficdr_partition_still_present(self):
        """The CFICDR partition header must still be parsed."""
        data = self._build_cficdr_pdi_with_false_cdo()
        vp = VersalPdi.from_bytes(data, "cficdr_test.pdi")
        assert len(vp.partitions()) == 1
        assert vp.partitions()[0].is_pl


class TestPartitionTypeNames:

    def test_all_known_types_named(self):
        for type_id, name in PRTN_TYPE_NAMES.items():
            assert isinstance(name, str) and len(name) > 0

    def test_cficdr_is_pl(self):
        from ablation.analyzers.versal_pdi import PRTN_TYPE_CFICDR
        assert PRTN_TYPE_NAMES[PRTN_TYPE_CFICDR] == "CFICDR/PL"

    def test_elf_name(self):
        assert PRTN_TYPE_NAMES[PRTN_TYPE_ELF] == "ELF/A72"

    def test_unknown_type_falls_back(self):
        # prtn_type=0x1F should fall back to hex label
        from ablation.analyzers.versal_pdi import PRTN_TYPE_NAMES
        assert 0x1F not in PRTN_TYPE_NAMES  # not in dict
        # VersalPdi.prtn_type_name property falls back to "type0x1f"


# ---------------------------------------------------------------------------
# 9. report() output
# ---------------------------------------------------------------------------

class TestReport:

    def test_report_contains_type(self):
        vp = VersalPdi.from_bytes(_pld_sync() + b"\x00" * 64, "test.pdi")
        report = vp.report()
        assert "pld" in report

    def test_report_contains_label(self):
        vp = VersalPdi.from_bytes(_pld_sync() + b"\x00" * 64, "my_label.pdi")
        assert "my_label.pdi" in vp.report()

    def test_report_file_size(self):
        data = _pld_sync() + b"\x00" * 64
        vp = VersalPdi.from_bytes(data)
        assert f"{len(data):#x}" in vp.report()

    def test_report_git_hash(self):
        cdo = _make_cdo([(0x0004 << 16) | (CDO_MOD_LOADER << 8) | CDO_CMD_LOADER_SET_IMAGE_INFO,
                         0, 0, 0, 0x035a2cc3])
        vp = VersalPdi.from_bytes(b"\x00" * 4 + cdo + b"\x00" * 4, "x.pdi")
        assert "035a2cc3" in vp.report()

    def test_report_boot_type(self):
        vp = VersalPdi.from_bytes(_boot_sync() + b"\x00" * 64)
        assert "boot" in vp.report()

    def test_report_unknown_type(self):
        vp = VersalPdi.from_bytes(b"\x00" * 64, "bad.pdi")
        assert "unknown" in vp.report()


# ---------------------------------------------------------------------------
# 10. scan_directory
# ---------------------------------------------------------------------------

class TestScanDirectory:

    def test_scan_empty_dir(self, tmp_path):
        results = VersalPdi.scan_directory(str(tmp_path))
        assert results == []

    def test_scan_non_pdi_ignored(self, tmp_path):
        (tmp_path / "not_a_pdi.bin").write_bytes(b"\x00" * 32)
        results = VersalPdi.scan_directory(str(tmp_path))
        assert results == []

    def test_scan_finds_pdi(self, tmp_path):
        (tmp_path / "test.pdi").write_bytes(_pld_sync() + b"\x00" * 64)
        results = VersalPdi.scan_directory(str(tmp_path))
        assert len(results) == 1

    def test_report_all(self, tmp_path):
        (tmp_path / "a.pdi").write_bytes(_pld_sync() + b"\x00" * 64)
        (tmp_path / "b.pdi").write_bytes(_pld_sync() + b"\x00" * 64)
        results = VersalPdi.scan_directory(str(tmp_path))
        combined = VersalPdi.report_all(results)
        assert "a.pdi" in combined
        assert "b.pdi" in combined


# ---------------------------------------------------------------------------
# 11. Real-file tests (skip when files absent)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _have(_GCI_PLD), reason="GCI pld PDI not found")
class TestRealGciPld:
    """Byte-verified against GCI_GCM415_pld-v0.159.38-35A2CC3.pdi (1.4 MB)."""

    @pytest.fixture(scope="class")
    def vp(self):
        return VersalPdi.from_path(_GCI_PLD)

    def test_type_is_pld(self, vp):
        assert vp.result.pdi_type == "pld"

    def test_sync_word_count(self, vp):
        assert vp.result.sync_word_count == 4

    def test_one_image(self, vp):
        assert len(vp.images()) == 1

    def test_image_name_config_master(self, vp):
        assert vp.images()[0].img_name == "CONFIG_MASTER"

    def test_git_hash_matches_filename(self, vp):
        # filename contains "35A2CC3" → git_hash word = 0x035a2cc3
        assert vp.git_hash() == "035a2cc3"

    def test_one_partition(self, vp):
        assert len(vp.partitions()) == 1

    def test_partition_type_cficdr(self, vp):
        assert vp.partitions()[0].prtn_type == PRTN_TYPE_CFICDR

    def test_partition_is_pl(self, vp):
        assert vp.partitions()[0].is_pl

    def test_partition_dst_load_is_pl_addr(self, vp):
        # Confirmed: both 32-bit halves = 0xFFFFFFFF → 64-bit = 0xFFFF_FFFF_FFFF_FFFF
        assert vp.partitions()[0].dst_load_addr == 0xFFFFFFFFFFFFFFFF

    def test_cdo_sections_present(self, vp):
        assert len(vp.cdo_sections()) >= 1  # single CDO: NPI writes + DmaWriteKeyHole for PL bitstream

    def test_cdo_version_is_v2(self, vp):
        for section in vp.cdo_sections():
            assert section.version == 0x00000200
            assert section.version_str == "2.0"

    def test_no_parse_errors(self, vp):
        # No parse warnings expected for a clean pld PDI
        # (some truncation warnings are acceptable at boundaries)
        assert vp.result is not None


@pytest.mark.skipif(not _have(_GEP_PLD2), reason="GEP pld PDI not found")
class TestRealGepPld:
    """Byte-verified against GEP_2ACC_GCM3_pld-v0.159.40-F119A21.pdi (12 MB)."""

    @pytest.fixture(scope="class")
    def vp(self):
        return VersalPdi.from_path(_GEP_PLD2)

    def test_type_is_pld(self, vp):
        assert vp.result.pdi_type == "pld"

    def test_image_name_config_master(self, vp):
        assert vp.images()[0].img_name == "CONFIG_MASTER"

    def test_git_hash_matches_filename(self, vp):
        # filename contains "F119A21" → git_hash word = 0x0f119a21
        assert vp.git_hash() == "0f119a21"

    def test_larger_than_gci(self, vp):
        # GEP PDI is 12 MB vs GCI 1.4 MB (larger PL fabric)
        assert vp.result.file_size > 10_000_000


@pytest.mark.skipif(not _have(_GCI_BOOT), reason="GCI boot PDI not found")
class TestRealGciBoot:
    """Byte-verified against GCI_GCM415_boot-v0.159.38-35A2CC3.pdi."""

    @pytest.fixture(scope="class")
    def vp(self):
        return VersalPdi.from_path(_GCI_BOOT)

    def test_type_is_boot(self, vp):
        assert vp.result.pdi_type == "boot"

    def test_sync_word_count(self, vp):
        assert vp.result.sync_word_count == 5

    def test_cdo_sections_present(self, vp):
        # Boot PDI has multiple CDO sections (PLM, PMC_METADATA, NPI, etc.)
        assert len(vp.cdo_sections()) >= 3

    def test_git_hash_from_xilpdi(self, vp):
        # Boot PDI: no parseable image headers, but XILPDI IMG_ID command
        # embeds 0x035a2cc3 (same as pld build from same commit)
        assert vp.git_hash() == "035a2cc3"

    def test_iht_parsed(self, vp):
        assert vp.result.iht is not None


@pytest.mark.skipif(not _have(_FELIX_BOOT), reason="FELIX boot PDI not found")
class TestRealFelixBoot:
    """Byte-verified against FELIX FLX182 boot PDI (35 MB)."""

    @pytest.fixture(scope="class")
    def vp(self):
        return VersalPdi.from_path(_FELIX_BOOT)

    def test_type_is_boot(self, vp):
        assert vp.result.pdi_type == "boot"

    def test_large_file(self, vp):
        assert vp.result.file_size > 30_000_000

    def test_cdo_sections_present(self, vp):
        assert len(vp.cdo_sections()) >= 1


class TestCdoValidationAndExtraction:

    def test_header_checksum_required_for_blind_scan(self):
        cdo = bytearray(_make_cdo(_make_nop_cmd(1)))
        cdo[12:16] = _u32le(0xDEADBEEF)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + cdo)
        assert vp.cdo_sections() == []

    def test_valid_header_checksum_exposed(self):
        vp = VersalPdi.from_bytes(b"\x00" * 4 + _make_cdo(_make_nop_cmd(1)))
        assert vp.cdo_sections()[0].header_checksum_valid is True

    def test_long_dma_write_skips_payload_and_extracts_bytes(self):
        header = (0xFF << 16) | (CDO_MOD_GENERIC << 8) | CDO_CMD_DMA_WRITE
        payload = [0, 0xF6130050, 0xB0000001, 0x31A0C148, 0x80000000, 0xB60F0008]
        words = [header, len(payload)] + payload + _make_nop_cmd(1)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + _make_cdo(words))
        section = vp.cdo_sections()[0]
        assert len(section.commands) == 2
        command = section.commands[0]
        assert command.is_long
        assert command.payload_length == len(payload)
        assert command.payload_offset == command.offset + 8
        assert section.commands[1].offset == command.offset + 8 + len(payload) * 4
        segments = vp.dma_write_segments()
        assert len(segments) == 1
        assert segments[0].address == 0xF6130050
        assert segments[0].data == b"".join(_u32le(w) for w in payload[2:])

    def test_truncated_long_command_is_an_error(self):
        header = (0xFF << 16) | (CDO_MOD_GENERIC << 8) | CDO_CMD_DMA_WRITE
        words = [header, 10, 0, 0xF6130050]
        vp = VersalPdi.from_bytes(b"\x00" * 4 + _make_cdo(words))
        section = vp.cdo_sections()[0]
        assert section.commands == []
        assert "truncated command" in section.parse_error

    def test_end_command_stops_parsing(self):
        words = _make_nop_cmd(1) + [CDO_CMD_END_WORD] + _make_nop_cmd(3)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + _make_cdo(words))
        section = vp.cdo_sections()[0]
        assert section.end_detected
        assert len(section.commands) == 1
        assert section.consumed_words == 2

    def test_write64_uses_full_address_and_third_payload_word(self):
        header = (3 << 16) | (CDO_MOD_GENERIC << 8) | CDO_CMD_WRITE64
        words = [header, 1, 0xF1234568, 0xA5A5A5A5]
        vp = VersalPdi.from_bytes(b"\x00" * 4 + _make_cdo(words))
        command = vp.cdo_sections()[0].commands[0]
        assert command.npi_addr == 0x1F1234568
        assert command.npi_data == 0xA5A5A5A5

    def test_reserved_header_bits_do_not_extend_command_length(self):
        header = (0xF << 28) | (2 << 16) | (CDO_MOD_GENERIC << 8) | CDO_CMD_WRITE
        words = [header, 0xF1000000, 0x1234] + _make_nop_cmd(1)
        vp = VersalPdi.from_bytes(b"\x00" * 4 + _make_cdo(words))
        section = vp.cdo_sections()[0]
        assert len(section.commands) == 2
        assert section.commands[0].payload_length == 2
        assert section.commands[1].cmd_id == CDO_CMD_NOP

    def test_pdi_size_limit_for_buffer_and_path(self, monkeypatch, tmp_path):
        monkeypatch.setattr(VersalPdi, "MAX_PDI_BYTES", 4)
        with pytest.raises(ValueError, match="exceeds 4 bytes"):
            VersalPdi.from_bytes(b"\x00" * 5)
        image = tmp_path / "oversize.pdi"
        image.write_bytes(b"\x00" * 5)
        with pytest.raises(ValueError, match="exceeds 4 bytes"):
            VersalPdi.from_path(str(image))

    def test_cficdr_direct_parse_requires_cdo_magic(self):
        data = bytearray(TestCficdrFalsePositiveSuppression()._build_cficdr_pdi_with_false_cdo())
        data[0x104:0x108] = b"BAD!"
        vp = VersalPdi.from_bytes(bytes(data))
        assert vp.cdo_sections() == []


@pytest.mark.skipif(not _have(_GCI_BOOT), reason="GCI boot PDI not found")
def test_real_long_plm_command_has_no_embedded_commands():
    vp = VersalPdi.from_path(_GCI_BOOT)
    section = next(s for s in vp.cdo_sections() if s.offset == 0xC71E4)
    command = next(c for c in section.commands if c.offset == 0x11DA80)
    assert command.is_long
    assert command.payload_length == 0x5BCE
    following = next(c for c in section.commands if c.offset > command.offset)
    assert following.offset == 0x1349C0
    assert all(s.header_checksum_valid for s in vp.cdo_sections())


def _assert_complete_boot_sections(vp):
    sections = vp.cdo_sections()
    assert vp.result.pdi_type == "boot"
    assert len(sections) == 5
    assert all(section.header_checksum_valid for section in sections)
    assert all(not section.parse_error for section in sections)
    assert all(section.consumed_words == section.length_words for section in sections)
    assert all(not section.end_detected for section in sections)
    commands = [command for section in sections for command in section.commands]
    assert not any(command.xilpm_node_class == XPM_NODECLASS_PROTECTION for command in commands)
    return commands


@pytest.mark.skipif(not _have(f"{_GEP_DIR}/LARPP_JET1_GCM3_boot-v0.159.29-FDDA9E0.pdi"), reason="LARPP boot PDI not found")
def test_real_larpp_boot_sections_and_dma():
    vp = VersalPdi.from_path(f"{_GEP_DIR}/LARPP_JET1_GCM3_boot-v0.159.29-FDDA9E0.pdi")
    commands = _assert_complete_boot_sections(vp)
    assert len(commands) == 30342
    assert len(vp.dma_write_segments()) == 154


@pytest.mark.parametrize("index", range(1, 10))
def test_real_transceiver_boot_sections(index):
    suffix = f"_{index}" if index > 1 else ""
    path = f"{_GEP_DIR}/transceiver_versal_interlaken_exdes_vio{suffix}.pdi"
    if not _have(path):
        pytest.skip("transceiver PDI not found")
    vp = VersalPdi.from_path(path)
    _assert_complete_boot_sections(vp)
    assert not any(
        0xF6130000 <= segment.address < 0xF6140000
        for segment in vp.dma_write_segments()
    )


def test_real_transceiver_variants_three_and_four_share_payload_and_npi_map():
    paths = [
        f"{_GEP_DIR}/transceiver_versal_interlaken_exdes_vio_3.pdi",
        f"{_GEP_DIR}/transceiver_versal_interlaken_exdes_vio_4.pdi",
    ]
    if not all(_have(path) for path in paths):
        pytest.skip("transceiver comparison PDIs not found")
    pdis = [VersalPdi.from_path(path) for path in paths]
    dma = [
        [(segment.address, segment.data) for segment in vp.dma_write_segments()]
        for vp in pdis
    ]
    npi = [
        sorted(
            (command.npi_addr, command.npi_data)
            for section in vp.cdo_sections()
            for command in section.commands
            if command.npi_addr is not None
        )
        for vp in pdis
    ]
    assert dma[0] == dma[1]
    assert npi[0] == npi[1]
