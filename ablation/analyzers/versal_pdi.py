"""
Versal PDI (Programmable Device Image) parser for Xilinx Versal ACAP.

Handles two PDI sub-formats found in the CERN ATLAS collection:

  pld PDI  — 4 sync words, plaintext IHT, PL-only image (CONFIG_MASTER)
  boot PDI — 5 sync words + XLNX, encrypted/opaque IHT, full boot image

Both formats embed CDO (Configuration Data Object) sections identified by
the ``CDO\x00`` magic. CDO sections are parsed regardless of IHT format.

Confirmed from RE of CERN GEP/FELIX Versal firmware (2026-10):
  - GCI_GCM415_pld-v0.159.38-35A2CC3.pdi  (pld, single partition, 7.5 MB)
  - GCI_GCM415_boot-v0.159.38-35A2CC3.pdi (boot, PLM+CDOs, 1.4 MB)
  - FLX182_STRIPS_24CH_...1448.pdi         (boot, FELIX 35 MB)
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# MetaHeader sync constants
# ---------------------------------------------------------------------------

# All PDI files start with these 4 words (LE)
PDI_SYNC_WORD_0 = 0x000000DD
PDI_SYNC_WORD_1 = 0x11223344
PDI_SYNC_WORD_2 = 0x55667788
PDI_SYNC_WORD_3 = 0x99AABBCC

# Boot/full PDIs add a 5th sync word and the XLNX identification
PDI_SYNC_WORD_4 = 0xAA995566
PDI_IHT_IDENT   = 0x584C4E58  # "XLNX" as LE uint32

# CDO section magic
CDO_MAGIC = b"CDO\x00"
CDO_HEADER_WORDS = 4  # magic, version, length, checksum; prefix is external
CDO_PAYLOAD_PREFIX_BYTES = 4
CDO_SHORT_LEN_EXTENDED = 0xFF
CDO_CMD_END_WORD = 0x000001FF

# ---------------------------------------------------------------------------
# Partition attribute constants  (PrtnAttrb bits)
# ---------------------------------------------------------------------------

PRTN_TYPE_MASK   = 0x1F
PRTN_TYPE_ELF    = 0x01   # PS/APU ELF (A72)
PRTN_TYPE_CDO    = 0x02   # CDO (generic subsystem config)
PRTN_TYPE_PMC    = 0x03   # PMC-specific CDO
PRTN_TYPE_AIE    = 0x04   # AI Engine CDO
PRTN_TYPE_ELF_R5 = 0x05   # RPU ELF (R5)
PRTN_TYPE_CFICDR = 0x06   # PL Config Frame Interface CDR (bitstream)

PRTN_TYPE_NAMES: Dict[int, str] = {
    PRTN_TYPE_ELF:    "ELF/A72",
    PRTN_TYPE_CDO:    "CDO",
    PRTN_TYPE_PMC:    "PMC_CDO",
    PRTN_TYPE_AIE:    "AIE_CDO",
    PRTN_TYPE_ELF_R5: "ELF/R5",
    PRTN_TYPE_CFICDR: "CFICDR/PL",
}

# DstLoadAddr == 0xFFFF_FFFF_FFFF_FFFF → PL CFRAME destination (not a RAM address)
PRTN_DST_PL = 0xFFFFFFFF

# ChecksumType bits[25:24]
CKSUM_TYPE_NONE  = 0
CKSUM_TYPE_SHA3  = 2

# ---------------------------------------------------------------------------
# CDO command module IDs (bits[15:8] of command header word)
# ---------------------------------------------------------------------------

CDO_MOD_GENERIC   = 0x01   # generic commands (xplmi_generic.c, XPLMI_MODULE_GENERIC_ID)
CDO_MOD_XILPM     = 0x02   # power management (XPLMI_MODULE_XILPM_ID)
CDO_MOD_SEM       = 0x03   # safety error monitoring (XPLMI_MODULE_SEM_ID)
CDO_MOD_XILSECURE = 0x05   # security (XPLMI_MODULE_XILSECURE_ID)
CDO_MOD_XILPSM    = 0x06   # PSM (XPLMI_MODULE_XILPSM_ID)
CDO_MOD_LOADER    = 0x07   # PDI loader — SetImageInfo, MbPmcI2cHandshake (XPLMI_MODULE_LOADER_ID)
CDO_MOD_ERROR     = 0x08   # error/event management (XPLMI_MODULE_ERROR_ID)
CDO_MOD_XILNVM    = 0x0B   # NVM (XPLMI_MODULE_XILNVM_ID)
CDO_MOD_XILPUF    = 0x0C   # PUF (XPLMI_MODULE_XILPUF_ID)

CDO_MOD_NAMES: Dict[int, str] = {
    CDO_MOD_GENERIC:   "GENERIC",
    CDO_MOD_XILPM:     "XILPM",
    CDO_MOD_SEM:       "SEM",
    CDO_MOD_XILSECURE: "XILSECURE",
    CDO_MOD_XILPSM:    "XILPSM",
    CDO_MOD_LOADER:    "LOADER",
    CDO_MOD_ERROR:     "ERROR",
    CDO_MOD_XILNVM:    "XILNVM",
    CDO_MOD_XILPUF:    "XILPUF",
}

# ---------------------------------------------------------------------------
# CDO command IDs for CDO_MOD_GENERIC (bits[7:0])
# ---------------------------------------------------------------------------

# Module GENERIC (0x01) command IDs — indexed positions from xplmi_generic.c handler array
CDO_CMD_FEATURES         = 0x00
CDO_CMD_MASK_POLL        = 0x01   # MaskPoll: addr, mask, value, count
CDO_CMD_MASK_WRITE       = 0x02   # MaskWrite: addr, mask, value
CDO_CMD_WRITE            = 0x03   # Write: addr, value  (NPI/CFRAME config and register writes)
CDO_CMD_DELAY            = 0x04   # Delay: cycles
CDO_CMD_DMA_WRITE        = 0x05   # DmaWrite: addr_hi, addr_lo, len, data...
CDO_CMD_MASK_POLL64      = 0x06   # MaskPoll64: addr_hi, addr_lo, mask, value, count
CDO_CMD_MASK_WRITE64     = 0x07   # MaskWrite64: addr_hi, addr_lo, mask, value
CDO_CMD_WRITE64          = 0x08   # Write64: addr_hi, addr_lo, value
CDO_CMD_KEYHOLE          = 0x0D   # DmaWriteKeyHole: bulk write via keyhole register
CDO_CMD_SSIT_SYNC_MASTER = 0x0E   # SsitSyncMaster
CDO_CMD_SSIT_SYNC_SLAVES = 0x0F   # SsitSyncSlaves
CDO_CMD_NOP              = 0x11   # Nop
CDO_CMD_LOG_STRING       = 0x17   # LogString: string payload
CDO_CMD_MARKER           = 0x19   # Marker: id, string...
CDO_CMD_PROC             = 0x1A   # Proc
CDO_CMD_BEGIN            = 0x1B   # Begin
CDO_CMD_END              = 0x1C   # End
CDO_CMD_BREAK            = 0x1D   # Break
CDO_CMD_OT_CHECK         = 0x1E   # OTCheck

# Module LOADER (0x07) command IDs
CDO_CMD_LOADER_SET_IMAGE_INFO = 0x04   # SetImageInfo: img_id, uid, parent_uid, func_id

# Module XILPM (0x02) command IDs used by topology and domain CDO sections
CDO_CMD_XILPM_SET_CURRENT_SUBSYSTEM = 0x36
CDO_CMD_XILPM_INIT = 0x38
CDO_CMD_XILPM_ADD_NODE = 0x39
CDO_CMD_XILPM_ADD_NODE_PARENT = 0x3A
CDO_CMD_XILPM_ADD_NODE_NAME = 0x3B
CDO_CMD_XILPM_INIT_NODE = 0x3E
CDO_CMD_XILPM_SET_NODE_ACCESS = 0x42

CDO_CMD_NAMES_GENERIC: Dict[int, str] = {
    CDO_CMD_FEATURES:         "Features",
    CDO_CMD_MASK_POLL:        "MaskPoll",
    CDO_CMD_MASK_WRITE:       "MaskWrite",
    CDO_CMD_WRITE:            "Write",
    CDO_CMD_DELAY:            "Delay",
    CDO_CMD_DMA_WRITE:        "DmaWrite",
    CDO_CMD_MASK_POLL64:      "MaskPoll64",
    CDO_CMD_MASK_WRITE64:     "MaskWrite64",
    CDO_CMD_WRITE64:          "Write64",
    CDO_CMD_KEYHOLE:          "DmaWriteKeyHole",
    CDO_CMD_SSIT_SYNC_MASTER: "SsitSyncMaster",
    CDO_CMD_SSIT_SYNC_SLAVES: "SsitSyncSlaves",
    CDO_CMD_NOP:              "Nop",
    CDO_CMD_LOG_STRING:       "LogString",
    CDO_CMD_MARKER:           "Marker",
    CDO_CMD_PROC:             "Proc",
    CDO_CMD_BEGIN:            "Begin",
    CDO_CMD_END:              "End",
    CDO_CMD_BREAK:            "Break",
    CDO_CMD_OT_CHECK:         "OTCheck",
}

CDO_CMD_NAMES_XILPM: Dict[int, str] = {
    CDO_CMD_XILPM_SET_CURRENT_SUBSYSTEM: "SetCurrentSubsystem",
    CDO_CMD_XILPM_INIT: "Init",
    CDO_CMD_XILPM_ADD_NODE: "AddNode",
    CDO_CMD_XILPM_ADD_NODE_PARENT: "AddNodeParent",
    CDO_CMD_XILPM_ADD_NODE_NAME: "AddNodeName",
    CDO_CMD_XILPM_INIT_NODE: "InitNode",
    CDO_CMD_XILPM_SET_NODE_ACCESS: "SetNodeAccess",
}

XPM_NODECLASS_PROTECTION = 0x09


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CdoCommand:
    """Single decoded CDO command."""

    offset: int           # byte offset in file
    module_id: int
    cmd_id: int
    payload: Tuple[int, ...]  # raw LE u32 words (up to 8 stored for RE use)
    payload_offset: int = 0   # byte offset of full payload in file
    payload_length: int = 0   # full payload length in words, excluding long-header extension
    is_long: bool = False

    # ---- derived fields populated by post-processing ----
    string_payload: str = ""  # extracted ASCII if payload encodes a string
    npi_addr: Optional[int] = None   # NPI address if NPI_WRITE / WRITE32 to 0xF1... space
    npi_data: Optional[int] = None   # first data word

    @property
    def module_name(self) -> str:
        return CDO_MOD_NAMES.get(self.module_id, f"mod{self.module_id:#04x}")

    @property
    def cmd_name(self) -> str:
        if self.module_id == CDO_MOD_GENERIC:
            return CDO_CMD_NAMES_GENERIC.get(self.cmd_id, f"cmd{self.cmd_id:#04x}")
        if self.module_id == CDO_MOD_XILPM:
            return CDO_CMD_NAMES_XILPM.get(self.cmd_id, f"cmd{self.cmd_id:#04x}")
        if self.module_id == CDO_MOD_LOADER and self.cmd_id == CDO_CMD_LOADER_SET_IMAGE_INFO:
            return "SetImageInfo"
        return f"cmd{self.cmd_id:#04x}"

    @property
    def xilpm_node_id(self) -> Optional[int]:
        if self.module_id != CDO_MOD_XILPM or not self.payload:
            return None
        if self.cmd_id in (CDO_CMD_XILPM_ADD_NODE, CDO_CMD_XILPM_ADD_NODE_PARENT,
                           CDO_CMD_XILPM_ADD_NODE_NAME, CDO_CMD_XILPM_INIT_NODE):
            return self.payload[0]
        return None

    @property
    def xilpm_function(self) -> Optional[int]:
        if (self.module_id == CDO_MOD_XILPM and
                self.cmd_id == CDO_CMD_XILPM_INIT_NODE and len(self.payload) > 1):
            return self.payload[1]
        return None

    @property
    def xilpm_node_class(self) -> Optional[int]:
        node_id = self.xilpm_node_id
        if node_id is None:
            return None
        return (node_id >> 26) & 0x3F


@dataclass
class CdoSection:
    """One CDO section parsed from the PDI."""

    offset: int               # byte offset of CDO magic in file
    version: int              # CDO version word (typically 0x00000200)
    length_words: int         # payload length in 32-bit words
    checksum: int
    commands: List[CdoCommand] = field(default_factory=list)
    parse_error: str = ""     # set if command parsing was truncated
    header_checksum_valid: Optional[bool] = None
    end_detected: bool = False
    consumed_words: int = 0

    @property
    def payload_bytes(self) -> int:
        return self.length_words * 4

    @property
    def version_str(self) -> str:
        # 0x00000200 → major=2, minor=0 → "2.0"
        major = (self.version >> 8) & 0xFF
        minor = self.version & 0xFF
        return f"{major}.{minor}"


@dataclass(frozen=True)
class DmaWriteSegment:
    """One memory load described by a GENERIC DmaWrite command."""

    address: int
    data: bytes
    command_offset: int
    section_offset: int

    @property
    def end_address(self) -> int:
        return self.address + len(self.data)


@dataclass
class PdiPartitionHeader:
    """Versal PDI partition header (0x3C bytes, confirmed for pld PDI)."""

    offset: int               # byte offset of header in file
    enc_data_word_len: int    # encrypted data size in 32-bit words
    unenc_data_word_len: int
    total_data_word_len: int
    next_prtn_off: int        # word offset to next PH (0 = last)
    dst_exec_addr: int        # u64 execution address (LE: lo|hi)
    dst_load_addr: int        # u64 load address (0xFFFF...FFFF = PL/CFRAME)
    data_word_off: int        # word offset from file start to partition payload
    prtn_attrb: int
    section_count: int
    checksum_word_off: int
    img_hdr_off: int          # back-reference to owning image header
    auth_cert_off: int
    checksum: int

    @property
    def prtn_type(self) -> int:
        return self.prtn_attrb & PRTN_TYPE_MASK

    @property
    def prtn_type_name(self) -> str:
        return PRTN_TYPE_NAMES.get(self.prtn_type, f"type{self.prtn_type:#x}")

    @property
    def is_pl(self) -> bool:
        return self.prtn_type == PRTN_TYPE_CFICDR

    @property
    def is_encrypted(self) -> bool:
        return bool((self.prtn_attrb >> 23) & 1)

    @property
    def data_byte_offset(self) -> int:
        """Byte offset to the 4-byte payload prefix (CDO magic is at +4)."""
        return self.data_word_off * 4

    @property
    def cdo_byte_offset(self) -> int:
        """Byte offset to the CDO magic (after the 4-byte prefix word)."""
        return self.data_word_off * 4 + CDO_PAYLOAD_PREFIX_BYTES

    @property
    def data_size_bytes(self) -> int:
        return self.enc_data_word_len * 4


@dataclass
class PdiImageHeader:
    """Versal PDI image header (0x40 bytes, confirmed for pld PDI)."""

    offset: int               # byte offset in file
    first_prtn_hdr_off: int   # word offset from file start to first partition header
    no_of_prtns: int
    img_attrb: int
    img_name: str             # 16-byte null-terminated ASCII
    img_id: int
    git_hash: int             # 4-byte git commit hash
    checksum: int


@dataclass
class PdiIHT:
    """Image Header Table — confirmed layout for pld PDI (4 sync words)."""

    offset: int               # byte offset of IHT in file (= 0x10 for pld PDI)
    pdi_flags: int            # PDI format flags / type word
    no_of_imgs: int
    img_hdr_off: int          # word offset from file start to first image header
    total_no_of_prtns: int
    part_hdr_off: int         # word offset from file start to first partition header
    sbd_off: int              # secondary boot device offset
    checksum: int

    @property
    def img_hdr_byte_offset(self) -> int:
        return self.img_hdr_off * 4

    @property
    def part_hdr_byte_offset(self) -> int:
        return self.part_hdr_off * 4


@dataclass
class VersalPdiResult:
    """Top-level parse result for a single PDI file."""

    path: str
    file_size: int
    pdi_type: str               # "pld", "boot", or "unknown"
    sync_word_count: int        # 4 or 5

    iht: Optional[PdiIHT] = None
    images: List[PdiImageHeader] = field(default_factory=list)
    partitions: List[PdiPartitionHeader] = field(default_factory=list)
    cdo_sections: List[CdoSection] = field(default_factory=list)

    parse_warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

class VersalPdi:
    """
    Parser for Xilinx Versal PDI firmware images.

    Construction::

        from ablation.analyzers.versal_pdi import VersalPdi
        vp = VersalPdi.from_path('/media/cowboy/research/CERN/fw/gep/GCI_GCM415_pld-v0.159.38-35A2CC3.pdi')
        print(vp.report())

    Key methods::

        VersalPdi.from_path(path)            – load from file
        VersalPdi.from_bytes(data, label)    – load from bytes in memory
        vp.result                            – VersalPdiResult with all parsed data
        vp.cdo_sections()                    – List[CdoSection] found by pattern scan
        vp.images()                          – List[PdiImageHeader] (pld PDI only)
        vp.partitions()                      – List[PdiPartitionHeader] (pld PDI)
        vp.git_hash()                        – str hex or "" if not found
        vp.report()                          – human-readable summary str
    """

    MAX_CDO_COMMANDS = 50_000  # safety cap per CDO section
    MAX_PDI_BYTES = 512 * 1024 * 1024

    def __init__(self, data: bytes, label: str = "") -> None:
        if len(data) > self.MAX_PDI_BYTES:
            raise ValueError(f"PDI exceeds {self.MAX_PDI_BYTES} bytes")
        self._data = data
        self._label = label
        self._result: Optional[VersalPdiResult] = None

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_path(cls, path: str) -> "VersalPdi":
        source = Path(path)
        if source.stat().st_size > cls.MAX_PDI_BYTES:
            raise ValueError(f"PDI exceeds {cls.MAX_PDI_BYTES} bytes: {source}")
        return cls(source.read_bytes(), source.name)

    @classmethod
    def from_bytes(cls, data: bytes, label: str = "<bytes>") -> "VersalPdi":
        return cls(data, label)

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    @property
    def result(self) -> VersalPdiResult:
        if self._result is None:
            self._result = self._parse()
        return self._result

    def cdo_sections(self) -> List[CdoSection]:
        return self.result.cdo_sections

    def images(self) -> List[PdiImageHeader]:
        return self.result.images

    def partitions(self) -> List[PdiPartitionHeader]:
        return self.result.partitions

    def embedded_elf(self):
        from .embedded_elf import find_embedded_elf
        return find_embedded_elf(self._data)

    def git_hash(self) -> str:
        """Return 8-char hex git hash from the first image header, or ''."""
        for img in self.result.images:
            if img.git_hash:
                return f"{img.git_hash:08x}"
        # Fall back: look for LOADER SetImageInfo command in CDO sections
        for cdo in self.result.cdo_sections:
            for cmd in cdo.commands:
                if cmd.module_id == CDO_MOD_LOADER and cmd.cmd_id == CDO_CMD_LOADER_SET_IMAGE_INFO:
                    if len(cmd.payload) >= 4:
                        return f"{cmd.payload[3]:08x}"
        return ""

    # ------------------------------------------------------------------
    # Top-level parse
    # ------------------------------------------------------------------

    def _parse(self) -> VersalPdiResult:
        data = self._data
        warnings: List[str] = []

        # -- detect PDI type from sync words --
        if len(data) < 0x18:
            return VersalPdiResult(
                path=self._label, file_size=len(data),
                pdi_type="unknown", sync_word_count=0,
                parse_warnings=["file too short"],
            )

        r = self._u32le
        if not (r(0) == PDI_SYNC_WORD_0 and r(4) == PDI_SYNC_WORD_1 and
                r(8) == PDI_SYNC_WORD_2 and r(12) == PDI_SYNC_WORD_3):
            # Still scan for CDO sections — useful for extracted partitions / blobs
            warnings_unk: List[str] = []
            cdo_sections = self._scan_cdo_sections(warnings_unk)
            return VersalPdiResult(
                path=self._label, file_size=len(data),
                pdi_type="unknown", sync_word_count=0,
                cdo_sections=cdo_sections,
                parse_warnings=["missing PDI sync words at offset 0"] + warnings_unk,
            )

        if r(0x10) == PDI_SYNC_WORD_4 and r(0x14) == PDI_IHT_IDENT:
            pdi_type = "boot"
            sync_count = 5
            iht_offset = 0x14
        else:
            pdi_type = "pld"
            sync_count = 4
            iht_offset = 0x10

        result = VersalPdiResult(
            path=self._label,
            file_size=len(data),
            pdi_type=pdi_type,
            sync_word_count=sync_count,
            parse_warnings=warnings,
        )

        # -- parse IHT --
        if pdi_type == "pld":
            result.iht = self._parse_iht_pld(iht_offset, warnings)
        else:
            # boot PDI IHT: ident confirmed, subsequent fields partially opaque
            # (fields 0x08-0x0c contain fixed magic values in known boot PDIs).
            result.iht = self._parse_iht_boot(iht_offset, warnings)

        # -- parse image headers and partition headers (pld PDI: confirmed) --
        if result.iht is not None:
            if pdi_type == "pld":
                result.images = self._parse_image_headers(
                    result.iht.img_hdr_byte_offset,
                    result.iht.no_of_imgs,
                    warnings,
                )
                result.partitions = self._parse_partition_headers(
                    result.iht.part_hdr_byte_offset,
                    result.iht.total_no_of_prtns,
                    warnings,
                )
            else:
                # Boot PDI: try to parse with best-effort; may produce empty lists
                result.images = self._parse_image_headers_best_effort(warnings)
                result.partitions = []

        # -- CDO sections: parse CFICDR partitions directly; blind-scan everything else --
        # CFICDR partitions contain raw PL CFRAME bitstream bytes that may include
        # CDO\x00 byte patterns, producing false positives with garbage module IDs
        # (0x40+, 0x80+) if scanned blindly.  For each CFICDR partition we:
        #   1. parse the CDO at the known cdo_byte_offset directly, and
        #   2. exclude the entire partition data range from the blind scan.
        cficdr_cdo_sections: List[CdoSection] = []
        cficdr_data_ranges: List[Tuple[int, int]] = []
        for ph in result.partitions:
            if ph.is_pl and ph.data_size_bytes > 0:
                cdo_off = ph.cdo_byte_offset
                if (cdo_off + 16 <= len(self._data)
                        and self._data[cdo_off:cdo_off + 4] == CDO_MAGIC):
                    r = self._u32le
                    version  = r(cdo_off + 4)
                    length_w = r(cdo_off + 8)
                    checksum = r(cdo_off + 12)
                    if 0 <= length_w < 8_000_000 and (version >> 16) <= 10:
                        section = CdoSection(
                            offset=cdo_off,
                            version=version,
                            length_words=length_w,
                            checksum=checksum,
                        )
                        self._parse_cdo_commands(section, warnings)
                        cficdr_cdo_sections.append(section)
                start = ph.data_byte_offset
                end   = start + ph.data_size_bytes
                cficdr_data_ranges.append((start, end))

        blind_sections = self._scan_cdo_sections(warnings, exclude_ranges=cficdr_data_ranges)
        result.cdo_sections = cficdr_cdo_sections + blind_sections

        return result

    # ------------------------------------------------------------------
    # IHT parsers
    # ------------------------------------------------------------------

    def _parse_iht_pld(self, offset: int, warnings: List[str]) -> Optional[PdiIHT]:
        """Parse IHT for pld PDI (4 sync words, plaintext, confirmed structure)."""
        data = self._data
        if offset + 0x30 > len(data):
            warnings.append(f"IHT at {offset:#x}: truncated")
            return None
        r = self._u32le
        return PdiIHT(
            offset=offset,
            pdi_flags=r(offset + 0x00),
            no_of_imgs=r(offset + 0x04),
            img_hdr_off=r(offset + 0x08),
            total_no_of_prtns=r(offset + 0x0C),
            part_hdr_off=r(offset + 0x10),
            sbd_off=r(offset + 0x14),
            checksum=r(offset + 0x18),
        )

    def _parse_iht_boot(self, offset: int, warnings: List[str]) -> Optional[PdiIHT]:
        """Parse IHT for boot PDI (5 sync words + XLNX, partially opaque fields)."""
        data = self._data
        if offset + 0x30 > len(data):
            warnings.append(f"boot IHT at {offset:#x}: truncated")
            return None
        r = self._u32le
        # Words +0x08 and +0x0C are fixed magic values in known boot PDIs
        # (0x00000F80 and 0xF2000000); treat them as reserved.
        # Fields +0x10 and +0x14 are equal in known boot PDIs: meaning uncertain.
        return PdiIHT(
            offset=offset,
            pdi_flags=r(offset + 0x00),   # = XLNX ident (0x584c4e58)
            no_of_imgs=r(offset + 0x04),   # version (0x00000000 in known files)
            img_hdr_off=0,                 # cannot reliably parse for boot PDI
            total_no_of_prtns=0,
            part_hdr_off=r(offset + 0x10), # tentative; semantics differ from pld
            sbd_off=r(offset + 0x14),
            checksum=r(offset + 0x18),
        )

    # ------------------------------------------------------------------
    # Image header parsers
    # ------------------------------------------------------------------

    # Image header layout (0x40 bytes each, confirmed for pld PDI):
    #   +0x00: first_prtn_hdr_off (word offset from file start)
    #   +0x04: no_of_prtns
    #   +0x08: reserved
    #   +0x0c: img_attrb
    #   +0x10: img_name[16] (null-terminated ASCII)
    #   +0x20: img_id
    #   +0x24: hash_word_1
    #   +0x28: hash_word_2
    #   +0x2c: git_hash (4-byte truncated commit hash)
    #   +0x30..0x38: reserved
    #   +0x3c: checksum (XOR)
    IMG_HDR_SIZE = 0x40

    def _parse_image_headers(
        self, offset: int, count: int, warnings: List[str]
    ) -> List[PdiImageHeader]:
        headers = []
        data = self._data
        for i in range(min(count, 64)):
            base = offset + i * self.IMG_HDR_SIZE
            if base + self.IMG_HDR_SIZE > len(data):
                warnings.append(f"image header {i} at {base:#x}: truncated")
                break
            r = self._u32le
            raw_name = data[base + 0x10 : base + 0x20]
            name = raw_name.split(b"\x00")[0].decode("ascii", errors="replace")
            headers.append(PdiImageHeader(
                offset=base,
                first_prtn_hdr_off=r(base + 0x00),
                no_of_prtns=r(base + 0x04),
                img_attrb=r(base + 0x0C),
                img_name=name,
                img_id=r(base + 0x20),
                git_hash=r(base + 0x2C),
                checksum=r(base + 0x3C),
            ))
        return headers

    def _parse_image_headers_best_effort(
        self, warnings: List[str]
    ) -> List[PdiImageHeader]:
        """Scan CDO LOADER SetImageInfo commands to recover image IDs for boot PDI."""
        # Boot PDI IHT offsets are opaque; discover images from embedded CDO commands.
        found: List[PdiImageHeader] = []
        for cdo in self._scan_cdo_sections([]):
            for cmd in cdo.commands:
                if (cmd.module_id == CDO_MOD_LOADER and
                        cmd.cmd_id == CDO_CMD_LOADER_SET_IMAGE_INFO and
                        len(cmd.payload) >= 4):
                    found.append(PdiImageHeader(
                        offset=cmd.offset,
                        first_prtn_hdr_off=0,
                        no_of_prtns=0,
                        img_attrb=0,
                        img_name="",
                        img_id=cmd.payload[0],
                        git_hash=cmd.payload[3],
                        checksum=0,
                    ))
        return found

    # ------------------------------------------------------------------
    # Partition header parser
    # ------------------------------------------------------------------

    # Partition header layout (0x3C bytes, confirmed for pld PDI):
    #   +0x00: enc_data_word_len
    #   +0x04: unenc_data_word_len
    #   +0x08: total_data_word_len
    #   +0x0c: next_prtn_off
    #   +0x10: dst_exec_addr_lo
    #   +0x14: dst_exec_addr_hi
    #   +0x18: dst_load_addr_lo
    #   +0x1c: dst_load_addr_hi
    #   +0x20: data_word_off
    #   +0x24: prtn_attrb
    #   +0x28: section_count
    #   +0x2c: checksum_word_off
    #   +0x30: img_hdr_off (back-ref to owning image header, opaque word offset)
    #   +0x34: auth_cert_off
    #   +0x38: checksum
    PRTN_HDR_SIZE = 0x3C

    def _parse_partition_headers(
        self, offset: int, count: int, warnings: List[str]
    ) -> List[PdiPartitionHeader]:
        headers: List[PdiPartitionHeader] = []
        data = self._data
        base = offset
        for i in range(min(count, 256)):
            if base + self.PRTN_HDR_SIZE > len(data):
                warnings.append(f"partition header {i} at {base:#x}: truncated")
                break
            r = self._u32le
            load_lo = r(base + 0x18)
            load_hi = r(base + 0x1C)
            dst_load = (load_hi << 32) | load_lo
            exec_lo  = r(base + 0x10)
            exec_hi  = r(base + 0x14)
            dst_exec = (exec_hi << 32) | exec_lo
            next_off = r(base + 0x0C)
            ph = PdiPartitionHeader(
                offset=base,
                enc_data_word_len=r(base + 0x00),
                unenc_data_word_len=r(base + 0x04),
                total_data_word_len=r(base + 0x08),
                next_prtn_off=next_off,
                dst_exec_addr=dst_exec,
                dst_load_addr=dst_load,
                data_word_off=r(base + 0x20),
                prtn_attrb=r(base + 0x24),
                section_count=r(base + 0x28),
                checksum_word_off=r(base + 0x2C),
                img_hdr_off=r(base + 0x30),
                auth_cert_off=r(base + 0x34),
                checksum=r(base + 0x38),
            )
            headers.append(ph)
            if next_off == 0:
                break
            base += self.PRTN_HDR_SIZE
        return headers

    # ------------------------------------------------------------------
    # CDO scanner
    # ------------------------------------------------------------------

    def _scan_cdo_sections(
        self,
        warnings: List[str],
        exclude_ranges: Optional[List[Tuple[int, int]]] = None,
    ) -> List[CdoSection]:
        """Find checksum-valid CDO sections outside excluded byte ranges."""
        data = self._data
        sections: List[CdoSection] = []
        excluded = exclude_ranges or []
        pos = 0
        while True:
            pos = data.find(CDO_MAGIC, pos)
            if pos < 0:
                break
            if pos < 4 or pos + 16 > len(data):
                pos += 1
                continue
            if any(start <= pos < end for start, end in excluded):
                pos += 1
                continue
            r = self._u32le
            version = r(pos + 4)
            length_w = r(pos + 8)
            checksum = r(pos + 12)
            declared_end = pos + 16 + length_w * 4
            if length_w >= 8_000_000 or (version >> 16) > 10 or declared_end > len(data):
                pos += 1
                continue
            checksum_valid = self._cdo_header_checksum_valid(pos)
            if not checksum_valid:
                pos += 1
                continue
            section = CdoSection(
                offset=pos,
                version=version,
                length_words=length_w,
                checksum=checksum,
                header_checksum_valid=True,
            )
            self._parse_cdo_commands(section, warnings)
            sections.append(section)
            pos = declared_end
        return sections

    def _cdo_header_checksum_valid(self, offset: int) -> bool:
        if offset < 4 or offset + 16 > len(self._data):
            return False
        words = struct.unpack_from("<4I", self._data, offset - 4)
        calculated = (~sum(words)) & 0xFFFFFFFF
        return calculated == self._u32le(offset + 12)

    def _parse_cdo_commands(self, section: CdoSection, warnings: List[str]) -> None:
        data = self._data
        base = section.offset + CDO_HEADER_WORDS * 4
        declared_end = base + section.length_words * 4
        end = min(declared_end, len(data))
        section.header_checksum_valid = self._cdo_header_checksum_valid(section.offset)
        r = self._u32le
        count = 0
        i = base
        if declared_end > len(data):
            section.parse_error = f"truncated section at {end:#x}: declared end is {declared_end:#x}"
            warnings.append(section.parse_error)

        while i < end and count < self.MAX_CDO_COMMANDS and not section.parse_error:
            if i + 4 > end:
                section.parse_error = f"truncated command header at {i:#x}"
                warnings.append(section.parse_error)
                break
            cmd_word = r(i)
            if cmd_word == CDO_CMD_END_WORD:
                section.end_detected = True
                i += 4
                break

            payload_len = (cmd_word >> 16) & 0xFF
            is_long = payload_len == CDO_SHORT_LEN_EXTENDED
            payload_offset = i + (8 if is_long else 4)
            if is_long:
                if i + 8 > end:
                    section.parse_error = f"truncated long-command header at {i:#x}"
                    warnings.append(section.parse_error)
                    break
                payload_len = r(i + 4)
            next_cmd = payload_offset + payload_len * 4
            if next_cmd > end:
                section.parse_error = (
                    f"truncated command at {i:#x}: {payload_len} payload words "
                    f"exceed section end {end:#x}"
                )
                warnings.append(section.parse_error)
                break

            store_n = min(payload_len, 8)
            payload = tuple(r(payload_offset + j * 4) for j in range(store_n))
            module_id = (cmd_word >> 8) & 0xFF
            cmd_id = cmd_word & 0xFF
            cmd = CdoCommand(
                offset=i,
                module_id=module_id,
                cmd_id=cmd_id,
                payload=payload,
                payload_offset=payload_offset,
                payload_length=payload_len,
                is_long=is_long,
            )

            if module_id == CDO_MOD_GENERIC and cmd_id in (CDO_CMD_MARKER,
                                                            CDO_CMD_LOG_STRING):
                raw = b"".join(struct.pack("<I", w) for w in payload[1:])
                txt = raw.split(b"\x00")[0].decode("ascii", errors="replace")
                if txt:
                    cmd.string_payload = txt

            if module_id == CDO_MOD_GENERIC and cmd_id in (CDO_CMD_WRITE, CDO_CMD_WRITE64):
                addr: Optional[int] = None
                value: Optional[int] = None
                if cmd_id == CDO_CMD_WRITE and len(payload) >= 2:
                    addr, value = payload[0], payload[1]
                elif cmd_id == CDO_CMD_WRITE64 and len(payload) >= 3:
                    addr = (payload[0] << 32) | payload[1]
                    value = payload[2]
                if addr is not None and addr >= 0xF0000000:
                    cmd.npi_addr = addr
                    cmd.npi_data = value

            section.commands.append(cmd)
            i = next_cmd
            count += 1

        section.consumed_words = (i - base) // 4
        if i < end and count >= self.MAX_CDO_COMMANDS and not section.parse_error:
            section.parse_error = f"truncated at {i:#x}: reached MAX_CDO_COMMANDS"
            warnings.append(section.parse_error)

    def command_payload(self, command: CdoCommand) -> bytes:
        """Return the complete command payload, including payloads over eight words."""
        end = command.payload_offset + command.payload_length * 4
        if command.payload_offset < 0 or end > len(self._data):
            raise ValueError(f"command payload at {command.payload_offset:#x} is out of bounds")
        return self._data[command.payload_offset:end]

    def dma_write_segments(self, section: Optional[CdoSection] = None) -> List[DmaWriteSegment]:
        """Reconstruct memory loads from GENERIC DmaWrite commands."""
        sections = [section] if section is not None else self.result.cdo_sections
        segments: List[DmaWriteSegment] = []
        for sec in sections:
            for cmd in sec.commands:
                if cmd.module_id != CDO_MOD_GENERIC or cmd.cmd_id != CDO_CMD_DMA_WRITE:
                    continue
                if cmd.payload_length < 2:
                    continue
                payload = self.command_payload(cmd)
                high, low = struct.unpack_from("<2I", payload)
                segments.append(DmaWriteSegment(
                    address=(high << 32) | low,
                    data=payload[8:],
                    command_offset=cmd.offset,
                    section_offset=sec.offset,
                ))
        return segments

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def report(self) -> str:
        res = self.result
        lines: List[str] = []

        lines.append(f"VersalPdi: {res.path}")
        lines.append(f"  type={res.pdi_type}  sync_words={res.sync_word_count}  "
                     f"size={res.file_size:#x} bytes ({res.file_size/1024/1024:.1f} MB)")

        git = self.git_hash()
        if git:
            lines.append(f"  git_hash={git}")

        if res.iht is not None:
            iht = res.iht
            lines.append(f"  IHT at {iht.offset:#x}:  no_of_imgs={iht.no_of_imgs}  "
                         f"total_prtns={iht.total_no_of_prtns}  "
                         f"img_hdr_off={iht.img_hdr_off:#x}  "
                         f"part_hdr_off={iht.part_hdr_off:#x}")

        if res.images:
            lines.append(f"  Images ({len(res.images)}):")
            for img in res.images:
                lines.append(f"    [{img.img_name}]  id={img.img_id:#010x}  "
                             f"git={img.git_hash:#010x}  "
                             f"prtns={img.no_of_prtns}")

        if res.partitions:
            lines.append(f"  Partitions ({len(res.partitions)}):")
            for i, ph in enumerate(res.partitions):
                enc_flag = " ENCRYPTED" if ph.is_encrypted else ""
                lines.append(
                    f"    [{i}] {ph.prtn_type_name}{enc_flag}  "
                    f"size={ph.data_size_bytes:#x}B  "
                    f"dst={ph.dst_load_addr:#018x}  "
                    f"data_off={ph.data_word_off:#x}(→{ph.cdo_byte_offset:#x})"
                )

        if res.cdo_sections:
            lines.append(f"  CDO sections ({len(res.cdo_sections)}):")
            for cdo in res.cdo_sections:
                cmds_summary = self._summarize_cdo(cdo)
                checksum = "ok" if cdo.header_checksum_valid else "INVALID"
                stream = "error" if cdo.parse_error else "complete"
                lines.append(f"    @{cdo.offset:#010x}  v{cdo.version_str}  "
                             f"len={cdo.length_words}w ({cdo.payload_bytes//1024}KB)  "
                             f"checksum={checksum}  stream={stream}  "
                             f"cmds={len(cdo.commands)}  [{cmds_summary}]")

        if res.parse_warnings:
            lines.append(f"  Warnings ({len(res.parse_warnings)}):")
            for w in res.parse_warnings[:10]:
                lines.append(f"    ! {w}")

        return "\n".join(lines)

    def _summarize_cdo(self, cdo: CdoSection) -> str:
        """One-line summary of what a CDO section does."""
        counts: Dict[str, int] = {}
        for cmd in cdo.commands:
            key = f"{cmd.module_name}/{cmd.cmd_name}"
            counts[key] = counts.get(key, 0) + 1
        top = sorted(counts.items(), key=lambda kv: -kv[1])[:3]
        return ", ".join(f"{k}×{n}" for k, n in top) if top else "empty"

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _u32le(self, offset: int) -> int:
        return struct.unpack_from("<I", self._data, offset)[0]

    # ------------------------------------------------------------------
    # Convenience class-method API (mirrors other RE extractor pattern)
    # ------------------------------------------------------------------

    @classmethod
    def scan_directory(cls, directory: str, glob: str = "*.pdi") -> List["VersalPdi"]:
        """Parse all PDI files in a directory. Returns a list of VersalPdi objects."""
        results = []
        for p in sorted(Path(directory).glob(glob)):
            try:
                results.append(cls.from_path(str(p)))
            except (OSError, struct.error):
                pass
        return results

    @staticmethod
    def report_all(pdis: Sequence["VersalPdi"]) -> str:
        return "\n\n".join(vp.report() for vp in pdis)
