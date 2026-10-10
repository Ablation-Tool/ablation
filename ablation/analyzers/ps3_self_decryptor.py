"""
ps3_self_decryptor.py — PS3 SELF (Signed ELF) decryptor.

## Why this exists

3 things that weren't possible before in Ablation:

1. Decrypting PS3 SELF files programmatically inside a Python analysis pipeline.
   lief, capstone, and BinaryContext.load_or_build() all fail silently on encrypted
   SELF format — they see garbage or raise on the non-ELF magic 0x53434500. Before
   this module, decryption required the external scetool binary (C, manual build,
   not importable), invoked manually before any analysis session.

2. Auto-detecting the correct keyset from the SELF header. The key_rev field at bytes
   6-7 of the SCE header selects the master keyset (ERK/RIV). Without this module,
   matching key_rev to the right ERK/RIV required manual lookup in scetool's keys.h
   or aldostools/webMAN-MOD data/keys — outside the analysis loop.

3. Integrating SELF decryption with BinaryContext.load_or_build() in one call.
   The pattern `ctx = BinaryContext.load_or_build(PS3SELFDecryptor.from_path(p).decrypt_to_tmp(p))`
   decrypts on first access and caches the ELF; subsequent loads hit the BinaryContext
   cache without re-decrypting.

Algorithm (naehrwert/scetool sce.cpp):
  Stage 1 — AES-256-CBC decrypt the 64-byte metadata_info block at
            (SCE_header_size + metadata_offset) using the master ERK/RIV.
            Yields per-file key[16] + pad[16] + IV[16] + pad[16].
  Stage 2 — AES-128-CTR decrypt (metadata_header + section_headers + key_table).
            Length = header_len - (SCE_header_size + metadata_offset + 64).
  Stage 3 — For each section where encrypted==3: AES-128-CTR with the per-section
            key/IV from the decrypted key table.
"""
from __future__ import annotations

import os
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import AES as _AES
    _PYCRYPTODOME_OK = True
except ImportError:
    _PYCRYPTODOME_OK = False

# ── SCE / SELF layout constants (matches scetool sce.h / sce.cpp) ────────────
_SCE_HDR_SIZE    = 0x20   # sizeof(sce_header_t)
_META_INFO_SIZE  = 0x40   # key[16]+pad[16]+iv[16]+pad[16]
_META_HDR_SIZE   = 0x20   # sizeof(metadata_header_t)
_SECTION_HDR_SZ  = 0x30   # sizeof(metadata_section_header_t)
_NOT_ENCRYPTED   = 1
_ENCRYPTED       = 3      # METADATA_SECTION_ENCRYPTED (not 1)
_NOT_COMPRESSED  = 1
_COMPRESSED      = 2
_PHDR_SECTION_TYPE = 2    # METADATA_SECTION_TYPE_PHDR
_PAGE_ALIGN      = 0x10000


@dataclass
class SELFDecryptResult:
    """Structured result of a PS3 SELF decryption."""
    in_path: str
    out_path: str
    key_rev: int
    section_count: int
    decrypted_sections: int
    elf_size: int


class PS3SELFDecryptor:
    """
    Decrypts PS3 SELF (Signed ELF) files into plain ELFs using known keysets.

    Construct with from_path() for auto-detection or from_key_rev() for an
    explicit keyset.  Both return a decryptor instance; call decrypt() or
    decrypt_to_tmp() to produce a plain ELF.

    Usage::

        # One-shot: auto-detect keyset, decrypt to temp, hand to BinaryContext.
        from ablation.analyzers.ps3_self_decryptor import PS3SELFDecryptor
        from ablation.analyzers.binary_context import BinaryContext

        elf = PS3SELFDecryptor.from_path(eboot_bin).decrypt_to_tmp(eboot_bin)
        ctx = BinaryContext.load_or_build(elf)

        # Dual-TOC example (GoldenEye BLUS30755):
        # ctx._r2_all will be [0xAD49B8, 0xAE4894] after build —
        # pass to PS3OPDVtableScanner.from_context(ctx) to scan all vtables.
    """

    # ERK = 256-bit master key; RIV = 128-bit master IV.
    # Source: aldostools/webMAN-MOD data/keys, verified against naehrwert/scetool.
    _KEYSETS: Dict[int, Tuple[bytes, bytes]] = {
        0x0016: (  # PS3 firmware 3.70 era APP keyset (covers BLUS30755 and contemporaries)
            bytes.fromhex(
                "A106692224F1E91E1C4EBAD4A25FBFF6"
                "6B4B13E88D878E8CD072F23CD1C5BF7C"
            ),
            bytes.fromhex("62773C70BD749269C0AFD1F12E73909E"),
        ),
    }

    def __init__(self, erk: bytes, riv: bytes) -> None:
        if len(erk) != 32:
            raise ValueError(f"ERK must be 32 bytes, got {len(erk)}")
        if len(riv) != 16:
            raise ValueError(f"RIV must be 16 bytes, got {len(riv)}")
        self._erk = erk
        self._riv = riv

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_key_rev(cls, key_rev: int) -> "PS3SELFDecryptor":
        """Construct from an explicit key_rev value (e.g. 0x0016)."""
        entry = cls._KEYSETS.get(key_rev)
        if entry is None:
            known = ", ".join(f"0x{k:04X}" for k in sorted(cls._KEYSETS))
            raise KeyError(
                f"Unknown key_rev=0x{key_rev:04X}. Known revisions: {known}. "
                "Add new keysets with PS3SELFDecryptor.register_keyset()."
            )
        erk, riv = entry
        return cls(erk, riv)

    @classmethod
    def from_path(cls, self_path: str) -> "PS3SELFDecryptor":
        """Auto-detect keyset by reading key_rev from the SELF header."""
        with open(self_path, "rb") as fh:
            header = fh.read(0x20)
        if len(header) < 0x08 or header[:4] != b"\x53\x43\x45\x00":
            raise ValueError(
                f"{self_path!r}: not a valid SELF/SCE file "
                f"(expected magic 53434500, got {header[:4].hex()})"
            )
        key_rev = struct.unpack_from(">H", header, 6)[0]
        return cls.from_key_rev(key_rev)

    @classmethod
    def register_keyset(cls, key_rev: int, erk: bytes, riv: bytes) -> None:
        """Register an additional keyset (community-sourced or per-title)."""
        if len(erk) != 32:
            raise ValueError(f"ERK must be 32 bytes, got {len(erk)}")
        if len(riv) != 16:
            raise ValueError(f"RIV must be 16 bytes, got {len(riv)}")
        cls._KEYSETS[key_rev] = (erk, riv)

    # ── Decryption ────────────────────────────────────────────────────────────

    def decrypt(self, in_path: str, out_path: str) -> SELFDecryptResult:
        """Decrypt a PS3 SELF file to *out_path* and return a structured result."""
        if not _PYCRYPTODOME_OK:
            raise ImportError(
                "pycryptodome is required for PS3SELFDecryptor: "
                "pip install pycryptodome"
            )
        return _decrypt_self(in_path, out_path, self._erk, self._riv)

    def decrypt_to_tmp(self, in_path: str, suffix: str = ".elf") -> str:
        """Decrypt to a temp file and return its path (caller owns deletion)."""
        tf = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        tf.close()
        try:
            self.decrypt(in_path, tf.name)
        except Exception:
            os.unlink(tf.name)
            raise
        return tf.name

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def erk(self) -> bytes:
        return self._erk

    @property
    def riv(self) -> bytes:
        return self._riv


# ── Internal decryption implementation ───────────────────────────────────────

def _aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CTR decrypt; nc_off=0 matches scetool."""
    cipher = _AES.new(key, _AES.MODE_CTR, initial_value=iv, nonce=b"")
    return cipher.encrypt(data)


def _decrypt_self(
    in_path: str,
    out_path: str,
    erk: bytes,
    riv: bytes,
) -> SELFDecryptResult:
    with open(in_path, "rb") as fh:
        raw = bytearray(fh.read())

    # ── Stage 1: parse SCE header ─────────────────────────────────────────
    magic, version, key_rev, hdr_type, meta_off, hdr_len, data_len = \
        struct.unpack_from(">IIHHIQQ", raw, 0)

    if magic != 0x53434500:
        raise ValueError(f"Not a SCE/SELF file (magic=0x{magic:08X})")

    meta_info_off = _SCE_HDR_SIZE + meta_off
    meta_hdr_off  = meta_info_off + _META_INFO_SIZE
    ctr_len       = hdr_len - (_SCE_HDR_SIZE + meta_off + _META_INFO_SIZE)

    if meta_info_off + _META_INFO_SIZE > len(raw):
        raise ValueError("metadata_info offset out of bounds — truncated SELF?")

    # ── Stage 2: AES-256-CBC decrypt metadata_info → per-file key + IV ───
    cbc_cipher = _AES.new(erk, _AES.MODE_CBC, iv=riv)
    mi_dec = bytearray(cbc_cipher.decrypt(
        bytes(raw[meta_info_off : meta_info_off + _META_INFO_SIZE])
    ))

    per_file_key  = bytes(mi_dec[0x00:0x10])
    per_file_pad  = bytes(mi_dec[0x10:0x20])
    per_file_iv   = bytes(mi_dec[0x20:0x30])
    per_file_ipad = bytes(mi_dec[0x30:0x40])

    if per_file_pad[0] != 0x00 or per_file_ipad[0] != 0x00:
        raise RuntimeError(
            f"metadata_info padding check failed (key_rev=0x{key_rev:04X}) — "
            f"key_pad[0]=0x{per_file_pad[0]:02X} iv_pad[0]=0x{per_file_ipad[0]:02X}. "
            "Wrong keyset?"
        )

    # ── Stage 3: AES-128-CTR decrypt metadata header + section headers + key table
    ctr_region = bytes(raw[meta_hdr_off : meta_hdr_off + ctr_len])
    raw[meta_hdr_off : meta_hdr_off + ctr_len] = _aes_ctr(
        per_file_key, per_file_iv, ctr_region
    )

    # ── Stage 4: parse metadata_header ───────────────────────────────────
    # sig_input_length(8) unknown0(4) section_count(4) key_count(4) ...
    _, _, section_count, key_count, _, _, _ = \
        struct.unpack_from(">QIIIIII", raw, meta_hdr_off)

    msh_base = meta_hdr_off + _META_HDR_SIZE
    keys_off  = msh_base + section_count * _SECTION_HDR_SZ

    def _get_key(idx: int) -> bytes:
        off = keys_off + idx * 0x10
        return bytes(raw[off : off + 0x10])

    # ── Stage 5: parse section headers and decrypt each encrypted section ─
    sections: List[Tuple] = []
    for i in range(section_count):
        o = msh_base + i * _SECTION_HDR_SZ
        (data_offset, data_size, s_type, s_index,
         hashed, sha1_idx, encrypted, key_idx, iv_idx, compressed) = \
            struct.unpack_from(">QQIIIIIIII", raw, o)
        sections.append(
            (data_offset, data_size, s_type, s_index,
             encrypted, key_idx, iv_idx, compressed)
        )

    decrypted_count = 0
    for i, (data_offset, data_size, s_type, s_index,
            encrypted, key_idx, iv_idx, compressed) in enumerate(sections):
        if encrypted != _ENCRYPTED or data_size == 0:
            continue
        if key_idx >= key_count or iv_idx >= key_count:
            continue
        seg_key  = _get_key(key_idx)
        seg_iv   = _get_key(iv_idx)
        raw[data_offset : data_offset + data_size] = _aes_ctr(
            seg_key, seg_iv, bytes(raw[data_offset : data_offset + data_size])
        )
        decrypted_count += 1

    # ── Stage 6: extract ELF from SELF ───────────────────────────────────
    # SELF header (10 × u64 at file offset SCE_HDR_SIZE)
    (_, app_info_off, elf_off, phdr_off, shdr_off,
     sec_info_off, sce_ver_off, ctrl_info_off, ctrl_info_sz, _) = \
        struct.unpack_from(">QQQQQQQQQQ", raw, _SCE_HDR_SIZE)

    if bytes(raw[elf_off : elf_off + 4]) != b"\x7fELF":
        raise RuntimeError(
            f"No ELF magic at elf_off=0x{elf_off:X} after decryption — "
            "keyset mismatch or unsupported SELF variant."
        )

    e_phoff         = struct.unpack_from(">Q", raw, elf_off + 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from(">HH", raw, elf_off + 0x36)

    phdrs: List[List] = []
    for i in range(e_phnum):
        poff = phdr_off + i * e_phentsize
        fields = list(struct.unpack_from(">IIQQQQQQ", raw, poff))
        phdrs.append(fields)

    # Build section_index → (self_data_offset, data_size) for PT_LOAD segments
    seg_map: Dict[int, Tuple[int, int]] = {}
    for data_offset, data_size, s_type, s_index, *_ in sections:
        if s_type == _PHDR_SECTION_TYPE and data_size > 0:
            seg_map[s_index] = (data_offset, data_size)

    # Assign non-overlapping ELF file offsets (page-aligned, after header block)
    elf_hdr_sz   = 64
    header_end   = elf_hdr_sz + e_phnum * e_phentsize
    cur_offset   = (header_end + _PAGE_ALIGN - 1) & ~(_PAGE_ALIGN - 1)
    new_offsets: Dict[int, int] = {}
    for i, (p_type, p_flags, p_offset, p_vaddr, p_paddr,
            p_filesz, p_memsz, p_align) in enumerate(phdrs):
        if p_type == 1 and p_filesz > 0:  # PT_LOAD
            new_offsets[i] = cur_offset
            cur_offset = (cur_offset + p_filesz + _PAGE_ALIGN - 1) & ~(_PAGE_ALIGN - 1)

    out_size = max(
        (off + phdrs[i][5] for i, off in new_offsets.items()),
        default=header_end,
    )
    out_size = max(out_size, header_end)

    elf_out = bytearray(out_size)
    elf_out[0:elf_hdr_sz] = raw[elf_off : elf_off + elf_hdr_sz]

    # Write relocated program headers
    for i, ph in enumerate(phdrs):
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = ph
        new_off = new_offsets.get(i, p_offset)
        packed = struct.pack(
            ">IIQQQQQQ",
            p_type, p_flags, new_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align,
        )
        dest = elf_hdr_sz + i * e_phentsize
        elf_out[dest : dest + e_phentsize] = packed

    # Copy decrypted segment data at new offsets
    for s_index, (data_offset, data_size) in seg_map.items():
        if s_index not in new_offsets:
            continue
        new_off   = new_offsets[s_index]
        p_filesz  = phdrs[s_index][5]
        copy_size = min(data_size, p_filesz)
        elf_out[new_off : new_off + copy_size] = raw[data_offset : data_offset + copy_size]

    # Fix e_phoff to point at the new phdr block (immediately after ELF header)
    struct.pack_into(">Q", elf_out, 0x20, elf_hdr_sz)

    Path(out_path).write_bytes(elf_out)

    if elf_out[:4] != b"\x7fELF":
        raise RuntimeError("ELF magic missing in output — internal logic error")

    return SELFDecryptResult(
        in_path=in_path,
        out_path=out_path,
        key_rev=key_rev,
        section_count=section_count,
        decrypted_sections=decrypted_count,
        elf_size=len(elf_out),
    )
