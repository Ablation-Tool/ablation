"""
_disasm_helper.py: Shared capstone disassembly utility for modules/.

Provides disasm_func() that disassembles a function from a BinaryContext
using capstone, matching the API the modules expect from ctx.disasm_func().

Not an analysis module — internal infrastructure only.
"""

from __future__ import annotations

from typing import List


def disasm_func(ctx, func_va: int, max_bytes: int = 4096) -> List:
    """Disassemble function at func_va using ctx's arch, data, and base."""
    try:
        import capstone
    except ImportError:
        return []

    arch = ctx.arch
    if arch in ('x86_64',):
        cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
    elif arch in ('x86', 'i386', 'i686'):
        cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
    elif arch in ('arm64', 'aarch64'):
        cs_arch = getattr(capstone, 'CS_ARCH_AARCH64', None) or getattr(capstone, 'CS_ARCH_ARM64', None)
        cs_mode = capstone.CS_MODE_ARM
    elif arch in ('arm', 'armv7', 'armv7l'):
        cs_arch, cs_mode = capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM
    elif arch in ('mips', 'mipsel'):
        cs_arch = capstone.CS_ARCH_MIPS
        cs_mode = capstone.CS_MODE_MIPS32
        if 'el' in arch or 'le' in arch:
            cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN
        else:
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN
    elif arch in ('ppc64', 'ppc64le', 'powerpc'):
        cs_arch = capstone.CS_ARCH_PPC
        cs_mode = capstone.CS_MODE_64
        if 'le' in arch:
            cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN
        else:
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN
    else:
        return []

    base = ctx.base_va
    try:
        data = open(ctx.path, 'rb').read()
    except OSError:
        return []

    off = func_va - base
    if off < 0 or off >= len(data):
        return []

    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    return list(md.disasm(data[off:off + max_bytes], func_va))
