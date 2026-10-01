"""
abc_disasm.py -- HarmonyOS/ArkTS Ark Bytecode (ABC) disassembler.

Decodes ABC bytecode using the full ArkCompiler ISA (v13.0.0.0, 324 opcodes
across 4 prefix groups). Produces both structured Instruction objects and
smali-style text output.

Usage:
    from ablation.analyzers.abc_parser import ABCParser
    from ablation.analyzers.abc_disasm import ARKDisasm

    with ABCParser.from_path('/path/to/modules.abc') as p:
        disasm = ARKDisasm(p)
        for method in p.iter_methods():
            code = p.get_code(method)
            if code:
                text = disasm.disasm_method(method, code)
                print(text)
                # Or structured:
                for insn in disasm.iter_insns(code):
                    print(insn)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field as dc_field
from typing import Dict, Iterator, List, Optional, Tuple

from .abc_parser import ABCParser, MethodInfo, CodeItem

# ── ISA opcode table ──────────────────────────────────────────────────────────
#
# Generated from isa.json (ArkCompiler v13.0.0.0, 324 entries).
#
# key:   (prefix_byte | None, opcode_byte)
# value: (mnemonic: str, size_bytes: int, operands: tuple)
# operands: tuple of (kind, bits) where
#   'r' = vreg index  'i' = immediate  'd' = entity ID  'x' = other
#
# Prefix bytes: callruntime=0xfb(251), deprecated=0xfc(252),
#               wide=0xfd(253), throw=0xfe(254)
#
# opcode_idx[i] <-> format[i] (parallel arrays in isa.json — dual-size
# opcodes like getiterator have two distinct opcode bytes, not one).

_OPCODE_TABLE: Dict[Tuple, Tuple[str, int, tuple]] = {
    (None, 0x00): ('ldundefined', 1, ()),
    (None, 0x01): ('ldnull', 1, ()),
    (None, 0x02): ('ldtrue', 1, ()),
    (None, 0x03): ('ldfalse', 1, ()),
    (None, 0x04): ('createemptyobject', 1, ()),
    (None, 0x05): ('createemptyarray', 2, (('i', 8),)),
    (None, 0x06): ('createarraywithbuffer', 4, (('i', 8), ('d', 16))),
    (None, 0x07): ('createobjectwithbuffer', 4, (('i', 8), ('d', 16))),
    (None, 0x08): ('newobjrange', 4, (('i', 8), ('i', 8), ('r', 8))),
    (None, 0x09): ('newlexenv', 2, (('i', 8),)),
    (None, 0x0a): ('add2', 3, (('i', 8), ('r', 8))),
    (None, 0x0b): ('sub2', 3, (('i', 8), ('r', 8))),
    (None, 0x0c): ('mul2', 3, (('i', 8), ('r', 8))),
    (None, 0x0d): ('div2', 3, (('i', 8), ('r', 8))),
    (None, 0x0e): ('mod2', 3, (('i', 8), ('r', 8))),
    (None, 0x0f): ('eq', 3, (('i', 8), ('r', 8))),
    (None, 0x10): ('noteq', 3, (('i', 8), ('r', 8))),
    (None, 0x11): ('less', 3, (('i', 8), ('r', 8))),
    (None, 0x12): ('lesseq', 3, (('i', 8), ('r', 8))),
    (None, 0x13): ('greater', 3, (('i', 8), ('r', 8))),
    (None, 0x14): ('greatereq', 3, (('i', 8), ('r', 8))),
    (None, 0x15): ('shl2', 3, (('i', 8), ('r', 8))),
    (None, 0x16): ('shr2', 3, (('i', 8), ('r', 8))),
    (None, 0x17): ('ashr2', 3, (('i', 8), ('r', 8))),
    (None, 0x18): ('and2', 3, (('i', 8), ('r', 8))),
    (None, 0x19): ('or2', 3, (('i', 8), ('r', 8))),
    (None, 0x1a): ('xor2', 3, (('i', 8), ('r', 8))),
    (None, 0x1b): ('exp', 3, (('i', 8), ('r', 8))),
    (None, 0x1c): ('typeof', 2, (('i', 8),)),
    (None, 0x1d): ('tonumber', 2, (('i', 8),)),
    (None, 0x1e): ('tonumeric', 2, (('i', 8),)),
    (None, 0x1f): ('neg', 2, (('i', 8),)),
    (None, 0x20): ('not', 2, (('i', 8),)),
    (None, 0x21): ('inc', 2, (('i', 8),)),
    (None, 0x22): ('dec', 2, (('i', 8),)),
    (None, 0x23): ('istrue', 1, ()),
    (None, 0x24): ('isfalse', 1, ()),
    (None, 0x25): ('isin', 3, (('i', 8), ('r', 8))),
    (None, 0x26): ('instanceof', 3, (('i', 8), ('r', 8))),
    (None, 0x27): ('strictnoteq', 3, (('i', 8), ('r', 8))),
    (None, 0x28): ('stricteq', 3, (('i', 8), ('r', 8))),
    (None, 0x29): ('callarg0', 2, (('i', 8),)),
    (None, 0x2a): ('callarg1', 3, (('i', 8), ('r', 8))),
    (None, 0x2b): ('callargs2', 4, (('i', 8), ('r', 8), ('r', 8))),
    (None, 0x2c): ('callargs3', 5, (('i', 8), ('r', 8), ('r', 8), ('r', 8))),
    (None, 0x2d): ('callthis0', 3, (('i', 8), ('r', 8))),
    (None, 0x2e): ('callthis1', 4, (('i', 8), ('r', 8), ('r', 8))),
    (None, 0x2f): ('callthis2', 5, (('i', 8), ('r', 8), ('r', 8), ('r', 8))),
    (None, 0x30): ('callthis3', 6, (('i', 8), ('r', 8), ('r', 8), ('r', 8), ('r', 8))),
    (None, 0x31): ('callthisrange', 4, (('i', 8), ('i', 8), ('r', 8))),
    (None, 0x32): ('supercallthisrange', 4, (('i', 8), ('i', 8), ('r', 8))),
    (None, 0x33): ('definefunc', 5, (('i', 8), ('d', 16), ('i', 8))),
    (None, 0x34): ('definemethod', 5, (('i', 8), ('d', 16), ('i', 8))),
    (None, 0x35): ('defineclasswithbuffer', 9, (('i', 8), ('d', 16), ('d', 16), ('i', 16), ('r', 8))),
    (None, 0x36): ('getnextpropname', 2, (('r', 8),)),
    (None, 0x37): ('ldobjbyvalue', 3, (('i', 8), ('r', 8))),
    (None, 0x38): ('stobjbyvalue', 4, (('i', 8), ('r', 8), ('r', 8))),
    (None, 0x39): ('ldsuperbyvalue', 3, (('i', 8), ('r', 8))),
    (None, 0x3a): ('ldobjbyindex', 4, (('i', 8), ('i', 16))),
    (None, 0x3b): ('stobjbyindex', 5, (('i', 8), ('r', 8), ('i', 16))),
    (None, 0x3c): ('ldlexvar', 2, (('i', 4), ('i', 4))),
    (None, 0x3d): ('stlexvar', 2, (('i', 4), ('i', 4))),
    (None, 0x3e): ('lda.str', 3, (('d', 16),)),
    (None, 0x3f): ('tryldglobalbyname', 4, (('i', 8), ('d', 16))),
    (None, 0x40): ('trystglobalbyname', 4, (('i', 8), ('d', 16))),
    (None, 0x41): ('ldglobalvar', 5, (('i', 16), ('d', 16))),
    (None, 0x42): ('ldobjbyname', 4, (('i', 8), ('d', 16))),
    (None, 0x43): ('stobjbyname', 5, (('i', 8), ('d', 16), ('r', 8))),
    (None, 0x44): ('mov', 2, (('r', 4), ('r', 4))),
    (None, 0x45): ('mov', 3, (('r', 8), ('r', 8))),
    (None, 0x46): ('ldsuperbyname', 4, (('i', 8), ('d', 16))),
    (None, 0x47): ('stconsttoglobalrecord', 5, (('i', 16), ('d', 16))),
    (None, 0x48): ('sttoglobalrecord', 5, (('i', 16), ('d', 16))),
    (None, 0x49): ('ldthisbyname', 4, (('i', 8), ('d', 16))),
    (None, 0x4a): ('stthisbyname', 4, (('i', 8), ('d', 16))),
    (None, 0x4b): ('ldthisbyvalue', 2, (('i', 8),)),
    (None, 0x4c): ('stthisbyvalue', 3, (('i', 8), ('r', 8))),
    (None, 0x4d): ('jmp', 2, (('i', 8),)),
    (None, 0x4e): ('jmp', 3, (('i', 16),)),
    (None, 0x4f): ('jeqz', 2, (('i', 8),)),
    (None, 0x50): ('jeqz', 3, (('i', 16),)),
    (None, 0x51): ('jnez', 2, (('i', 8),)),
    (None, 0x52): ('jstricteqz', 2, (('i', 8),)),
    (None, 0x53): ('jnstricteqz', 2, (('i', 8),)),
    (None, 0x54): ('jeqnull', 2, (('i', 8),)),
    (None, 0x55): ('jnenull', 2, (('i', 8),)),
    (None, 0x56): ('jstricteqnull', 2, (('i', 8),)),
    (None, 0x57): ('jnstricteqnull', 2, (('i', 8),)),
    (None, 0x58): ('jequndefined', 2, (('i', 8),)),
    (None, 0x59): ('jneundefined', 2, (('i', 8),)),
    (None, 0x5a): ('jstrictequndefined', 2, (('i', 8),)),
    (None, 0x5b): ('jnstrictequndefined', 2, (('i', 8),)),
    (None, 0x5c): ('jeq', 3, (('r', 8), ('i', 8))),
    (None, 0x5d): ('jne', 3, (('r', 8), ('i', 8))),
    (None, 0x5e): ('jstricteq', 3, (('r', 8), ('i', 8))),
    (None, 0x5f): ('jnstricteq', 3, (('r', 8), ('i', 8))),
    (None, 0x60): ('lda', 2, (('r', 8),)),
    (None, 0x61): ('sta', 2, (('r', 8),)),
    (None, 0x62): ('ldai', 5, (('i', 32),)),
    (None, 0x63): ('fldai', 9, (('i', 64),)),
    (None, 0x64): ('return', 1, ()),
    (None, 0x65): ('returnundefined', 1, ()),
    (None, 0x66): ('getpropiterator', 1, ()),
    (None, 0x67): ('getiterator', 2, (('i', 8),)),
    (None, 0x68): ('closeiterator', 3, (('i', 8), ('r', 8))),
    (None, 0x69): ('poplexenv', 1, ()),
    (None, 0x6a): ('ldnan', 1, ()),
    (None, 0x6b): ('ldinfinity', 1, ()),
    (None, 0x6c): ('getunmappedargs', 1, ()),
    (None, 0x6d): ('ldglobal', 1, ()),
    (None, 0x6e): ('ldnewtarget', 1, ()),
    (None, 0x6f): ('ldthis', 1, ()),
    (None, 0x70): ('ldhole', 1, ()),
    (None, 0x71): ('createregexpwithliteral', 5, (('i', 8), ('d', 16), ('i', 8))),
    (None, 0x72): ('createregexpwithliteral', 6, (('i', 16), ('d', 16), ('i', 8))),
    (None, 0x73): ('callrange', 4, (('i', 8), ('i', 8), ('r', 8))),
    (None, 0x74): ('definefunc', 6, (('i', 16), ('d', 16), ('i', 8))),
    (None, 0x75): ('defineclasswithbuffer', 10, (('i', 16), ('d', 16), ('d', 16), ('i', 16), ('r', 8))),
    (None, 0x76): ('gettemplateobject', 2, (('i', 8),)),
    (None, 0x77): ('setobjectwithproto', 3, (('i', 8), ('r', 8))),
    (None, 0x78): ('stownbyvalue', 4, (('i', 8), ('r', 8), ('r', 8))),
    (None, 0x79): ('stownbyindex', 5, (('i', 8), ('r', 8), ('i', 16))),
    (None, 0x7a): ('stownbyname', 5, (('i', 8), ('d', 16), ('r', 8))),
    (None, 0x7b): ('getmodulenamespace', 2, (('i', 8),)),
    (None, 0x7c): ('stmodulevar', 2, (('i', 8),)),
    (None, 0x7d): ('ldlocalmodulevar', 2, (('i', 8),)),
    (None, 0x7e): ('ldexternalmodulevar', 2, (('i', 8),)),
    (None, 0x7f): ('stglobalvar', 5, (('i', 16), ('d', 16))),
    (None, 0x80): ('createemptyarray', 3, (('i', 16),)),
    (None, 0x81): ('createarraywithbuffer', 5, (('i', 16), ('d', 16))),
    (None, 0x82): ('createobjectwithbuffer', 5, (('i', 16), ('d', 16))),
    (None, 0x83): ('newobjrange', 5, (('i', 16), ('i', 8), ('r', 8))),
    (None, 0x84): ('typeof', 3, (('i', 16),)),
    (None, 0x85): ('ldobjbyvalue', 4, (('i', 16), ('r', 8))),
    (None, 0x86): ('stobjbyvalue', 5, (('i', 16), ('r', 8), ('r', 8))),
    (None, 0x87): ('ldsuperbyvalue', 4, (('i', 16), ('r', 8))),
    (None, 0x88): ('ldobjbyindex', 5, (('i', 16), ('i', 16))),
    (None, 0x89): ('stobjbyindex', 6, (('i', 16), ('r', 8), ('i', 16))),
    (None, 0x8a): ('ldlexvar', 3, (('i', 8), ('i', 8))),
    (None, 0x8b): ('stlexvar', 3, (('i', 8), ('i', 8))),
    (None, 0x8c): ('tryldglobalbyname', 5, (('i', 16), ('d', 16))),
    (None, 0x8d): ('trystglobalbyname', 5, (('i', 16), ('d', 16))),
    (None, 0x8e): ('stownbynamewithnameset', 5, (('i', 8), ('d', 16), ('r', 8))),
    (None, 0x8f): ('mov', 5, (('r', 16), ('r', 16))),
    (None, 0x90): ('ldobjbyname', 5, (('i', 16), ('d', 16))),
    (None, 0x91): ('stobjbyname', 6, (('i', 16), ('d', 16), ('r', 8))),
    (None, 0x92): ('ldsuperbyname', 5, (('i', 16), ('d', 16))),
    (None, 0x93): ('ldthisbyname', 5, (('i', 16), ('d', 16))),
    (None, 0x94): ('stthisbyname', 5, (('i', 16), ('d', 16))),
    (None, 0x95): ('ldthisbyvalue', 3, (('i', 16),)),
    (None, 0x96): ('stthisbyvalue', 4, (('i', 16), ('r', 8))),
    (None, 0x97): ('asyncgeneratorreject', 2, (('r', 8),)),
    (None, 0x98): ('jmp', 5, (('i', 32),)),
    (None, 0x99): ('stownbyvaluewithnameset', 4, (('i', 8), ('r', 8), ('r', 8))),
    (None, 0x9a): ('jeqz', 5, (('i', 32),)),
    (None, 0x9b): ('jnez', 3, (('i', 16),)),
    (None, 0x9c): ('jnez', 5, (('i', 32),)),
    (None, 0x9d): ('jstricteqz', 3, (('i', 16),)),
    (None, 0x9e): ('jnstricteqz', 3, (('i', 16),)),
    (None, 0x9f): ('jeqnull', 3, (('i', 16),)),
    (None, 0xa0): ('jnenull', 3, (('i', 16),)),
    (None, 0xa1): ('jstricteqnull', 3, (('i', 16),)),
    (None, 0xa2): ('jnstricteqnull', 3, (('i', 16),)),
    (None, 0xa3): ('jequndefined', 3, (('i', 16),)),
    (None, 0xa4): ('jneundefined', 3, (('i', 16),)),
    (None, 0xa5): ('jstrictequndefined', 3, (('i', 16),)),
    (None, 0xa6): ('jnstrictequndefined', 3, (('i', 16),)),
    (None, 0xa7): ('jeq', 4, (('r', 8), ('i', 16))),
    (None, 0xa8): ('jne', 4, (('r', 8), ('i', 16))),
    (None, 0xa9): ('jstricteq', 4, (('r', 8), ('i', 16))),
    (None, 0xaa): ('jnstricteq', 4, (('r', 8), ('i', 16))),
    (None, 0xab): ('getiterator', 3, (('i', 16),)),
    (None, 0xac): ('closeiterator', 4, (('i', 16), ('r', 8))),
    (None, 0xad): ('ldsymbol', 1, ()),
    (None, 0xae): ('asyncfunctionenter', 1, ()),
    (None, 0xaf): ('ldfunction', 1, ()),
    (None, 0xb0): ('debugger', 1, ()),
    (None, 0xb1): ('creategeneratorobj', 2, (('r', 8),)),
    (None, 0xb2): ('createiterresultobj', 3, (('r', 8), ('r', 8))),
    (None, 0xb3): ('createobjectwithexcludedkeys', 4, (('i', 8), ('r', 8), ('r', 8))),
    (None, 0xb4): ('newobjapply', 3, (('i', 8), ('r', 8))),
    (None, 0xb5): ('newobjapply', 4, (('i', 16), ('r', 8))),
    (None, 0xb6): ('newlexenvwithname', 4, (('i', 8), ('d', 16))),
    (None, 0xb7): ('createasyncgeneratorobj', 2, (('r', 8),)),
    (None, 0xb8): ('asyncgeneratorresolve', 4, (('r', 8), ('r', 8), ('r', 8))),
    (None, 0xb9): ('supercallspread', 3, (('i', 8), ('r', 8))),
    (None, 0xba): ('apply', 4, (('i', 8), ('r', 8), ('r', 8))),
    (None, 0xbb): ('supercallarrowrange', 4, (('i', 8), ('i', 8), ('r', 8))),
    (None, 0xbc): ('definegettersetterbyvalue', 5, (('r', 8), ('r', 8), ('r', 8), ('r', 8))),
    (None, 0xbd): ('dynamicimport', 1, ()),
    (None, 0xbe): ('definemethod', 6, (('i', 16), ('d', 16), ('i', 8))),
    (None, 0xbf): ('resumegenerator', 1, ()),
    (None, 0xc0): ('getresumemode', 1, ()),
    (None, 0xc1): ('gettemplateobject', 3, (('i', 16),)),
    (None, 0xc2): ('delobjprop', 2, (('r', 8),)),
    (None, 0xc3): ('suspendgenerator', 2, (('r', 8),)),
    (None, 0xc4): ('asyncfunctionawaituncaught', 2, (('r', 8),)),
    (None, 0xc5): ('copydataproperties', 2, (('r', 8),)),
    (None, 0xc6): ('starrayspread', 3, (('r', 8), ('r', 8))),
    (None, 0xc7): ('setobjectwithproto', 4, (('i', 16), ('r', 8))),
    (None, 0xc8): ('stownbyvalue', 5, (('i', 16), ('r', 8), ('r', 8))),
    (None, 0xc9): ('stsuperbyvalue', 4, (('i', 8), ('r', 8), ('r', 8))),
    (None, 0xca): ('stsuperbyvalue', 5, (('i', 16), ('r', 8), ('r', 8))),
    (None, 0xcb): ('stownbyindex', 6, (('i', 16), ('r', 8), ('i', 16))),
    (None, 0xcc): ('stownbyname', 6, (('i', 16), ('d', 16), ('r', 8))),
    (None, 0xcd): ('asyncfunctionresolve', 2, (('r', 8),)),
    (None, 0xce): ('asyncfunctionreject', 2, (('r', 8),)),
    (None, 0xcf): ('copyrestargs', 2, (('i', 8),)),
    (None, 0xd0): ('stsuperbyname', 5, (('i', 8), ('d', 16), ('r', 8))),
    (None, 0xd1): ('stsuperbyname', 6, (('i', 16), ('d', 16), ('r', 8))),
    (None, 0xd2): ('stownbyvaluewithnameset', 5, (('i', 16), ('r', 8), ('r', 8))),
    (None, 0xd3): ('ldbigint', 3, (('d', 16),)),
    (None, 0xd4): ('stownbynamewithnameset', 6, (('i', 16), ('d', 16), ('r', 8))),
    (None, 0xd5): ('nop', 1, ()),
    (None, 0xd6): ('setgeneratorstate', 2, (('i', 8),)),
    (None, 0xd7): ('getasynciterator', 2, (('i', 8),)),
    (None, 0xd8): ('ldprivateproperty', 6, (('i', 8), ('i', 16), ('i', 16))),
    (None, 0xd9): ('stprivateproperty', 7, (('i', 8), ('i', 16), ('i', 16), ('r', 8))),
    (None, 0xda): ('testin', 6, (('i', 8), ('i', 16), ('i', 16))),
    (None, 0xdb): ('definefieldbyname', 5, (('i', 8), ('d', 16), ('r', 8))),
    (None, 0xdc): ('definepropertybyname', 5, (('i', 8), ('d', 16), ('r', 8))),
    (251, 0x00): ('callruntime.notifyconcurrentresult', 2, ()),
    (251, 0x01): ('callruntime.definefieldbyvalue', 5, (('i', 8), ('r', 8), ('r', 8))),
    (251, 0x02): ('callruntime.definefieldbyindex', 8, (('i', 8), ('i', 32), ('r', 8))),
    (251, 0x03): ('callruntime.topropertykey', 2, ()),
    (251, 0x04): ('callruntime.createprivateproperty', 6, (('i', 16), ('d', 16))),
    (251, 0x05): ('callruntime.defineprivateproperty', 8, (('i', 8), ('i', 16), ('i', 16), ('r', 8))),
    (251, 0x06): ('callruntime.callinit', 4, (('i', 8), ('r', 8))),
    (251, 0x07): ('callruntime.definesendableclass', 11, (('i', 16), ('d', 16), ('d', 16), ('i', 16), ('r', 8))),
    (251, 0x08): ('callruntime.ldsendableclass', 4, (('i', 16),)),
    (251, 0x09): ('callruntime.ldsendableexternalmodulevar', 3, (('i', 8),)),
    (251, 0x0a): ('callruntime.wideldsendableexternalmodulevar', 4, (('i', 16),)),
    (251, 0x0b): ('callruntime.newsendableenv', 3, (('i', 8),)),
    (251, 0x0c): ('callruntime.widenewsendableenv', 4, (('i', 16),)),
    (251, 0x0d): ('callruntime.stsendablevar', 3, (('i', 4), ('i', 4))),
    (251, 0x0e): ('callruntime.stsendablevar', 4, (('i', 8), ('i', 8))),
    (251, 0x0f): ('callruntime.widestsendablevar', 6, (('i', 16), ('i', 16))),
    (251, 0x10): ('callruntime.ldsendablevar', 3, (('i', 4), ('i', 4))),
    (251, 0x11): ('callruntime.ldsendablevar', 4, (('i', 8), ('i', 8))),
    (251, 0x12): ('callruntime.wideldsendablevar', 6, (('i', 16), ('i', 16))),
    (251, 0x13): ('callruntime.istrue', 3, (('i', 8),)),
    (251, 0x14): ('callruntime.isfalse', 3, (('i', 8),)),
    (251, 0x15): ('callruntime.ldlazymodulevar', 3, (('i', 8),)),
    (251, 0x16): ('callruntime.wideldlazymodulevar', 4, (('i', 16),)),
    (251, 0x17): ('callruntime.ldlazysendablemodulevar', 3, (('i', 8),)),
    (251, 0x18): ('callruntime.wideldlazysendablemodulevar', 4, (('i', 16),)),
    (251, 0x19): ('callruntime.supercallforwardallargs', 3, (('r', 8),)),
    (252, 0x00): ('deprecated.ldlexenv', 2, ()),
    (252, 0x01): ('deprecated.poplexenv', 2, ()),
    (252, 0x02): ('deprecated.getiteratornext', 4, (('r', 8), ('r', 8))),
    (252, 0x03): ('deprecated.createarraywithbuffer', 4, (('i', 16),)),
    (252, 0x04): ('deprecated.createobjectwithbuffer', 4, (('i', 16),)),
    (252, 0x05): ('deprecated.tonumber', 3, (('r', 8),)),
    (252, 0x06): ('deprecated.tonumeric', 3, (('r', 8),)),
    (252, 0x07): ('deprecated.neg', 3, (('r', 8),)),
    (252, 0x08): ('deprecated.not', 3, (('r', 8),)),
    (252, 0x09): ('deprecated.inc', 3, (('r', 8),)),
    (252, 0x0a): ('deprecated.dec', 3, (('r', 8),)),
    (252, 0x0b): ('deprecated.callarg0', 3, (('r', 8),)),
    (252, 0x0c): ('deprecated.callarg1', 4, (('r', 8), ('r', 8))),
    (252, 0x0d): ('deprecated.callargs2', 5, (('r', 8), ('r', 8), ('r', 8))),
    (252, 0x0e): ('deprecated.callargs3', 6, (('r', 8), ('r', 8), ('r', 8), ('r', 8))),
    (252, 0x0f): ('deprecated.callrange', 5, (('i', 16), ('r', 8))),
    (252, 0x10): ('deprecated.callspread', 5, (('r', 8), ('r', 8), ('r', 8))),
    (252, 0x11): ('deprecated.callthisrange', 5, (('i', 16), ('r', 8))),
    (252, 0x12): ('deprecated.defineclasswithbuffer', 10, (('d', 16), ('i', 16), ('i', 16), ('r', 8), ('r', 8))),
    (252, 0x13): ('deprecated.resumegenerator', 3, (('r', 8),)),
    (252, 0x14): ('deprecated.getresumemode', 3, (('r', 8),)),
    (252, 0x15): ('deprecated.gettemplateobject', 3, (('r', 8),)),
    (252, 0x16): ('deprecated.delobjprop', 4, (('r', 8), ('r', 8))),
    (252, 0x17): ('deprecated.suspendgenerator', 4, (('r', 8), ('r', 8))),
    (252, 0x18): ('deprecated.asyncfunctionawaituncaught', 4, (('r', 8), ('r', 8))),
    (252, 0x19): ('deprecated.copydataproperties', 4, (('r', 8), ('r', 8))),
    (252, 0x1a): ('deprecated.setobjectwithproto', 4, (('r', 8), ('r', 8))),
    (252, 0x1b): ('deprecated.ldobjbyvalue', 4, (('r', 8), ('r', 8))),
    (252, 0x1c): ('deprecated.ldsuperbyvalue', 4, (('r', 8), ('r', 8))),
    (252, 0x1d): ('deprecated.ldobjbyindex', 7, (('r', 8), ('i', 32))),
    (252, 0x1e): ('deprecated.asyncfunctionresolve', 5, (('r', 8), ('r', 8), ('r', 8))),
    (252, 0x1f): ('deprecated.asyncfunctionreject', 5, (('r', 8), ('r', 8), ('r', 8))),
    (252, 0x20): ('deprecated.stlexvar', 4, (('i', 4), ('i', 4), ('r', 8))),
    (252, 0x21): ('deprecated.stlexvar', 5, (('i', 8), ('i', 8), ('r', 8))),
    (252, 0x22): ('deprecated.stlexvar', 7, (('i', 16), ('i', 16), ('r', 8))),
    (252, 0x23): ('deprecated.getmodulenamespace', 6, (('d', 32),)),
    (252, 0x24): ('deprecated.stmodulevar', 6, (('d', 32),)),
    (252, 0x25): ('deprecated.ldobjbyname', 7, (('d', 32), ('r', 8))),
    (252, 0x26): ('deprecated.ldsuperbyname', 7, (('d', 32), ('r', 8))),
    (252, 0x27): ('deprecated.ldmodulevar', 7, (('d', 32), ('i', 8))),
    (252, 0x28): ('deprecated.stconsttoglobalrecord', 6, (('d', 32),)),
    (252, 0x29): ('deprecated.stlettoglobalrecord', 6, (('d', 32),)),
    (252, 0x2a): ('deprecated.stclasstoglobalrecord', 6, (('d', 32),)),
    (252, 0x2b): ('deprecated.ldhomeobject', 2, ()),
    (252, 0x2c): ('deprecated.createobjecthavingmethod', 4, (('i', 16),)),
    (252, 0x2d): ('deprecated.dynamicimport', 3, (('r', 8),)),
    (252, 0x2e): ('deprecated.asyncgeneratorreject', 4, (('r', 8), ('r', 8))),
    (253, 0x00): ('wide.createobjectwithexcludedkeys', 6, (('i', 16), ('r', 8), ('r', 8))),
    (253, 0x01): ('wide.newobjrange', 5, (('i', 16), ('r', 8))),
    (253, 0x02): ('wide.newlexenv', 4, (('i', 16),)),
    (253, 0x03): ('wide.newlexenvwithname', 6, (('i', 16), ('d', 16))),
    (253, 0x04): ('wide.callrange', 5, (('i', 16), ('r', 8))),
    (253, 0x05): ('wide.callthisrange', 5, (('i', 16), ('r', 8))),
    (253, 0x06): ('wide.supercallthisrange', 5, (('i', 16), ('r', 8))),
    (253, 0x07): ('wide.supercallarrowrange', 5, (('i', 16), ('r', 8))),
    (253, 0x08): ('wide.ldobjbyindex', 6, (('i', 32),)),
    (253, 0x09): ('wide.stobjbyindex', 7, (('r', 8), ('i', 32))),
    (253, 0x0a): ('wide.stownbyindex', 7, (('r', 8), ('i', 32))),
    (253, 0x0b): ('wide.copyrestargs', 4, (('i', 16),)),
    (253, 0x0c): ('wide.ldlexvar', 6, (('i', 16), ('i', 16))),
    (253, 0x0d): ('wide.stlexvar', 6, (('i', 16), ('i', 16))),
    (253, 0x0e): ('wide.getmodulenamespace', 4, (('i', 16),)),
    (253, 0x0f): ('wide.stmodulevar', 4, (('i', 16),)),
    (253, 0x10): ('wide.ldlocalmodulevar', 4, (('i', 16),)),
    (253, 0x11): ('wide.ldexternalmodulevar', 4, (('i', 16),)),
    (253, 0x12): ('wide.ldpatchvar', 4, (('i', 16),)),
    (253, 0x13): ('wide.stpatchvar', 4, (('i', 16),)),
    (254, 0x00): ('throw', 2, ()),
    (254, 0x01): ('throw.notexists', 2, ()),
    (254, 0x02): ('throw.patternnoncoercible', 2, ()),
    (254, 0x03): ('throw.deletesuperproperty', 2, ()),
    (254, 0x04): ('throw.constassignment', 3, (('r', 8),)),
    (254, 0x05): ('throw.ifnotobject', 3, (('r', 8),)),
    (254, 0x06): ('throw.undefinedifhole', 4, (('r', 8), ('r', 8))),
    (254, 0x07): ('throw.ifsupernotcorrectcall', 3, (('i', 8),)),
    (254, 0x08): ('throw.ifsupernotcorrectcall', 4, (('i', 16),)),
    (254, 0x09): ('throw.undefinedifholewithname', 4, (('d', 16),)),
}

_PREFIX_BYTES = frozenset({251, 252, 253, 254})

# Mnemonics that constitute call sites (any variant)
_CALL_MNEMONICS = frozenset({
    'callarg0', 'callarg1', 'callargs2', 'callargs3',
    'callthis0', 'callthis1', 'callthis2', 'callthis3',
    'callthisrange', 'callrange',
    'supercallthisrange', 'supercallarrowrange', 'supercallspread',
    'apply', 'newobjapply',
    'deprecated.callarg0', 'deprecated.callarg1',
    'deprecated.callargs2', 'deprecated.callargs3',
    'deprecated.callrange', 'deprecated.callspread',
    'deprecated.callthisrange',
    'callruntime.callinit', 'callruntime.supercallforwardallargs',
})

# Mnemonics that load a string literal into the accumulator
_STR_LOAD_MNEMONICS = frozenset({'lda.str', 'ldbigint'})

# Mnemonics that define / reference a function entity
_FUNC_DEF_MNEMONICS = frozenset({
    'definefunc', 'definemethod', 'defineclasswithbuffer',
    'callruntime.definesendableclass',
    'deprecated.defineclasswithbuffer',
})


# ── Instruction dataclass ─────────────────────────────────────────────────────

@dataclass
class ARKInstruction:
    offset: int                            # byte offset within CodeItem.bytecode
    mnemonic: str
    size: int                              # total bytes consumed (including prefix)
    raw: bytes                             # raw bytes of this instruction
    operands: List[Tuple[str, int]]        # [(kind, value), ...]

    def __str__(self) -> str:
        ops = ', '.join(
            f'v{v}' if k == 'r'
            else (f'{hex(v)}' if k == 'd' else f'{v}')
            for k, v in self.operands
        )
        return f'+{self.offset:04x}  {self.mnemonic:<32} {ops}'

    @property
    def is_call(self) -> bool:
        return self.mnemonic in _CALL_MNEMONICS

    @property
    def is_string_load(self) -> bool:
        return self.mnemonic in _STR_LOAD_MNEMONICS

    @property
    def string_id(self) -> Optional[int]:
        """Entity ID (file offset) of the referenced string for lda.str / ldbigint."""
        if self.mnemonic in _STR_LOAD_MNEMONICS and self.operands:
            return self.operands[0][1]
        return None

    @property
    def func_entity_id(self) -> Optional[int]:
        """Entity ID for definefunc / definemethod instructions (d-kind operand)."""
        if self.mnemonic in _FUNC_DEF_MNEMONICS:
            for kind, val in self.operands:
                if kind == 'd':
                    return val
        return None


# ── Disassembler ──────────────────────────────────────────────────────────────

class ARKDisasm:
    """
    Disassembler for Ark Bytecode (ABC) methods.

    Constructed with an ABCParser so it can resolve entity IDs to strings.
    Stateless after construction — safe to share across threads.
    """

    def __init__(self, parser: ABCParser) -> None:
        self._parser = parser

    # ── Core iterator ─────────────────────────────────────────────────────────

    def iter_insns(self, code: "CodeItem | bytes") -> Iterator[ARKInstruction]:
        """
        Yield ARKInstruction objects for every instruction in *code*.

        Accepts either a CodeItem or raw bytecode bytes. Unknown opcodes are
        emitted as single-byte .data directives to preserve alignment.
        """
        bc = code.bytecode if isinstance(code, CodeItem) else code
        pos = 0
        n = len(bc)
        while pos < n:
            b0 = bc[pos]
            if b0 in _PREFIX_BYTES and pos + 1 < n:
                b1 = bc[pos + 1]
                key = (b0, b1)
            else:
                key = (None, b0)
            entry = _OPCODE_TABLE.get(key)
            if entry is None:
                # Unknown opcode — emit as .data and advance one byte
                yield ARKInstruction(
                    offset=pos, mnemonic='.data',
                    size=1, raw=bytes([b0]),
                    operands=[('x', b0)],
                )
                pos += 1
                continue
            mnem, sz, operand_fmt = entry
            raw = bc[pos: pos + sz]
            if len(raw) < sz:
                break
            operands = _decode_operands(raw, operand_fmt, key[0] is not None)
            yield ARKInstruction(
                offset=pos, mnemonic=mnem,
                size=sz, raw=raw,
                operands=operands,
            )
            pos += sz

    # ── Convenience methods ───────────────────────────────────────────────────

    def find_calls(self, code: CodeItem) -> List[ARKInstruction]:
        return [i for i in self.iter_insns(code) if i.is_call]

    def find_string_loads(self, code: CodeItem) -> List[Tuple[ARKInstruction, str]]:
        """
        Return [(insn, resolved_string), ...] for all lda.str / ldbigint instructions.

        The 16-bit ID in lda.str is an INDEX into the per-region class_idx table
        (not a raw file offset).  Resolved via ABCParser.resolve_class_idx(N).
        """
        out = []
        for insn in self.iter_insns(code):
            n = insn.string_id
            if n is not None:
                s = self._parser.resolve_class_idx(n)
                if s:
                    out.append((insn, s))
        return out

    def disasm_method(self, method: MethodInfo,
                      code: Optional[CodeItem] = None) -> str:
        """Return a smali-style text disassembly of *method*."""
        if code is None:
            code = self._parser.get_code(method)
        if code is None:
            return f'# {method.fqn} — no code\n'
        lines = [
            f'# {method.fqn}',
            f'# regs={code.register_count} args={code.parameter_count} '
            f'code_size={code.code_size} exc={code.exception_handler_count}',
        ]
        for insn in self.iter_insns(code):
            # Annotate string loads inline
            comment = ''
            if insn.is_string_load:
                n = insn.string_id
                if n is not None:
                    s = self._parser.resolve_class_idx(n)
                    if s:
                        comment = f'  # "{s[:60]}"'
            lines.append(f'  {insn}{comment}')
        return '\n'.join(lines)

    def disasm_all(self) -> str:
        """Disassemble every method with code in the file."""
        parts = []
        for method in self._parser.iter_methods():
            code = self._parser.get_code(method)
            if code:
                parts.append(self.disasm_method(method, code))
        return '\n\n'.join(parts)


# ── Operand decoder ───────────────────────────────────────────────────────────

def _decode_operands(raw: bytes, fmt: tuple, is_prefixed: bool) -> List[Tuple[str, int]]:
    """
    Decode operands from raw instruction bytes using the format tuple.

    raw[0] is the primary opcode (or prefix byte for prefixed instructions).
    Operand bytes begin at raw[1] (non-prefixed) or raw[2] (prefixed).

    4-bit fields are packed two per byte (low nibble = first field,
    high nibble = second field).
    """
    out = []
    if not fmt:
        return out
    # byte cursor into raw, skipping opcode byte(s)
    byte_pos = 2 if is_prefixed else 1
    # sub-byte cursor for 4-bit packing (0 = low nibble, 4 = high nibble)
    bit_offset = 0

    for kind, bits in fmt:
        if bits == 4:
            # 4-bit field packed in a nibble
            if byte_pos >= len(raw):
                break
            nibble_byte = raw[byte_pos]
            if bit_offset == 0:
                val = nibble_byte & 0x0f
                bit_offset = 4
            else:
                val = (nibble_byte >> 4) & 0x0f
                bit_offset = 0
                byte_pos += 1
            out.append((kind, val))
        else:
            # flush any pending nibble state
            if bit_offset:
                byte_pos += 1
                bit_offset = 0
            nbytes = bits // 8
            if byte_pos + nbytes > len(raw):
                break
            chunk = raw[byte_pos: byte_pos + nbytes]
            byte_pos += nbytes
            if nbytes == 1:
                val = chunk[0]
            elif nbytes == 2:
                val = struct.unpack_from('<H', chunk)[0]
            elif nbytes == 4:
                val = struct.unpack_from('<I', chunk)[0]
            elif nbytes == 8:
                val = struct.unpack_from('<Q', chunk)[0]
            else:
                val = int.from_bytes(chunk, 'little')
            out.append((kind, val))
    return out
