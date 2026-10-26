"""
undocumented_ppc_opcodes.py — IBM POWER functional simulator opcode gap scanner

Compares the opcode decode tables (decode.map) from IBM POWER functional
simulators (sim_ppc, systemsim) against the public IBM POWER ISA specification
to identify undocumented, internal, or management-only instructions.

Why this exists:
  1. IBM ships functional simulators with text decode.map files that include
     ALL opcodes the hardware implements, including privileged management
     instructions not documented in the public POWER ISA books.
  2. Binary analysis of firmware (e.g. FSP, hostboot) that uses internal
     instructions requires knowing those instruction encodings.
  3. The decode.map files allow identifying instructions removed or added
     between POWER7/POWER8/POWER9/POWER10 without disassembling the binary.

Usage:
    scanner = PPCOpcodeScanner(p7_map=path_to_p7_decode_map,
                               p9_map=path_to_p9_decode_map)
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations
import re
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class OpcodeEntry:
    bits:    str        # bit pattern from decode.map (30-32 chars of 01-)
    unit:    str        # execution unit (FXU, BRU, FPU, CMU, VPU, ...)
    mnem:    str        # mnemonic (or '-' for reserved/unnamed)
    source:  str        # 'p7', 'p8', 'p9', 'p10'
    raw:     str        # original line from decode.map


@dataclass
class OpcodeGapFinding:
    kind:     str           # 'internal_unit' | 'primary0' | 'removed' | 'added' | 'mnemonic_dash'
    mnem:     str
    unit:     str
    bits:     str
    present:  list[str]     # which ISA generations have this
    absent:   list[str]     # which ISA generations lack this
    note:     str


# Public POWER ISA mnemonics (ISA 3.1 / POWER10 public spec).
# Additions here reduce false positives in the undocumented scan.
# Source: IBM POWER ISA Version 3.1 (SA23-2260-01).
PUBLIC_POWER_ISA_MNEMONICS = frozenset([
    # Branch instructions
    'b','ba','bl','bla','bc','bca','bcl','bcla','bclr','bclrl','bcctr','bcctrl',
    'bctar','bctarl','bdnz','bdnzl','bdnza','bdnzla','bdz','bdzl','bdza','bdzla',
    # Fixed-point
    'add','addo','addo.','add.','addc','addco','addc.','addco.','adde','addeo',
    'adde.','addeo.','addi','addic','addic.','addis','addme','addmeo','addme.',
    'addmeo.','addze','addzeo','addze.','addzeo.','subf','subfo','subf.','subfo.',
    'subfc','subfco','subfc.','subfco.','subfe','subfeo','subfe.','subfeo.',
    'subfic','subfme','subfmeo','subfme.','subfmeo.','subfze','subfzeo','subfze.',
    'subfzeo.','and','ando','and.','andc','andc.','andi.','andis.','or','oro',
    'orc','orc.','ori','oris','xor','xoro','xor.','xori','xoris','nand','nand.',
    'nor','nor.','eqv','eqv.','neg','nego','neg.','nego.','mul','mulo','mul.',
    'mulo.','mulhd','mulhd.','mulhdu','mulhdu.','mulhw','mulhw.','mulhwu',
    'mulhwu.','mulli','mulld','mulldo','mulld.','mulldo.','mullw','mullwo',
    'mullw.','mullwo.','divd','divdo','divd.','divdo.','divdu','divduo','divdu.',
    'divduo.','divde','divdeo','divde.','divdeo.','divdeu','divdeuo','divdeu.',
    'divdeuo.','divw','divwo','divw.','divwo.','divwu','divwuo','divwu.','divwuo.',
    'cmp','cmpi','cmpl','cmpli','cmpeqb','cmprb','cntlzd','cntlzd.','cntlzw',
    'cntlzw.','cnttzd','cnttzd.','cnttzw','cnttzw.','extsb','extsb.','extsh',
    'extsh.','extsw','extsw.','popcntb','popcntd','popcntw','prtyd','prtyw',
    'bpermd','cmpb','isel','sld','sld.','slw','slw.','srd','srd.','srw','srw.',
    'srad','srad.','sradi','sradi.','sraw','sraw.','srawi','srawi.','rldicl',
    'rldicl.','rldicr','rldicr.','rldic','rldic.','rldimi','rldimi.','rldcl',
    'rldcl.','rldcr','rldcr.','rlwimi','rlwimi.','rlwinm','rlwinm.','rlwnm',
    'rlwnm.',
    # Load/store
    'ld','ldu','ldx','ldux','lwa','lwax','lwaux','ldarx','lwarx','lharx','lbarx',
    'lfd','lfdu','lfdx','lfdux','lfs','lfsu','lfsx','lfsux','lq','lqarx',
    'std','stdu','stdx','stdux','stdcx.','stw','stwu','stwx','stwux','stwcx.',
    'sth','sthu','sthx','sthux','sthcx.','stb','stbu','stbx','stbux','stbcx.',
    'stfd','stfdu','stfdx','stfdux','stfs','stfsu','stfsx','stfsux','stfiwx',
    'stfpx','stq','stqcx.','lwz','lwzu','lwzx','lwzux','lhz','lhzu','lhzx',
    'lhzux','lha','lhau','lhax','lhaux','lbz','lbzu','lbzx','lbzux',
    'dcbz','dcbst','dcbf','dcbt','dcbtst','dcbi','icbi','icbt',
    # Branch to LR/CTR/TAR
    'rfid','rfsvc','hrfid',
    # System call
    'sc','scv','tbegin','tend','tabort','tabortwc','tabortdc','tabortwci',
    'tabortdci','tcheck','tsr','trechkpt','trecia','treclaim',
    # Trap
    'tw','twi','td','tdi',
    # FP
    'fadd','fadds','fsub','fsubs','fmul','fmuls','fdiv','fdivs','fmadd','fmadds',
    'fmsub','fmsubs','fnmadd','fnmadds','fnmsub','fnmsubs','fabs','fabs.',
    'fnabs','fnabs.','fmr','fmr.','fneg','fneg.','frsp','frsp.','fctid','fctid.',
    'fctidz','fctidz.','fctidu','fctidu.','fctiduz','fctiduz.','fctiw','fctiw.',
    'fctiwz','fctiwz.','fctiwu','fctiwu.','fctiwuz','fctiwuz.','fcfid','fcfid.',
    'fcfidu','fcfidu.','fcfids','fcfids.','fcfidus','fcfidus.','fsqrt','fsqrts',
    'fre','fres','frsqrte','frsqrtes','fsel','fsel.','mffs','mffs.','mtfsb0',
    'mtfsb1','mtfsf','mtfsfi','fcmpu','fcmpo',
    # VMX/AltiVec
    'vaddubm','vadduhm','vadduwm','vaddudm','vadduqm','vaddcuq','vaddcuw',
    'vaddubs','vadduhs','vadduws','vaddsbs','vaddshs','vaddsws',
    'vsububm','vsubuhm','vsubuwm','vsubudm','vsubuqm','vsubcuq','vsubcuw',
    'vsububs','vsubuhs','vsubuws','vsubsbs','vsubshs','vsubsws',
    'vmulouw','vmulohw','vmuleuw','vmulehw','vmulosb','vmulosw','vmulesh','vmulesw',
    'vmuluwm','vmulld','vand','vandc','vor','vorc','vxor','vnor','veqv','vnand',
    'vrlb','vrlh','vrlw','vrld','vslb','vslh','vslw','vsld','vsrb','vsrh','vsrw',
    'vsrd','vsrab','vsrah','vsraw','vsrad','vsr','vsl','vslo','vsro','vsldoi',
    'vperm','vpermxor','vpermr','vsel','vcmpequb','vcmpequh','vcmpequw','vcmpequd',
    'vcmpgtsb','vcmpgtsh','vcmpgtsw','vcmpgtsd','vcmpgtub','vcmpgtuh','vcmpgtuw',
    'vcmpgtud','vcmpneb','vcmpneh','vcmpnew','vcmpnezb','vcmpnezh','vcmpnezw',
    'vmrghb','vmrghh','vmrghw','vmrglb','vmrglh','vmrglw','vspltb','vsplth',
    'vspltw','vspltisb','vspltish','vspltisw','vrefp','vrsqrtefp','vexptefp',
    'vlogefp','vrfim','vrfin','vrfip','vrfiz','vcfux','vcfsx','vctuxs','vctsxs',
    'vaddfp','vsubfp','vmaddfp','vnmsubfp','vcmpbfp','vcmpeqfp','vcmpgefp',
    'vcmpgtfp','vmaxfp','vminfp','vpkuhum','vpkuwum','vpkuhus','vpkuwus',
    'vpkshus','vpkswus','vpkshss','vpkswss','vpkpx','vupkhsb','vupkhsh',
    'vupkhpx','vupklsb','vupklsh','vupklpx','lvx','lvxl','stvx','stvxl',
    'lvsl','lvsr','lvebx','lvehx','lvewx','stvebx','stvehx','stvewx',
    'lvlx','lvrx','stvlx','stvrx','lvlxl','lvrxl','stvlxl','stvrxl',
    # VSX
    'lxsdx','lxsssx','lxvd2x','lxvdsx','lxvw4x','lxsiwax','lxsiwzx',
    'lxsibzx','lxsihzx','lxsiwzx','lxsspx','stxsdx','stxsspx','stxvd2x',
    'stxvw4x','stxsiwx','stxsibx','stxsihx',
    'xsaddsp','xsadddp','xssubsp','xssubdp','xsmulsp','xsmuldp','xsdivsp',
    'xsdivdp','xsmaxsp','xsmaxdp','xsminsp','xsmindp','xsabsdp','xsnabsdp',
    'xsnegdp','xscpsgndp','xssqrtsp','xssqrtdp','xscvspdp','xscvdpsp',
    'xvcpsgndp','xvabsdp','xvnabsdp','xvnegdp','xvsqrtdp','xvsqrtsp',
    # BCD
    'bcdadd.','bcdsub.','bcdus.','bcds.','bcdtrunc.','bcdutrunc.','bcdcfn.',
    'bcdcfz.','bcdcfsq.','bcdctn.','bcdctz.','bcdctsq.','bcdsetsgn.','bcdsr.',
    # POWER9 new
    'darn','addex','addpcis','addex.','copy','paste.','cp_abort','stop',
    'slbia','tlbie','tlbiel','tlbsync','eieio','hwsync','isync','sync','lwsync',
    # Misc
    'mfspr','mtspr','mfmsr','mtmsr','mtmsrd','mfcr','mtcrf','mfocrf','mtocrf',
    'mcrxr','mcrxrx','mfxer','mtxer','mflr','mtlr','mfctr','mtctr','mftb',
    'nop','attn','wait',
    # Power mgmt (public)
    'rfscv','rfebb','lnia',
])

# Units that signal internal/management instructions
INTERNAL_UNITS = frozenset(['CMU'])


def parse_decode_map(path: str, source: str) -> list[OpcodeEntry]:
    """Parse an IBM sim_ppc decode.map file into OpcodeEntry list."""
    entries: list[OpcodeEntry] = []
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            m = re.match(r'^([01\-]{20,})\s+.*?#(\w+),([-\w.]*)', stripped)
            if m:
                entries.append(OpcodeEntry(
                    bits=m.group(1),
                    unit=m.group(2),
                    mnem=m.group(3),
                    source=source,
                    raw=stripped[:120],
                ))
    return entries


class PPCOpcodeScanner:
    """Scan IBM POWER functional simulator decode tables for undocumented opcodes.

    Compares up to four generations of POWER ISA decode tables (from text
    decode.map files shipped with IBM sim_ppc / systemsim packages) and flags
    instructions that:
      - Use primary opcode 0 (normally reserved for attn/illegal)
      - Are assigned to internal execution units (CMU = Chip Management Unit)
      - Have '-' as their mnemonic (reserved/placeholder entries)
      - Are present in one generation but absent in another

    Args:
        p7_map:  Path to POWER7 decode.map (sim_ppc-power7 RPM, opt/ibm/sim_ppc/sim_p7/bin/)
        p8_map:  Path to POWER8 decode.map (optional)
        p9_map:  Path to POWER9 decode.map (sim_ppc-power9 RPM, opt/ibm/sim_ppc/sim_p9/bin/)
        p10_map: Path to POWER10 decode.map (not available in systemsim-p10 1.2-4; None ok)
    """

    def __init__(
        self,
        p7_map:  Optional[str] = None,
        p8_map:  Optional[str] = None,
        p9_map:  Optional[str] = None,
        p10_map: Optional[str] = None,
    ) -> None:
        self._maps: dict[str, list[OpcodeEntry]] = {}
        for label, path in [('p7', p7_map), ('p8', p8_map), ('p9', p9_map), ('p10', p10_map)]:
            if path and os.path.exists(path):
                self._maps[label] = parse_decode_map(path, label)

    @classmethod
    def from_context(cls, ctx) -> 'PPCOpcodeScanner':  # type: ignore[override]
        """BinaryContext-compatible factory (ctx unused; for API conformity)."""
        return cls()

    def scan(self) -> list[OpcodeGapFinding]:
        findings: list[OpcodeGapFinding] = []

        # Build per-generation mnem → bits mapping
        gen_mnems: dict[str, dict[str, list[str]]] = {}
        for gen, entries in self._maps.items():
            gen_mnems[gen] = {}
            for e in entries:
                gen_mnems[gen].setdefault(e.mnem, []).append(e.bits)

        all_gens = list(self._maps.keys())

        # Scan each generation's entries
        for gen, entries in self._maps.items():
            seen_mnems: set[str] = set()
            for e in entries:
                if e.mnem in seen_mnems:
                    continue

                # 1. Primary opcode 0 (unusual: normally reserved/trap)
                if e.bits.startswith('000000'):
                    present = [g for g in all_gens if e.mnem in gen_mnems.get(g, {})]
                    absent  = [g for g in all_gens if e.mnem not in gen_mnems.get(g, {})]
                    findings.append(OpcodeGapFinding(
                        kind='primary0',
                        mnem=e.mnem,
                        unit=e.unit,
                        bits=e.bits,
                        present=present,
                        absent=absent,
                        note=(
                            f'Primary opcode 0 (reserved/trap in public POWER ISA). '
                            f'XO bits 21-31: {e.bits[-11:]}. '
                            f'Unit: {e.unit}. '
                            f'Not in IBM POWER ISA public spec as user-space instruction.'
                        ),
                    ))
                    seen_mnems.add(e.mnem)
                    continue

                # 2. Internal unit (CMU = Chip Management Unit)
                if e.unit in INTERNAL_UNITS:
                    present = [g for g in all_gens if e.mnem in gen_mnems.get(g, {})]
                    absent  = [g for g in all_gens if e.mnem not in gen_mnems.get(g, {})]
                    findings.append(OpcodeGapFinding(
                        kind='internal_unit',
                        mnem=e.mnem,
                        unit=e.unit,
                        bits=e.bits,
                        present=present,
                        absent=absent,
                        note=(
                            f'CMU (Chip Management Unit) instruction — '
                            f'privileged power management, not documented in user-space POWER ISA. '
                            f'Opcode bits: {e.bits[:32]}.'
                        ),
                    ))
                    seen_mnems.add(e.mnem)
                    continue

                # 3. Mnemonic '-' (reserved / no public name)
                if e.mnem == '-':
                    findings.append(OpcodeGapFinding(
                        kind='mnemonic_dash',
                        mnem='-',
                        unit=e.unit,
                        bits=e.bits,
                        present=[gen],
                        absent=[g for g in all_gens if g != gen],
                        note=(
                            f'Reserved instruction with no public mnemonic. '
                            f'Unit {e.unit}, opcode bits: {e.bits[:32]}.'
                        ),
                    ))
                    continue

                # 4. Not in public POWER ISA mnemonic set
                mnem_clean = e.mnem.rstrip('.')
                if mnem_clean not in PUBLIC_POWER_ISA_MNEMONICS and e.mnem not in PUBLIC_POWER_ISA_MNEMONICS:
                    present = [g for g in all_gens if e.mnem in gen_mnems.get(g, {})]
                    absent  = [g for g in all_gens if e.mnem not in gen_mnems.get(g, {})]
                    if absent:  # only flag if absent in at least one generation
                        findings.append(OpcodeGapFinding(
                            kind='added' if gen != all_gens[0] else 'removed',
                            mnem=e.mnem,
                            unit=e.unit,
                            bits=e.bits,
                            present=present,
                            absent=absent,
                            note=f'Not in PUBLIC_POWER_ISA_MNEMONICS set; generation-specific.',
                        ))
                        seen_mnems.add(e.mnem)

        return findings

    def report(self, findings: list[OpcodeGapFinding]) -> str:
        if not findings:
            return 'PPCOpcodeScanner: no undocumented opcode findings.'

        lines = [f'PPCOpcodeScanner: {len(findings)} findings', '']
        by_kind: dict[str, list[OpcodeGapFinding]] = {}
        for f in findings:
            by_kind.setdefault(f.kind, []).append(f)

        for kind in ['primary0', 'internal_unit', 'mnemonic_dash', 'removed', 'added']:
            if kind not in by_kind:
                continue
            lines.append(f'=== {kind.upper()} ({len(by_kind[kind])}) ===')
            for f in by_kind[kind]:
                lines.append(
                    f'  {f.mnem:25s}  unit={f.unit:5s}  '
                    f'present={f.present}  absent={f.absent}'
                )
                lines.append(f'    bits: {f.bits[:40]}')
                lines.append(f'    note: {f.note[:100]}')
            lines.append('')

        return '\n'.join(lines)
