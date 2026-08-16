#!/usr/bin/env python3
"""
deep_jni_analysis.py — Deep Dive JNI Analysis

Performs detailed disassembly analysis on key JNI functions to extract:
- Vtable dispatch patterns
- Structure field accesses
- Common code patterns
- Internal state management

Usage:
  python3 deep_jni_analysis.py <libhijoyptt.so>
"""

import sys
from pathlib import Path
from collections import defaultdict
from arm_disasm import ARMDisassembler
from arm_symbolic import ARMSymbolicAnalyzer

JNI_FUNCTIONS = {
    'CreateChannel': 0x000239a4,
    'DeleteChannel': 0x00023a78,
    'SetLocalReceiver': 0x00023b10,
    'SetSendDestination': 0x00023ba4,
    'StartListen': 0x00023ca0,
    'StartSend': 0x00023d90,
    'StopListen': 0x00023e08,
    'StopSend': 0x00023ef8,
    'SetSendCodec': 0x00023fe8,
    'SendSignaling': 0x0002511c,
}


def analyze_structure_accesses(lib_path: Path):
    """Extract structure field access patterns"""

    with open(lib_path, 'rb') as f:
        data = f.read()

    disasm = ARMDisassembler(data, base_addr=0)

    print("="*80)
    print("STRUCTURE ACCESS PATTERN ANALYSIS")
    print("="*80)

    # Track offsets across all functions
    all_offsets = defaultdict(list)

    for name, addr in sorted(JNI_FUNCTIONS.items(), key=lambda x: x[1]):
        print(f"\n[{name}] @ 0x{addr:x}")

        # Disassemble
        insns = disasm.disassemble(addr, 100)

        # Extract LDR/STR with offsets
        offsets_seen = set()

        for insn in insns:
            if insn.mnemonic.startswith('ldr') or insn.mnemonic.startswith('str'):
                # Parse offset from operands like [r0, #0x10]
                if '#' in insn.operands:
                    parts = insn.operands.split(',')
                    if len(parts) >= 2:
                        offset_part = parts[-1].strip().rstrip(']')
                        if offset_part.startswith('#') or offset_part.startswith('+#'):
                            try:
                                offset_str = offset_part.lstrip('+#')
                                if offset_str.startswith('0x'):
                                    offset = int(offset_str, 16)
                                else:
                                    offset = int(offset_str)

                                if 0 < offset < 0x200:  # Reasonable structure size
                                    offsets_seen.add(offset)
                                    all_offsets[offset].append(name)
                            except:
                                pass

        if offsets_seen:
            print(f"  Structure offsets: {', '.join(f'0x{x:x}' for x in sorted(offsets_seen)[:10])}")
        else:
            print(f"  No significant offsets detected")

    # Common offsets (accessed by multiple functions)
    print("\n" + "="*80)
    print("COMMON STRUCTURE OFFSETS (accessed by 3+ functions)")
    print("="*80)

    for offset, funcs in sorted(all_offsets.items()):
        if len(funcs) >= 3:
            print(f"0x{offset:03x}: {', '.join(funcs[:5])}")
            if len(funcs) > 5:
                print(f"       ... and {len(funcs) - 5} more")


def analyze_immediate_constants(lib_path: Path):
    """Extract immediate constants that may be protocol-relevant"""

    with open(lib_path, 'rb') as f:
        data = f.read()

    disasm = ARMDisassembler(data, base_addr=0)

    print("\n" + "="*80)
    print("IMMEDIATE CONSTANT ANALYSIS")
    print("="*80)

    # Track constants across all functions
    all_constants = defaultdict(list)

    for name, addr in sorted(JNI_FUNCTIONS.items(), key=lambda x: x[1]):
        # Disassemble
        insns = disasm.disassemble(addr, 100)

        # Extract immediate constants from MOV instructions
        for insn in insns:
            if insn.mnemonic.startswith('mov'):
                if '#' in insn.operands:
                    parts = insn.operands.split(',')
                    if len(parts) >= 2:
                        imm_part = parts[1].strip()
                        if imm_part.startswith('#'):
                            try:
                                imm_str = imm_part.lstrip('#')
                                if imm_str.startswith('0x'):
                                    imm = int(imm_str, 16)
                                else:
                                    imm = int(imm_str)

                                # Filter for protocol-relevant constants
                                if 0 < imm < 256 or imm in [1000, 5000, 32000]:
                                    all_constants[imm].append((name, f'0x{insn.address:x}'))
                            except:
                                pass

    # Show common constants
    print("\nCommon constants (seen in 2+ functions):")
    for const, occurrences in sorted(all_constants.items()):
        if len(occurrences) >= 2:
            print(f"\n  {const} (0x{const:x}):")
            for func, loc in occurrences[:5]:
                print(f"    - {func} @ {loc}")


def analyze_call_targets(lib_path: Path):
    """Identify common call targets and their semantic roles"""

    with open(lib_path, 'rb') as f:
        data = f.read()

    disasm = ARMDisassembler(data, base_addr=0)

    print("\n" + "="*80)
    print("CALL TARGET ANALYSIS")
    print("="*80)

    # Track call targets
    call_targets = defaultdict(list)

    for name, addr in sorted(JNI_FUNCTIONS.items(), key=lambda x: x[1]):
        insns = disasm.disassemble(addr, 100)

        for insn in insns:
            if insn.mnemonic.startswith('bl') and not insn.mnemonic.startswith('blx'):
                # Parse target
                target_str = insn.operands.strip()
                try:
                    if target_str.startswith('0x'):
                        target = int(target_str, 16)
                    else:
                        target = int(target_str)

                    call_targets[target].append(name)
                except:
                    pass

    # Show common targets
    print("\nCommon call targets (called by 3+ JNI functions):")
    for target, callers in sorted(call_targets.items(), key=lambda x: -len(x[1])):
        if len(callers) >= 3:
            print(f"\n  0x{target:x}: called by {len(callers)} functions")
            for caller in callers[:7]:
                print(f"    - {caller}")
            if len(callers) > 7:
                print(f"    - ... and {len(callers) - 7} more")


def analyze_vtable_patterns(lib_path: Path):
    """Identify vtable dispatch patterns"""

    with open(lib_path, 'rb') as f:
        data = f.read()

    disasm = ARMDisassembler(data, base_addr=0)

    print("\n" + "="*80)
    print("VTABLE DISPATCH PATTERN ANALYSIS")
    print("="*80)

    for name, addr in sorted(JNI_FUNCTIONS.items(), key=lambda x: x[1]):
        insns = disasm.disassemble(addr, 150)

        # Look for BLX (indirect call) patterns
        vtable_calls = []

        for i, insn in enumerate(insns):
            if insn.mnemonic.startswith('blx'):
                # Get context (prev 5 instructions)
                context_start = max(0, i - 5)
                context = insns[context_start:i]

                # Look for LDR pattern that loads function pointer
                for ctx_insn in reversed(context):
                    if ctx_insn.mnemonic.startswith('ldr'):
                        # Check if loading with offset (vtable slot)
                        if '#' in ctx_insn.operands:
                            vtable_calls.append({
                                'addr': f'0x{insn.address:x}',
                                'context': str(ctx_insn)
                            })
                        break

        if vtable_calls:
            print(f"\n[{name}]:")
            for vc in vtable_calls[:3]:
                print(f"  BLX @ {vc['addr']}")
                print(f"    Context: {vc['context']}")


def main():
    if len(sys.argv) < 2:
        print("Usage: deep_jni_analysis.py <libhijoyptt.so>")
        sys.exit(1)

    lib_path = Path(sys.argv[1])

    # Run all analyses
    analyze_structure_accesses(lib_path)
    analyze_immediate_constants(lib_path)
    analyze_call_targets(lib_path)
    analyze_vtable_patterns(lib_path)

    print("\n" + "="*80)
    print("DEEP ANALYSIS COMPLETE")
    print("="*80)


if __name__ == '__main__':
    main()
