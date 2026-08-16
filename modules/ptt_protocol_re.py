#!/usr/bin/env python3
"""
ptt_protocol_re.py — HiJoy PTT Wire Protocol Reverse Engineering

Analyzes SendSignaling() and related functions to extract protocol structure.
Custom ARM disassembler + symbolic execution to map message formats.

Protocol Structure Inference
─────────────────────────────
From SendSignaling() @ 0x2511c:
  1. Immediate value #18 (0x12) → likely message size or type field
  2. Immediate value #2 → protocol version or command type
  3. Multiple vtable calls → OOP protocol handler

Message Structure Hypothesis:
  struct PTTSignal {
      uint8_t  type;        // Inferred from #2 constant
      uint8_t  flags;
      uint16_t length;      // Inferred from #18 constant
      uint32_t channel_id;  // From function arguments
      uint8_t  payload[];
  };

Usage:
  python3 ptt_protocol_re.py libhijoyptt.so --function SendSignaling

Output:
  - Disassembly with protocol annotations
  - Extracted message structure
  - Network I/O patterns (sendto calls)

Author: NuClide Research (2026-08-16)
"""

import struct
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from arm_disasm import ARMDisassembler, ARMInstruction
from arm_symbolic import ARMSymbolicAnalyzer, FuncSummary

class PTTProtocolAnalyzer:
    """Protocol structure extractor from ARM code"""

    FUNCTIONS = {
        'SendSignaling': 0x2511c,
        'SetSendDestination': 0x23ba4,
        'StartSend': 0x23d90,
        'StopSend': 0x23ef8,
        'SetSendCodec': 0x23fe8,
    }

    def __init__(self, lib_path: Path):
        self.lib_path = lib_path
        with open(lib_path, 'rb') as f:
            self.data = f.read()
        self.disasm = ARMDisassembler(self.data, base_addr=0)
        self.symbolic = ARMSymbolicAnalyzer(self.data, base_addr=0)

    def analyze_function(self, name: str, max_insns: int = 200) -> Dict:
        """Analyze a specific function for protocol patterns"""
        if name not in self.FUNCTIONS:
            raise ValueError(f"Unknown function: {name}")

        addr = self.FUNCTIONS[name]
        insns = self.disasm.disassemble(addr, max_insns)

        analysis = {
            'function': name,
            'address': f'0x{addr:x}',
            'constants': [],
            'network_calls': [],
            'structure_accesses': [],
            'protocol_fields': {}
        }

        # Track register state for constant propagation
        reg_state = {}

        for insn in insns:
            # Extract immediate constants (protocol fields)
            if insn.mnemonic.startswith('mov') and '#' in insn.operands:
                parts = insn.operands.split(',')
                if len(parts) == 2:
                    reg = parts[0].strip()
                    val_str = parts[1].strip().lstrip('#')
                    try:
                        if val_str.startswith('0x'):
                            val = int(val_str, 16)
                        else:
                            val = int(val_str)

                        # Filter for protocol-relevant constants
                        if 0 < val < 256:  # Likely protocol field
                            analysis['constants'].append({
                                'address': f'0x{insn.address:x}',
                                'register': reg,
                                'value': val,
                                'hex': f'0x{val:x}'
                            })
                            reg_state[reg] = val
                    except:
                        pass

            # Track structure field accesses (LDR with offset)
            if insn.mnemonic.startswith('ldr') and '+#' in insn.operands:
                match = insn.operands.split('[')
                if len(match) > 1:
                    offset_part = match[1].split('+#')
                    if len(offset_part) > 1:
                        offset_str = offset_part[1].rstrip(']')
                        try:
                            offset = int(offset_str)
                            analysis['structure_accesses'].append({
                                'address': f'0x{insn.address:x}',
                                'offset': offset,
                                'hex': f'0x{offset:x}'
                            })
                        except:
                            pass

            # Detect potential sendto/network calls
            if insn.mnemonic.startswith('bl'):
                analysis['network_calls'].append({
                    'address': f'0x{insn.address:x}',
                    'target': insn.operands,
                    'instruction': str(insn)
                })

        # Infer protocol structure from constants
        analysis['protocol_fields'] = self._infer_protocol_structure(analysis['constants'])

        return analysis

    def _infer_protocol_structure(self, constants: List[Dict]) -> Dict:
        """Infer protocol message structure from extracted constants"""
        fields = {}

        for const in constants:
            val = const['value']

            # Heuristics for field classification
            if val == 2:
                fields['version_or_type'] = {
                    'value': val,
                    'description': 'Protocol version or message type',
                    'size': 1
                }
            elif val == 3:
                fields['command_class'] = {
                    'value': val,
                    'description': 'Command class or severity level',
                    'size': 1
                }
            elif val == 6:
                fields['error_code'] = {
                    'value': val,
                    'description': 'Error code or status',
                    'size': 1
                }
            elif val == 18 or val == 0x12:
                fields['message_length'] = {
                    'value': val,
                    'description': 'Message body length (18 bytes)',
                    'size': 1
                }
            elif 1000 <= val <= 65535:
                fields['port_or_id'] = {
                    'value': val,
                    'description': 'Port number or channel ID',
                    'size': 2
                }

        return fields

    def generate_protocol_spec(self, function_name: str = 'SendSignaling') -> str:
        """Generate C-style protocol structure definition"""
        analysis = self.analyze_function(function_name)

        spec = f"// {function_name} Protocol Structure\n"
        spec += f"// Extracted from {self.lib_path.name} @ {analysis['address']}\n\n"

        spec += "struct PTTSignalingMessage {\n"

        for field_name, field_info in analysis['protocol_fields'].items():
            size = field_info['size']
            val = field_info['value']
            desc = field_info['description']

            if size == 1:
                spec += f"    uint8_t  {field_name:20s}; // {desc} (observed: {val})\n"
            elif size == 2:
                spec += f"    uint16_t {field_name:20s}; // {desc} (observed: {val})\n"
            else:
                spec += f"    uint32_t {field_name:20s}; // {desc} (observed: {val})\n"

        spec += "    uint8_t  payload[];             // Variable length data\n"
        spec += "};\n\n"

        # Add observed constants
        spec += "// Observed Constants:\n"
        for const in analysis['constants']:
            spec += f"//   {const['register']:4s} = {const['value']:3d} (0x{const['value']:02x}) @ {const['address']}\n"

        return spec

    def symbolic_protocol_analysis(self, function_name: str = 'SendSignaling', mark_inputbuf: int = 0) -> Dict:
        """
        Perform symbolic analysis to extract protocol structure with provenance.

        Args:
            function_name: Function to analyze
            mark_inputbuf: Which argument is the protocol buffer (0=r0, 1=r1, etc.)

        Returns:
            Dict with field mappings and provenance
        """
        if function_name not in self.FUNCTIONS:
            raise ValueError(f"Unknown function: {function_name}")

        addr = self.FUNCTIONS[function_name]

        # Run symbolic analysis
        summary = self.symbolic.analyze_function(addr, max_insns=200, mark_inputbuf=mark_inputbuf)

        # Build protocol field map with provenance
        protocol_map = {
            'function': function_name,
            'address': f'0x{addr:x}',
            'field_accesses': [],
            'arg_propagation': [],
            'calls': len(summary.calls),
            'vcalls': len(summary.vcalls)
        }

        # Input buffer field accesses
        for offset in sorted(set(summary.inputbuf_reads)):
            protocol_map['field_accesses'].append({
                'offset': offset,
                'hex': f'0x{offset:x}',
                'type': 'read',
                'description': self._infer_field_type_from_offset(offset)
            })

        # Argument propagation (args written to session/output structures)
        for arg_idx, offset in sorted(set(summary.arg_field_writes)):
            protocol_map['arg_propagation'].append({
                'arg': f'r{arg_idx}',
                'arg_index': arg_idx,
                'written_to_offset': offset,
                'hex': f'0x{offset:x}',
                'provenance': f'Arg({arg_idx}) → Session[0x{offset:x}]'
            })

        return protocol_map

    def _infer_field_type_from_offset(self, offset: int) -> str:
        """Infer field purpose from offset in protocol buffer"""
        if offset == 0:
            return "message_type or header_start"
        elif offset == 1:
            return "flags or version"
        elif offset == 2 or offset == 3:
            return "length field (16-bit)"
        elif offset == 4:
            return "channel_id or session_id (32-bit)"
        elif offset >= 8:
            return "payload data"
        else:
            return "header field"

    def generate_provenance_report(self, function_name: str = 'SendSignaling') -> str:
        """Generate complete provenance-based protocol report"""
        # Run both analyses
        symbolic_result = self.symbolic_protocol_analysis(function_name, mark_inputbuf=0)
        constant_result = self.analyze_function(function_name)

        report = []
        report.append(f"# {function_name} Protocol Analysis with Provenance")
        report.append(f"Function: 0x{symbolic_result['address']}")
        report.append("")

        # Protocol buffer field map
        if symbolic_result['field_accesses']:
            report.append("## Protocol Buffer Field Accesses (from Symbolic Execution)")
            report.append("")
            for field in symbolic_result['field_accesses']:
                report.append(f"- **InputBuf[{field['hex']}]** ({field['type']})")
                report.append(f"  - Inferred: {field['description']}")
            report.append("")

        # Argument propagation
        if symbolic_result['arg_propagation']:
            report.append("## Argument → Session Field Propagation")
            report.append("")
            for prop in symbolic_result['arg_propagation']:
                report.append(f"- **{prop['arg']}** → Session[{prop['hex']}]")
                report.append(f"  - Provenance: {prop['provenance']}")
            report.append("")

        # Protocol constants (from static analysis)
        if constant_result['protocol_fields']:
            report.append("## Protocol Constants (from Static Analysis)")
            report.append("")
            for name, info in constant_result['protocol_fields'].items():
                report.append(f"- **{name}**: {info['value']} ({info['description']})")
            report.append("")

        # Combined structure inference
        report.append("## Inferred Protocol Structure")
        report.append("")
        report.append("```c")
        report.append("struct PTTSignalingMessage {")

        # Merge symbolic + constant analysis
        all_offsets = set()
        if symbolic_result['field_accesses']:
            all_offsets.update(f['offset'] for f in symbolic_result['field_accesses'])

        # Add fields
        for offset in sorted(all_offsets):
            field_name = f"field_{offset:02x}"
            field_type = "uint8_t"

            # Match with constants
            for name, info in constant_result['protocol_fields'].items():
                if info['value'] in [2, 3, 6, 18]:  # Known protocol constants
                    field_name = name
                    field_type = f"uint{info['size']*8}_t"
                    break

            report.append(f"    {field_type:10s} {field_name:20s}; // offset 0x{offset:x}")

        report.append("    uint8_t      payload[];             // Variable length")
        report.append("};")
        report.append("```")
        report.append("")

        # Call graph
        report.append(f"## Function Calls")
        report.append(f"- Direct calls: {symbolic_result['calls']}")
        report.append(f"- Vtable calls: {symbolic_result['vcalls']}")
        report.append("")

        return '\n'.join(report)

    def print_annotated_disassembly(self, function_name: str, count: int = 80):
        """Print disassembly with protocol annotations"""
        analysis = self.analyze_function(function_name, count)
        addr = self.FUNCTIONS[function_name]
        insns = self.disasm.disassemble(addr, count)

        print(f"\n{'='*80}")
        print(f"{function_name}() @ {analysis['address']}")
        print(f"{'='*80}\n")

        # Build annotation map
        annotations = {}
        for const in analysis['constants']:
            addr_int = int(const['address'], 16)
            annotations[addr_int] = f"  ← Protocol field: {const['value']} (0x{const['value']:x})"

        for net_call in analysis['network_calls']:
            addr_int = int(net_call['address'], 16)
            annotations[addr_int] = f"  ← Network call"

        for insn in insns:
            line = f"0x{insn.address:08x}: {insn.encoding:08x}  {insn}"
            if insn.address in annotations:
                line += annotations[insn.address]
            print(line)

def main():
    parser = argparse.ArgumentParser(description='HiJoy PTT Protocol Reverse Engineering')
    parser.add_argument('library', type=Path, help='Path to libhijoyptt.so')
    parser.add_argument('--function', default='SendSignaling', choices=PTTProtocolAnalyzer.FUNCTIONS.keys())
    parser.add_argument('--spec', action='store_true', help='Generate protocol structure definition')
    parser.add_argument('--disasm', action='store_true', help='Print annotated disassembly')
    parser.add_argument('--symbolic', action='store_true', help='Run symbolic analysis with provenance')
    parser.add_argument('--count', type=int, default=80, help='Number of instructions to analyze')

    args = parser.parse_args()

    analyzer = PTTProtocolAnalyzer(args.library)

    if args.symbolic:
        # Symbolic analysis with provenance
        report = analyzer.generate_provenance_report(args.function)
        print(report)
    elif args.spec or not (args.spec or args.disasm or args.symbolic):
        # Original constant-based analysis
        spec = analyzer.generate_protocol_spec(args.function)
        print(spec)

    if args.disasm:
        analyzer.print_annotated_disassembly(args.function, args.count)

if __name__ == '__main__':
    main()
