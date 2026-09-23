#!/usr/bin/env python3
"""
analyze_all_jni.py — Complete JNI Surface Analysis

Analyzes all 10 JNI functions in libhijoyptt.so using symbolic execution.
Generates comprehensive function interaction map and protocol surface.

Usage:
  python3 analyze_all_jni.py <libhijoyptt.so>

Output:
  - Per-function summaries
  - Call graph
  - Protocol field map
  - Complete surface report
"""

import sys
from pathlib import Path
from arm_symbolic import ARMSymbolicAnalyzer, FuncSummary
from ptt_protocol_re import PTTProtocolAnalyzer

# JNI function table from hijoy_ptt_re.py
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


def analyze_all_functions(lib_path: Path) -> dict:
    """Analyze all JNI functions"""

    # Load binary
    with open(lib_path, 'rb') as f:
        data = f.read()

    analyzer = ARMSymbolicAnalyzer(data, base_addr=0)

    results = {
        'functions': {},
        'call_graph': [],
        'protocol_ops': [],
        'io_operations': [],
    }

    print(f"Analyzing {len(JNI_FUNCTIONS)} JNI functions from libhijoyptt.so\n")
    print("="*80)

    for name, addr in sorted(JNI_FUNCTIONS.items(), key=lambda x: x[1]):
        print(f"\n[{name}] @ 0x{addr:x}")
        print("-"*80)

        # Analyze with symbolic execution
        summary = analyzer.analyze_function(addr, max_insns=150)

        # Classify function by behavior
        classification = classify_function(name, summary)

        # Store results
        results['functions'][name] = {
            'addr': f'0x{addr:x}',
            'summary': summary,
            'classification': classification,
        }

        # Print summary
        print(f"Classification: {classification['type']}")
        print(f"Description: {classification['description']}")

        if summary.arg_field_writes:
            print(f"Arg writes: {len(summary.arg_field_writes)}")
            for arg_idx, offset in sorted(set(summary.arg_field_writes))[:5]:
                print(f"  - Arg({arg_idx}) → [base + 0x{offset:x}]")

        if summary.inputbuf_reads:
            print(f"Input reads: {len(summary.inputbuf_reads)}")
            for offset in sorted(set(summary.inputbuf_reads))[:5]:
                print(f"  - InputBuf[0x{offset:x}]")

        if summary.calls:
            print(f"Direct calls: {len(summary.calls)}")

        if summary.vcalls:
            print(f"Vtable calls: {len(summary.vcalls)}")

        # Extract call targets
        for target, args in summary.calls:
            results['call_graph'].append({
                'caller': name,
                'target': f'0x{target:x}',
                'args_symbolic': str(args[:4])
            })

    print("\n" + "="*80)
    return results


def classify_function(name: str, summary: FuncSummary) -> dict:
    """Classify function by name + behavior patterns"""

    # Name-based classification
    if 'Create' in name:
        type_ = 'INIT'
        desc = 'Channel/session initialization'
    elif 'Delete' in name:
        type_ = 'CLEANUP'
        desc = 'Resource cleanup and teardown'
    elif 'Start' in name:
        type_ = 'CONTROL'
        desc = 'Start PTT transmission/reception'
    elif 'Stop' in name:
        type_ = 'CONTROL'
        desc = 'Stop PTT transmission/reception'
    elif 'Set' in name:
        type_ = 'CONFIG'
        desc = 'Configure session parameters'
    elif 'Send' in name:
        type_ = 'IO'
        desc = 'Protocol signaling/data transmission'
    else:
        type_ = 'UNKNOWN'
        desc = 'Unknown function type'

    # Refine by behavior
    if summary.calls and len(summary.calls) > 5:
        complexity = 'COMPLEX'
    elif summary.calls:
        complexity = 'MODERATE'
    else:
        complexity = 'SIMPLE'

    return {
        'type': type_,
        'description': desc,
        'complexity': complexity,
        'has_io': len(summary.calls) > 0,
        'has_state_writes': len(summary.arg_field_writes) > 0,
    }


def generate_report(results: dict, output_path: Path):
    """Generate comprehensive Markdown report"""

    lines = []
    lines.append("# HiJoy PTT Complete JNI Surface Analysis")
    lines.append("")
    lines.append(f"**Functions Analyzed:** {len(results['functions'])}")
    lines.append(f"**Total Call Graph Edges:** {len(results['call_graph'])}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Function table
    lines.append("## JNI Function Surface")
    lines.append("")
    lines.append("| Function | Address | Type | Complexity | Calls | Arg Writes | Description |")
    lines.append("|----------|---------|------|------------|-------|------------|-------------|")

    for name, data in sorted(results['functions'].items(), key=lambda x: x[1]['addr']):
        summary = data['summary']
        classification = data['classification']

        lines.append(
            f"| {name} | {data['addr']} | {classification['type']} | "
            f"{classification['complexity']} | {len(summary.calls)} | "
            f"{len(summary.arg_field_writes)} | {classification['description']} |"
        )

    lines.append("")
    lines.append("---")
    lines.append("")

    # Per-function details
    lines.append("## Per-Function Analysis")
    lines.append("")

    for name, data in sorted(results['functions'].items(), key=lambda x: x[1]['addr']):
        summary = data['summary']
        classification = data['classification']

        lines.append(f"### {name}")
        lines.append("")
        lines.append(f"**Address:** {data['addr']}")
        lines.append(f"**Type:** {classification['type']}")
        lines.append(f"**Complexity:** {classification['complexity']}")
        lines.append("")

        # Symbolic effects
        lines.append("**Symbolic Effects:**")
        lines.append("")

        if summary.arg_field_writes:
            lines.append("- **Argument Writes:**")
            for arg_idx, offset in sorted(set(summary.arg_field_writes)):
                lines.append(f"  - `Arg({arg_idx}) → [base + 0x{offset:x}]`")
            lines.append("")

        if summary.inputbuf_reads:
            lines.append("- **Protocol Buffer Reads:**")
            for offset in sorted(set(summary.inputbuf_reads)):
                lines.append(f"  - `InputBuf[0x{offset:x}]`")
            lines.append("")

        if summary.calls:
            lines.append(f"- **Direct Calls:** {len(summary.calls)} functions")
            lines.append("")

        if summary.vcalls:
            lines.append(f"- **Vtable Calls:** {len(summary.vcalls)} virtual dispatches")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Call graph
    if results['call_graph']:
        lines.append("## Call Graph Sample")
        lines.append("")
        lines.append("| Caller | Target | Args |")
        lines.append("|--------|--------|------|")

        for edge in results['call_graph'][:20]:  # First 20 edges
            lines.append(f"| {edge['caller']} | {edge['target']} | {edge['args_symbolic'][:50]} |")

        if len(results['call_graph']) > 20:
            lines.append(f"| ... | ... | *{len(results['call_graph']) - 20} more edges* |")

        lines.append("")
        lines.append("---")
        lines.append("")

    # Protocol surface summary
    lines.append("## Protocol Surface Summary")
    lines.append("")

    # Count I/O operations
    io_funcs = [name for name, data in results['functions'].items()
                if data['classification']['type'] == 'IO']
    control_funcs = [name for name, data in results['functions'].items()
                     if data['classification']['type'] == 'CONTROL']
    config_funcs = [name for name, data in results['functions'].items()
                    if data['classification']['type'] == 'CONFIG']

    lines.append(f"- **I/O Operations:** {len(io_funcs)} functions")
    for f in io_funcs:
        lines.append(f"  - {f}")
    lines.append("")

    lines.append(f"- **Control Operations:** {len(control_funcs)} functions")
    for f in control_funcs:
        lines.append(f"  - {f}")
    lines.append("")

    lines.append(f"- **Configuration Operations:** {len(config_funcs)} functions")
    for f in config_funcs:
        lines.append(f"  - {f}")
    lines.append("")

    # Attack surface
    lines.append("## Attack Surface")
    lines.append("")
    lines.append("### High-Risk Functions")
    lines.append("")

    # Functions with complex call graphs
    complex_funcs = [(name, data) for name, data in results['functions'].items()
                     if data['classification']['complexity'] == 'COMPLEX']

    if complex_funcs:
        lines.append("**Complex Call Graphs (>5 calls):**")
        for name, data in complex_funcs:
            summary = data['summary']
            lines.append(f"- **{name}**: {len(summary.calls)} calls, "
                        f"{len(summary.arg_field_writes)} arg writes")
        lines.append("")

    # Functions with protocol buffer access
    inputbuf_funcs = [(name, data) for name, data in results['functions'].items()
                      if data['summary'].inputbuf_reads]

    if inputbuf_funcs:
        lines.append("**Protocol Buffer Access:**")
        for name, data in inputbuf_funcs:
            summary = data['summary']
            lines.append(f"- **{name}**: {len(summary.inputbuf_reads)} buffer reads")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("**Analysis Complete**")
    lines.append("")
    lines.append(f"Generated by arm_symbolic.py + analyze_all_jni.py")
    lines.append("")

    # Write report
    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))

    print(f"\n✓ Report written to {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_all_jni.py <libhijoyptt.so>")
        sys.exit(1)

    lib_path = Path(sys.argv[1])
    output_path = lib_path.parent.parent.parent / "JNI-SURFACE-ANALYSIS.md"

    # Analyze all functions
    results = analyze_all_functions(lib_path)

    # Generate report
    generate_report(results, output_path)

    # Summary stats
    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print(f"Functions analyzed: {len(results['functions'])}")
    print(f"Call graph edges: {len(results['call_graph'])}")

    # Breakdown by type
    types = {}
    for name, data in results['functions'].items():
        type_ = data['classification']['type']
        types[type_] = types.get(type_, 0) + 1

    print(f"\nFunction breakdown:")
    for type_, count in sorted(types.items()):
        print(f"  {type_:12s}: {count}")


if __name__ == '__main__':
    main()
