"""
macos_mach_o_re — macOS Mach-O binary RE module for ablation.

Wraps tools/macos_re.py (LIEF + capstone engine).
Targets: NetworkExtension.framework, kextd, neagent, nesessionmanager, NE extensions.
Primary target: Catalina 10.15.7 (Build 19H2).

Tool: ~/ablation/tools/macos_re.py
"""

import subprocess
import sys
import json
from pathlib import Path

TOOL = Path(__file__).parent.parent / 'tools' / 'macos_re.py'

# LINA signature set — from ASA 9.22.2.32 RE
LINA_SIGS = [
    '9c42f9fd11a9fcfc26b5bc5325fd51c5',  # JWT key bytes
    'X-DTLS-Master-Secret',
    'X-CSTP-',
    'STF\x01',                           # CSTP header magic
    'CiscoSSL',
    'CStrapMgr',
    'ac_strap.dat',
    'decryptHPKEMessage',
    'Message-Authenticator',
    'dtls1_get_record',
    'ssl3_read_bytes',
]

# Cisco co-design patterns
CISCO_PATTERNS = [
    'DE8Y96K9QP',
    'com.cisco.anyconnect',
    'com.cisco.kext.acsock',
    'com.cisco.anyconnect.macos.acsockext',
]

# Known NE method addresses in NetworkExtension 1095.140.2 (Catalina 10.15.7)
NE_1095_140_2 = {
    'shouldAllowUnentitledExtension:':                              0x107dc5,
    'requestSocket:interface:local:remote:completionHandler:':      0x3e26c,
    'extensionHasACRequirement':                                    0x3e982,
    'configurePluginWithPayload:pluginType:payloadType:':           0x244613,
    'upgradeLegacyPluginConfigurationsWithUpgradeInfo:':            0x246198,
    'addAppToKeychainACLsForConfiguration:':                        0x3528a,
    'NEIKEv2Session.initiateConnect':                               0xa2c42,
    'NEIKEv2Session.installChildSA:':                               0xee682,
}


def lina_hunt(binary_path):
    """Run LINA signature hunt on a Mach-O binary. Returns JSON result."""
    result = subprocess.run(
        [sys.executable, str(TOOL), str(binary_path), '--lina', '--json'],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        return {'error': result.stderr}
    return json.loads(result.stdout)


def objc_dump(binary_path):
    """Dump ObjC class/method list. Returns JSON result."""
    result = subprocess.run(
        [sys.executable, str(TOOL), str(binary_path), '--objc', '--json'],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        return {'error': result.stderr}
    return json.loads(result.stdout)


def disasm(binary_path, vaddr, count=80):
    """Disassemble instructions at vaddr in a Mach-O binary. Returns JSON."""
    result = subprocess.run(
        [sys.executable, str(TOOL), str(binary_path),
         '--disasm', f'{vaddr:#x}:{count}', '--json'],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        return {'error': result.stderr}
    return json.loads(result.stdout)


def full_re(binary_path, out_file=None):
    """Full RE pass: LINA hunt + ObjC + strings + CFStrings. Writes JSON if out_file given."""
    cmd = [sys.executable, str(TOOL), str(binary_path),
           '--lina', '--objc', '--strings', '--cfstrings', '--json']
    if out_file:
        cmd += ['--out', str(out_file)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        return {'error': result.stderr}
    if out_file:
        return {'written': str(out_file)}
    return json.loads(result.stdout)


def sym_grep(binary_path, pattern):
    """Find all defined symbols matching a regex pattern."""
    result = subprocess.run(
        [sys.executable, str(TOOL), str(binary_path),
         '--sym-filter', pattern, '--json'],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        return {'error': result.stderr}
    data = json.loads(result.stdout)
    return data.get('sym_filter_results', [])


def disasm_known(binary_path, method_name):
    """Disassemble a known NE method by name (uses NE_1095_140_2 address table)."""
    vaddr = NE_1095_140_2.get(method_name)
    if vaddr is None:
        return {'error': f'unknown method: {method_name}'}
    return disasm(binary_path, vaddr)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('binary')
    ap.add_argument('--hunt', action='store_true', help='LINA signature hunt')
    ap.add_argument('--objc', action='store_true', help='ObjC dump')
    ap.add_argument('--full', action='store_true', help='Full RE pass')
    ap.add_argument('--disasm', metavar='ADDR', help='Disassemble at hex addr')
    ap.add_argument('--method', metavar='NAME', help='Disassemble named NE method')
    ap.add_argument('--sym', metavar='REGEX', help='Symbol grep')
    args = ap.parse_args()

    if args.hunt:
        print(json.dumps(lina_hunt(args.binary), indent=2))
    elif args.objc:
        print(json.dumps(objc_dump(args.binary), indent=2))
    elif args.full:
        print(json.dumps(full_re(args.binary), indent=2))
    elif args.disasm:
        print(json.dumps(disasm(args.binary, int(args.disasm, 16)), indent=2))
    elif args.method:
        print(json.dumps(disasm_known(args.binary, args.method), indent=2))
    elif args.sym:
        print(json.dumps(sym_grep(args.binary, args.sym), indent=2))
    else:
        print(json.dumps(lina_hunt(args.binary), indent=2))
