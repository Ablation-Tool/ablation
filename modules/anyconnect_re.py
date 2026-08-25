"""
anyconnect_re — AnyConnect / macOS NE Framework RE module

Mach-O RE engine for Apple NetworkExtension.framework and AnyConnect system extensions.
Integrates tools/macos_re.py (LIEF + capstone).

Primary targets:
  NetworkExtension (Catalina 10.15.7 build 1095.140.2) — 4.1MB, 15,735 symbols
  com.cisco.anyconnect.macos.acsockext — Cisco NE extension (requires extraction)
  kextd (kext_tools-623.120.1) — kext approval chain

Usage:
    from modules.anyconnect_re import AnyConnectNEAnalyzer
    a = AnyConnectNEAnalyzer('/path/to/NetworkExtension')
    a.hunt_lina()
    a.disasm('shouldAllowUnentitledExtension:')
    a.cisco_artifacts()
    a.keychain_surface()

Standalone:
    python3 modules/anyconnect_re.py /path/to/NE --all
    python3 modules/anyconnect_re.py /path/to/NE --disasm shouldAllowUnentitledExtension:
    python3 modules/anyconnect_re.py /path/to/NE --sym (cisco|ikev2|packet|session)
"""

import json
import re
import subprocess
import sys
from pathlib import Path

MACOS_RE = Path(__file__).parent.parent / 'tools' / 'macos_re.py'

# Method addresses in NetworkExtension 1095.140.2 (Catalina 10.15.7)
# Extracted via LIEF symbol dump — NOT stripped
NE_1095_140_2_METHODS = {
    # Entitlement gate — validates Cisco sysext before loading
    'shouldAllowUnentitledExtension:':                              0x107dc5,
    # Raw socket grant — where Apple hands Cisco the CSTP/DTLS socket
    # Gate chain: _SecRequirementCreateWithString (lazy-init @ 0x3e5b6) ->
    #   0x18a2f4: _SecCodeCopyGuestWithAttributes -> _SecCodeCheckValidity(callerCode, flags, DR)
    #   DR = "identifier com.cisco.anyconnect.macos.acsockext and cert leaf[OU]=DE8Y96K9QP"
    #   Bypass: null DR ptr in lazy-init block (skips check) OR hook SecCodeCheckValidity -> 0
    'requestSocket:interface:local:remote:completionHandler:':      0x3e26c,
    # Always-on VPN requirement check
    'extensionHasACRequirement':                                    0x3e982,
    # Central Cisco plugin dispatch (IKEv2 | L2TP | Cisco NExt)
    'configurePluginWithPayload:pluginType:payloadType:':           0x244613,
    # Explicit kext→sysext migration (acsock.kext → acsockext)
    'upgradeLegacyPluginConfigurationsWithUpgradeInfo:':            0x246198,
    # Keychain ACL insertion — race window for cred read access
    'addAppToKeychainACLsForConfiguration:':                        0x3528a,
    # IKEv2 session initiator
    'NEIKEv2Session.initiateConnect':                               0xa2c42,
    # IKEv2 child SA installation
    'NEIKEv2Session.installChildSA:':                               0xee682,
    # EAP IKEv2 SA handler
    'NEIKEv2Session.handleEAPIKESA:...':                            0xa26ee,
    # Phase 2 ChildSA key material — exact fields LINA generates on ASA side (RFC 5996)
    'NEIKEv2ChildSA.initiatorSendEncryptionKey':                    0x75bab,
    'NEIKEv2ChildSA.responderSendEncryptionKey':                    0x75c59,
    'NEIKEv2ChildSA.initiatorSendIntegrityKey':                     0x75d07,
    'NEIKEv2ChildSA.responderSendIntegrityKey':                     0x75db5,
    'NEIKEv2ChildSA.shouldGenerateNewDHKeys':                       0x757ed,
    'NEIKEv2ChildSA.initiatorTrafficSelectors':                     0x75fc7,
    'NEIKEv2ChildSA.responderTrafficSelectors':                     0x76075,
    # Cisco private IKEv2 notify — non-RFC, LINA-only extension
    'NEIKEv2PrivateNotify.initWithNotifyStatus:notifyData:':        0x77274,
    'NEIKEv2PrivateNotify.notifyStatus':                            0x77620,
    # Vendor ID — AnyConnect identifies itself to LINA
    'NEIKEv2VendorIDPayload.parsePayloadData':                      0xc9d85,
    'NEIKEv2VendorIDPayload.generatePayloadData':                   0xc9bda,
    # EAP over IKEv2 — module selection (EAP-GTC for SecurID, EAP-MSCHAPV2 for password)
    'NEIKEv2EAP.selectModuleForPayload:ikeSA:':                     0x9da3c,
    'NEIKEv2EAP.createPayloadResponseForRequest:ikeSA:...':         0x9ebd9,
    # Post-EAP MSK — RFC 5106 AUTH derivation key (LINA and NE both compute this)
    'NEIKEv2EAP.sessionKey':                                        0x9f303,
    # Config payload — where LINA assigns IP/DNS to AnyConnect client
    'NEIKEv2AppVersionAttribute.attributeType':                     0x8373d,
    'NEIKEv2AppVersionAttribute.attributeName':                     0x83776,
    # Internal NE code-signature gate — called from requestSocket: and other methods
    # 0x18a2f4: _SecCodeCopyGuestWithAttributes -> _SecCodeCheckValidity -> _SecCopyErrorMessageString
    '_ne_code_sig_gate':                                            0x18a2f4,
    # Always-on VPN gate — REAL check is at 0x3e9a4 preference read
    # NOTE: call at 0x3e9c5 (esi=0x10) is os_log_type_enabled(OS_LOG_TYPE_ERROR) — NOT a security gate
    # Actual gate: _SecRequirementCreateWithString at 0x3e9a4 -> _SecCodeCheckValidity
    'extensionHasACRequirement':                                    0x3e982,
    # Keychain ACL race — TOCTOU between isKindOfClass: @ 0x352e3 and SecACL write @ 0x35488
    'addAppToKeychainACLsForConfiguration:':                        0x3528a,
    # Phase 1 IKESA key derivation — RFC 5996 SKEYSEED = prf(Ni|Nr, g^ir)
    'NEIKEv2IKESA.sKeySeed':                                        0xb9946,
    'NEIKEv2IKESA.setSKeySeed:':                                    0xb995a,
    # DH shared secret before SKEYSEED derivation (input to prf)
    'NEIKEv2IKESA.sharedSecret':                                    0xb8969,
    # IKEv2-PSK from system keychain — static cred for PSK-mode LINA auth
    'NEIKEv2IKESA.fetchedSharedSecret':                             0xb9e3c,
    # Client private key from keychain (granted via addAppToKeychainACLsForConfiguration:)
    'NEIKEv2IKESA.digitalSignatureLocalPrivateKey':                 0xb9aa4,
    # LINA server public key from its TLS cert in IKE_AUTH
    'NEIKEv2IKESA.digitalSignatureRemotePublicKey':                 0xb9aea,
    # SK_e: IKE SA encryption/decryption keys (derived from SKEYSEED via PRF+)
    'NEIKEv2IKESA.encryptionKey':                                   0xb9207,
    'NEIKEv2IKESA.decryptionKey':                                   0xb9250,
    # SK_a: IKE SA integrity keys
    'NEIKEv2IKESA.localIntegrityKey':                               0xb9172,
    'NEIKEv2IKESA.remoteIntegrityKey':                              0xb91bb,
}

# Full Cisco designated requirement string hardcoded in Apple's NE binary @ 0x1f8b00
# Used by _SecCodeCheckValidity in requestSocket:, extensionHasACRequirement, etc.
# Requires: Cisco bundle ID + Team ID DE8Y96K9QP + Apple-anchored Developer ID Application cert
# Bypass: hook _SecCodeCheckValidity at GOT (0x262008) to return 0, or corrupt DR ptr
NE_CISCO_DR = (
    'anchor apple generic and identifier "com.cisco.anyconnect.macosext.networkextension"'
    ' and (certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */'
    ' or certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */'
    ' and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */'
    ' and certificate leaf[subject.OU] = DE8Y96K9QP)'
)

# Cisco co-design markers in Apple's binary
CISCO_MARKERS = [
    b'DE8Y96K9QP',                                    # Cisco Team ID (Apple hardcoded)
    b'com.cisco.anyconnect.macosext.networkextension', # NE extension bundle ID
    b'com.cisco.kext.acsock',                          # Legacy kext bundle ID
    b'com.cisco.anyconnect.macos.acsockext',           # System extension bundle ID
    b'com.cisco.anyconnect.applevpn.plugin',           # Legacy plugin bundle ID
    b'CiscoIPSec',                                     # cert install log string
]

# LINA signatures (from ASA 9.22.2.32 RE — confirm boundary = zero hits expected in Apple binary)
LINA_SIGS = [
    b'\x9c\x42\xf9\xfd\x11\xa9\xfc\xfc\x26\xb5\xbc\x53\x25\xfd\x51\xc5',  # JWT key
    b'X-DTLS-Master-Secret',
    b'X-CSTP-',
    b'STF\x01',           # CSTP header magic
    b'CiscoSSL',
    b'CStrapMgr',
    b'ac_strap.dat',
    b'decryptHPKEMessage',
    b'Message-Authenticator',
    b'dtls1_get_record',
]

# Protocol overlap patterns — auth methods shared between LINA and Apple NE
PROTOCOL_OVERLAP_PATTERNS = [
    b'XAuthName', b'XAuthPassword', b'XAuthPasswordRef',
    b'securID', b'cryptocard',
    b'MOBIKE', b'DisableMOBIKE',
    b'MODP768', b'MODP1024', b'MODP2048', b'Curve25519',
    b'ChaCha20Poly1305', b'3DES',
    b'RSASecurID_DHParams', b'/var/ace',
    b'IPSecSharedSecret', b'PasswordReference',
]


def _run_tool(binary, *flags, json_out=True):
    cmd = [sys.executable, str(MACOS_RE), str(binary)] + list(flags)
    if json_out:
        cmd.append('--json')
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        return {'error': r.stderr.strip()}
    if json_out:
        return json.loads(r.stdout)
    return r.stdout


class AnyConnectNEAnalyzer:
    """RE engine for AnyConnect NE framework and Apple NetworkExtension binary."""

    def __init__(self, binary_path):
        self.path = Path(binary_path)
        if not self.path.exists():
            raise FileNotFoundError(binary_path)
        self._raw = self.path.read_bytes()
        print(f'[anyconnect_re] loaded {self.path.name} ({len(self._raw):,} bytes)')

    def hunt_lina(self):
        """Search binary for LINA signatures. Expected result: CLEAN (trust boundary = XPC gate)."""
        hits = {}
        for sig in LINA_SIGS:
            off = self._raw.find(sig)
            if off >= 0:
                ctx = self._raw[max(0,off-8):off+len(sig)+24]
                hits[sig.decode('ascii','replace')] = {
                    'offset': hex(off),
                    'context': ctx.hex(),
                }
        verdict = 'HIT' if hits else 'CLEAN'
        result = {'verdict': verdict, 'hits': hits, 'searched': len(LINA_SIGS)}
        print(f'[anyconnect_re] LINA hunt: {verdict} ({len(hits)} hits / {len(LINA_SIGS)} sigs)')
        return result

    def cisco_artifacts(self):
        """Find Cisco co-design markers hardcoded by Apple into the NE binary."""
        hits = {}
        for marker in CISCO_MARKERS:
            off = 0
            locs = []
            while True:
                idx = self._raw.find(marker, off)
                if idx < 0:
                    break
                locs.append(hex(idx))
                off = idx + 1
            if locs:
                hits[marker.decode('ascii','replace')] = locs
        print(f'[anyconnect_re] Cisco artifacts: {len(hits)} markers found')
        return hits

    def protocol_overlap(self):
        """Find LINA auth method strings in Apple binary (XAUTH, SecurID, MOBIKE, etc.)."""
        hits = {}
        for pat in PROTOCOL_OVERLAP_PATTERNS:
            off = self._raw.find(pat)
            if off >= 0:
                ctx = self._raw[off:off+len(pat)+32]
                hits[pat.decode('ascii','replace')] = {
                    'offset': hex(off),
                    'context': ctx.decode('ascii','replace'),
                }
        print(f'[anyconnect_re] Protocol overlap: {len(hits)}/{len(PROTOCOL_OVERLAP_PATTERNS)} patterns found')
        return hits

    def keychain_surface(self):
        """Find keychain credential access patterns (ACL, persistent refs, password store)."""
        patterns = [
            b'addAppToKeychainACLsForConfiguration:',
            b'persistentReference',
            b'copyDataFromPersistentReference:',
            b'Authentication is required, but password is missing',
            b'Adding/Updating keychain item',
            b'Added app paths to ACL',
            b'__NEVPNKeychainDomain',
            b'PasswordReference',
            b'XAuthPassword',
        ]
        hits = {}
        for pat in patterns:
            off = self._raw.find(pat)
            if off >= 0:
                hits[pat.decode('ascii','replace')] = hex(off)
        print(f'[anyconnect_re] Keychain surface: {len(hits)} patterns found')
        return hits

    def disasm(self, method_name, count=80):
        """Disassemble a known NE 1095.140.2 method by name."""
        vaddr = NE_1095_140_2_METHODS.get(method_name)
        if vaddr is None:
            return {'error': f'unknown method: {method_name}. choices: {list(NE_1095_140_2_METHODS)}'}
        result = _run_tool(self.path, '--disasm', f'{vaddr:#x}:{count}')
        return result.get('disasm', result)

    def disasm_va(self, vaddr, count=80):
        """Disassemble at arbitrary virtual address."""
        result = _run_tool(self.path, '--disasm', f'{vaddr:#x}:{count}')
        return result.get('disasm', result)

    def objc_classes(self, filter_re=None):
        """ObjC class dump, optional regex filter."""
        flags = ['--objc']
        if filter_re:
            flags += ['--sym-filter', filter_re]
        return _run_tool(self.path, *flags)

    def sym_grep(self, pattern):
        """Find all defined symbols matching regex pattern."""
        return _run_tool(self.path, '--sym-filter', pattern)

    def full_re(self, out_file=None):
        """Full RE pass: LINA hunt + ObjC + strings + CFStrings."""
        flags = ['--lina', '--objc', '--strings', '--cfstrings']
        if out_file:
            flags += ['--out', str(out_file)]
        return _run_tool(self.path, *flags)

    def entitlement_gate(self):
        """Disassemble shouldAllowUnentitledExtension: — NE extension validation gate."""
        return self.disasm('shouldAllowUnentitledExtension:')

    def socket_grant(self):
        """Disassemble requestSocket: — where Apple grants Cisco a raw CSTP/DTLS socket."""
        return self.disasm('requestSocket:interface:local:remote:completionHandler:')

    def kext_migration(self):
        """Disassemble upgradeLegacyPluginConfigurationsWithUpgradeInfo: — kext→sysext race window."""
        return self.disasm('upgradeLegacyPluginConfigurationsWithUpgradeInfo:')

    def run_all(self):
        return {
            'lina_hunt': self.hunt_lina(),
            'cisco_artifacts': self.cisco_artifacts(),
            'protocol_overlap': self.protocol_overlap(),
            'keychain_surface': self.keychain_surface(),
        }


def ikev2_class_methods(binary_path, class_name):
    """
    Get all instance methods for a specific NEIKEv2 class.
    Example: ikev2_class_methods(ne, 'NEIKEv2Session')
    Returns list of {addr, name} for each -[ClassName *] method.
    """
    result = _run_tool(binary_path, '--sym-filter', f'^-\\[{re.escape(class_name)} ')
    return result.get('sym_filter_results', result)


def ikev2_key_material(binary_path):
    """
    Extract NEIKEv2ChildSA key-material method symbols.
    These are the IKEv2 Phase 2 key fields that must interop with LINA's IKEv2 SA on the ASA.
    Same RFC 5996 structure on both sides: LINA (ASA) <-> Apple NE (client).
    """
    result = _run_tool(binary_path, '--sym-filter',
                       r'NEIKEv2ChildSA.*(encrypt|integrity|nonce|Traffic|rekey|DH)')
    return result.get('sym_filter_results', result)


def ne_extension_gate(binary_path):
    """
    Disassemble shouldAllowUnentitledExtension: switch table.
    Cisco's plugin type is one case; patching to always return Cisco's DR = load bypass.
    Binary: NetworkExtension 1095.140.2 @ 0x107dc5
    """
    result = _run_tool(binary_path, '--disasm', '0x107dc5:120')
    return result.get('disasm', result)


def raw_socket_gate(binary_path):
    """
    Disassemble requestSocket: — where Apple grants Cisco a raw CSTP/DTLS socket.
    Authority check at 0x3e2ce (call 0x1f421e, esi=2):
      test al,al / jne 0x3e362 -> flip jne to jmp = skip auth check.
    Binary: NetworkExtension 1095.140.2 @ 0x3e26c
    """
    result = _run_tool(binary_path, '--disasm', '0x3e26c:120')
    return result.get('disasm', result)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('binary')
    ap.add_argument('--all', action='store_true')
    ap.add_argument('--lina', action='store_true')
    ap.add_argument('--cisco', action='store_true')
    ap.add_argument('--proto', action='store_true')
    ap.add_argument('--keychain', action='store_true')
    ap.add_argument('--disasm', metavar='METHOD', help='Disassemble named method or hex addr')
    ap.add_argument('--sym', metavar='REGEX', help='Symbol grep')
    ap.add_argument('--objc', action='store_true')
    ap.add_argument('--full', action='store_true')
    ap.add_argument('--out', metavar='FILE', help='JSON output file')
    args = ap.parse_args()

    a = AnyConnectNEAnalyzer(args.binary)

    if args.all:
        print(json.dumps(a.run_all(), indent=2))
    elif args.lina:
        print(json.dumps(a.hunt_lina(), indent=2))
    elif args.cisco:
        print(json.dumps(a.cisco_artifacts(), indent=2))
    elif args.proto:
        print(json.dumps(a.protocol_overlap(), indent=2))
    elif args.keychain:
        print(json.dumps(a.keychain_surface(), indent=2))
    elif args.disasm:
        if args.disasm.startswith('0x') or args.disasm[0].isdigit():
            print(json.dumps(a.disasm_va(int(args.disasm, 16)), indent=2))
        else:
            print(json.dumps(a.disasm(args.disasm), indent=2))
    elif args.sym:
        print(json.dumps(a.sym_grep(args.sym), indent=2))
    elif args.objc:
        print(json.dumps(a.objc_classes(), indent=2))
    elif args.full:
        out = args.out
        print(json.dumps(a.full_re(out), indent=2))
    else:
        print(json.dumps(a.run_all(), indent=2))
