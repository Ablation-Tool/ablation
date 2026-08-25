"""
anyconnect_re — AnyConnect / macOS NE Framework RE module

Mach-O RE engine for Apple NetworkExtension.framework and AnyConnect system extensions.
Integrates tools/macos_re.py (LIEF + capstone).

Primary targets:
  NetworkExtension (Catalina 10.15.7 build 1095.140.2) — 4.1MB, 15,735 symbols
  com.cisco.anyconnect.macos.acsockext — Cisco NE extension (requires extraction)
  kextd (kext_tools-623.120.1) — kext approval chain

NE Trust Architecture (from sandbox profiles + binary RE):
  nesessionmanager ──XPC──► neagent (com.apple.neagent)
                   ──XPC──► nehelper (com.apple.nehelper)
                   ──fork──► pppd [no-sandbox] (L2TP/IPsec + RSA SecurID via /var/ace)
                   reads:  /Library/Preferences/com.apple.networkextension.*.plist
  neagent ──XPC──► acsockext [pluginkit.pkd loads, DR-gated by NE binary]
  NE binary ── requestSocket: DR gate: _SecRequirementCreateWithString → _SecCodeCheckValidity
               DR @ 0x1f8b00: "identifier com.cisco.anyconnect.macosext.networkextension ... DE8Y96K9QP"
  kextd ── validates acsock.kext via MDM AllowedKernelExtensions policy (Team ID DE8Y96K9QP)
           NOT by hardcoded DR; trust source = /Library/SystemExtensions/

  RSA SecurID path: nesessionmanager can write /var/ace and /var/db/RSASecurID_DHParams
  (these are LINA auth method fields that live on the macOS side, pppd-inherited)

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
# IMP addresses from ObjC classlist parse (NOT LIEF symbol_dump — those return methname strings).
# sym_filter addresses in range 0x24xxxx are __TEXT,__objc_methname strings, NOT code.
# Verified: functions in range 0x0xxxx–0x1exxxx are in __TEXT,__text (correct).
NE_1095_140_2_METHODS = {
    # ── Entitlement + socket grant gate ─────────────────────────────────────────
    # CVE-2019-8805 (10.15.0): entitlement verification bypass here; patched 10.15.1
    'shouldAllowUnentitledExtension:':                              0x107dc5,
    # Raw socket grant — where Apple hands Cisco the CSTP/DTLS socket
    # Gate chain: _SecRequirementCreateWithString (lazy-init @ 0x3e5b6) ->
    #   0x18a2f4: _SecCodeCopyGuestWithAttributes -> _SecCodeCheckValidity(callerCode, flags, DR)
    #   DR = "identifier com.cisco.anyconnect.macos.acsockext and cert leaf[OU]=DE8Y96K9QP"
    #   Bypass: hook _SecCodeCheckValidity GOT (0x262008) → return 0 OR null DR ptr in lazy-init
    #   NOTE: call @ 0x3e2ce (esi=2) is _os_log_type_enabled(DEBUG) — NOT a security gate
    'requestSocket:interface:local:remote:completionHandler:':      0x3e26c,
    'extensionHasACRequirement':                                    0x3e982,
    '_ne_code_sig_gate':                                            0x18a2f4,

    # ── NEConfiguration plugin type dispatch ─────────────────────────────────────
    # Type dispatch: retains payload/pluginType/payloadType, then isKindOfClass: branches
    # to IKEv2 | L2TP | CiscoNExt handler. Block invoke at 0x33b91 does actual migration work.
    # NOTE: class is NEConfiguration (not NEConfigurationManager); IMP from classlist parse
    'NEConfiguration.configurePluginWithPayload:pluginType:payloadType:': 0x11299,
    # kext→sysext migration: captures (self, upgradeInfo, queue, handler) into a dispatch_block
    # block invoke at 0x33b91; race window between isKindOfClass: check and block dispatch
    'NEConfigurationManager.upgradeLegacyPluginConfigurationsWithUpgradeInfo:completionQueue:handler:': 0x33a8c,
    # Keychain ACL insertion — TOCTOU race: isKindOfClass @ 0x352e3 vs SecACL write @ 0x35488 (~250 insns)
    'addAppToKeychainACLsForConfiguration:':                        0x3528a,

    # ── NEIKEv2Session Phase 1 ───────────────────────────────────────────────────
    'NEIKEv2Session.initiateConnect':                               0xa2c42,

    # ── NEIKEv2Session(Exchange) Phase 2 handlers ────────────────────────────────
    'NEIKEv2Session.initiateDeleteChildSPI:remoteSPI:':             0xa006e,
    'NEIKEv2Session.receiveDeleteChildSPI:remoteSPI:packet:':       0xa0336,
    'NEIKEv2Session.handleEAPIKESA:childSA:authPacket:handler:':    0xa26ee,
    'NEIKEv2Session.setupReceivedChildWithHandler:':                0xa4809,
    'NEIKEv2Session.initiateNewChildSA:':                           0xa64a4,
    'NEIKEv2Session.receiveNewChildSA:packet:':                     0xa6d21,
    'NEIKEv2Session.initiateRekeyChildSA:':                         0xa775f,
    'NEIKEv2Session.receiveRekeyChildSA:packet:':                   0xa85a6,
    'NEIKEv2Session.initiateRekeyIKESA':                            0xa9463,
    'NEIKEv2Session.receiveRekeyIKESA:':                            0xa9cf6,
    'NEIKEv2Session.receiveDeleteChildSA:packet:':                  0xac247,
    'NEIKEv2Session.initiateDeleteChildSA:':                        0xac557,
    # ChildSA install / migrate / uninstall
    'NEIKEv2Session.installChildSA:':                               0xee682,
    'NEIKEv2Session.migrateChildSA:':                               0xefca4,
    'NEIKEv2Session.migrateAllChildSAs':                            0xf0bcf,
    'NEIKEv2Session.copySAsToDeleteAndInstallRekeyedChildSA:':      0xf6d4b,
    'NEIKEv2Session.uninstallChildSA:':                             0xf7161,
    'NEIKEv2Session.uninstallAllChildSAs':                          0xf7395,
    'NEIKEv2Session.reportTrafficSelectorsForChildSA:':             0xf76c6,
    'NEIKEv2Session.resetChild:':                                   0xf7d08,

    # ── NEIKEv2IKESA(Crypto) — PRF+ key derivation (RFC 5996 §2.14) ──────────────
    # SKEYSEED = prf(Ni|Nr, g^ir)  [initial]
    # SKEYSEED_rekey = prf(SK_d(old), g^ir(new) | Ni | Nr)
    # {SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr} = prf+(SKEYSEED, Ni|Nr|SPIi|SPIr)
    'NEIKEv2IKESA(Crypto).calculateSKEYSEEDDerivatives':           0x95706,
    'NEIKEv2IKESA(Crypto).calculateSKEYSEEDForRekey:':             0x950a4,
    'NEIKEv2IKESA(Crypto).generateLocalDHValues':                   0x9498d,
    'NEIKEv2IKESA(Crypto).generateLocalNonce':                      0x94bcc,
    'NEIKEv2IKESA(Crypto).fetchLocalCertificateIdentity':           0x94c8e,
    'NEIKEv2IKESA(Crypto).generateLocalValues':                     0x966db,
    'NEIKEv2IKESA(Crypto).generateAllValuesForRekey:':              0x9672c,
    'NEIKEv2IKESA(Crypto).createAuthenticationDataForSharedSecret:octets:': 0x98509,
    'NEIKEv2IKESA(Crypto).createInitiatorSignedOctets':             0x98987,
    'NEIKEv2IKESA(Crypto).createResponderSignedOctets':             0x98e85,
    'NEIKEv2IKESA(Crypto).createInitiatorAuthenticationData':       0x9b090,
    'NEIKEv2IKESA(Crypto).createResponderAuthenticationData':       0x9b303,
    'NEIKEv2IKESA(Crypto).checkNonCertAuthData:':                   0x9b576,
    'NEIKEv2IKESA(Crypto).createInitiatorEAPAuthenticationData':    0x9bc40,
    'NEIKEv2IKESA(Crypto).createResponderEAPAuthenticationData':    0x9be57,

    # ── NEIKEv2Crypto class methods ──────────────────────────────────────────────
    # PRF+ primitive (the load-bearing call inside calculateSKEYSEEDDerivatives)
    'NEIKEv2Crypto.createPRFPlusFromData:key:prfAlgorithm:outputLength:': 0x8e500,
    'NEIKEv2Crypto.createHMACFromData:key:prfAlgorithm:':           0x8e284,
    'NEIKEv2Crypto.createHMACFromData:key:integrityAlgorithm:':     0x8e008,
    'NEIKEv2Crypto.createRandomWithSize:':                          0x8de32,
    'NEIKEv2Crypto.encryptGCMWithContext:aad:aadLen:plaintext:len:output:outputLen:': 0x92e29,
    'NEIKEv2Crypto.decryptGCMWithKey:keyLen:iv:ivLen:aad:aadLen:encryptedText:len:output:outputLen:': 0x92ff4,
    'NEIKEv2Crypto.encryptChaChaPolyWithContext:key:iv:aad:aadLen:plaintext:len:output:outputLen:': 0x932de,
    'NEIKEv2Crypto.decryptChaChaPolyWithKey:keyLen:iv:ivLen:aad:aadLen:encryptedText:len:output:outputLen:': 0x9362a,
    'NEIKEv2Crypto.createEncryptedData:algorithm:key:iv:encryptionContext:aad:padDataToKeyLength:': 0x9376f,
    'NEIKEv2Crypto.createDecryptedData:algorithm:key:iv:aad:padDataToKeyLength:':    0x9401d,
    'NEIKEv2Crypto.prototypeDHKeysForGroup:':                       0x8ff04,
    'NEIKEv2Crypto.copyDHKeys:':                                    0x90805,
    'NEIKEv2Crypto.createNATDetectionHashForInitiatorSPI:responderSPI:address:': 0x8f9bb,
    'NEIKEv2Crypto.copyAuthenticationProtocolForAuthMethod:authData:': 0x8f1b8,

    # ── NEIKEv2ChildSA Phase 2 key material (RFC 5996 §2.17) ───────────────────
    # LINA and NE both derive these from the same PRF+ keystream
    'NEIKEv2ChildSA.initiatorSendEncryptionKey':                    0x75bab,
    'NEIKEv2ChildSA.responderSendEncryptionKey':                    0x75c59,
    'NEIKEv2ChildSA.initiatorSendIntegrityKey':                     0x75d07,
    'NEIKEv2ChildSA.responderSendIntegrityKey':                     0x75db5,
    'NEIKEv2ChildSA.shouldGenerateNewDHKeys':                       0x757ed,
    'NEIKEv2ChildSA.initiatorTrafficSelectors':                     0x75fc7,
    'NEIKEv2ChildSA.responderTrafficSelectors':                     0x76075,

    # ── Cisco private IKEv2 notify — non-RFC, LINA-only extension ───────────────
    'NEIKEv2PrivateNotify.initWithNotifyStatus:notifyData:':        0x77274,
    'NEIKEv2PrivateNotify.notifyStatus':                            0x77620,

    # ── Vendor ID — AnyConnect identifies itself to LINA ────────────────────────
    'NEIKEv2VendorIDPayload.parsePayloadData':                      0xc9d85,
    'NEIKEv2VendorIDPayload.generatePayloadData':                   0xc9bda,

    # ── EAP over IKEv2 — 9 module dispatch paths ────────────────────────────────
    # selectModuleForPayload has 9 cold paths = EAP-GTC/MSCHAPV2/TLS/TTLS/PEAP/LEAP/FAST/MD5/Identity
    'NEIKEv2EAP.selectModuleForPayload:ikeSA:':                     0x9da3c,
    'NEIKEv2EAP.createPayloadResponseForRequest:ikeSA:...':         0x9ebd9,
    # Post-EAP MSK — RFC 5106 AUTH derivation key (LINA and NE both compute this)
    'NEIKEv2EAP.sessionKey':                                        0x9f303,

    # ── App version attribute ────────────────────────────────────────────────────
    'NEIKEv2AppVersionAttribute.attributeType':                     0x8373d,
    'NEIKEv2AppVersionAttribute.attributeName':                     0x83776,

    # ── Phase 1 IKESA key storage (RFC 5996) ────────────────────────────────────
    'NEIKEv2IKESA.sKeySeed':                                        0xb9946,
    'NEIKEv2IKESA.setSKeySeed:':                                    0xb995a,
    'NEIKEv2IKESA.skD':                                             0xb9969,
    'NEIKEv2IKESA.sharedSecret':                                    0xb8969,
    # IKEv2-PSK from system keychain — static cred for PSK-mode LINA auth
    'NEIKEv2IKESA.fetchedSharedSecret':                             0xb9e3c,
    'NEIKEv2IKESA.digitalSignatureLocalPrivateKey':                 0xb9aa4,
    'NEIKEv2IKESA.digitalSignatureRemotePublicKey':                 0xb9aea,
    'NEIKEv2IKESA.encryptionKey':                                   0xb9207,
    'NEIKEv2IKESA.decryptionKey':                                   0xb9250,
    'NEIKEv2IKESA.localIntegrityKey':                               0xb9172,
    'NEIKEv2IKESA.remoteIntegrityKey':                              0xb91bb,
    'NEIKEv2IKESA.encryptCryptoCtx':                                0xb9a5e,
}

# XPC / Mach bootstrap service names hardcoded in NE binary
NE_XPC_SERVICES = [
    'com.apple.networkextension.ikev2.listener',      # IKEv2 listener bootstrap name (key Mach service)
    'com.apple.networkextension.packet-tunnel',
    'com.apple.networkextension.app-proxy',
    'com.apple.networkextension.filter-control',
    'com.apple.networkextension.filter-data',
    'com.apple.networkextension.filter-packet',
    'com.apple.networkextension.dns-proxy',
    'com.apple.networkextension.statuschanged',
    'com.apple.networkextension.app-configuration-changed',
    'com.apple.vpn.managed',
    'com.apple.vpn.managed.alwayson',
    'com.apple.vpn.managed.applayer',
]

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
        """Disassemble upgradeLegacyPluginConfigurationsWithUpgradeInfo: — kext→sysext race window.
        Block invoke at 0x33b91 does the actual migration; dispatch_async race after isKindOfClass:.
        """
        return self.disasm('NEConfigurationManager.upgradeLegacyPluginConfigurationsWithUpgradeInfo:completionQueue:handler:')

    def xpc_services(self):
        """Extract all XPC/Mach service names from the binary."""
        return xpc_service_map(self.path)

    def run_all(self):
        return {
            'lina_hunt': self.hunt_lina(),
            'cisco_artifacts': self.cisco_artifacts(),
            'protocol_overlap': self.protocol_overlap(),
            'keychain_surface': self.keychain_surface(),
            'xpc_services': self.xpc_services(),
            'sandbox_surface': sandbox_surface(),
        }


def xpc_service_map(binary_path):
    """
    Extract XPC / Mach service names from the NE binary.
    These are the IPC endpoints in the nesessionmanager→neagent→acsockext chain.
    Known from sandbox profiles:
      neagent registers: com.apple.ist.ds.appleconnect2.service.neagent
      nesessionmanager looks up: com.apple.neagent, com.apple.nehelper, com.apple.sysextd
    """
    raw = Path(binary_path).read_bytes()
    import re as _re
    pat = _re.compile(rb'com\.(apple|cisco)\.[a-z][a-z0-9._-]{5,60}')
    hits = {}
    for m in pat.finditer(raw):
        try:
            s = m.group().decode('ascii')
            hits.setdefault(s, []).append(hex(m.start()))
        except Exception:
            pass
    return hits


def sandbox_surface():
    """
    Return the macOS NE sandbox architecture derived from nesessionmanager.sb + neagent.sb.
    These define the trust boundary surfaces between processes.
    """
    return {
        'neagent_registers': ['com.apple.ist.ds.appleconnect2.service.neagent'],
        'nesessionmanager_lookups': [
            'com.apple.neagent',
            'com.apple.neagent.lsproxy',
            'com.apple.nehelper',
            'com.apple.pluginkit.pkd',   # loads acsockext
            'com.apple.sysextd',         # manages system extension lifecycle
            'com.apple.securityd.xpc',
            'com.apple.SecurityServer',  # keychain access
        ],
        'nesessionmanager_file_writes': [
            '/Library/Preferences/com.apple.networkextension.*.plist',
            '/Library/Preferences/SystemConfiguration/VPN-*.plist',
            '/private/var/run/racoon',   # IKEv1 racoon socket
            '/var/ace',                  # RSA SecurID ACE directory
            '/var/db/RSASecurID_DHParams',  # RSA SecurID DH params
        ],
        'nesessionmanager_spawns': [
            '/usr/sbin/pppd [no-sandbox]',  # L2TP/IPsec; inherits RSA SecurID paths
        ],
        'authorization_rights': ['system.keychain.modify'],
        'kextd_trust_model': 'MDM AllowedKernelExtensions (Team ID DE8Y96K9QP) — NOT hardcoded DR',
    }


def objc_imp_scan(binary_path, target_methods):
    """
    Parse ObjC classlist to extract real IMP (implementation) addresses for named methods.
    LIEF symbol_dump() returns selector string addresses (in __TEXT,__objc_methname), NOT IMPs.
    This function navigates objc_class_t → class_ro_t → method_list_t to get actual code addresses.

    Args:
        binary_path: path to Mach-O binary
        target_methods: set of selector strings to find
    Returns:
        dict: {selector: {'imp': hex(addr), 'class': class_name}}
    """
    try:
        import lief as _lief
        import struct
    except ImportError:
        return {'error': 'pip install lief'}

    binary = _lief.parse(str(binary_path))
    raw = Path(binary_path).read_bytes()

    def va_to_off(va):
        for seg in binary.segments:
            if seg.virtual_address <= va < seg.virtual_address + seg.virtual_size:
                return seg.file_offset + (va - seg.virtual_address)
        return -1

    def get_sec(seg, sect):
        for s in binary.sections:
            if s.segment_name.strip('\x00') == seg and s.name.strip('\x00') == sect:
                return bytes(s.content), s.virtual_address
        return b'', 0

    def rd_ptr(off):
        if off + 8 > len(raw):
            return 0
        return struct.unpack_from('<Q', raw, off)[0]

    def rd_u32(off):
        if off + 4 > len(raw):
            return 0
        return struct.unpack_from('<I', raw, off)[0]

    def cstr(off):
        if off < 0 or off >= len(raw):
            return ''
        end = off
        while end < len(raw) and raw[end]:
            end += 1
        return raw[off:end].decode('ascii', 'replace')

    methname_raw, methname_va = get_sec('__TEXT', '__objc_methname')

    def resolve_sel(ptr):
        if methname_va and methname_va <= ptr < methname_va + len(methname_raw):
            return cstr(ptr - methname_va + (va_to_off(methname_va) or 0))
        foff = va_to_off(ptr)
        return cstr(foff) if foff >= 0 else ''

    classlist_raw, _ = get_sec('__DATA', '__objc_classlist')
    if not classlist_raw:
        classlist_raw, _ = get_sec('__DATA_CONST', '__objc_classlist')

    found = {}
    target = set(target_methods)
    for i in range(0, len(classlist_raw) - 7, 8):
        class_ptr = rd_ptr(i) & ~0x7
        if not class_ptr:
            continue
        cf = va_to_off(class_ptr)
        if cf < 0 or cf + 40 > len(raw):
            continue
        data_ptr = rd_ptr(cf + 32) & ~0x7
        df = va_to_off(data_ptr)
        if df < 0 or df + 40 > len(raw):
            continue
        name_foff = va_to_off(rd_ptr(df + 24))
        class_name = cstr(name_foff) if name_foff >= 0 else ''
        methods_ptr = rd_ptr(df + 32)
        if not methods_ptr:
            continue
        mf = va_to_off(methods_ptr)
        if mf < 0 or mf + 8 > len(raw):
            continue
        entsize = rd_u32(mf) & 0xfffc
        count = rd_u32(mf + 4)
        if entsize != 24 or count > 5000:
            continue
        for j in range(count):
            mo = mf + 8 + j * 24
            if mo + 24 > len(raw):
                break
            sel_ptr = rd_ptr(mo)
            imp = rd_ptr(mo + 16)
            if not sel_ptr or not imp:
                continue
            sel_name = resolve_sel(sel_ptr)
            if sel_name in target:
                found[sel_name] = {'imp': hex(imp), 'class': class_name}
                if len(found) == len(target):
                    return found
    return found


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
    Real gate chain @ 0x3e5b6: _SecRequirementCreateWithString (lazy-init, DR = Cisco Team ID)
      -> 0x18a2f4 (_ne_code_sig_gate): _SecCodeCopyGuestWithAttributes -> _SecCodeCheckValidity
    NOTE: call @ 0x3e2ce (esi=2) is _os_log_type_enabled(DEBUG) — NOT a security gate.
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
    ap.add_argument('--xpc', action='store_true', help='XPC service name extraction')
    ap.add_argument('--sandbox', action='store_true', help='Print sandbox architecture map')
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
    elif args.xpc:
        print(json.dumps(a.xpc_services(), indent=2))
    elif args.sandbox:
        print(json.dumps(sandbox_surface(), indent=2))
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
