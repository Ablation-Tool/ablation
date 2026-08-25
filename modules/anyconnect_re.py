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

    # ── NEIKEv2PacketTunnelProvider — tunnel startup + Cisco auth delegation ──────
    # THE function containing the ONE call to NEIKEv2ProviderAuthenticate: (at 0xd8f53).
    # r12=self (provider), r14=rdx=tunnelOptions (retained into r14 at prologue 0xd87b6).
    # At 0xd8f53: [self NEIKEv2ProviderAuthenticate:tunnelOptions] → BOOL
    # YES → session continues (jne 0xd8f0e), NO → failure path (call 0x1f3dec)
    # This is where Apple calls into Cisco's acsockext during tunnel startup (not rekey/reconnect).
    'NEIKEv2PacketTunnelProvider.startIKEv2TunnelWithOptions:':    0xd878b,

    # ── NEIKEv2 TCP connection accept path (called after handleNewConnection: passes) ──
    # Prologue: r15=self, r12=retain(rdx=connection), r14=session/queue property of self.
    # 6-guard gate chain:
    #   0xa4e70: connection nil → bail 0xa567e
    #   0xa4ed5: r14 property nil → bail 0xa569d
    #   0xa4f73: type/cert check on r12 → debug-log path 0xa5149
    #   0xa4f87: [r12 isConnectionReusableForDestination:r14] (sel@0x224ea1) → NO: 0xa51b0
    #   0xa4fad: [r14 <sel@0x224d46>] → debug-log path 0xa52f0 if NO
    #   0xa4fc7: [r14 <sel@0x224d66>:0] → 0xa534d if NO
    # Factory @ 0xa4fcd: [SharedClass <sel@0x224e5d>:r12(conn):r14] → retained IKEv2Session (rbx/r13)
    # Key dispatch @ 0xa50a8: [self <sel@0x224b25>:session:block] → BOOL
    #   YES = validateSAInit:block: scheduled (queued async) → early exit
    #   NO  = error: [self <logProp>]:3 set, two cleanup calls, → exit
    #
    # TOCTOU — new-conn path @ 0xa51b0 (entered when reuse check returned NO):
    #   r14 = existing-connection state; NO lock held after reuse check at 0xa4f87.
    #   0xa51ba: [r14 <sel@0x221767>] retain → addr struct (FIRST USE of stale r14)
    #   0xa51d3: [rax <sel@0x223bf6>] retain → port (second field)
    #   0xa51ec: [rax <sel@0x222cad>] retain → third field
    #   0xa5205: [rax <sel@0x224344>] retain → fourth field
    #   0xa5230: rol r12w, 8 — port byte-swap (network→host order)
    #   If r14 deallocated between 0xa4f87 (check) and 0xa51ba (use) → UAF: IKE_SA_INIT
    #   parameters built from freed connection object; corrupted proposal sent to peer.
    #   Race window: ~115 insns of unprotected r14 reads before any new-conn factory call.
    'NEIKEv2PacketTunnelProvider.receiveConnection:':              0xa4e00,

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

# NEIKEv2Listener method addresses — the acsockext→NE receive path
# Listener registers on 'com.apple.networkextension.ikev2.listener' (Mach bootstrap)
# handleNewConnection: validates the connecting extension's DR before handing off to session
NE_LISTENER_METHODS = {
    # Connection receive gate chain (6 nil/type checks before session create):
    # 0xc0eb6: nil-check on retained connection → 0xc12d4
    # 0xc0ecd: nil-check on endpoint derived from connection → 0xc12fe
    # 0xc0ef8: nil-check on another derived value → 0xc132b
    # 0xc0f26: [endpoint isKindOfClass: ExpectedClass.class] → 0xc1358 if wrong type
    #   (NOT a DR check — DR validation happens at extension LOAD TIME by pluginkit.pkd)
    # 0xc0f87: nil-check on self.saSession → 0xc1386
    # 0xc0fc1: nil-check on something else → 0xc13c0
    # After gates: calls requestConfigurationForListener:session:... on delegate (nesessionmanager)
    # sessionsBeforeAuth tracks pre-auth sessions; race window = here until auth completes
    'handleNewConnection:':                                           0xc0e85,
    # Calls back to nesessionmanager delegate (configurationDelegate) for VPN config;
    # validateAuthBlock param is the custom auth callback (RSA SecurID / Duo path)
    'requestConfigurationForSession:sessionConfig:childConfig:validateAuthBlock:responseBlock:': 0xc156d,
    'sessionFailedBeforeRequestingConfiguration:':                    0xc1a38,
    # Full init variants: saSession=kernel SA mode, packetDelegate=user-space mode
    'initWithListenerIKEConfig:saSession:kernelSASessionName:listenerUDPPort:listenerInterface:listenerQueue:delegate:delegateQueue:': 0xc1b79,
    'initWithListenerIKEConfig:saSession:kernelSASessionName:packetDelegate:listenerQueue:delegate:delegateQueue:': 0xc294f,
    'receivePacket:':                                                 0xc248d,
    'cancel':                                                         0xc3d1b,
    # Property: tracks pre-auth sessions (TOCTOU race window between here and auth complete)
    'sessionsBeforeAuth':                                             0xc3ead,
}

# Phase 1 IKE auth selref addresses (in __DATA,__objc_selrefs)
# IMPs are in acsockext (Cisco's binary, not NE.framework). NE binary contains the call sites.
# Selref VAs used for call-site tracing: resolve which method is being called at runtime.
NE_PHASE1_SELREFS = {
    # IKE_SA_INIT — proposal and DH validation
    'validateSAInitAsInitiator:':                                     0x2c9cd8,
    'validateSAInitAsResponder:sendInvalidKE:':                       0x2c9e28,
    # IKE_AUTH — standard PKI/PSK auth
    'createIKEAuthForInitiatorIKESA:childSA:':                        0x2c9d28,
    'validateAuthAsInitiator:childSA:':                               0x2c9d40,
    'validateAuthPart1AsResponderCopyErrorForIKESA:':                 0x2c9e40,
    'validateAuthPart2AsResponderCopyErrorForIKESA:childSA:':         0x2c9e50,
    'createIKEAuthResponse:ikeSA:childSA:':                           0x2c9e58,
    # EAP over IKEv2 (RSA SecurID, Duo, LDAP) — RFC 5106 + RFC 5998
    'handleEAPIKESA:childSA:authPacket:handler:':                     0x2c9d08,
    'validateEAPOnlyAuthentication:':                                  0x2c9d30,
    # NEIKEv2ProviderAuthenticate: — THE Cisco delegate callback
    # NE calls this into acsockext for vendor-specific auth (custom IKE payloads, SecurID).
    # ONE call site in NE binary: 0xd8f53, inside startIKEv2TunnelWithOptions: @ 0xd878b.
    # Fires at tunnel START, not rekey. Arg: tunnelOptions dict (rdx → r14 at prologue).
    # BOOL return: YES → tunnel proceeds, NO → error path (0x1f3dec).
    # IMP is in acsockext. Hook objc_msgSend call at 0xd8f60 → bypass Cisco auth entirely.
    'NEIKEv2ProviderAuthenticate:':                                    0x2ca770,
    # Cisco private IKEv2 extensions (non-RFC vendor payloads in IKE_AUTH)
    'customIKEAuthPayloads':                                          0x2c92c0,
    'customIKEAuthVendorPayloads':                                    0x2c92d0,
    'customIKEAuthPrivateNotifies':                                    0x2c9078,
    # Certificate validation chain
    'checkValidityOfDigitalSignature:authenticationProtocol:sessionConfiguration:remoteSignedOctets:': 0x2c9a18,
    'copyTrustedKeyForCertificate:remoteCAArray:policyRef:enableRevocationCheck:strictRevocationCheck:': 0x2c9a00,
    # Config request / validate auth block
    'copyValidateAuthBlock':                                           0x2c9dd8,
    'requestConfigurationForListener:session:sessionConfig:childConfig:validateAuthBlock:responseBlock:': 0x2ca468,
}

# startIKEv2TunnelWithOptions: session setup selrefs (in order of execution before auth)
# Function @ 0xd878b. These are the exact selrefs called on self (r12) before the Cisco
# delegate is invoked at 0xd8f53. All VAs are in __DATA,__objc_selrefs.
#
# Sequence:
#   protocolConfiguration → tunnelKind → setTunnelKind: → setOptions:(r14) →
#   ifIndex → pathStatus (must==1) → protocolConfiguration → serverAddress →
#   [... more setup ...] → NEIKEv2ProviderAuthenticate:(r14) @ 0xd8f53
#
# setOptions: @ 0x2ca758 is the pre-auth intercept: provider STORES tunnelOptions
# before calling Cisco. Hook setOptions: to observe/replace creds before Cisco sees them.
# Bypass: patch 0xd8f60 (call [rip+0x188a32]) → skip Cisco delegate, return rax=1.
NE_TUNNEL_START_SELREFS = {
    'protocolConfiguration':   0x2c7b60,  # get IKEv2 protocol config from provider
    'tunnelKind':              0x2ca6f8,  # get tunnel kind from config
    'setTunnelKind:':          0x2ca750,  # set tunnel kind on provider
    'setOptions:':             0x2ca758,  # store tunnelOptions on provider (pre-auth intercept)
    'ifIndex':                 0x2ca708,  # interface index guard check
    'pathStatus':              0x2ca760,  # network path must be 1 (satisfied) to proceed
    'serverAddress':           0x2c6e58,  # VPN server address from protocol config
    'NEIKEv2ProviderAuthenticate:': 0x2ca770,  # Cisco delegate auth (ONE call @ 0xd8f53)
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

# acsockext 5.1.16.194 (Cisco Secure Client) — com.cisco.anyconnect.macos.acsockext
# Universal binary x86_64+arm64. VAs below are x86_64 slice (PIE base 0x100000000).
# Extracted from: cisco-secure-client-macos-5.1.16.194-core-vpn-webdeploy-k9.dmg
# → XAR vpn_module.pkg/Payload → gzip+cpio → Socket Filter.app/Contents/Library/SystemExtensions/
# Verified: all show push rbp; mov rbp, rsp prologue.
#
# VERSION BOUNDARY NOTE: 5.1.x acsockext is pure AppProxy/Filter/DNS proxy extension.
# NEIKEv2ProviderAuthenticate: is NOT present in 5.1.x binary.
# That interface was AnyConnect 4.x / Catalina-era (NE 1095.140.2).
# In Secure Client 5.x, IKEv2 is handled via Apple's standard NEVPNProtocolIKEv2 or
# a separate Packet Tunnel Provider (not this extension).
# AnyConnect 4.10.x acsockext needed for the Catalina auth delegate implementation.
ACSOCKEXT_5_1_16_194_METHODS = {
    # ── ExtensionWrapper — C++ core bridge (IMultiplexer / InterceptorCB holder) ───────────
    # newFlowStarted loads global C++ obj via [rip+0x7b7e9]; tests for NULL before dispatching.
    # First stack params at [rbp+0x10],[rbp+0x18],[rbp+0x28] = addrs/ports/remoteHostName.
    'ExtensionWrapper.startExtension':                                    0x10005ad06,
    'ExtensionWrapper.stopExtension:':                                    0x10005ad6d,
    'ExtensionWrapper.onFilterStart':                                     0x10005adb4,
    'ExtensionWrapper.newFlowStarted:family:protocol:pid:localAddr:localPort:remoteAddr:remotePort:flowData:remoteHostName:': 0x10005adcc,
    'ExtensionWrapper.flowClosed:family:localAddr:localPort:remoteAddr:remotePort:flowData:': 0x10005aed6,
    'ExtensionWrapper.updateFlowData:family:localAddr:localPort:remoteAddr:remotePort:data:bytes:isSend:': 0x10005ae16,

    # ── AppProxyProvider — NEAppProxyProvider subclass (TCP/UDP flow intercept) ────────────
    'AppProxyProvider.handleNewTCPFlow:flowVerdict:':                     0x10006a52c,
    'AppProxyProvider.handleNewUDPFlow:initialRemoteEndpoint:':           0x100069b52,
    'AppProxyProvider.notifyProxyRulesForConsumer:':                      0x10007503f,
    'AppProxyProvider.updateProxyRulesWithCompletionHandler:':            0x100067820,

    # ── AppProxyTCPConnection — per-connection handler; TOCTOU in reuse check ───────────
    # isConnectionReusableForDestination: (called from NE receiveConnection: @ 0xa4f87)
    # Args: r15=self, rdx=candidate(rbx retained), rcx=r14=existing(retained).
    # TRIPLE-READ race — 3 unprotected property reads with no lock:
    #   Read 1: [self <sel@0x86109>] @ 0x10004b3c0 → active connection object
    #   Compare: [activeConn <sel@0x862c6>:candidate] @ 0x10004b3e2 → BOOL (r13d)
    #   Read 2: [self <sel@0x862da>] @ 0x10004b3ff → second self property (r13)
    #   Read 3: [self <sel@0x86346>] @ 0x10004b43b → counter/ID from self (eax)
    #   ID compare: [r14 →0x10009b132] vs eax @ 0x10004b44b; sete r12b = final result
    # Race: another thread can change active connection (Add/Remove) between Read 1 and Read 3.
    # Reuse returns YES while the underlying connection object has already been deallocated.
    'AppProxyTCPConnection.isConnectionReusableForDestination:withPreferredInterface:': 0x10004b393,

    # ── AppProxyUDPSession — UDP session TOCTOU ──────────────────────────────────────────
    'AppProxyUDPSession.isSessionReusableForDestination:withPreferredInterface:':       0x10007805f,

    # ── DNSProxyProvider — DNS intercept + UDP flow injection ───────────────────────────
    'DNSProxyProvider.startProxyWithOptions:completionHandler:':          0x1000788cb,
    'DNSProxyProvider.handleNewOpenTCPFlow:':                             0x10007ab8f,
    'DNSProxyProvider.handleNewOpenUDPFlow:':                             0x10007a322,
    # TOCTOU DNS injection:
    # 1. Caller: findUDPFlowWithDelayedReponse: @ 0x100082827 → identifies flow F
    # 2. Caller: injectDelayedResponseIntoUDPFlow:flow:... @ 0x100082ad4 called with flow F
    # 3. INSIDE inject: flow rsi is NOT saved; function does addr formatting then at 0x100082dc9
    #    calls [self queue] → dispatch_async(self.queue, block) @ 0x100082e63
    # 4. Block captures {self, packet_data, peer_addr, local_addr_byte} — NOT flow F
    # 5. Block callback @ 0x100082f38 re-fetches flow by address from self's state
    # RACE: if flow F recycled between step 1 and block execution → packet injects into new flow F'
    # Prologue args: rdi→r15=self, edx→r14d=local_addr(uint32), rcx=peer_addr struct*, r8=peer_addr?
    # Injection call: 0x100082e63 = dispatch_async(r12=[self queue], r13=block_struct)
    # Block callback entry: 0x100082f38 (next function); extracts self from block[0x20]
    'DNSProxyProvider.injectDelayedResponseIntoUDPFlow:local_addr:peer_addr:packet:':  0x100082ad4,
    # Block callback: [self findUDPFlowWithDelayedReponse:peer_addr] re-fetches flow (DOUBLE-FETCH)
    # Flow found → [flow delayedResponseCount] dec → [flow setDelayedResponseCount:]
    # → call 0x10005da06 (actual write: esi=2/edx=1/r8=flow_obj/rcx=format)
    'DNSProxyProvider._injectBlock_callback':                             0x100082f38,
    # The write function called from block callback (0x1000830c3 and 0x100083122).
    # Args: rdi=peer_addr_str, esi=2(family), edx=1(proto), rcx=format_arg, r8=flow_obj.
    # Internal: cmp esi,3 → trace-only path. Otherwise:
    #   0x10005db2c: subroutine — actual flow write (ecx=0x801=flags, rdi=flow_obj, rdx=formatted_data)
    #   0x10005dbaa: secondary write (edi=2, esi=r14b=1, rdx=r13=data)
    'DNSProxyProvider._writeUDPDatagramToFlow':                           0x10005da06,
    'DNSProxyProvider.findUDPFlowWithDelayedReponse:':                    0x100082827,
    'DNSProxyProvider.notifyFlowEnd:':                                    0x1000821c7,
    'DNSProxyProvider.checkUdpSessionLeak:pendingSessionCnt:':            0x100079ae1,

    # ── FilterDataProvider (Swift) — NEFilterDataProvider subclass ──────────────────────
    # Swift class: _TtC36com_cisco_anyconnect_macos_acsockext18FilterDataProvider
    # handleNewFlow loads r15 via [rip+0x33a33] then calls r15(rdx) = swift_retain/class lookup.
    '_TtC36com_cisco_anyconnect_macos_acsockext18FilterDataProvider.handleNewFlow:':   0x100094770,
    '_TtC36com_cisco_anyconnect_macos_acsockext18FilterDataProvider.startFilterWithCompletionHandler:': 0x100092d40,
    '_TtC36com_cisco_anyconnect_macos_acsockext18FilterDataProvider.handleReport:':    0x100097190,
}

# C++ RTTI type info VAs in acsockext x86_64 (PIE base 0x100000000)
# These mark the vtable interfaces for the C++ core beneath the ObjC/Swift layer.
# m_pMultiplexer (ObjC ivar) -> IMultiplexer* vtable @ 0x1000c8ba8
# m_pInterceptorCB -> IAppProxyInterceptorCB* @ 0x1000cb218 or IDnsProxyInterceptorCB* @ 0x1000cb3a0
ACSOCKEXT_CPP_TYPEINFO = {
    'IMultiplexer':               0x1000c8ba8,
    'IAppProxyInterceptorCB':     0x1000cb218,
    'IDnsProxyInterceptorCB':     0x1000cb3a0,
    'ISocketPlugin':              0x1000c92a8,
    'ISocketMultiplexorPlugin':   0x1000c8bc8,
    'IIpcServiceCallbacks':       0x1000c8bb8,
    'IZtnaFakeDnsHandler':        0x1000c9090,  # ZTNA fake DNS: injects policy DNS responses
    'IZtnaPluginCallback':        0x1000c8c08,
    'IOpenDnsPluginClient':       0x1000c8be8,  # OpenDNS/Umbrella plugin
    'IScanSafePluginCallback':    0x1000c8c18,  # ScanSafe (web security) callback
    'IDnsCachePluginClient':      0x1000c8bd8,
    'ITcpSocket':                 0x1000ca500,
    'IUdpSocket':                 0x1000c8548,
    'ISocketPacket':              0x1000ca870,
    'ISignalEvent':               0x1000cb608,
}

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

    def listener_rx_path(self, count=120):
        """Disassemble handleNewConnection: @ 0xc0e85 — acsockext→NE trust boundary.
        Gate at 0xc0f26 (test al,al; je 0xc1358) is signingIdentifierAllowed: check.
        Failing: connection rejected. Bypass: spoof signing ID or return true from hook.
        """
        return self.disasm_va(0xc0e85, count=count)

    def phase1_rx(self, count=320):
        """Disassemble receiveConnection: @ 0xa4e00 — Phase 1 TCP connection accept.
        Called after handleNewConnection: @ 0xc0e85 passes DR gate.
        Prologue: r15=self, r12=retain(rdx=connection), r14=session/queue property.
        Two paths after 6-guard chain:
          REUSE path (isReusable YES):
            Factory @ 0xa4fcd: [SharedClass sel:r12:r14] → IKEv2Session
            Dispatch @ 0xa50a8: [self sel@0x224b25:session:block] — validateSAInit:block: scheduled
            YES → exit cleanly; NO → error cleanup
          NEW-CONN path @ 0xa51b0 (isReusable NO):
            Extract r14 addr/port → r12w byte-swapped port via rol r12w,8 @ 0xa5230
            Build IKE_SA_INIT struct @ [rbp-0x40]
            Factory @ 0xa5288: [static sel:packet_struct:2:flags] → new IKEv2Session
            Final dispatch @ 0xa52c7: [self sel@0x2248f2:new_session:nil] → BOOL
        TOCTOU (new-conn path): r14 extracted 0xa51ba–0xa5227 without lock;
        r14 freed between reuse check (0xa4f87) and extract (0xa51ba) → UAF/corrupted
        IKE_SA_INIT proposal (port/addr from stale connection object).
        """
        return self.disasm_va(0xa4e00, count=count)

    def plugin_dispatch(self):
        """Disassemble configurePluginWithPayload: — routes IKEv2|L2TP|CiscoNExt connection types."""
        return self.disasm('NEConfiguration.configurePluginWithPayload:pluginType:payloadType:')

    def skeyseed_derivation(self, count=150):
        """Disassemble calculateSKEYSEEDDerivatives — RFC 5996 §2.14 PRF+ key material derivation.
        Derives {SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr} from SKEYSEED + Ni|Nr|SPIi|SPIr.
        LINA runs the identical computation on the ASA side. @ 0x95706
        """
        return self.disasm_va(0x95706, count=count)

    def prf_plus(self, count=80):
        """Disassemble NEIKEv2Crypto.createPRFPlusFromData: — the PRF+ primitive. @ 0x8e500"""
        return self.disasm_va(0x8e500, count=count)

    def phase2_install(self, count=120):
        """Disassemble NEIKEv2Session.installChildSA: — Phase 2 SA install into kernel. @ 0xee682"""
        return self.disasm('NEIKEv2Session.installChildSA:')

    def start_ikev2_tunnel(self, count=200):
        """Disassemble NEIKEv2PacketTunnelProvider.startIKEv2TunnelWithOptions: @ 0xd878b.
        Contains the ONE call to NEIKEv2ProviderAuthenticate: at 0xd8f53.
        Prologue: r12=self, r14=retain(rdx=tunnelOptions).
        Call site: [self NEIKEv2ProviderAuthenticate:tunnelOptions] → BOOL
        YES path: jne 0xd8f0e (continue session), NO path: call 0x1f3dec (error).
        Auth delegation fires at tunnel START (not rekey). rdx=tunnelOptions is what
        Cisco receives and must validate (group policy, creds, SecurID config, etc.).
        """
        return self.disasm('NEIKEv2PacketTunnelProvider.startIKEv2TunnelWithOptions:')

    def provider_auth_callsite(self, count=30):
        """Disassemble 15 instructions around the NEIKEv2ProviderAuthenticate: call at 0xd8f53."""
        return self.disasm_va(0xd8f3f, count=count)

    def tunnel_start_selrefs(self):
        """Return ordered selref map for startIKEv2TunnelWithOptions: pre-auth setup sequence.
        Sequence: protocolConfiguration → tunnelKind → setTunnelKind: → setOptions:(tunnelOptions)
        → ifIndex (guard) → pathStatus==1 (guard) → serverAddress → NEIKEv2ProviderAuthenticate:
        Bypass target: patch call at 0xd8f60 (objc_msgSend via [rip+0x188a32]) → rax=1, skip Cisco.
        Pre-auth intercept: hook setOptions: @ 0x2ca758 to observe/replace tunnelOptions dict.
        """
        return NE_TUNNEL_START_SELREFS

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


class ACSockExtAnalyzer:
    """
    RE engine for com.cisco.anyconnect.macos.acsockext (Cisco Socket Filter system extension).
    Replaces acsock.kext on macOS 11+. Universal binary (x86_64 + arm64).
    C++ core (IMultiplexer / IAppProxyInterceptorCB / NGC types) beneath ObjC + Swift NE layer.

    Architecture:
      NEFilterDataProvider (Swift: FilterDataProvider) ─┐
      NEAppProxyProvider (ObjC: AppProxyProvider)       ├─► ExtensionWrapper
      NEDNSProxyProvider (ObjC: DNSProxyProvider)       ┘       │
                                                          m_pMultiplexer (IMultiplexer C++)
                                                          m_pInterceptorCB (IAppProxyInterceptorCB C++)
                                                          m_pRuleAggregator (C++ rule engine)
    Attack surface:
      - injectDelayedResponseIntoUDPFlow: — packet injection path
      - isConnectionReusableForDestination: — TOCTOU race (~50 insns check→use window)
      - IZtnaFakeDnsHandler vtable — ZTNA DNS policy enforcement bypass
      - CSerializerReader::get_list<T> — custom deserialization (OOB target on untrusted input)
    """

    def __init__(self, binary_path):
        self.path = Path(binary_path)
        if not self.path.exists():
            raise FileNotFoundError(binary_path)
        raw_fat = self.path.read_bytes()
        self._raw = _extract_x86_64_slice(raw_fat)
        print(f'[acsockext_re] loaded {self.path.name} ({len(raw_fat):,} bytes fat, '
              f'{len(self._raw):,} bytes x86_64 slice)')

    def disasm_va(self, vaddr, count=80):
        """Disassemble at vaddr (full VA, e.g. 0x100082ad4) in x86_64 slice."""
        try:
            import lief as _lief
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            import tempfile, os
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.macho')
            tmp.write(self._raw)
            tmp.flush()
            b = _lief.parse(tmp.name)
            os.unlink(tmp.name)
        except ImportError:
            return {'error': 'pip install lief capstone'}

        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        raw = self._raw
        for seg in b.segments:
            if seg.virtual_address <= vaddr < seg.virtual_address + seg.virtual_size:
                foff = seg.file_offset + (vaddr - seg.virtual_address)
                code = raw[foff:foff + count * 8]
                insns = []
                for ins in cs.disasm(code, vaddr):
                    insns.append({'addr': hex(ins.address), 'mnem': ins.mnemonic, 'op': ins.op_str})
                    if len(insns) >= count:
                        break
                return insns
        return {'error': f'vaddr 0x{vaddr:x} not found in segments'}

    def disasm(self, method_name, count=80):
        """Disassemble a known acsockext 5.1.16.194 method by name."""
        vaddr = ACSOCKEXT_5_1_16_194_METHODS.get(method_name)
        if vaddr is None:
            return {'error': f'unknown method: {method_name}. '
                    f'choices: {list(ACSOCKEXT_5_1_16_194_METHODS)}'}
        return self.disasm_va(vaddr, count=count)

    def inject_path(self, count=160):
        """Disassemble injectDelayedResponseIntoUDPFlow — async DNS injection entry @ 0x100082ad4.
        TOCTOU: passed flow (rsi) is NOT saved to callee-saved register at prologue.
        @ 0x100082dc9: [self queue] → r12 = dispatch_queue
        @ 0x100082e63: dispatch_async(queue, block) — injection dispatched ASYNCHRONOUSLY.
        Block captures {self, packet_data, peer_addr, local_addr_byte} — NOT the flow.
        Block callback @ 0x100082f38 re-fetches flow by addr. If flow recycled between
        findUDPFlowWithDelayedReponse: (@ 0x100082827) and block execution → packet lands
        on wrong (new) flow. Race window = [findFlow result] to [block dispatch execution].
        """
        return self.disasm('DNSProxyProvider.injectDelayedResponseIntoUDPFlow:local_addr:peer_addr:packet:',
                           count=count)

    def inject_block_callback(self, count=120):
        """Disassemble the async block callback for DNS injection @ 0x100082f38.
        Block struct layout: [0x20]=self, [0x28]=packet_data, [0x30]=peer_addr(28B),
        [0x48]=local_addr_byte, [0x4c]=local_addr(28B).
        DOUBLE-FETCH confirmed:
        - 0x100082f5e: [self findUDPFlowWithDelayedReponse:&block[0x30]] — RE-FETCHES flow
        - Flow DISCARDED by outer injectDelayedResponseIntoUDPFlow: (rsi never saved)
        - This is the SECOND fetch; first is in caller before injectDelayed... is called
        Post-fetch: [flow delayedResponseCount] → dec → [flow setDelayedResponseCount:]
        Write chain: 0x1000830c3 calls _writeUDPDatagramToFlow @ 0x10005da06
          → 0x10005db2c (ecx=0x801, rdi=flow_obj, rdx=data): actual NE flow write
          → 0x10005dbaa (edi=2, esi=1, rdx=data): secondary write/cleanup
        """
        return self.disasm_va(0x100082f38, count=count)

    def reuse_toctou(self, count=80):
        """Disassemble isConnectionReusableForDestination — triple-read TOCTOU @ 0x10004b393.
        Called from NE receiveConnection: @ 0xa4f87 (sel@0x224ea1) as connection reuse gate.
        Args: r15=self, rdx=candidate(retained→rbx), rcx=existing(retained→r14).
        Race: 3 unprotected property reads between check and use:
          Read 1 (0x10004b3c0): [self <active_conn_sel>] — gets current active connection
          Compare (0x10004b3e2): [activeConn <match_sel>:candidate] → BOOL
          Read 2 (0x10004b3ff): [self <second_sel>]
          Read 3 (0x10004b43b): [self <counter_sel>] → eax
          ID compare (0x10004b44b): r14_id == eax → sete r12b
        Returns YES while active connection already deallocated (use-after-free candidate).
        """
        return self.disasm('AppProxyTCPConnection.isConnectionReusableForDestination:withPreferredInterface:',
                           count=count)

    def flow_start(self, count=80):
        """Disassemble ExtensionWrapper.newFlowStarted — all flow metadata (pid, addrs, ports) @ 0x10005adcc."""
        return self.disasm('ExtensionWrapper.newFlowStarted:family:protocol:pid:localAddr:localPort:remoteAddr:remotePort:flowData:remoteHostName:',
                           count=count)

    def filter_flow(self, count=80):
        """Disassemble FilterDataProvider.handleNewFlow (Swift) — NE filter intercept @ 0x100094770."""
        return self.disasm(
            '_TtC36com_cisco_anyconnect_macos_acsockext18FilterDataProvider.handleNewFlow:',
            count=count)

    def cpp_typeinfo(self):
        """Return C++ RTTI typeinfo addresses for vtable hooking targets."""
        return ACSOCKEXT_CPP_TYPEINFO

    def imp_scan(self, extra_selectors=None):
        """Scan classlist for IMP addresses of all known attack-surface methods."""
        targets = set(ACSOCKEXT_5_1_16_194_METHODS)
        if extra_selectors:
            targets.update(extra_selectors)
        return objc_imp_scan(self.path, targets)

    def xpc_services(self):
        """Extract XPC/Mach service names from acsockext binary."""
        return xpc_service_map(self.path)


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


def _extract_x86_64_slice(raw):
    """Extract x86_64 slice bytes from a fat (universal) Mach-O binary.
    Returns raw bytes of the thin x86_64 slice, or raw unchanged for thin binaries.
    Fat magic = 0xcafebabe (big-endian). Arch cputype 0x01000007 = x86_64.
    """
    import struct as _struct
    FAT_MAGIC = 0xcafebabe
    if len(raw) < 8:
        return raw
    magic = _struct.unpack_from('>I', raw, 0)[0]
    if magic != FAT_MAGIC:
        return raw
    narch = _struct.unpack_from('>I', raw, 4)[0]
    for i in range(narch):
        off = 8 + i * 20
        cputype = _struct.unpack_from('>i', raw, off)[0]
        file_offset = _struct.unpack_from('>I', raw, off + 8)[0]
        size = _struct.unpack_from('>I', raw, off + 12)[0]
        if cputype & 0x00ffffff == 0x7:  # x86_64
            return raw[file_offset:file_offset + size]
    return raw  # no x86_64 slice found


def objc_imp_scan(binary_path, target_methods):
    """
    Parse ObjC classlist to extract real IMP (implementation) addresses for named methods.
    LIEF symbol_dump() returns selector string addresses (in __TEXT,__objc_methname), NOT IMPs.
    This function navigates objc_class_t → class_ro_t → method_list_t to get actual code addresses.
    Handles fat (universal) binaries by extracting the x86_64 slice first.

    Args:
        binary_path: path to Mach-O binary (thin or fat/universal)
        target_methods: set of selector strings to find
    Returns:
        dict: {selector: {'imp': hex(addr), 'class': class_name}}
    """
    try:
        import lief as _lief
        import struct
        import tempfile, os
    except ImportError:
        return {'error': 'pip install lief'}

    raw_file = Path(binary_path).read_bytes()
    raw = _extract_x86_64_slice(raw_file)

    # If we extracted a slice, write to a temp file so lief.parse() gets a thin binary
    _tmp = None
    if raw is not raw_file:
        _tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.macho')
        _tmp.write(raw)
        _tmp.flush()
        parse_path = _tmp.name
    else:
        parse_path = str(binary_path)

    binary = _lief.parse(parse_path)
    if _tmp:
        os.unlink(_tmp.name)

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
    ap.add_argument('--acsockext', action='store_true', help='Use ACSockExtAnalyzer (fat universal binary)')
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
    ap.add_argument('--cpp-typeinfo', action='store_true', help='C++ RTTI typeinfo addresses (acsockext)')
    ap.add_argument('--out', metavar='FILE', help='JSON output file')
    args = ap.parse_args()

    if args.acsockext:
        a = ACSockExtAnalyzer(args.binary)
        if args.disasm:
            if args.disasm.startswith('0x') or args.disasm[0].isdigit():
                print(json.dumps(a.disasm_va(int(args.disasm, 16)), indent=2))
            else:
                print(json.dumps(a.disasm(args.disasm), indent=2))
        elif args.cpp_typeinfo:
            print(json.dumps(a.cpp_typeinfo(), indent=2))
        elif args.xpc:
            print(json.dumps(a.xpc_services(), indent=2))
        elif args.all:
            print(json.dumps({'methods': ACSOCKEXT_5_1_16_194_METHODS,
                              'cpp_typeinfo': ACSOCKEXT_CPP_TYPEINFO,
                              'xpc': a.xpc_services()}, indent=2))
        else:
            print(json.dumps({'methods': list(ACSOCKEXT_5_1_16_194_METHODS),
                              'cpp_interfaces': list(ACSOCKEXT_CPP_TYPEINFO)}, indent=2))
    else:
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
