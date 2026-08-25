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
    # Gate chain: DR lazy-init in requestSocket: → caller wrapper @ 0x3e5b6 → _ne_code_sig_gate
    #
    # DR caller wrapper @ 0x3e5b6 (embedded in requestSocket:):
    #   0x3e5b6: call 0x1f39fc     → validates DR requirement ref at [rbp-0x10]
    #   0x3e5bb: test eax; je 0x3e5ed   → eax==0: DR ready; proceed to gate call
    #   0x3e5ed: rdi=[rbp-0x10], esi=0, edx=0
    #   0x3e5f5: call 0x18a2f4     → _ne_code_sig_gate(requirement, NULL_url, NULL_aux)
    #   NULL url → gate takes SecCodeCopySelf path: validates the CALLING PROCESS (not a file)
    #   vs DR = "identifier com.cisco.anyconnect.macos.acsockext and cert leaf[OU]=DE8Y96K9QP"
    #
    # NULL-REQUIREMENT BYPASS:
    #   Lazy-init stub @ 0x3e64e writes requirement ref to [rip+0x299905].
    #   If [rip+0x299905] is zeroed (NULL requirement), _ne_code_sig_gate(NULL, NULL, NULL) is called.
    #   → SecStaticCodeCheckValidity(self_code, 0, NULL) with no requirement → always passes.
    #   An unsigned extension with no embedded requirements clears this gate.
    #   NOTE: call @ 0x3e2ce (esi=2) is _os_log_type_enabled(DEBUG) — NOT a security gate.
    'requestSocket:interface:local:remote:completionHandler:':      0x3e26c,
    'extensionHasACRequirement':                                    0x3e982,
    # TWO-STAGE CODESIG GATE — validates that a caller extension satisfies a DR.
    # Signature: _ne_code_sig_gate(SecRequirementRef req, id urlOrPath, id aux) → BOOL
    #   r15=rdi=req, r12=retain(rsi=url/path), rbx=retain(rdx=aux)
    #
    # STAGE 1 — SecStaticCode creation (error check, NOT the security gate):
    #   0x18a33b: test r12; je 0x18a398 → nil path skips static code creation
    #   Non-nil path @ 0x18a344: build struct at [rbp-0x40]/[rbp-0x38] with r12 (path)
    #   0x18a369: call [rip+0xd7629] → creates SecStaticCode from r12 with flags=1 → retained rbx
    #   0x18a37a-0x18a385: call 0x1f38f4(0, rbx, 0, &[rbp-0x68]) → first code validity check
    #   r13d = result; jne 0x18a431 if non-zero (code object creation failed → bail)
    #   Nil path @ 0x18a398: call 0x1f38fa(0, &[rbp-0x68]) → same check for nil-url case
    #
    # STAGE 2 — THE ACTUAL GATE:
    #   0x18a3af: rdi=[rbp-0x68] (code object from stage 1)
    #   0x18a3b8: esi=0 (kSecCSDefaultFlags)
    #   0x18a3ba: rdx=r15 (the requirement ref from original rdi arg)
    #   0x18a3bd: call 0x1f38e8 → SecStaticCodeCheckValidity(code, 0, requirement)
    #   0x18a3c2: test eax, eax
    #   0x18a3c4: je 0x18a4a3  ← BYPASS TARGET (2-byte patch: 74 dd → eb dd)
    #     eax==0 (success): jmp to 0x18a4a3 (continue processing valid code)
    #     eax!=0 (fail): log error, return r15d=0 (BOOL NO)
    #
    # BYPASS OPTIONS:
    #   A. Patch 0x18a3c4: `74 dd` → `eb dd` (je → jmp) — always success regardless of result
    #   B. Hook GOT[_SecStaticCodeCheckValidity] @ 0x262008 → redirect to `xor eax,eax; ret`
    #   Both require code injection into nesessionmanager or dyld-load hook in the extension.
    #
    # Error path @ 0x18a431: builds error struct, logs with 0x8400102 flag, return 0.
    # Stack canary: [rbp-0x30] checked @ 0x18a486 before ret (standard canary pattern).
    '_ne_code_sig_gate':                                            0x18a2f4,

    # ── NEConfiguration plugin type dispatch ─────────────────────────────────────
    # Type dispatch: retains payload/pluginType/payloadType, then isKindOfClass: branches
    # to IKEv2 | L2TP | CiscoNExt handler. Block invoke at 0x33b91 does actual migration work.
    # NOTE: class is NEConfiguration (not NEConfigurationManager); IMP from classlist parse
    'NEConfiguration.configurePluginWithPayload:pluginType:payloadType:': 0x11299,
    # kext→sysext migration: captures (self, upgradeInfo, queue, handler) into a dispatch_block
    # block invoke at 0x33b91; race window between isKindOfClass: check and block dispatch
    'NEConfigurationManager.upgradeLegacyPluginConfigurationsWithUpgradeInfo:completionQueue:handler:': 0x33a8c,
    # Keychain ACL insertion (adds app to Cisco's Keychain ACL for PSK/XAuthPassword/cert privkey).
    # rdx=config (NEConfiguration-like object containing new app path in property sel@0x2916d9).
    #
    # STRUCTURE (420 insns total):
    #   0x352b8: r13 = [config <sel@0x2916d9>] retain → app path/identifier
    #   0x352dc: TYPE CHECK: [static_class_ref <sel@0x2917d6>:r13] → bail if bad ObjC type
    #           *** TYPE-ONLY CHECK — validates ObjC class, NOT code signature ***
    #           Any NSString/NSURL-typed path passes regardless of app identity.
    #   0x3543c: [r15 <sel@0x291d0d>] → existing ACL app paths from config's ACL object
    #   0x35473: rdi=[rip+0x297d96], rsi=sel@0x2922e1, rdx=r13; SecACL-related call
    #   0x35595: BATCH ITERATION LOOP — reads all existing Keychain ACL entries in batches of 0x10
    #           per-entry: [entry_array[i] <sel@0x292141>] → sub-property → add to new list
    #           next batch: [iter_obj <sel@0x291115>:struct:error:0x10] @ 0x356a4
    #   0x356d3: build final app list r12 including the NEW entry (r13)
    #   0x35707: [r14 <sel@0x292075>:r12] → FIRST ACL WRITE (r14 = primary ACL object)
    #   0x3572d: [[rbp-0xd8] <sel@0x292054>:r12] → SECOND ACL WRITE (secondary ACL object)
    #
    # PRIMARY ISSUE: type check at 0x352dc is insufficient — validates ObjC class only.
    #   Craft NEConfiguration with malicious app path (valid NSString) → passes type check
    #   → malicious app written to Cisco Keychain ACL → can read PSK/XAuthPassword/cert privkey.
    #   No code-signature verification at any point in this function.
    #
    # SECONDARY TOCTOU: ACL read-modify-write without lock (~420-insn window):
    #   type_check(0x352dc) → batch_read_loop(0x35595) → ACL_write(0x35707)
    #   Concurrent `addAppToKeychainACLsForConfiguration:` loses write if it lands
    #   between batch read and write (classic lost-update on the ACL app list).
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
    #   0xa4f73: type/cert check on r12 → debug-log path 0xa5149 (log + edx=3 error)
    #   0xa4f87: [r12 isConnectionReusableForDestination:r14] (sel@0x224ea1) → NO: 0xa51b0
    #   0xa4fad: [r14 <sel@0x224d46>] → debug-log path 0xa52f0 if NO
    #   0xa4fc7: [r14 <sel@0x224d66>:0] → 0xa534d if NO
    # Factory @ 0xa4fcd: [SharedClass <sel@0x224e5d>:r12(conn):r14] → retained IKEv2Session (rbx/r13)
    # Key dispatch @ 0xa50a8: [self <sel@0x224b25>:session:block] → BOOL
    #   YES = validateSAInit:block: scheduled (queued async) → early exit 0xa513a
    #   NO  = error: [self <logProp>]:3 set (edx=3), two cleanup calls, → exit
    # Final dispatch @ 0xa52c7: [self sel@0x2248f2:new_session:nil] → BOOL
    #   YES @ 0xa55d5: [self setCurrentSession:sel]; release(new_session,r14,r12); ret
    #   NO  @ 0xa555e: [self.prop setCount:3:log]; [self stateChange:]; → falls to YES cleanup
    #   NO path does NOT retry — single-shot failure, no re-fetch, no loop amplification.
    # Session-nil bail @ 0xa545a: edx=3 error log + [self sel@0x2246b8/2246b6] cleanup.
    # Error classification: ALL error paths use edx=3 to set error count on a property.
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
    #   Race window: ~115 insns of unprotected r14 reads. SINGLE-SHOT (no retry loop).
    'NEIKEv2PacketTunnelProvider.receiveConnection:':              0xa4e00,

    # ── NEIKEv2Session — ChildSA kernel install path ────────────────────────────
    # Writes negotiated ChildSA keying material into kernel network stack.
    # rdx=ChildSA_obj (3rd ObjC arg, retained → r14 at 0xee6a7); r13=self.
    #
    # GUARDS (all must be non-nil):
    #   0xee6ba-0xee6de: [self sel@0x1dafb9] retain → rbx (session property) → nil bail 0xefb77
    #   0xee6e4: test r14 → nil bail 0xefba9
    #   Additional nil checks on 3 session crypto properties (0xee736, 0xee77b, 0xeeaaf)
    #
    # CRYPTO OBJECT BUILD:
    #   0xee7b5: [self sel@0x1dc6cc] → r14 (session crypto suite identifier)
    #   0xee7d3: [childSA sel@0x1da548] → r12 (direction/SPI property of childSA)
    #   0xee7e8: [r12 sel@0x1da4f0] → rbx (key material descriptor)
    #   0xee807-0xee810: [self sel@0x1dc800:r14(suite):rbx(key_desc)] → r13 (combined crypto obj)
    #
    # KERNEL SA OBJECT ALLOC:
    #   0xee8df: [NEKernelSAClass_0x1dedc9 alloc/init] → r12 (kernel SA wrapper)
    #
    # DIRECTION SET:
    #   [IKE_context sel@0x1daa73] → rax; bl = (rax==1) (inbound flag)
    #   [r12 sel@0x1daa68:edx=(2-bl)] → set traffic direction (inbound=1, outbound=2 or vice versa)
    #
    # CIPHER TYPE SET:
    #   [self sel@0x1da321] → r15 (encryption algorithm object)
    #   [r15 sel@0x1d7f74] → rax; bl = (rax==2); inc bl
    #   [r12 sel@0x1d83d8:edx=bl] → set cipher type (1=AES-CBC, 2=AES-GCM)
    #
    # KEY MATERIAL WRITE (sequential, no atomic commit):
    #   [self sel@0x1dac75] → r15 (encryption keying material object)
    #   [r15 sel@0x1db518] → rbx (AUTH/HMAC key bytes)
    #   0xeea32: [r12 sel@0x1d9704:rbx] ← WRITE AUTH KEY TO KERNEL SA OBJECT
    #   [self sel@0x1dac20] → r15 (IV/salt material object)
    #   [r15 sel@0x1db722] → rbx (IV/salt bytes)
    #   0xeea95: [r12 sel@0x1d96ad:rbx] ← WRITE IV/SALT TO KERNEL SA OBJECT
    #
    # CIPHER DISPATCH @ 0xeeaf5 (rbx = IKEv2 transform type from childSA.encAlgID):
    #   rbx == 2   → 0xeec5d  ← ENCR_DES (broken — silently accepted, downgrade target)
    #   rbx == 3   → 0xeebe5  ← ENCR_3DES
    #   rbx == 12  → AES-CBC path: key_size_enum check; eax=5 → 0xeec53 install
    #   rbx == 20  → 0xeebec  ← ENCR_AES_GCM_16
    #   rbx == 28  → 0xeec58  ← ENCR_CHACHA20_POLY1305
    #   rbx > 19 else → 0xeef41 (unsupported/fallback)
    #
    # DOWNGRADE ATTACK SURFACE: ENCR_DES (rbx==2) is accepted without policy enforcement.
    #   MitM IKE_SA_INIT proposal to replace AES-CBC (12) with DES (2) → 56-bit key installed.
    #   No validation that childSA.encAlgID is in a policy-approved set.
    #
    # KEY MATERIAL RACE: auth key and IV/salt written to r12 in two sequential calls.
    #   Kernel SA commit is further in the function (beyond 450 insns). Between 0xeea32 and
    #   the final commit, another thread with r12 access can read partial keying state.
    'NEIKEv2Session.installChildSA:':                               0xee682,

    # ── NEIKEv2Session Phase 1 ───────────────────────────────────────────────────
    # IKE SA_INIT initiator path (called from connection setup after receiveConnection: accepts).
    # r13=self (NEIKEv2Session); r12=objc_msgSend (used throughout).
    #
    # PROLOGUE / PROPERTY LOADS:
    #   0xa2c64: sel@0x2269d8 → [self propA] retain → r15 (IKE config / server info)
    #   0xa2ca9: sel@0x227060 → [self propB] retain → r14 (connection context / dispatch queue)
    #   0xa2cc4: test r15; je 0xa32f5 → bail if IKE config nil
    #   0xa2ccd: test r14; je 0xa3320 → bail if connection context nil
    #
    # SELECTOR RESOLUTION:
    #   0xa2cd7: r13 = sel@0x223c4a (selD — probably `localAddress` or `remoteAddress`)
    #   0xa2ce4: [r14 selD] retain → rbx; nil guard → 0xa334b
    #
    # CONFIG-FLAG BRANCH (0xa2def):
    #   0xa2dba: [r12=IKE_config sel@0x223b67] → retain rbx
    #   0xa2de3: [rbx sel@0x226558] → r14d (BOOL) — flag check (likely isMobileConnect/isReauthRequired)
    #   0xa2def: test r14b; je 0xa2e9b → FALSE = standard SA_INIT path; TRUE = retransmit/reauth path
    #
    # TRUE-FLAG PATH (retransmit / reauth variant):
    #   0xa2e27: [self sel@0x22683f] retain → r14 (state/timer object)
    #   0xa2e46: edi=9; call 0x7651c → clock_gettime_nsec_np(CLOCK_UPTIME_RAW_APPROX) → rbx (timestamp)
    #   0xa2e5a: [r14 sel@0x226826:3:rbx] — set retransmit-count=3, base-timestamp=rbx
    #   0xa2e74: [self sel@0x226d1d]; [self sel@0x226d18] — two setters on self
    #   → jmp 0xa3281 (skip standard SA_INIT, use timer-driven retransmit)
    #
    # FALSE-FLAG PATH (standard SA_INIT):
    #   0xa2ecd: [self sel@0x226cc4] — setter on self (marks connection as initiating)
    #   0xa2ee7: [self sel@0x223a41] retain → [rbp-0x60] (probably socket/flow object)
    #   0xa2efc: [[rbp-0x60] sel@0x225ecd] retain → rbx (sub-property, maybe write-handler)
    #   0xa2f2b: [self sel@0x226dfd:r15:rbx] → BOOL r15d
    #           *** IKE SA_INIT DISPATCH (pre-send gate — passes connection + handler) ***
    #   0xa2f43: test r15b; je 0xa3098 → if false, error path (edx=3 state set)
    #
    # IKE_SA_INIT SEND (reached after bool check):
    #   0xa2f4c: [r12 sel@0x226d95] → test al; je 0xa3137 (MOBIKE flag check)
    #   If MOBIKE/rekey flag set:
    #     0xa2f78: [SomeClass sel@0x226d5b:r12(IKE_SA)] retain → [rbp-0x60] (probe object)
    #   0xa2fa5-0xa2fc7: build stack block literal at [rbp-0x98]:
    #     [r14]      = _NSConcreteStackBlock isa ptr [rip+0x1be0ca]
    #     [r14+8]    = 0xc2000000 (block flags: BLOCK_HAS_COPY_DISPOSE | BLOCK_HAS_DESCRIPTOR)
    #     [r14+0x10] = invoke fn ptr [rip+0x3fb] (relative to 0xa2fb8 ≈ 0xa2fb3+local offset)
    #     [r14+0x18] = descriptor ptr [rip+0x1c204d]
    #     [r14+0x20] = self (r12 = [rbp-0x58])
    #     [r14+0x28] = retained(IKE_SA_obj) — captures IKE SA
    #     [r14+0x30] = retained([rbp-0x48]) — captures connection context
    #   0xa3000: [self sel@0x226bb6:IKE_SA_obj:1:block_ptr]
    #           *** ACTUAL IKE_SA_INIT SEND ***
    #           cmp eax, -1; jne 0xa307c → if -1 (error), log + set error state edx=3
    #
    # ERROR PATTERN: ALL failure branches set [property sel@0x22663d:3:msg] — edx=3 = error marker
    #   (same as receiveConnection: — system-wide error count convention)
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
    # IKE SA rekey initiator — near-identical structure to initiateConnect.
    # r13=self; r12=objc_msgSend throughout.
    #
    # STATE GUARD @ 0xa94c8 (sel@0x2209d1):
    #   [r14 sel] → test al; je 0xa950f — TRUE: already rekeying → bail/cleanup (no double rekey)
    #
    # FALSE path (standard rekey initiation @ 0xa950f):
    #   [r14 sel@0x2209ca:1] — SET REKEY-IN-PROGRESS flag
    #   [r14 sel@0x220980] → retain → rbx (current IKE SA)
    #   [rbx sel@0x2207a7] → test al; je 0xa9722 — IKE SA state guard (wrong state → edx=3 error)
    #
    # REKEY SA PROPOSAL BUILD @ 0xa9556:
    #   [RekeyClass_0x223f13 sel@0x220984:current_SA(rbx)] → r15 (new rekey SA proposal object)
    #   nil guard → 0xa97cb (error)
    #
    # BLOCK BUILD (same pattern as initiateConnect @ 0xa9585-0xa95d0):
    #   Stack block at [rbp-0x70]: isa=_NSConcreteStackBlock, flags=0xc2000000,
    #   invoke=[rip+0x35e] (≈ 0xa9904), descriptor=[rip+0x1bba5f]
    #   Captures: [rbx+0x20]=self(r13), [rbx+0x28]=retain(current_IKE_SA), [rbx+0x30]=retain(r14)
    #
    # REKEY SA_INIT SEND @ 0xa95e5:
    #   [self sel@0x2205d1:rekey_SA_proposal(r15):1:block]
    #   cmp eax, -1; jne 0xa965a → error if -1
    #
    # ERROR PATHS: edx=3 convention confirmed at 0xa9620, 0xa96e4, 0xa978d, 0xa983a
    #   (all 4 error branches log via [prop sel@0x220060:3:msg] — same as initiateConnect)
    'NEIKEv2Session.initiateRekeyIKESA':                            0xa9463,
    # IKE SA rekey RESPONDER path. r13=self; r14=retain(rdx=incoming rekey packet).
    # r15 = [self sel@0x21f923] (current IKE SA object). Guards: r15 nil→0xaa411, r14 nil→0xaa443.
    #
    # STATE GUARD @ 0xa9d70 (sel@0x220129):
    #   [r15 sel] → test al → jne 0xa9db1 — TRUE = already rekeying → skip to double-rekey bail
    #   Double-rekey bail: error obj nil-checked (esi=2), then jmp 0xaa3aa cleanup
    #
    # FALSE path (normal responder, @ 0xa9db1):
    #   0xa9db8: [r15 sel@0x220128:1] — SET REKEY-IN-PROGRESS flag on current IKE SA
    #   0xa9dca: [r15 sel@0x2200de] → rbx (current IKE SA)
    #   0xa9ddc: [rbx sel@0x21ef05:0] → [rbp-0x29]=1 (byte flag on IKE SA)
    #
    # COMPATIBILITY CHECK @ 0xa9dff:
    #   0xa9dff: [r14(incoming) sel@0x220107:rbx(current_IKESA)] → test al; je 0xaa008
    #   Compares incoming rekey proposal IKE SA identity against current SA.
    #   al==0 (mismatch) → 0xaa008 (SPI-construction path — builds explicit SPI response)
    #   al!=0 (match) → standard responder path
    #
    # IKE SA TYPE GUARD @ 0xa9e0e:
    #   [rbx sel@0x21fed3] → test al; je 0xaa140 (error — wrong SA state)
    #
    # NEW IKE SA BUILD FROM INCOMING PROPOSAL @ 0xa9e2a (RESPONDER DOWNGRADE SURFACE):
    #   rdi=[rip+0x22363f] (NEIKEv2IKESA class)
    #   sel@0x2200d0; rdx=r14 (incoming packet), rcx=rbx (current IKE SA)
    #   → [NEIKEv2IKESAClass sel@0x2200d0:incoming_packet:current_SA] → retain → [rbp-0x38]
    #
    #   *** NO CIPHER-SUITE POLICY ENFORCEMENT ***
    #   The new IKESA is created directly from the PEER'S PROPOSAL in r14 (the incoming
    #   rekey packet). If that packet proposes ENCR_DES (transform type 2), the resulting
    #   new_IKESA has DES as its cipher. When installChildSA: later runs against this SA,
    #   the rbx==2 dispatch at 0xeec5d installs a 56-bit DES-keyed kernel SA.
    #
    #   FULL RESPONDER DOWNGRADE CHAIN:
    #     MitM IKE rekey packet → propose ENCR_DES (type 2) instead of ENCR_AES_CBC (12)
    #     → receiveRekeyIKESA: creates DES-keyed new_IKESA (no policy check here)
    #     → [self sel@0x21fd11:new_IKESA:block] sends responder accept
    #     → installChildSA: dispatches to 0xeec5d (ENCR_DES handler)
    #     → 56-bit DES key installed in kernel → all subsequent tunnel traffic attackable
    #
    # BLOCK BUILD @ 0xa9e59-0xa9ea4 (same layout as initiateRekeyIKESA):
    #   Stack block at [rbp-0x90]: isa=_NSConcreteStackBlock, flags=0xc2000000,
    #   invoke=[rip+0x5f8] (≈0xaa476), descriptor=[rip+0x1bb188]
    #   Captures: [+0x20]=self(r13), [+0x28]=retain(current_IKE_SA), [+0x30]=retain(r15)
    #
    # RESPONDER REKEY SEND @ 0xa9ebc:
    #   [self sel@0x21fd11:new_IKESA([rbp-0x38]):block] → test al; jne 0xa9f38
    #   al==0: log error at 0xa9ef6 (edx=3 convention — 7th function with this pattern)
    #
    # SPI MISMATCH PATH @ 0xaa008 (from compatibility check al==0):
    #   [rbx sel@0x21ecb7] → r15; [r15 sel@0x21f51e] → r12
    #   0xaa056: rol bx, 8  ← SPI byte-swap (same as receiveConnection: 0xa5230 and
    #                         installChildSA: -- network→host byte order for SPI)
    #   alloc obj; [obj sel@0x21c834:2:&bx_bytes] → create SPI data (ecx=2 bytes)
    #   0xaa0c4: [class sel@0x21fddf:0x11:r14:SPI_data_obj] — build explicit rekey response with SPI
    #   0xaa0dc: [r15 sel@0x21fdfb:0] — IKE SA state update (post-SPI-response)
    'NEIKEv2Session.receiveRekeyIKESA:':                            0xa9cf6,
    # ChildSA rekey RESPONDER path. r15=self; r12=retain(rdx=incoming rekey packet); [rbp-0x68]=4th arg.
    #
    # COMPATIBILITY CHECK @ 0xa8755 (RESPONDER DOWNGRADE SURFACE, SAME AS receiveRekeyIKESA:):
    #   [[rbp-0x68] sel@0x221774:r12(incoming_rekey)] → test al; je 0xa893b (mismatch path)
    #   al==0 (mismatch) → SPI-construction path with explicit SPI response @ 0xa893b
    #   al!=0 (match) → standard responder path
    #
    # CIPHER CHECK @ 0xa876e:
    #   [r12(incoming_rekey_pkt) sel@0x221573] → test al; je 0xa8902 (cipher not acceptable path)
    #   Note: test al NOT implemented as a policy enforcement gate — if al!=0, directly proceeds
    #   to child SA build without validating cipher-suite against local policy.
    #   Incoming packet proposing ENCR_DES (transform 2) will pass this test on the cipher field
    #   since the selector returns the peer's proposed value, not a policy approval flag.
    #
    # NEW CHILDSA BUILD FROM PEER PROPOSAL @ 0xa87d0 (DOWNGRADE COMPLETES HERE):
    #   [NEIKEv2ChildSA_class sel@0x21e48c:1] → r14 (alloc)
    #   [self sel@0x221542:r12(peer_rekey):rax(SA_init):block] → r13 SEND at 0xa87e0
    #   *** No cipher-suite policy check between cipher-read (0xa876e) and send (0xa87e0)
    #   Child SA created and response sent with whatever cipher the peer proposed.
    #
    # DOWNGRADE CHAIN (CHILD SA REKEY, CLOSES RESPONDER LOOP):
    #   MitM intercepts child SA rekey → proposes ENCR_DES (type 2)
    #   → receiveRekeyChildSA:packet: cipher check passes (0xa876e al test — value not policy gate)
    #   → new ChildSA built from peer proposal, SEND at 0xa87e0
    #   → installChildSA: dispatches rbx==2 to 0xeec5d (ENCR_DES handler)
    #   → 56-bit DES-keyed kernel SA installed for child SA traffic
    #   This is the child SA counterpart to receiveRekeyIKESA: (which covers IKE SA rekey).
    #   Both paths confirmed unchecked — full dual-path downgrade attack surface.
    #
    # ERROR MARKER @ 0xa88cd: edx=3 (8th function with this convention confirmed)
    #
    # SPI BYTE-SWAP @ 0xa898d: `rol r14w, 8` (4th occurrence — network→host SPI order)
    #   [r14_class sel@0x22149e:0x11:r12(incoming):SPI_obj] → new ChildSA with explicit SPI @ 0xa89ea
    'NEIKEv2Session.receiveRekeyChildSA:packet:':                   0xa85a6,
    # ChildSA DELETE handler (RFC 7296 §3.11 INFORMATIONAL + DELETE). r15=self.
    # rdx=ChildSA_to_delete → retain → r12; rcx=delete_packet → retain → r13.
    # Stack canary @ 0xac268; retain-check (0x1f3bfa) @ 0xac2a7.
    #
    # THREE NIL-GUARDS: r14 @ 0xac2d4, r12 @ 0xac2dd, r13 @ 0xac2e6 → error on any nil.
    #
    # DELETE DISPATCH @ 0xac361 (5-arg msgSend):
    #   Packet SPI (r13 field) flows into the delete call without visible validation
    #   against session-owned SA list. Crafted out-of-session SPI in a DELETE payload
    #   may trigger deletion of an unrelated SA.
    #
    # RESULT DISPATCH @ 0xac3b2: `test r13b, r13b`
    #   r13b==0 (failure): esi=0x10 isKindOfClass check @ 0xac455 (class 16)
    #   r13b!=0 (success): isKindOfClass(0) @ 0xac3bb — esi=0 → al always 0 (dead-code log path)
    #     log flag 0x8400202 at 0xac3d2 (DIFFERENT from 0x8400302 — lower verbosity than install/migrate)
    #     dead-code confirmed: isKindOfClass:nil always returns NO → log block never executes.
    #
    # ERROR MARKER @ 0xac41a: `mov edx, 3` (9th function with this convention confirmed)
    'NEIKEv2Session.receiveDeleteChildSA:packet:':                  0xac247,
    # ChildSA DELETE initiator path (self sends the delete, vs receiveDeleteChildSA: handles peer's).
    # r12=self; rdx=ChildSA → retain → r14. Stack canary; retain-check (0x1f3bfa) @ 0xac5a3.
    #
    # r14 nil → 0xac71d: isKindOfClass(0x11) nil-guard (standard class check, not dead code here).
    #
    # r14 non-nil:
    #   error ctx alloc (0x1f3dec) → rbx; isKindOfClass(0) @ 0xac5cd (esi=xor-zero) → DEAD CODE
    #     (same dead-code log path as receiveDeleteChildSA: — isKindOfClass:nil always NO)
    #   log flag 0x8400202 @ 0xac5dc (SAME lower-verbosity flag as receiveDeleteChildSA:)
    #
    # DOUBLE-READ TOCTOU @ 0xac655 / 0xac680:
    #   READ 1: [r14(ChildSA) sel@0x21c67b] → retain → [rbp-0x58]  ← property read
    #   subread: [[rbp-0x58] sel@0x21c668] → retain → r15           ← sub-property
    #   READ 2: [r14(ChildSA) sel@0x21c67b] → retain → r13          ← SAME selector, second read
    #   subread: [r13 sel@0x21c646] → retain → r14                  ← sub-property
    #   Main call @ 0xac6bd: [self sel@0x21d7cc:r15(sub1):r14(sub2)] — 4-arg delete dispatch
    #   r15 from sub-read-1, r14 from sub-read-2 → inputs from different ChildSA state reads.
    #   Concurrent SA modification between 0xac655 and 0xac680 → mismatched sub-properties.
    #
    # ERROR MARKER @ 0xac636: `mov edx, 3` (10th function with edx=3 convention confirmed)
    #
    # BLOCK LITERAL @ 0xac7d4 (overlapping next fn body): flags=0xc2000000, invoke@0xac8d8
    #   Completion handler for async delete acknowledgment from peer.
    'NEIKEv2Session.initiateDeleteChildSA:':                        0xac557,
    # ChildSA install / migrate / uninstall (installChildSA: fully annotated above)
    # MOBIKE child SA address migration. r13=self; rdx=ChildSA → retain → r14. Stack canary @ 0xefcbf.
    #
    # DOUBLE-READ OF SA LIST @ 0xefcdf / 0xefd19 (same TOCTOU as install/uninstall):
    #   0xefcdf: [r13 sel@0x1d9997] → retain → rbx  ← READ 1 (nil → 0xf0ae7 error)
    #   0xefd19: [r13 sel@0x1d9997] → retain → r14  ← READ 2 (same selector, new retain)
    #   Window: concurrent installChildSA:/uninstallChildSA: modifies SA list between reads →
    #   rbx and r14 reference different list generations; operations on rbx and r14 diverge.
    #
    # LOG STRUCT @ 0xefe1c: flag=0x8400302 (same verbose flag as installChildSA: and uninstallChildSA:)
    #   Confirms migrateChildSA: is in the same unprotected critical region as install/uninstall.
    #
    # MIGRATION CALL @ 0xefecc (MOBIKE ADDRESS HIJACKING SURFACE):
    #   [r12 sel@0x1db13d:new_src_addr(rdx):new_dest_addr(rcx)] → rbx
    #   Source and destination addresses read from the incoming ChildSA object (r13/r14 derived).
    #   No visible verification that the new address belongs to the authenticated IKE peer.
    #   MOBIKE RFC 4555 §3.5 requires UPDATE_SA_ADDRESSES with NOTIFY payloads protected by
    #   the IKE SA — if the IKE SA is compromised (e.g. via DES downgrade) the address
    #   verification is also compromised → traffic hijack to attacker-controlled address.
    #
    # FAILURE PATH @ 0xefef1: test rbx; je 0xf027f (nil return from migration → no cleanup visible
    #   in first 200 insns; function continues beyond window at 0xf027f).
    'NEIKEv2Session.migrateChildSA:':                               0xefca4,
    # Bulk MOBIKE migration — iterates all child SAs calling migrateChildSA: on each.
    # r13=self. Stack canary @ 0xf0bf0. NSFastEnumeration over child SA collection.
    #
    # ENUMERATION SETUP @ 0xf0c0d-0xf0c47:
    #   [self sel@0x1da254] → retain → [rbp-0xb8] (child SA collection)
    #   NSFastEnumeration init (struct at [rbp-0x100], [rbp-0xb0], r8d=0x10)
    #
    # PER-ITEM MIGRATION LOOP @ 0xf0c71-0xf0caa (NO LOCK ON SA LIST):
    #   rdx = collection[r14] (current child SA)
    #   [r13(self) sel@0x1da442:rdx] → al  ← calls migrateChildSA: on each SA
    #   test al; je 0xf0ce1 → EARLY EXIT on first failure: xor r14d (return 0)
    #   Subsequent SAs in the list are NOT migrated; partial migration state.
    #
    # COMPOSITION RISK:
    #   migrateAllChildSAs iterates without a list lock.
    #   Concurrent uninstallChildSA: or copySAsToDeleteAndInstallRekeyedChildSA: modifies the list
    #   during enumeration → iterator skips or double-visits SAs.
    #   Each per-SA call inherits migrateChildSA:'s own double-read race (0xefcdf/0xefd19).
    #   Outcome: some SAs migrated to new address, some not → asymmetric tunnel state
    #   (inbound SA at old address, outbound at new) → traffic blackhole without teardown.
    'NEIKEv2Session.migrateAllChildSAs':                            0xf0bcf,
    # Atomic old→new SA swap for rekeyed child SAs. r14=self; rdx=rekeyed_ChildSA → retain → r15.
    #
    # NIL REKEYED-SA PATH @ 0xf6ee4:
    #   error ctx alloc (0x1f3dec) → isKindOfClass(0x11) check (esi=0x11 at 0xf6ef7)
    #   mismatch: [rbx] release → xor r14d,r14d → cleanup ret
    #
    # OLD-SA DISCOVERY @ 0xf6d74-0xf6de2:
    #   [class_alloc(0x1f40f8)] → NSMutableArray for deletion list
    #   [r14 sel@0x1cf899] → rbx (populate from alloc)
    #   [r14 sel@0x1d402d] + msgSend → retain → rbx (self's current SA collection)
    #   [r14 sel@0x1d44aa:current_SAs:rekeyed_SA] → r13 (old SA entries to evict — iterator/list)
    #   test r13; je 0xf6e8f → nil: no old SAs, skip delete loop → go straight to install
    #
    # DELETE LOOP @ 0xf6dfa-0xf6e89 (NO VISIBLE LOCK — DOUBLE-READ RACE):
    #   Per-iteration (r13 = current old SA entry):
    #     0xf6dfa-0xf6e08:  [sel@rbp-0x40]:r14:r13] — delete r13 from SA list on r14(self)
    #     0xf6e0f-0xf6e22:  [r14 sel@rbx(0x1d3fb7)] → retain → r15   ← READ 1: fresh SA list
    #     0xf6e27-0xf6e36:  [r15 sel@[rbp-0x48]:0:r13]               ← flag old SA in list
    #     0xf6e39-0xf6e43:  release r15
    #     0xf6e45-0xf6e56:  [r14 sel@rbx(0x1d3fb7)] → retain → r15   ← READ 2: SAME selector, fresh read
    #     0xf6e59-0xf6e6a:  [r14 sel@0x1d440d:r15:r15_rcx] → rbx     ← install/replace on list
    #     0xf6e70-0xf6e80:  release r13, release r15
    #     r13 = rbx; test rbx; jne 0xf6dfa (loop continues while next old SA non-nil)
    #
    # DOUBLE-READ RACE (COMPOSES WITH uninstallChildSA: ITERATOR RACE):
    #   READ 1 and READ 2 both call sel@0x1d3fb7 on self — same SA list, no lock between them.
    #   Window: concurrent uninstallChildSA: deletes entries from this list between READ 1 and READ 2.
    #   Outcome A: READ 1 sees entry, flag op runs; READ 2 misses entry (deleted) → install op
    #     operates on stale list → the old SA is NOT fully evicted → dangling SA with stale keying.
    #   Outcome B: uninstallChildSA: and this function both evict the same entry →
    #     double-delete on kernel SA handle → UAF / kernel panic risk.
    #   Race window: O(N_old_SAs * ~30 insns) — scales with child SA count.
    #
    # POST-LOOP CONDITIONAL INSTALL @ 0xf6e8f-0xf6eb8:
    #   [r14(self) sel@0x1d2ed6:r15(rekeyed_SA)] → al (install-permission gate)
    #   test al; je 0xf6ebd → 0 = cannot install → xor r14d,r14d → return nil
    #   al!=0 → [rbx sel@??] → r14 (installs rekeyed SA; return value = new SA handle)
    #
    # RETURN: r14 = newly installed rekeyed ChildSA handle, or nil on any failure
    'NEIKEv2Session.copySAsToDeleteAndInstallRekeyedChildSA:':      0xf6d4b,
    # Kernel SA teardown path. r12=self; rdx=ChildSA object → retain → r15.
    # `call 0x1f3dec` → error context → rbx (always created, used on nil-ChildSA path).
    #
    # NIL CHILDSA PATH @ 0xf736d:
    #   esi=0x11; call 0x1f421e → isKindOfClass check → test al
    #   al==0: release(rbx); ret (no-op uninstall)
    #   al!=0: call 0x1da32c (error handler — ObjC type violation)
    #
    # LOGGING @ 0xf71ba (r15 non-nil path):
    #   log struct flag = 0x8400302 (verbose, same value as installChildSA: at 0xee881)
    #
    # KERNEL SA LOOKUP @ 0xf7238-0xf725c:
    #   [self sel@0x1d3b98] → retain → r15 (SA list / kernel SA manager)
    #   [self sel@0x1d401a:r15:r14(ChildSA)] → rbx (kernel SA info for this ChildSA)
    #   test rbx; je 0xf7344 → nil: no kernel SA registered, skip removal (no-op)
    #
    # REMOVAL LOOP @ 0xf7273-0xf733e (iterates kernel SA entries for this ChildSA):
    #   Cache loop selectors: [rbp-0x68]=sel@0x1d3ffe, [rbp-0x60]=sel_from_[rip+0x1cf5fb]
    #   Per-iteration (rbx = current SA entry):
    #     [self sel@0x1d3aed] → retain → r15
    #     [r15 sel@0x1d3ffe:rbx:r14(ChildSA)] ← first kernel SA removal call
    #     [r14_new sel@0x1cf5fb:0:r14(ChildSA)] ← second removal call (inbound+outbound pair)
    #     [self sel@0x1d3acc] → r15
    #     [self sel@0x1d3f51:r15:r15_prev] → r14 (next entry in list)
    #   0xf733b: test r14; jne 0xf7289 ← LOOP: continue while next entry != nil
    #
    # ITERATOR INVALIDATION RACE:
    #   Loop iterates the kernel SA list (loaded once at 0xf7238) with NO LOCK.
    #   A concurrent [self installChildSA:] adds a new entry to the same list while the
    #   removal loop is running. Two outcomes:
    #     a) New entry added between loop-load and first iteration → new SA deleted
    #        (premature teardown: VPN kernel SA evicted before it's fully initialized)
    #     b) New entry added mid-loop after current iteration pointer → loop terminates
    #        without removing the OLD ChildSA entries (dangling kernel SAs with stale keying)
    #   This race window spans the entire loop body (~65 insns * N SA entries).
    #
    # STACK CANARY @ 0xf7355/0xf7358: jne 0xf7390 → smash handler (standard pattern)
    'NEIKEv2Session.uninstallChildSA:':                             0xf7161,
    # Bulk child SA teardown. r14=self. Stack canary @ 0xf73b6.
    # isKindOfClass(0) @ 0xf73cd (xor-zero esi → DEAD CODE, same as receiveDeleteChildSA:)
    # log flag 0x8400202 @ 0xf73fa (3rd function with this lower-verbosity flag).
    #
    # TWO SEPARATE NSFastEnumeration loops over TWO DIFFERENT collection properties (NO LOCK):
    #   Loop 1 @ 0xf744b-0xf7545: [r14 sel@0x1d39f2] → collection; per-item: sel@0x1d05a0 on each SA
    #   Loop 2 @ 0xf7560-0xf762a+: [r14 sel@0x1d3921] → second collection; per-item: sel@0x1d048e on each SA
    #   Different selectors → two different SA lists, each uninstalled separately, with no lock on either.
    #
    # COMPOSITION RACE: concurrent installChildSA: or migrateChildSA: writes to either list during
    #   enumeration → new SA added mid-loop deleted (premature teardown) or loop terminates early
    #   leaving old SAs installed (dangling kernel SAs). Both loops are affected independently.
    'NEIKEv2Session.uninstallAllChildSAs':                          0xf7395,
    # Traffic selector reporting for a ChildSA. r12=self; rdx=ChildSA → retain → r13.
    # r13 nil → 0xf7860: isKindOfClass(0x11) guard (standard nil path).
    #
    # THREE READS FROM ChildSA (r13):
    #   [r13 sel@0x1d15d2] → eax stored [rbp-0x34] (TS type/count integer)
    #   [r13 sel@0x1d1714] → retain → [rbp-0x30] (initiator traffic selectors)
    #   [r13 sel@0x1d1704] → retain → [rbp-0x40] (responder traffic selectors)
    #   No lock between reads — concurrent ChildSA modification → inconsistent TS snapshot.
    #
    # BLOCK BUILD @ 0xf77a4: isa=[rip+0x1698c4], flags=0xc2000000, invoke@0xf7894
    #   Captures: self(r12), ChildSA property (rbx), TS-type-int(eax), initTS, respTS
    #   Block passed as completion handler to reporting call.
    #
    # BLOCK INVOKE @ 0xf788e: gate predicate @ 0xf78a7
    #   [self sel@0x1d354f] → al; al!=0 → return immediately (report silently suppressed!)
    #   al==0 → report: esi=[rbx+0x40](TS count); rdi/rdx/rcx = TS data from captures
    #   → vtable call: jmp [rdi+0x10]
    #   TOCTOU: TS snapshot taken at block-build time; predicate check at invoke time (async).
    #   If TS changes between capture and invoke, reported TS does not match live SA state.
    'NEIKEv2Session.reportTrafficSelectorsForChildSA:':             0xf76c6,
    # Child SA reset. r14=self; rdx=ChildSA → retain → rbx. Short body (~60 insns).
    # error ctx @ 0xf7d32 (0x1f3dec); isKindOfClass(1) @ 0xf7d53 (esi=1, NOT 0x11 or 0 —
    #   checks ChildSA type against class ID 1; je 0xf7d97 skips log if wrong type).
    # log flag 0x8400202 @ 0xf7d60 (4th occurrence — all delete/reset paths share this flag).
    #
    # RESET DISPATCH (two sequential unlocked calls):
    #   0xf7da0: [r14(self) sel@0x1d2209:rbx(ChildSA)] ← reset ChildSA state on self
    #   0xf7dbe: [rbx(ChildSA) sel@0x1d0fea]           ← clear something on the ChildSA itself
    #   No lock between the two calls; concurrent installChildSA: or migrateChildSA: between them
    #   → ChildSA partially reset: first clear done, second not yet → inconsistent SA state.
    'NEIKEv2Session.resetChild:':                                   0xf7d08,

    # ── NEIKEv2IKESA(Crypto) — PRF+ key derivation (RFC 5996 §2.14) ──────────────
    # SKEYSEED = prf(Ni|Nr, g^ir)  [initial]
    # SKEYSEED_rekey = prf(SK_d(old), g^ir(new) | Ni | Nr)
    # {SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr} = prf+(SKEYSEED, Ni|Nr|SPIi|SPIr)
    #
    # r13=self (NEIKEv2IKESA crypto object).
    # FOUR SEQUENTIAL NIL-GUARDED PROPERTY READS (0x9571a-0x957c5):
    #   [self sel@0x2335af] → bail 0x965cf  (crypto param A — Ni or g^ir)
    #   [self sel@0x234145] → bail 0x96601  (crypto param B)
    #   [self sel@0x2340d8] → bail 0x96633  (crypto param C)
    #   [self sel@0x2340b3] → bail 0x96665  (crypto param D)
    #   *** ALL FOUR READS UNPROTECTED — no lock between reads ***
    #   Concurrent modification of any property between reads produces inconsistent
    #   keying material (partial-old, partial-new SKEYSEED input).
    #
    # PRF OBJECT CREATION @ 0x957cb (KEY MOMENT — created with NO KEY):
    #   rdi=[rip+0x237a6e] (PRF implementation class); sel@0x233ef7; edx=0; ecx=0
    #   [PRFClass sel@0x233ef7:0:0] → r14 (PRF context — no key bound yet)
    #   test r14; je 0x959c0 (bail if PRF alloc failed)
    #
    # NONCE LOADS @ 0x957ef-0x95830:
    #   [self sel@0x234068] → rbx (Ni obj); [rbx sel@0x23361a] → r14 (Ni bytes); stored [rbp-0x80]
    #   [self sel@0x233fd0] → rbx (Nr obj); ... → stored [rbp-0x78]
    #
    # PRF INPUT ACCUMULATION (SPI / nonce blocks, ecx=8 stride):
    #   0x958e5: [r12 sel@0x232048:[rbp-0x80]:ecx=8] ← set 8-byte input block A (Ni or SPIi)
    #   0x958fe: [r12 sel@0x232048:[rbp-0x78]:ecx=8] ← set 8-byte input block B (Nr or SPIr)
    #
    # FIRST SKEYSEED READ @ 0x9591b:
    #   sel@0x2333c8 → [self sel] → retain → r14 (SKEYSEED seed object or SK_d)
    #   [r14 sel@0x233f50] → rbx (derived sub-component); [rbx sel@0x230d20] → [rbp-0x48]
    #
    # SECOND SKEYSEED READ @ 0x95963 (TOCTOU):
    #   sel@0x2333c8 → [self sel] → retain → r15 (SAME SELECTOR, SECOND READ)
    #   *** If self.sKeySeed mutated between 0x9591b and 0x95963 (e.g., concurrent
    #       IKE rekey completing), r14 and r15 reference DIFFERENT SKEYSEED objects.
    #       PRF+ input is split: first half derived from old SKEYSEED, second from new.
    #       Result: SK_ei/SK_er are NOT derived from the IKE SA that both peers agreed on.
    #
    # PRF KEY BIND @ 0x9596f:
    #   [self sel@0x233f2a] → r14 (PRF key — g^ir for initial, SK_d(old) for rekey)
    #   [r14 sel@0x233d9b] → test al; je 0x959f5 (hasOutputLength check)
    #
    # NULL PRF KEY RACE:
    #   PRF object created at 0x957cb with no key. PRF key loaded at 0x9596f from self.
    #   If another thread nulls the key property between these two points:
    #   [PRFClass sel@0x233ef7:0:0] created → key property zeroed → PRF(NULL_key, S|i)
    #   NULL-keyed HMAC-SHA1 output is predictable (fixed-key PRF → attacker can
    #   reproduce SK_d/SK_ei/SK_er offline given Ni, Nr, SPIi, SPIr from the IKE exchange).
    #
    # PRF+ OUTPUT LOOP SETUP @ 0x959a7:
    #   [rbp-0x40]=0 (T_0 empty block), [rbp-0x50]=sel@0x233e1c (T-counter selector)
    #   jmp 0x95a64 — enter RFC 5996 §2.13 PRF+ loop
    #   Derives in sequence: SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
    #   SK_ei and SK_er feed installChildSA: (encryption keys for IPsec kernel SAs)
    'NEIKEv2IKESA(Crypto).calculateSKEYSEEDDerivatives':           0x95706,
    # IKE rekey PRF computation. r15=self; rdx=g^ir(new) → retain → [rbp-0x30].
    # RFC 5996 §2.18: SKEYSEED_rekey = prf(SK_d(old), g^ir(new) | Ni | Nr)
    # Structurally isomorphic to calculateSKEYSEEDDerivatives — same 4-read + double-fetch pattern.
    #
    # FOUR SEQUENTIAL NIL-GUARDED READS @ 0x950cf-0x95149 (NO LOCK):
    #   [self sel@r13]     → rbx; je 0x95670   (SK_d(old) or crypto param A)
    #   [self sel@0x234754] → rbx; je 0x956a2  (crypto param B — Ni or g^ir component)
    #   [self sel@0x23472f] → rbx; je 0x956d4  (crypto param C — Nr component)
    #   (4th at 0x9514f: r14=sel@0x23835a; r12=msgSend cached ptr)
    #   *** Concurrent IKE SA teardown nulling any property between reads →
    #       inconsistent keying input (partial-old, partial-new SKEYSEED_rekey input)
    #
    # KEY MATERIAL ASSEMBLY @ 0x95163-0x9526a:
    #   [r15 sel@r13:...] — read SK_d(old) components
    #   [rax sel@0x2343d8] — transform step on SK_d
    #   [rax sel@0x233d90] — extract key bytes
    #   [r14 sel@0x23466b:rax] → r14 — bind key material to PRF object
    #   Length extraction loop: [r14 sel@0x2344e9] → edx → [self sel@0x23462a/0x234616:edx]
    #     stores SK_ei_len @ [rbp-0x48], SK_er_len @ [rbp-0x40]
    #   Nonce reads: [self sel@0x23464b] → rbx (Ni), [self sel@0x23463b] → r15 (Nr)
    #   SKEYSEED_rekey derivation: 6-arg call at 0x9526a →
    #     prf+(SKEYSEED, Ni|Nr|SPIi|SPIr) → retain → r15
    #   nil check at 0x95281 (je 0x95418) — bail if derivation returns nil
    #
    # NULL SK_d(old) RACE (EXTENDS calculateSKEYSEEDDerivatives NULL-PRF-KEY RACE):
    #   At 0x9529c: [class sel@0x234438:0:0] → r14 (new PRF ctx, NO key bound yet)
    #   At 0x952a5: cmp [rbp-0x30], 0 → je 0x95451 (nil g^ir(new) check)
    #   test r14; je 0x955bf (nil PRF alloc bail)
    #   At 0x952bc/0x952c9: bind SKEYSEED_rekey (r15) as PRF key
    #   Race window: from [class sel@0x234438:0:0] to bind — if concurrent teardown
    #   nulls SK_d(old) after the 4-read block but before the bind:
    #   prf(NULL_key, g^ir(new) | Ni | Nr) → predictable SKEYSEED_rekey
    #   → attacker derives all rekeyed {SK_d_new, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr}
    #   offline from observed IKE exchange parameters.
    'NEIKEv2IKESA(Crypto).calculateSKEYSEEDForRekey:':             0x950a4,
    # DH local value generation. r12=self.
    # r13 = DH group object from self; r14 = msgSend cached ptr.
    # NIL DH GROUP @ 0x949ed: je 0x94b02 → error path; isKindOfClass(esi=0x10, not 0x11)
    #   Note: esi=0x10 here vs esi=0x11 (NEIKEv2ChildSA) on all other nil paths — different class check.
    #
    # DH GROUP VALIDITY PREDICATE @ 0x94a30-0x94a43:
    #   [r13 sel@0x234de9:rbx(len_a):rax(len_b)] → test al; je 0x94b3b
    #   Lengths extracted twice from DH group object at 0x94a03 (sel@0x234e03:edx) and 0x94a1b (sel@0x234df0:edx).
    #   If predicate returns 0 (invalid group/lengths inconsistent) → abort: DH object on self unchanged.
    #   Concurrent call with different DH group wins on the self store race (below).
    #
    # DH CONTEXT BUILD @ 0x94a4b-0x94af5 (SUCCESS PATH):
    #   [r13 sel@0x234c76] → retain → rbx (DH context object containing private key material)
    #   [r13 sel@0x231e76] → rax; [self sel@0x2342f1:rax] — bind DH input param
    #   [r13 sel@0x234c61:0] — zero old state on DH group object
    #   [r13 sel@r15] → retain → rbx (re-read DH params after zero)
    #   [self sel@0x23429e:rbx] ← STORE DH component A on self (NO LOCK)
    #   [r13 sel@0x234d49] → rax; [self sel@0x234284:rax] ← STORE DH component B on self (NO LOCK)
    #   Concurrent generateLocalDHValues: second write overwrites first → first caller holds stale
    #   local DH values; SKEYSEED derived from mismatched DH public/private components.
    #
    # ACTUAL KEY GENERATION: inside DH group object methods (not visible at this level).
    #   Entropy source (SecRandomCopyBytes vs /dev/urandom) resides in DH group implementation.
    'NEIKEv2IKESA(Crypto).generateLocalDHValues':                   0x9498d,
    # Nonce generation. r14=self. Very short (~54 bytes, 0x94bcc-0x94c80).
    # READ NONCE LENGTH @ 0x94be8-0x94c09:
    #   [self sel@0x231d47] → retain → rbx (nonce obj); [rbx sel@0x234743] → r15d (length); release rbx
    #
    # MINIMUM LENGTH ENFORCEMENT @ 0x94c0f:
    #   `cmp r15d, 0xf; ja 0x94c43` (unsigned) — NONCE MUST BE > 15 (≥ 16 bytes = 128 bits)
    #   ≤ 15 → error path at 0x94c15: 0x1f3dec alloc → isKindOfClass(0x11) → error or no-op
    #   RFC 7296 §2.10: nonce MUST be ≥ 128 bits — this check correctly enforces the minimum.
    #   RISK: configured nonce length of exactly 16 bytes passes; RFC recommends ≥ 256 bits.
    #         If NE configuration accepts nonce_len=16, connections use minimum-compliant entropy.
    #
    # NONCE CREATION @ 0x94c43:
    #   [nonce_class sel@0x234aef:r15d] → rbx (alloc nonce of configured length)
    #   [self sel@0x2340ef:rbx] (store on self); release rbx; return 1
    #   Entropy source is in the nonce class method — not visible at this level.
    'NEIKEv2IKESA(Crypto).generateLocalNonce':                      0x94bcc,
    'NEIKEv2IKESA(Crypto).fetchLocalCertificateIdentity':           0x94c8e,
    'NEIKEv2IKESA(Crypto).generateLocalValues':                     0x966db,
    # Rekey readiness predicate (~30 insns, 0x9672c-0x96768). rbx=self.
    # TWO SEQUENTIAL BOOLEAN READS, SHORT-CIRCUITS ON FALSE:
    #   0x96735: [self sel@0x23321c] → al; je 0x9675d → return 0 (DH not ready?)
    #   0x96746: [self sel@0x233213] → al; setne al (nonce not ready?)
    #   Returns 1 only if BOTH properties are truthy.
    # Likely called before sending a rekey proposal to confirm local values are prepared.
    # No evident race surface in the predicate itself; risk is at the values it checks.
    'NEIKEv2IKESA(Crypto).generateAllValuesForRekey:':              0x9672c,
    # PSK auth data computation. r14=self; rdx=shared_secret(PSK)→r13; rcx=octets→r12.
    # NIL PSK @ 0x9853c: je 0x98673 → error (esi=0x11); nil octets @ 0x98545: je 0x9869e → error (esi=0x11)
    # nil PRF config @ 0x98576: je 0x986c9 → error (esi=0x11)
    #
    # DOUBLE-READ OF PRF CONFIG @ 0x98556 / 0x9858a (TOCTOU):
    #   0x98556: [r14(self) sel@0x23077a] → retain → rbx  ← READ 1 (test rbx → nil bail 0x986c9)
    #   0x9858a: [r14(self) sel@0x23077a] → retain → rbx  ← READ 2 (same selector)
    #   Window: concurrent IKE renegotiation modifies self's PRF configuration between reads →
    #   first rbx is released; second read's PRF object is used for auth computation.
    #   If the PRF type changes (e.g., SHA1→SHA256 during concurrent reauth), auth data is computed
    #   with a different PRF than the IKE SA was set up with → auth verification failure
    #   or mismatch between initiator/responder auth computation.
    #
    # AUTH COMPUTATION @ 0x9862f:
    #   [r15(PRF_obj) sel@0x23138d:rbx(PSK):r12(octets):rax(extra_component)] → r15
    #   MAC/PRF output: prf(PSK, data_to_authenticate | signed_octets) per RFC 7296 §2.15
    #   Returns auth data object; r15=nil on any error.
    'NEIKEv2IKESA(Crypto).createAuthenticationDataForSharedSecret:octets:': 0x98509,
    # IKEv2 initiator signed-octets construction (RFC 7296 §2.15 / §2.6). r12=self.
    # FOUR NIL-GUARDED READS (same unprotected pattern as calculateSKEYSEEDDerivatives):
    #   [self sel@0x23100e], [self sel@0x230e8c], [self sel@0x230f17], [self sel@0x2302aa]
    #   Any nil → esi=0x11 error. No lock between reads; all four reference self properties.
    #
    # CONDITIONAL SELECTOR @ 0x98a7c:
    #   [r12 sel@0x230373] → al; je 0x98a87
    #   al!=0 → sel@0x230f33; al==0 → sel@0x230f32 (selects nonce variant for assembly)
    #
    # SIGNING CONTEXT @ 0x98c03 (NULL-KEY RACE — same pattern as calculateSKEYSEEDDerivatives):
    #   [class sel@0x230ad1:0:0] → r14  (MAC/signing context allocated with NO key arg)
    #   key bound via [r14 sel@0x22ecf5:rbx] in next instruction
    #   Race window: concurrent teardown nulls key before bind → null-keyed signing context
    #   → null-keyed MAC over signed octets → AUTH payload built with a predictable HMAC.
    #
    # OUTPUT: MACedIDForI per RFC 7296 §2.15 — feeds into createInitiatorAuthenticationData
    #   and ultimately into the initiator AUTH payload. Null-keyed version is reproducible offline.
    'NEIKEv2IKESA(Crypto).createInitiatorSignedOctets':             0x98987,
    # IKEv2 responder signed-octets construction. Symmetric counterpart to createInitiatorSignedOctets.
    # r15=self. Same structure: four nil-guarded reads, NSMutableData assembly, null-key signing context.
    #
    # FOUR NIL-GUARDED READS @ 0x98ebd, 0x98eea, 0x98f17, 0x98f47 (esi=0x11 on nil).
    #
    # MAC CONTEXT @ 0x9906a (NULL-KEY RACE — identical to initiator path):
    #   [class sel@0x230666:0:0] → r13  (xor edx,ecx → edx=0 → class alloc, NO key arg)
    #   key bound @ 0x9907c: [r13 sel@0x22e886:rbx]
    #   Same race window; null-keyed responder signed octets composable with null-keyed initiator.
    #
    # BLOCK LITERAL @ 0x9b854: `mov eax, 0xc2000000` (standard _NSConcreteStackBlock flags)
    #   invoke pointer @ 0x9b864 — block used in the 5-arg assembly call @ 0x99035.
    'NEIKEv2IKESA(Crypto).createResponderSignedOctets':             0x98e85,
    # Initiator auth data construction. r12=self.
    # PROPERTY READS @ 0x9b0a1 / 0x9b0cb / 0x9b0e7 — three from self before dispatch:
    #   [self sel@0x22dc28] → rbx; nil → je 0x9b2d4 (esi=0x11 error)
    #   [self sel@0x22e91e] → r14; nil → je 0x9b18b (esi=0x11 error)
    #   [self sel@0x22de8a] → retain → r15; [r15 sel@0x22ddb4] → rax (auth type integer)
    #
    # AUTH TYPE DISPATCH @ 0x9b111:
    #   `cmp rax, 2; jne 0x9b1bd`
    #   rax == 2 → PSK / shared-secret path (RFC 7296: auth method 2 = Shared Key Message Integrity Code)
    #   rax != 2 → cert or EAP path at 0x9b1bd
    #
    # PSK PATH (rax==2) @ 0x9b11b:
    #   [self sel@0x22c0d6] → retain → r13 (PSK object)
    #   [self sel@0x22e8e7:r13(PSK):r14(nonce?)] → rbx
    #   ← chains into createAuthenticationDataForSharedSecret:octets: (TOCTOU risk inherited)
    #   test rbx; jne 0x9b2a6 (success: release, return rbx)
    #
    # CERT/EAP PATH @ 0x9b1bd:
    #   [r15 sel@0x22e864] → al; je 0x9b21b (not cert → non-cert branch)
    #   CERT (al!=0): [self sel@0x22e858:r14] → rax; test → jne 0x9b247 (cert auth data)
    #   NOT-CERT @ 0x9b21b: [r15 sel@0x22e816] → al; je 0x9b24c (third type check)
    #
    # TOCTOU ON AUTH TYPE: r15 (auth method obj) and r14 (nonce/octets) read from self
    # before the cmp-rax-2 dispatch. Concurrent renegotiation changing auth method:
    #   PSK→cert: r14 was bound for cert path, PSK dispatch runs → wrong octets in PSK HMAC.
    'NEIKEv2IKESA(Crypto).createInitiatorAuthenticationData':       0x9b090,
    # Responder AUTH data construction. Mirror of createInitiatorAuthenticationData. r15=self.
    #
    # AUTH TYPE DISPATCH @ 0x9b384 (IDENTICAL PATTERN to initiator @ 0x9b111):
    #   `cmp rax, 2; jne 0x9b430`
    #   rax==2 → PSK path: [self sel@0x22be63] → r13(PSK); [self sel@0x22e674:r13:r14] → rbx
    #   ← chains into createAuthenticationDataForSharedSecret:octets: (TOCTOU risk inherited)
    #   rax!=2 → cert path @ 0x9b430: [r15 sel@0x22e5f1] → al; je 0x9b48e (EAP/other check)
    #           cert (al!=0): [self sel@0x22e5e5:r14] → rbx
    #   not-cert @ 0x9b48e: [r15 sel@0x22e5a3] → al; je 0x9b4bf
    #           other (al!=0): [self sel@0x22e597:r14] → rbx
    #
    # TOCTOU: auth method object (r15) read before dispatch; concurrent renegotiation changing
    # auth method → PSK dispatch with cert octets, or cert dispatch with PSK octets.
    # Initiator and responder use symmetric dispatch; both carry the same auth-type race.
    'NEIKEv2IKESA(Crypto).createResponderAuthenticationData':       0x9b303,
    # Non-certificate auth data verification. r12=self; rdx=auth_data → retain → r14.
    # THREE NIL-GUARDED PROPERTY READS (0x9b5a6, 0x9b5c9, 0x9b5d3 — all from self):
    #   rbx: nil → 0x9b710 (esi=0x11); r15: nil → 0x9b742 (esi=0x11)
    #
    # AUTH-TYPE GATE @ 0x9b5f4:
    #   [r15 sel@0x22e434] → test al; je 0x9b634 (al==0: not cert-type, proceed)
    #   al==1 → 0x9b601: error immediately (caller passed cert auth data to non-cert checker)
    #
    # PSK SUBPATH @ 0x9b634:
    #   [r15 sel@0x22e3fd] → al; je 0x9b660 (al==0: not PSK either)
    #   al==1: [r12 sel@0x22e3f9:r14] → r13d (PSK verification); return r13d
    #
    # CMOVE SELECTOR DISPATCH @ 0x9b660-0x9b6a4:
    #   [r12(self) sel@0x22d781] → al  (runtime boolean read from self)
    #   `cmove rcx, rax` at 0x9b683: selects between sel@0x22e3cd (al==0) or sel@0x22e3dc (al!=0)
    #   [r12 sel(chosen)] → r12_new (reads WHICH auth method object to use based on runtime state)
    #   [r12_new sel@0x22bf17:r14(auth_data)] → r13d (actual verification call)
    #
    # CMOVE RACE: if self's state property (sel@0x22d781) changes between 0x9b66e read and
    # the cmove at 0x9b683 (e.g., concurrent auth config update), wrong verification method
    # selected → valid auth data rejected, or wrong-method data accepted (auth bypass).
    'NEIKEv2IKESA(Crypto).checkNonCertAuthData:':                   0x9b576,
    # EAP initiator AUTH data construction. r13=self. Parallel structure to createInitiatorAuthenticationData.
    # THREE NIL-GUARDED PROPERTY READS (no lock between reads):
    #   [self sel@<r15>] → rbx; nil → 0x9bdfc (esi=0x11 guard)
    #   [self sel@0x22d04b] → rbx; nil → 0x9be27 (esi=0x11 guard)
    #   [self sel@0x22dd3e] → r14; nil → 0x9bd71 (esi=0x11 guard) — likely MSK/EAP session key
    #
    # DOUBLE-READ ON FIRST SELECTOR @ 0x9bc51 / 0x9bcd1 (TOCTOU):
    #   READ 1: [self sel@<r15=rip+0x22de20>] → rbx ← first property
    #   READ 2: [self sel@<r15>] → rbx (SAME selector, second read)
    #   [rbx sel@0x22dd97] → r12 (sub-property from READ 2)
    #   Concurrent EAP negotiation state change between reads → r12 derived from different session
    #   state than r14 (MSK) → EAP auth computed with mismatched components.
    #
    # AUTH COMPUTATION @ 0x9bd28: [self sel@0x22dcf1:r12:r14] → r15 (4-arg EAP MAC call)
    #   Returns r15 or nil on failure. Three release paths before return.
    'NEIKEv2IKESA(Crypto).createInitiatorEAPAuthenticationData':    0x9bc40,
    # EAP responder AUTH data construction. Structurally IDENTICAL to initiator EAP version.
    # r13=self. Same 3 nil-guarded reads + double-read on first selector + 4-arg MAC call.
    #
    # THREE READS: sel@<r15=[rip+0x22dc09]>, sel@0x22ce34, sel@0x22db1f
    # DOUBLE-READ ON FIRST SELECTOR @ 0x9be72 / 0x9beeb (different selector constant from initiator)
    # AUTH COMPUTATION @ 0x9bf3f: [self sel@0x22dada:r12:r14] → r15
    # Carries same TOCTOU risk as initiator path; initiator/responder double-reads use different
    # selector addrs but identical control flow — the same concurrent-state race applies to both.
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
    # Primary IKE message encryption dispatch. 7 args: data, algorithm, key, iv, encCtx, aad, padToKey.
    # PROLOGUE: retains all 6 ObjC args (algorithm, key, iv, encCtx, aad, padToKeyLength) via r13 fn ptr.
    # FOUR NIL GUARDS: iv (0x937d8), encCtx (0x937e5), algorithm (0x937eb), key (0x937fd).
    #
    # ALGORITHM CONSISTENCY CHECKS (two sequential comparisons, both required to pass):
    #   0x93833: [iv sel@0x232e57] == [key sel@0x235fa5]; jne 0x9395e (esi=0x11 error)
    #   0x9385b: [encCtx sel@0x232e57] == [key sel@0x235e60]; jne 0x93990 (esi=0x11 error)
    #   If algorithm properties of iv/encCtx don't match key's expected values → error.
    #   These checks validate input consistency but do NOT validate the algorithm against policy
    #   (no DES-forbidden check here; policy enforcement absent in receiveRekeyIKESA: path).
    #
    # CBC PADDING @ 0x9386c-0x93928 (entered if padDataToKeyLength==true):
    #   pad_size = ceil(data_len, block_size) - data_len (PKCS-style)
    #   computed: [encCtx.length] % [key.length + 1] → stored [rbp-0x31]
    #   calloc at 0x1f3d80 + memset equivalent at 0x1f39f0 for padding buffer
    #   Applies to CBC-mode ciphers; no-padding path at 0x939c2.
    #
    # CIPHER DISPATCH @ 0x939f4:
    #   [key sel@0x235d4a] → al; jne: AES/CBC path (al!=0 → GCM/AEAD wrapper)
    #   je 0x93abb: non-AES path → [key sel@0x235436] → rax; cmp rax, 0x1c; jne 0x93bd8
    #     0x1c path: ChaCha20-Poly1305 (or GCM constant = 28 in NE's internal type numbering)
    #     0x93bd8 path: DES/3DES or other legacy cipher — this is where ENCR_DES (type 2) lands
    #       after the downgrade chain delivers a DES-keyed encCtx from installChildSA:.
    #
    # ENCR_DES IN USER-SPACE: The kernel SA handles IPsec data-plane DES; IKE control messages
    #   also traverse this function. If the IKE SA itself is DES-keyed (IKE SA downgrade via
    #   receiveRekeyIKESA:), subsequent IKE_AUTH and INFORMATIONAL exchanges use DES encryption
    #   here (0x93bd8 path) — the attacker can decrypt ALL subsequent IKE exchanges.
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
    # EAP module selector. r12=self; rdx=payload → retain → r15; rcx=ikeSA → retain → r13.
    # Stack canary @ 0x9da60. Either arg nil → 0x9eaa8/0x9ead3 (error exits).
    #
    # TWO-LEVEL DISPATCH:
    #   OUTER @ 0x9daa0: [class sel@0x22c031:r15(payload)] → eax; cmp eax, 1; jne 0x9dc60
    #     eax==1: EAP-Request/Response inner path (reads ikeSA property and subtype)
    #     eax!=1: 0x9dc60 error context; isKindOfClass(0x10) — class 16 (NOT 0x11)
    #
    # INNER LOOP FOR eax==1 (NSFastEnumeration over EAP module registry):
    #   Reads subtype from payload; [ikeSA sel@0x22b1e8] → retain → r14 (module list)
    #   cmp r13d, 1; je 0x9dd12 (subtype==1 skips the loop — EAP-Identity shortcut)
    #   Loop: [objects[r15] sel@0x228daf] → eax; cmp eax, [rbp-0xc0](saved subtype)
    #     je 0x9dca8 (MATCH: [self sel@0x229109:matched_module] — module selected)
    #     No match: inc, continue until end; → 0x9dcc2 (no matching module)
    #   No list lock during enumeration — concurrent EAP renegotiation modifying module list
    #   during this loop → module skipped or stale module selected.
    #
    # ERROR DISCRIMINATOR: class 0x10 in non-type-1 path vs class 0x11 in nil-guard paths.
    # The 9 paths (GTC/MSCHAPV2/TLS/TTLS/PEAP/LEAP/FAST/MD5/Identity) map to the 9 registered
    # modules scanned by this NSFastEnumeration.
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
    # Args: rdi=peer_addr_str, esi=2(AF_INET), edx=1(proto), rcx=format_arg, r8=flow_obj.
    # COMPLETE WRITE CHAIN (end-to-end):
    #   _writeUDPDatagramToFlow (0x10005da06) — trace log check (cmp esi,3), va_list format
    #     ↳ 0x10005db2c (addr-prefix router):
    #         addr string checked against prefix constants via 0x10009b306 (prefix match fn)
    #         prefix match A → 0x10005e1e4 (handle setup path)
    #         prefix match B → tail-call 0x10009b384 (alt write)
    #     ↳ 0x10005e1e4 (handle setup):
    #         0x10009adb4(edi=0, rsi=data, edx=0x8000100) → handle
    #         0x10009adba(edi=0, esi=0, rdx=handle, rcx=extra) → write_obj
    #         0x10005e2cc(rdi=write_obj, rsi=output_struct, rdx=flags=0x801) → BOOL ← ACTUAL WRITE
    #         log: 0x10009b2f4(rdi=buffer, rdx=flags=0x801) on success
    #     ↳ 0x10005dbaa (secondary chunked path, called at 0x10005daff):
    #         Args: edi=2(AF_INET), esi=1(proto), rdx=data_string
    #         Swift string ABI: byte[0]&1 = large string (heap ptr), else inline (shr rbx,1)
    #         1000-byte chunk loop (r14 = r15 + 0x3e8): 0x10005dc7e-0x10005dd18
    #         chunk boundary detection: '\n'(0x0a) @ 0x10005dcc9, ' '(0x20) @ 0x10005dce7
    #         per-chunk append: 0x10009ae50/ae5c/ae68 (Swift stdlib string ops)
    'DNSProxyProvider._writeUDPDatagramToFlow':                           0x10005da06,
    'DNSProxyProvider._write_addr_prefix_router':                         0x10005db2c,
    'DNSProxyProvider._write_handle_setup':                               0x10005e1e4,
    'DNSProxyProvider._write_actual_ne_flow_write':                       0x10005e2cc,
    'DNSProxyProvider._write_chunked_path':                               0x10005dbaa,
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

    def install_child_sa(self, count=450):
        """Disassemble NEIKEv2Session.installChildSA: @ 0xee682.
        Maps keying material write into kernel SA object and cipher dispatch.

        Key material write sequence (sequential, no atomic commit):
          [self sel@0x1dac75] → enc_key_obj → [enc_key_obj sel@0x1db518] → auth_key_bytes
          0xeea32: [r12 sel@0x1d9704:auth_key]    <- AUTH KEY WRITE TO KERNEL SA
          [self sel@0x1dac20] → iv_obj → [iv_obj sel@0x1db722] → iv_salt_bytes
          0xeea95: [r12 sel@0x1d96ad:iv_salt]     <- IV/SALT WRITE TO KERNEL SA

        Cipher dispatch at 0xeeaf5 on childSA.encAlgID (IKEv2 transform type):
          2  → ENCR_DES (56-bit — silently accepted; downgrade target)
          3  → ENCR_3DES
          12 → ENCR_AES_CBC (key size enum check)
          20 → ENCR_AES_GCM_16
          28 → ENCR_CHACHA20_POLY1305
          else → unsupported/fallback @ 0xeef41

        DOWNGRADE: no policy enforcement on encAlgID before dispatch.
        MitM IKE_SA_INIT to substitute DES (2) for AES-CBC (12) → 56-bit key installs silently.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.installChildSA:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def initiate_rekey_ikesa(self, count=250):
        """Disassemble NEIKEv2Session.initiateRekeyIKESA @ 0xa9463.
        Maps IKE SA rekey initiator — near-identical to initiateConnect structure.

        State guard at 0xa94c8 (sel@0x2209d1): bail if already rekeying (no double-rekey).
        Rekey SA proposal built via [RekeyClass sel@0x220984:current_SA] at 0xa9567.
        Same block-capture pattern as initiateConnect:
          [self sel@0x2205d1:rekey_SA_proposal:1:block] at 0xa95e5 = REKEY SA_INIT SEND
        edx=3 error convention confirmed at 4 branches (0xa9620/0xa96e4/0xa978d/0xa983a).
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.initiateRekeyIKESA')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def receive_rekey_ikesa(self, count=280):
        """Disassemble NEIKEv2Session.receiveRekeyIKESA: @ 0xa9cf6 — responder downgrade surface.
        Creates new IKE SA from PEER'S PROPOSAL with no cipher-suite policy enforcement.

        Compatibility check at 0xa9dff: [incoming sel@0x220107:current_SA] → if mismatch, SPI path.
        New IKE SA built at 0xa9e2a: [NEIKEv2IKESAClass sel@0x2200d0:incoming:current_SA]
        No validation of cipher suite — if incoming proposes ENCR_DES (type 2),
        new_IKESA is DES-keyed. installChildSA: cipher dispatch at 0xeeaf5 then silently installs
        56-bit key. Full downgrade chain: MitM rekey → propose DES → responder accepts → DES installed.

        SPI mismatch path at 0xaa008: rol bx,8 byte-swap → [class sel@0x21fddf:0x11:r14:SPI_data]
        (same SPI byte-swap pattern as receiveConnection: rol r12w,8 at 0xa5230).
        edx=3 error convention confirmed at 0xa9ef6.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.receiveRekeyIKESA:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def skeyseed_derivatives(self, count=200):
        """Disassemble calculateSKEYSEEDDerivatives @ 0x95706 — PRF+ key derivation TOCTOU.
        Derives {SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr} = prf+(SKEYSEED, Ni|Nr|SPIi|SPIr).

        Four sequential unprotected property reads (0x9571a-0x957c5): Ni/Nr/g^ir/SPI.
        PRF object created at 0x957cb with NO KEY — key bound at 0x9596f.
        SKEYSEED loaded twice (0x9591b and 0x95963, same selector@0x2333c8) without lock.

        Race scenarios:
          a) TOCTOU on SKEYSEED: concurrent rekey completing → r14/r15 reference different
             SKEYSEED objects → SK_ei/SK_er derived from split (old+new) SKEYSEED input.
          b) NULL PRF key: zero key property between PRF alloc (0x957cb) and key bind (0x9596f)
             → PRF(NULL_key, S|i) is predictable → all 7 derived keys reconstructable offline.

        PRF+ loop at 0x959a7: T_0=empty, counter sel@0x233e1c, derives keys in sequence.
        SK_ei and SK_er from this loop feed NEIKEv2Session.installChildSA: kernel SA install.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).calculateSKEYSEEDDerivatives')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def uninstall_child_sa(self, count=200):
        """Disassemble NEIKEv2Session.uninstallChildSA: @ 0xf7161 — SA list iterator race.
        Iterates kernel SA entries in a loop with NO LOCK on the SA list.

        Kernel SA lookup at 0xf7238-0xf725c:
          [self sel@0x1d3b98] → SA list; [self sel@0x1d401a:list:ChildSA] → SA info

        Removal loop at 0xf7273 (iterates while r14 != nil, jne 0xf7289):
          per-iteration: [r15 sel@0x1d3ffe:entry:ChildSA] + [sel@0x1cf5fb:0:ChildSA] removals
          [self sel@0x1d3acc] → next entry → loop

        Iterator invalidation: concurrent installChildSA: modifying the same SA list
        → either new SA deleted (premature teardown) or old SA entries leak (stale keying).

        Nil ChildSA path at 0xf736d: isKindOfClass(0x11) check → error or no-op.
        Stack canary checked at 0xf7355/0xf7358, smash handler at 0xf7390.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.uninstallChildSA:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def receive_rekey_child_sa(self, count=280):
        """Disassemble NEIKEv2Session.receiveRekeyChildSA:packet: @ 0xa85a6 — child SA downgrade.
        Responder path for child SA rekey. Cipher check at 0xa876e (sel@0x221573 on incoming
        packet) is a value-read, NOT a policy gate — proceeds to new ChildSA build regardless
        of cipher type. Completes the dual-path downgrade attack surface (child SA counterpart
        to receiveRekeyIKESA: @ 0xa9cf6).

        Attack chain: MitM rekey packet with ENCR_DES → cipher read passes → ChildSA built from
        peer proposal at 0xa87d0 → SEND at 0xa87e0 → installChildSA: rbx==2 dispatch to
        0xeec5d (ENCR_DES handler) → 56-bit DES kernel SA for child SA traffic.

        edx=3 error convention confirmed at 0xa88cd (8th function).
        rol r14w, 8 at 0xa898d (4th SPI byte-swap occurrence, network→host order).
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.receiveRekeyChildSA:packet:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def skeyseed_for_rekey(self, count=200):
        """Disassemble calculateSKEYSEEDForRekey: @ 0x950a4 — rekey PRF race.
        Computes SKEYSEED_rekey = prf(SK_d(old), g^ir(new) | Ni | Nr) per RFC 5996 §2.18.
        Structurally isomorphic to calculateSKEYSEEDDerivatives: same 4-read unprotected
        property block and null-PRF-key race window.

        Race: PRF ctx alloc at 0x9529c (no key) → SK_d(old) bind at 0x952bc.
        If concurrent IKE teardown nulls SK_d between alloc and bind:
        prf(NULL_key, ...) → attacker derives all rekeyed SK_ei/SK_er offline
        from observed IKE exchange parameters.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).calculateSKEYSEEDForRekey:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def migrate_all_child_sas(self, count=200):
        """Disassemble migrateAllChildSAs @ 0xf0bcf — bulk MOBIKE migration without lock.
        NSFastEnumeration over all child SAs, calling migrateChildSA: on each (sel@0x1da442).
        No lock on the SA list during enumeration — concurrent modify skips or double-visits SAs.
        Early exit on first failure (je 0xf0ce1 → xor r14d=0) → partial migration state:
        some SAs at new address, some still at old → asymmetric tunnel blackhole.
        Each per-SA call inherits migrateChildSA:'s double-read race.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.migrateAllChildSAs')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def generate_all_values_for_rekey(self, count=40):
        """Disassemble generateAllValuesForRekey: @ 0x9672c — short rekey readiness predicate.
        Reads two boolean properties from self in sequence; returns 1 only if both are truthy.
        Short-circuits on first false. No lock; predicate checks state set by concurrent callers.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).generateAllValuesForRekey:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def create_initiator_auth_data(self, count=200):
        """Disassemble createInitiatorAuthenticationData @ 0x9b090 — auth type dispatch.
        Reads auth type integer from self's auth method object, dispatches:
          rax==2 → PSK path → chains into createAuthenticationDataForSharedSecret:octets:
          rax!=2 → cert (sel@0x22e864 al-check) or EAP path
        TOCTOU: auth method and nonce/octets read from self before dispatch; concurrent
        auth-type change → mismatched inputs to auth computation (wrong PSK HMAC octets).
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).createInitiatorAuthenticationData')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def check_non_cert_auth_data(self, count=200):
        """Disassemble checkNonCertAuthData: @ 0x9b576 — non-cert auth verification.
        Auth-type gate at 0x9b5f4 (al==1 → reject cert-type data immediately).
        PSK subpath at 0x9b634.
        cmove selector dispatch at 0x9b683: branch-free selection between two verification
        method selectors based on runtime self property (sel@0x22d781 → al → cmove rcx,rax).
        If self's state changes between the al read (0x9b66e) and the dispatch, wrong
        verification method selected → auth bypass or false rejection.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).checkNonCertAuthData:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def migrate_child_sa(self, count=200):
        """Disassemble NEIKEv2Session.migrateChildSA: @ 0xefca4 — MOBIKE address migration.
        Double-reads the SA list (sel@0x1d9997, 0xefcdf and 0xefd19) without lock, same
        pattern as install/uninstall. Shares log flag 0x8400302 — unprotected critical region.

        Migration call at 0xefecc: [r12 sel@0x1db13d:new_src:new_dest] uses addresses
        from the incoming ChildSA object without visible peer-identity verification.
        Combined with DES downgrade (IKE SA compromised): attacker-controlled MOBIKE
        UPDATE_SA_ADDRESSES → kernel SA migrated to attacker address → traffic hijack.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.migrateChildSA:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def generate_local_dh_values(self, count=240):
        """Disassemble generateLocalDHValues @ 0x9498d — DH local value generation.
        DH group validity predicate at 0x94a43 (two length args → al test). STORES at
        0x94acb and 0x94af2 both unlocked — concurrent calls: last write wins, first
        caller holds stale DH public/private pair → SKEYSEED derived from mismatched
        DH components. Actual key-generation entropy source is inside the DH group object.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).generateLocalDHValues')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def generate_local_nonce(self, count=80):
        """Disassemble generateLocalNonce @ 0x94bcc — nonce creation with length gate.
        Reads configured nonce length; enforces `cmp r15d, 0xf; ja` (≥ 16 bytes = 128 bits,
        RFC 7296 minimum). Length ≤ 15 → error. Nonce class method at 0x94c54 generates
        the actual bytes — entropy source not visible at this level.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).generateLocalNonce')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def create_auth_data_psk(self, count=220):
        """Disassemble createAuthenticationDataForSharedSecret:octets: @ 0x98509 — PSK auth.
        Double-reads PRF config from self (sel@0x23077a at 0x98556 and 0x9858a) without lock
        — same TOCTOU pattern as calculateSKEYSEEDDerivatives. Concurrent renegotiation changing
        PRF type between reads → auth computed with wrong PRF → auth mismatch.

        Main auth call at 0x9862f: prf(PSK, data_to_auth | signed_octets) per RFC 7296 §2.15.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).createAuthenticationDataForSharedSecret:octets:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def copy_sas_to_delete_install_rekeyed(self, count=200):
        """Disassemble copySAsToDeleteAndInstallRekeyedChildSA: @ 0xf6d4b — double-read SA race.
        Old→new child SA atomic swap. Delete loop at 0xf6dfa reads the SA list TWICE per
        iteration (0xf6e0f and 0xf6e45, same selector sel@0x1d3fb7) with no lock.

        Composes with uninstallChildSA: iterator race:
          concurrent uninstallChildSA: modifies SA list between READ 1 and READ 2 →
          Outcome A: old SA not fully evicted → dangling kernel SA with stale keying.
          Outcome B: double-delete of same entry → UAF / kernel panic risk.
        Race window scales with child SA count (O(N * ~30 insns) per iteration).

        Post-loop install gate at 0xf6e93: [self sel@0x1d2ed6:rekeyed_SA] → al.
        al==0 → install skipped → returns nil (rekeyed SA lost, tunnel continues on old SA).
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.copySAsToDeleteAndInstallRekeyedChildSA:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def initiate_delete_child_sa(self, count=220):
        """Disassemble initiateDeleteChildSA: @ 0xac557 — initiator DELETE path.
        Symmetric to receiveDeleteChildSA: but self-initiated. Double-read TOCTOU on ChildSA
        property sel@0x21c67b at 0xac655 and 0xac680 (no lock); sub-properties r15/r14 fed
        into main delete dispatch at 0xac6bd from mismatched state reads.
        edx=3 at 0xac636 — 10th function with this convention.
        Block literal at 0xac7d4 (flags=0xc2000000): async completion handler.
        Log flag 0x8400202; isKindOfClass(0) at 0xac5cd is dead code.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.initiateDeleteChildSA:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def uninstall_all_child_sas(self, count=200):
        """Disassemble uninstallAllChildSAs @ 0xf7395 — bulk child SA teardown.
        Two separate unlocked NSFastEnumeration loops over two different collection properties
        (sel@0x1d39f2 and sel@0x1d3921): per-item calls sel@0x1d05a0 and sel@0x1d048e
        respectively. Concurrent installChildSA:/migrateChildSA: during either loop →
        premature teardown of new SAs or dangling old SAs. Isomorphic to migrateAllChildSAs
        but applied to uninstall, and running two independent loops without a list lock.
        Log flag 0x8400202; isKindOfClass(0) at 0xf73cd is dead code.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.uninstallAllChildSAs')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def report_traffic_selectors(self, count=200):
        """Disassemble reportTrafficSelectorsForChildSA: @ 0xf76c6 — TS reporting.
        Reads initiator TS (sel@0x1d1714) and responder TS (sel@0x1d1704) from ChildSA,
        captures both in a stack block (flags=0xc2000000, invoke@0xf7894), then calls
        async reporter. Block gate predicate at 0xf78a7: [self sel@0x1d354f] al!=0 silently
        suppresses the report. TOCTOU: TS snapshot at block-build vs TS at async invoke.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.reportTrafficSelectorsForChildSA:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def reset_child(self, count=160):
        """Disassemble resetChild: @ 0xf7d08 — short child SA reset (~60 insns).
        isKindOfClass(1) at 0xf7d53 (type ID 1, not 0x11 — distinct from nil-path checks).
        Two sequential unlocked calls: [self sel@0x1d2209:ChildSA] then [ChildSA sel@0x1d0fea].
        Concurrent installChildSA:/migrateChildSA: between the two → partial reset race.
        Log flag 0x8400202 (4th function sharing this lower-verbosity tier).
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.resetChild:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def create_initiator_eap_auth(self, count=200):
        """Disassemble createInitiatorEAPAuthenticationData @ 0x9bc40 — EAP initiator AUTH.
        Three nil-guarded reads from self (sel@<r15>, sel@0x22d04b, sel@0x22dd3e).
        Double-read TOCTOU on first selector at 0x9bc51/0x9bcd1 — sub-property r12 derived
        from READ 2 (0x9bce2) while MSK r14 is from an earlier read; concurrent EAP state
        change → mismatched inputs to EAP MAC computation at 0x9bd28.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).createInitiatorEAPAuthenticationData')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def create_responder_eap_auth(self, count=200):
        """Disassemble createResponderEAPAuthenticationData @ 0x9be57 — EAP responder AUTH.
        Structurally identical to initiator EAP path with different selector addresses.
        Double-read on first selector at 0x9be72/0x9beeb; 4-arg MAC call at 0x9bf3f.
        Same TOCTOU as initiator; initiator and responder both composable under concurrent EAP.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).createResponderEAPAuthenticationData')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def create_encrypted_data(self, count=240):
        """Disassemble createEncryptedData:algorithm:key:iv:encCtx:aad:padToKey @ 0x9376f.
        Primary IKE control message encryption dispatch. Two algorithm consistency checks
        (0x93833: iv.algorithm==key.expected; 0x9385b: encCtx.algorithm==key.other) before
        CBC padding calculation (PKCS-style at 0x9386c) and cipher dispatch at 0x939f4.
        AES-CBC: al!=0 path. Non-AES: cmp rax, 0x1c at 0x93acb (ChaCha20/GCM id);
        jne 0x93bd8 = DES/3DES path — where ENCR_DES lands after IKE SA downgrade.
        No algorithm-against-policy check: downgraded DES encCtx passes consistency checks
        silently and reaches DES encryption path at 0x93bd8.
        """
        va = NE_1095_140_2_METHODS.get(
            'NEIKEv2Crypto.createEncryptedData:algorithm:key:iv:encryptionContext:aad:padDataToKeyLength:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def select_eap_module(self, count=240):
        """Disassemble selectModuleForPayload:ikeSA: @ 0x9da3c — 9-module EAP dispatcher.
        Outer dispatch: [class sel:payload] → eax; cmp eax, 1 → inner loop or error path.
        Inner: NSFastEnumeration over EAP module registry; per-item: [obj sel@0x228daf] → eax;
        cmp eax, subtype → match → [self sel@0x229109:module]. Subtype==1 (EAP-Identity) skips
        loop. No list lock during enum → concurrent EAP negotiation → module skip/stale select.
        isKindOfClass(0x10) on error (class 16, distinct from 0x11 in nil-guard paths).
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2EAP.selectModuleForPayload:ikeSA:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def create_responder_auth_data(self, count=220):
        """Disassemble createResponderAuthenticationData @ 0x9b303 — responder AUTH construction.
        Mirror of createInitiatorAuthenticationData. Identical `cmp rax, 2; jne 0x9b430` PSK
        dispatch (@ 0x9b384); PSK path chains into createAuthenticationDataForSharedSecret:octets:.
        cert path @ 0x9b430; EAP/other @ 0x9b48e. Same TOCTOU on auth method object: concurrent
        renegotiation → wrong auth type used in responder AUTH payload.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).createResponderAuthenticationData')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def create_initiator_signed_octets(self, count=240):
        """Disassemble createInitiatorSignedOctets @ 0x98987 — MACedIDForI construction.
        Four unprotected nil-guarded reads from self (sel@0x23100e/0x230e8c/0x230f17/0x2302aa).
        Null-key MAC race at 0x98c03: [class sel@0x230ad1:0:0] allocs signing context with no
        key; key bound in next instruction. Race window: concurrent teardown nulls the key →
        null-keyed HMAC over signed octets → predictable AUTH payload offline.
        Output feeds into createInitiatorAuthenticationData → initiator AUTH payload.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).createInitiatorSignedOctets')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def create_responder_signed_octets(self, count=240):
        """Disassemble createResponderSignedOctets @ 0x98e85 — MACedIDForR construction.
        Symmetric counterpart to createInitiatorSignedOctets. Four nil-guarded reads;
        null-key MAC race at 0x9906a: [class sel@0x230666:0:0] alloc, no key, key bound
        at 0x9907c. Block literal at 0x9b854 (flags=0xc2000000, invoke@0x9b864).
        Both initiator and responder null-key races composable.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2IKESA(Crypto).createResponderSignedOctets')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def receive_delete_child_sa(self, count=200):
        """Disassemble receiveDeleteChildSA:packet: @ 0xac247 — child SA DELETE handler.
        Stack canary + retain-check (0x1f3bfa) @ 0xac2a7. Three nil-guards on r14/r12/r13.
        5-arg delete dispatch @ 0xac361: packet SPI flows without visible session-SA-list
        validation — crafted out-of-session SPI may trigger deletion of unrelated SA.
        Log flag 0x8400202 (vs 0x8400302 in install/migrate — lower verbosity tier).
        isKindOfClass(0) @ 0xac3bb is dead code (isKindOfClass:nil always NO).
        edx=3 at 0xac41a — 9th function with this convention confirmed.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.receiveDeleteChildSA:packet:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def codesig_gate(self, count=200):
        """Disassemble _ne_code_sig_gate @ 0x18a2f4.
        Maps the two-stage SecStaticCodeCheckValidity gate and bypass target.

        Stage 1 (0x18a369): creates SecStaticCode from URL/path arg (flags=1).
        Stage 2 (0x18a3bd): SecStaticCodeCheckValidity(code, flags=0, requirement=r15).
        Gate: je 0x18a4a3 at 0x18a3c4 — patches to jmp to bypass validation.

        Bypass options:
          A. 2-byte patch at 0x18a3c4: `74 dd` → `eb dd` (je → jmp unconditional)
          B. Hook GOT[_SecStaticCodeCheckValidity] @ 0x262008 → `xor eax,eax; ret`
        Both require injection into nesessionmanager or NE extension load hook.
        """
        va = NE_1095_140_2_METHODS.get('_ne_code_sig_gate')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def initiate_connect(self, count=320):
        """Disassemble NEIKEv2Session.initiateConnect @ 0xa2c42.
        Maps Phase 1 initiator: SA_INIT dispatch and two-path structure.

        Config-flag branch at 0xa2def (sel@0x226558 BOOL):
          TRUE  → retransmit/reauth path: clock_gettime_nsec_np + [obj sel:3:timestamp]
          FALSE → standard path → [self sel@0x226dfd:r15:rbx] pre-send gate
                  → [self sel@0x226bb6:IKE_SA:1:block] ACTUAL SA_INIT send at 0xa3000

        Block literal at [rbp-0x98] (0xa2fa5-0xa2fc7) captures {self, IKE_SA, connection}.
        Error marker: edx=3 on all failure branches (system-wide NE error convention).
        MOBIKE conditional: sel@0x226d95 check after successful initiation.
        """
        va = NE_1095_140_2_METHODS.get('NEIKEv2Session.initiateConnect')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def keychain_acl_race(self, count=280):
        """Disassemble addAppToKeychainACLsForConfiguration: @ 0x3528a.
        Maps the type check vs ACL write race and the batch iteration loop.

        Structure:
          0x352b8: r13 = [config <sel@0x2916d9>] retain  → new app path/identifier
          0x352dc: TYPE CHECK [static_class <sel@0x2917d6>:r13] → bail if invalid ObjC type
                   *** TYPE-ONLY: validates ObjC class, NOT code signature ***
          0x3543c: existing ACL app paths from config's retained ACL object (r15)
          0x35473: SecACL-related call (rdi=[rip+0x297d96], rdx=r13, rcx=0)
          0x35595: batch iteration loop — reads all Keychain ACL entries in 0x10-entry batches
                   per entry: [entry_array[i] <sel@0x292141>] → sub-property → accumulate
                   next batch: [iter_obj <sel@0x291115>:struct:error:0x10] @ 0x356a4
          0x35707: [r14 <sel@0x292075>:r12] FIRST ACL WRITE  (primary ACL object)
          0x3572d: [[rbp-0xd8] <sel@0x292054>:r12] SECOND ACL WRITE  (secondary ACL object)

        PRIMARY ISSUE: type check at 0x352dc insufficient — any NSString/NSURL passes.
          Craft NEConfiguration with malicious app path → type check passes
          → malicious app written to Cisco Keychain ACL
          → reads PSK / XAuthPassword / cert privkey without code-signature gate.

        SECONDARY TOCTOU: read-modify-write without lock (~420-insn window).
          type_check(0x352dc) → batch_read(0x35595) → ACL_write(0x35707)
          Concurrent call loses update (batch read of concurrent write overwritten).
        """
        va = NE_1095_140_2_METHODS.get('addAppToKeychainACLsForConfiguration:')
        if va is None:
            return {'error': 'method not in address table'}
        return self.disasm_va(va, count)

    def xpc_services(self):
        """Extract all XPC/Mach service names from the binary."""
        return xpc_service_map(self.path)

    def run_all(self):
        return {
            'lina_hunt': self.hunt_lina(),
            'cisco_artifacts': self.cisco_artifacts(),
            'protocol_overlap': self.protocol_overlap(),
            'keychain_surface': self.keychain_surface(),
            'keychain_acl_race': self.keychain_acl_race(),
            'codesig_gate': self.codesig_gate(),
            'initiate_connect': self.initiate_connect(),
            'install_child_sa': self.install_child_sa(),
            'initiate_rekey_ikesa': self.initiate_rekey_ikesa(),
            'receive_rekey_ikesa': self.receive_rekey_ikesa(),
            'skeyseed_derivatives': self.skeyseed_derivatives(),
            'uninstall_child_sa': self.uninstall_child_sa(),
            'receive_rekey_child_sa': self.receive_rekey_child_sa(),
            'skeyseed_for_rekey': self.skeyseed_for_rekey(),
            'copy_sas_to_delete_install_rekeyed': self.copy_sas_to_delete_install_rekeyed(),
            'migrate_all_child_sas': self.migrate_all_child_sas(),
            'generate_all_values_for_rekey': self.generate_all_values_for_rekey(),
            'create_initiator_auth_data': self.create_initiator_auth_data(),
            'check_non_cert_auth_data': self.check_non_cert_auth_data(),
            'migrate_child_sa': self.migrate_child_sa(),
            'generate_local_dh_values': self.generate_local_dh_values(),
            'generate_local_nonce': self.generate_local_nonce(),
            'create_auth_data_psk': self.create_auth_data_psk(),
            'create_initiator_eap_auth': self.create_initiator_eap_auth(),
            'create_responder_eap_auth': self.create_responder_eap_auth(),
            'create_encrypted_data': self.create_encrypted_data(),
            'select_eap_module': self.select_eap_module(),
            'initiate_delete_child_sa': self.initiate_delete_child_sa(),
            'uninstall_all_child_sas': self.uninstall_all_child_sas(),
            'report_traffic_selectors': self.report_traffic_selectors(),
            'reset_child': self.reset_child(),
            'create_responder_auth_data': self.create_responder_auth_data(),
            'create_initiator_signed_octets': self.create_initiator_signed_octets(),
            'create_responder_signed_octets': self.create_responder_signed_octets(),
            'receive_delete_child_sa': self.receive_delete_child_sa(),
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
        Write chain (end-to-end) — call at 0x1000830c3:
          _writeUDPDatagramToFlow @ 0x10005da06
            → 0x10005db2c (addr-prefix router; ecx=0x801 passed as flags)
              → 0x10005e1e4 (handle setup):
                  0x10009adb4(data, 0x8000100) → handle
                  0x10009adba(handle, extra) → write_obj
                  0x10005e2cc(write_obj, output, flags=0x801) ← ACTUAL NE FLOW WRITE
              → 0x10009b384 (alt write path, no prefix match)
            → 0x10005dbaa (chunked write, 1000B/chunk, Swift string ABI, '\n'/'  ' split)
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
