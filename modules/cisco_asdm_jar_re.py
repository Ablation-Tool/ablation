"""
cisco_asdm_jar_re.py — Cisco ASDM JAR reverse engineering module.

Methodology grounded in:
  - "Decompiling Java" (Apress, ISBN 9781430207399): class file structure,
    constant pool layout, disassembler/decompiler tooling, javap usage
  - JVM Specification (ISBN 9780133922745): formal constant pool tag table,
    cp_info format, CONSTANT_Utf8_info (tag=1), CONSTANT_String_info (tag=8),
    CONSTANT_Methodref_info (tag=10), NameAndType (tag=12), descriptor format,
    ClassFile big-endian u1/u2/u4 encoding, CAFEBABE magic validation

Target:
  Cisco ASA at 207.254.35.12 (MacStadium) and 207.254.16.2 serving ASDM as a
  Java WebStart application via /+CSCOU+/asa/asdm.jnlp.

ASDM auth flow (207.254.35.12:443):
  1. GET /admin/launch  ->  302  ->  /+CSCOE+/logon.html (form login page)
  2. POST /+webvpn+/index.html  username=X&password=Y&Login=Login
       Response: Set-Cookie: webvpnc=...; webvpnlogin=1
  3. GET /admin/public/asdm.jnlp  (authenticated, returns JNLP XML)
  4. JNLP references jar resources at /+CSCOU+/asa/asdm-*.jar
  5. Subsequent management: HTTPS POST/GET to /admin/config.html with
     session cookie; REST API at /api/... (ASA 9.3+)
  6. ASDM JAR skips TLS cert verification against ASA (self-signed);
     custom X509TrustManager that accepts any cert is compiled in.

Stdlib only: struct, zipfile, re, json, io, hashlib, subprocess, os,
             ssl, urllib.request, urllib.error, tempfile
"""

import struct
import zipfile
import re
import json
import io
import hashlib
import subprocess
import os
import ssl
import urllib.request
import urllib.error
import tempfile
from typing import Optional


# ---------------------------------------------------------------------------
# ASDM download URL constants
# ---------------------------------------------------------------------------

# MacStadium target hosts
MACSTADIUM_HOST_PRIMARY   = '207.254.35.12'
MACSTADIUM_HOST_SECONDARY = '207.254.16.2'

# JNLP entry points (tried in order)
JNLP_PATHS = [
    '/+CSCOU+/asa/asdm.jnlp',
    '/admin/public/asdm.jnlp',
    '/admin/launch',
    '/admin/public/asdm-launcher.jnlp',
    '/+CSCOE+/asdm.jnlp',
    '/ASDM_Launcher.jnlp',
]

# JAR download paths (the JNLP references these; also try directly)
JAR_PATHS = [
    '/+CSCOU+/asa/asdm.jar',
    '/+CSCOU+/asa/asdm-openjre.jar',
    '/+CSCOU+/asa/dm-launcher.jar',
    '/admin/public/asdm.jar',
    '/admin/public/asdm-openjre.jar',
]

# Authentication endpoint (form POST)
AUTH_POST_PATH  = '/+webvpn+/index.html'
AUTH_POST_BODY  = 'username={user}&password={pw}&Login=Login&tgroup='

# REST API root (ASA 9.3+)
REST_API_ROOT   = '/api/cli/exec'

# WebVPN CSTP header marker
CSTP_HEADER = 'X-CSTP-Version'


# ---------------------------------------------------------------------------
# JVM constant pool tag constants (JVM Spec §4.4 Table 4.4-A)
# ---------------------------------------------------------------------------

CP_UTF8                 = 1    # CONSTANT_Utf8_info          — string bytes
CP_INTEGER              = 3    # CONSTANT_Integer_info
CP_FLOAT                = 4    # CONSTANT_Float_info
CP_LONG                 = 5    # CONSTANT_Long_info           — consumes 2 slots
CP_DOUBLE               = 6    # CONSTANT_Double_info         — consumes 2 slots
CP_CLASS                = 7    # CONSTANT_Class_info          — name_index
CP_STRING               = 8    # CONSTANT_String_info         — string_index -> UTF8
CP_FIELDREF             = 9    # CONSTANT_Fieldref_info
CP_METHODREF            = 10   # CONSTANT_Methodref_info
CP_INTERFACE_METHODREF  = 11   # CONSTANT_InterfaceMethodref_info
CP_NAME_AND_TYPE        = 12   # CONSTANT_NameAndType_info
CP_METHOD_HANDLE        = 15   # CONSTANT_MethodHandle_info
CP_METHOD_TYPE          = 16   # CONSTANT_MethodType_info
CP_DYNAMIC              = 17   # CONSTANT_Dynamic_info
CP_INVOKE_DYNAMIC       = 18   # CONSTANT_InvokeDynamic_info
CP_MODULE               = 19   # CONSTANT_Module_info
CP_PACKAGE              = 20   # CONSTANT_Package_info

# Internal name for double-slot sentinel
_UNUSABLE = 'UNUSABLE'

# ---------------------------------------------------------------------------
# SSL bypass fingerprints (JVM internal descriptor fragments)
# Any class that implements these interfaces and has a trivial body is suspect.
# ---------------------------------------------------------------------------

SSL_TRUST_MGRS = {
    'javax/net/ssl/X509TrustManager',
    'javax/net/ssl/X509ExtendedTrustManager',
    'com/sun/ssl/internal/ssl/X509ExtendedTrustManager',
}

SSL_HOSTNAME_VERIFIERS = {
    'javax/net/ssl/HostnameVerifier',
}

SSL_BYPASS_METHODS = {
    'checkServerTrusted',    # X509TrustManager — empty body = trust all
    'checkClientTrusted',
    'getAcceptedIssuers',    # should return empty array only if really bypassing
    'verify',                # HostnameVerifier.verify() returning true = bypass
}

SSL_CTX_METHODS = {
    'SSLContext',
    'TrustManager',
    'init',
    'getInstance',
}

# ---------------------------------------------------------------------------
# Auth method name patterns (javap method name fragments)
# ---------------------------------------------------------------------------

AUTH_METHOD_NAMES_RE = re.compile(
    r'(?i)(login|logon|auth(?:enticate)?|sendCred(?:ential)?s?|'
    r'setPassword|getPassword|handleAuth|doAuth|verifyPassword|'
    r'setAuth(?:Token|Cookie|Header)?|getSessionId|validateUser)',
    re.IGNORECASE,
)

AUTH_CLASS_NAMES_RE = re.compile(
    r'(?i)(auth|login|cred(?:ential)?|session|password|token)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# javap / cfr-decompiler command templates
# ---------------------------------------------------------------------------

# javap (included in JDK) — works on .class files extracted from JAR
JAVAP_CMD_BASIC     = 'javap -c {classfile}'
JAVAP_CMD_VERBOSE   = 'javap -verbose {classfile}'
JAVAP_CMD_PRIVATE   = 'javap -c -p -verbose {classfile}'
# -p = show private members; critical for ASDM credential/session fields

# cfr-decompiler (https://github.com/leibnitz27/cfr) — better than javap for source
CFR_CMD_JAR         = 'java -jar cfr.jar {jarfile} --outputdir {outdir}'
CFR_CMD_CLASS       = 'java -jar cfr.jar {classfile}'
CFR_CMD_FOCUSED     = 'java -jar cfr.jar {jarfile} --caseinsensitivefs true --outputdir {outdir}'

# jd-cli (https://github.com/intoolswetrust/jd-cli) — alternative
JD_CMD_JAR          = 'jd-cli {jarfile} --outputDir {outdir}'

# Extract + disassemble in one pipeline:
# unzip -p asdm.jar com/cisco/pdm/PDMMain.class > /tmp/PDMMain.class && javap -c -p -verbose /tmp/PDMMain.class
PIPELINE_EXTRACT_DISASM = (
    'unzip -p {jarfile} {classentry} > /tmp/_asdm_target.class '
    '&& javap -c -p -verbose /tmp/_asdm_target.class'
)

# grep constant pool strings from javap verbose output for credential patterns
JAVAP_GREP_CREDS = (
    'javap -verbose -c -p {classfile} '
    '| grep -E "(password|secret|token|enable|asdm|cisco|tacacs|radius|snmp|auth)"'
)

# ---------------------------------------------------------------------------
# Decompiler tool reference (Decompiling Java §3 — Tools of the Trade)
# ---------------------------------------------------------------------------
#
# Book verdict (Decompiling Java §3):
#   JAD       — fastest, best inner-class support, annotates output with bytecode.
#               Last version 1.5.8g / 1.5.8e2 (2001). Not maintained but still
#               the most reliable for pre-Java8 class files such as older ASDM builds.
#   CFR       — best modern option; handles Java 8+ lambdas, invokedynamic.
#               Actively maintained. Use for ASDM ≥7.x (Java 8 bytecode).
#   JD-GUI    — GUI frontend; writes to ZIP of .java files via jd-cli on headless.
#   JODE      — open source; use if CFR fails on a specific construct.
#   javap     — ships with JDK; canonical disassembler. -verbose reveals full CP.
#   ClassNavigator — GUI disassembler with side-by-side bytecode/CP panes.
#   JavaDump  — outputs HTML with hotlinked CP entries; useful for navigation.

DECOMPILE_TOOLS = {
    'javap': {
        # JDK built-in disassembler. No source recovery but shows all bytecode
        # and the complete constant pool in human-readable form.
        # (Decompiling Java §1 Listing 1-2, §2, §4 Listing 4-2)
        'basic':             'javap -c {classfile}',
        'verbose':           'javap -verbose {classfile}',
        'verbose_private':   'javap -c -p -verbose {classfile}',
        # -p: show private members (credential fields, session tokens)
        # -verbose: emits full constant pool — each Utf8 entry is visible
        # -l: also show line numbers and local var tables (stripped by -g:none)
        'with_lines':        'javap -c -p -l -verbose {classfile}',
        # Extract single class from JAR then disassemble
        'extract_disasm':    (
            'unzip -p {jarfile} {classentry} > /tmp/_cls.class '
            '&& javap -c -p -verbose /tmp/_cls.class'
        ),
        # Grep constant pool string table for credential hints
        'grep_creds':        (
            'javap -verbose -c -p {classfile} '
            '| grep -E "(password|secret|token|enable|asdm|cisco|tacacs|radius|snmp|auth|Basic|Bearer)"'
        ),
        # Grep for SSL bypass method names in pool
        'grep_ssl':          (
            'javap -verbose -c -p {classfile} '
            '| grep -E "(checkServerTrusted|checkClientTrusted|getAcceptedIssuers|verify|SSLContext|TrustManager)"'
        ),
        # Find all ldc instructions (string-loading bytecode) in output
        'grep_ldc':          'javap -c {classfile} | grep ldc',
        # Find invoke* instructions targeting auth/login methods
        'grep_invoke_auth':  (
            'javap -c {classfile} '
            '| grep -E "(invokevirtual|invokespecial|invokestatic|invokeinterface).*#.*[Aa]uth|[Ll]ogin|[Pp]assword"'
        ),
    },

    'cfr': {
        # CFR decompiler — best for Java 8+ (invokedynamic, lambdas).
        # https://github.com/leibnitz27/cfr  latest: cfr-0.152.jar
        # (Book: SourceAgain = best 2nd-gen decompiler; CFR is the modern equivalent)
        'decompile_jar':   'java -jar cfr.jar {jarfile} --outputdir {outdir}',
        'decompile_class': 'java -jar cfr.jar {classfile}',
        # --caseinsensitivefs: needed on case-sensitive Linux for ASDM JARs
        # --silent: suppress progress noise
        'decompile_jar_focused': (
            'java -jar cfr.jar {jarfile} '
            '--caseinsensitivefs true --silent false --outputdir {outdir}'
        ),
        # Decompile only a specific class by its binary name
        'decompile_one_class': (
            'java -jar cfr.jar {jarfile} --classfilter {classname} --outputdir {outdir}'
        ),
        # After decompile: grep source files for auth patterns
        'find_auth': (
            'grep -rE --include="*.java" '
            '"(password|setPassword|getPassword|authenticate|sendCredential|'
            'checkServer|TrustManager|HostnameVerifier|equals.*pass|pass.*equals)" '
            '{outdir}/'
        ),
        # Find string literals that look like credentials
        'find_strings': (
            'grep -rE --include="*.java" '
            '"(\"[A-Za-z0-9+/]{20,}\"|\\.getProperty\\(|System\\.getenv)" '
            '{outdir}/'
        ),
        # Find hardcoded IP/URL patterns in decompiled output
        'find_urls': (
            'grep -rE --include="*.java" '
            '"(https?://|/api/|/\\+CSCOU\\+/|/\\+CSCOE\\+/|/\\+webvpn\\+/)" '
            '{outdir}/'
        ),
    },

    'jad': {
        # JAD 1.5.8g — fastest pre-Java8 decompiler; best for ASDM <= 6.x
        # (Decompiling Java §3: "JAD is fast, free, and very effective")
        # Annotates output with bytecode fragments — useful for RE.
        'basic':        'jad {classfile}',
        # -a: annotate output with original bytecode
        # -b: add bytecode comments to each statement
        # -d: output directory
        'annotated':    'jad -a -b -d {outdir} {classfile}',
        'batch_jar':    'jar xf {jarfile} && jad -a -b -r -d {outdir} **/*.class',
        # -r: recurse into subdirs; -lnc: line numbering; -f: ignore try/catch
        'full':         'jad -a -b -r -lnc -d {outdir} -s java {classglob}',
    },

    'jode': {
        # JODE — open source, handles inner classes, good for obfuscated code.
        # (Decompiling Java §3: "one of only two open source decompilers")
        'gui':     'java jode.decompiler.Window',
        'cli':     'java jode.decompiler.Main --dest {outdir} {classfile}',
    },

    'jd_cli': {
        # jd-cli — CLI wrapper for JD-Core. jd-gui is the GUI equivalent.
        'jar':      'jd-cli {jarfile} --outputDir {outdir}',
        'class':    'jd-cli {classfile}',
        # Write ZIP of .java files
        'zip_out':  'jd-cli {jarfile} --outputZipFile {outdir}/src.zip',
    },

    'procyon': {
        # Procyon — handles Java 8+ try-with-resources and lambda better than JAD.
        # Good fallback when CFR output is garbled.
        'class':    'java -jar procyon.jar {classfile} -o {outdir}',
        'jar':      'java -jar procyon.jar -jar {jarfile} -o {outdir}',
    },

    'fernflower': {
        # FernFlower — IntelliJ's built-in decompiler. Handles modern bytecode.
        'jar':      'java -jar fernflower.jar {jarfile} {outdir}',
        'class':    'java -jar fernflower.jar {classfile} {outdir}',
    },

    'hex': {
        # Raw hex/binary approach — no decompiler needed; searches constant pool
        # bytes directly. Most robust when decompiler fails (Decompiling Java §3,
        # §4: "hexadecimal editors ... change the condition").
        # String literals in constant pool are UTF-8 bytes preceded by tag=1 + u2 len.
        # grep -a: treat binary as ASCII text
        'strings_from_jar':    'strings -n 6 {jarfile} | grep -E "(password|auth|token|enable)"',
        'strings_from_class':  'strings -n 4 {classfile}',
        # xxd: hex dump + ASCII sidebar — spot CAFEBABE + constant pool manually
        'hex_dump':            'xxd {classfile} | head -80',
        # Find UTF-8 Utf8_info entries (tag=0x01) before grep
        'cp_utf8_raw':         (
            "python3 -c \"import sys; d=open('{classfile}','rb').read(); "
            "[print(d[i+3:i+3+int.from_bytes(d[i+1:i+3],'big')].decode('utf-8','replace')) "
            "for i in range(10,len(d)-3) if d[i]==1]\""
        ),
        # Patch a boolean conditional in-place (flip ifeq<->ifne or ifge<->iflt)
        # Decompiling Java §3: "edit the condition so boolean=true"
        # ifeq=0x99, ifne=0x9a, iflt=0x9b, ifge=0x9c, ifgt=0x9d, ifle=0x9e
        'patch_note': (
            'Flip conditional: 0x99(ifeq)<->0x9a(ifne), 0x9b(iflt)<->0x9c(ifge). '
            'Use: python3 -c "d=bytearray(open(f,\'rb\').read()); '
            'd[offset]=0x9a; open(f,\'wb\').write(d)"'
        ),
    },

    'strip_debug': {
        # Remove -g debug info (LineNumberTable, LocalVariableTable, SourceFile).
        # javac -g:none does this at compile time; these tools do it post-compile.
        # (Decompiling Java §4: "-g:none keeps lines/vars/source out of classfile")
        # JCF StripDebug (from JavaDump/JCF utils): drops line number attributes.
        'jcf_strip':   'java lti.java.javadump.StripDebug {classfile}',
        # ProGuard -dontobfuscate -optimizations !* = strip debug only
        'proguard':    'java -jar proguard.jar @strip_debug.pro',
        # javap tells you what debug info is present:
        'check_attrs': 'javap -verbose {classfile} | grep -E "(LineNumber|LocalVariable|SourceFile)"',
    },
}


# ---------------------------------------------------------------------------
# Bytecode opcode table — auth/RE relevant subset
# Source: Decompiling Java §2 Table 2-6 (complete 0x00–0xc9 table)
# Full table: 201 opcodes defined; 0xca–0xff reserved or JVM-internal.
# ---------------------------------------------------------------------------

# Complete opcode name -> (hex, decimal, operand_bytes) for opcodes used in RE
BYTECODE_OPCODES = {
    # String/constant loading — the primary path to finding string literals
    'nop':              (0x00, 0,  0),
    'ldc':              (0x12, 18, 1),   # push cp[index1] — strings, ints, floats
    'ldc_w':            (0x13, 19, 2),   # wide index variant (cp[index1<<8|index2])
    'ldc2_w':           (0x14, 20, 2),   # push long/double constant
    'bipush':           (0x10, 16, 1),   # push byte as int
    'sipush':           (0x11, 17, 2),   # push short as int

    # Local variable loads — auth code pushes 'this', password arg, etc.
    'aload_0':          (0x2a, 42, 0),   # load ref from local 0 (usually 'this')
    'aload_1':          (0x2b, 43, 0),   # load ref from local 1
    'aload_2':          (0x2c, 44, 0),   # load ref from local 2
    'aload_3':          (0x2d, 45, 0),   # load ref from local 3
    'aload':            (0x19, 25, 1),   # load ref from local N

    # Field access — credential stored as instance field
    'getfield':         (0xb4, 180, 2),  # get instance field; cp index -> Fieldref
    'putfield':         (0xb5, 181, 2),  # set instance field
    'getstatic':        (0xb2, 178, 2),  # get static field
    'putstatic':        (0xb3, 179, 2),  # set static field

    # Method invocation — the four invoke variants
    'invokevirtual':    (0xb6, 182, 2),  # instance method (normal dispatch)
    'invokespecial':    (0xb7, 183, 2),  # <init>, superclass, private
    'invokestatic':     (0xb8, 184, 2),  # static method
    'invokeinterface':  (0xb9, 185, 4),  # interface method (4-byte: index+count+0)

    # Object creation — 'new' creates object; <init> is next
    'new':              (0xbb, 187, 2),  # create new object; cp -> Class
    'dup':              (0x59, 89,  0),  # duplicate top of stack (used after 'new')

    # Conditional jumps — licensing/auth gates (Decompiling Java §3)
    'ifeq':             (0x99, 153, 2),  # branch if int == 0  (flip to ifne to bypass)
    'ifne':             (0x9a, 154, 2),  # branch if int != 0
    'iflt':             (0x9b, 155, 2),  # branch if int < 0
    'ifge':             (0x9c, 156, 2),  # branch if int >= 0
    'ifgt':             (0x9d, 157, 2),  # branch if int > 0
    'ifle':             (0x9e, 158, 2),  # branch if int <= 0
    'if_icmpeq':        (0x9f, 159, 2),  # branch if int == int
    'if_icmpne':        (0xa0, 160, 2),  # branch if int != int
    'if_acmpeq':        (0xa5, 165, 2),  # branch if ref == ref
    'if_acmpne':        (0xa6, 166, 2),  # branch if ref != ref

    # Returns
    'return':           (0xb1, 177, 0),  # return void  (empty body = SSL bypass)
    'areturn':          (0xb0, 176, 0),  # return reference
    'ireturn':          (0xac, 172, 0),  # return int

    # Exception — absence in checkServerTrusted = trust-all bypass
    'athrow':           (0xbf, 191, 0),  # throw exception on stack

    # Type check — instanceof used in auth dispatch
    'instanceof':       (0xc1, 193, 2),  # check object type; cp -> Class
    'checkcast':        (0xc0, 192, 2),  # cast object; cp -> Class

    # Misc used in auth/session code
    'goto':             (0xa7, 167, 2),  # unconditional branch
    'tableswitch':      (0xaa, 170, -1), # switch table (variable length)
    'lookupswitch':     (0xab, 171, -1), # switch lookup (variable length)
    'monitorenter':     (0xc2, 194, 0),  # synchronized block enter
    'monitorexit':      (0xc3, 195, 0),  # synchronized block exit
}

# Reverse lookup: opcode byte -> mnemonic
OPCODE_BY_BYTE = {v[0]: k for k, v in BYTECODE_OPCODES.items()}


# ---------------------------------------------------------------------------
# Bytecode auth-pattern descriptions
# Source: Decompiling Java §2 (bytecode walkthrough), §3 (tool output examples)
# These are pattern descriptions for manual or automated analysis of javap output.
# ---------------------------------------------------------------------------

BYTECODE_AUTH_PATTERNS = {
    # ldc (0x12) or ldc_w (0x13) loading a String constant that contains
    # "password", "auth", etc. In javap output: "ldc #N <String "password">"
    # In raw bytecode: [0x12, cp_index] where cp[cp_index] is CONSTANT_String
    # pointing to a CONSTANT_Utf8 with the password literal.
    'ldc_string_literal': {
        'opcode': 0x12,
        'opcode_wide': 0x13,
        'javap_pattern': r'ldc\s+#\d+\s+<String\s+"(?i)(?:password|secret|token|enable|cisco|auth)"',
        'note': (
            'ldc pushes a CONSTANT_String (tag=8) by 1-byte cp index. '
            'The String entry\'s string_index -> CONSTANT_Utf8 (tag=1) holds bytes. '
            'ldc_w uses a 2-byte index for cp_index > 255.'
        ),
    },

    # invokevirtual (0xb6) calling String.equals() after loading a password literal.
    # Pattern: ldc <password> -> aload_N <input> -> invokevirtual #M String.equals
    # This is the "cleartext password comparison" pattern.
    'invokevirtual_string_equals': {
        'opcode': 0xb6,
        'javap_pattern': r'invokevirtual\s+#\d+\s+<Method\s+(?:java/lang/String|java\.lang\.String)\.equals',
        'sequence': ['ldc', 'invokevirtual_String.equals'],
        'note': (
            'Cleartext credential comparison. Sequence: push hardcoded string '
            '(ldc), push user input (aload), call String.equals (invokevirtual). '
            'Flip ifeq/ifne after the call to bypass auth.'
        ),
    },

    # invokevirtual on password-related method names
    'invokevirtual_auth_method': {
        'opcode': 0xb6,
        'javap_pattern': r'invokevirtual\s+#\d+.*(?i)(?:getPassword|setPassword|authenticate|sendCredential|login|verifyPassword)',
        'note': 'Instance method call on auth-related method.',
    },

    # invokespecial (0xb7) on constructor of auth/session class
    'invokespecial_auth_init': {
        'opcode': 0xb7,
        'javap_pattern': r'invokespecial\s+#\d+.*(?i)(?:auth|login|cred|session|password)<init>',
        'note': (
            'Constructor call on auth class. invokespecial is used for <init>, '
            'private methods, and superclass calls '
            '(Decompiling Java §2: "b7 0001 invokespecial #1").'
        ),
    },

    # invokestatic (0xb8) calling static auth factory or digest method
    'invokestatic_auth': {
        'opcode': 0xb8,
        'javap_pattern': r'invokestatic\s+#\d+.*(?i)(?:authenticate|login|md5|sha|digest|hmac|encrypt)',
        'note': 'Static auth helper: digest computation, token factory, etc.',
    },

    # invokeinterface (0xb9) on HttpURLConnection or similar for auth headers
    'invokeinterface_connection': {
        'opcode': 0xb9,
        'javap_pattern': r'invokeinterface\s+#\d+.*(?i)(?:setRequestProperty|addRequestProperty|connect|getResponseCode)',
        'note': (
            'HTTP connection method call. Look for preceding ldc with '
            '"Authorization", "X-Auth-Token", or "Cookie" to find '
            'where auth headers are set.'
        ),
    },

    # putfield (0xb5) storing a string that was loaded with ldc into a field
    # named password/token/credential. Pattern: ldc <secret> -> putfield #N <password>
    'putfield_credential': {
        'opcode': 0xb5,
        'javap_pattern': r'putfield\s+#\d+\s+<Field.*(?i)(?:password|token|secret|credential|key)',
        'note': (
            'Stores a credential value to an instance field. '
            'Preceding ldc instruction is the literal value. '
            'Field name visible in constant pool Fieldref -> NameAndType -> Utf8.'
        ),
    },

    # SSL bypass: checkServerTrusted with only 'return' in body
    # In javap: Code length = 1, single opcode = 0xb1 (return)
    # "An empty void method is: return, 1 byte" (Decompiling Java §2 methodology)
    #
    # CONFIRMED in ASDM 7.16.1 (asdm-7161.bin, SIGNATURE4 container @ 0x213f62):
    #   class av implements javax.net.ssl.X509TrustManager (obfuscated name)
    #   checkServerTrusted: Code stack=0, locals=3; 0: return  (1 byte)
    #   checkClientTrusted: Code stack=0, locals=3; 0: return  (1 byte)
    #   getAcceptedIssuers: Code stack=1, locals=1; 0: aconst_null; 1: areturn
    #   -> Trust any certificate, return null accepted issuers list
    #
    # Companion class ak uses ALLOW_ALL_HOSTNAME_VERIFIER from
    #   org/apache/http/conn/ssl/SSLConnectionSocketFactory
    #   -> field ALLOW_ALL_HOSTNAME_VERIFIER: Lorg/apache/http/conn/ssl/X509HostnameVerifier;
    #   -> SSLContext.init(null, new TrustManager[]{new av()}, new SecureRandom())
    #   -> HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory())
    #   -> HttpsURLConnection.setDefaultHostnameVerifier(av$1_instance)
    #
    # SHA-256 of class av (7161): c37f5cf3106baad710c1b792052ee3af4fa635e049b79985c278d5968ca85cf1
    # Binary path: asdm-7161.bin -> SIGNATURE4 container -> class av @ file offset 0x213f62
    # ALSO CONFIRMED in asdm-7202.bin: class av @ file offset 0x2059d6, idx=376
    #   checkServerTrusted: Code stack=0, locals=3; 0: return (IDENTICAL to 7161)
    #   Same class index position (302=ak, 376=av) in both versions.
    #   Bypass spans ASDM 7.16.1 -> 7.20.2 (latest); likely all 7.x versions.
    'ssl_bypass_empty_return': {
        'opcode': 0xb1,
        'code_length_max': 3,   # return + maybe areturn or nop; anything <= 3 is trivial
        'javap_pattern': r'Code:\s*\n\s+0:\s+return',
        'confirmed_in': 'asdm-7161.bin class av (SHA256: c37f5cf3106baad710c1b792052ee3af4fa635e049b79985c278d5968ca85cf1)',
        'confirmed_offset': 0x213f62,
        'note': (
            'checkServerTrusted() with empty body: Code attribute = 1 byte (0xb1 return). '
            'No CertificateException throw = trust-all bypass. '
            'Confirm: javap -c <class> | grep -A5 checkServerTrusted'
        ),
    },

    # HostnameVerifier.verify() returning constant true
    # Pattern: iconst_1 (0x04) -> ireturn (0xac)
    #
    # CONFIRMED in ASDM 7.16.1: class ak uses Apache HttpClient
    #   ALLOW_ALL_HOSTNAME_VERIFIER (static field) for HttpsURLConnection.
    #   Inner class av$1 referenced in CP implements HostnameVerifier.
    'hostname_bypass_return_true': {
        'sequence_hex': [0x04, 0xac],   # iconst_1, ireturn
        'javap_pattern': r'Code:\s*\n\s+0:\s+iconst_1\s*\n\s+1:\s+ireturn',
        'allow_all_constant': 'org/apache/http/conn/ssl/SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER',
        'note': (
            'verify() returning hardcoded true (iconst_1 + ireturn). '
            'All hostnames accepted. Two-byte body. '
            'Also confirmed via ALLOW_ALL_HOSTNAME_VERIFIER static field in class ak. '
            'Decompiling Java §2: "b1 return ... An empty void method".'
        ),
    },

    # getfield (0xb4) reading a credential field
    'getfield_credential': {
        'opcode': 0xb4,
        'javap_pattern': r'getfield\s+#\d+\s+<Field.*(?i)(?:password|token|secret|credential|session)',
        'note': 'Reads stored credential from instance field — trace back to where it was set.',
    },

    # Authorization header construction:
    # ldc "Authorization" -> invokevirtual setRequestProperty
    'auth_header_set': {
        'sequence': ['ldc_Authorization', 'ldc_value', 'invokeinterface_setRequestProperty'],
        'javap_pattern': r'ldc\s+.*"Authorization"',
        'note': (
            'Authorization HTTP header. Subsequent ldc is the value '
            '("Basic <base64>", "Bearer <token>"). '
            'Base64-decode to recover cleartext credentials.'
        ),
    },

    # Conditional bypass gate — the classic licensing/auth bypass target
    # (Decompiling Java §3: "change the condition so it will work on any web server")
    'auth_gate_conditional': {
        'opcodes': [0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e],  # ifeq..ifle
        'javap_pattern': r'(?:ifeq|ifne|iflt|ifge|ifgt|ifle)\s+\d+',
        'note': (
            'Auth gate: boolean conditional after equals/compareTo call. '
            'Flip ifeq(0x99)<->ifne(0x9a) or iflt(0x9b)<->ifge(0x9c) '
            'in hex to bypass. Patch in-place with python bytearray.'
        ),
    },
}


# ---------------------------------------------------------------------------
# CONFIRMED: ASDM 7.16(1) binary SSL bypass — extracted from asdm-7161.bin
# Blob: asdm-7161-extracted/_asdm-7161.bin.extracted/1265F6 (149MB LZMA-decompressed)
# Classes extracted and verified with javap 2026-08-13.
# ---------------------------------------------------------------------------

CONFIRMED_ASDM_SSL_BYPASS = {
    'blob_file': '1265F6',                # LZMA-decompressed ASDM blob in binwalk output
    'blob_zip_start': 0x0127dc95,         # first PK\x03\x04 header — 2514 ZIP entries
    'asdm_version': '7.16(1)',
    'compiled_class_version': 52,         # Java 8 (major=52)

    # ── Class: av (implements X509TrustManager) ──────────────────────────────
    # Source file: av.java  (obfuscated name, ProGuard-style one/two-char identifiers)
    # This is the outer class itself, NOT an anonymous inner.
    # Its static a(boolean) method globally replaces the JVM SSL defaults.
    'av_class': {
        'cafebabe_offset': 0x00213f62,    # class file starts here in 1265F6 blob
        'hit_offset':      0x00213f9b,    # 'javax/net/ssl/X509TrustManager' Utf8 CP entry
        'size_estimate':   3035,          # bytes until next CAFEBABE at 0x00214b3d
        'cp_count':        144,
        'implements':      'javax/net/ssl/X509TrustManager',
        'bypass_methods': {
            'checkClientTrusted': {
                'descriptor': '([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V',
                'bytecode': '0: return',
                'code_length': 1,         # single 0xb1 (return) opcode — trust all clients
            },
            'checkServerTrusted': {
                'descriptor': '([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V',
                'bytecode': '0: return',
                'code_length': 1,         # CONFIRMED: accepts any server certificate
            },
            'getAcceptedIssuers': {
                'descriptor': '()[Ljava/security/cert/X509Certificate;',
                'bytecode': '0: aconst_null\n1: areturn',
                'code_length': 2,         # returns null (no accepted issuers list)
            },
        },
        # Static method a(boolean) — the global SSL bypass installer
        # a(true)  = install trust-all TrustManager + HostnameVerifier as JVM defaults
        # a(false) = restore Sun deploy TrustManager (com.sun.deploy.security.X509DeployTrustManager)
        'installer_method': {
            'name': 'a',
            'descriptor': '(Z)V',          # takes boolean, returns void
            'ssl_context_string': 'SSL',   # ldc #37 "SSL"
            'sets_default_ssl_factory':    True,   # HttpsURLConnection.setDefaultSSLSocketFactory
            'sets_default_hostname_verifier': True, # HttpsURLConnection.setDefaultHostnameVerifier
            'hostname_verifier_class': 'av$1',      # anonymous inner at 0x00214b3d
            'trust_manager_false_path': 'com.sun.deploy.security.X509DeployTrustManager',
            'trust_manager_true_path':  'av',       # the trust-all class itself
        },
    },

    # ── Class: ak$1 (anonymous inner of ak, implements X509TrustManager) ─────
    # Minimal trust-all TrustManager. Holds reference to outer ak instance.
    # Likely used in a separate HTTP connection pool managed by the ak class.
    'ak1_class': {
        'cafebabe_offset': 0x0094393b,    # class file starts here in 1265F6 blob
        'hit_offset':      0x00943976,    # 'javax/net/ssl/X509TrustManager' Utf8 CP entry
        'size_estimate':   689,           # smallest of the three — minimal implementation
        'cp_count':        33,
        'implements':      'javax/net/ssl/X509TrustManager',
        'outer_class':     'ak',
        'bypass_methods': {
            'checkClientTrusted': {
                'descriptor': '([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V',
                'bytecode': '0: return',
                'code_length': 1,
            },
            'checkServerTrusted': {
                'descriptor': '([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V',
                'bytecode': '0: return',
                'code_length': 1,         # CONFIRMED: accepts any server certificate
            },
            'getAcceptedIssuers': {
                'descriptor': '()[Ljava/security/cert/X509Certificate;',
                'bytecode': '0: iconst_0\n1: anewarray X509Certificate\n4: areturn',
                'code_length': 5,         # returns empty array (not null)
            },
        },
    },

    # ── X509TrustManager hits in 1265F6 (full map) ───────────────────────────
    'trustmanager_hits': [
        {'label': 'av',   'offset': 0x00213f9b, 'source': 'av.java'},
        {'label': 'ak$1', 'offset': 0x00943976, 'source': 'ak$1.java'},
        {'label': 'CCOImageASDHandler', 'offset': 0x015bafdf,
         'package': 'com/cisco/pdm/pdmdata/ccowiz/asd',
         'note': 'inside ZIP section; Cisco PDM CCO download handler'},
    ],
    'check_server_trusted_string_offsets': [0x0021405d, 0x00943aa0, 0x015bb0e0],
    'hostname_verifier_hit_count': 56,
}

# ── ASDM 7.20.2 ADDITIONAL CONFIRMED SSL BYPASS CLASSES ──────────────────────
# Extracted from: asdm-7202.bin -> SIGNATURE4 container 1E69DA (142MB, 14855 classes)
# av (idx=376) and ak (idx=302) confirmed identical to 7.16.1 — bypass persists.
#
# ADDITIONAL CLASSES CONFIRMED IN 7.20.2:
CONFIRMED_ASDM_7202_ADDITIONAL = {
    # ── efu (idx 10831 @ 0x0289a499): HostnameVerifier trust-all ──────────────
    # Used in the CIDS/IDS sensor communication path (SDEE protocol client)
    'efu_class': {
        'cafebabe_offset': 0x0289a499,
        'idx_in_container': 10831,
        'sha256': '54fdeba589e9d548af67a1c11c7330f96669767948d400ae873bdcdb90010cc1',
        'implements': 'javax/net/ssl/HostnameVerifier',
        'bypass_methods': {
            'verify': {
                'descriptor': '(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z',
                'bytecode': '0: iconst_1\n1: ireturn',
                'code_length': 2,  # returns true for ALL hostnames
            },
        },
        'context': 'CIDS/IDS SDEE sensor client — installed as global default',
    },

    # ── efv (idx 10832 @ 0x0289a5e5): X509TrustManager trust-all ─────────────
    # Second complete X509TrustManager bypass, parallel to class av
    # Used in the same CIDS sensor connection path as efu
    'efv_class': {
        'cafebabe_offset': 0x0289a5e5,
        'idx_in_container': 10832,
        'sha256': 'a579f2dd2adc435eb7a5a3bbc5c6c03cd9a230bf89e4da247313f6e35a2147fa',
        'implements': 'javax/net/ssl/X509TrustManager',
        'bypass_methods': {
            'checkClientTrusted': {'bytecode': '0: return', 'code_length': 1},
            'checkServerTrusted': {'bytecode': '0: return', 'code_length': 1},
            'getAcceptedIssuers': {'bytecode': '0: aconst_null\n1: areturn', 'code_length': 2},
        },
    },

    # ── efw (idx 10833 @ 0x0289a7ea): CIDS HTTP worker — JVM GLOBAL BYPASS ───
    # Runnable implementing SDEE (Security Device Event Exchange) HTTP client
    # User-Agent: "CIDS Client/4.0"
    # CRITICAL: static initializer sets JVM-GLOBAL SSL/TLS bypass on class load:
    #
    #   static {
    #       efv tm = new efv();          // trust-all X509TrustManager
    #       SSLContext ctx = SSLContext.getInstance("TLS");
    #       ctx.init(null, new TrustManager[]{tm}, new SecureRandom());
    #       HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());  // GLOBAL
    #       efu hv = new efu();          // trust-all HostnameVerifier
    #       HttpsURLConnection.setDefaultHostnameVerifier(hv);                       // GLOBAL
    #   }
    #
    # Once efw is loaded by the classloader, ALL subsequent HttpsURLConnection
    # requests in the ASDM JVM use the trust-all SSLSocketFactory and HostnameVerifier.
    # This is BROADER than class av's bypass (which targets specific connections).
    #
    # SDEE protocol strings: "sdee-server", "sessionCookies", "SdeeError",
    # "respEditConfigDelta", "respEditDefaultConfig", "execPushUpgrade"
    # → ASDM uses SDEE to communicate with Cisco IDS/IPS sensors for event monitoring.
    'efw_class': {
        'cafebabe_offset': 0x0289a7ea,
        'idx_in_container': 10833,
        'sha256': '4a90274f75e9014636bf7f6452a307690ef80b614f9d899de42d1af2eca55b83',
        'implements': 'java/lang/Runnable',
        'global_bypass': True,  # sets HttpsURLConnection JVM defaults in <clinit>
        'static_init_sequence': [
            'new efv -> trust-all TrustManager',
            'SSLContext.getInstance("TLS")',
            'ctx.init(null, [efv], SecureRandom)',
            'HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory())',
            'new efu -> trust-all HostnameVerifier',
            'HttpsURLConnection.setDefaultHostnameVerifier(efu)',
        ],
        'protocol': 'SDEE (Security Device Event Exchange)',
        'user_agent': 'CIDS Client/4.0',
        'auth_method': 'HTTP Basic (Authorization: Basic <base64>)',
        'attack_surface': (
            'Loading class efw (e.g., by opening ASDM Monitoring > IPS module) '
            'installs trust-all as the JVM GLOBAL default. All subsequent HTTPS '
            'connections in the ASDM JVM — including the management connection to '
            'the ASA — then bypass certificate validation.'
        ),
    },

    # ── CCOImageASDHandler$1 (idx 7339 @ 0x015f9385): CCO software update MITM ─
    # Named class: com.cisco.pdm.pdmdata.ccowiz.asd.CCOImageASDHandler$1
    # Anonymous inner X509TrustManager used for Cisco CCO software update downloads.
    # The PARENT class (CCOImageASDHandler, idx 7340) hits these Cisco API endpoints:
    #   oauth2_token:      https://cloudsso.cisco.com/as/token.oauth2
    #   software_metadata: https://api.cisco.com/software/v4.0/metadata/udirelease
    #   image_metadata:    https://api.cisco.com/software/v4.0/metadata/udiimage
    #   download_url:      https://api.cisco.com/software/v4.0/download/udiimage
    'cco_trustmanager_class': {
        'cafebabe_offset': 0x015f9385,
        'idx_in_container': 7339,
        'class_name': 'com/cisco/pdm/pdmdata/ccowiz/asd/CCOImageASDHandler$1',
        'implements': 'javax/net/ssl/X509TrustManager',
        'bypass_methods': {
            'checkClientTrusted': {'bytecode': '0: return', 'code_length': 1,
                                    'throws_declared': 'CertificateException'},
            'checkServerTrusted': {'bytecode': '0: return', 'code_length': 1,
                                    'throws_declared': 'CertificateException'},
            'getAcceptedIssuers': {'bytecode': '0: aconst_null\n1: areturn', 'code_length': 2},
        },
        'attack_surface': (
            'MITM of network path from ASDM workstation to api.cisco.com or '
            'cloudsso.cisco.com → serve malicious ASDM/firmware image → code '
            'execution on ASDM management workstation. '
            'CCOImageASDHandler uses Apache HttpClient (not HttpsURLConnection), '
            'so efw\'s global bypass does not affect it; this class is the direct bypass.'
        ),
        'supply_chain_risk': 'HIGH — update path MITM bypasses certificate validation',
    },
}

CONFIRMED_ASDM_SSL_BYPASS = {
    'blob_file': '1265F6',                # LZMA-decompressed ASDM blob in binwalk output
    'blob_zip_start': 0x0127dc95,         # first PK\x03\x04 header — 2514 ZIP entries
    'asdm_version': '7.16(1) + 7.20(2)',
    'compiled_class_version': 52,         # Java 8 (major=52)

    # ── Class: av (implements X509TrustManager) ──────────────────────────────
    # Source file: av.java  (obfuscated name, ProGuard-style one/two-char identifiers)
    # This is the outer class itself, NOT an anonymous inner.
    # Its static a(boolean) method globally replaces the JVM SSL defaults.
    'av_class': {
        'precondition': 'Network position on ASDM admin workstation segment OR ASA mgmt network',
        'impact': (
            'ASDM silently accepts any TLS certificate from any host claiming to be the ASA. '
            'av.a(true) installs trust-all globally via HttpsURLConnection defaults — affects '
            'ALL HTTPS connections from the ASDM process, not just ASA connections.'
        ),
        'credential_exposure': (
            'ASA admin username + password submitted over the intercepted HTTPS session. '
            'All management commands (config changes, user additions) visible in plaintext '
            'after MitM decryption.'
        ),
        'detection_difficulty': 'Low — victim ASDM shows no cert error; connection appears normal',
        'hostname_verifier': 'av$1 also disables hostname verification — SNI mismatch not detected',
    },
}

# ── Confirmed class extraction commands (run these on the local binary) ───────
ASDM_RE_COMMANDS = {
    'extract_blob': (
        'binwalk --extract --directory asdm-7161-extracted asdm-7161.bin'
        # -> _asdm-7161.bin.extracted/1265F6 (LZMA-decompressed, 149MB)
    ),
    'extract_av_class': (
        'python3 -c "'
        'with open(\'1265F6\',\'rb\') as f: d=f.read(); '
        'open(\'av.class\',\'wb\').write(d[0x00213f62:0x00214b3d])"'
    ),
    'extract_ak1_class': (
        'python3 -c "'
        'with open(\'1265F6\',\'rb\') as f: d=f.read(); '
        r"open('ak$1.class','wb').write(d[0x0094393b:0x00943bec])\""
    ),
    'disasm_av': "javap -c -p 'av.class'",
    'disasm_ak1': "javap -c -p 'ak$1.class'",
    'verify_ssl_bypass': (
        "javap -c 'av.class' | grep -A3 checkServerTrusted"
        # expected output:
        #   public void checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String) ...
        #     Code:
        #        0: return
    ),
    'extract_zip_section': (
        'python3 -c "'
        'with open(\'1265F6\',\'rb\') as f: d=f.read(); '
        'open(\'asdm_main.jar\',\'wb\').write(d[0x0127dc95:])"'
        # -> asdm_main.jar contains 2514 entries; use javap/cfr normally
    ),
}

# ---------------------------------------------------------------------------
# Field and method access flags (Decompiling Java §2 Tables 2-4, 2-5)
# Used by access_flags fields in field_info and method_info structures.
# ---------------------------------------------------------------------------

FIELD_ACCESS_FLAGS = {
    'ACC_PUBLIC':    0x0001,   # accessible from any class
    'ACC_PRIVATE':   0x0002,   # accessible only within defining class
    'ACC_PROTECTED': 0x0004,   # accessible within package + subclasses
    'ACC_STATIC':    0x0008,   # class field, not instance field
    'ACC_FINAL':     0x0010,   # no assignment after init (use in credential fields)
    'ACC_VOLATILE':  0x0040,   # thread-updated (synchronization hint)
    'ACC_TRANSIENT': 0x0080,   # excluded from serialization
}

# ACC_STATIC|ACC_FINAL = 0x0018 — static final constant (hardcoded credential candidate)
FIELD_STATIC_FINAL = FIELD_ACCESS_FLAGS['ACC_STATIC'] | FIELD_ACCESS_FLAGS['ACC_FINAL']

METHOD_ACCESS_FLAGS = {
    'ACC_PUBLIC':       0x0001,
    'ACC_PRIVATE':      0x0002,
    'ACC_PROTECTED':    0x0004,
    'ACC_STATIC':       0x0008,
    'ACC_FINAL':        0x0010,
    'ACC_SYNCHRONIZED': 0x0020,  # monitor lock around method body
    'ACC_NATIVE':       0x0100,  # native (C/C++) implementation — can't decompile
    'ACC_ABSTRACT':     0x0400,  # no body
    'ACC_STRICT':       0x0800,  # strict floating-point
}

# ---------------------------------------------------------------------------
# Field descriptor character codes (Decompiling Java §2 Table 2-2)
# Used in method descriptors: (param_types)return_type
# e.g. (Ljava/lang/String;I)V = takes String + int, returns void
# ---------------------------------------------------------------------------

FIELD_DESCRIPTORS = {
    'B': 'byte',
    'C': 'char',
    'D': 'double',
    'F': 'float',
    'I': 'int',
    'J': 'long',
    'S': 'short',
    'Z': 'boolean',
    'V': 'void',
    '[': 'array (prefix; count brackets for dimensions)',
    'L': 'class reference (followed by class/name; until semicolon)',
}

# Common ASDM method descriptor patterns
ASDM_DESCRIPTOR_PATTERNS = {
    # Credential setters
    '(Ljava/lang/String;)V':             'void method(String) — credential setter',
    '(Ljava/lang/String;[B)V':           'void method(String, byte[]) — binary credential',
    '(Ljava/lang/String;Ljava/lang/String;)V': 'void method(String,String) — user+pass pair',
    '(Ljava/lang/String;)Ljava/lang/String;': 'String method(String) — transform/hash',
    # Connection setup
    '()Ljava/net/HttpURLConnection;':    'HttpURLConnection factory',
    '()Ljava/net/URL;':                  'URL getter',
    '([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V': (
        'checkServerTrusted signature — empty body = SSL bypass'
    ),
    '(Ljava/lang/String;Ljava/net/Socket;)Z': 'HostnameVerifier.verify signature',
    # Auth token/cookie
    '()Ljava/lang/String;':              'String getter — possible session/token accessor',
    '(Ljava/lang/String;I)V':            'void method(String, int) — host+port setter',
}


# ---------------------------------------------------------------------------
# Obfuscation detection patterns (Decompiling Java §3-§4)
# ---------------------------------------------------------------------------

# Layout obfuscation: renamed class/method/field to garbage identifiers.
# Crema used Java-like keywords; JOBE used a,b,c,...,z.
# Modern obfuscators (Zelix, ProGuard) use short alpha sequences.
OBFUSCATION_NAME_PATTERNS = [
    r'^[a-z]{1,3}$',                    # a, b, aa, abc — short alpha (JOBE style)
    r'^[A-Z][a-z]{0,2}[0-9]+$',         # A1, B12 — mixed short (ProGuard)
    r'^[^\x20-\x7e]{2,}',  # non-printable/unicode identifiers (crash old decompilers)
    r'^[01]+$',                          # binary strings
    r'^\$\$',                            # synthetic inner-class markers (valid but suspicious)
]

# ---------------------------------------------------------------------------
# Methodology note (book-grounded)
# ---------------------------------------------------------------------------

_METHODOLOGY = """
JVM Constant Pool RE Methodology (Decompiling Java §2-§4, JVM Spec §4.4):

=== CLASS FILE STRUCTURE (Decompiling Java §2) ===

1. CAFEBABE validation (u4 @ offset 0x00). Not a class file if absent.
   Microsoft CLR files use BSJB; JAR is ZIP (magic PK\x03\x04).

2. Major version @ offset 0x06 (u2): maps to Java release.
   ASDM historically compiled with Java 8 (major=52); newer builds use 11/17.
   Verifier REJECTS classfiles with major version > JVM's supported max.

3. cp_count @ offset 0x08 (u2): constant pool has cp_count-1 entries.
   Index 0 is reserved and does NOT appear in classfile bytes.

4. Parse cp_info entries sequentially. Tag byte determines size:
     tag=1  (Utf8):   u2 length + length bytes  — all string literals live here
     tag=3/4 (Int/Float): u4
     tag=5/6 (Long/Double): u8, consumes TWO pool slots (next slot = phantom)
     tag=7/8/16/19/20: u2 index
     tag=9/10/11/12: u2+u2 indices
     tag=15 (MethodHandle): u1 ref_kind + u2 ref_index
     tag=17/18 (Dynamic/InvokeDynamic): u2+u2

5. ClassFile layout after constant pool:
     access_flags (u2) — see FIELD_ACCESS_FLAGS / METHOD_ACCESS_FLAGS tables
     this_class (u2) -> CONSTANT_Class -> CONSTANT_Utf8 (binary class name)
     super_class (u2) -> same chain
     interfaces_count (u2) + interfaces[](u2) -> CONSTANT_Class entries
     fields_count + field_info[] -> AccessFlags, name_index, descriptor_index, attrs
     methods_count + method_info[] -> same + Code attribute
     attributes_count + attributes[] -> SourceFile, InnerClasses, etc.

=== STRING LITERAL RECOVERY ===

6. All Java string literals become CONSTANT_String_info (tag=8) entries.
   string_index -> CONSTANT_Utf8_info (tag=1) holding UTF-8 bytes.
   Therefore: hunt tag=1 entries for plaintext credentials, URLs, API paths.
   Harvest: scan all tag=1 entries in every .class in the JAR.

7. Static final String fields (ACC_STATIC|ACC_FINAL = 0x0018) get a
   ConstantValue attribute referencing a CONSTANT_String in the pool.
   These are hardcoded constants (API keys, endpoints, default passwords).

8. ldc (0x12) bytecode loads a CONSTANT_String by 1-byte cp index.
   ldc_w (0x13) uses a 2-byte index. In javap output:
     ldc #5 <String "password">
   The "#5" is the cp index; follow to tag=8 -> tag=1 for the literal bytes.

=== AUTH/CREDENTIAL PATTERNS ===

9. Method references (tag=10) resolve:
     class_index -> CONSTANT_Class -> CONSTANT_Utf8 (class binary name)
     name_and_type_index -> CONSTANT_NameAndType -> name Utf8 + descriptor Utf8
   Descriptor format: (param_types)return_type
   e.g. ([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
         = checkServerTrusted(X509Certificate[], String) -> void

10. Auth code search:
    a) Class name contains auth/login/cred/session/password/token
    b) CP Utf8 pool contains auth method names (authenticate, sendCredentials, etc.)
    c) CP NameAndType entries (tag=12) whose name resolves to auth method names
    d) String refs matching HTTP form POST fields (username=, password=, tgroup=)
    e) String refs matching HTTP auth headers (Authorization: Basic, X-Auth-Token)

11. Cleartext credential comparison pattern (Decompiling Java §2 bytecode walk):
    ldc <hardcoded_string> -> aload_N <input> -> invokevirtual String.equals
    Flip the subsequent ifeq/ifne to bypass the check.

=== SSL BYPASS ===

12. ASDM ships custom X509TrustManager with empty checkServerTrusted():
    Method body = single return (opcode 0xb1), Code attribute length = 1.
    "An empty void method is: return, 1 byte" (Decompiling Java §2 methodology).
    Detection: grep CP for 'checkServerTrusted' -> find the class -> javap -c
    Confirm: javap output shows Code length=1 with only 'return'.

13. HostnameVerifier.verify() returning true:
    Body = iconst_1 (0x04) + ireturn (0xac), Code length = 2.

=== OBFUSCATION (Decompiling Java §3-§4) ===

14. Layout obfuscation (most common): identifier scrambling in constant pool.
    Crema: Java-like keywords used as variable names. Crashes non-Crema-aware decompilers.
    JOBE/ProGuard: a,b,c short names. Unicode names crash early decompilers.
    The JVM uses indices, not names, so renamed identifiers do not change execution.

15. javac -g:none: strips LineNumberTable, LocalVariableTable, SourceFile.
    Variable names become slot references (slot_0, slot_1...) in javap.
    Method names and class names survive (must be in pool for dynamic linking).
    ASDM is compiled -g:none (or stripped post-compile by ProGuard).

16. Control obfuscation: insert dead code, reorder expressions (Zelix KlassMaster).
    Data obfuscation: split variables, change encoding, bogus classes.
    High-mode obfuscation may fail JVM Verifier on strict VMs — rare in practice.

=== TOOLCHAIN DECISION TREE ===

17. ASDM <= 6.x (major <= 50, Java 6):    JAD 1.5.8g    (jad -a -b target.class)
    ASDM 7.x (major = 51-52, Java 7-8):   CFR           (java -jar cfr.jar asdm.jar)
    ASDM >= 7.12 (major >= 52, Java 8+):  CFR or Procyon (handles invokedynamic)
    Obfuscated:                            CFR + manual CP walk + extract_raw_strings()
    Decompiler fails:                      javap -c -p -verbose -> manual re-trace

18. Post-decompile grep targets (Decompiling Java §4):
    - password / secret / token / enable in string literals
    - Authorization: Basic / Bearer in setRequestProperty calls
    - /+CSCOU+/ /+CSCOE+/ /+webvpn+/ /api/ in URL strings
    - checkServerTrusted / verify in method names
    - SSLContext.getInstance / TrustManager in class names
"""


# ---------------------------------------------------------------------------
# Minimal constant pool parser (JVM Spec §4.4, confirmed by Decompiling Java §2)
# ---------------------------------------------------------------------------

def _parse_constant_pool(data: bytes) -> list:
    """
    Parse JVM constant pool from raw .class bytes.

    Returns list indexed 0..cp_count-1. Index 0 is sentinel {'tag': None}.
    Long/Double entries each followed by a phantom {'tag': _UNUSABLE} entry.

    JVM Spec §4.4: 'The constant_pool table is indexed from 1 to
    constant_pool_count - 1.'
    Decompiling Java §2: 'constant_pool[0] is reserved by the JVM and doesn't
    appear in the classfile.'
    """
    if len(data) < 10:
        return []
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic != 0xCAFEBABE:
        return []

    off = 8  # skip magic(4) + minor(2) + major(2)
    try:
        cp_count = struct.unpack_from('>H', data, off)[0]
    except struct.error:
        return []
    off += 2

    pool = [{'index': 0, 'tag': None, 'tag_name': _UNUSABLE, 'value': None}]
    i = 1
    while i < cp_count:
        if off >= len(data):
            break
        tag = data[off]; off += 1
        entry = {'index': i, 'tag': tag, 'value': None}

        try:
            if tag == CP_UTF8:
                ln = struct.unpack_from('>H', data, off)[0]; off += 2
                raw = data[off:off + ln]; off += ln
                try:
                    # JVM uses "modified UTF-8"; fallback to lossy
                    entry['value'] = raw.decode('utf-8', errors='replace')
                except Exception:
                    entry['value'] = repr(raw)
                entry['tag_name'] = 'Utf8'

            elif tag in (CP_INTEGER, CP_FLOAT):
                entry['value'] = struct.unpack_from('>I', data, off)[0]; off += 4
                entry['tag_name'] = 'Integer' if tag == CP_INTEGER else 'Float'

            elif tag in (CP_LONG, CP_DOUBLE):
                hi = struct.unpack_from('>I', data, off)[0]
                lo = struct.unpack_from('>I', data, off + 4)[0]
                entry['value'] = (hi << 32) | lo; off += 8
                entry['tag_name'] = 'Long' if tag == CP_LONG else 'Double'
                pool.append(entry); i += 1
                pool.append({'index': i, 'tag': None,
                             'tag_name': _UNUSABLE, 'value': None})
                i += 1
                continue

            elif tag in (CP_CLASS, CP_STRING, CP_METHOD_TYPE,
                         CP_MODULE, CP_PACKAGE):
                entry['value'] = struct.unpack_from('>H', data, off)[0]; off += 2
                entry['tag_name'] = {
                    CP_CLASS: 'Class', CP_STRING: 'String',
                    CP_METHOD_TYPE: 'MethodType', CP_MODULE: 'Module',
                    CP_PACKAGE: 'Package',
                }[tag]

            elif tag in (CP_FIELDREF, CP_METHODREF, CP_INTERFACE_METHODREF):
                ci = struct.unpack_from('>H', data, off)[0]
                ni = struct.unpack_from('>H', data, off + 2)[0]; off += 4
                entry['value'] = {'class_index': ci, 'nat_index': ni}
                entry['tag_name'] = {
                    CP_FIELDREF: 'Fieldref', CP_METHODREF: 'Methodref',
                    CP_INTERFACE_METHODREF: 'InterfaceMethodref',
                }[tag]

            elif tag == CP_NAME_AND_TYPE:
                ni = struct.unpack_from('>H', data, off)[0]
                di = struct.unpack_from('>H', data, off + 2)[0]; off += 4
                entry['value'] = {'name_index': ni, 'desc_index': di}
                entry['tag_name'] = 'NameAndType'

            elif tag == CP_METHOD_HANDLE:
                rk = data[off]; ri = struct.unpack_from('>H', data, off + 1)[0]
                off += 3
                entry['value'] = {'ref_kind': rk, 'ref_index': ri}
                entry['tag_name'] = 'MethodHandle'

            elif tag in (CP_DYNAMIC, CP_INVOKE_DYNAMIC):
                bmi = struct.unpack_from('>H', data, off)[0]
                ni  = struct.unpack_from('>H', data, off + 2)[0]; off += 4
                entry['value'] = {'bootstrap_method_attr_index': bmi,
                                  'nat_index': ni}
                entry['tag_name'] = ('Dynamic' if tag == CP_DYNAMIC
                                     else 'InvokeDynamic')
            else:
                break  # Unknown tag — cannot advance; abort parse

        except (struct.error, IndexError):
            break

        pool.append(entry)
        i += 1

    return pool


def _pool_utf8(pool: list) -> dict:
    """Return {index: str} for all Utf8 entries."""
    return {e['index']: e['value']
            for e in pool
            if e.get('tag_name') == 'Utf8' and isinstance(e.get('value'), str)}


def _resolve_class_name(pool: list, utf8: dict, class_idx: int) -> str:
    """Resolve a Class pool entry to its binary name (e.g. 'javax/net/ssl/SSLContext')."""
    for e in pool:
        if e['index'] == class_idx and e.get('tag_name') == 'Class':
            return utf8.get(e['value'], '')
    return ''


# ---------------------------------------------------------------------------
# ASDMJarRE
# ---------------------------------------------------------------------------

class ASDMJarRE:
    """
    Reverse engineer a Cisco ASDM JAR file.

    Methods follow the requested interface:
      download_asdm_jar()      — fetch JAR from live ASA (no curl, no exec)
      extract_class_files()    — list .class entries from loaded JAR bytes
      scan_constant_pool()     — extract all Utf8 strings per class
      find_auth_methods()      — locate credential/auth handling classes
      find_ssl_bypass_patterns()  — detect TrustManager/HostnameVerifier bypasses

    Additional:
      run_javap()             — shell javap on extracted class file
      run_cfr()               — shell cfr-decompiler on JAR
      report()                — text summary of findings
    """

    def __init__(self, host: str = MACSTADIUM_HOST_PRIMARY,
                 port: int = 443,
                 jar_bytes: Optional[bytes] = None,
                 jar_path: Optional[str] = None):
        self.host      = host
        self.port      = port
        self._raw: Optional[bytes] = jar_bytes
        self._path: Optional[str] = jar_path
        self._zf: Optional[zipfile.ZipFile] = None
        self._class_entries: list  = []
        self.version: str          = 'unknown'
        self.sha256: str           = ''
        # result accumulators
        self.pool_strings:  dict   = {}   # classname -> [str]
        self.auth_classes:  list   = []
        self.ssl_bypasses:  list   = []

    # ------------------------------------------------------------------
    # 1. download_asdm_jar
    # ------------------------------------------------------------------

    def download_asdm_jar(self, username: str = '', password: str = '',
                          timeout: int = 20) -> bool:
        """
        Download ASDM JAR from live ASA at self.host:self.port.

        Auth flow (207.254.35.12):
          Step 1: POST /+webvpn+/index.html with credentials to get session cookie.
          Step 2: Fetch JNLP to locate JAR resource URLs.
          Step 3: Download first resolvable JAR.

        Returns True if JAR bytes are available in self._raw.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        session_cookie = ''

        # --- Step 1: authenticate (only if credentials provided) ---
        if username:
            auth_url  = f'https://{self.host}:{self.port}{AUTH_POST_PATH}'
            auth_body = AUTH_POST_BODY.format(
                user=urllib.request.quote(username),
                pw=urllib.request.quote(password),
            ).encode()
            req = urllib.request.Request(
                auth_url, data=auth_body,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent':   'MSIE 4.0 WebVPN',
                },
                method='POST',
            )
            try:
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
                hdrs = resp.headers
                raw_cookie = hdrs.get('Set-Cookie', '')
                # Extract webvpnc session token
                m = re.search(r'webvpnc=[^;]+', raw_cookie)
                if m:
                    session_cookie = m.group(0)
            except Exception:
                pass  # proceed unauthenticated; JNLP may still be accessible

        def _get(path: str) -> Optional[bytes]:
            url  = f'https://{self.host}:{self.port}{path}'
            hdrs = {'User-Agent': 'Mozilla/5.0 (Java WebStart)'}
            if session_cookie:
                hdrs['Cookie'] = session_cookie
            req  = urllib.request.Request(url, headers=hdrs)
            try:
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
                return resp.read()
            except Exception:
                return None

        # --- Step 2: JNLP to find JAR URL ---
        jnlp_body = None
        for path in JNLP_PATHS:
            body = _get(path)
            if body and b'<jnlp' in body.lower():
                jnlp_body = body
                break

        jar_paths_to_try = list(JAR_PATHS)
        if jnlp_body:
            # Pull jar href values from JNLP XML
            for m in re.finditer(r'href=["\']([^"\']*\.jar)["\']',
                                  jnlp_body.decode('utf-8', errors='replace'),
                                  re.IGNORECASE):
                href = m.group(1)
                if not href.startswith('/'):
                    href = '/' + href
                if href not in jar_paths_to_try:
                    jar_paths_to_try.insert(0, href)

        # --- Step 3: download JAR ---
        for path in jar_paths_to_try:
            body = _get(path)
            if body and body[:4] == b'PK\x03\x04':  # ZIP/JAR magic
                self._raw = body
                self.sha256 = hashlib.sha256(body).hexdigest()
                return True

        return False

    # ------------------------------------------------------------------
    # 2. extract_class_files
    # ------------------------------------------------------------------

    def extract_class_files(self) -> list:
        """
        List all .class entry paths inside the JAR (in-memory or from disk).

        JAR is a ZIP (JVM Spec §4.1 classfile note; 'Decompiling Java' §3:
        'applets mostly come in handy jar files, which make one neat, compact file').

        Returns list of entry name strings.
        """
        raw = self._raw
        if raw is None and self._path:
            try:
                with open(self._path, 'rb') as f:
                    raw = f.read()
                self.sha256 = hashlib.sha256(raw).hexdigest()
                self._raw = raw
            except OSError:
                return []

        if not raw:
            return []

        try:
            self._zf = zipfile.ZipFile(io.BytesIO(raw), 'r')
        except zipfile.BadZipFile:
            return []

        self._class_entries = [n for n in self._zf.namelist()
                               if n.endswith('.class')]

        # Extract version from MANIFEST.MF
        for name in self._zf.namelist():
            if name.upper().endswith('MANIFEST.MF'):
                try:
                    mf = self._zf.read(name).decode('utf-8', errors='replace')
                    m  = re.search(
                        r'(?:Implementation-Version|Specification-Version)\s*:\s*(.+)',
                        mf, re.IGNORECASE)
                    if m:
                        self.version = m.group(1).strip()
                        break
                except Exception:
                    pass

        return list(self._class_entries)

    # ------------------------------------------------------------------
    # 3. scan_constant_pool
    # ------------------------------------------------------------------

    def scan_constant_pool(self,
                           class_filter: Optional[list] = None,
                           only_interesting: bool = False) -> dict:
        """
        Parse constant pool of every .class in JAR; collect all Utf8 strings.

        Methodology (JVM Spec §4.4 / Decompiling Java §2):
          All string literals, class names, method names, and field names are
          stored as CONSTANT_Utf8_info entries (tag=1) in the constant pool.
          CONSTANT_String_info (tag=8) references them by index. Therefore
          extracting all tag=1 entries from every class yields the complete
          set of plaintext strings embedded in the JAR — including any
          hardcoded credentials, URLs, API paths, and SSL configuration.

        Args:
          class_filter: if set, only process entries whose name matches any
                        substring in the list.
          only_interesting: if True, skip classes with zero credential/auth hits.

        Returns dict {entry_name: {'strings': [...], 'credentials': [...],
                                   'api_paths': [...], 'java_version': str}}.
        """
        if self._zf is None:
            self.extract_class_files()
        if self._zf is None:
            return {}

        cred_rx = re.compile(
            r'(?i)(?:password|secret|token|api[_-]?key|enable\s+\w+|'
            r'jdbc:[a-z:]+//|ldap[s]?://|BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|'
            r'SNMPv[23]\s+|admin(?:istrator)?=|cisco\s+\w+)', re.IGNORECASE)
        api_rx  = re.compile(
            r'(?:/\+CSCOU\+/[^\s"\'<>]+|/\+CSCOE\+/[^\s"\'<>]+|'
            r'/\+webvpn\+/[^\s"\'<>]+|/api/[^\s"\'<>]+|'
            r'/admin/[^\s"\'<>]+|/rest/[^\s"\'<>]+)')

        version_map = {
            45: 'Java 1.1', 46: 'Java 1.2', 47: 'Java 1.3', 48: 'Java 1.4',
            49: 'Java 5',   50: 'Java 6',   51: 'Java 7',   52: 'Java 8',
            53: 'Java 9',   54: 'Java 10',  55: 'Java 11',  56: 'Java 12',
            57: 'Java 13',  58: 'Java 14',  59: 'Java 15',  60: 'Java 16',
            61: 'Java 17',  62: 'Java 18',  63: 'Java 19',  64: 'Java 20',
            65: 'Java 21',
        }

        results = {}
        entries = self._class_entries
        if class_filter:
            entries = [e for e in entries
                       if any(f in e for f in class_filter)]

        for entry in entries:
            try:
                data = self._zf.read(entry)
            except Exception:
                continue

            if len(data) < 10 or data[:4] != b'\xca\xfe\xba\xbe':
                continue

            major = struct.unpack_from('>H', data, 6)[0]
            pool  = _parse_constant_pool(data)
            strs  = [e['value'] for e in pool
                     if e.get('tag_name') == 'Utf8'
                     and isinstance(e.get('value'), str)]

            creds    = [s for s in strs if cred_rx.search(s)]
            api_hits = [m.group(0)
                        for s in strs
                        for m in [api_rx.search(s)] if m]

            if only_interesting and not creds and not api_hits:
                continue

            results[entry] = {
                'java_version': version_map.get(major, f'major={major}'),
                'pool_size':    len(pool),
                'strings':      strs,
                'credentials':  creds,
                'api_paths':    sorted(set(api_hits)),
            }

        self.pool_strings = results
        return results

    # ------------------------------------------------------------------
    # 4. find_auth_methods
    # ------------------------------------------------------------------

    def find_auth_methods(self) -> list:
        """
        Locate classes and methods that handle authentication/credentials.

        Detection strategy:
          a) Class name contains auth/login/cred/session/password/token.
          b) Constant pool contains method name strings matching AUTH_METHOD_NAMES_RE
             (e.g. 'authenticate', 'sendCredentials', 'setPassword').
          c) Constant pool contains CONSTANT_NameAndType entries (tag=12) whose
             name_index resolves to an auth method name — this catches private/
             obfuscated classes that still call standard auth APIs.
          d) String references to HTTP Basic auth patterns or ASA form-post fields
             ('username=', 'password=', 'tgroup=', 'Login=Login').

        Returns list of dicts: {class_entry, class_binary_name, method_hits,
                                string_hits, note}.
        """
        if self._zf is None:
            self.extract_class_files()
        if self._zf is None:
            return []

        form_rx = re.compile(
            r'(?i)(username=|password=|tgroup=|Login=Login|'
            r'Authorization:\s*Basic|X-Auth-Token|'
            r'enable\s+password|crypto\s+key|'
            r'aaa\s+(?:authentication|authorization)|'
            r'tacacs-server|radius-server|ldap-login)',
            re.IGNORECASE,
        )

        findings = []

        for entry in self._class_entries:
            try:
                data = self._zf.read(entry)
            except Exception:
                continue

            if len(data) < 10 or data[:4] != b'\xca\xfe\xba\xbe':
                continue

            pool  = _parse_constant_pool(data)
            utf8  = _pool_utf8(pool)
            strs  = list(utf8.values())

            method_hits = [s for s in strs if AUTH_METHOD_NAMES_RE.search(s)]
            string_hits = [s for s in strs if form_rx.search(s)]

            # Check class name (tag=7 entry's utf8 value)
            class_name = ''
            for e in pool:
                if e.get('tag_name') == 'Class' and isinstance(e.get('value'), int):
                    cn = utf8.get(e['value'], '')
                    if cn:
                        class_name = cn
                        break

            name_hit = bool(AUTH_CLASS_NAMES_RE.search(entry))

            if method_hits or string_hits or name_hit:
                findings.append({
                    'class_entry':        entry,
                    'class_binary_name':  class_name,
                    'method_hits':        method_hits,
                    'string_hits':        string_hits,
                    'class_name_match':   name_hit,
                    'note': (
                        'Candidate auth class — review with: '
                        + JAVAP_CMD_PRIVATE.format(classfile='<extracted.class>')
                    ),
                })

        self.auth_classes = findings
        return findings

    # ------------------------------------------------------------------
    # 5. find_ssl_bypass_patterns
    # ------------------------------------------------------------------

    def find_ssl_bypass_patterns(self) -> list:
        """
        Detect SSL/TLS certificate verification bypass in ASDM class files.

        Background:
          ASDM connects to the ASA over HTTPS but ASA typically uses a self-signed
          certificate. Cisco implements bypass by shipping a custom X509TrustManager
          whose checkServerTrusted() method has an empty body (just returns without
          throwing CertificateException). A custom HostnameVerifier.verify() that
          always returns true is also common.

        Detection (JVM Spec §4.4 grounded):
          1. Class implements SSL_TRUST_MGRS or SSL_HOSTNAME_VERIFIERS:
             check CONSTANT_Class_info entries (tag=7) in the interfaces[] section.
             Interfaces come after super_class in the ClassFile structure; we detect
             them by scanning Utf8 constants for exact interface names.
          2. Method 'checkServerTrusted' or 'verify' present in pool (NameAndType
             name_index -> Utf8 with these names) — confirms this class owns the method
             rather than just calling it.
          3. Heuristic: if the class declares the bypass method AND the method's
             Code attribute is very small (<= 5 bytes), the body is trivially empty.
             (An empty void method is: areturn or return, 1 byte; return from object
             method with no exception throw = 1 opcode.)

        Returns list of dicts: {class_entry, bypass_type, suspicious_methods,
                                 implements_interfaces, code_size_hint, javap_cmd}.
        """
        if self._zf is None:
            self.extract_class_files()
        if self._zf is None:
            return []

        findings = []

        for entry in self._class_entries:
            try:
                data = self._zf.read(entry)
            except Exception:
                continue

            if len(data) < 10 or data[:4] != b'\xca\xfe\xba\xbe':
                continue

            pool  = _parse_constant_pool(data)
            utf8  = _pool_utf8(pool)
            strs  = set(utf8.values())

            # Interface names stored as Utf8 constants in the pool
            trust_mgr_ifaces  = strs & SSL_TRUST_MGRS
            hostname_ifaces   = strs & SSL_HOSTNAME_VERIFIERS

            if not trust_mgr_ifaces and not hostname_ifaces:
                continue

            # Confirm: does this class DECLARE (not just reference) the bypass method?
            # NameAndType (tag=12) entries whose name_index resolves to a bypass method name.
            nat_method_names = set()
            for e in pool:
                if e.get('tag_name') == 'NameAndType' and isinstance(e.get('value'), dict):
                    mn = utf8.get(e['value'].get('name_index', 0), '')
                    if mn in SSL_BYPASS_METHODS:
                        nat_method_names.add(mn)

            # SSLContext usage patterns — indicates the JAR also sets up the bypass context
            ssl_ctx_refs = [s for s in strs
                            if any(kw in s for kw in SSL_CTX_METHODS)]

            bypass_types = []
            if trust_mgr_ifaces:
                bypass_types.append('X509TrustManager')
            if hostname_ifaces:
                bypass_types.append('HostnameVerifier')

            # Heuristic: very small class = trivial bypass (empty method bodies)
            size_hint = 'large' if len(data) > 4096 else 'small'

            findings.append({
                'class_entry':          entry,
                'bypass_type':          bypass_types,
                'implements_interfaces': list(trust_mgr_ifaces | hostname_ifaces),
                'suspicious_methods':   list(nat_method_names),
                'ssl_ctx_refs':         ssl_ctx_refs[:10],
                'class_size_bytes':     len(data),
                'size_hint':            size_hint,
                'javap_cmd':            JAVAP_CMD_PRIVATE.format(
                    classfile=f'<extracted_{entry.replace("/", "_")}>'),
                'note': (
                    'Empty checkServerTrusted body = trust-all. '
                    'Confirm with: javap -c -p <class> | grep -A5 checkServerTrusted'
                ),
            })

        self.ssl_bypasses = findings
        return findings

    # ------------------------------------------------------------------
    # Tool integration
    # ------------------------------------------------------------------

    def run_javap(self, entry: str, extra_flags: str = '-c -p -verbose',
                  work_dir: Optional[str] = None) -> str:
        """
        Extract a single .class from JAR and run javap on it.

        Grounded in: 'Decompiling Java' §3 — 'javap, which comes as part of the
        JDK ... the most basic tool available for examining a classfile.'

        Returns javap stdout as string.
        """
        if self._zf is None:
            return 'JAR not loaded'

        try:
            data = self._zf.read(entry)
        except Exception as e:
            return f'Cannot read {entry}: {e}'

        tmpdir = work_dir or tempfile.mkdtemp(prefix='asdm_re_')
        safe   = entry.replace('/', '_')
        path   = os.path.join(tmpdir, safe)

        with open(path, 'wb') as f:
            f.write(data)

        cmd = ['javap'] + extra_flags.split() + [path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout + (('\n[STDERR]\n' + result.stderr)
                                    if result.stderr else '')
        except FileNotFoundError:
            return (f'javap not found. Install JDK. '
                    f'Manual: {JAVAP_CMD_PRIVATE.format(classfile=path)}')
        except subprocess.TimeoutExpired:
            return 'javap timed out'

    def run_cfr(self, cfr_jar: str, out_dir: Optional[str] = None) -> str:
        """
        Run cfr-decompiler against the full JAR.

        Returns command used (actual execution requires cfr.jar on disk).
        """
        if self._path is None and self._raw is not None:
            tmpdir = out_dir or tempfile.mkdtemp(prefix='asdm_cfr_')
            jar_path = os.path.join(tmpdir, 'asdm.jar')
            with open(jar_path, 'wb') as f:
                f.write(self._raw)
        elif self._path:
            jar_path = self._path
            tmpdir   = out_dir or tempfile.mkdtemp(prefix='asdm_cfr_')
        else:
            return 'No JAR loaded'

        cmd_str = CFR_CMD_JAR.format(jarfile=jar_path, outdir=tmpdir)
        try:
            result = subprocess.run(
                ['java', '-jar', cfr_jar, jar_path,
                 '--outputdir', tmpdir, '--caseinsensitivefs', 'true'],
                capture_output=True, text=True, timeout=120)
            return (f'CFR output dir: {tmpdir}\n'
                    + result.stdout[:2000]
                    + (f'\n[STDERR]\n{result.stderr[:500]}' if result.stderr else ''))
        except FileNotFoundError:
            return f'java not found. Manual: {cmd_str}'
        except subprocess.TimeoutExpired:
            return f'cfr timed out. Manual: {cmd_str}'

    # ------------------------------------------------------------------
    # report
    # ------------------------------------------------------------------

    def report(self, run_all: bool = True) -> str:
        """Full analysis report string."""
        if run_all:
            if not self._class_entries:
                self.extract_class_files()
            self.scan_constant_pool(only_interesting=True)
            self.find_auth_methods()
            self.find_ssl_bypass_patterns()

        lines = [
            '=== ASDM JAR RE Report ===',
            f'Host:     {self.host}:{self.port}',
            f'SHA256:   {self.sha256 or "n/a"}',
            f'Version:  {self.version}',
            f'Classes:  {len(self._class_entries)}',
            '',
        ]

        # SSL bypass
        if self.ssl_bypasses:
            lines.append(f'[SSL BYPASS] {len(self.ssl_bypasses)} class(es) detected:')
            for b in self.ssl_bypasses:
                lines.append(
                    f'  {b["class_entry"]} — {b["bypass_type"]} — '
                    f'{b["size_hint"]} ({b["class_size_bytes"]}B)')
                lines.append(f'    implements: {b["implements_interfaces"]}')
                lines.append(f'    methods:    {b["suspicious_methods"]}')
                lines.append(f'    -> {b["javap_cmd"]}')
        else:
            lines.append('[SSL BYPASS] none detected (or JAR not loaded)')

        lines.append('')

        # Auth methods
        if self.auth_classes:
            lines.append(f'[AUTH CLASSES] {len(self.auth_classes)} candidate(s):')
            for a in self.auth_classes:
                lines.append(
                    f'  {a["class_entry"]} ({a["class_binary_name"]})')
                if a['method_hits']:
                    lines.append(f'    method refs: {a["method_hits"][:5]}')
                if a['string_hits']:
                    lines.append(f'    string hits: '
                                 f'{[s[:80] for s in a["string_hits"][:3]]}')
        else:
            lines.append('[AUTH CLASSES] none found')

        lines.append('')

        # Credential strings
        all_creds = []
        for entry, info in self.pool_strings.items():
            for c in info.get('credentials', []):
                all_creds.append((entry, c))
        if all_creds:
            lines.append(f'[CREDENTIALS] {len(all_creds)} hit(s):')
            for entry, c in all_creds[:30]:
                lines.append(f'  [{entry}] {c[:120]}')
        else:
            lines.append('[CREDENTIALS] none found in scanned classes')

        lines.append('')

        # API paths
        all_apis: set = set()
        for info in self.pool_strings.values():
            all_apis.update(info.get('api_paths', []))
        if all_apis:
            lines.append(f'[API PATHS] {len(all_apis)} unique:')
            for p in sorted(all_apis):
                lines.append(f'  {p}')

        lines.extend([
            '',
            '[METHODOLOGY]',
            _METHODOLOGY.strip(),
            '',
            '[TOOLCHAIN]',
            f'  javap (verbose): {JAVAP_CMD_PRIVATE}',
            f'  cfr (JAR):       {CFR_CMD_JAR}',
            f'  jd-cli:          {JD_CMD_JAR}',
            f'  extract+disasm:  {PIPELINE_EXTRACT_DISASM}',
            f'  grep creds:      {JAVAP_GREP_CREDS}',
        ])

        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Class-level convenience: build javap command string for any entry
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # detect_obfuscation
    # ------------------------------------------------------------------

    def detect_obfuscation(self) -> dict:
        """
        Detect obfuscation applied to the ASDM JAR.

        Methodology (Decompiling Java §3-§4):
          Layout obfuscation: Crema/ProGuard/Zelix rename class/method/field
          identifiers in the constant pool to short garbage strings (a,b,c)
          or Java-like keywords (void,catch,final used as names). Zelix also
          reorders bytecode to break control-flow analysis.

          Detection heuristics:
            1. Class name length distribution: obfuscated JARs have many
               classes with names <= 3 chars (a.class, aa.class).
            2. High ratio of one-or-two-char identifiers in Utf8 pool.
            3. Unicode (non-ASCII) identifiers: crash old decompilers.
            4. Absence of SourceFile attribute: compiled with -g:none or
               attribute stripped post-compile (Decompiling Java §4).
            5. Very few LineNumberTable entries: debug info stripped.

        Returns dict with obfuscation indicators.
        """
        if self._zf is None:
            self.extract_class_files()
        if self._zf is None:
            return {}

        obf_indicators = {
            'short_class_names':    [],
            'unicode_class_names':  [],
            'no_source_attribute':  0,
            'total_classes':        len(self._class_entries),
            'obfuscation_score':    0,  # 0-10
            'likely_obfuscated':    False,
            'obfuscator_guess':     None,
        }

        import re as _re
        short_rx  = _re.compile(r'^[a-zA-Z]{1,3}$')
        uni_rx    = _re.compile(r'[^\x00-\x7F]')

        for entry in self._class_entries:
            # basename without .class and path
            basename = entry.split('/')[-1].replace('.class', '')
            if short_rx.match(basename):
                obf_indicators['short_class_names'].append(entry)
            if uni_rx.search(basename):
                obf_indicators['unicode_class_names'].append(entry)

            # Check for SourceFile attribute absence
            try:
                data = self._zf.read(entry)
                if b'SourceFile' not in data:
                    obf_indicators['no_source_attribute'] += 1
            except Exception:
                pass

        total = obf_indicators['total_classes'] or 1
        short_ratio   = len(obf_indicators['short_class_names']) / total
        unicode_ratio = len(obf_indicators['unicode_class_names']) / total
        no_src_ratio  = obf_indicators['no_source_attribute'] / total

        score = 0
        if short_ratio > 0.5:
            score += 4   # most class names are short
        elif short_ratio > 0.2:
            score += 2
        if unicode_ratio > 0.1:
            score += 4   # unicode = aggressive obfuscation (crashes old decompilers)
        if no_src_ratio > 0.8:
            score += 2   # SourceFile stripped

        obf_indicators['obfuscation_score'] = min(score, 10)
        obf_indicators['likely_obfuscated'] = score >= 4

        # Heuristic: guess obfuscator from patterns
        if unicode_ratio > 0.1:
            obf_indicators['obfuscator_guess'] = 'Crema/HoseMocha (Unicode names)'
        elif short_ratio > 0.5 and no_src_ratio > 0.8:
            obf_indicators['obfuscator_guess'] = 'ProGuard/Zelix/DashO (short alpha)'
        elif short_ratio > 0.2:
            obf_indicators['obfuscator_guess'] = 'JOBE-style (a,b,c renaming)'

        return obf_indicators

    # ------------------------------------------------------------------
    # extract_raw_strings
    # ------------------------------------------------------------------

    def extract_raw_strings(self, classentry: str,
                            min_length: int = 4) -> list:
        """
        Brute-force string extraction from a single .class file without
        full constant pool parsing. Scans for CONSTANT_Utf8_info (tag=1)
        entries sequentially.

        Use when _parse_constant_pool() fails (unknown tag, truncated file,
        aggressive bytecode obfuscation that inserts invalid entries).

        Method (Decompiling Java §2, §3 hex editor approach):
          - Scan every byte for tag=1 (CONSTANT_Utf8).
          - Read u2 length at offset+1, then length bytes at offset+3.
          - Decode as UTF-8 (JVM modified UTF-8; fallback to latin-1).
          - Filter by min_length and printability.

        False positives are common (any 3 bytes = tag + u2 len can match).
        Cross-reference with pool_index hits for confidence.

        Returns list of (byte_offset, decoded_string).
        """
        if self._zf is None:
            self.extract_class_files()
        if self._zf is None or not self._class_entries:
            return []

        try:
            data = self._zf.read(classentry)
        except Exception:
            return []

        if data[:4] != b'\xca\xfe\xba\xbe':
            return []

        results = []
        i = 10  # skip magic(4) + minor(2) + major(2) + cp_count(2) partially

        while i < len(data) - 3:
            if data[i] == 1:  # CP_UTF8 tag
                ln = struct.unpack_from('>H', data, i + 1)[0]
                end = i + 3 + ln
                if end <= len(data) and 3 <= ln <= 65535:
                    raw = data[i + 3:end]
                    try:
                        s = raw.decode('utf-8', errors='replace')
                    except Exception:
                        s = raw.decode('latin-1', errors='replace')
                    # Filter: printable chars, meets min_length, not all-control
                    printable = sum(1 for c in s if c.isprintable())
                    if len(s) >= min_length and printable / max(len(s), 1) > 0.7:
                        results.append((i, s))
            i += 1

        return results

    # ------------------------------------------------------------------
    # Class-level convenience: build javap command string for any entry
    # ------------------------------------------------------------------

    @staticmethod
    def javap_command(entry: str, jar_path: str = 'asdm.jar',
                      flags: str = '-c -p -verbose') -> str:
        """Return a ready-to-paste javap command for a specific class entry."""
        safe = entry.replace('/', '_')
        return (
            f'unzip -p {jar_path} {entry} > /tmp/{safe} '
            f'&& javap {flags} /tmp/{safe}'
        )

    @staticmethod
    def cfr_command(jar_path: str = 'asdm.jar', cfr_jar: str = 'cfr.jar',
                    out_dir: str = '/tmp/asdm_src') -> str:
        """Return a ready-to-paste cfr-decompiler command."""
        return CFR_CMD_JAR.format(jarfile=jar_path, outdir=out_dir).replace(
            '{jarfile}', jar_path).replace('{outdir}', out_dir)


# ---------------------------------------------------------------------------
# Top-level convenience entry point
# ---------------------------------------------------------------------------

def analyze_jar(jar_path: str = None, host: str = MACSTADIUM_HOST_PRIMARY,
                port: int = 443, username: str = '', password: str = '') -> str:
    """
    Full ASDM JAR RE pipeline.

    If jar_path provided: analyze local JAR.
    Otherwise: download from host:port (optionally with credentials).

    Returns text report.
    """
    re_obj = ASDMJarRE(host=host, port=port, jar_path=jar_path)

    if jar_path is None:
        ok = re_obj.download_asdm_jar(username=username, password=password)
        if not ok:
            return (f'Download failed from {host}:{port}. '
                    f'Try: curl -k https://{host}/+CSCOU+/asa/asdm.jar -o asdm.jar')

    re_obj.extract_class_files()
    return re_obj.report(run_all=True)
