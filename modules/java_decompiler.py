#!/usr/bin/env python3
"""
Java Bytecode Analysis Module
Synthesized from: Decompiling Java (9781430207399),
                  Refactoring in Java (9781805126638),
                  Data Structures and Algorithms in Java (9780134849775, 9781118771334)

Parses .class files, extracts constant pool, methods, fields, and flags.
Identifies security-relevant patterns: reflection, serialization, hardcoded creds,
ClassLoader abuse, deserialization gadgets, and insecure RNG.

.class file layout (big-endian):
  u4 magic (0xCAFEBABE) | u2 minor | u2 major | u2 cp_count | cp_info[] |
  u2 access_flags | u2 this_class | u2 super_class | u2 iface_count | u2[] |
  u2 field_count | field_info[] | u2 method_count | method_info[] |
  u2 attr_count | attr_info[]
"""

import re
import struct
import os
import zipfile
import io
from pathlib import Path
from typing import Optional


# ── Constant Pool tags (JVM spec §4.4) ────────────────────────────────────────

CP_UTF8               = 1
CP_INTEGER            = 3
CP_FLOAT              = 4
CP_LONG               = 5
CP_DOUBLE             = 6
CP_CLASS              = 7
CP_STRING             = 8
CP_FIELDREF           = 9
CP_METHODREF          = 10
CP_IFACE_METHODREF    = 11
CP_NAME_AND_TYPE      = 12
CP_METHOD_HANDLE      = 15
CP_METHOD_TYPE        = 16
CP_DYNAMIC            = 17
CP_INVOKE_DYNAMIC     = 18
CP_MODULE             = 19
CP_PACKAGE            = 20

# CP tags that consume two slots (long, double)
CP_WIDE_TAGS = {CP_LONG, CP_DOUBLE}


# ── Class access flags ─────────────────────────────────────────────────────────

ACC_PUBLIC       = 0x0001
ACC_FINAL        = 0x0010
ACC_SUPER        = 0x0020
ACC_INTERFACE    = 0x0200
ACC_ABSTRACT     = 0x0400
ACC_SYNTHETIC    = 0x1000
ACC_ANNOTATION   = 0x2000
ACC_ENUM         = 0x4000
ACC_MODULE       = 0x8000

# Method/field flags
ACC_PRIVATE      = 0x0002
ACC_PROTECTED    = 0x0004
ACC_STATIC       = 0x0008
ACC_SYNCHRONIZED = 0x0020
ACC_BRIDGE       = 0x0040
ACC_VARARGS      = 0x0080
ACC_NATIVE       = 0x0100
ACC_STRICT       = 0x0800


# ── Bytecode opcodes (security-relevant subset) ────────────────────────────────

OPCODES = {
    # invoke family
    0xb6: 'invokevirtual',
    0xb7: 'invokespecial',
    0xb8: 'invokestatic',
    0xb9: 'invokeinterface',
    0xba: 'invokedynamic',
    # object / class ops
    0xbb: 'new',
    0xbd: 'anewarray',
    0xc0: 'checkcast',
    0xc1: 'instanceof',
    # field access
    0xb4: 'getfield',
    0xb5: 'putfield',
    0xb2: 'getstatic',
    0xb3: 'putstatic',
    # returns
    0xb0: 'areturn', 0xac: 'ireturn', 0xad: 'lreturn',
    0xae: 'freturn', 0xaf: 'dreturn', 0xb1: 'return',
    # load constants
    0x12: 'ldc', 0x13: 'ldc_w', 0x14: 'ldc2_w',
    # throws
    0xbf: 'athrow',
}

# Methods that indicate security-relevant behaviour
SECURITY_METHODS = {
    # Reflection
    ('java/lang/Class',       'forName'),
    ('java/lang/Class',       'newInstance'),
    ('java/lang/Class',       'getMethod'),
    ('java/lang/Class',       'getDeclaredMethod'),
    ('java/lang/Class',       'getConstructor'),
    ('java/lang/reflect/Method', 'invoke'),
    # ClassLoader abuse
    ('java/lang/ClassLoader', 'loadClass'),
    ('java/lang/ClassLoader', 'defineClass'),
    # Deserialization gadgets
    ('java/io/ObjectInputStream', 'readObject'),
    ('java/io/ObjectInputStream', 'readUnshared'),
    # Command execution
    ('java/lang/Runtime',     'exec'),
    ('java/lang/ProcessBuilder', 'start'),
    # RNG (insecure)
    ('java/util/Random',      '<init>'),
    # Crypto weak
    ('javax/crypto/Cipher',   'getInstance'),
    ('java/security/MessageDigest', 'getInstance'),
    # SQL injection surface
    ('java/sql/Statement',    'executeQuery'),
    ('java/sql/Statement',    'execute'),
    ('java/sql/Statement',    'executeUpdate'),
    # Scripting engine (code execution)
    ('javax/script/ScriptEngine', 'eval'),
    ('javax/script/ScriptEngine', 'put'),
}

# Descriptor types (JVM §4.3.2)
DESC_TYPES = {
    'B': 'byte', 'C': 'char', 'D': 'double', 'F': 'float',
    'I': 'int',  'J': 'long', 'S': 'short',  'V': 'void', 'Z': 'boolean',
}


def _parse_descriptor(desc: str) -> str:
    """Convert JVM method descriptor to human-readable signature."""
    if not desc.startswith('('):
        return desc

    result = []
    i = 1  # skip '('
    params = []
    while i < len(desc) and desc[i] != ')':
        t, i = _next_type(desc, i)
        params.append(t)
    i += 1  # skip ')'
    ret, _ = _next_type(desc, i)
    return f"({', '.join(params)}) -> {ret}"


def _next_type(desc: str, i: int):
    """Parse one type token from descriptor starting at index i."""
    c = desc[i]
    if c in DESC_TYPES:
        return DESC_TYPES[c], i + 1
    if c == 'L':
        end = desc.index(';', i)
        return desc[i+1:end].replace('/', '.'), end + 1
    if c == '[':
        inner, ni = _next_type(desc, i + 1)
        return inner + '[]', ni
    return c, i + 1


class ClassFile:
    """Parses a single JVM .class file."""

    MAGIC = 0xCAFEBABE

    def __init__(self, data: bytes):
        self.data = data
        self.cp = []          # constant pool (1-indexed; index 0 = None placeholder)
        self.class_name = ''
        self.super_name = ''
        self.interfaces = []
        self.access_flags = 0
        self.fields = []
        self.methods = []
        self.attributes = []
        self.major_version = 0
        self.minor_version = 0
        self._off = 0

    def _u1(self): v = self.data[self._off]; self._off += 1; return v
    def _u2(self): v = struct.unpack_from('>H', self.data, self._off)[0]; self._off += 2; return v
    def _u4(self): v = struct.unpack_from('>I', self.data, self._off)[0]; self._off += 4; return v
    def _bytes(self, n): v = self.data[self._off:self._off+n]; self._off += n; return v

    def parse(self) -> dict:
        if len(self.data) < 8:
            return {'error': 'too short'}
        magic = self._u4()
        if magic != self.MAGIC:
            return {'error': f'bad magic 0x{magic:08X}'}

        self.minor_version = self._u2()
        self.major_version = self._u2()
        self._parse_constant_pool()
        self.access_flags = self._u2()
        this_idx  = self._u2()
        super_idx = self._u2()

        self.class_name = self._cp_class_name(this_idx)
        self.super_name = self._cp_class_name(super_idx) if super_idx else ''

        iface_count = self._u2()
        self.interfaces = [self._cp_class_name(self._u2()) for _ in range(iface_count)]

        field_count = self._u2()
        self.fields = [self._parse_member() for _ in range(field_count)]

        method_count = self._u2()
        self.methods = [self._parse_member() for _ in range(method_count)]

        attr_count = self._u2()
        self.attributes = [self._parse_attribute() for _ in range(attr_count)]

        return self._build_result()

    def _parse_constant_pool(self):
        count = self._u2()
        self.cp = [None]  # 1-indexed
        i = 1
        while i < count:
            tag = self._u1()
            if tag == CP_UTF8:
                length = self._u2()
                s = self._bytes(length).decode('utf-8', errors='replace')
                self.cp.append({'tag': tag, 'value': s})
            elif tag in (CP_INTEGER, CP_FLOAT):
                self.cp.append({'tag': tag, 'value': self._u4()})
            elif tag in (CP_LONG, CP_DOUBLE):
                hi = self._u4(); lo = self._u4()
                self.cp.append({'tag': tag, 'value': (hi << 32) | lo})
                self.cp.append(None)  # wide entry occupies two slots
                i += 1
            elif tag in (CP_CLASS, CP_STRING, CP_METHOD_TYPE,
                         CP_MODULE, CP_PACKAGE):
                self.cp.append({'tag': tag, 'idx': self._u2()})
            elif tag in (CP_FIELDREF, CP_METHODREF, CP_IFACE_METHODREF,
                         CP_NAME_AND_TYPE, CP_DYNAMIC, CP_INVOKE_DYNAMIC):
                self.cp.append({'tag': tag, 'idx1': self._u2(), 'idx2': self._u2()})
            elif tag == CP_METHOD_HANDLE:
                self.cp.append({'tag': tag, 'kind': self._u1(), 'idx': self._u2()})
            else:
                self.cp.append({'tag': tag})
            i += 1

    def _cp_utf8(self, idx: int) -> str:
        if 0 < idx < len(self.cp) and self.cp[idx]:
            return self.cp[idx].get('value', '')
        return ''

    def _cp_class_name(self, idx: int) -> str:
        if 0 < idx < len(self.cp) and self.cp[idx]:
            name_idx = self.cp[idx].get('idx', 0)
            return self._cp_utf8(name_idx).replace('/', '.')
        return ''

    def _cp_nameandtype(self, idx: int) -> tuple:
        if 0 < idx < len(self.cp) and self.cp[idx]:
            e = self.cp[idx]
            return self._cp_utf8(e.get('idx1', 0)), self._cp_utf8(e.get('idx2', 0))
        return '', ''

    def _parse_member(self) -> dict:
        flags = self._u2()
        name_idx = self._u2()
        desc_idx = self._u2()
        attr_count = self._u2()
        attrs = [self._parse_attribute() for _ in range(attr_count)]
        return {
            'flags': flags,
            'name': self._cp_utf8(name_idx),
            'descriptor': self._cp_utf8(desc_idx),
            'attributes': attrs,
        }

    def _parse_attribute(self) -> dict:
        name_idx = self._u2()
        length = self._u4()
        name = self._cp_utf8(name_idx)
        data = self._bytes(length)
        return {'name': name, 'data': data}

    def _build_result(self) -> dict:
        java_ver = self.major_version - 44 if self.major_version >= 44 else self.major_version
        flags_str = self._decode_class_flags(self.access_flags)

        methods_out = []
        for m in self.methods:
            desc_human = _parse_descriptor(m['descriptor'])
            mflags = self._decode_method_flags(m['flags'])
            methods_out.append({
                'name': m['name'],
                'descriptor': m['descriptor'],
                'signature': f"{m['name']}{desc_human}",
                'flags': mflags,
            })

        fields_out = []
        for f in self.fields:
            fields_out.append({
                'name': f['name'],
                'descriptor': f['descriptor'],
                'flags': self._decode_method_flags(f['flags']),
            })

        strings = self._extract_string_constants()

        return {
            'class_name': self.class_name,
            'super_class': self.super_name,
            'interfaces': self.interfaces,
            'access_flags': flags_str,
            'java_version': java_ver,
            'major': self.major_version,
            'methods': methods_out,
            'fields': fields_out,
            'string_constants': strings[:64],
        }

    def _extract_string_constants(self) -> list:
        strings = []
        for entry in self.cp:
            if entry and entry.get('tag') == CP_STRING:
                val = self._cp_utf8(entry.get('idx', 0))
                if val:
                    strings.append(val)
        return strings

    def _decode_class_flags(self, f: int) -> list:
        out = []
        if f & ACC_PUBLIC:    out.append('public')
        if f & ACC_FINAL:     out.append('final')
        if f & ACC_INTERFACE: out.append('interface')
        if f & ACC_ABSTRACT:  out.append('abstract')
        if f & ACC_SYNTHETIC: out.append('synthetic')
        if f & ACC_ANNOTATION:out.append('annotation')
        if f & ACC_ENUM:      out.append('enum')
        return out

    def _decode_method_flags(self, f: int) -> list:
        out = []
        if f & ACC_PUBLIC:       out.append('public')
        if f & ACC_PRIVATE:      out.append('private')
        if f & ACC_PROTECTED:    out.append('protected')
        if f & ACC_STATIC:       out.append('static')
        if f & ACC_FINAL:        out.append('final')
        if f & ACC_SYNCHRONIZED: out.append('synchronized')
        if f & ACC_NATIVE:       out.append('native')
        if f & ACC_ABSTRACT:     out.append('abstract')
        if f & ACC_SYNTHETIC:    out.append('synthetic')
        if f & ACC_BRIDGE:       out.append('bridge')
        return out


class JavaAnalyzer:
    """Analyzes Java .class and .jar files for security-relevant patterns."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.findings = []
        self._classes = []

    def analyze(self) -> dict:
        suffix = self.path.suffix.lower()
        if suffix == '.class':
            self._analyze_class_file(self.path.read_bytes(), str(self.path))
        elif suffix in ('.jar', '.war', '.ear', '.zip'):
            self._analyze_jar(str(self.path))
        else:
            try:
                data = self.path.read_bytes()
                if data[:4] == b'\xca\xfe\xba\xbe':
                    self._analyze_class_file(data, str(self.path))
                elif data[:2] == b'PK':
                    self._analyze_jar(str(self.path))
            except Exception:
                pass

        security = self._security_audit()
        return {
            'path': str(self.path),
            'classes': self._classes,
            'security': security,
            'findings': self.findings,
        }

    def _analyze_class_file(self, data: bytes, source: str):
        try:
            cf = ClassFile(data)
            info = cf.parse()
            if 'error' not in info:
                info['source'] = source
                self._classes.append(info)
                self._scan_strings(info.get('string_constants', []),
                                   info['class_name'])
        except Exception:
            pass

    def _analyze_jar(self, jar_path: str):
        try:
            with zipfile.ZipFile(jar_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.class'):
                        try:
                            data = zf.read(name)
                            self._analyze_class_file(data, f"{jar_path}!{name}")
                        except Exception:
                            pass
        except Exception:
            pass

    def _scan_strings(self, strings: list, class_name: str):
        suspicious_patterns = [
            ('password', 'HARDCODED_CREDENTIAL'),
            ('passwd',   'HARDCODED_CREDENTIAL'),
            ('secret',   'HARDCODED_CREDENTIAL'),
            ('api_key',  'HARDCODED_CREDENTIAL'),
            ('apikey',   'HARDCODED_CREDENTIAL'),
            ('token',    'HARDCODED_CREDENTIAL'),
            ('jdbc:',    'DATABASE_URL'),
            ('mongodb:', 'DATABASE_URL'),
            ('redis://', 'DATABASE_URL'),
            ('BEGIN RSA', 'EMBEDDED_KEY'),
            ('BEGIN EC', 'EMBEDDED_KEY'),
            ('-----BEGIN', 'EMBEDDED_KEY'),
            ('DES',      'WEAK_CIPHER'),
            ('MD5',      'WEAK_HASH'),
            ('SHA1',     'WEAK_HASH'),
            ('RC4',      'WEAK_CIPHER'),
        ]
        for s in strings:
            sl = s.lower()
            for pattern, tag in suspicious_patterns:
                if pattern.lower() in sl:
                    self.findings.append({
                        'type': tag,
                        'class': class_name,
                        'value': s[:120],
                        'severity': 'HIGH' if tag == 'HARDCODED_CREDENTIAL' else 'MEDIUM',
                    })
                    break

    def _security_audit(self) -> dict:
        method_hits = []
        native_methods = []
        serializable = []
        reflection_users = []
        exec_users = []

        for cls in self._classes:
            cname = cls.get('class_name', '')
            ifaces = cls.get('interfaces', [])

            # Serializable → deserialization gadget candidate
            if any('Serializable' in i for i in ifaces):
                serializable.append(cname)

            for m in cls.get('methods', []):
                mname = m['name']
                mflags = m.get('flags', [])

                if 'native' in mflags:
                    native_methods.append(f"{cname}.{mname}")

                # Check if method name matches known dangerous patterns
                for (cls_pattern, meth_pattern) in SECURITY_METHODS:
                    if meth_pattern in mname and cls_pattern.split('/')[-1] in cname:
                        if 'reflection' in cls_pattern:
                            reflection_users.append(f"{cname}.{mname}")
                        elif 'Runtime' in cls_pattern or 'ProcessBuilder' in cls_pattern:
                            exec_users.append(f"{cname}.{mname}")
                        method_hits.append({
                            'class': cname,
                            'method': mname,
                            'pattern': cls_pattern + '.' + meth_pattern,
                        })

        return {
            'serializable_classes': serializable,
            'native_methods': native_methods,
            'dangerous_method_calls': method_hits,
            'reflection_users': reflection_users,
            'exec_users': exec_users,
        }


def scan_java_artifacts(root: str = '/', max_depth: int = 5) -> list:
    """Walk filesystem looking for .class/.jar files up to max_depth."""
    results = []
    root_path = Path(root)
    try:
        for item in root_path.rglob('*'):
            if item.suffix.lower() in ('.class', '.jar', '.war', '.ear'):
                try:
                    analyzer = JavaAnalyzer(str(item))
                    result = analyzer.analyze()
                    if result['classes'] or result['findings']:
                        results.append(result)
                except Exception:
                    pass
                if len(results) >= 50:
                    break
    except Exception:
        pass
    return results


def report_java_findings(results: list) -> str:
    lines = ['Java Artifact Analysis', '=' * 60]
    total_classes = sum(len(r['classes']) for r in results)
    total_findings = sum(len(r['findings']) for r in results)
    lines.append(f"Artifacts scanned: {len(results)}")
    lines.append(f"Classes parsed:    {total_classes}")
    lines.append(f"Security findings: {total_findings}")
    lines.append('')

    for r in results:
        if not r['findings'] and not any(
            r['security'].get(k) for k in
            ('native_methods', 'serializable_classes', 'exec_users')
        ):
            continue
        lines.append(f"[FILE] {r['path']}")
        sec = r['security']
        if sec.get('serializable_classes'):
            lines.append(f"  Serializable: {', '.join(sec['serializable_classes'][:5])}")
        if sec.get('native_methods'):
            lines.append(f"  Native methods: {', '.join(sec['native_methods'][:5])}")
        if sec.get('exec_users'):
            lines.append(f"  exec() callers: {', '.join(sec['exec_users'][:5])}")
        for f in r['findings']:
            lines.append(f"  [{f['severity']}] {f['type']}: {f['value'][:80]}")
        lines.append('')

    return '\n'.join(lines)


def detect_malicious_class_loader(class_data: bytes) -> list:
    """Scan class constant pool for dangerous dynamic class loading patterns.

    Checks:
      - URLClassLoader instantiation (HIGH)
      - Reflection Method.invoke (HIGH)
      - defineClass native reference (CRITICAL)
      - Unsafe.allocateInstance (CRITICAL)

    Args:
        class_data: raw bytes of a .class file.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings = []

    if b"java/net/URLClassLoader" in class_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'URL_CLASSLOADER_DYNAMIC',
            'detail': 'URLClassLoader reference in constant pool — remote class loading possible',
            'host': 'localhost',
            'port': 0,
        })

    if b"java/lang/reflect/Method" in class_data and b"invoke" in class_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'REFLECTION_INVOKE',
            'detail': 'Reflection Method.invoke in constant pool — arbitrary method execution',
            'host': 'localhost',
            'port': 0,
        })

    if b"defineClass" in class_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'DEFINE_CLASS_CALL',
            'detail': 'defineClass reference — custom class injection into JVM',
            'host': 'localhost',
            'port': 0,
        })

    if b"allocateInstance" in class_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'UNSAFE_ALLOCATE',
            'detail': 'Unsafe.allocateInstance reference — constructor bypass, object fabrication without initialization',
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_java_deserialization_exploitation(class_data: bytes) -> list:
    """Detect deserialization gadget chains and command execution sinks in class bytecode.

    Checks:
      - Java serialization magic header 0xACED0005 embedded in class (CRITICAL)
      - InvokerTransformer/ChainedTransformer (Commons Collections gadgets) (CRITICAL)
      - Runtime.exec reference (CRITICAL)
      - ProcessBuilder.start reference (CRITICAL)

    Args:
        class_data: raw bytes of a .class file.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings = []

    if b"\xac\xed\x00\x05" in class_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SERIALIZED_BLOB_IN_CLASS',
            'detail': 'Java serialization magic 0xACED0005 embedded — pre-built gadget payload suspected',
            'host': 'localhost',
            'port': 0,
        })

    if b"InvokerTransformer" in class_data or b"ChainedTransformer" in class_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'COMMONS_COLLECTIONS_GADGET',
            'detail': 'InvokerTransformer/ChainedTransformer in constant pool — Commons Collections gadget chain',
            'host': 'localhost',
            'port': 0,
        })

    if b"java/lang/Runtime" in class_data and b"exec" in class_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'RUNTIME_EXEC_IN_CLASS',
            'detail': 'Runtime.exec reference in constant pool — OS command execution sink',
            'host': 'localhost',
            'port': 0,
        })

    if b"ProcessBuilder" in class_data and b"start" in class_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'PROCESSBUILDER_START',
            'detail': 'ProcessBuilder.start reference in constant pool — process spawning capability',
            'host': 'localhost',
            'port': 0,
        })

    return findings


def analyze_bytecode_flow(class_data: bytes) -> list:
    """Analyze opcode distribution for obfuscation and control-flow anomalies.

    Checks:
      - INVOKEVIRTUAL (0xB6) vs INVOKESTATIC (0xB8) ratio >80% virtual (INFO)
      - GOTO_W (0xC8) or JSR_W (0xC9) presence (MEDIUM)
      - ATHROW (0xBF) occurrences without exception table context (MEDIUM)
      - TABLESWITCH (0xAA) with >50 cases (MEDIUM)

    Note: byte counts include constant pool bytes, so values are heuristic.

    Args:
        class_data: raw bytes of a .class file.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings = []

    # INVOKEVIRTUAL / INVOKESTATIC ratio
    virtual_count = class_data.count(b"\xb6")
    static_count = class_data.count(b"\xb8")
    total_invoke = virtual_count + static_count
    if total_invoke > 0:
        virtual_ratio = virtual_count / total_invoke
        if virtual_ratio > 0.80:
            findings.append({
                'severity': 'INFO',
                'title': 'HIGH_VIRTUAL_DISPATCH',
                'detail': (
                    f'INVOKEVIRTUAL ratio {virtual_ratio:.0%} '
                    f'({virtual_count}/{total_invoke}) — complex object graph or heavy dynamic dispatch'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # Wide jump opcodes
    if b"\xc8" in class_data or b"\xc9" in class_data:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'WIDE_JUMPS',
            'detail': 'GOTO_W/JSR_W opcodes present — wide jump targets, potential bytecode obfuscation or repackaging artifact',
            'host': 'localhost',
            'port': 0,
        })

    # ATHROW without exception table framing (heuristic)
    athrow_count = class_data.count(b"\xbf")
    if athrow_count > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'BARE_THROW',
            'detail': (
                f'ATHROW opcode found {athrow_count}x — bare throw pattern detected; '
                'verify exception table coverage; may indicate control-flow obfuscation'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # TABLESWITCH with large case ranges
    # TABLESWITCH layout: opcode(1) | padding(0-3) | default(4) | low(4) | high(4) | offsets
    # Padding aligns defaultbyte1 to 4-byte boundary from method start (unknown here).
    # Try all 4 padding amounts per occurrence as a heuristic.
    large_switches = 0
    idx = 0
    while True:
        pos = class_data.find(b"\xaa", idx)
        if pos < 0:
            break
        for pad in range(4):
            base = pos + 1 + pad
            if base + 12 > len(class_data):
                continue
            try:
                low = struct.unpack('>i', class_data[base + 4:base + 8])[0]
                high = struct.unpack('>i', class_data[base + 8:base + 12])[0]
                case_count = high - low + 1
                if 50 < case_count <= 65535:
                    large_switches += 1
                    break
            except struct.error:
                continue
        idx = pos + 1

    if large_switches > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'LARGE_SWITCH',
            'detail': (
                f'{large_switches} TABLESWITCH instruction(s) with >50 cases detected — '
                'possible obfuscated dispatch table'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def scan_jar_for_vulnerabilities(jar_path: str) -> list:
    """Scan a JAR archive for structural vulnerabilities and classloader abuse patterns.

    Checks:
      - Path traversal in ZIP entry names — ZIP Slip (CVE-2018-1002200) (CRITICAL)
      - .class files in META-INF/ — classloader abuse vector (HIGH)
      - Missing or empty MANIFEST.MF — integrity unknown (MEDIUM)
      - Nested JAR files — classloader confusion / shadow dependency (MEDIUM)

    Args:
        jar_path: filesystem path to a .jar, .war, or .ear file.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings = []

    try:
        with zipfile.ZipFile(jar_path, 'r') as zf:
            names = zf.namelist()

            # ZIP Slip: path traversal in entry names
            for name in names:
                if '../' in name or name.startswith('/'):
                    findings.append({
                        'severity': 'CRITICAL',
                        'title': 'ZIP_SLIP_VULNERABLE',
                        'detail': (
                            f'Path traversal in ZIP entry "{name}" — '
                            'CVE-2018-1002200 pattern, arbitrary write on extract'
                        ),
                        'host': 'localhost',
                        'port': 0,
                    })
                    break  # one finding per jar is sufficient

            # .class files placed under META-INF/
            meta_classes = [n for n in names if n.startswith('META-INF/') and n.endswith('.class')]
            if meta_classes:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'CLASS_IN_META_INF',
                    'detail': (
                        f'{len(meta_classes)} .class file(s) in META-INF/ '
                        f'(e.g. "{meta_classes[0]}") — classloader abuse vector'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })

            # MANIFEST.MF presence and content
            manifest_names = [n for n in names if n.upper() == 'META-INF/MANIFEST.MF']
            if not manifest_names:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'NO_MANIFEST',
                    'detail': 'MANIFEST.MF absent from JAR — integrity and signing status unknown',
                    'host': 'localhost',
                    'port': 0,
                })
            else:
                try:
                    manifest_data = zf.read(manifest_names[0])
                    if not manifest_data.strip():
                        findings.append({
                            'severity': 'MEDIUM',
                            'title': 'NO_MANIFEST',
                            'detail': 'MANIFEST.MF present but empty — integrity unknown',
                            'host': 'localhost',
                            'port': 0,
                        })
                except Exception:
                    pass

            # Nested JARs
            nested = [n for n in names if n.lower().endswith('.jar')]
            if nested:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'NESTED_JAR',
                    'detail': (
                        f'{len(nested)} nested JAR(s) inside archive '
                        f'(e.g. "{nested[0]}") — classloader confusion, shadow dependency risk'
                    ),
                    'host': 'localhost',
                    'port': 0,
                })

    except zipfile.BadZipFile:
        findings.append({
            'severity': 'INFO',
            'title': 'NOT_A_ZIP',
            'detail': f'{os.path.basename(jar_path)} is not a valid ZIP/JAR archive',
            'host': 'localhost',
            'port': 0,
        })
    except OSError as exc:
        findings.append({
            'severity': 'INFO',
            'title': 'JAR_READ_ERROR',
            'detail': str(exc),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_java_runtime_exec_patterns(class_data: bytes) -> list:
    """Scan class constant pool for runtime execution and subprocess-spawn patterns.

    Behavioral monitoring analog: dynamic analysis surfaces process-creation events
    (Runtime.exec, ProcessBuilder) and arbitrary-code-evaluation surfaces
    (ScriptEngine) the same way procmon/Process Explorer surface CreateProcess calls.
    Socket+exec co-presence is the bytecode signature of a reverse shell — the
    behavioral equivalent of a monitored outbound connection immediately followed
    by a shell spawn event.

    Checks:
      - "Runtime" + "exec" constants within 64 bytes of each other (HIGH)
      - "ProcessBuilder" constant pool reference (HIGH)
      - "javax/script/ScriptEngine" or "ScriptEngineManager" (CRITICAL)
      - "sun/misc/Unsafe" or "sun.misc.Unsafe" (CRITICAL)
      - "java/net/Socket" + "exec" in same class (CRITICAL)

    Note: does not duplicate detect_java_deserialization_exploitation which checks
    java/lang/Runtime+exec (anywhere) and ProcessBuilder+start. This function adds
    proximity-gated Runtime detection and standalone ProcessBuilder presence.

    Args:
        class_data: raw bytes of a .class file.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings = []

    # Runtime + exec within 64 bytes — proximity-gated exec chain heuristic.
    # Tighter than the anywhere-in-class check in detect_java_deserialization_exploitation.
    if re.search(b'Runtime.{0,64}exec', class_data, re.DOTALL):
        findings.append({
            'severity': 'HIGH',
            'title': 'RUNTIME_EXEC_PATTERN',
            'detail': (
                'Runtime + exec constants within 64 bytes — command execution chain; '
                'proximity indicates direct call rather than unrelated string constants'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ProcessBuilder in constant pool — subprocess spawn capability.
    # Distinct from detect_java_deserialization_exploitation (requires ProcessBuilder+start).
    if b'ProcessBuilder' in class_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'PROCESSBUILDER_USAGE',
            'detail': (
                'ProcessBuilder constant pool reference — subprocess spawn capability; '
                'audit invocation chain for untrusted input reaching command arguments'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ScriptEngine / ScriptEngineManager — arbitrary script evaluation surface.
    if b'javax/script/ScriptEngine' in class_data or b'ScriptEngineManager' in class_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SCRIPT_ENGINE_INJECTION',
            'detail': (
                'javax.script.ScriptEngine or ScriptEngineManager in constant pool — '
                'arbitrary script execution surface; evaluate() with user-controlled input '
                'is full code execution'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # sun.misc.Unsafe — JVM internals bypass; memory manipulation without safety checks.
    # Distinct from allocateInstance check in detect_malicious_class_loader (method-level).
    if b'sun/misc/Unsafe' in class_data or b'sun.misc.Unsafe' in class_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'UNSAFE_CLASS_USAGE',
            'detail': (
                'sun.misc.Unsafe class reference — JVM internals bypass; '
                'arbitrary memory read/write, class fabrication, monitor manipulation'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # java/net/Socket + exec in same class — reverse shell behavioral signature.
    if b'java/net/Socket' in class_data and b'exec' in class_data:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SOCKET_EXEC_COMBINATION',
            'detail': (
                'java/net/Socket + exec constants co-present — reverse shell pattern; '
                'socket I/O stream wired to process stdin/stdout/stderr'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def analyze_spring_application_context(binary_data: bytes) -> list:
    """Detect Spring Framework security exposure patterns in class or JAR binary data.

    Behavioral analog: registry snapshot comparison (Regshot) reveals persistence
    and configuration changes; Spring annotation scanning is the bytecode equivalent —
    a snapshot of the declared HTTP surface, expression evaluation wiring, and
    deserialization exposure baked into the application context at build time.

    Checks:
      - RequestMapping annotation presence — active HTTP controller surface (MEDIUM)
      - @Value + "${" SpEL expression pattern — SpEL injection surface (HIGH)
      - org/springframework/expression/spel class reference (HIGH)
      - java.io.ObjectInputStream + Spring class co-presence (CRITICAL)
      - org/springframework/web/multipart reference — file upload handler (MEDIUM)

    Args:
        binary_data: raw bytes of a .class file or JAR archive.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings = []

    # RequestMapping annotation — active Spring MVC controller, live HTTP surface.
    # In bytecode the annotation descriptor contains 'RequestMapping'.
    if b'RequestMapping' in binary_data or b'requestMapping' in binary_data:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SPRING_CONTROLLER_CLASS',
            'detail': (
                '@RequestMapping annotation present — Spring MVC controller class; '
                'enumerate mapped paths for unintended public exposure'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # @Value with "${" expression — property placeholder that can carry SpEL.
    # The annotation descriptor 'annotation/Value' and the placeholder prefix '${'
    # both appear in the constant pool when @Value("${...}") is compiled.
    has_value_annotation = (
        b'annotation/Value' in binary_data
        or b'@Value' in binary_data
        or b'beans/factory/annotation/Value' in binary_data
    )
    if has_value_annotation and b'${' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title': 'SPRING_EL_EXPRESSION',
            'detail': (
                '@Value annotation + "${" expression pattern — potential SpEL injection surface; '
                'user-controlled property values evaluated as expressions enable RCE'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # SpEL engine class reference — expression evaluator loaded in application context.
    if (b'springframework/expression/spel' in binary_data
            or b'springframework.expression.spel' in binary_data):
        findings.append({
            'severity': 'HIGH',
            'title': 'SPEL_ENGINE_LOADED',
            'detail': (
                'org.springframework.expression.spel class reference — '
                'SpEL evaluator present; audit all Expression.getValue() call sites '
                'for untrusted input'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # java.io.ObjectInputStream + Spring class — deserialization surface in Spring context.
    # Co-presence does not require direct call; classpath gadget chains are sufficient.
    has_spring = b'springframework' in binary_data
    has_ois = (
        b'java/io/ObjectInputStream' in binary_data
        or b'java.io.ObjectInputStream' in binary_data
        or b'ObjectInputStream' in binary_data
    )
    if has_spring and has_ois:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SPRING_DESERIALIZATION_SURFACE',
            'detail': (
                'ObjectInputStream + Spring class co-present — deserialization gadget surface '
                'in Spring context; Spring classpath typically includes Commons Collections '
                'and other gadget-chain enablers'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # Spring multipart handler — file upload surface; path traversal / arbitrary write risk.
    if (b'springframework/web/multipart' in binary_data
            or b'springframework.web.multipart' in binary_data
            or b'org.springframework.web.multipart' in binary_data):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'MULTIPART_UPLOAD_HANDLER',
            'detail': (
                'Spring multipart handler reference — file upload surface present; '
                'verify destination path sanitization, file type enforcement, '
                'and upload size limits'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_java_ssrf_patterns(binary_data: bytes) -> list:
    """Scan Java class/jar bytes for server-side request forgery (SSRF) indicators.

    Targets outbound HTTP construction paths where user-controlled strings reach
    java.net.URL, HttpURLConnection, Spring RestTemplate, or WebClient.  Each
    co-presence check mirrors the pattern a decompiler reveals: constant-pool
    strings that appear together when a call-site is compiled.

    Source context: Secure APIs (O'Reilly) ch05 -- SSRF via webhook/avatar URL
    patterns; webhook endpoints and metadata-service probes are the canonical
    exploit paths in Java microservices.
    """
    findings = []

    # java.net.URL + openConnection/openStream near user-controlled strings.
    # In compiled bytecode both the class descriptor and method name appear as
    # UTF-8 constants; co-presence is the decompiler's signal.
    has_url_class = (
        b'java/net/URL' in binary_data
        or b'java.net.URL' in binary_data
    )
    has_open_connection = (
        b'openConnection' in binary_data
        or b'openStream' in binary_data
    )
    # Proxy for user-controlled input: parameter/request-scope strings that
    # appear in the constant pool when a controller or service takes user input.
    has_user_input_signal = (
        b'getParameter' in binary_data
        or b'getQueryString' in binary_data
        or b'@RequestParam' in binary_data
        or b'requestParam' in binary_data
        or b'PathVariable' in binary_data
        or b'RequestBody' in binary_data
        or b'@RequestBody' in binary_data
    )
    if has_url_class and has_open_connection and has_user_input_signal:
        findings.append({
            'severity': 'HIGH',
            'title': 'JAVA_SSRF_URL_OPEN',
            'detail': (
                'URL connection from user input -- java.net.URL + openConnection/openStream '
                'co-present with request-parameter markers; attacker-supplied URL reaches '
                'outbound HTTP call enabling internal network scanning, cloud metadata '
                'service probing (169.254.169.254), and SSRF-chained credential theft'
            ),
            'host': 'localhost',
            'port': 0,
        })
    elif has_url_class and has_open_connection:
        # openConnection without obvious user-input signal -- still audit-worthy.
        findings.append({
            'severity': 'MEDIUM',
            'title': 'JAVA_SSRF_URL_OPEN',
            'detail': (
                'URL connection from user input -- java.net.URL + openConnection/openStream '
                'present; trace call-sites to verify whether URL origin is user-controlled'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # HttpURLConnection + setRequestMethod -- outbound HTTP call explicitly constructed.
    if (b'HttpURLConnection' in binary_data
            and b'setRequestMethod' in binary_data):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'JAVA_HTTP_CONNECTION',
            'detail': (
                'Outbound HTTP calls -- HttpURLConnection + setRequestMethod pattern; '
                'verify URL origin is not user-controlled and allowlist is enforced; '
                'common vector for webhook-based SSRF in payment/notification APIs'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # new URL(...) + getInputStream() -- classic SSRF two-liner.
    has_url_ctor = b'new URL(' in binary_data or b'<init>' in binary_data
    has_get_input_stream = b'getInputStream' in binary_data
    if has_url_class and has_url_ctor and has_get_input_stream:
        findings.append({
            'severity': 'HIGH',
            'title': 'JAVA_URL_INPUT_STREAM',
            'detail': (
                'Potential SSRF pattern -- URL instantiation + getInputStream() present; '
                'pattern matches the two-line SSRF primitive: new URL(userInput).openStream(); '
                'audit for missing allowlist/denylist enforcement'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # Spring RestTemplate -- exchange() or getForObject() signal outbound calls.
    has_rest_template = (
        b'RestTemplate' in binary_data
        or b'springframework/web/client/RestTemplate' in binary_data
    )
    has_rest_exchange = (
        b'exchange' in binary_data
        or b'getForObject' in binary_data
        or b'postForObject' in binary_data
        or b'getForEntity' in binary_data
    )
    if has_rest_template and has_rest_exchange:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SPRING_REST_TEMPLATE',
            'detail': (
                'Spring HTTP calls -- RestTemplate + exchange/getForObject present; '
                'RestTemplate performs outbound HTTP; if URL is derived from user input '
                'without a domain allowlist the endpoint is an SSRF surface'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # Spring WebClient (reactive) -- reactor/flux patterns alongside WebClient.
    has_webclient = (
        b'WebClient' in binary_data
        or b'springframework/web/reactive/function/client/WebClient' in binary_data
    )
    has_reactor = (
        b'reactor/core' in binary_data
        or b'reactor.core' in binary_data
        or b'Mono' in binary_data
        or b'Flux' in binary_data
    )
    if has_webclient and has_reactor:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SPRING_WEBCLIENT',
            'detail': (
                'Reactive HTTP client -- Spring WebClient + reactor/flux pattern present; '
                'WebClient is the reactive replacement for RestTemplate; '
                'audit retrieve()/exchange() call-sites for user-controlled URI construction'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_java_xxe_patterns(binary_data: bytes) -> list:
    """Scan Java class/jar bytes for XML External Entity (XXE) injection surfaces.

    XXE arises when an XML parser is configured to resolve external entity
    references embedded in attacker-supplied XML.  The safe fix for every
    Java XML API is to set the disallow-doctype-decl feature before parsing;
    absence of that feature string alongside a parser class reference is the
    detector's signal.

    Source context: WAF book (O'Reilly) OWASP A4 XXE listing; Secure APIs
    ch05 security misconfiguration survey.
    """
    findings = []

    # DOM parser -- DocumentBuilderFactory without XXE-disabling feature string.
    has_dbf = (
        b'DocumentBuilderFactory' in binary_data
        or b'javax/xml/parsers/DocumentBuilderFactory' in binary_data
        or b'javax.xml.parsers.DocumentBuilderFactory' in binary_data
    )
    # Safe configuration leaves one of these strings in the constant pool.
    has_xxe_protection = (
        b'disallow-doctype-decl' in binary_data
        or b'external-general-entities' in binary_data
        or b'external-parameter-entities' in binary_data
        or b'load-external-dtd' in binary_data
        or b'FEATURE_SECURE_PROCESSING' in binary_data
    )
    if has_dbf and not has_xxe_protection:
        findings.append({
            'severity': 'HIGH',
            'title': 'XXE_RISK_DOM_PARSER',
            'detail': (
                'XML parser without XXE protection -- DocumentBuilderFactory present but '
                '"disallow-doctype-decl" and external-entity feature strings absent; '
                'parser processes DOCTYPE declarations by default enabling XXE, '
                'SSRF via entity URL resolution, and local file disclosure'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # SAX parser -- SAXParserFactory without protection features.
    has_saxpf = (
        b'SAXParserFactory' in binary_data
        or b'javax/xml/parsers/SAXParserFactory' in binary_data
        or b'javax.xml.parsers.SAXParserFactory' in binary_data
        or b'XMLReader' in binary_data
    )
    if has_saxpf and not has_xxe_protection:
        findings.append({
            'severity': 'HIGH',
            'title': 'XXE_RISK_SAX_PARSER',
            'detail': (
                'SAX parser without XXE hardening -- SAXParserFactory/XMLReader present '
                'without setFeature("disallow-doctype-decl", true) evidence; '
                'streaming SAX parsers resolve external entities by default; '
                'fix: setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # StAX parser -- XMLInputFactory without IS_SUPPORTING_EXTERNAL_ENTITIES disabled.
    has_xif = (
        b'XMLInputFactory' in binary_data
        or b'javax/xml/stream/XMLInputFactory' in binary_data
        or b'javax.xml.stream.XMLInputFactory' in binary_data
    )
    has_stax_protection = (
        b'IS_SUPPORTING_EXTERNAL_ENTITIES' in binary_data
        or b'SUPPORT_DTD' in binary_data
        or b'supportDtd' in binary_data
    )
    if has_xif and not has_stax_protection:
        findings.append({
            'severity': 'HIGH',
            'title': 'XXE_RISK_STAX_PARSER',
            'detail': (
                'StAX parser without external-entity guard -- XMLInputFactory present without '
                'IS_SUPPORTING_EXTERNAL_ENTITIES=false evidence; '
                'fix: factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false) '
                'and factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # XPath evaluation near user-input signals -- XPath injection surface.
    has_xpath = (
        b'XPathFactory' in binary_data
        or b'javax/xml/xpath/XPathFactory' in binary_data
        or b'javax.xml.xpath' in binary_data
        or b'XPath' in binary_data
    )
    has_user_input_signal = (
        b'getParameter' in binary_data
        or b'getQueryString' in binary_data
        or b'@RequestParam' in binary_data
        or b'requestParam' in binary_data
        or b'PathVariable' in binary_data
        or b'RequestBody' in binary_data
    )
    if has_xpath and has_user_input_signal:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'XPATH_INJECTION_SURFACE',
            'detail': (
                'XPath from external input -- XPathFactory/XPath present alongside '
                'request-parameter markers; if XPath expressions are constructed by '
                'string concatenation with user input, authentication bypass and '
                'data extraction are achievable via XPath injection'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # XMLDecoder -- Java XML serialization, always unsafe with untrusted input.
    # No safe configuration exists; presence alone is a critical signal.
    if (b'XMLDecoder' in binary_data
            or b'java/beans/XMLDecoder' in binary_data
            or b'java.beans.XMLDecoder' in binary_data):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'JAVA_XMLDECODER',
            'detail': (
                'XML deserialization RCE surface -- java.beans.XMLDecoder present; '
                'XMLDecoder deserializes arbitrary Java objects from XML with no safe mode; '
                'any user-supplied input reaching XMLDecoder is exploitable for RCE; '
                'Apache Struts CVE-2017-9805 is the canonical exploit of this class; '
                'remediation: replace XMLDecoder entirely with a safe alternative such '
                'as Jackson or XStream with explicit allowlisting'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def probe_spring_actuator_exposure(host: str, port: int = 8080, timeout: float = 10.0) -> list:
    """Probe Spring Boot management endpoints for unauthenticated read access.

    Attempts GET against each well-known actuator path.  A 200 response
    (regardless of body size) is treated as confirmed exposure.  Tries HTTP
    first; falls back to HTTPS on connection failure.

    Returns a list of finding dicts: {severity, title, detail, host, port}.
    """
    import urllib.request
    import urllib.error
    import ssl
    import json as _json

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    findings: list = []

    endpoints = [
        (
            '/actuator',
            'CRITICAL',
            'SPRING_ACTUATOR_EXPOSED',
            'Spring Boot management endpoints accessible without authentication -- '
            '/actuator index returned 200; attacker can enumerate all enabled '
            'management endpoints and escalate to env/heapdump reads; '
            'fix: management.endpoints.web.exposure.include=health and '
            'restrict /actuator/** behind an authenticated management port '
            '(management.server.port with firewall rule)',
        ),
        (
            '/actuator/env',
            'CRITICAL',
            'SPRING_ACTUATOR_ENV',
            'Application environment and secrets exposed via /actuator/env -- '
            'response includes all Spring Environment properties: datasource URLs, '
            'passwords, API keys, JWT secrets, cloud provider credentials; '
            'fix: management.endpoints.web.exposure.include=health,info only; '
            'never expose env endpoint on a production host',
        ),
        (
            '/actuator/heapdump',
            'CRITICAL',
            'SPRING_HEAPDUMP_EXPOSED',
            'Full JVM heap dump downloadable via /actuator/heapdump without authentication -- '
            'heap dump contains in-memory strings, connection pool credentials, '
            'session tokens, decrypted secrets, and live object graphs; '
            'analysis with Eclipse MAT or jhat extracts credentials in minutes; '
            'fix: disable endpoint (management.endpoint.heapdump.enabled=false) '
            'or restrict to management-only port behind auth',
        ),
        (
            '/actuator/loggers',
            'HIGH',
            'SPRING_LOGGERS_EXPOSED',
            'Logger configuration readable via /actuator/loggers -- '
            'exposes application package structure, configured log levels, and '
            'logger hierarchy; aids targeted injection and enumeration; '
            'write access (POST) permits log-level elevation for lateral info disclosure; '
            'fix: exclude from public exposure.include list',
        ),
        (
            '/actuator/beans',
            'HIGH',
            'SPRING_BEANS_EXPOSED',
            'Spring application context bean map disclosed via /actuator/beans -- '
            'response enumerates all registered beans, their types, dependencies, '
            'and scope; reveals internal component architecture and third-party '
            'library versions for targeted CVE exploitation; '
            'fix: management.endpoints.web.exposure.include=health,info',
        ),
        (
            '/actuator/mappings',
            'HIGH',
            'SPRING_MAPPINGS_EXPOSED',
            'All HTTP route mappings disclosed via /actuator/mappings -- '
            'response lists every @RequestMapping, handler method, accepted media '
            'types, and filter chain; exposes admin routes, internal APIs, and '
            'undocumented endpoints; enables targeted fuzzing without crawling; '
            'fix: exclude mappings from public endpoint list',
        ),
    ]

    for path, severity, title, detail in endpoints:
        response_code = None
        for scheme in ('http', 'https'):
            url = f'{scheme}://{host}:{port}{path}'
            try:
                req = urllib.request.Request(url, headers={'Accept': 'application/json'})
                if scheme == 'https':
                    resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                else:
                    resp = urllib.request.urlopen(req, timeout=timeout)
                response_code = resp.getcode()
                break
            except urllib.error.HTTPError as exc:
                response_code = exc.code
                break
            except Exception:
                continue

        if response_code == 200:
            findings.append({
                'severity': severity,
                'title': title,
                'detail': detail,
                'host': host,
                'port': port,
            })

    return findings


def probe_spring_actuator_exec(host: str, port: int = 8080, timeout: float = 10.0) -> list:
    """Probe Spring Boot actuator endpoints for unauthenticated write/exec surfaces.

    Tests POST endpoints that trigger state changes (shutdown, restart, log-level
    write) and the Jolokia JMX bridge which can reach RCE via MBean invocation.
    Tries HTTP first; falls back to HTTPS on connection failure.

    Returns a list of finding dicts: {severity, title, detail, host, port}.
    """
    import urllib.request
    import urllib.error
    import ssl
    import json as _json

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    findings: list = []

    def _request(method: str, path: str, body: bytes | None = None,
                 content_type: str = 'application/json') -> int | None:
        """Return HTTP status code or None on connection failure."""
        for scheme in ('http', 'https'):
            url = f'{scheme}://{host}:{port}{path}'
            try:
                headers = {'Accept': 'application/json'}
                if body is not None:
                    headers['Content-Type'] = content_type
                req = urllib.request.Request(
                    url, data=body, headers=headers, method=method
                )
                if scheme == 'https':
                    resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                else:
                    resp = urllib.request.urlopen(req, timeout=timeout)
                return resp.getcode()
            except urllib.error.HTTPError as exc:
                return exc.code
            except Exception:
                continue
        return None

    exec_endpoints = [
        (
            'POST',
            '/actuator/shutdown',
            b'{}',
            'CRITICAL',
            'SPRING_ACTUATOR_SHUTDOWN',
            'Application shutdown triggered via unauthenticated POST /actuator/shutdown -- '
            'endpoint accepted the request (200); any unauthenticated caller can '
            'terminate the JVM process; constitutes an availability/DoS critical; '
            'chained with /actuator/env read it enables destructive + credential-theft '
            'in a single unauthenticated session; '
            'fix: management.endpoint.shutdown.enabled=false (disabled by default; '
            'this host has explicitly enabled it)',
        ),
        (
            'POST',
            '/actuator/restart',
            b'{}',
            'CRITICAL',
            'SPRING_ACTUATOR_RESTART',
            'Application restart triggered via unauthenticated POST /actuator/restart -- '
            'endpoint accepted the request (200); attacker can force config reload, '
            'disrupt in-flight transactions, or time restart to coincide with '
            'credential rotation window; '
            'fix: disable spring-boot-devtools restart or secure endpoint behind auth',
        ),
        (
            'POST',
            '/actuator/loggers/ROOT',
            _json.dumps({'configuredLevel': 'TRACE'}).encode(),
            'HIGH',
            'SPRING_LOGGER_WRITE',
            'Log level modification accepted via unauthenticated POST /actuator/loggers/ROOT -- '
            'attacker set ROOT logger to TRACE; at TRACE level Spring logs request '
            'bodies, headers, SQL parameters, and internal state; enables lateral '
            'information disclosure without direct env/heapdump read; '
            'fix: restrict loggers endpoint to read-only management port or disable',
        ),
    ]

    for method, path, body, severity, title, detail in exec_endpoints:
        code = _request(method, path, body)
        if code == 200:
            findings.append({
                'severity': severity,
                'title': title,
                'detail': detail,
                'host': host,
                'port': port,
            })

    # Jolokia JMX bridge -- GET is sufficient to confirm exposure; RCE via exec
    # operation requires a follow-up POST to jolokia/exec/<MBean>/... but
    # presence alone is CRITICAL (MLet MBean load permits arbitrary class loading).
    jolokia_code = _request('GET', '/actuator/jolokia')
    if jolokia_code == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title': 'SPRING_JOLOKIA_EXPOSED',
            'detail': (
                'JMX beans accessible via HTTP through unauthenticated /actuator/jolokia -- '
                'Jolokia bridges JMX over HTTP; with the MLet MBean an attacker can '
                'load an arbitrary remote MBean JAR (POST /jolokia/exec/java.lang:type=MBeanServer/createMBean/...)'
                ' achieving full RCE; historical exploitation: CVE-2022-22963 class; '
                'fix: remove jolokia dependency or gate behind management auth; '
                'management.endpoints.web.exposure.include must never contain jolokia '
                'on a public-facing port'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_jvm_bytecode_download_surface(host: str, port: int = 443, timeout: float = 10.0) -> list:
    import urllib.request
    import urllib.error
    import ssl
    import struct
    import re

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    findings: list = []

    def _fetch(path: str) -> tuple:
        for scheme in ('https', 'http'):
            url = f'{scheme}://{host}:{port}{path}'
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Java/11.0.2'})
                if scheme == 'https':
                    resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                else:
                    resp = urllib.request.urlopen(req, timeout=timeout)
                data = resp.read(65536)
                return resp.getcode(), data
            except urllib.error.HTTPError as exc:
                return exc.code, b''
            except Exception:
                continue
        return None, b''

    class_paths = [
        '/WEB-INF/classes/com/cisco/asdm/Main.class',
        '/WEB-INF/classes/Main.class',
        '/admin/classes/Main.class',
        '/api/classes/Main.class',
        '/classes/Main.class',
    ]

    for path in class_paths:
        code, data = _fetch(path)
        if code == 200 and len(data) >= 8 and data[:4] == b'\xca\xfe\xba\xbe':
            minor, major = struct.unpack('>HH', data[4:8])
            java_ver = major - 44 if major >= 45 else 0
            findings.append({
                'severity': 'HIGH',
                'title': 'JVM_CLASS_FILE_DOWNLOAD',
                'detail': (
                    f'Unauthenticated download of JVM class file confirmed at {path} '
                    f'(magic 0xCAFEBABE; class format {major}.{minor}; '
                    f'compiled for Java {java_ver}+); '
                    'class files expose decompilable bytecode containing business logic, '
                    'embedded credentials, JDBC URLs, and internal API endpoints; '
                    'chain with constant-pool extraction for credential harvest; '
                    'fix: restrict /WEB-INF/ and management class paths behind auth; '
                    'ensure web.xml security-constraint covers static resource paths'
                ),
                'host': host,
                'port': port,
            })
            break

    jar_paths = [
        '/admin/asdm.jar',
        '/admin/asdm-launcher.jar',
        '/admin/public/asdm.jar',
        '/pub/a/asdm.jar',
        '/asdm.jar',
        '/WEB-INF/lib/app.jar',
        '/download/app.jar',
    ]

    for path in jar_paths:
        code, data = _fetch(path)
        if code == 200 and len(data) >= 4 and data[:4] == b'PK\x03\x04':
            findings.append({
                'severity': 'HIGH',
                'title': 'JVM_JAR_DOWNLOAD',
                'detail': (
                    f'Unauthenticated download of JAR archive confirmed at {path} '
                    '(PK\\x03\\x04 ZIP local file header); '
                    'JAR contains embedded class files, manifest, and configuration; '
                    'decompile with javap/fernflower to extract hardcoded credentials, '
                    'JDBC connection strings, API keys, and internal hostnames; '
                    'fix: gate JAR delivery paths behind session auth; '
                    'Cisco ASDM path exposure correlates with CVE-2021-1585 class'
                ),
                'host': host,
                'port': port,
            })
            break

    jnlp_paths = [
        '/admin/public/asdm.jnlp',
        '/admin/asdm.jnlp',
        '/pub/a/asdm.jnlp',
        '/asdm.jnlp',
    ]

    for path in jnlp_paths:
        code, data = _fetch(path)
        if code == 200 and b'jar href=' in data:
            jars = re.findall(rb'jar href=["\']([^"\']+)["\']', data)
            jar_list = ', '.join(j.decode(errors='replace') for j in jars[:10])
            findings.append({
                'severity': 'MEDIUM',
                'title': 'JNLP_JAR_MANIFEST_EXPOSED',
                'detail': (
                    f'JNLP file at {path} exposes downloadable JAR names via jar href= '
                    f'attributes: [{jar_list}]; '
                    'JNLP manifests enumerate the full client-side JAR set delivered by '
                    'management portals; '
                    'each named JAR is a candidate for unauthenticated download and '
                    'bytecode extraction; '
                    'fix: require session cookie or client cert before serving .jnlp '
                    'and referenced .jar paths'
                ),
                'host': host,
                'port': port,
            })
            break

    return findings


def probe_jvm_constant_pool_credential_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    import urllib.request
    import ssl
    import struct
    import re
    import base64

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    findings: list = []

    def _fetch_bytes(path: str) -> bytes:
        for scheme in ('https', 'http'):
            url = f'{scheme}://{host}:{port}{path}'
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Java/11.0.2'})
                if scheme == 'https':
                    resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                else:
                    resp = urllib.request.urlopen(req, timeout=timeout)
                return resp.read(8 * 1024 * 1024)
            except Exception:
                continue
        return b''

    def _extract_class_bytes(raw: bytes) -> bytes:
        if raw[:4] == b'PK\x03\x04':
            pos = 0
            while pos < len(raw) - 30:
                if raw[pos:pos+4] != b'PK\x03\x04':
                    pos += 1
                    continue
                fname_len = struct.unpack_from('<H', raw, pos + 26)[0]
                extra_len = struct.unpack_from('<H', raw, pos + 28)[0]
                comp_size = struct.unpack_from('<I', raw, pos + 18)[0]
                fname = raw[pos+30:pos+30+fname_len]
                data_start = pos + 30 + fname_len + extra_len
                entry = raw[data_start:data_start+comp_size]
                if fname.endswith(b'.class') and len(entry) >= 4 and entry[:4] == b'\xca\xfe\xba\xbe':
                    return entry
                if comp_size == 0:
                    pos += 30 + fname_len + extra_len + 1
                else:
                    pos = data_start + comp_size
        if raw[:4] == b'\xca\xfe\xba\xbe':
            return raw
        return b''

    def _parse_utf8_constants(class_bytes: bytes) -> list:
        if len(class_bytes) < 10 or class_bytes[:4] != b'\xca\xfe\xba\xbe':
            return []
        cp_count = struct.unpack_from('>H', class_bytes, 8)[0]
        pos = 10
        strings = []
        i = 1
        while i < cp_count and pos < len(class_bytes):
            tag = class_bytes[pos]
            pos += 1
            if tag == 1:
                if pos + 2 > len(class_bytes):
                    break
                length = struct.unpack_from('>H', class_bytes, pos)[0]
                pos += 2
                if pos + length > len(class_bytes):
                    break
                try:
                    s = class_bytes[pos:pos+length].decode('utf-8', errors='replace')
                except Exception:
                    s = ''
                strings.append(s)
                pos += length
                i += 1
            elif tag in (3, 4):
                pos += 4
                strings.append('')
                i += 1
            elif tag in (5, 6):
                pos += 8
                strings.append('')
                strings.append('')
                i += 2
            elif tag in (7, 8, 16):
                pos += 2
                strings.append('')
                i += 1
            elif tag in (9, 10, 11, 12, 18):
                pos += 4
                strings.append('')
                i += 1
            elif tag == 15:
                pos += 3
                strings.append('')
                i += 1
            else:
                break
        return strings

    probe_paths = [
        '/admin/asdm.jar',
        '/admin/asdm-launcher.jar',
        '/admin/public/asdm.jar',
        '/pub/a/asdm.jar',
        '/asdm.jar',
        '/WEB-INF/classes/com/cisco/asdm/Main.class',
        '/WEB-INF/classes/Main.class',
        '/admin/classes/Main.class',
    ]

    raw = b''
    fetched_path = ''
    for path in probe_paths:
        data = _fetch_bytes(path)
        if data and data[:4] in (b'PK\x03\x04', b'\xca\xfe\xba\xbe'):
            raw = data
            fetched_path = path
            break

    if not raw:
        return findings

    class_bytes = _extract_class_bytes(raw)
    if not class_bytes:
        return findings

    strings = _parse_utf8_constants(class_bytes)
    if not strings:
        return findings

    url_patterns = [
        (
            r'jdbc:[a-z]+://',
            'JDBC_URL_IN_CONSTANT_POOL',
            'CRITICAL',
            'JDBC connection URL hardcoded in constant pool Utf8 entry; '
            'includes database host, port, and often embedded credentials in the connection string; '
            'fix: externalize to encrypted credential store; never hardcode in compiled artifacts',
        ),
        (
            r'ldap[s]?://',
            'LDAP_URL_IN_CONSTANT_POOL',
            'HIGH',
            'LDAP connection URL hardcoded in constant pool; '
            'exposes directory server address; combined with adjacent password constants '
            'enables directory bind credential recovery; '
            'fix: load from environment or vault at runtime',
        ),
        (
            r'java:comp/env/jdbc/',
            'JNDI_JDBC_LOOKUP_IN_CONSTANT_POOL',
            'CRITICAL',
            'JNDI JDBC datasource lookup string in constant pool; '
            'if JNDI context is injectable, attacker redirects datasource to attacker-controlled DB; '
            'chain with Log4Shell class for RCE; '
            'fix: disable JNDI lookups; upgrade affected libraries',
        ),
        (
            r'(java:comp/|java:jboss/|java:global/)',
            'JNDI_LOOKUP_IN_CONSTANT_POOL',
            'HIGH',
            'JNDI lookup string found in constant pool Utf8 entry; '
            'JNDI injection primitives rely on these prefixes; '
            'presence confirms injectable JNDI dependency chain in this artifact; '
            'fix: audit all InitialContext.lookup() call sites; disable remote class loading',
        ),
    ]

    seen_titles: set = set()
    for s in strings:
        for pattern, title, severity, base_detail in url_patterns:
            if title in seen_titles:
                continue
            if re.search(pattern, s, re.IGNORECASE):
                findings.append({
                    'severity': severity,
                    'title': title,
                    'detail': (
                        f'Constant pool Utf8 entry from {fetched_path} matches [{pattern}]: '
                        f'"{s[:120]}"; ' + base_detail
                    ),
                    'host': host,
                    'port': port,
                })
                seen_titles.add(title)
                break

    b64_pat = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
    for s in strings:
        if b64_pat.match(s):
            try:
                padding = '=' * (-len(s) % 4)
                decoded = base64.b64decode(s + padding).decode('utf-8', errors='strict')
                if ':' in decoded and 6 <= len(decoded) <= 256 and not decoded.startswith('http'):
                    parts = decoded.split(':', 1)
                    if (len(parts[0]) >= 2 and len(parts[1]) >= 1
                            and all(c.isprintable() for c in decoded)):
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'BASE64_CREDENTIAL_IN_CONSTANT_POOL',
                            'detail': (
                                f'Base64 Utf8 constant from {fetched_path} decodes to '
                                'colon-separated credential format (user:pass); '
                                f'encoded value: "{s[:80]}"; '
                                'hardcoded credential detected in compiled bytecode; '
                                'fix: remove all hardcoded credentials from source; '
                                'rotate immediately; audit git history for prior exposure'
                            ),
                            'host': host,
                            'port': port,
                        })
                        break
            except Exception:
                pass

    pw_pat = re.compile(r'(?i)(password|passwd|secret|credential|apikey|api_key|token)')
    skip_pat = re.compile(r'^[\[(]|^[A-Z_]{3,}$|^java/|^sun/|^com/sun/')
    pw_indices = [i for i, s in enumerate(strings) if pw_pat.search(s)]
    reported: set = set()
    for idx in pw_indices:
        for offset in (-2, -1, 1, 2):
            adj_idx = idx + offset
            if adj_idx in reported or not (0 <= adj_idx < len(strings)):
                continue
            adj = strings[adj_idx]
            if (len(adj) >= 6
                    and adj.isprintable()
                    and not skip_pat.search(adj)
                    and not re.match(r'^[A-Z_]+$', adj)):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'CREDENTIAL_ADJACENT_CONSTANT',
                    'detail': (
                        f'Constant pool entry "{strings[idx][:60]}" (pool index {idx}) '
                        f'is adjacent to candidate value "{adj[:80]}" (pool index {adj_idx}) '
                        f'from {fetched_path}; '
                        'field-name/value constant pairs appear adjacent in the pool when '
                        'the compiler inlines static field initializers; '
                        'manual decompilation required to confirm binding; '
                        'fix: externalize secrets; scan all artifacts with trufflehog '
                        'or semgrep secrets rules pre-deployment'
                    ),
                    'host': host,
                    'port': port,
                })
                reported.add(adj_idx)
                break

    return findings
