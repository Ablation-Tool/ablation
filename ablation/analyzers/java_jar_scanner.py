"""
java_jar_scanner.py — Java JAR/class exec-class API scanner.

Gap filled vs existing Ablation analyzers:
  1. PESinkClassifier and SinkArgClassifier only handle native binaries (ELF/PE).
     IBM-RE contains Java components: IBM Debugger ships derdebug.jar; IBM EGL-VSE
     ships src.jar (819 .class files, IBM EGL compiler source).  These were previously
     summarized as "no native exec calls" without an Ablation sweep to back that up.
  2. Java exec-class APIs differ from POSIX:
       Runtime.exec(cmd)            — direct OS command execution
       ProcessBuilder / .start()   — process spawning with environment control
       System.load / loadLibrary   — native library loading (attack surface)
       Class.forName(name) + getMethod("exec") — reflective exec
     None of these appear in PLT or IAT tables.  They require constant-pool scanning.
  3. BinaryContext.load_or_build() returns arch=x86_64 fallback (func_starts=0) for
     .class files; SinkArgClassifier produces 0 results.  This module fills that gap.

Approach:
  Scans Java class-file constant pools for CONSTANT_Utf8 entries matching exec-class
  class names and method names.  Does NOT require javap, class loading, or a JVM.
  Works on any .class file (including obfuscated, if the method names are unchanged).
  Operates directly on JAR entries via zipfile.

Exec categories:
  RUNTIME_EXEC        — java/lang/Runtime.exec() variants
  PROCESS_BUILDER     — java/lang/ProcessBuilder / .start()
  NATIVE_LOAD         — System.load / System.loadLibrary / System.mapLibraryName
  REFLECTIVE_EXEC     — Class.forName + getMethod (reflective invocation)
"""
from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# ── constant-pool tag codes ────────────────────────────────────────────────────

_TAG_UTF8        = 1
_TAG_INTEGER     = 3
_TAG_FLOAT       = 4
_TAG_LONG        = 5
_TAG_DOUBLE      = 6
_TAG_CLASS       = 7
_TAG_STRING      = 8
_TAG_FIELDREF    = 9
_TAG_METHODREF   = 10
_TAG_IFACEREF    = 11
_TAG_NAMEANDTYPE = 12
_TAG_METHODHANDLE = 15
_TAG_METHODTYPE  = 16
_TAG_DYNAMIC     = 17
_TAG_INVOKEDYN   = 18
_TAG_MODULE      = 19
_TAG_PACKAGE     = 20

_CLASS_MAGIC = b'\xca\xfe\xba\xbe'

# ── exec-class detection tables ───────────────────────────────────────────────

# Maps constant-pool UTF8 value → category
_EXEC_CLASS_NAMES: Dict[str, str] = {
    'java/lang/Runtime':        'RUNTIME_EXEC',
    'java/lang/ProcessBuilder': 'PROCESS_BUILDER',
    'java/lang/Process':        'PROCESS_BUILDER',
}

_EXEC_METHOD_NAMES: Dict[str, str] = {
    'exec':              'RUNTIME_EXEC',
    'start':             'PROCESS_BUILDER',
    'load':              'NATIVE_LOAD',
    'loadLibrary':       'NATIVE_LOAD',
    'mapLibraryName':    'NATIVE_LOAD',
}

_NATIVE_CLASS_NAMES: Dict[str, str] = {
    'java/lang/System':  'NATIVE_LOAD',
}

_REFLECTIVE_NAMES: Set[str] = {'forName', 'getMethod', 'invoke', 'getDeclaredMethod'}

# ── data classes ──────────────────────────────────────────────────────────────

@dataclass
class JavaExecFinding:
    class_file: str          # JAR-relative path of the .class file
    category:   str          # one of the categories above
    api_ref:    str          # human-readable description of what was found
    evidence:   str          # UTF8 constant that triggered the hit


@dataclass
class JavaJarResult:
    jar_path:    str
    class_count: int
    findings:    List[JavaExecFinding] = field(default_factory=list)

    @property
    def categories(self) -> Set[str]:
        return {f.category for f in self.findings}

    def summary(self) -> str:
        if not self.findings:
            return f'{self.jar_path}: {self.class_count} classes, 0 exec-class APIs'
        cats = ', '.join(sorted(self.categories))
        return (
            f'{self.jar_path}: {self.class_count} classes, '
            f'{len(self.findings)} exec-class hits — {cats}'
        )

    def report(self) -> str:
        lines = [self.summary()]
        for f in self.findings:
            lines.append(f'  [{f.category}] {f.class_file}: {f.api_ref} ({f.evidence!r})')
        return '\n'.join(lines)


# ── parser ────────────────────────────────────────────────────────────────────

def _read_utf8_pool(data: bytes) -> List[str]:
    """
    Parse all CONSTANT_Utf8 entries from a .class constant pool.

    Returns a list indexed from 1 (constant pool index 0 is unused per JVM spec).
    Entries that are not CONSTANT_Utf8 are stored as empty string.
    """
    if len(data) < 10 or data[:4] != _CLASS_MAGIC:
        return []
    # Skip magic (4) + minor_version (2) + major_version (2)
    pos = 8
    cp_count = struct.unpack_from('>H', data, pos)[0]
    pos += 2
    utf8_pool: List[str] = [''] * cp_count  # index 0 unused; pool[1..cp_count-1]

    i = 1
    while i < cp_count:
        if pos >= len(data):
            break
        tag = data[pos]
        pos += 1
        if tag == _TAG_UTF8:
            length = struct.unpack_from('>H', data, pos)[0]
            pos += 2
            raw = data[pos:pos + length]
            pos += length
            try:
                utf8_pool[i] = raw.decode('utf-8', errors='replace')
            except Exception:
                utf8_pool[i] = ''
        elif tag in (_TAG_CLASS, _TAG_STRING, _TAG_METHODTYPE,
                     _TAG_MODULE, _TAG_PACKAGE):
            pos += 2
        elif tag in (_TAG_METHODREF, _TAG_FIELDREF, _TAG_IFACEREF,
                     _TAG_NAMEANDTYPE, _TAG_DYNAMIC, _TAG_INVOKEDYN):
            pos += 4
        elif tag in (_TAG_INTEGER, _TAG_FLOAT):
            pos += 4
        elif tag in (_TAG_LONG, _TAG_DOUBLE):
            pos += 8
            i += 1  # longs and doubles take two constant pool slots
        elif tag == _TAG_METHODHANDLE:
            pos += 3
        else:
            break  # unknown tag — stop (corrupt class file)
        i += 1

    return utf8_pool


def _scan_class(class_name: str, data: bytes) -> List[JavaExecFinding]:
    """
    Return exec-class findings for a single .class file.

    Requires co-occurrence of the exec-class class name AND method name in the
    same constant pool to suppress false positives from common method names
    ('start', 'exec', 'load') that appear in unrelated contexts.
    """
    pool = _read_utf8_pool(data)
    if not pool:
        return []

    pool_set = set(p for p in pool if p)
    findings: List[JavaExecFinding] = []

    # RUNTIME_EXEC: java/lang/Runtime + exec method
    if 'java/lang/Runtime' in pool_set and 'exec' in pool_set:
        findings.append(JavaExecFinding(
            class_file=class_name,
            category='RUNTIME_EXEC',
            api_ref='Runtime.exec()',
            evidence='java/lang/Runtime + exec',
        ))

    # PROCESS_BUILDER: java/lang/ProcessBuilder + start
    if ('java/lang/ProcessBuilder' in pool_set or 'java/lang/Process' in pool_set) \
            and 'start' in pool_set:
        pb = 'java/lang/ProcessBuilder' if 'java/lang/ProcessBuilder' in pool_set \
             else 'java/lang/Process'
        findings.append(JavaExecFinding(
            class_file=class_name,
            category='PROCESS_BUILDER',
            api_ref='ProcessBuilder.start()',
            evidence=f'{pb} + start',
        ))

    # NATIVE_LOAD: java/lang/System + load or loadLibrary
    if 'java/lang/System' in pool_set:
        for meth in ('loadLibrary', 'load', 'mapLibraryName'):
            if meth in pool_set:
                findings.append(JavaExecFinding(
                    class_file=class_name,
                    category='NATIVE_LOAD',
                    api_ref=f'System.{meth}()',
                    evidence=f'java/lang/System + {meth}',
                ))
                break

    # REFLECTIVE_EXEC: both forName and invoke/getMethod in the same class
    has_classload = 'forName' in pool_set
    has_invoke = any(m in pool_set for m in ('invoke', 'getDeclaredMethod', 'getMethod'))
    if has_classload and has_invoke:
        findings.append(JavaExecFinding(
            class_file=class_name,
            category='REFLECTIVE_EXEC',
            api_ref='Class.forName() + invoke',
            evidence='forName + invoke/getMethod',
        ))

    return findings


# ── public API ────────────────────────────────────────────────────────────────

class JavaJarScanner:
    """
    Scan a JAR file (or a list of .class bytes) for exec-class Java API usage.

    Usage:
        result = JavaJarScanner.scan_jar('/path/to/app.jar')
        print(result.report())

        # From an open ZipFile (e.g. JAR nested inside another archive):
        result = JavaJarScanner.scan_zip(zf, jar_entry_name)
    """

    @staticmethod
    def scan_jar(jar_path: str) -> JavaJarResult:
        """Scan a JAR file on disk."""
        p = Path(jar_path)
        result = JavaJarResult(jar_path=str(p), class_count=0)
        try:
            with zipfile.ZipFile(str(p)) as zf:
                JavaJarScanner._scan_zip_into(zf, result, label=str(p))
        except Exception as exc:
            result.findings.append(JavaExecFinding(
                class_file='<error>',
                category='SCAN_ERROR',
                api_ref=str(exc),
                evidence='',
            ))
        return result

    @staticmethod
    def scan_zip(zf: zipfile.ZipFile, label: str = '') -> JavaJarResult:
        """Scan a JAR that is already open as a ZipFile."""
        result = JavaJarResult(jar_path=label, class_count=0)
        JavaJarScanner._scan_zip_into(zf, result, label=label)
        return result

    @staticmethod
    def scan_bytes(data: bytes, label: str = '') -> JavaJarResult:
        """Scan a JAR from raw bytes (e.g. extracted from a BFF archive)."""
        import io
        result = JavaJarResult(jar_path=label, class_count=0)
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                JavaJarScanner._scan_zip_into(zf, result, label=label)
        except Exception as exc:
            result.findings.append(JavaExecFinding(
                class_file='<error>',
                category='SCAN_ERROR',
                api_ref=str(exc),
                evidence='',
            ))
        return result

    @staticmethod
    def _scan_zip_into(zf: zipfile.ZipFile, result: JavaJarResult, label: str) -> None:
        for entry in zf.namelist():
            if not entry.endswith('.class'):
                continue
            result.class_count += 1
            try:
                data = zf.read(entry)
                hits = _scan_class(entry, data)
                result.findings.extend(hits)
            except Exception:
                pass
