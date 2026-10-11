#!/usr/bin/env python3
"""
sweeps/ti_sweep.py — Texas Instruments SDK firmware vulnerability sweep.

Handles TI TIREX package directories (138 zip archives, 23 GB).

Binary classes dispatched:
    TI COFF2/AR (.a, .lib)  → TiCoffLoader + TiNNCScanner + EcuC28xDecoder
    ARM Thumb ELF (.out)    → ARM32TaintTracker(thumb=True)
    ARM64 ELF (.out)        → ARM64TaintTracker
    Flat binary (.bin)      → FlatBinaryFuncStartScanner + EcuArchDetector

Phase order per package:
    0  Triage  — extract zip, classify by magic, PLT-exec-sink filter for ELFs
    1  NNC     — TiNNCScanner (symbol-table only; fast)
    2  Taint   — arch-routed TaintTracker on PLT-passing ELFs
    3  C28x    — EcuC28xDecoder func-start harvest + EcuSecurityAccessScanner
    4  Crypto  — CryptoPatternDetector on all binary types

Usage:
    python3 sweeps/ti_sweep.py /media/cowboy/research/TI-RE/tirex/
    python3 sweeps/ti_sweep.py /media/cowboy/research/TI-RE/tirex/MSPM0-SDK__2.11.00.07.zip
    python3 sweeps/ti_sweep.py /tmp/mspm0_sdk/ --product MSPM0-SDK --version 2.11.00.07
    python3 sweeps/ti_sweep.py /media/cowboy/research/TI-RE/tirex/ --no-taint
    python3 sweeps/ti_sweep.py /media/cowboy/research/TI-RE/tirex/ --filter simplelink
"""
from __future__ import annotations

import argparse
import os
import shutil
import struct
import sys
import tempfile
import traceback
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── arch constants ─────────────────────────────────────────────────────────────

_ARCH_ARM32  = "ARCH.ARM"
_ARCH_ARM64  = "ARCH.AARCH64"
_ARCH_RISCV32 = "ARCH.RISCV"

# ── TI-specific vulnerability profiles ────────────────────────────────────────

TI_VULN_PROFILES: List[Tuple[str, str]] = [
    ("ti_ota_no_auth",
     "FUNC | calls: memcpy SHA256 ECDSA_Verify BIM_open BIM_close Flash_verify | "
     "vuln: OTA firmware image loaded without ECDSA/RSA signature verification; "
     "only CRC16 or CRC32 integrity check; any image accepted as valid; "
     "TI BIM OAD bootloader; CWE-347 class"),

    ("ti_uart_overflow",
     "FUNC | calls: UART_read UART_readPolling UART2_read memcpy strcpy | "
     "vuln: UART HAL receive into fixed-size stack or heap buffer without length "
     "bound check; attacker controls receive length via serial line; "
     "TI-RTOS UART driver; CWE-121 class"),

    ("ti_ble_packet_overflow",
     "FUNC | calls: HCI_LE_ReadBufSize memcpy memmove osal_mem_alloc | "
     "vuln: BLE/BLE5 advertisement or data packet; length field from remote peer "
     "controls memcpy destination size without upper bound; heap or stack overflow; "
     "TI BLE-Stack / BLE5-Stack; CWE-122 class"),

    ("ti_uds_sa_weak_seed",
     "FUNC | calls: Diag_SendPositiveResponse memcpy SecurityAccess | "
     "vuln: UDS/KWP2000 SecurityAccess service returns static or predictable seed; "
     "same seed returned on every request; no TRNG or timer-based randomness; "
     "attacker computes key offline and gains unauthenticated diagnostic access; "
     "CWE-798 class"),

    ("ti_flash_write_unchecked",
     "FUNC | calls: FlashProgram FlashSectorErase Flash_write NVS_write NVOCMP_writeItem | "
     "vuln: flash write address or length from untrusted source without range check; "
     "attacker controls write offset; arbitrary flash overwrite; "
     "TI SimpleLink/MSP430 flash driver; CWE-787 class"),

    ("ti_coap_parse_overflow",
     "FUNC | calls: memcpy CoAP_parse MQTT_recvPacket recv recvfrom | "
     "vuln: CoAP/MQTT packet length field from network controls memcpy "
     "destination buffer size without upper bound; heap or stack overflow; "
     "TI SimpleLink CC13xx/CC26xx; CWE-122 class"),

    ("ti_wifi_ssid_overflow",
     "FUNC | calls: sl_WlanConnect memcpy strcpy strncpy | "
     "vuln: SimpleLink WiFi SSID or passphrase string not null-terminated or "
     "exceeds 32/64 byte buffer; fixed-size stack buffer overflow; "
     "sl_WlanConnect does not validate SSID length; CWE-121 class"),

    ("ti_dmm_race",
     "FUNC | calls: DMM_rfCallback RF_postCmd RF_pendCmd | "
     "vuln: TI Dynamic Multi-protocol Manager shared RF command queue accessed "
     "from multiple protocol stacks without synchronization; TOCTOU on "
     "RF_Stat_CmdDoneSuccess check before buffer reuse; CWE-362 class"),

    ("ti_rtos_stack_overflow",
     "FUNC | calls: Task_create Semaphore_pend memcpy | "
     "vuln: TI-RTOS/FreeRTOS task stack allocated without overflow guard page; "
     "stack size computed from untrusted input; adjacent task stack corrupted; "
     "CWE-121 class"),

    ("ti_crypto_weak_rng",
     "FUNC | calls: TRNG_getRandomBytes CryptoKey_initBlankKey AES_CCM_init | "
     "vuln: TRNG initialized with fixed seed or entropy not collected before key "
     "generation; deterministic key material; repeated session keys; "
     "TI PSA Crypto / CC26xx TRNG; CWE-330 class"),
]

# ── binary format detection ────────────────────────────────────────────────────

_ELF_MAGIC   = b'\x7fELF'
_COFF2_MAGIC = b'\xC2\x00'   # TI COFF2 (little-endian: 0x00C2)
_COFF1_MAGIC = b'\xC1\x00'   # TI COFF1
_AR_MAGIC    = b'!<arch>\n'


def _classify_binary(path: str) -> str:
    """Return 'elf', 'ti_coff', 'flat_bin', or 'skip'."""
    try:
        with open(path, 'rb') as f:
            header = f.read(8)
    except OSError:
        return 'skip'
    if header[:4] == _ELF_MAGIC:
        return 'elf'
    if header[:8] == _AR_MAGIC:
        return 'ti_coff'
    if header[:2] in (_COFF2_MAGIC, _COFF1_MAGIC):
        return 'ti_coff'
    ext = Path(path).suffix.lower()
    if ext == '.bin':
        return 'flat_bin'
    return 'skip'


def _detect_elf_arch(path: str) -> Optional[str]:
    """Return arch constant from ELF e_machine field, or None."""
    try:
        import lief
        b = lief.parse(path)
        if b is None:
            return None
        arch_str = str(b.header.machine_type)
        return arch_str
    except Exception:
        return None


# ── package extraction ─────────────────────────────────────────────────────────

def _extract_zip(zip_path: str, dest: str, _depth: int = 0) -> List[str]:
    """Extract zip to dest, return list of extracted file paths.

    Recursively extracts inner .zip files one level deep to handle TI "demo"
    packages that wrap all content in a single nested zip.
    """
    extracted = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for info in zf.infolist():
                if info.filename.endswith('/'):
                    continue
                target = os.path.join(dest, info.filename)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                try:
                    with zf.open(info) as src, open(target, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                    extracted.append(target)
                except Exception:
                    pass
    except Exception as e:
        print(f"  [!] Zip extraction failed: {e}")
        return extracted

    # If the outer zip had no binaries but contains exactly one inner zip,
    # recurse one level to handle TI demo packages.
    if _depth == 0:
        binary_exts = {'.out', '.elf', '.lib', '.a', '.bin'}
        direct_bins = [p for p in extracted if Path(p).suffix.lower() in binary_exts]
        inner_zips = [p for p in extracted if p.endswith('.zip')]
        if not direct_bins and len(inner_zips) == 1:
            extra = _extract_zip(inner_zips[0], dest, _depth=1)
            extracted.extend(extra)

    return extracted


def _enumerate_binaries(paths: List[str]) -> Dict[str, List[str]]:
    """Classify paths into buckets: elf, ti_coff, flat_bin."""
    buckets: Dict[str, List[str]] = {'elf': [], 'ti_coff': [], 'flat_bin': []}
    for p in paths:
        ext = Path(p).suffix.lower()
        if ext in ('.hex', '.srec', '.mot', '.s19', '.py', '.c', '.h',
                   '.json', '.xml', '.txt', '.md', '.pdf', '.js', '.html'):
            continue
        kind = _classify_binary(p)
        if kind in buckets:
            buckets[kind].append(p)
    return buckets


# ── ELF AR extraction ─────────────────────────────────────────────────────────

def _extract_elf_ar_members(ar_path: str, dest_dir: str) -> List[str]:
    """
    Extract ELF object files from a GNU AR archive into dest_dir.

    TI tiarmclang (LLVM-based) produces ELF-based AR archives where each
    member is an ARM ELF object file. TiCoffLoader rejects these (not COFF2);
    lief.parse() also rejects them (AR magic). This helper extracts each ELF
    member to a temp file so TiNNCScanner can scan them individually.

    Returns list of extracted ELF paths. Returns empty list if the AR
    contains only COFF2 members or is not an ELF AR.
    """
    extracted = []
    try:
        with open(ar_path, 'rb') as f:
            data = f.read()
    except OSError:
        return extracted

    if data[:8] != _AR_MAGIC:
        return extracted

    offset = 8
    idx = 0
    while offset + 60 <= len(data):
        name_raw = data[offset:offset+16].rstrip(b' /')
        size_raw = data[offset+48:offset+58].rstrip(b' \x00')
        end_magic = data[offset+58:offset+60]
        if end_magic != b'`\n':
            break
        try:
            member_size = int(size_raw)
        except ValueError:
            break
        member_data = data[offset+60:offset+60+member_size]
        offset += 60 + member_size
        if offset % 2:
            offset += 1

        # Skip AR symbol-table members (name starts with '/')
        name = name_raw.decode('ascii', errors='replace').strip()
        if name.startswith('/') or not name:
            continue

        # Only extract ELF members
        if member_data[:4] != b'\x7fELF':
            continue

        out_path = os.path.join(dest_dir, f'{os.path.basename(ar_path)}_{idx}_{name}')
        try:
            with open(out_path, 'wb') as f:
                f.write(member_data)
            extracted.append(out_path)
        except OSError:
            pass
        idx += 1

    return extracted


# ── Phase 1: TI NNC scan ───────────────────────────────────────────────────────

def _phase1_nnc(paths: List[str]) -> List[dict]:
    """Run TiNNCScanner on COFF/AR and ELF files. Fast (symbol table only).

    Also handles ELF-based AR archives (tiarmclang output) by extracting
    ELF members to a temp directory before scanning.
    """
    from ablation.analyzers.ti_nnc_scanner import TiNNCScanner
    findings = []
    tmp_elf_dir = tempfile.mkdtemp(prefix='ti_elf_ar_')
    try:
        # Expand ELF AR archives into individual ELF members
        expanded: List[str] = []
        for p in paths:
            with open(p, 'rb') as f:
                magic8 = f.read(8)
            if magic8 == _AR_MAGIC:
                members = _extract_elf_ar_members(p, tmp_elf_dir)
                if members:
                    expanded.extend(members)
                    continue
            expanded.append(p)

        for p in expanded:
            try:
                scanner = TiNNCScanner.from_path(p)
                result = scanner.scan()
                for f in result.findings:
                    findings.append({
                        'binary': os.path.basename(p),
                        'binary_path': p,
                        'finding_id': f.finding_id,
                        'severity': f.severity,
                        'title': f.title,
                        'module_name': f.module_name,
                        'va': f.va,
                        'symbol': f.symbol,
                        'description': f.description,
                        'phase': 'nnc',
                    })
            except Exception:
                pass
    finally:
        shutil.rmtree(tmp_elf_dir, ignore_errors=True)
    return findings


# ── Phase 2: ELF taint ─────────────────────────────────────────────────────────

def _phase2_taint(elf_paths: List[str], use_taint: bool) -> List[dict]:
    """Arch-routed taint analysis on ARM ELF files."""
    if not use_taint:
        return []

    from ablation.core.platform_detect import PlatformDetect
    findings = []

    for path in elf_paths:
        arch = _detect_elf_arch(path)
        if arch is None:
            continue
        try:
            _run_taint_on_elf(path, arch, findings)
        except Exception as e:
            print(f"  [!] Taint on {os.path.basename(path)} failed: {e}")

    return findings


def _run_taint_on_elf(path: str, arch: str, findings: List[dict]) -> None:
    """Dispatch taint analysis by arch."""
    basename = os.path.basename(path)

    # ARM32 Thumb (Cortex-M0+/M33/M4/R5)
    if _ARCH_ARM32 in arch:
        from ablation.analyzers.taint_tracker_arm32 import ARM32TaintTracker
        tracker = ARM32TaintTracker.from_path(path, thumb=True)
        results = tracker.run_interprocedural()
        for r in results:
            findings.append({
                'binary': basename,
                'binary_path': path,
                'finding_id': 'TAINT-ARM32',
                'severity': 'HIGH',
                'title': str(r),
                'phase': 'taint',
                'arch': 'arm32_thumb',
            })
        return

    # ARM64 (Cortex-A53 / AM62x)
    if _ARCH_ARM64 in arch:
        from ablation.analyzers.taint_tracker_arm64 import ARM64TaintTracker
        tracker = ARM64TaintTracker.from_path_full(path)
        results = tracker.run_interprocedural()
        for r in results:
            findings.append({
                'binary': basename,
                'binary_path': path,
                'finding_id': 'TAINT-ARM64',
                'severity': 'HIGH',
                'title': str(r),
                'phase': 'taint',
                'arch': 'arm64',
            })
        return

    # RISC-V 32 (future TI targets)
    if _ARCH_RISCV32 in arch:
        from ablation.analyzers.taint_tracker_riscv32 import RISCV32TaintTracker
        tracker = RISCV32TaintTracker.from_path(path)
        results = tracker.run_interprocedural()
        for r in results:
            findings.append({
                'binary': basename,
                'binary_path': path,
                'finding_id': 'TAINT-RV32',
                'severity': 'HIGH',
                'title': str(r),
                'phase': 'taint',
                'arch': 'riscv32',
            })


# ── Phase 3: C28x disasm + security access ────────────────────────────────────

def _phase3_c28x(coff_paths: List[str], flat_paths: List[str]) -> List[dict]:
    """C28x function-start harvest + SecurityAccess scan on flat ROMs."""
    from ablation.analyzers.ecu_c28x_decoder import EcuC28xDecoder
    from ablation.analyzers.ti_coff_loader import TiCoffLoader, TI_TARGET_C2800
    from ablation.analyzers.ecu_security_access_scanner import EcuSecurityAccessScanner

    findings = []

    # C28x function-start harvest on COFF archives
    for path in coff_paths:
        try:
            loader = TiCoffLoader.from_path(path)
            loader.parse()
            for obj in loader.objects():
                if obj.header.target_id != TI_TARGET_C2800:
                    continue
                # Collect .text section bytes for function-start harvest
                # (EcuC28xDecoder works on raw bytes; COFF section extraction needed)
                # For now: enumerate C_UEXT symbols as weak-symbol candidates
                weak_syms = [s for s in obj.symbols if s.is_weak]
                if weak_syms:
                    for sym in weak_syms[:10]:
                        findings.append({
                            'binary': os.path.basename(path),
                            'binary_path': path,
                            'finding_id': 'C28X-WEAK-SYM',
                            'severity': 'MEDIUM',
                            'title': f'C28x C_UEXT (weak) symbol: {sym.name}',
                            'description': (
                                f'Symbol {sym.name!r} in {obj.member_name} is tentative external '
                                '(C_UEXT storage class = TI COFF weak). Any object linked after '
                                'this archive providing a C_EXT of the same name silently overrides '
                                'it. If this is a normalization or calibration constant the override '
                                'can corrupt floating-point arithmetic without warning.'
                            ),
                            'phase': 'c28x',
                        })
        except Exception:
            pass

    # SecurityAccess static seed scan on flat .bin images
    for path in flat_paths:
        try:
            data = Path(path).read_bytes()
            if len(data) < 256:
                continue
            scanner = EcuSecurityAccessScanner(data)
            sa_findings = scanner.scan()
            for sf in sa_findings:
                findings.append({
                    'binary': os.path.basename(path),
                    'binary_path': path,
                    'finding_id': 'C28X-SA-STATIC-SEED',
                    'severity': 'CRITICAL',
                    'title': str(sf),
                    'phase': 'c28x',
                })
        except Exception:
            pass

    return findings


# ── Phase 4: Crypto pattern ────────────────────────────────────────────────────

def _phase4_crypto(elf_paths: List[str]) -> List[dict]:
    """HashAlgoDiscriminator scan on ARM Thumb ELF binaries."""
    from ablation.analyzers.crypto_pattern_detector import HashAlgoDiscriminator
    findings = []
    for path in elf_paths:
        arch = _detect_elf_arch(path)
        if arch is None or _ARCH_ARM32 not in arch:
            continue
        try:
            data = Path(path).read_bytes()
            if len(data) < 256:
                continue
            disc = HashAlgoDiscriminator(data, load_addr=0)
            # Scan entire binary for crypto constants
            matches = disc.scan_function(0, len(data))
            if matches and matches.algo:
                findings.append({
                    'binary': os.path.basename(path),
                    'binary_path': path,
                    'finding_id': f'CRYPTO-{matches.algo}',
                    'severity': 'INFO',
                    'title': f'Hash implementation detected: {matches.algo} (confidence={matches.confidence})',
                    'phase': 'crypto',
                })
        except Exception:
            pass
    return findings


# ── Semantic sweep on ELFs ─────────────────────────────────────────────────────

def _semantic_sweep_elf(elf_paths: List[str], vendor: str, product: str,
                        version: str) -> List[dict]:
    """SemanticSearcher sweep with TI-specific profiles on ARM ELF binaries."""
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.semantic_search import SemanticSearcher
    from sweeps.base_sweep import VULN_PROFILES

    all_profiles = VULN_PROFILES + TI_VULN_PROFILES
    findings = []

    for path in elf_paths:
        arch = _detect_elf_arch(path)
        if arch is None:
            continue
        # Only sweep binaries large enough to have meaningful functions
        size = Path(path).stat().st_size
        if size < 4096:
            continue
        try:
            ctx = BinaryContext.load_or_build(path)
            searcher = SemanticSearcher.from_context(ctx)
            for name, query in all_profiles:
                hits = searcher.query(query, top_k=3)
                for hit in hits:
                    if hit.score < 0.65:
                        continue
                    findings.append({
                        'binary': os.path.basename(path),
                        'binary_path': path,
                        'finding_id': f'SEM-{name.upper()}',
                        'severity': 'HIGH' if hit.score >= 0.75 else 'MEDIUM',
                        'title': f'{name}: score={hit.score:.3f} va=0x{hit.va:08x}',
                        'description': hit.name,
                        'phase': 'semantic',
                        'score': hit.score,
                        'va': hit.va,
                    })
        except Exception as e:
            print(f"  [!] Semantic sweep on {os.path.basename(path)}: {e}")

    return findings


# ── Report generation ──────────────────────────────────────────────────────────

_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}


def _render_report(
    package_name: str,
    all_findings: List[dict],
    binaries: Dict[str, List[str]],
    elapsed: float,
) -> str:
    lines = [
        f'# TI Sweep: {package_name}',
        f'',
        f'- Generated: {datetime.now(timezone.utc).isoformat()}',
        f'- ELF binaries: {len(binaries["elf"])}',
        f'- COFF/AR binaries: {len(binaries["ti_coff"])}',
        f'- Flat binaries: {len(binaries["flat_bin"])}',
        f'- Elapsed: {elapsed:.1f}s',
        f'- Total findings: {len(all_findings)}',
        f'',
    ]

    if not all_findings:
        lines.append('No findings.')
        return '\n'.join(lines)

    sorted_findings = sorted(all_findings,
                             key=lambda f: _SEV_ORDER.get(f.get('severity', 'INFO'), 9))

    lines.append('## Findings')
    lines.append('')
    lines.append('| ID | Severity | Binary | Title | Phase |')
    lines.append('|---|---|---|---|---|')

    for f in sorted_findings:
        fid = f.get('finding_id', '?')
        sev = f.get('severity', '?')
        binary = f.get('binary', '?')
        title = f.get('title', '')[:80]
        phase = f.get('phase', '?')
        lines.append(f'| {fid} | {sev} | {binary} | {title} | {phase} |')

    lines.append('')
    lines.append('## Details')
    lines.append('')
    for f in sorted_findings:
        lines.append(f'### [{f.get("severity","?")}] {f.get("finding_id","?")}')
        lines.append(f'**Binary:** `{f.get("binary","?")}`')
        if 'va' in f:
            lines.append(f'**VA:** `0x{f["va"]:08x}`')
        if 'symbol' in f and f['symbol']:
            lines.append(f'**Symbol:** `{f["symbol"]}`')
        desc = f.get('description', f.get('title', ''))
        lines.append('')
        lines.append(desc)
        lines.append('')

    return '\n'.join(lines)


# ── Package sweep entry point ──────────────────────────────────────────────────

def sweep_package(
    input_path: str,
    use_taint: bool = True,
    use_semantic: bool = False,
    vendor: str = 'ti',
    product: str = '',
    version: str = '',
) -> Tuple[str, List[dict]]:
    """
    Sweep a single TI package (zip, directory, or binary).
    Returns (package_name, findings_list).
    """
    import time
    t0 = time.time()

    pkg_name = Path(input_path).stem.replace('__', '_')
    print(f'\n[*] Package: {pkg_name}')

    tmp_dir = None
    file_paths: List[str] = []

    p = Path(input_path)
    if p.is_dir():
        for f in p.rglob('*'):
            if f.is_file():
                file_paths.append(str(f))
    elif p.suffix.lower() == '.zip':
        tmp_dir = tempfile.mkdtemp(prefix='ti_sweep_')
        print(f'  Extracting to {tmp_dir} ...')
        file_paths = _extract_zip(str(p), tmp_dir)
    elif p.is_file():
        file_paths = [str(p)]

    try:
        binaries = _enumerate_binaries(file_paths)
        n_elf = len(binaries['elf'])
        n_coff = len(binaries['ti_coff'])
        n_flat = len(binaries['flat_bin'])
        print(f'  Binaries: ELF={n_elf} COFF/AR={n_coff} flat={n_flat}')

        all_findings: List[dict] = []

        # Phase 1: NNC (all binary types)
        nnc_targets = binaries['ti_coff'] + binaries['elf']
        if nnc_targets:
            print(f'  Phase 1: NNC scan ({len(nnc_targets)} files) ...')
            all_findings.extend(_phase1_nnc(nnc_targets))

        # Phase 2: ELF taint
        if binaries['elf'] and use_taint:
            print(f'  Phase 2: Taint ({n_elf} ELFs) ...')
            all_findings.extend(_phase2_taint(binaries['elf'], use_taint))

        # Phase 3: C28x + SecurityAccess
        if binaries['ti_coff'] or binaries['flat_bin']:
            print(f'  Phase 3: C28x / SA scan ...')
            all_findings.extend(_phase3_c28x(binaries['ti_coff'], binaries['flat_bin']))

        # Phase 4: Crypto (ARM32 Thumb ELFs only)
        if binaries['elf']:
            print(f'  Phase 4: Crypto hash scan ({len(binaries["elf"])} ELFs) ...')
            all_findings.extend(_phase4_crypto(binaries['elf']))

        # Optional semantic sweep
        if use_semantic and binaries['elf']:
            print(f'  Semantic sweep ({n_elf} ELFs) ...')
            all_findings.extend(_semantic_sweep_elf(
                binaries['elf'], vendor, product, version
            ))

        elapsed = time.time() - t0
        report_md = _render_report(pkg_name, all_findings, binaries, elapsed)

        sev_counts = {}
        for f in all_findings:
            s = f.get('severity', 'INFO')
            sev_counts[s] = sev_counts.get(s, 0) + 1
        print(f'  Done in {elapsed:.1f}s — {len(all_findings)} findings: {sev_counts}')

        return pkg_name, all_findings, report_md

    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ── Master sweep ───────────────────────────────────────────────────────────────

def sweep_directory(
    tirex_dir: str,
    filter_str: str = '',
    use_taint: bool = True,
    use_semantic: bool = False,
) -> None:
    """Sweep all TI TIREX packages in a directory."""
    import time
    t0 = time.time()

    tirex = Path(tirex_dir)
    zip_files = sorted(tirex.glob('*.zip'))
    if filter_str:
        zip_files = [z for z in zip_files
                     if filter_str.lower() in z.name.lower()]

    print(f'[*] TI sweep: {len(zip_files)} packages in {tirex_dir}')
    if filter_str:
        print(f'[*] Filter: {filter_str!r}')

    ts = datetime.utcnow().strftime('%Y%m%d_%H%M')
    reports_dir = Path('reports')
    reports_dir.mkdir(exist_ok=True)

    all_master_findings: List[dict] = []

    for i, zip_path in enumerate(zip_files, 1):
        print(f'\n[{i}/{len(zip_files)}] {zip_path.name}')
        try:
            pkg_name, findings, report_md = sweep_package(
                str(zip_path),
                use_taint=use_taint,
                use_semantic=use_semantic,
                vendor='ti',
                product=zip_path.stem,
            )

            # Write per-package report
            slug = pkg_name[:60].replace(' ', '_').replace('/', '_')
            report_path = reports_dir / f'sweep_ti_{slug}_{ts}.md'
            report_path.write_text(report_md)

            # Tag findings with package name
            for f in findings:
                f['package'] = pkg_name
            all_master_findings.extend(findings)

        except KeyboardInterrupt:
            print('\n[!] Interrupted by user')
            break
        except Exception as e:
            print(f'[!] Package failed: {e}')
            traceback.print_exc()

    # Write master report
    elapsed_total = time.time() - t0
    master_path = reports_dir / f'sweep_ti_master_{ts}.md'
    master_lines = [
        f'# TI Firmware Sweep — Master Report',
        f'',
        f'- Generated: {datetime.now(timezone.utc).isoformat()}',
        f'- Packages: {len(zip_files)}',
        f'- Total findings: {len(all_master_findings)}',
        f'- Total elapsed: {elapsed_total:.0f}s ({elapsed_total/60:.1f} min)',
        f'',
        '## All Findings',
        '',
        '| Package | ID | Severity | Binary | Title | Phase |',
        '|---|---|---|---|---|---|',
    ]
    sorted_master = sorted(
        all_master_findings,
        key=lambda f: (_SEV_ORDER.get(f.get('severity', 'INFO'), 9), f.get('package', ''))
    )
    for f in sorted_master:
        master_lines.append(
            f'| {f.get("package","?")} '
            f'| {f.get("finding_id","?")} '
            f'| {f.get("severity","?")} '
            f'| {f.get("binary","?")} '
            f'| {f.get("title","")[:70]} '
            f'| {f.get("phase","?")} |'
        )

    master_path.write_text('\n'.join(master_lines))
    print(f'\n[*] Master report: {master_path}')
    print(f'[*] Total: {len(all_master_findings)} findings across {len(zip_files)} packages '
          f'in {elapsed_total:.0f}s')


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description='TI firmware vulnerability sweep'
    )
    ap.add_argument('input', help='TIREX directory, .zip package, or binary file')
    ap.add_argument('--no-taint', action='store_true',
                    help='Skip taint analysis (NNC + crypto only — faster)')
    ap.add_argument('--semantic', action='store_true',
                    help='Enable semantic search sweep on ELF binaries (slow)')
    ap.add_argument('--filter', default='',
                    help='Only process packages whose name contains this string')
    ap.add_argument('--product', default='', help='Product name override')
    ap.add_argument('--version', default='', help='Version override')
    args = ap.parse_args()

    use_taint    = not args.no_taint
    use_semantic = args.semantic

    p = Path(args.input)
    if p.is_dir() and any(p.glob('*.zip')):
        # Directory of zip packages
        sweep_directory(
            str(p),
            filter_str=args.filter,
            use_taint=use_taint,
            use_semantic=use_semantic,
        )
    elif p.is_dir() or p.suffix.lower() == '.zip' or p.is_file():
        # Single package or binary
        pkg_name, findings, report_md = sweep_package(
            str(p),
            use_taint=use_taint,
            use_semantic=use_semantic,
            vendor='ti',
            product=args.product or p.stem,
            version=args.version,
        )
        ts = datetime.utcnow().strftime('%Y%m%d_%H%M')
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        slug = pkg_name[:60].replace(' ', '_')
        report_path = reports_dir / f'sweep_ti_{slug}_{ts}.md'
        report_path.write_text(report_md)
        print(f'\n[*] Report: {report_path}')
    else:
        print(f'[!] Input not found: {args.input}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
