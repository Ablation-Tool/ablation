"""
axis_eap_re — AXIS ACAP EAP package RE module

Reverse engineers AXIS camera application packages (*.eap = gzip'd tar).
Targets:
  SipThirdPartyIntegration (aarch64 ELF, debug symbols, liblicensekey.so)
  BarcodeReader             (ARM32 ELF, stripped, libaxhttp/libvdostream)
  BodyWornLiveSelfHosted    (aarch64 Go static, WebRTC/coturn/MQTT/JWT)
  facedetector              (aarch64 ELF, stripped, libvideo-object-detection)

Attack surface by component:
  licensekey_verify() bypass — LD_LIBRARY_PATH / LD_PRELOAD / /etc/ld.so.preload
  SipThirdPartyIntegration — sipd dependency gate (post_install.sh exit 77 skip)
  BodyWornLiveSelfHosted   — getStunTurnTestCredentials CGI, signaling JWT, coturn TURN creds
  BarcodeReader            — VAPIX service account token, http://127.0.0.12/ loopback, libcurl
  facedetector             — CVE-2024-47257 (AXIS) CGI param injection via protobuf decode

Usage:
    from modules.axis_eap_re import AxisEAPAnalyzer
    a = AxisEAPAnalyzer('/media/cowboy/research/AXIS')
    a.survey()
    a.licensekey_bypass_vectors('/path/to/SipThirdPartyIntegration')
    a.bodyworn_attack_surface()
    a.barcode_vapix_surface()

Standalone:
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --all
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --license-bypass
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --bodyworn
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --barcode
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --facedetector
    python3 modules/axis_eap_re.py /path/to/SipThirdPartyIntegration --license-bypass
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


# ── helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    kw.setdefault('capture_output', True)
    kw.setdefault('text', True)
    return subprocess.run(cmd, **kw)


def _strings(path: str, min_len: int = 4) -> list[str]:
    r = _run(['strings', f'-{min_len}', path])
    return r.stdout.splitlines() if r.returncode == 0 else []


def _nm(path: str) -> tuple[list[str], list[str]]:
    """Returns (defined_syms, undefined_imports)."""
    r = _run(['nm', path])
    defined, undefined = [], []
    for line in r.stdout.splitlines():
        parts = line.split()
        if ' U ' in line:
            undefined.append(parts[-1])
        elif len(parts) >= 3:
            defined.append(parts[-1])
    return defined, undefined


def _readelf_dynamic(path: str) -> list[str]:
    r = _run(['readelf', '-d', path])
    libs = []
    for line in r.stdout.splitlines():
        m = re.search(r'NEEDED.*\[(.+?)\]', line)
        if m:
            libs.append(m.group(1))
    return libs


def _file(path: str) -> str:
    r = _run(['file', path])
    return r.stdout.strip()


def _extract_eap(eap_path: str, dest: str) -> bool:
    try:
        with tarfile.open(eap_path, 'r:gz') as tf:
            tf.extractall(dest)
        return True
    except tarfile.TarError:
        # Trailing garbage (EAP signature); try streaming
        try:
            r = _run(['tar', 'xzf', eap_path, '-C', dest])
            return True
        except Exception:
            return False


# ── core class ───────────────────────────────────────────────────────────────

class AxisEAPAnalyzer:
    """
    RE engine for AXIS ACAP EAP packages.

    Pass either:
      - A directory containing *.eap files (survey mode)
      - A path to a single extracted ELF binary (targeted mode)
    """

    # Known EAP slugs and their primary binary name
    KNOWN_PACKAGES = {
        'SipThirdPartyIntegration': 'sip_ucs',
        'BarcodeReader': 'barcode',
        'BodyWornLiveSelfHosted': 'bodyworn',
        'facedetector': 'facedetector',
    }

    # licensekey_verify bypass env vars (from disasm of licensekey_stat.c)
    # Verified in SipThirdPartyIntegration @ 0x26b0–0x2770:
    #   getenv("licensekey_path") → handle_pathlist → file_overrides_symbols (dlopen/dlsym)
    #   getenv("LD_LIBRARY_PATH") → handle_pathlist → dir_contains_overriding_lib
    #   test_ld_so_preload()      → open("/etc/ld.so.preload"), mmap, parse, handle_pathlist
    LICENSE_BYPASS_ENV = [
        ('licensekey_path', 'colon-separated path list; if dir contains liblicensekey.so with matching symbols, verify returns 0'),
        ('LD_LIBRARY_PATH', 'standard LD path; dir_contains_overriding_lib scans for liblicensekey.so match'),
    ]

    # /etc/ld.so.preload bypass (test_ld_so_preload @ 0x24d0):
    # Opens /etc/ld.so.preload O_RDONLY, mmaps it, strips '#' comment lines,
    # passes each path token to handle_pathlist → dir_contains_overriding_lib.
    # Requires write access to /etc/ld.so.preload on device.
    LD_SO_PRELOAD_PATH = '/etc/ld.so.preload'

    # Enabled sentinel file (create_enabled_file / remove_enabled_file):
    ENABLED_FILE = '/etc/dynamic/sipd/acaps/third-party-integration-enabled'

    # ACAP app ID for SIP UCS (from manifest.json + licensekey_verify call @ 0x1ddc):
    # licensekey_verify(app_name, 0x654d2, minor=1, flags=0)
    # 0x654d2 = 414930 decimal = appId in manifest
    SIP_APP_ID = 414930

    def __init__(self, target: str):
        self.target = Path(target)
        self.tmpdir = None
        self.packages: dict[str, Path] = {}  # slug -> extracted dir
        self._scan_target()

    def _scan_target(self):
        if self.target.is_dir():
            # Check if it's a pre-extracted package dir
            for name in self.KNOWN_PACKAGES:
                binary = self.target / name
                if binary.exists():
                    self.packages[name] = self.target
                    return
            # Otherwise scan for *.eap files
            seen: set[str] = set()
            for eap in sorted(self.target.glob('*.eap')):
                # Deduplicate: keep one per base name (strip " (N)" suffix)
                base = re.sub(r'\s*\(\d+\)$', '', eap.stem)
                if base in seen:
                    continue
                seen.add(base)
                self._extract_package(eap)
        elif self.target.is_file():
            # Single binary — determine type from filename
            for name in self.KNOWN_PACKAGES:
                if name.lower() in self.target.name.lower():
                    self.packages[name] = self.target.parent
                    return
            # Unknown binary — add as raw
            self.packages[self.target.name] = self.target.parent

    def _extract_package(self, eap_path: Path) -> Path | None:
        if self.tmpdir is None:
            self.tmpdir = Path(tempfile.mkdtemp(prefix='axis_eap_'))
        dest = self.tmpdir / eap_path.stem.replace(' ', '_')
        dest.mkdir(exist_ok=True)
        ok = _extract_eap(str(eap_path), str(dest))
        if not ok:
            return None
        for name in self.KNOWN_PACKAGES:
            binary = dest / name
            if binary.exists():
                self.packages[name] = dest
                return dest
        # Unknown package — add by stem
        self.packages[eap_path.stem] = dest
        return dest

    # ── public API ────────────────────────────────────────────────────────────

    def survey(self) -> dict:
        """Quick survey of all extracted packages."""
        results = {}
        for slug, pkg_dir in self.packages.items():
            binary = pkg_dir / slug if (pkg_dir / slug).exists() else None
            if binary is None:
                # Find the first executable
                for f in pkg_dir.iterdir():
                    if f.is_file() and os.access(f, os.X_OK):
                        binary = f
                        break
            if binary is None:
                results[slug] = {'error': 'no binary found', 'dir': str(pkg_dir)}
                continue
            info = {
                'binary': str(binary),
                'file': _file(str(binary)),
                'size': binary.stat().st_size,
                'libs': _readelf_dynamic(str(binary)),
                'manifest': self._read_manifest(pkg_dir),
            }
            results[slug] = info
        return results

    def licensekey_bypass_vectors(self, binary_path: str | None = None) -> dict:
        """
        Map licensekey_verify() bypass paths for SipThirdPartyIntegration.

        Three bypass paths (from licensekey_stat.c via DWARF + disasm):
          1. licensekey_path env var → handle_pathlist → file_overrides_symbols
             (dlopen the colon-list; if dlsym finds licensekey_dyn_verify in it → returns 0)
          2. LD_LIBRARY_PATH → dir_contains_overriding_lib (scans each dir for liblicensekey.so)
          3. /etc/ld.so.preload → same dir scan (requires write to /etc/ld.so.preload)

        All three converge at dir_contains_overriding_lib.part.0 @ 0x2300:
          opendir(dir), snprintf path = dir + "/" + "liblicensekey.so",
          access(path, F_OK) → if exists, returns 1 → licensekey_verify returns 0 (VALID).

        Frida hook target on device:
          licensekey_verify @ liblicensekey.so.1 (NOT the wrapper in this binary)
          Patch: replace retval register (w0) with 0 after bl licensekey_dyn_verify@plt
        """
        if binary_path is None:
            pkg_dir = self.packages.get('SipThirdPartyIntegration')
            if pkg_dir:
                binary_path = str(pkg_dir / 'SipThirdPartyIntegration')

        result = {
            'binary': binary_path,
            'app_id': self.SIP_APP_ID,
            'enabled_sentinel': self.ENABLED_FILE,
            'sipd_required': '/usr/bin/sipd',
            'bypass_paths': [],
            'frida_hook': None,
        }

        # Path 1: licensekey_path env var
        result['bypass_paths'].append({
            'method': 'licensekey_path env var',
            'mechanism': (
                'Set licensekey_path=/writable/dir before exec. '
                'file_overrides_symbols() dlopen()s each colon-separated path as a dir; '
                'if dlsym(handle, "licensekey_dyn_verify") succeeds, returns 1 → verify returns 0.'
            ),
            'prerequisite': 'Can inject env vars into the ACAP process (e.g., via /etc/acap.conf or ACAP start hook)',
            'payload': 'mkdir /tmp/lk; cp <stub.so> /tmp/lk/liblicensekey.so; export licensekey_path=/tmp/lk',
        })

        # Path 2: LD_LIBRARY_PATH
        result['bypass_paths'].append({
            'method': 'LD_LIBRARY_PATH',
            'mechanism': (
                'dir_contains_overriding_lib() walks each LD_LIBRARY_PATH dir; '
                'checks access("dir/liblicensekey.so", F_OK). '
                'If found, licensekey_verify() short-circuits and returns 0 (VALID). '
                'The stub does NOT need to implement any symbols — access() check only.'
            ),
            'prerequisite': 'Can set LD_LIBRARY_PATH in the process environment',
            'payload': 'mkdir /tmp/lk; touch /tmp/lk/liblicensekey.so; export LD_LIBRARY_PATH=/tmp/lk',
        })

        # Path 3: /etc/ld.so.preload
        result['bypass_paths'].append({
            'method': '/etc/ld.so.preload write',
            'mechanism': (
                'test_ld_so_preload() opens /etc/ld.so.preload O_RDONLY, mmaps it, '
                'strips lines starting with 0x23 (#), splits on whitespace, '
                'calls handle_pathlist → dir_contains_overriding_lib per token. '
                'Same F_OK check as LD_LIBRARY_PATH path.'
            ),
            'prerequisite': 'Write access to /etc/ld.so.preload on device (root / ACAP install context)',
            'payload': 'echo /tmp/lk > /etc/ld.so.preload; mkdir /tmp/lk; touch /tmp/lk/liblicensekey.so',
        })

        # Frida hook
        result['frida_hook'] = self._sip_frida_hook()

        # Static verification from binary
        if binary_path and Path(binary_path).exists():
            result['static_checks'] = self._verify_license_disasm(binary_path)

        return result

    def bodyworn_attack_surface(self) -> dict:
        """
        BodyWornLiveSelfHosted Go binary attack surface.

        Components: rsignal (WebRTC signaling), coturn (TURN relay), mosquitto (MQTT),
                    vapixbridge (VAPIX↔MQTT), JWT auth (golang-jwt/jwt v5),
                    policykitcert (D-Bus cert management), IDD daemon.

        High-value CGI endpoints (from embedded Go symbol table):
          - auth.getSignalingClientToken  → issues JWT for WebRTC clients
          - auth.getStunTurnTestCredentials → returns TURN username+credential
          - setup.testSystemCredentials   → tests VAPIX digest auth (creds in request)
          - rsignal.getICEConfig          → ICE server list (STUN/TURN URLs + auth)
          - cgi.SetBasicAuth              → VAPIX Basic Auth wrapper
        """
        pkg_dir = self.packages.get('BodyWornLiveSelfHosted')
        binary = str(pkg_dir / 'BodyWornLiveSelfHosted') if pkg_dir else None

        result = {
            'binary': binary,
            'type': 'Go static aarch64',
            'go_build_id': None,
            'components': {
                'rsignal': 'WebRTC signaling server; JWT-gated ICE config endpoint',
                'coturn': 'TURN relay; cert-aware; restarts on cert/param change',
                'mosquitto': 'MQTT broker; vapixbridge translates Axis events to MQTT',
                'vapixbridge': 'MQTT↔VAPIX bridge; handles positioning + state events',
                'policykitcert': 'D-Bus client for cert set management (CreateCertificateSet)',
                'idd': 'rsignal/ IDD daemon directory present',
            },
            'cgi_attack_surface': [
                {
                    'endpoint': 'auth.getStunTurnTestCredentials',
                    'risk': 'Returns live TURN username+credential; no auth validated in test path',
                    'method': 'GET',
                    'notes': 'Issued via Authorizer.NewCoturnCredentials; coturn HMAC-SHA1 TURN credential',
                },
                {
                    'endpoint': 'auth.getSignalingClientToken',
                    'risk': 'Issues short-lived JWT signed with device key; WebRTC client access',
                    'method': 'GET',
                    'notes': 'golang-jwt/jwt v5; ECDSA or HMAC depending on key type in policykitcert',
                },
                {
                    'endpoint': 'setup.testSystemCredentials',
                    'risk': 'Validates VAPIX digest credentials supplied in CGI params; credential oracle',
                    'method': 'POST',
                    'notes': 'vapix.GetCredentials → VAPIX loopback auth; wrong creds = 401 timing diff',
                },
                {
                    'endpoint': 'rsignal.getICEConfig',
                    'risk': 'Returns STUN/TURN server list with auth tokens; may expose internal relay',
                    'method': 'GET',
                    'notes': 'rsignal.API.getICEConfig; auth via ValidateSignalingServerCredential',
                },
            ],
            'jwt_notes': (
                'golang-jwt/jwt v5 with WithValidMethods enforced. '
                'SigningMethodNone (alg:none) is registered but should be blocked by WithValidMethods. '
                'Verify ValidateSignalingServerCredential.WithValidMethods.func2 enforces non-none algs. '
                'JWT kid header not observed in symbols — key rotation surface unclear.'
            ),
            'coturn_credential_algo': (
                'Standard TURN REST API: username=<timestamp>:<user>, '
                'credential=HMAC-SHA1(shared_secret, username). '
                'getStunTurnTestCredentials exposes this without requiring camera auth in test context.'
            ),
            'files': {},
        }

        if pkg_dir:
            for fname in ['coturn', 'mosquitto', 'rsignal', 'idd']:
                subdir = pkg_dir / fname
                if subdir.is_dir():
                    result['files'][fname] = [f.name for f in subdir.iterdir()]

            # Extract Go build ID
            if binary and Path(binary).exists():
                strs = _strings(binary, min_len=6)
                for s in strs:
                    if 'BuildID' in s or s.startswith('S9R') or s.startswith('Go build'):
                        result['go_build_id'] = s
                        break

        return result

    def barcode_vapix_surface(self) -> dict:
        """
        BarcodeReader ARM32 ELF attack surface.

        Key observations:
          - http://127.0.0.12/ loopback VAPIX calls (Axis camera internal API)
          - VAPIX service account token via com.axis.HTTPConf1.VAPIXServiceAccounts1
          - libaxhttp.so: HTTP handler framework (ax_http_handler_new)
          - libaxevent.so: event system (ax_event_key_value_set_*)
          - libaxparameter.so: persistent param store (ax_parameter_get/register_callback)
          - libvdostream.so: video frame access
          - liblicensekey.so: same license gate as SIP UCS
          - OpenCV 3.4.7 embedded (binary converter alignment gap CVE note in strings)
        """
        pkg_dir = self.packages.get('BarcodeReader')
        binary = str(pkg_dir / 'BarcodeReader') if pkg_dir else None

        result = {
            'binary': binary,
            'arch': 'ARM32 EABI5 (armhf)',
            'stripped': True,
            'loopback_vapix': 'http://127.0.0.12/%s — internal VAPIX endpoint pattern',
            'vapix_service_account': 'com.axis.HTTPConf1.VAPIXServiceAccounts1 — token-based auth to camera API',
            'event_system': 'ax_event_key_value_set_* — publishes barcode scan events to ACAP event bus',
            'parameter_store': 'ax_parameter_get/register_callback — reads/watches ACAP params (/usr/share/acap-param/)',
            'opencv_version': '3.4.7 (embedded; binary converter alignment gap note present)',
            'cgi_handler': 'libaxhttp.so via ax_http_handler_new — HTTP CGI endpoint',
            'license_gate': 'liblicensekey.so.1 — same bypass vectors as SipThirdPartyIntegration',
            'attack_paths': [
                'CGI param injection via ax_http_handler: barcode data reflected in event JSON template',
                'VAPIX service account token exposure: token passed to http://127.0.0.12/ in plaintext (loopback)',
                'License bypass: LD_LIBRARY_PATH / licensekey_path (same as SIP UCS)',
                'OpenCV 3.4.7: check NVD for post-3.4.7 CVEs applicable to barcode decode path',
            ],
            'files': {},
        }

        if pkg_dir:
            for fname in ['cgi.conf', 'param.conf', 'whitelist.txt', 'manifest.json']:
                f = pkg_dir / fname
                if f.exists():
                    result['files'][fname] = f.read_text(errors='replace').strip()

        return result

    def facedetector_surface(self) -> dict:
        """
        facedetector aarch64 ELF attack surface.

        Uses protobuf + CGI handler pattern. Key findings:
          - libvideo-object-detection-subscriber.so.0: video analytics subscriber
          - libbbox.so.1: bounding box library
          - CGI methods: GetConfig, SetConfig, SendAlarmEvent, GetSupportedVersions,
                         GetConfigurationCapabilities
          - sendAlarmEvent params decoded from protobuf — malformed pb may crash
          - Face detection event published via ax_event_key_value_set_*
        """
        pkg_dir = self.packages.get('facedetector')
        binary = str(pkg_dir / 'facedetector') if pkg_dir else None

        result = {
            'binary': binary,
            'arch': 'aarch64',
            'stripped': True,
            'cgi_methods': [
                'GetConfig', 'SetConfig', 'SendAlarmEvent',
                'GetSupportedVersions', 'GetConfigurationCapabilities',
            ],
            'protobuf_decode': 'sendAlarmEvent params decoded via protobuf; malformed input path exists',
            'libs': [
                'libvideo-object-detection-subscriber.so.0',
                'libaxhttp.so.1', 'libaxevent.so.1', 'libaxparameter.so.1',
                'libbbox.so.1', 'libvdostream.so.1', 'libjansson.so.4',
            ],
            'attack_paths': [
                'SendAlarmEvent CGI: protobuf decode without explicit size guard — fuzz with malformed proto',
                'SetConfig CGI: "A mandatory parameter is missing" error path — parameter injection surface',
                'GetConfigurationCapabilities: "Cannot insert the parameters capabilities" — internal state exposure',
                'No liblicensekey in imports — not license-gated; runs unattended',
            ],
            'files': {},
        }

        if pkg_dir:
            lib_dir = pkg_dir / 'lib'
            if lib_dir.is_dir():
                result['files']['lib/'] = [f.name for f in lib_dir.iterdir()]
            for fname in ['cgi.txt', 'manifest.json']:
                f = pkg_dir / fname
                if f.exists():
                    result['files'][fname] = f.read_text(errors='replace').strip()

        return result

    # ── internal helpers ──────────────────────────────────────────────────────

    def _read_manifest(self, pkg_dir: Path) -> dict:
        m = pkg_dir / 'manifest.json'
        if m.exists():
            try:
                return json.loads(m.read_text())
            except Exception:
                pass
        p = pkg_dir / 'package.conf'
        if p.exists():
            cfg = {}
            for line in p.read_text().splitlines():
                if '=' in line:
                    k, _, v = line.partition('=')
                    cfg[k.strip()] = v.strip().strip('"\'')
            return cfg
        return {}

    def _verify_license_disasm(self, binary_path: str) -> dict:
        """Confirm key disasm landmarks from the licensekey bypass chain."""
        checks = {}
        strs = _strings(binary_path)
        checks['has_licensekey_path_env'] = 'licensekey_path' in strs
        checks['has_ld_preload_check'] = '/etc/ld.so.preload' in strs
        checks['has_ld_library_path'] = 'LD_LIBRARY_PATH' in strs
        checks['has_enabled_sentinel'] = self.ENABLED_FILE in strs
        checks['has_sipd_check'] = '/usr/bin/sipd' in strs
        checks['has_pem_read_rsa'] = 'PEM_read_RSA_PUBKEY' in strs
        checks['has_liblicensekey_so'] = 'liblicensekey.so' in strs
        # Verify dynamic import of licensekey_dyn_* (not static)
        _, imports = _nm(binary_path)
        checks['imports_licensekey_dyn_verify'] = 'licensekey_dyn_verify' in imports
        checks['imports_dlopen'] = any('dlopen' in i for i in imports)
        return checks

    def _sip_frida_hook(self) -> str:
        """
        Frida script to bypass licensekey_verify() on device.

        Hooks the wrapper in SipThirdPartyIntegration (which calls licensekey_dyn_verify@plt)
        AND the underlying liblicensekey.so.1 symbol for defense-in-depth bypass.
        """
        return r"""
// AXIS SipThirdPartyIntegration — licensekey_verify bypass
// Attach to the ACAP process: frida -n SipThirdPartyIntegration -l axis_license_bypass.js
// Or via USB: frida -U -n SipThirdPartyIntegration -l axis_license_bypass.js

'use strict';

const LIBNAME = 'liblicensekey.so.1';

function hookLicensekey() {
    // Hook 1: high-level wrapper exported from the ACAP binary itself
    const mod = Process.findModuleByName('SipThirdPartyIntegration');
    if (mod) {
        // licensekey_verify @ 0x26b0 (PIE — use symbol name)
        const sym = mod.findExportByName('licensekey_verify');
        if (sym) {
            Interceptor.attach(sym, {
                onLeave(retval) { retval.replace(1); }
            });
            console.log('[axis] hooked SipThirdPartyIntegration!licensekey_verify');
        }
        // licensekey_verify_ex
        const symEx = mod.findExportByName('licensekey_verify_ex');
        if (symEx) {
            Interceptor.attach(symEx, {
                onLeave(retval) { retval.replace(1); }
            });
            console.log('[axis] hooked SipThirdPartyIntegration!licensekey_verify_ex');
        }
    }

    // Hook 2: underlying dynamic resolver in liblicensekey.so.1
    const lib = Process.findModuleByName(LIBNAME);
    if (lib) {
        for (const name of ['licensekey_dyn_verify', 'licensekey_dyn_verify_ex']) {
            const s = lib.findExportByName(name);
            if (s) {
                Interceptor.attach(s, {
                    onLeave(retval) { retval.replace(1); }
                });
                console.log('[axis] hooked ' + LIBNAME + '!' + name);
            }
        }
    }
}

// Wait for liblicensekey.so.1 to load if not yet present
if (Process.findModuleByName(LIBNAME)) {
    hookLicensekey();
} else {
    Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
        onLeave(retval) {
            if (Process.findModuleByName(LIBNAME)) hookLicensekey();
        }
    });
}
""".strip()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='AXIS ACAP EAP RE module',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('target', help='Path to AXIS directory or single EAP/ELF binary')
    parser.add_argument('--all', action='store_true', help='Run all analysis passes')
    parser.add_argument('--survey', action='store_true', help='Survey all packages')
    parser.add_argument('--license-bypass', action='store_true',
                        help='Map licensekey_verify bypass vectors (SipThirdPartyIntegration)')
    parser.add_argument('--bodyworn', action='store_true', help='BodyWornLiveSelfHosted attack surface')
    parser.add_argument('--barcode', action='store_true', help='BarcodeReader VAPIX attack surface')
    parser.add_argument('--facedetector', action='store_true', help='facedetector CGI attack surface')
    parser.add_argument('--frida', action='store_true', help='Print Frida license bypass script')
    parser.add_argument('--json', action='store_true', help='Output JSON')
    args = parser.parse_args()

    analyzer = AxisEAPAnalyzer(args.target)
    results = {}

    if args.all or args.survey:
        results['survey'] = analyzer.survey()

    if args.all or args.license_bypass:
        results['license_bypass'] = analyzer.licensekey_bypass_vectors()

    if args.all or args.bodyworn:
        results['bodyworn'] = analyzer.bodyworn_attack_surface()

    if args.all or args.barcode:
        results['barcode'] = analyzer.barcode_vapix_surface()

    if args.all or args.facedetector:
        results['facedetector'] = analyzer.facedetector_surface()

    if args.frida:
        a = AxisEAPAnalyzer(args.target)
        print(a._sip_frida_hook())
        return

    if not results:
        results['survey'] = analyzer.survey()

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        _pretty_print(results)


def _pretty_print(results: dict):
    for section, data in results.items():
        print(f'\n{"="*60}')
        print(f'  {section.upper()}')
        print('='*60)
        _print_dict(data, indent=0)


def _print_dict(obj, indent: int):
    pad = '  ' * indent
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                print(f'{pad}{k}:')
                _print_dict(v, indent + 1)
            else:
                print(f'{pad}{k}: {v}')
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                _print_dict(item, indent)
                print()
            else:
                print(f'{pad}- {item}')
    else:
        print(f'{pad}{obj}')


if __name__ == '__main__':
    main()
